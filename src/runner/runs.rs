//! The runner's side of a run (part 6b): clone the task's repository
//! through lore's git proxy with the run token, write the CLI's MCP
//! configuration so that lore is there (and checked before the CLI
//! starts), start the CLI unattended with the model and the prompt lore
//! chose, stream its JSON events back as `run_output` lines, keep it to
//! its wall clock and output cap, and in every case delete the work
//! directory and report whether a push happened.
//!
//! The run token reaches git and the CLI only through their environment:
//! git gets it as an `http.<lore>/.extraHeader` from `GIT_CONFIG_*`
//! variables (so it is neither in `.git/config` nor in the process list,
//! and goes to lore only), the CLI as `LORE_AGENT_TOKEN`, which its MCP
//! configuration names. Every line sent to lore is redacted against the
//! token and every credential the agent's volume holds.
//!
//! A CLI runs in a session of its own (`setsid`), `nice`d, and under
//! `ionice -c 3` when the image has it. Ending a run interrupts the whole
//! session, waits, then kills it.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rustix::process::{Pid, Signal};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::Command,
    sync::{mpsc, watch},
};

use super::{
    drivers::{Driver, redact_with, shorten},
    protocol::{FromRunner, Kind, RunKind, RunSpec, ToRunner},
};

/// How long the clone may take.
const CLONE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How long a quick git command (rev-parse, ls-remote) may take.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long an interrupted CLI has before its session is killed.
const INTERRUPT_GRACE: Duration = Duration::from_secs(15);
/// Longest line sent to lore; longer ones are cut.
const LINE_CHARS: usize = 2000;
/// Longest raw line read from the CLI; the rest of it is skipped.
const RAW_LINE_BYTES: usize = 1024 * 1024;
/// The turn limit a Claude run gets.
const CLAUDE_MAX_TURNS: u32 = 200;
/// The `nice` increment of a run's CLI.
const NICE: i32 = 10;
/// Longest final answer sent back for a conversation.
const ANSWER_CHARS: usize = 32_000;

/// The runs of one link: at most one at a time.
pub struct Runs {
    driver: Arc<Driver>,
    out: mpsc::Sender<FromRunner>,
    work: PathBuf,
    git: PathBuf,
    agent: String,
    /// Dropping a run's sender stops it.
    active: Arc<Mutex<HashMap<String, watch::Sender<Option<String>>>>>,
}

impl Runs {
    pub fn new(
        driver: Arc<Driver>,
        out: mpsc::Sender<FromRunner>,
        work: PathBuf,
        git: PathBuf,
        agent: String,
    ) -> Self {
        Self {
            driver,
            out,
            work,
            git,
            agent,
            active: Arc::default(),
        }
    }

    fn active(&self) -> std::sync::MutexGuard<'_, HashMap<String, watch::Sender<Option<String>>>> {
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes the run commands this runner carries out; anything else is
    /// handed back.
    pub fn handle(&self, command: ToRunner) -> Option<ToRunner> {
        match command {
            ToRunner::RunStart { spec } => {
                self.start(spec);
                None
            }
            ToRunner::RunStop { run_id } => {
                if let Some(stop) = self.active().get(&run_id) {
                    let _ = stop.send(Some("stopped".into()));
                }
                None
            }
            ToRunner::CleanWorkdir { run_id } => {
                if valid_run_id(&run_id) && !self.active().contains_key(&run_id) {
                    let _ = std::fs::remove_dir_all(self.work.join(&run_id));
                }
                None
            }
            other => Some(other),
        }
    }

    fn start(&self, spec: RunSpec) {
        let run_id = spec.run_id.clone();
        let dir_name = spec.workdir.clone().unwrap_or_else(|| run_id.clone());
        let refusal = if !valid_run_id(&run_id) || !valid_run_id(&dir_name) {
            Some("the run id is not a plain name".to_string())
        } else if !self.active().is_empty() {
            Some("another run is still going in this container".to_string())
        } else {
            None
        };
        if let Some(reason) = refusal {
            let out = self.out.clone();
            tokio::spawn(async move {
                let _ = out
                    .send(FromRunner::RunExit {
                        run_id,
                        code: None,
                        pushed: false,
                        head: None,
                        work_free_bytes: None,
                        reason: Some(format!("failed: {reason}")),
                        answer: None,
                    })
                    .await;
            });
            return;
        }
        let (stop_tx, stop_rx) = watch::channel(None);
        self.active().insert(run_id.clone(), stop_tx);
        let run = Run {
            driver: self.driver.clone(),
            out: self.out.clone(),
            dir: self.work.join(&dir_name),
            work: self.work.clone(),
            git: self.git.clone(),
            agent: self.agent.clone(),
            secrets: Vec::new(),
            seq: 0,
            sent_bytes: 0,
            answer: None,
            spec,
        };
        let active = self.active.clone();
        tokio::spawn(async move {
            run.execute(stop_rx).await;
            active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&run_id);
        });
    }
}

/// The link closed: every run stops (its sender goes), and still deletes
/// its work directory.
impl Drop for Runs {
    fn drop(&mut self) {
        self.active().clear();
    }
}

/// A run id: 1 to 64 letters, digits, `-` and `_`.
fn valid_run_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// One run in progress.
struct Run {
    driver: Arc<Driver>,
    out: mpsc::Sender<FromRunner>,
    /// `/work/<run id>`: `repo` (the checkout) and `lore` (the CLI's
    /// configuration), deleted whatever happens.
    dir: PathBuf,
    work: PathBuf,
    git: PathBuf,
    agent: String,
    /// Everything redacted from what is sent: the run token and the
    /// agent's stored credentials.
    secrets: Vec<String>,
    seq: u64,
    sent_bytes: u64,
    /// The CLI's final message so far (a conversation's answer).
    answer: Option<String>,
    spec: RunSpec,
}

/// How the CLI ended.
struct Ended {
    code: Option<i32>,
    reason: Option<String>,
}

impl Run {
    async fn execute(mut self, mut stop: watch::Receiver<Option<String>>) {
        self.secrets = self.driver.secrets();
        self.secrets.push(self.spec.token.expose().to_string());
        let (ended, pushed, head) = match self.work_through(&mut stop).await {
            Ok(result) => result,
            Err(error) => {
                let message = format!("{error:#}");
                self.say("error", &message).await;
                (
                    Ended {
                        code: None,
                        reason: Some(format!("failed: {}", shorten(&message, 300))),
                    },
                    false,
                    None,
                )
            }
        };
        // The work directory goes, whatever happened.
        if let Err(error) = remove_dir(&self.dir) {
            self.say(
                "error",
                &format!("the work directory could not be deleted: {error}"),
            )
            .await;
        }
        let free = super::read_resources(&self.work).await.work_free_bytes;
        let reason = ended.reason.map(|reason| self.redact(&reason));
        let answer = self
            .answer
            .take()
            .map(|answer| shorten(&self.redact(&answer), ANSWER_CHARS))
            .filter(|answer| !answer.trim().is_empty());
        let _ = self
            .out
            .send(FromRunner::RunExit {
                run_id: self.spec.run_id.clone(),
                code: ended.code,
                pushed,
                head,
                work_free_bytes: free,
                reason,
                answer,
            })
            .await;
    }

    fn redact(&self, text: &str) -> String {
        redact_with(text, &self.secrets)
    }

    /// Sends one line (redacted and cut) to lore.
    async fn say(&mut self, stream: &str, text: &str) {
        let line = shorten(&self.redact(text), LINE_CHARS);
        if line.is_empty() {
            return;
        }
        self.seq += 1;
        self.sent_bytes += line.len() as u64;
        let _ = self
            .out
            .send(FromRunner::RunOutput {
                run_id: self.spec.run_id.clone(),
                seq: self.seq,
                stream: stream.into(),
                line,
            })
            .await;
    }

    /// Clone, configure, run, and look whether the default branch moved.
    async fn work_through(
        &mut self,
        stop: &mut watch::Receiver<Option<String>>,
    ) -> Result<(Ended, bool, Option<String>)> {
        let _ = std::fs::remove_dir_all(&self.dir);
        create_private_dir(&self.dir)?;
        let repo = self.dir.join("repo");
        let conf = self.dir.join("lore");
        create_private_dir(&conf)?;

        self.say("lore", "checking that lore's MCP server answers")
            .await;
        check_mcp(&self.spec.mcp_url, self.spec.token.expose())
            .await
            .context("lore's MCP server is required for a run and did not answer")?;

        // A conversation without a project has no checkout: the CLI works
        // in an empty directory and only talks.
        if self.spec.clone_url.trim().is_empty() {
            let chat = self.dir.join("chat");
            create_private_dir(&chat)?;
            self.say("lore", "a conversation without a checkout").await;
            let (program, args, env) = self.cli_command(&chat, &conf)?;
            let command = self.cli_process(&program, &args, env, &chat);
            let ended = self.run_cli(command, stop, None).await?;
            return Ok((ended, false, None));
        }
        self.say("lore", "cloning the repository through lore")
            .await;
        let clone = self
            .git(
                &[
                    "clone".into(),
                    "--quiet".into(),
                    "--".into(),
                    self.spec.clone_url.clone(),
                    repo.display().to_string(),
                ],
                &self.dir,
                CLONE_TIMEOUT,
            )
            .await?;
        if !clone.0 {
            bail!("cloning failed: {}", shorten(&self.redact(&clone.1), 400));
        }
        let branch = self
            .git(
                &[
                    "symbolic-ref".into(),
                    "--quiet".into(),
                    "--short".into(),
                    "refs/remotes/origin/HEAD".into(),
                ],
                &repo,
                GIT_TIMEOUT,
            )
            .await?
            .1
            .trim()
            .trim_start_matches("origin/")
            .to_string();
        let base = self
            .git(&["rev-parse".into(), "HEAD".into()], &repo, GIT_TIMEOUT)
            .await?
            .1
            .trim()
            .to_string();
        let branch = if branch.is_empty() {
            "HEAD".into()
        } else {
            branch
        };
        self.say(
            "lore",
            &format!(
                "checked out {branch} at {}",
                base.chars().take(12).collect::<String>()
            ),
        )
        .await;

        let (program, args, env) = self.cli_command(&repo, &conf)?;
        let command = self.cli_process(&program, &args, env, &repo);
        let base_sent = (base.len() >= 40).then(|| base.clone());
        let ended = self.run_cli(command, stop, base_sent).await?;

        // A conversation pushes nothing (lore refuses it), so there is
        // nothing to look at.
        if self.spec.kind == RunKind::Chat {
            return Ok((ended, false, None));
        }
        // Did the default branch move? Asked through lore, with the token.
        let head = if branch == "HEAD" {
            None
        } else {
            match self
                .git(
                    &[
                        "ls-remote".into(),
                        "origin".into(),
                        format!("refs/heads/{branch}"),
                    ],
                    &repo,
                    GIT_TIMEOUT,
                )
                .await
            {
                Ok((true, text)) => text
                    .split_whitespace()
                    .next()
                    .filter(|sha| sha.len() >= 40 && sha.chars().all(|c| c.is_ascii_hexdigit()))
                    .map(str::to_string),
                _ => None,
            }
        };
        let pushed = head.as_deref().is_some_and(|head| head != base);
        match &head {
            Some(head) if pushed => {
                self.say("lore", &format!("{branch} moved to {head}")).await;
            }
            Some(_) => self.say("lore", &format!("{branch} did not move")).await,
            None => {
                self.say("lore", "the remote branch could not be read after the run")
                    .await;
            }
        }
        Ok((ended, pushed, head))
    }

    /// The CLI's process: its environment (the token, git's settings,
    /// what the CLI needs), its own session, `nice`d.
    fn cli_process(&self, program: &Path, args: &[String], env: Env, cwd: &Path) -> Command {
        let mut command = self.driver.run_command(program, args, cwd);
        command
            .env("LORE_AGENT_TOKEN", self.spec.token.expose())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in self.git_env() {
            command.env(name, value);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        // SAFETY: between fork and exec only two system calls run, through
        // rustix, which neither allocates nor takes locks.
        unsafe {
            command.pre_exec(|| {
                rustix::process::setsid().map_err(std::io::Error::from)?;
                let _ = rustix::process::nice(NICE);
                Ok(())
            });
        }
        command
    }

    /// What git needs for the run: the token as a header for lore's own
    /// address only, an identity, and no prompts.
    fn git_env(&self) -> Vec<(String, String)> {
        let lore = lore_origin(&self.spec.clone_url);
        vec![
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_COUNT".into(), "3".into()),
            (
                "GIT_CONFIG_KEY_0".into(),
                format!("http.{lore}/.extraHeader"),
            ),
            (
                "GIT_CONFIG_VALUE_0".into(),
                format!("Authorization: Bearer {}", self.spec.token.expose()),
            ),
            ("GIT_CONFIG_KEY_1".into(), "user.name".into()),
            ("GIT_CONFIG_VALUE_1".into(), self.agent.clone()),
            ("GIT_CONFIG_KEY_2".into(), "user.email".into()),
            (
                "GIT_CONFIG_VALUE_2".into(),
                format!("{}@users.noreply.lore.invalid", self.agent),
            ),
        ]
    }

    /// Runs git with the run's environment; answers success and output.
    async fn git(&self, args: &[String], cwd: &Path, wait: Duration) -> Result<(bool, String)> {
        let mut command = self.driver.run_command(&self.git, args, cwd);
        for (name, value) in self.git_env() {
            command.env(name, value);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = tokio::time::timeout(wait, command.output())
            .await
            .context("git took too long")?
            .context("starting git")?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok((output.status.success(), text))
    }

    /// The CLI's program, arguments and extra environment, with its MCP
    /// configuration written to `conf` (outside the checkout).
    fn cli_command(&self, repo: &Path, conf: &Path) -> Result<CliCommand> {
        let kind = self.driver.kind();
        let program = self.driver.settings.program.clone();
        let model = self.spec.model.trim();
        let model = (!model.is_empty() && !model.starts_with('-')).then_some(model);
        let resume = self
            .spec
            .resume
            .as_deref()
            .map(str::trim)
            .filter(|id| valid_session_id(id));
        let (args, env) = cli_arguments(
            kind,
            &self.driver.settings.provider,
            model,
            &self.spec.prompt,
            &self.spec.mcp_url,
            &self.spec.run_id,
            repo,
            conf,
            &Turn {
                chat: self.spec.kind == RunKind::Chat,
                resume,
            },
        )?;
        // `ionice -c 3` when the image has it: the CLI's disk use waits for
        // everything else.
        match find_on_path("ionice") {
            Some(ionice) => {
                let mut wrapped = vec!["-c".to_string(), "3".to_string()];
                wrapped.push(program.display().to_string());
                wrapped.extend(args);
                Ok((ionice, wrapped, env))
            }
            None => Ok((program, args, env)),
        }
    }

    /// Starts the CLI and relays its output until it ends, is stopped,
    /// runs out of time or prints too much.
    async fn run_cli(
        &mut self,
        mut command: Command,
        stop: &mut watch::Receiver<Option<String>>,
        base: Option<String>,
    ) -> Result<Ended> {
        let mut child = command.spawn().context("starting the CLI")?;
        let session = child.id().and_then(|pid| Pid::from_raw(pid as i32));
        let _ = self
            .out
            .send(FromRunner::RunStarted {
                run_id: self.spec.run_id.clone(),
                session_id: None,
                base,
            })
            .await;
        self.say("lore", "the CLI started").await;
        let (lines_tx, mut lines_rx) = mpsc::channel::<(bool, String)>(256);
        for (is_err, pipe) in [
            (
                false,
                child
                    .stdout
                    .take()
                    .map(|p| Box::new(p) as Box<dyn AsyncRead + Send + Unpin>),
            ),
            (
                true,
                child
                    .stderr
                    .take()
                    .map(|p| Box::new(p) as Box<dyn AsyncRead + Send + Unpin>),
            ),
        ] {
            let Some(pipe) = pipe else { continue };
            let lines_tx = lines_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(pipe);
                let mut buffer = Vec::new();
                loop {
                    buffer.clear();
                    match read_line(&mut reader, &mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let line = String::from_utf8_lossy(&buffer).trim_end().to_string();
                            if lines_tx.send((is_err, line)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        drop(lines_tx);
        let kind = self.driver.kind();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.spec.wall_clock_secs);
        let mut session_sent = false;
        let mut reason: Option<String> = None;
        let mut code = None;
        let mut exited = false;
        let mut open = true;
        while open || !exited {
            tokio::select! {
                line = lines_rx.recv(), if open => match line {
                    Some((is_err, line)) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        let parsed = if is_err {
                            Parsed::lines(vec![("stderr".into(), line)])
                        } else {
                            parse_event(kind, &line)
                        };
                        if let Some(session_id) = parsed.session.filter(|_| !session_sent) {
                            session_sent = true;
                            let _ = self.out.send(FromRunner::RunStarted {
                                run_id: self.spec.run_id.clone(),
                                session_id: Some(self.redact(&session_id)),
                                base: None,
                            }).await;
                        }
                        if let Some(answer) = parsed.answer {
                            self.answer = Some(answer);
                        }
                        for (stream, text) in parsed.lines {
                            self.say(&stream, &text).await;
                        }
                        if let Some(why) = parsed.fatal.filter(|_| reason.is_none()) {
                            self.say("error", &why).await;
                            reason = Some(format!("failed: {why}"));
                            interrupt(&mut child, session).await;
                        }
                        if self.sent_bytes > self.spec.output_cap_bytes && reason.is_none() {
                            self.say("lore", "the output cap was reached; stopping the CLI").await;
                            reason = Some("output_cap".into());
                            interrupt(&mut child, session).await;
                        }
                    }
                    None => open = false,
                },
                status = child.wait(), if !exited => {
                    exited = true;
                    code = status.ok().and_then(|status| status.code());
                    // Let the pipes drain a moment, not for ever (a
                    // background process may hold them open).
                    if open {
                        let drain = tokio::time::sleep(Duration::from_secs(2));
                        tokio::pin!(drain);
                        loop {
                            tokio::select! {
                                line = lines_rx.recv() => match line {
                                    Some((is_err, line)) if !line.trim().is_empty() => {
                                        let parsed = if is_err {
                                            Parsed::lines(vec![("stderr".into(), line)])
                                        } else {
                                            parse_event(kind, &line)
                                        };
                                        if let Some(answer) = parsed.answer {
                                            self.answer = Some(answer);
                                        }
                                        for (stream, text) in parsed.lines {
                                            self.say(&stream, &text).await;
                                        }
                                    }
                                    Some(_) => {}
                                    None => break,
                                },
                                _ = &mut drain => break,
                            }
                        }
                        open = false;
                    }
                }
                changed = stop.changed(), if reason.is_none() => {
                    let why = match changed {
                        Ok(()) => stop.borrow().clone().unwrap_or_else(|| "stopped".into()),
                        // The link to lore closed: nobody is left to report to.
                        Err(_) => "link_closed".into(),
                    };
                    self.say("lore", &format!("stopping the CLI ({why})")).await;
                    reason = Some(why);
                    interrupt(&mut child, session).await;
                }
                _ = tokio::time::sleep_until(deadline), if reason.is_none() => {
                    self.say("lore", "the wall clock ran out; stopping the CLI").await;
                    reason = Some("timeout".into());
                    interrupt(&mut child, session).await;
                }
            }
        }
        // Nothing the CLI started outlives the run.
        if let Some(session) = session {
            super::terminal::kill_session(session);
        }
        Ok(Ended { code, reason })
    }
}

/// Extra environment variables, as `(name, value)`.
type Env = Vec<(String, String)>;

/// What kind of turn a run is, for its command line.
#[derive(Debug, Default, Clone, Copy)]
pub struct Turn<'a> {
    /// A conversation (`ask`): it may run outside a git checkout.
    pub chat: bool,
    /// The CLI session to resume, for a follow-up question.
    pub resume: Option<&'a str>,
}

/// A CLI session id as lore passes it on: letters, digits, `-`, `_`
/// and `.`, at most 200 characters.
fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

type CliCommand = (PathBuf, Vec<String>, Env);

/// Interrupts the CLI's whole session, then kills it if it does not end
/// within the grace period.
async fn interrupt(child: &mut tokio::process::Child, session: Option<Pid>) {
    let Some(session) = session else {
        let _ = child.kill().await;
        return;
    };
    let _ = rustix::process::kill_process_group(session, Signal::INT);
    if tokio::time::timeout(INTERRUPT_GRACE, child.wait())
        .await
        .is_err()
    {
        super::terminal::kill_session(session);
        let _ = child.kill().await;
    }
}

/// Reads one line, keeping at most `RAW_LINE_BYTES` of it.
async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total);
        }
        let (used, done) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        let room = RAW_LINE_BYTES.saturating_sub(buffer.len());
        buffer.extend_from_slice(&available[..used.min(room)]);
        reader.consume(used);
        total += used;
        if done {
            return Ok(total);
        }
    }
}

/// `scheme://host[:port]` of the clone URL: the only address git sends
/// the token to.
fn lore_origin(clone_url: &str) -> String {
    let (scheme, rest) = clone_url.split_once("://").unwrap_or(("http", clone_url));
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// The arguments and environment each CLI runs with, and the MCP
/// configuration it reads, written to `conf`. The prompt is the last
/// argument (or the first, for Claude, whose `--mcp-config` takes several
/// values).
///
/// A follow-up resumes the CLI's own session (each verified against the
/// CLI's `--help`): `claude -p … --resume <id>`, `codex exec resume
/// [options] <id> <prompt>` (which takes no `-C` or `-s`: the working
/// directory is the process's, the sandbox a `-c` setting), and
/// `opencode run --session <id>`.
#[expect(
    clippy::too_many_arguments,
    reason = "everything a command line is made of"
)]
pub fn cli_arguments(
    kind: Kind,
    provider: &str,
    model: Option<&str>,
    prompt: &str,
    mcp_url: &str,
    run_id: &str,
    repo: &Path,
    conf: &Path,
    turn: &Turn<'_>,
) -> Result<(Vec<String>, Env)> {
    let mut args: Vec<String> = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    match kind {
        Kind::Claude => {
            let config = serde_json::json!({
                "mcpServers": { "lore": {
                    "type": "http",
                    "url": mcp_url,
                    "headers": { "Authorization": "Bearer ${LORE_AGENT_TOKEN}" },
                } }
            });
            let path = conf.join("mcp.json");
            super::drivers::write_private(
                &path,
                serde_json::to_string_pretty(&config)?.as_bytes(),
            )?;
            args.extend(["-p".into(), prompt.into()]);
            args.extend([
                "--output-format".into(),
                "stream-json".into(),
                "--verbose".into(),
                "--max-turns".into(),
                CLAUDE_MAX_TURNS.to_string(),
                "--permission-mode".into(),
                "bypassPermissions".into(),
                "--setting-sources".into(),
                "user".into(),
                "--strict-mcp-config".into(),
                "--mcp-config".into(),
                path.display().to_string(),
            ]);
            if let Some(model) = model {
                args.extend(["--model".into(), model.into()]);
            }
            if let Some(session) = turn.resume {
                args.extend(["--resume".into(), session.into()]);
            }
        }
        Kind::Codex => {
            if turn.resume.is_some() {
                args.extend([
                    "exec".into(),
                    "resume".into(),
                    "--json".into(),
                    "-c".into(),
                    "sandbox_mode=\"danger-full-access\"".into(),
                ]);
            } else {
                args.extend([
                    "exec".into(),
                    "--json".into(),
                    "-C".into(),
                    repo.display().to_string(),
                    "-s".into(),
                    "danger-full-access".into(),
                ]);
            }
            if turn.chat {
                args.push("--skip-git-repo-check".into());
            }
            args.extend([
                "-c".into(),
                "approval_policy=\"never\"".into(),
                "-c".into(),
                format!("mcp_servers.lore.url={}", toml_string(mcp_url)),
                "-c".into(),
                "mcp_servers.lore.bearer_token_env_var=\"LORE_AGENT_TOKEN\"".into(),
                "-c".into(),
                "mcp_servers.lore.required=true".into(),
            ]);
            if let Some(model) = model {
                args.extend(["-m".into(), model.into()]);
            }
            if let Some(session) = turn.resume {
                args.push(session.into());
            }
            args.push(prompt.into());
        }
        Kind::Opencode => {
            let config = serde_json::json!({
                "$schema": "https://opencode.ai/config.json",
                "autoupdate": false,
                "share": "disabled",
                "mcp": { "lore": {
                    "type": "remote",
                    "url": mcp_url,
                    "enabled": true,
                    "oauth": false,
                    "headers": { "Authorization": "Bearer {env:LORE_AGENT_TOKEN}" },
                } }
            });
            let path = conf.join("opencode.json");
            super::drivers::write_private(
                &path,
                serde_json::to_string_pretty(&config)?.as_bytes(),
            )?;
            env.extend([
                ("OPENCODE_CONFIG".to_string(), path.display().to_string()),
                // The repository's own opencode.json is not trusted.
                (
                    "OPENCODE_DISABLE_PROJECT_CONFIG".to_string(),
                    "1".to_string(),
                ),
            ]);
            args.extend([
                "run".into(),
                "--standalone".into(),
                "--format".into(),
                "json".into(),
                "--auto".into(),
                "--archived".into(),
                "--title".into(),
                format!("lore run {run_id}"),
            ]);
            if let Some(model) = model {
                let model = if model.contains('/') {
                    model.to_string()
                } else {
                    format!("{provider}/{model}")
                };
                args.extend(["--model".into(), model]);
            }
            if let Some(session) = turn.resume {
                args.extend(["--session".into(), session.into()]);
            }
            args.push(prompt.into());
        }
    }
    Ok((args, env))
}

/// A TOML basic string.
fn toml_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

/// Checks that lore's MCP endpoint answers an `initialize` with the run
/// token: lore is required for a run.
async fn check_mcp(url: &str, token: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "lore-runner", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let mut header =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).context("token")?;
    header.set_sensitive(true);
    let response = client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, header)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(&body)
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("{}", error.without_url()))?;
    if !response.status().is_success() {
        bail!("it answered HTTP {}", response.status().as_u16());
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Deletes a work directory, making read-only parts (git's packs, a
/// tool's caches) writable first if the plain delete fails.
fn remove_dir(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            make_writable(path);
            std::fs::remove_dir_all(path)
        }
    }
}

fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    }
}

/// What one line of a CLI's JSON stream says.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// `(stream, text)`: `text`, `tool`, `result`, `error` or `raw`.
    pub lines: Vec<(String, String)>,
    /// The CLI's session id, when this line names it.
    pub session: Option<String>,
    /// A reason to end the run at once (lore's MCP server failed).
    pub fatal: Option<String>,
    /// The CLI's message to the user, when this line holds one: the last
    /// one is a conversation's answer.
    pub answer: Option<String>,
}

impl Parsed {
    fn lines(lines: Vec<(String, String)>) -> Self {
        Self {
            lines,
            ..Self::default()
        }
    }
}

/// Reads one line of a CLI's JSON event stream into what the page shows.
/// A line that is not JSON is passed on as `raw`.
pub fn parse_event(kind: Kind, line: &str) -> Parsed {
    let Ok(event) = serde_json::from_str::<Value>(line) else {
        return Parsed::lines(vec![("raw".into(), line.to_string())]);
    };
    match kind {
        Kind::Claude => parse_claude(&event),
        Kind::Codex => parse_codex(&event),
        Kind::Opencode => parse_opencode(&event),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// A tool's input in one short line.
fn brief(value: &Value) -> String {
    let shown = match value {
        Value::Object(map) => [
            "command",
            "file_path",
            "path",
            "pattern",
            "url",
            "query",
            "description",
        ]
        .iter()
        .find_map(|key| map.get(*key).map(text))
        .unwrap_or_else(|| value.to_string()),
        other => text(other),
    };
    shorten(&shown.replace('\n', " "), 200)
}

/// Claude Code's `stream-json` (with `--verbose`): `system` (`init`, with
/// the session id and each MCP server's status), `assistant` and `user`
/// messages whose content holds `text`, `tool_use` and `tool_result`
/// blocks, and a final `result`.
fn parse_claude(event: &Value) -> Parsed {
    let mut parsed = Parsed {
        session: event["session_id"].as_str().map(str::to_string),
        ..Parsed::default()
    };
    match event["type"].as_str().unwrap_or_default() {
        "system" if event["subtype"] == "init" => {
            let lore = event["mcp_servers"]
                .as_array()
                .and_then(|servers| servers.iter().find(|server| server["name"] == "lore"))
                .and_then(|server| server["status"].as_str())
                .unwrap_or("missing")
                .to_string();
            parsed.lines.push((
                "lore".into(),
                format!(
                    "session started · model {} · lore MCP {lore}",
                    text(&event["model"])
                ),
            ));
            if lore != "connected" {
                parsed.fatal = Some(format!("lore's MCP server is required and is {lore}"));
            }
        }
        "assistant" => {
            for block in event["message"]["content"].as_array().into_iter().flatten() {
                match block["type"].as_str().unwrap_or_default() {
                    "text" => {
                        let said = text(&block["text"]);
                        if !said.trim().is_empty() {
                            parsed.answer = Some(said.clone());
                        }
                        parsed.lines.push(("text".into(), said));
                    }
                    "tool_use" => parsed.lines.push((
                        "tool".into(),
                        format!("{} {}", text(&block["name"]), brief(&block["input"])),
                    )),
                    _ => {}
                }
            }
        }
        "user" => {
            for block in event["message"]["content"].as_array().into_iter().flatten() {
                if block["type"] == "tool_result" && block["is_error"] == true {
                    let content = match &block["content"] {
                        Value::Array(parts) => parts.iter().map(|p| text(&p["text"])).collect(),
                        other => text(other),
                    };
                    parsed.lines.push((
                        "tool".into(),
                        format!("tool error: {}", shorten(&content, 300)),
                    ));
                }
            }
        }
        "result" => {
            let stream = if event["is_error"] == true {
                "error"
            } else {
                "result"
            };
            let mut line = format!(
                "{} after {} turns",
                text(&event["subtype"]),
                text(&event["num_turns"])
            );
            if let Some(result) = event["result"].as_str() {
                line.push_str(": ");
                line.push_str(result);
                if !result.trim().is_empty() {
                    parsed.answer = Some(result.to_string());
                }
            }
            parsed.lines.push((stream.into(), line));
        }
        _ => {}
    }
    parsed
}

/// `codex exec --json`: `thread.started` (the thread id), `turn.started`,
/// `turn.completed` (usage), `turn.failed` (error), `item.started`,
/// `item.updated`, `item.completed` (an `agent_message`, `reasoning`,
/// `command_execution`, `file_change`, `mcp_tool_call`, `web_search`,
/// `todo_list` or `error` item), and `error`.
fn parse_codex(event: &Value) -> Parsed {
    let mut parsed = Parsed::default();
    match event["type"].as_str().unwrap_or_default() {
        "thread.started" => {
            parsed.session = event["thread_id"].as_str().map(str::to_string);
            parsed.lines.push(("lore".into(), "session started".into()));
        }
        "turn.completed" => {
            let usage = &event["usage"];
            parsed.lines.push((
                "result".into(),
                format!(
                    "turn completed · {} input tokens, {} output tokens",
                    text(&usage["input_tokens"]),
                    text(&usage["output_tokens"])
                ),
            ));
        }
        "turn.failed" => parsed.lines.push((
            "error".into(),
            format!("turn failed: {}", text(&event["error"]["message"])),
        )),
        "error" => parsed.lines.push(("error".into(), text(&event["message"]))),
        "item.completed" => {
            let item = &event["item"];
            match item["type"].as_str().unwrap_or_default() {
                "agent_message" => {
                    let said = text(&item["text"]);
                    if !said.trim().is_empty() {
                        parsed.answer = Some(said.clone());
                    }
                    parsed.lines.push(("text".into(), said));
                }
                "command_execution" => parsed.lines.push((
                    "tool".into(),
                    format!(
                        "$ {} → exit {}",
                        shorten(&text(&item["command"]), 200),
                        text(&item["exit_code"])
                    ),
                )),
                "file_change" => {
                    let changes: Vec<String> = item["changes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|change| {
                            format!("{} {}", text(&change["kind"]), text(&change["path"]))
                        })
                        .collect();
                    parsed
                        .lines
                        .push(("tool".into(), format!("changed {}", changes.join(", "))));
                }
                "mcp_tool_call" => {
                    let line = format!(
                        "{}.{} {}",
                        text(&item["server"]),
                        text(&item["tool"]),
                        text(&item["status"])
                    );
                    parsed.lines.push(("tool".into(), line));
                }
                "web_search" => parsed.lines.push((
                    "tool".into(),
                    format!("web search: {}", text(&item["query"])),
                )),
                "error" => parsed.lines.push(("error".into(), text(&item["message"]))),
                _ => {}
            }
        }
        _ => {}
    }
    parsed
}

/// `opencode run --format json` (2.x): one object per line with `type`,
/// `timestamp` and `sessionID`: `step_start`, `text` and `reasoning`
/// (`part.text`), `tool_use` (`part.tool`, `part.state.status`, its
/// `input`, and `output` or `error`), `step_finish` (`part.reason`,
/// tokens, cost), `retry`, `error` (`error.message`, or
/// `error.data.message`) and `background_wait`.
fn parse_opencode(event: &Value) -> Parsed {
    let mut parsed = Parsed {
        session: event["sessionID"]
            .as_str()
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        ..Parsed::default()
    };
    let part = &event["part"];
    match event["type"].as_str().unwrap_or_default() {
        "text" => {
            let said = text(&part["text"]);
            if !said.trim().is_empty() {
                parsed.answer = Some(said.clone());
            }
            parsed.lines.push(("text".into(), said));
        }
        "tool_use" => {
            let state = &part["state"];
            let status = text(&state["status"]);
            let mut line = format!(
                "{} {} → {status}",
                text(&part["tool"]),
                brief(&state["input"])
            );
            if status == "error" {
                line.push_str(&format!(": {}", text(&state["error"])));
            }
            parsed.lines.push(("tool".into(), line));
        }
        "step_finish" if part["reason"] == "stop" => {
            parsed.lines.push((
                "result".into(),
                format!("finished · cost {}", text(&part["cost"])),
            ));
        }
        "retry" => parsed.lines.push((
            "lore".into(),
            format!("retrying: {}", text(&event["error"]["message"])),
        )),
        "error" => {
            let error = &event["error"];
            let message = error["message"]
                .as_str()
                .or_else(|| error["data"]["message"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());
            parsed.lines.push(("error".into(), message));
        }
        _ => {}
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_cli_s_documented_events_are_read() {
        let claude = parse_event(
            Kind::Claude,
            r#"{"type":"system","subtype":"init","session_id":"s-1","model":"claude-x","mcp_servers":[{"name":"lore","status":"connected"}]}"#,
        );
        assert_eq!(claude.session.as_deref(), Some("s-1"));
        assert!(claude.fatal.is_none());
        let failed = parse_event(
            Kind::Claude,
            r#"{"type":"system","subtype":"init","session_id":"s-1","mcp_servers":[{"name":"lore","status":"failed"}]}"#,
        );
        assert!(failed.fatal.is_some());
        let message = parse_event(
            Kind::Claude,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Reading the task"},{"type":"tool_use","name":"Bash","input":{"command":"git status"}}]},"session_id":"s-1"}"#,
        );
        assert_eq!(
            message.lines,
            vec![
                ("text".to_string(), "Reading the task".to_string()),
                ("tool".to_string(), "Bash git status".to_string())
            ]
        );
        let result = parse_event(
            Kind::Claude,
            r#"{"type":"result","subtype":"success","is_error":false,"num_turns":4,"result":"Done.","session_id":"s-1"}"#,
        );
        assert_eq!(result.lines[0].0, "result");

        let codex = parse_event(
            Kind::Codex,
            r#"{"type":"thread.started","thread_id":"th-1"}"#,
        );
        assert_eq!(codex.session.as_deref(), Some("th-1"));
        let command = parse_event(
            Kind::Codex,
            r#"{"type":"item.completed","item":{"id":"item_1","type":"command_execution","command":"bash -lc ls","aggregated_output":"x","exit_code":0,"status":"completed"}}"#,
        );
        assert_eq!(command.lines[0].1, "$ bash -lc ls → exit 0");
        let failed = parse_event(
            Kind::Codex,
            r#"{"type":"turn.failed","error":{"message":"quota"}}"#,
        );
        assert_eq!(
            failed.lines[0],
            ("error".into(), "turn failed: quota".into())
        );

        let text = parse_event(
            Kind::Opencode,
            r#"{"type":"text","timestamp":1,"sessionID":"ses_1","part":{"id":"p","sessionID":"ses_1","messageID":"m","type":"text","text":"Hello","time":{"start":1,"end":2}}}"#,
        );
        assert_eq!(text.session.as_deref(), Some("ses_1"));
        assert_eq!(text.lines[0], ("text".into(), "Hello".into()));
        let tool = parse_event(
            Kind::Opencode,
            r#"{"type":"tool_use","timestamp":1,"sessionID":"ses_1","part":{"type":"tool","tool":"bash","state":{"status":"completed","input":{"command":"ls"},"output":"a"}}}"#,
        );
        assert_eq!(tool.lines[0].1, "bash ls → completed");
        let error = parse_event(
            Kind::Opencode,
            r#"{"type":"error","timestamp":1,"sessionID":"ses_1","error":{"type":"unknown","message":"no key"}}"#,
        );
        assert_eq!(error.lines[0], ("error".into(), "no key".into()));
        assert_eq!(parse_event(Kind::Opencode, "plain words").lines[0].0, "raw");
    }

    #[test]
    fn command_lines_name_lore_and_the_model_and_hold_no_token() {
        let dir = std::env::temp_dir().join(format!("lore-runs-args-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for kind in [Kind::Claude, Kind::Codex, Kind::Opencode] {
            let (args, env) = cli_arguments(
                kind,
                "deepseek",
                Some("m1"),
                "the prompt",
                "http://lore:8080/mcp",
                "r1",
                Path::new("/work/r1/repo"),
                &dir,
                &Turn::default(),
            )
            .unwrap();
            let joined = args.join(" ");
            assert!(joined.contains("the prompt"), "{joined}");
            assert!(joined.contains("m1"), "{joined}");
            assert!(!joined.contains("lore_run_"), "{joined}");
            match kind {
                Kind::Claude => {
                    assert_eq!(args[0], "-p");
                    assert!(joined.contains("--strict-mcp-config"));
                    let config = std::fs::read_to_string(dir.join("mcp.json")).unwrap();
                    assert!(config.contains("${LORE_AGENT_TOKEN}"));
                }
                Kind::Codex => {
                    assert!(joined.contains("mcp_servers.lore.required=true"));
                    assert!(joined.contains("mcp_servers.lore.url=\"http://lore:8080/mcp\""));
                }
                Kind::Opencode => {
                    assert!(joined.contains("--model deepseek/m1"));
                    assert!(joined.contains("--standalone"));
                    assert!(
                        env.iter()
                            .any(|(name, _)| name == "OPENCODE_DISABLE_PROJECT_CONFIG")
                    );
                    let config = std::fs::read_to_string(dir.join("opencode.json")).unwrap();
                    assert!(config.contains("{env:LORE_AGENT_TOKEN}"));
                }
            }
        }
        assert_eq!(
            lore_origin("http://lore:8080/git/github/o/r.git"),
            "http://lore:8080"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A follow-up question resumes the CLI's own session, in the form
    /// each CLI's `--help` documents; a conversation may run outside a git
    /// checkout.
    #[test]
    fn a_follow_up_resumes_each_cli_s_session() {
        let dir = std::env::temp_dir().join(format!("lore-runs-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let turn = Turn {
            chat: true,
            resume: Some("sess-42"),
        };
        let run = |kind| {
            cli_arguments(
                kind,
                "deepseek",
                Some("m1"),
                "the question",
                "http://lore:8080/mcp",
                "r2",
                Path::new("/work/conv-1/chat"),
                &dir,
                &turn,
            )
            .unwrap()
            .0
        };
        let claude = run(Kind::Claude);
        assert!(claude.join(" ").contains("--resume sess-42"));
        let codex = run(Kind::Codex);
        assert_eq!(&codex[..3], ["exec", "resume", "--json"]);
        assert!(!codex.contains(&"-C".to_string()) && !codex.contains(&"-s".to_string()));
        assert!(codex.contains(&"--skip-git-repo-check".to_string()));
        assert!(codex.contains(&"sandbox_mode=\"danger-full-access\"".to_string()));
        // The session id, then the prompt, last.
        assert_eq!(&codex[codex.len() - 2..], ["sess-42", "the question"]);
        let opencode = run(Kind::Opencode);
        assert!(opencode.join(" ").contains("--session sess-42"));
        assert_eq!(opencode.last().unwrap(), "the question");
        // A fresh conversation: Codex skips its git check, nothing resumes.
        let fresh = cli_arguments(
            Kind::Codex,
            "openai",
            None,
            "q",
            "http://lore:8080/mcp",
            "r3",
            Path::new("/work/conv-1/chat"),
            &dir,
            &Turn {
                chat: true,
                resume: None,
            },
        )
        .unwrap()
        .0;
        assert_eq!(&fresh[..2], ["exec", "--json"]);
        assert!(fresh.contains(&"--skip-git-repo-check".to_string()));
        assert!(!valid_session_id("--dangerous") && !valid_session_id("a b"));
        assert!(valid_session_id("ses_01JX.abc-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_last_message_is_the_answer() {
        let claude = parse_event(
            Kind::Claude,
            r#"{"type":"result","subtype":"success","is_error":false,"num_turns":2,"result":"It lives in src/db.rs.","session_id":"s"}"#,
        );
        assert_eq!(claude.answer.as_deref(), Some("It lives in src/db.rs."));
        let codex = parse_event(
            Kind::Codex,
            r#"{"type":"item.completed","item":{"id":"i","type":"agent_message","text":"Yes."}}"#,
        );
        assert_eq!(codex.answer.as_deref(), Some("Yes."));
        let opencode = parse_event(
            Kind::Opencode,
            r#"{"type":"text","sessionID":"s","part":{"type":"text","text":"No."}}"#,
        );
        assert_eq!(opencode.answer.as_deref(), Some("No."));
        assert!(
            parse_event(Kind::Codex, r#"{"type":"turn.started"}"#)
                .answer
                .is_none()
        );
    }
}
