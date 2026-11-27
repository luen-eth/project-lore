//! `lore runner`: the supervisor inside a built-in agent's container.
//!
//! It dials out to lore over the compose network (a WebSocket to
//! `/runner/ws` on lore's internal listener), says who it is, and then
//! carries out lore's commands with the CLI it was built with: report the
//! sign-in state, sign in and out, list the models, open terminals
//! (`terminal`), and run the CLI on a task (`runs`). lore never reaches into
//! the container: no Docker socket, no inbound port. When the link drops
//! the runner dials again, waiting a little longer each time.
//!
//! Configuration, from the environment:
//! - `LORE_RUNNER_TOKEN` (required), or `LORE_RUNNER_TOKEN_FILE` naming a
//!   file that holds it: this runner's secret, the same value lore has for
//!   it in `LORE_RUNNER_TOKENS`. Both variables are removed from the
//!   runner's environment once read, and the runner makes itself
//!   non-dumpable, so the CLI cannot read the secret from `/proc`.
//! - `LORE_RUNNER_STATE`: the runner's own directory (stored sign-in,
//!   transcripts). When set, every CLI command runs in a fresh home under
//!   `<work>/.homes` (see `drivers::Isolation`); the image sets it.
//! - `LORE_RUNNER_AGENT_UID`, `LORE_RUNNER_AGENT_GID`: the unprivileged
//!   user the CLI runs as. The runner must then run as root with only the
//!   capabilities `SETUID`, `SETGID` and `CHOWN`; a runner running as root
//!   without an agent user refuses to start (see `sandbox`).
//! - `LORE_RUNNER_KIND`: `claude`, `codex` or `opencode`; by default what
//!   the image was built for (`LORE_RUNNER_IMAGE_AGENT`, where `deepseek`
//!   means opencode pointed at DeepSeek).
//! - `LORE_RUNNER_PROVIDER`: the model provider; `anthropic`, `openai`, or
//!   for opencode `deepseek` by default.
//! - `LORE_RUNNER_AGENT`: the agent name; `claude-builtin`,
//!   `codex-builtin`, or `<provider>-builtin` for opencode by default.
//! - `LORE_RUNNER_URL`: default `ws://lore:8081/runner/ws`.
//! - `LORE_RUNNER_HOME`: the agent's home volume; default `$HOME`.
//! - `LORE_RUNNER_CLI`: the CLI executable; default the kind's name.
//! - `LORE_RUNNER_WORK`: where runs clone their repositories; default
//!   `/work`. `LORE_RUNNER_GIT`: the git executable; default `git`.
//! - `LORE_RUNNER_EXEC_TMP`: for opencode, a small mount that allows exec,
//!   where each fresh home gets the directory Bun (`BUN_TMPDIR`) extracts
//!   its native library to; `/work` and `/tmp` stay noexec.

pub mod drivers;
pub mod protocol;
pub mod proxy;
pub mod runs;
pub mod sandbox;
pub mod terminal;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest, http::HeaderValue};

use drivers::{Driver, Fresh, Isolation, Settings};
use protocol::{FromRunner, Kind, PROTOCOL_VERSION, Resources, Secret, ToRunner};

/// The header that names the agent a runner speaks for.
pub const AGENT_HEADER: &str = "x-lore-runner";

/// The link is taken as dead after this long without a frame from lore
/// (lore pings every 30 seconds).
const SILENCE_LIMIT: Duration = Duration::from_secs(90);

/// Resource readings are sent this often.
const RESOURCES_EVERY: Duration = Duration::from_secs(60);

/// The janitor looks for leftovers this often while the container is idle
/// (and after every run, terminal and sign-in).
const JANITOR_EVERY: Duration = Duration::from_secs(10 * 60);

/// The runner renews an interactive sign-in in a clean moment this often
/// (runs never give a renewed credential back).
const RENEW_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// Longest wait between two connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Everything the runner is configured with.
#[derive(Clone)]
pub struct Config {
    pub url: String,
    pub token: Secret,
    pub agent: String,
    pub settings: Settings,
    /// Where runs clone their repositories (part 6b): `/work/<run id>`.
    pub work: PathBuf,
    /// The git executable runs use (`LORE_RUNNER_GIT`, default `git`).
    pub git: PathBuf,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("url", &self.url)
            .field("token", &"[redacted]")
            .field("agent", &self.agent)
            .field("settings", &self.settings)
            .finish()
    }
}

/// The default provider of a kind.
pub fn default_provider(kind: Kind) -> &'static str {
    match kind {
        Kind::Claude => "anthropic",
        Kind::Codex => "openai",
        Kind::Opencode => "deepseek",
    }
}

/// The default agent name of a kind and provider.
pub fn default_agent(kind: Kind, provider: &str) -> String {
    match kind {
        Kind::Claude => "claude-builtin".into(),
        Kind::Codex => "codex-builtin".into(),
        Kind::Opencode => format!("{provider}-builtin"),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let token = sandbox::take_secret("LORE_RUNNER_TOKEN", "LORE_RUNNER_TOKEN_FILE")?
            .context("LORE_RUNNER_TOKEN (or LORE_RUNNER_TOKEN_FILE) is not set")?;
        if token.len() < 24 {
            bail!("LORE_RUNNER_TOKEN must be at least 24 characters (openssl rand -hex 32)");
        }
        // The image says which agent it was built for (`AGENT` build
        // argument): claude, codex or deepseek.
        let image = var("LORE_RUNNER_IMAGE_AGENT").unwrap_or_default();
        let (image_kind, image_provider) = match image.as_str() {
            "claude" => (Some("claude"), None),
            "codex" => (Some("codex"), None),
            "" => (None, None),
            provider => (Some("opencode"), Some(provider.to_string())),
        };
        let kind_name = var("LORE_RUNNER_KIND")
            .or_else(|| image_kind.map(str::to_string))
            .context("LORE_RUNNER_KIND is not set")?;
        let kind = Kind::parse(&kind_name)
            .context("LORE_RUNNER_KIND must be claude, codex or opencode")?;
        let provider = var("LORE_RUNNER_PROVIDER")
            .or(image_provider.filter(|_| kind == Kind::Opencode))
            .unwrap_or_else(|| default_provider(kind).into())
            .to_lowercase();
        if provider.is_empty()
            || !provider
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            bail!("LORE_RUNNER_PROVIDER must be a plain provider id such as deepseek");
        }
        let agent = var("LORE_RUNNER_AGENT")
            .unwrap_or_else(|| default_agent(kind, &provider))
            .to_lowercase();
        let home = var("LORE_RUNNER_HOME")
            .or_else(|| var("HOME"))
            .map(PathBuf::from)
            .context("set LORE_RUNNER_HOME or HOME")?;
        Ok(Self {
            url: var("LORE_RUNNER_URL").unwrap_or_else(|| "ws://lore:8081/runner/ws".into()),
            token: Secret::new(token),
            agent,
            settings: Settings {
                kind,
                provider,
                home,
                program: var("LORE_RUNNER_CLI")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(kind.program())),
            },
            work: var("LORE_RUNNER_WORK")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/work")),
            git: var("LORE_RUNNER_GIT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("git")),
        })
    }
}

/// How CLI commands are kept apart, from `LORE_RUNNER_STATE` and
/// `LORE_RUNNER_AGENT_UID` / `_GID`. Changes `settings.home` to the
/// runner's own home inside the state directory when fresh homes are used.
pub fn isolation_from_env(settings: &mut Settings, work: &std::path::Path) -> Result<Isolation> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let user = sandbox::AgentUser::from_values(
        var("LORE_RUNNER_AGENT_UID").as_deref(),
        var("LORE_RUNNER_AGENT_GID").as_deref(),
    )?;
    let root = sandbox::can_switch_user();
    if root && user.is_none() {
        bail!(
            "the runner runs as root but LORE_RUNNER_AGENT_UID is not set: the CLI must never run \
             as root"
        );
    }
    if user.is_some() && !root {
        bail!(
            "LORE_RUNNER_AGENT_UID is set but the runner is not root: it needs root with the \
             capabilities SETUID, SETGID and CHOWN to start the CLI as the agent user"
        );
    }
    let Some(state) = var("LORE_RUNNER_STATE").map(PathBuf::from) else {
        if user.is_some() {
            bail!("LORE_RUNNER_AGENT_UID needs LORE_RUNNER_STATE too");
        }
        return Ok(Isolation::Shared);
    };
    settings.home = state.join("home");
    sandbox::make_dir(&settings.home, 0o700)?;
    let exec_tmp = var("LORE_RUNNER_EXEC_TMP").map(PathBuf::from);
    if exec_tmp.is_none() && settings.kind == Kind::Opencode {
        tracing::warn!(
            "LORE_RUNNER_EXEC_TMP is not set: opencode's interface cannot load its native \
             library from /work, which is noexec. Add the exec tmpfs (/run/lore-exec) and \
             LORE_RUNNER_EXEC_TMP=/run/lore-exec to this agent's service, as \
             docker-compose.agents.yml does"
        );
    }
    if let Some(root) = &exec_tmp
        && !root.is_absolute()
    {
        bail!("LORE_RUNNER_EXEC_TMP must be an absolute path");
    }
    Ok(Isolation::Fresh(Fresh {
        state,
        homes: work.join(".homes"),
        exec_tmp,
        user,
    }))
}

/// `lore runner`: connects for ever.
pub async fn main_from_env() -> Result<()> {
    // First of all: closed to every other process, the CLI's included.
    sandbox::harden()?;
    let mut config = Config::from_env()?;
    let isolation = isolation_from_env(&mut config.settings, &config.work)?;
    tracing::info!(
        agent = %config.agent,
        kind = config.settings.kind.id(),
        provider = %config.settings.provider,
        url = %config.url,
        isolation = match &isolation {
            Isolation::Shared => "one home",
            Isolation::Fresh(Fresh { user: Some(_), .. }) => "fresh homes, agent user",
            Isolation::Fresh(Fresh { user: None, .. }) => "fresh homes, one user",
        },
        "runner starting"
    );
    if let Isolation::Fresh(Fresh { user: Some(_), .. }) = &isolation {
        // The work area is the runner's: the agent user gets only what is
        // handed to it.
        sandbox::make_dir(&config.work, 0o711)?;
    }
    let driver = Arc::new(Driver::with_isolation(config.settings.clone(), isolation));
    if let Err(error) = driver.prepare() {
        tracing::warn!(%error, "preparing the CLI's state directory failed");
    }
    // Whatever an earlier runner left under /work goes now.
    driver.clean_leftovers().await;
    {
        // While idle: leftovers every ten minutes, a clean sign-in renewal
        // every six hours (the first one after ten minutes).
        let driver = driver.clone();
        tokio::spawn(async move {
            let mut janitor = tokio::time::interval(JANITOR_EVERY);
            let start = tokio::time::Instant::now() + JANITOR_EVERY;
            let mut renew = tokio::time::interval_at(start, RENEW_EVERY);
            loop {
                tokio::select! {
                    _ = janitor.tick() => {
                        driver.clean_leftovers().await;
                    }
                    _ = renew.tick() => match driver.renew_sign_in().await {
                        Ok(true) => tracing::info!("a renewed sign-in was stored"),
                        Ok(false) => {}
                        Err(error) => tracing::warn!(%error, "renewing the sign-in failed"),
                    },
                }
            }
        });
    }
    // One for the process: a run still being cleaned up after the link
    // dropped stays here, and keeps the container, until it is done.
    let registry = runs::Registry::default();
    let mut backoff = Duration::from_secs(1);
    loop {
        match session(&config, driver.clone(), registry.clone()).await {
            Ok(End::Closed) => {
                tracing::info!("the link to lore closed; dialling again");
                backoff = Duration::from_secs(1);
            }
            Ok(End::Refused(reason)) => {
                tracing::error!(%reason, "lore refused this runner");
                backoff = Duration::from_secs(60);
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "the link to lore failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// How a session ended without an error.
#[derive(Debug, PartialEq, Eq)]
pub enum End {
    Closed,
    Refused(String),
}

/// One connection: the handshake, then commands until the link drops.
pub async fn session(
    config: &Config,
    driver: Arc<Driver>,
    registry: runs::Registry,
) -> Result<End> {
    let mut request = config
        .url
        .as_str()
        .into_client_request()
        .context("LORE_RUNNER_URL is not a ws:// URL")?;
    request.headers_mut().insert(
        tungstenite::http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", config.token.expose()))
            .context("the runner token holds characters a header cannot")?,
    );
    request.headers_mut().insert(
        AGENT_HEADER,
        HeaderValue::from_str(&config.agent).context("the agent name is not a plain name")?,
    );
    let ws_config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(protocol::MAX_FRAME_BYTES))
        .max_frame_size(Some(protocol::MAX_FRAME_BYTES));
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false),
    )
    .await
    .context("connecting took too long")?
    .context("connecting to lore")?;
    let (mut sink, mut stream) = socket.split();

    let hello = FromRunner::Hello {
        protocol: PROTOCOL_VERSION,
        agent: config.agent.clone(),
        kind: driver.kind(),
        provider: config.settings.provider.clone(),
        runner_version: env!("CARGO_PKG_VERSION").into(),
        cli_version: driver.version().await,
    };
    sink.send(Message::text(protocol::encode(&hello))).await?;
    let welcome = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(frame) = stream.next().await {
            match frame? {
                Message::Text(text) => return Ok(Some(protocol::decode::<ToRunner>(&text)?)),
                Message::Close(_) => return Ok(None),
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(None)
    })
    .await
    .context("lore did not answer the hello")??;
    match welcome {
        Some(ToRunner::Welcome { .. }) => {}
        Some(ToRunner::Refused { reason }) => return Ok(End::Refused(reason)),
        Some(_) => bail!("lore answered the hello with something else"),
        None => return Ok(End::Closed),
    }
    tracing::info!("connected to lore");

    let (out_tx, mut out_rx) = mpsc::channel::<FromRunner>(256);
    // Closed with the link: dropping it kills every terminal's session.
    let terminals =
        terminal::Terminals::new(driver.clone(), out_tx.clone(), terminal::Limits::default());
    // Closed with the link too: dropping it stops the run, which still
    // cleans up before it frees the container.
    let runs = runs::Runs::new(
        driver.clone(),
        out_tx.clone(),
        config.work.clone(),
        config.git.clone(),
        config.agent.clone(),
        registry,
    );
    {
        let (driver, out) = (driver.clone(), out_tx.clone());
        tokio::spawn(async move {
            let _ = out.send(driver.status(None).await).await;
        });
    }
    let mut resources = tokio::time::interval(RESOURCES_EVERY);
    let mut last_heard = tokio::time::Instant::now();
    let mut silence = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            frame = stream.next() => {
                let Some(frame) = frame else { return Ok(End::Closed) };
                last_heard = tokio::time::Instant::now();
                match frame? {
                    Message::Text(text) => match protocol::decode::<ToRunner>(&text) {
                        Ok(command) => {
                            // Terminal commands are carried out in order,
                            // here; everything else in a task of its own.
                            if let Some(command) = terminals
                                .handle(command)
                                .and_then(|command| runs.handle(command))
                            {
                                handle(command, &driver, &out_tx);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "a command from lore could not be read");
                            let _ = out_tx.try_send(FromRunner::Error {
                                id: None,
                                message: format!("unreadable command: {error}"),
                            });
                        }
                    },
                    Message::Close(_) => return Ok(End::Closed),
                    _ => {}
                }
            }
            Some(message) = out_rx.recv() => {
                sink.send(Message::text(protocol::encode(&message))).await?;
            }
            _ = resources.tick() => {
                // Off the link's loop: the volume's size is a walk of its
                // files (bounded), and `df` is a process.
                let (driver, work, out) = (driver.clone(), config.work.clone(), out_tx.clone());
                tokio::spawn(async move {
                    let mut reading = read_resources(&work).await;
                    if driver.is_fresh() {
                        let state = driver.state_path();
                        reading.state_free_bytes = free_bytes(&state).await;
                        let measuring = driver.clone();
                        reading.state_bytes = tokio::time::timeout(
                            Duration::from_secs(20),
                            tokio::task::spawn_blocking(move || measuring.state_bytes()),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok);
                    }
                    let (cleaned, cleaned_at) = driver.cleaned();
                    reading.cleaned = Some(cleaned);
                    reading.cleaned_at = cleaned_at;
                    let _ = out.try_send(FromRunner::Resources(reading));
                });
            }
            _ = silence.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT {
                    bail!("nothing heard from lore for {} seconds", SILENCE_LIMIT.as_secs());
                }
            }
        }
    }
}

/// Carries out one command in its own task, so a slow CLI never holds the
/// link up.
fn handle(command: ToRunner, driver: &Arc<Driver>, out: &mpsc::Sender<FromRunner>) {
    let (driver, out) = (driver.clone(), out.clone());
    tokio::spawn(async move {
        let answer = match command {
            ToRunner::Welcome { .. } | ToRunner::Refused { .. } => return,
            ToRunner::Ping { id } => FromRunner::Pong { id },
            ToRunner::Status { id } => driver.status(Some(id)).await,
            ToRunner::ListModels { id } => {
                let (models, source) = driver.models().await;
                FromRunner::Models {
                    id,
                    models,
                    source: source.into(),
                }
            }
            ToRunner::LoginStart { id, method } => {
                match driver.login_start(id, method, out.clone()).await {
                    Ok(()) => return,
                    Err(error) => FromRunner::Error {
                        id: Some(id),
                        message: driver.redact(&format!("{error:#}")),
                    },
                }
            }
            ToRunner::LoginCode { id, code } => match driver.login_code(&code).await {
                Ok(()) => FromRunner::Done {
                    id,
                    ok: true,
                    message: "the code was passed to the sign-in".into(),
                },
                Err(error) => FromRunner::Error {
                    id: Some(id),
                    message: error.to_string(),
                },
            },
            ToRunner::LoginCancel { id } => {
                let cancelled = driver.cancel_login().await;
                FromRunner::Done {
                    id,
                    ok: true,
                    message: if cancelled {
                        "the sign-in was cancelled".into()
                    } else {
                        "no sign-in was running".into()
                    },
                }
            }
            ToRunner::SetCredential {
                id,
                credential,
                value,
            } => {
                let answer = match driver.set_credential(credential, &value).await {
                    Ok(message) => FromRunner::Done {
                        id,
                        ok: true,
                        message,
                    },
                    Err(error) => FromRunner::Error {
                        id: Some(id),
                        message: drivers::redact_with(
                            &error.to_string(),
                            &[value.expose().to_string()],
                        ),
                    },
                };
                let _ = out.send(answer).await;
                driver.status(None).await
            }
            ToRunner::Logout { id } => {
                let answer = match driver.logout().await {
                    Ok(message) => FromRunner::Done {
                        id,
                        ok: true,
                        message,
                    },
                    Err(error) => FromRunner::Error {
                        id: Some(id),
                        message: error.to_string(),
                    },
                };
                let _ = out.send(answer).await;
                driver.status(None).await
            }
            // Follow-up messages to a running CLI belong to part 6c.
            ToRunner::RunInput { run_id, .. } => FromRunner::Unsupported {
                command: "run_input".into(),
                target: Some(run_id),
            },
            // `session` gives these to its `Runs` before they reach here.
            ToRunner::RunStart { spec } => FromRunner::Unsupported {
                command: "run_start".into(),
                target: Some(spec.run_id),
            },
            ToRunner::RunStop { run_id } | ToRunner::CleanWorkdir { run_id } => {
                FromRunner::Unsupported {
                    command: "run".into(),
                    target: Some(run_id),
                }
            }
            // `session` gives these to its `Terminals` before they reach
            // here.
            ToRunner::TerminalOpen { term_id, .. }
            | ToRunner::TerminalInput { term_id, .. }
            | ToRunner::TerminalResize { term_id, .. }
            | ToRunner::TerminalClose { term_id } => FromRunner::Unsupported {
                command: "terminal".into(),
                target: Some(term_id),
            },
        };
        let _ = out.send(answer).await;
    });
}

/// Reads the load, the container's memory and the free space for runs.
/// Anything that cannot be read is left out.
pub async fn read_resources(work: &std::path::Path) -> Resources {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let load = read("/proc/loadavg").and_then(|text| text.split_whitespace().next()?.parse().ok());
    let mem_used_bytes = read("/sys/fs/cgroup/memory.current").and_then(|t| t.trim().parse().ok());
    let mem_limit_bytes = read("/sys/fs/cgroup/memory.max").and_then(|t| t.trim().parse().ok());
    Resources {
        load,
        mem_used_bytes,
        mem_limit_bytes,
        work_free_bytes: free_bytes(work).await,
        ..Resources::default()
    }
}

/// Free space where `path` is, from `df`.
async fn free_bytes(path: &std::path::Path) -> Option<u64> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("df")
            .args(["-Pk"])
            .arg(path)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = text.lines().nth(1)?.to_string();
    let available: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(available * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn commands_of_later_parts_are_answered_as_unsupported() {
        let home =
            std::env::temp_dir().join(format!("lore-runner-unsupported-{}", std::process::id()));
        let driver = Arc::new(Driver::new(Settings {
            kind: Kind::Claude,
            provider: "anthropic".into(),
            home,
            program: PathBuf::from("/nonexistent/claude"),
        }));
        let (tx, mut rx) = mpsc::channel(4);
        handle(
            ToRunner::RunInput {
                run_id: "r1".into(),
                text: "more".into(),
            },
            &driver,
            &tx,
        );
        assert_eq!(
            rx.recv().await,
            Some(FromRunner::Unsupported {
                command: "run_input".into(),
                target: Some("r1".into()),
            })
        );
        handle(
            ToRunner::TerminalClose {
                term_id: "t1".into(),
            },
            &driver,
            &tx,
        );
        assert!(matches!(
            rx.recv().await,
            Some(FromRunner::Unsupported { command, .. }) if command == "terminal"
        ));
        // A CLI that cannot be started is reported, not fatal.
        handle(ToRunner::Status { id: 4 }, &driver, &tx);
        assert!(matches!(
            rx.recv().await,
            Some(FromRunner::Status {
                id: Some(4),
                signed_in: false,
                cli_version: None,
                ..
            })
        ));
    }

    #[test]
    fn default_names_follow_the_kind_and_provider() {
        assert_eq!(
            default_agent(Kind::Opencode, "deepseek"),
            "deepseek-builtin"
        );
        assert_eq!(default_agent(Kind::Codex, "openai"), "codex-builtin");
        assert_eq!(default_provider(Kind::Opencode), "deepseek");
    }
}
