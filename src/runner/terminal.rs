//! Terminals: a PTY inside the agent's container, relayed over the runner
//! link so the admin page can show it (part 6d).
//!
//! A terminal runs the CLI's own interactive interface or a shell, as the
//! agent user in its home, with the same cleared environment as every
//! other CLI command (plus the agent's stored credentials, so the CLI is
//! signed in). Its bytes go to lore as they are: a terminal cannot be
//! redacted reliably, so lore only lets the `agents` permission open one.
//!
//! Each terminal gets its own session (`setsid`) with the PTY as its
//! controlling terminal. Closing it, its idle limit, or the link dropping
//! kills that whole session: the program, its process group, and anything
//! it started in another group (a shell's background jobs). At most
//! [`MAX_TERMINALS`] are open at once; one without input and without anyone
//! looking (the page sends an empty input every minute while it is shown)
//! is closed after [`IDLE_LIMIT`].

use std::{
    collections::HashMap,
    io,
    os::fd::{BorrowedFd, OwnedFd},
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use base64::Engine;
use rustix::{
    fs::{Mode, OFlags},
    process::{Pid, Signal},
    pty::OpenptFlags,
    termios::Winsize,
};
use tokio::{io::unix::AsyncFd, process::Child, sync::mpsc, time::Instant};

use super::{
    drivers::{CliHome, Driver, Source},
    protocol::{FromRunner, TerminalMcp, TerminalMode, ToRunner},
    sandbox::Occupancy,
};

/// Terminals one runner keeps open at once.
pub const MAX_TERMINALS: usize = 2;

/// A terminal with no input and nobody looking is closed after this long.
pub const IDLE_LIMIT: Duration = Duration::from_secs(15 * 60);

/// Most bytes read from a terminal per frame.
const READ_CHUNK: usize = 16 * 1024;

/// Typed input waiting for a terminal that does not read it; more is
/// dropped.
const INPUT_QUEUE: usize = 1024;

/// Output still read after the program ended (what it printed last).
const DRAIN_LIMIT: usize = 1024 * 1024;

/// Smallest and largest window accepted.
const MIN_SIZE: u16 = 2;
const MAX_SIZE: u16 = 1000;

/// What the terminals are allowed.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max: usize,
    pub idle: Duration,
    /// The shell a `shell` terminal runs.
    pub shell: PathBuf,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max: MAX_TERMINALS,
            idle: IDLE_LIMIT,
            shell: PathBuf::from("bash"),
        }
    }
}

/// What lore asked of one open terminal.
enum Command {
    Input(Vec<u8>),
    Resize(u16, u16),
    Close,
}

type Open = Arc<Mutex<HashMap<String, mpsc::Sender<Command>>>>;

/// The terminals of one link. Dropping it (the link closed) closes them
/// all.
pub struct Terminals {
    driver: Arc<Driver>,
    out: mpsc::Sender<FromRunner>,
    limits: Limits,
    open: Open,
    /// The runner process's: a terminal does not open during a run or a
    /// sign-in.
    occupancy: Arc<Occupancy>,
    /// Held while a terminal opens or closes, so the sweep before the
    /// first one and after the last one never meets another starting.
    turnstile: Arc<tokio::sync::Mutex<()>>,
    /// Homes of terminals that closed while another was still open: what
    /// the owner signed in there is taken back once the last one closes
    /// and nothing of the agent user is left.
    pending: Arc<Mutex<Vec<CliHome>>>,
}

impl Terminals {
    pub fn new(driver: Arc<Driver>, out: mpsc::Sender<FromRunner>, limits: Limits) -> Self {
        let occupancy = driver.occupancy().clone();
        Self {
            driver,
            out,
            limits,
            open: Arc::default(),
            occupancy,
            turnstile: Arc::default(),
            pending: Arc::default(),
        }
    }

    fn open(&self) -> std::sync::MutexGuard<'_, HashMap<String, mpsc::Sender<Command>>> {
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many terminals are open.
    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.open().len()
    }

    /// Takes a terminal command and returns any other command untouched.
    /// Called in the order the link delivers commands, so typed bytes keep
    /// their order.
    pub fn handle(&self, command: ToRunner) -> Option<ToRunner> {
        match command {
            ToRunner::TerminalOpen {
                term_id,
                mode,
                cols,
                rows,
                model,
                mcp,
            } => self.start(term_id, mode, cols, rows, model, mcp),
            ToRunner::TerminalInput { term_id, data } => {
                match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
                    Ok(bytes) => self.send(&term_id, Command::Input(bytes)),
                    Err(_) => tracing::warn!(%term_id, "terminal input that is not base64"),
                }
            }
            ToRunner::TerminalResize {
                term_id,
                cols,
                rows,
            } => self.send(&term_id, Command::Resize(cols, rows)),
            ToRunner::TerminalClose { term_id } => self.send(&term_id, Command::Close),
            other => return Some(other),
        }
        None
    }

    fn send(&self, term_id: &str, command: Command) {
        let sender = self.open().get(term_id).cloned();
        match sender {
            Some(sender) => {
                if sender.try_send(command).is_err() {
                    tracing::warn!(%term_id, "a terminal is not reading its input; input dropped");
                }
            }
            None => {
                if matches!(command, Command::Close) {
                    self.exit(term_id.to_string(), None, Some("no such terminal".into()));
                }
            }
        }
    }

    /// Reports a terminal that ended without having run.
    fn exit(&self, term_id: String, code: Option<i32>, message: Option<String>) {
        let out = self.out.clone();
        tokio::spawn(async move {
            let _ = out
                .send(FromRunner::TerminalExit {
                    term_id,
                    code,
                    message,
                })
                .await;
        });
    }

    fn start(
        &self,
        term_id: String,
        mode: TerminalMode,
        cols: u16,
        rows: u16,
        model: Option<String>,
        mcp: Option<TerminalMcp>,
    ) {
        let mut open = self.open();
        if open.contains_key(&term_id) {
            drop(open);
            self.exit(term_id, None, Some("that terminal is already open".into()));
            return;
        }
        if open.len() >= self.limits.max {
            drop(open);
            self.exit(
                term_id,
                None,
                Some(format!(
                    "this agent already has {} terminals open; close one first",
                    self.limits.max
                )),
            );
            return;
        }
        let first = match self.occupancy.open_terminal() {
            Ok(first) => first,
            Err(why) => {
                drop(open);
                self.exit(term_id, None, Some(why.into()));
                return;
            }
        };
        // Input typed while the terminal starts waits for it.
        let (tx, rx) = mpsc::channel(INPUT_QUEUE);
        open.insert(term_id.clone(), tx);
        drop(open);
        let (out, registry, idle, shell) = (
            self.out.clone(),
            self.open.clone(),
            self.limits.idle,
            self.limits.shell.clone(),
        );
        let (driver, occupancy, turnstile, pending) = (
            self.driver.clone(),
            self.occupancy.clone(),
            self.turnstile.clone(),
            self.pending.clone(),
        );
        tokio::spawn(async move {
            let spawned = {
                let _turn = turnstile.lock().await;
                // The first terminal finds no process of the agent user:
                // nothing a run or a sign-in left can watch it.
                if first {
                    driver.sweep().await;
                }
                driver
                    .terminal_home(mode, model.as_deref())
                    .and_then(|mut home| {
                        // Only the CLI's interactive interface needs the exec
                        // mount (opencode's renderer); a shell never gets it.
                        if mode == TerminalMode::Cli {
                            driver.give_exec_tmp(&mut home)?;
                        }
                        let (child, master) = spawn(
                            &driver,
                            mode,
                            model.as_deref(),
                            mcp.as_ref(),
                            &shell,
                            size(cols, rows),
                            &home,
                        )?;
                        Ok((child, master, home))
                    })
            };
            let (child, master, home) = match spawned {
                Ok(spawned) => spawned,
                Err(error) => {
                    registry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&term_id);
                    occupancy.close_terminal();
                    let message = driver.redact(&format!("{error:#}"));
                    tracing::warn!(%term_id, %message, "a terminal could not be opened");
                    // The page shows the cause in words; the container's
                    // paths tell the owner nothing and stay in the log.
                    let message = format!(
                        "the terminal could not be opened: {}",
                        without_paths(&message)
                    );
                    let _ = out
                        .send(FromRunner::TerminalExit {
                            term_id,
                            code: None,
                            message: Some(message),
                        })
                        .await;
                    return;
                }
            };
            tracing::info!(%term_id, mode = ?mode, "a terminal opened");
            let (code, message) = run(&term_id, child, master, rx, &out, idle).await;
            registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&term_id);
            finish(&driver, &occupancy, &turnstile, &pending, home).await;
            tracing::info!(%term_id, ?code, "a terminal closed");
            let _ = out
                .send(FromRunner::TerminalExit {
                    term_id,
                    code,
                    message,
                })
                .await;
        });
    }
}

impl Drop for Terminals {
    fn drop(&mut self) {
        // Each terminal's task sees its command channel close and kills
        // its session.
        self.open().clear();
    }
}

/// A message with every absolute path replaced by "a path".
fn without_paths(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            if word.starts_with('/') {
                let tail: String = word
                    .chars()
                    .rev()
                    .take_while(|c| matches!(c, ':' | ',' | ')'))
                    .collect();
                format!("a path{}", tail.chars().rev().collect::<String>())
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn size(cols: u16, rows: u16) -> Winsize {
    Winsize {
        ws_row: rows.clamp(MIN_SIZE, MAX_SIZE),
        ws_col: cols.clamp(MIN_SIZE, MAX_SIZE),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// After a terminal. While another is still open its home waits; when it
/// is the last one, still counted (so no run can start in between), every
/// process of the agent user ends (the runner exits when they cannot), a
/// sign-in the owner made in any of the waiting homes is kept, and the
/// homes go. Nothing is read from a home while a process of the agent
/// user is alive.
async fn finish(
    driver: &Arc<Driver>,
    occupancy: &Occupancy,
    turnstile: &tokio::sync::Mutex<()>,
    pending: &Mutex<Vec<CliHome>>,
    home: CliHome,
) {
    let _turn = turnstile.lock().await;
    if occupancy.terminals_open() > 1 {
        pending.lock().unwrap_or_else(|e| e.into_inner()).push(home);
        occupancy.close_terminal();
        return;
    }
    driver.sweep().await;
    let mut homes = std::mem::take(&mut *pending.lock().unwrap_or_else(|e| e.into_inner()));
    homes.push(home);
    for home in homes {
        match driver.harvest(&home, Source::Owner) {
            Ok(true) => tracing::info!("a sign-in made in a terminal was stored"),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "a sign-in made in a terminal could not be stored")
            }
        }
    }
    driver.clean_now();
    occupancy.close_terminal();
}

/// Opens a PTY and starts the program on it, in a session of its own.
fn spawn(
    driver: &Driver,
    mode: TerminalMode,
    model: Option<&str>,
    mcp: Option<&TerminalMcp>,
    shell: &std::path::Path,
    winsize: Winsize,
    home: &CliHome,
) -> Result<(Child, AsyncFd<OwnedFd>)> {
    // Close-on-exec from the start: a process another task starts at the
    // same moment never inherits the master.
    let master =
        rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
            .context("opening a pseudo-terminal")?;
    rustix::pty::grantpt(&master).context("granting the pseudo-terminal")?;
    rustix::pty::unlockpt(&master).context("unlocking the pseudo-terminal")?;
    let name = rustix::pty::ptsname(&master, Vec::new()).context("naming the pseudo-terminal")?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening the terminal side of the pseudo-terminal")?;
    rustix::termios::tcsetwinsize(&master, winsize).context("sizing the terminal")?;
    // The master is never inherited by the program.
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;

    let mut command = driver.terminal_command(mode, model, mcp, shell, home)?;
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // SAFETY: between fork and exec only two system calls run, through
    // rustix, which neither allocates nor takes locks.
    unsafe {
        command.pre_exec(|| {
            rustix::process::setsid().map_err(io::Error::from)?;
            rustix::process::ioctl_tiocsctty(BorrowedFd::borrow_raw(0)).map_err(io::Error::from)?;
            Ok(())
        });
    }
    let child = command
        .spawn()
        .with_context(|| format!("starting the {mode:?} terminal"))?;
    // The program holds the terminal side now; ours must close, or the
    // end of the program would never show as the end of its output.
    drop(command);
    rustix::io::ioctl_fionbio(&master, true)?;
    // SAFETY: the `OwnedFd` is moved into the `AsyncFd`, which keeps it
    // open, and always the same descriptor, until it is dropped.
    let master = unsafe { AsyncFd::register(master) }.map_err(io::Error::from)?;
    Ok((child, master))
}

/// Relays one terminal until it ends; answers its exit code and, when it
/// did not end by itself, why it was closed.
async fn run(
    term_id: &str,
    mut child: Child,
    master: AsyncFd<OwnedFd>,
    mut commands: mpsc::Receiver<Command>,
    out: &mpsc::Sender<FromRunner>,
    idle: Duration,
) -> (Option<i32>, Option<String>) {
    let session = child.id().and_then(|pid| Pid::from_raw(pid as i32));
    let mut buffer = vec![0u8; READ_CHUNK];
    let mut last_active = Instant::now();
    let mut code = None;
    let mut exited = false;
    let mut message = None;
    loop {
        tokio::select! {
            read = read_some(&master, &mut buffer) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.send(output(term_id, &buffer[..n])).await.is_err() {
                        message = Some("the link to lore closed".to_string());
                        break;
                    }
                }
            },
            status = child.wait(), if !exited => {
                exited = true;
                code = status.ok().and_then(|status| status.code());
                // What it printed last is still in the terminal.
                let mut drained = 0;
                while drained < DRAIN_LIMIT {
                    match tokio::time::timeout(
                        Duration::from_millis(200),
                        read_some(&master, &mut buffer),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            drained += n;
                            if out.send(output(term_id, &buffer[..n])).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                break;
            }
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => {
                    last_active = Instant::now();
                    if !bytes.is_empty() && write_all(&master, &bytes).await.is_err() {
                        break;
                    }
                }
                Some(Command::Resize(cols, rows)) => {
                    last_active = Instant::now();
                    let _ = rustix::termios::tcsetwinsize(master.get_ref(), size(cols, rows));
                }
                Some(Command::Close) => {
                    message = Some("closed".to_string());
                    break;
                }
                None => {
                    message = Some("the link to lore closed".to_string());
                    break;
                }
            },
            _ = tokio::time::sleep_until(last_active + idle) => {
                message = Some(format!(
                    "closed after {} minutes without input and without anyone looking",
                    idle.as_secs() / 60
                ));
                break;
            }
        }
    }
    // Whatever is left of the session goes, before the program is reaped
    // (so its id cannot have been handed to another process yet).
    if let Some(session) = session {
        kill_session(session);
    }
    drop(master);
    if !exited {
        code = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => status.code(),
            _ => {
                let _ = child.kill().await;
                None
            }
        };
    }
    (code, message)
}

fn output(term_id: &str, bytes: &[u8]) -> FromRunner {
    FromRunner::TerminalOutput {
        term_id: term_id.to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

/// Reads what the terminal has; 0 when it is closed (every program on it
/// ended: Linux answers EIO then).
async fn read_some(master: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = master.readable().await?;
        match guard
            .try_io(|fd| rustix::io::read(fd.get_ref(), &mut *buffer).map_err(io::Error::from))
        {
            Ok(Ok(n)) => return Ok(n),
            Ok(Err(error))
                if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
            {
                return Ok(0);
            }
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => continue,
        }
    }
}

async fn write_all(master: &AsyncFd<OwnedFd>, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut guard = master.writable().await?;
        match guard.try_io(|fd| rustix::io::write(fd.get_ref(), bytes).map_err(io::Error::from)) {
            Ok(Ok(n)) => bytes = &bytes[n..],
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// Kills a terminal's or a run's session: its process group, then every
/// process still in the session (a shell's jobs run in groups of their
/// own). Each member found in `/proc` is signalled through a pidfd and only
/// once it is seen, pinned, to still be in the session, so a pid recycled
/// since the scan is never hit.
///
/// The group signal goes by number. For a terminal the session leader is
/// not reaped yet, so the number cannot name anyone else. For a run the CLI
/// (the leader) has already been reaped by then; the kernel still keeps the
/// number reserved while any process remains in that group or session, so
/// the signal can reach a stranger only if the group is already empty and
/// a new process has since taken the number and made itself a group leader.
///
/// This is best effort: a `/proc` that cannot be read finds no member here.
/// It is not the guarantee. With an agent user, after every run and after
/// the last terminal the runner ends every process of that user
/// ([`super::sandbox::sweep`]), whose scan fails closed (the runner exits
/// rather than go on).
pub(super) fn kill_session(session: Pid) {
    let _ = rustix::process::kill_process_group(session, Signal::KILL);
    let sid = session.as_raw_nonzero().get();
    let proc = std::path::Path::new("/proc");
    for pid in session_members(session) {
        let _ =
            super::sandbox::signal_pinned(proc, pid.as_raw_nonzero().get(), Signal::KILL, |dir| {
                Ok(session_of(dir) == Some(sid))
            });
    }
}

/// The session id in the `stat` of the process whose `/proc` directory is
/// `dir`.
fn session_of(dir: &std::path::Path) -> Option<i32> {
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    // `pid (comm) state ppid pgrp session …`; comm may hold spaces.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(3)?.parse().ok()
}

/// The processes whose session is `session`, from `/proc`.
fn session_members(session: Pid) -> Vec<Pid> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            (session_of(&entry.path())? == session.as_raw_nonzero().get())
                .then(|| Pid::from_raw(pid))
                .flatten()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{drivers::Settings, protocol::Kind};

    /// A viewer's keep-alive, as the page's minute tick has lore send it.
    fn keep_alive(term_id: &str) -> ToRunner {
        ToRunner::TerminalInput {
            term_id: term_id.into(),
            data: String::new(),
        }
    }

    fn temp_home(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lore-terminal-{label}-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    struct Bench {
        terminals: Terminals,
        rx: mpsc::Receiver<FromRunner>,
        home: PathBuf,
    }

    fn bench(label: &str, program: Option<&str>, limits: Limits) -> Bench {
        let home = temp_home(label);
        let program = match program {
            Some(body) => script(&home, "fake-cli", body),
            None => PathBuf::from("/nonexistent/claude"),
        };
        let driver = Arc::new(Driver::new(Settings {
            kind: Kind::Claude,
            provider: "anthropic".into(),
            home: home.clone(),
            program,
        }));
        let (tx, rx) = mpsc::channel(256);
        Bench {
            terminals: Terminals::new(driver, tx, limits),
            rx,
            home,
        }
    }

    fn sh() -> Limits {
        Limits {
            shell: PathBuf::from("/bin/sh"),
            ..Limits::default()
        }
    }

    fn open(term_id: &str, mode: TerminalMode, cols: u16, rows: u16) -> ToRunner {
        ToRunner::TerminalOpen {
            term_id: term_id.into(),
            mode,
            cols,
            rows,
            model: Some("opus".into()),
            mcp: None,
        }
    }

    fn input(term_id: &str, text: &str) -> ToRunner {
        ToRunner::TerminalInput {
            term_id: term_id.into(),
            data: base64::engine::general_purpose::STANDARD.encode(text),
        }
    }

    /// What a terminal said until `until` shows in its output or it
    /// exits; the exit, if it came.
    async fn collect(
        rx: &mut mpsc::Receiver<FromRunner>,
        term_id: &str,
        until: &str,
    ) -> (String, Option<(Option<i32>, Option<String>)>) {
        let mut text = String::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let message = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .unwrap_or_else(|_| panic!("waited for {until:?}; got {text:?}"))
                .expect("the output channel closed");
            match message {
                FromRunner::TerminalOutput { term_id: id, data } if id == term_id => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .unwrap();
                    text.push_str(&String::from_utf8_lossy(&bytes));
                    if !until.is_empty() && text.contains(until) {
                        return (text, None);
                    }
                }
                FromRunner::TerminalExit {
                    term_id: id,
                    code,
                    message,
                } if id == term_id => return (text, Some((code, message))),
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn a_shell_echoes_resizes_and_reports_its_exit_code() {
        let mut bench = bench("shell", None, sh());
        assert!(
            bench
                .terminals
                .handle(open("t1", TerminalMode::Shell, 100, 30))
                .is_none()
        );
        bench.terminals.handle(input("t1", "echo ok-$((40+2))\n"));
        collect(&mut bench.rx, "t1", "ok-42").await;
        // The size given at open, then a resize, as the program sees them.
        bench.terminals.handle(input("t1", "stty size\n"));
        collect(&mut bench.rx, "t1", "30 100").await;
        bench.terminals.handle(ToRunner::TerminalResize {
            term_id: "t1".into(),
            cols: 120,
            rows: 40,
        });
        bench.terminals.handle(input("t1", "stty size\n"));
        collect(&mut bench.rx, "t1", "40 120").await;
        // It runs in the agent's home, with a terminal type that has colour.
        bench
            .terminals
            .handle(input("t1", "echo \"at:$PWD:$TERM\"\n"));
        let home = bench.home.display().to_string();
        collect(&mut bench.rx, "t1", &format!("at:{home}:xterm-256color")).await;
        bench.terminals.handle(input("t1", "exit 7\n"));
        let (_, exit) = collect(&mut bench.rx, "t1", "").await;
        assert_eq!(exit, Some((Some(7), None)));
        assert_eq!(bench.terminals.count(), 0);
    }

    #[tokio::test]
    async fn the_cli_gets_its_model_and_credentials_but_never_the_link_secret() {
        let mut bench = bench(
            "cli",
            Some(
                "#!/bin/sh\necho \"args:$*\"\necho \"token:${CLAUDE_CODE_OAUTH_TOKEN:-none}\"\n\
                 echo \"link:${LORE_RUNNER_TOKEN:-none}\"\nread line\necho \"got:$line\"\nexit 3\n",
            ),
            sh(),
        );
        std::fs::create_dir_all(bench.home.join(".lore-runner")).unwrap();
        std::fs::write(
            bench.home.join(".lore-runner/secrets.env"),
            "CLAUDE_CODE_OAUTH_TOKEN=stored-token-value\n",
        )
        .unwrap();
        bench
            .terminals
            .handle(open("c1", TerminalMode::Cli, 80, 24));
        let (mut text, _) = collect(&mut bench.rx, "c1", "link:").await;
        assert!(text.contains("args:--model opus"), "{text}");
        assert!(text.contains("token:stored-token-value"), "{text}");
        bench.terminals.handle(input("c1", "hello\r"));
        let (rest, exit) = collect(&mut bench.rx, "c1", "").await;
        text.push_str(&rest);
        assert!(text.contains("got:hello"), "{text}");
        assert!(text.contains("link:none"), "{text}");
        assert_eq!(exit, Some((Some(3), None)));
    }

    #[tokio::test]
    async fn closing_kills_the_whole_session() {
        let mut bench = bench("close", None, sh());
        bench
            .terminals
            .handle(open("k1", TerminalMode::Shell, 80, 24));
        // A background job runs in a process group of its own.
        bench
            .terminals
            .handle(input("k1", "sleep 300 & echo \"job=$!=\"\n"));
        let (text, _) = collect(&mut bench.rx, "k1", "=\r").await;
        let pid: i32 = text
            .rsplit("job=")
            .next()
            .and_then(|rest| rest.split('=').next())
            .and_then(|pid| pid.parse().ok())
            .unwrap_or_else(|| panic!("{text}"));
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        bench.terminals.handle(ToRunner::TerminalClose {
            term_id: "k1".into(),
        });
        let (_, exit) = collect(&mut bench.rx, "k1", "").await;
        assert_eq!(exit.unwrap().1.as_deref(), Some("closed"));
        let gone = || {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|stat| stat.contains(") Z "))
                .unwrap_or(true)
        };
        for _ in 0..100 {
            if gone() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(gone(), "the background job {pid} survived the close");
        // Closing a terminal that is not open says so.
        bench.terminals.handle(ToRunner::TerminalClose {
            term_id: "k1".into(),
        });
        let (_, exit) = collect(&mut bench.rx, "k1", "").await;
        assert_eq!(exit.unwrap().1.as_deref(), Some("no such terminal"));
    }

    #[tokio::test]
    async fn an_idle_terminal_is_closed_unless_someone_is_looking() {
        let mut bench = bench(
            "idle",
            None,
            Limits {
                idle: Duration::from_millis(600),
                ..sh()
            },
        );
        bench
            .terminals
            .handle(open("i1", TerminalMode::Shell, 80, 24));
        // A viewer's keep-alive holds it open past the limit...
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            bench.terminals.handle(keep_alive("i1"));
        }
        assert_eq!(bench.terminals.count(), 1);
        // ...and without one it closes.
        let started = Instant::now();
        let (_, exit) = collect(&mut bench.rx, "i1", "").await;
        let (_, message) = exit.unwrap();
        assert!(message.unwrap().contains("without input"));
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(bench.terminals.count(), 0);
    }

    #[tokio::test]
    async fn at_most_two_terminals_are_open_and_a_dropped_link_closes_them() {
        let mut bench = bench("cap", None, sh());
        for id in ["a", "b", "c"] {
            bench
                .terminals
                .handle(open(id, TerminalMode::Shell, 80, 24));
        }
        let (_, exit) = collect(&mut bench.rx, "c", "").await;
        let (code, message) = exit.unwrap();
        assert_eq!(code, None);
        assert!(message.unwrap().contains("2 terminals"));
        assert_eq!(bench.terminals.count(), 2);
        // A program that cannot start is reported, not fatal.
        let broken = bench_with_shell("/nonexistent/shell");
        let mut rx = broken.1;
        broken.0.handle(open("x", TerminalMode::Shell, 80, 24));
        let (_, exit) = collect(&mut rx, "x", "").await;
        assert!(exit.unwrap().1.unwrap().contains("starting"));
        // The link went: both terminals end.
        let Bench {
            terminals, mut rx, ..
        } = bench;
        drop(terminals);
        let mut ended = Vec::new();
        while ended.len() < 2 {
            match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
                Ok(Some(FromRunner::TerminalExit { term_id, .. })) => ended.push(term_id),
                Ok(Some(_)) => {}
                other => panic!("{other:?}"),
            }
        }
        ended.sort();
        assert_eq!(ended, vec!["a", "b"]);
    }

    /// A terminal does not open while a run holds the container (ending
    /// every process of the agent user after one would cut the other
    /// short), and in a fresh home it gets its own home, deleted after.
    #[tokio::test]
    async fn no_terminal_during_a_run_and_each_gets_a_fresh_home() {
        use crate::runner::drivers::{Fresh, Isolation};
        let dir = temp_home("fresh");
        let driver = Arc::new(Driver::with_isolation(
            Settings {
                kind: Kind::Claude,
                provider: "anthropic".into(),
                home: dir.join("runner"),
                program: PathBuf::from("/nonexistent/claude"),
            },
            Isolation::Fresh(Fresh {
                exec_tmp: None,
                state: dir.join("state"),
                homes: dir.join("homes"),
                user: None,
            }),
        ));
        driver.prepare().unwrap();
        let occupancy = driver.occupancy().clone();
        occupancy.start_run().unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let terminals = Terminals::new(driver, tx, sh());
        terminals.handle(open("f1", TerminalMode::Shell, 80, 24));
        let (_, exit) = collect(&mut rx, "f1", "").await;
        assert!(exit.unwrap().1.unwrap().contains("a run is going"));
        occupancy.end_run();
        terminals.handle(open("f2", TerminalMode::Shell, 80, 24));
        terminals.handle(input(
            "f2",
            "echo \"home=$HOME=\"; touch \"$HOME/left-behind\"\n",
        ));
        let (text, _) = collect(&mut rx, "f2", "=\r").await;
        assert!(
            text.contains(&dir.join("homes").display().to_string()),
            "{text}"
        );
        // A run cannot start while it is open.
        assert!(occupancy.start_run().is_err());
        terminals.handle(input("f2", "exit\n"));
        collect(&mut rx, "f2", "").await;
        for _ in 0..100 {
            if std::fs::read_dir(dir.join("homes")).unwrap().count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(std::fs::read_dir(dir.join("homes")).unwrap().count(), 0);
        assert!(occupancy.start_run().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn bench_with_shell(shell: &str) -> (Terminals, mpsc::Receiver<FromRunner>) {
        let bench = bench(
            "broken",
            None,
            Limits {
                shell: PathBuf::from(shell),
                ..Limits::default()
            },
        );
        (bench.terminals, bench.rx)
    }
}
