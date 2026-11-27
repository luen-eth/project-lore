//! Keeping the CLI apart from the runner.
//!
//! In the agent's container the runner runs as root with only the
//! capabilities it needs to hand work to another user (`SETUID`, `SETGID`,
//! `CHOWN`), and every CLI process, git process of the CLI, terminal and
//! shell runs as the unprivileged `agent` user ([`AgentUser`]), with no
//! capabilities at all. The CLI is treated as hostile: it may run whatever
//! a task's text talks it into. So:
//!
//! - the runner is not dumpable ([`harden`]): another user cannot read
//!   its memory or its `/proc/<pid>/environ`, and its link secret is taken
//!   out of its environment once read ([`take_secret`]);
//! - nothing of the agent user outlives a run or a terminal:
//!   [`kill_all`] ends every process of that user (stopping them all, then
//!   killing them, from the runner itself, so neither a process that forks
//!   or calls `setsid` nor one that holds every free pid can slip away), and
//!   [`wipe_owned`] removes what it left in the shared temporary
//!   directories;
//! - files the agent user wrote are taken back ([`reclaim`]) before the
//!   runner reads or deletes them, never following a symbolic link.
//!
//! Without an agent user (a runner started by hand, the tests) everything
//! runs as one user, as before: the functions that need the second user do
//! nothing then.

use std::{
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rustix::{
    fs::{AtFlags, CWD, Gid, OFlags, Uid},
    process::DumpableBehavior,
};

/// The unprivileged user every CLI process runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentUser {
    pub uid: u32,
    pub gid: u32,
}

impl AgentUser {
    /// Reads `LORE_RUNNER_AGENT_UID` / `LORE_RUNNER_AGENT_GID`. `None` when
    /// unset (one user for everything); an error when set to root or to
    /// something that is not a number.
    pub fn from_values(uid: Option<&str>, gid: Option<&str>) -> Result<Option<Self>> {
        let Some(uid) = uid.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let uid: u32 = uid
            .parse()
            .context("LORE_RUNNER_AGENT_UID must be a number")?;
        let gid: u32 = match gid.map(str::trim).filter(|v| !v.is_empty()) {
            Some(gid) => gid
                .parse()
                .context("LORE_RUNNER_AGENT_GID must be a number")?,
            None => uid,
        };
        if uid == 0 || gid == 0 {
            bail!("the agent user must not be root");
        }
        Ok(Some(Self { uid, gid }))
    }
}

/// Makes this process non-dumpable: no core dump, and `/proc/<pid>/mem`,
/// `environ` and friends are closed to every other process without
/// `CAP_SYS_PTRACE`, the agent user's included.
pub fn harden() -> Result<()> {
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .context("making the runner non-dumpable")
}

/// Whether this process is non-dumpable.
#[cfg(test)]
pub fn is_hardened() -> bool {
    matches!(
        rustix::process::dumpable_behavior(),
        Ok(DumpableBehavior::NotDumpable)
    )
}

/// Reads a secret from the file `file_var` names, or else from `var`, and
/// removes both variables from this process's environment, so that no
/// child can inherit them even by mistake.
pub fn take_secret(var: &str, file_var: &str) -> Result<Option<String>> {
    let from_file = std::env::var_os(file_var)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading {file_var} ({})", Path::new(&path).display()))
        })
        .transpose()?;
    let value = from_file.or_else(|| std::env::var(var).ok());
    // SAFETY: called once at start-up, before the runner starts any task
    // that reads or writes the environment.
    unsafe {
        std::env::remove_var(var);
        std::env::remove_var(file_var);
    }
    Ok(value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

/// Whether the runner can switch to another user (it runs as root, with
/// `SETUID` and `SETGID`).
pub fn can_switch_user() -> bool {
    rustix::process::geteuid().is_root()
}

/// The thread groups of `uid` that are still alive, this process
/// excepted, each with the state letters (`R`, `S`, `D`, `T`, `t`, …) of
/// its live threads. A group is alive while any of its threads
/// (`/proc/<pid>/task/*`) belongs to `uid` (real, effective or saved) and
/// is not itself dead (`Z`, `X`): a process whose main thread ended with a
/// raw `exit` shows a zombie leader while its other threads run on, and is
/// alive. A group whose threads are all dead (a zombie waiting for its
/// parent) is left out.
fn live_groups(uid: u32) -> io::Result<Vec<(i32, Vec<char>)>> {
    live_groups_in(Path::new("/proc"), uid, std::process::id() as i32)
}

/// Whether an error reading `/proc` only says that the process (or
/// thread) went away between being listed and being read: `ENOENT`, or
/// `ESRCH` for a status file opened just before its process was reaped.
fn vanished(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

/// [`live_groups`] over the `/proc` at `proc`. Fails closed: any error
/// other than a process vanishing while it is looked at (an unreadable
/// `/proc`, entry or status file) is an error, never "nothing left", so a
/// sweep that cannot see is a sweep that failed.
fn live_groups_in(proc: &Path, uid: u32, me: i32) -> io::Result<Vec<(i32, Vec<char>)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(proc)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let states = group_states(&entry.path(), uid)?;
        if !states.is_empty() {
            found.push((pid, states));
        }
    }
    Ok(found)
}

/// The states of the live threads of `uid` in the thread group whose
/// `/proc` directory is `dir`; empty when there is none or the group went
/// away. Errors as [`live_groups_in`] does.
fn group_states(dir: &Path, uid: u32) -> io::Result<Vec<char>> {
    let mut states = Vec::new();
    match std::fs::read_dir(dir.join("task")) {
        Ok(tasks) => {
            for task in tasks {
                let task = match task {
                    Ok(task) => task,
                    Err(error) if vanished(&error) => continue,
                    Err(error) => return Err(error),
                };
                match std::fs::read_to_string(task.path().join("status")) {
                    Ok(status) => states.extend(live_state_of(&status, uid)),
                    Err(error) if vanished(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        // No task list (it went away, or an unusual /proc): the group's
        // own status is all there is.
        Err(error) if vanished(&error) => match std::fs::read_to_string(dir.join("status")) {
            Ok(status) => states.extend(live_state_of(&status, uid)),
            Err(error) if vanished(&error) => {}
            Err(error) => return Err(error),
        },
        Err(error) => return Err(error),
    }
    Ok(states)
}

/// Sends `signal` to the thread group `pid` only if, once a pidfd pins
/// the process that holds that pid, `still_ours` (given the process's
/// `/proc` directory) says it is still the one meant. The pidfd keeps
/// naming that one process even if it dies and its pid is handed to
/// another: when `still_ours` reads `/proc/<pid>` after the pidfd is held,
/// either the pinned process is alive (and what was read is its own) or it
/// is gone (and the signal reaches nobody). So a pid recycled between a
/// scan and the signal never gets it, the runner included. Answers whether
/// a signal was sent; a process that went away is not an error.
pub fn signal_pinned(
    proc: &Path,
    pid: i32,
    signal: rustix::process::Signal,
    still_ours: impl FnOnce(&Path) -> io::Result<bool>,
) -> io::Result<bool> {
    use rustix::process::{Pid, PidfdFlags, pidfd_open, pidfd_send_signal};
    let Some(raw) = Pid::from_raw(pid) else {
        return Ok(false);
    };
    let pidfd = match pidfd_open(raw, PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(rustix::io::Errno::SRCH) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !still_ours(&proc.join(pid.to_string()))? {
        return Ok(false);
    }
    match pidfd_send_signal(&pidfd, signal) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::SRCH) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The state letter of one thread's `status` when it belongs to `uid` and
/// is not dead.
fn live_state_of(status: &str, uid: u32) -> Option<char> {
    let mut state = '?';
    let mut matches = false;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            state = rest.trim_start().chars().next().unwrap_or('?');
        } else if let Some(ids) = line.strip_prefix("Uid:") {
            matches = ids
                .split_whitespace()
                .take(3)
                .any(|id| id.parse::<u32>() == Ok(uid));
        }
    }
    (matches && !matches!(state, 'Z' | 'X')).then_some(state)
}

/// The live processes (thread groups) of `uid`, from `/proc`, this
/// process excepted (see [`live_groups`]: a zombie leader with a live
/// thread counts).
/// `None` when `/proc` cannot be read (see [`live_groups_in`]): callers
/// treat that as "some process may be left".
pub fn processes_of(uid: u32) -> Option<Vec<i32>> {
    match live_groups(uid) {
        Ok(groups) => Some(groups.into_iter().map(|(pid, _)| pid).collect()),
        Err(error) => {
            tracing::warn!(%error, "the agent user's processes could not be listed");
            None
        }
    }
}

/// How long [`kill_all`] keeps at it before it gives up.
const KILL_PATIENCE: Duration = Duration::from_secs(10);

/// Most passes [`kill_all`] spends stopping processes before it kills
/// every one of them, stopped or not (a process in uninterruptible sleep,
/// such as a `vfork` parent waiting on a stopped child, never reads as
/// stopped).
const STOP_PASSES: u32 = 100;

/// Ends every process of the agent user and waits until none is left,
/// without starting any process or thread: the runner signals them
/// itself (`CAP_KILL`), so a process that holds every pid the container
/// may have cannot stop it. First every running one is stopped
/// (`SIGSTOP` to the thread group, which no process can catch, block or
/// ignore; a stopped process cannot fork), pass after pass, until a pass
/// finds every thread of them stopped or [`STOP_PASSES`] are spent; then
/// all of them are killed (`SIGKILL` to the thread group ends every
/// thread, a zombie leader's live threads included), and the whole round
/// starts again until none is left. Errors when some process is still
/// alive after [`KILL_PATIENCE`].
pub async fn kill_all(user: AgentUser) -> Result<()> {
    use rustix::process::Signal;
    let deadline = tokio::time::Instant::now() + KILL_PATIENCE;
    let proc = Path::new("/proc");
    let mut passes = 0u32;
    loop {
        let found = live_groups(user.uid).context("looking for the agent user's processes")?;
        if found.is_empty() {
            return Ok(());
        }
        let running: Vec<i32> = found
            .iter()
            .filter(|(_, states)| states.iter().any(|state| !matches!(state, 'T' | 't')))
            .map(|(pid, _)| *pid)
            .collect();
        let (targets, signal): (Vec<i32>, Signal) = if running.is_empty() || passes >= STOP_PASSES {
            passes = 0;
            (found.iter().map(|(pid, _)| *pid).collect(), Signal::KILL)
        } else {
            passes += 1;
            (running, Signal::STOP)
        };
        for pid in targets {
            // Checked again through a pidfd: the pid may have been handed
            // to another process since the scan.
            signal_pinned(proc, pid, signal, |dir| {
                Ok(!group_states(dir, user.uid)?.is_empty())
            })
            .with_context(|| format!("signalling process {pid} of the agent user"))?;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{} process(es) of the agent user would not end",
                live_groups(user.uid).map_or(0, |left| left.len())
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Between runs and after the last terminal: every process of the agent
/// user ends, and what it left in the shared temporary directories, in
/// POSIX message queues and in System V shared memory, queues and
/// semaphores goes.
pub async fn sweep(user: AgentUser) -> Result<()> {
    kill_all(user).await?;
    for dir in ["/tmp", "/dev/shm", "/dev/mqueue"] {
        wipe_owned(Path::new(dir), user.uid);
    }
    remove_ipc(user).await;
    // `ipcrm` was a process of the agent user: it must be gone too.
    kill_all(user).await
}

/// Removes every System V IPC object the agent user may remove (only its
/// own: it has no capability). Runs only once no process of that user is
/// left, so a pid is free for it.
async fn remove_ipc(user: AgentUser) {
    let mut command = tokio::process::Command::new("ipcrm");
    command
        .arg("--all")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .uid(user.uid)
        .gid(user.gid)
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(10), command.status()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "ipcrm could not be started"),
        Err(_) => tracing::warn!("ipcrm took too long"),
    }
}

/// The exit code of a runner that could not end the agent user's
/// processes: the container restarts (compose `restart: unless-stopped`),
/// which ends every process in it, and lore marks the run interrupted
/// when the link drops.
pub const SWEEP_FAILED_EXIT: i32 = 70;

/// [`sweep`], and when it fails the runner exits, so that nothing is
/// harvested, reclaimed or started while a process of the agent user
/// survives.
pub async fn sweep_or_exit(user: AgentUser) {
    if let Err(error) = sweep(user).await {
        tracing::error!(
            %error,
            "the agent user's processes could not be ended; exiting so the container restarts"
        );
        std::process::exit(SWEEP_FAILED_EXIT);
    }
}

/// What is going on in one container: a run, how many terminals are
/// open, and an exclusive owner action (a sign-in, a credential being
/// stored or removed, a clean status check). None of the three overlaps
/// another, so that ending every process of the agent user after one
/// never cuts another short, and no run's process is alive while a
/// credential is handled. One for the whole runner process: it outlives
/// a link, so a run still being cleaned up after a reconnect keeps the
/// container.
#[derive(Debug, Default)]
pub struct Occupancy {
    slots: std::sync::Mutex<Slots>,
}

#[derive(Debug, Default)]
struct Slots {
    run: bool,
    terminals: usize,
    exclusive: Option<&'static str>,
}

/// Why an exclusive action is refused while a run goes.
pub const RUN_GOING: &str = "a run is going in this agent's container: wait until it ends (or \
                             stop it), then try again";

impl Occupancy {
    fn slots(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes the run slot; refused while a run, a terminal or an
    /// exclusive action holds the container.
    pub fn start_run(&self) -> Result<(), &'static str> {
        let mut slots = self.slots();
        if slots.terminals > 0 {
            return Err("a terminal is open in this container");
        }
        if slots.run {
            return Err("another run is still going in this container");
        }
        if slots.exclusive.is_some() {
            return Err("a sign-in or a credential change is in progress in this container");
        }
        slots.run = true;
        Ok(())
    }

    pub fn end_run(&self) {
        self.slots().run = false;
    }

    pub fn run_going(&self) -> bool {
        self.slots().run
    }

    /// Counts a terminal in; answers whether it is the first one open.
    /// Refused while a run or an exclusive action holds the container.
    pub fn open_terminal(&self) -> Result<bool, &'static str> {
        let mut slots = self.slots();
        if slots.run {
            return Err("a run is going in this container; watch its output, or stop it first");
        }
        if slots.exclusive.is_some() {
            return Err("a sign-in or a credential change is in progress in this container");
        }
        slots.terminals += 1;
        Ok(slots.terminals == 1)
    }

    /// How many terminals are open.
    pub fn terminals_open(&self) -> usize {
        self.slots().terminals
    }

    /// Counts a terminal out; answers how many are still open.
    pub fn close_terminal(&self) -> usize {
        let mut slots = self.slots();
        slots.terminals = slots.terminals.saturating_sub(1);
        slots.terminals
    }

    /// Takes the container for one exclusive action until the answer is
    /// dropped.
    pub fn exclusive(self: &Arc<Self>, what: &'static str) -> Result<Exclusive, String> {
        let mut slots = self.slots();
        if slots.run {
            return Err(RUN_GOING.to_string());
        }
        if slots.terminals > 0 {
            return Err(
                "a terminal is open in this agent's container: close it first, then try again"
                    .to_string(),
            );
        }
        if let Some(busy) = slots.exclusive {
            return Err(format!("{busy} is in progress in this agent's container"));
        }
        slots.exclusive = Some(what);
        Ok(Exclusive {
            occupancy: self.clone(),
        })
    }
}

/// An exclusive action's hold on the container; released when dropped.
#[derive(Debug)]
pub struct Exclusive {
    occupancy: Arc<Occupancy>,
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        self.occupancy.slots().exclusive = None;
    }
}

/// Changes the owner of one path without following a symbolic link.
fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    rustix::fs::chownat(
        CWD,
        path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
}

/// Takes a tree back from the agent user: every entry becomes this
/// process's own (directories `0700`), top-down, so each directory is
/// searchable before its entries are looked at. Symbolic links are changed
/// themselves, never followed. Only for trees no process of the agent
/// user can still change (after [`kill_all`]).
pub fn reclaim(path: &Path) -> io::Result<()> {
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    reclaim_as(path, uid, gid)
}

fn reclaim_as(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.uid() != uid || meta.gid() != gid {
        // Without CAP_CHOWN (one user for everything) the tree is ours
        // already; a failure is only fatal when the entry is someone
        // else's.
        if let Err(error) = lchown(path, uid, gid)
            && meta.uid() != uid
        {
            return Err(error);
        }
    }
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(path)? {
            reclaim_as(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// Gives a tree the runner prepared to the agent user, without following
/// a symbolic link. Does nothing without an agent user.
pub fn hand_over(path: &Path, user: Option<AgentUser>) -> io::Result<()> {
    let Some(user) = user else {
        return Ok(());
    };
    let meta = std::fs::symlink_metadata(path)?;
    // Bottom-up: once a directory is the agent's (mode 0700), the runner,
    // without DAC_OVERRIDE, can no longer list it.
    if meta.is_dir() && !meta.file_type().is_symlink() {
        for entry in std::fs::read_dir(path)? {
            hand_over(&entry?.path(), Some(user))?;
        }
    }
    lchown(path, user.uid, user.gid)
}

/// Deletes a tree whatever its owner or modes left it as.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            reclaim(path)?;
            std::fs::remove_dir_all(path)
        }
    }
}

/// Removes every entry of `dir` (a shared temporary directory: `/tmp`,
/// `/dev/shm`) that belongs to `uid`.
pub fn wipe_owned(dir: &Path, uid: u32) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.uid() != uid {
            continue;
        }
        let result = if meta.is_dir() {
            remove_tree(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(error) = result {
            tracing::warn!(path = %path.display(), %error, "a file the agent left could not be removed");
        }
    }
}

/// Reads a regular file of at most `max` bytes, refusing a symbolic link,
/// a device or a FIFO.
pub fn read_regular(path: &Path, max: u64) -> Option<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= max).then_some(bytes)
}

/// A fresh directory name: 16 random hex characters.
pub fn random_name(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{hex}")
}

/// Creates `path` (and its parents) with `mode`; an existing directory gets
/// the mode too.
pub fn make_dir(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", path.display()))?;
    Ok(())
}

/// Most entries [`tree_size`] looks at: past them it answers what it
/// counted so far.
pub const TREE_SIZE_ENTRIES: usize = 200_000;

/// The total size of the regular files under `path` and how many entries
/// (files and directories) it holds, symbolic links not followed, looking
/// at no more than `max_entries` entries.
pub fn tree_usage(path: &Path, max_entries: usize) -> (u64, usize) {
    let mut bytes = 0;
    let mut entries = 0;
    usage_into(path, max_entries, &mut bytes, &mut entries, 0);
    (bytes, entries)
}

fn usage_into(path: &Path, max: usize, bytes: &mut u64, entries: &mut usize, depth: usize) {
    if *entries >= max || depth > 32 {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    *entries += 1;
    if meta.is_file() {
        *bytes += meta.len();
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let Ok(list) = std::fs::read_dir(path) else {
        return;
    };
    for entry in list.flatten() {
        if *entries >= max {
            return;
        }
        usage_into(&entry.path(), max, bytes, entries, depth + 1);
    }
}

/// The total size of the regular files under `path`, symbolic links not
/// followed, bounded by [`TREE_SIZE_ENTRIES`].
pub fn tree_size(path: &Path) -> u64 {
    tree_usage(path, TREE_SIZE_ENTRIES).0
}

/// What a copy may use: bytes, where every entry (a file or a directory)
/// costs at least `min_cost`, and entries.
#[derive(Debug, Clone, Copy)]
pub struct CopyLimits {
    pub bytes: u64,
    pub entries: usize,
    pub min_cost: u64,
    /// Every entry looked at counts here, copied or not, so a directory of
    /// millions of skipped files cannot hold the walk up.
    pub looked_at: usize,
}

/// What a copy used.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Copied {
    pub bytes: u64,
    pub entries: usize,
    looked_at: usize,
}

/// Copies the regular files under `from` into `to`, keeping the layout,
/// skipping symbolic links and anything else, every file `0600` and every
/// directory `0700`, within `limits` (an empty file or a directory costs
/// `min_cost`: they hold inodes). With `only`, a file is copied only when
/// its extension is one of them. With `take_back`, every entry is made
/// this process's own before it is read (a tree the agent user wrote, once
/// no process of that user is left), so the walk never touches more than
/// it looks at. Answers what was copied.
pub fn copy_plain_tree(
    from: &Path,
    to: &Path,
    limits: CopyLimits,
    only: &[&str],
    take_back: bool,
) -> io::Result<Copied> {
    let mut used = Copied::default();
    copy_into(from, to, &limits, only, take_back, &mut used, 0)?;
    Ok(used)
}

fn copy_into(
    from: &Path,
    to: &Path,
    limits: &CopyLimits,
    only: &[&str],
    take_back: bool,
    used: &mut Copied,
    depth: usize,
) -> io::Result<()> {
    if depth > 12 || used.looked_at >= limits.looked_at {
        return Ok(());
    }
    used.looked_at += 1;
    if take_back {
        take_back_one(from)?;
    }
    let meta = std::fs::symlink_metadata(from)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    let room = |used: &Copied, cost: u64| {
        used.entries < limits.entries && used.bytes + cost <= limits.bytes
    };
    if meta.is_dir() {
        if !room(used, limits.min_cost) {
            return Ok(());
        }
        std::fs::create_dir_all(to)?;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700))?;
        used.entries += 1;
        used.bytes += limits.min_cost;
        for entry in std::fs::read_dir(from)? {
            if used.looked_at >= limits.looked_at || used.entries >= limits.entries {
                break;
            }
            let entry = entry?;
            copy_into(
                &entry.path(),
                &to.join(entry.file_name()),
                limits,
                only,
                take_back,
                used,
                depth + 1,
            )?;
        }
        return Ok(());
    }
    let wanted = only.is_empty()
        || from
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| only.contains(&extension));
    if !meta.is_file() || !wanted || !room(used, meta.len().max(limits.min_cost)) {
        return Ok(());
    }
    let Some(bytes) = read_regular(from, limits.bytes - used.bytes) else {
        return Ok(());
    };
    used.entries += 1;
    used.bytes += (bytes.len() as u64).max(limits.min_cost);
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32);
    use std::io::Write;
    options.open(to)?.write_all(&bytes)
}

/// Makes one entry this process's own (directories `0700`), without
/// following a symbolic link and without going into a directory.
pub fn take_back_one(path: &Path) -> io::Result<()> {
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let meta = std::fs::symlink_metadata(path)?;
    if (meta.uid() != uid || meta.gid() != gid)
        && let Err(error) = lchown(path, uid, gid)
        && meta.uid() != uid
    {
        return Err(error);
    }
    if meta.is_dir() && !meta.file_type().is_symlink() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The paths a list names, for messages.
pub fn shown(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(random_name(&format!(
            "lore-sandbox-{label}-{}-",
            std::process::id()
        )));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The tests that start processes as another user are `#[ignore]`d
    /// (they need root); run on purpose without it they fail loudly
    /// instead of passing without having tested anything.
    fn needs_root() {
        assert!(
            can_switch_user(),
            "this test needs root to start processes as another user: \
             see the README, Development"
        );
    }

    #[test]
    fn the_agent_user_is_never_root() {
        assert_eq!(AgentUser::from_values(None, None).unwrap(), None);
        assert_eq!(AgentUser::from_values(Some(" "), None).unwrap(), None);
        assert_eq!(
            AgentUser::from_values(Some("10002"), None).unwrap(),
            Some(AgentUser {
                uid: 10002,
                gid: 10002
            })
        );
        assert!(AgentUser::from_values(Some("0"), None).is_err());
        assert!(AgentUser::from_values(Some("10002"), Some("0")).is_err());
        assert!(AgentUser::from_values(Some("agent"), None).is_err());
    }

    /// The secret is read from its file (or variable) and both variables
    /// are gone afterwards, so no child can inherit them.
    #[test]
    fn the_link_secret_leaves_the_environment_once_read() {
        let dir = temp("secret");
        let file = dir.join("token");
        std::fs::write(&file, "from-the-file-0123456789abcdef\n").unwrap();
        let (var, file_var) = ("LORE_TEST_TAKE_SECRET_A", "LORE_TEST_TAKE_SECRET_A_FILE");
        // SAFETY: names no other test uses.
        unsafe {
            std::env::set_var(var, "from-the-environment-0123456789");
            std::env::set_var(file_var, &file);
        }
        assert_eq!(
            take_secret(var, file_var).unwrap().as_deref(),
            Some("from-the-file-0123456789abcdef")
        );
        assert!(std::env::var_os(var).is_none());
        assert!(std::env::var_os(file_var).is_none());
        let (var, file_var) = ("LORE_TEST_TAKE_SECRET_B", "LORE_TEST_TAKE_SECRET_B_FILE");
        unsafe { std::env::set_var(var, " from-the-environment-0123456789 ") };
        assert_eq!(
            take_secret(var, file_var).unwrap().as_deref(),
            Some("from-the-environment-0123456789")
        );
        assert!(std::env::var_os(var).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Once hardened, another process of the same user can no longer read
    /// this process's environment (with two users it could not anyway).
    #[test]
    fn a_hardened_runner_s_environment_is_closed_to_other_processes() {
        harden().unwrap();
        assert!(is_hardened());
        let output = std::process::Command::new("cat")
            .arg(format!("/proc/{}/environ", std::process::id()))
            .output()
            .unwrap();
        assert!(!output.status.success(), "the environment could be read");
    }

    #[test]
    fn processes_are_found_by_user() {
        let me = rustix::process::getuid().as_raw();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(processes_of(me).unwrap().contains(&pid));
        assert!(
            !processes_of(me)
                .unwrap()
                .contains(&(std::process::id() as i32))
        );
        assert!(!processes_of(me.wrapping_add(4242)).unwrap().contains(&pid));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!processes_of(me).unwrap().contains(&pid));
    }

    /// Needs root (the uid switch): skipped otherwise. A process of the
    /// agent user that left its session and double-forked is still ended.
    #[tokio::test]
    #[ignore = "needs root: see the README, Development"]
    async fn kill_all_ends_every_process_of_the_agent_user() {
        needs_root();
        let user = AgentUser {
            uid: 64_123,
            gid: 64_123,
        };
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "setsid sh -c 'sleep 300 &' ; sleep 300 &"])
            .uid(user.uid)
            .gid(user.gid)
            .current_dir("/");
        command.status().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!processes_of(user.uid).unwrap().is_empty());
        kill_all(user).await.unwrap();
        assert!(processes_of(user.uid).unwrap().is_empty());
    }

    /// A process whose main thread ended with a raw `SYS_exit` while
    /// another thread runs on shows a zombie leader, and is alive: it is
    /// found (by the janitor's check and by `kill_all`), and a group whose
    /// threads are all dead is not.
    #[test]
    fn a_zombie_leader_with_a_live_thread_is_alive() {
        if std::process::Command::new("python3")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("skipped: needs python3");
            return;
        }
        let me = rustix::process::getuid().as_raw();
        /// Ends the survivor even when an assertion fails.
        struct Reap(std::process::Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Reap(
            std::process::Command::new("python3")
                .args(["-I", "-c", ZOMBIE_LEADER])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id() as i32;
        wait_for_zombie_leader(pid);
        assert!(
            processes_of(me).unwrap().contains(&pid),
            "the survivor was missed"
        );
        let states = live_groups(me)
            .unwrap()
            .into_iter()
            .find(|(found, _)| *found == pid)
            .map(|(_, states)| states)
            .unwrap();
        assert_eq!(states.len(), 1, "{states:?}");
        drop(child);
        assert!(!processes_of(me).unwrap().contains(&pid));
    }

    /// The same from a fake `/proc`: per-thread states and owners decide.
    #[test]
    fn groups_are_judged_from_their_threads() {
        let dir = temp("proc");
        let thread = |pid: i32, tid: i32, state: &str, uid: u32| {
            let task = dir.join(format!("{pid}/task/{tid}"));
            std::fs::create_dir_all(&task).unwrap();
            std::fs::write(
                task.join("status"),
                format!(
                    "Name:\tx\nState:\t{state}\nTgid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                ),
            )
            .unwrap();
        };
        thread(100, 100, "Z (zombie)", 4242);
        thread(100, 101, "S (sleeping)", 4242);
        thread(200, 200, "Z (zombie)", 4242);
        thread(300, 300, "R (running)", 4343);
        thread(400, 400, "T (stopped)", 4242);
        thread(400, 401, "D (disk sleep)", 4242);
        thread(500, 500, "S (sleeping)", 4242);
        let mut found = live_groups_in(&dir, 4242, 500).unwrap();
        for (_, states) in &mut found {
            states.sort();
        }
        found.sort();
        // 100: a zombie leader with a live thread; 200: dead; 300: someone
        // else's; 400: one thread stopped, one in D; 500: this process.
        assert_eq!(found, vec![(100, vec!['S']), (400, vec!['D', 'T'])]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `/proc` that cannot be read is never taken for "nothing left":
    /// an unreadable directory, task list or status file fails the scan,
    /// while a process that vanished between listing and reading does not.
    #[test]
    fn an_unreadable_proc_fails_the_scan() {
        // Not a directory at all.
        let dir = temp("proc-broken");
        let file = dir.join("not-proc");
        std::fs::write(&file, "").unwrap();
        assert!(live_groups_in(&file, 4242, 1).is_err());
        assert!(live_groups_in(&dir.join("missing"), 4242, 1).is_err());

        // A status file that cannot be read (a directory in its place,
        // which no permission bit or root can read as a file).
        let status_dir = dir.join("a");
        std::fs::create_dir_all(status_dir.join("100/task/100/status")).unwrap();
        assert!(live_groups_in(&status_dir, 4242, 1).is_err());

        // A task list that is not a directory.
        let task_file = dir.join("b");
        std::fs::create_dir_all(task_file.join("100")).unwrap();
        std::fs::write(task_file.join("100/task"), "").unwrap();
        assert!(live_groups_in(&task_file, 4242, 1).is_err());

        // A group that vanished (no task list, no status) or a thread
        // that vanished (a task directory without its status) is fine.
        let gone = dir.join("c");
        std::fs::create_dir_all(gone.join("100")).unwrap();
        std::fs::create_dir_all(gone.join("200/task/201")).unwrap();
        assert_eq!(live_groups_in(&gone, 4242, 1).unwrap(), Vec::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A signal through a pidfd reaches the process only when the check,
    /// made while the pidfd is held, approves it; a pid nobody holds is
    /// not an error.
    #[test]
    fn a_pinned_signal_needs_the_check_to_pass() {
        use rustix::process::Signal;
        let proc = Path::new("/proc");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let mut seen = None;
        let sent = signal_pinned(proc, pid, Signal::KILL, |dir| {
            seen = Some(dir.to_path_buf());
            Ok(false)
        })
        .unwrap();
        assert!(!sent);
        assert_eq!(seen.unwrap(), proc.join(pid.to_string()));
        assert!(
            child.try_wait().unwrap().is_none(),
            "killed without approval"
        );
        let me = rustix::process::getuid().as_raw();
        let sent = signal_pinned(proc, pid, Signal::KILL, |dir| {
            Ok(!group_states(dir, me)?.is_empty())
        })
        .unwrap();
        assert!(sent);
        let status = child.wait().unwrap();
        assert!(!status.success());
        // Reaped: the pid is free (or someone else's, checked again).
        let sent = signal_pinned(proc, pid, Signal::KILL, |dir| {
            Ok(!group_states(dir, me.wrapping_add(4242))?.is_empty())
        })
        .unwrap();
        assert!(!sent);
    }

    /// A Python process whose main thread leaves with a raw `SYS_exit`
    /// (x86-64: 60, arm64: 93) while a second thread sleeps on.
    const ZOMBIE_LEADER: &str = "import ctypes, os, platform, threading, time\n\
                                 threading.Thread(target=lambda: time.sleep(300)).start()\n\
                                 time.sleep(0.2)\n\
                                 nr = 93 if platform.machine() in ('aarch64', 'arm64') else 60\n\
                                 ctypes.CDLL(None).syscall(nr, 0)\n";

    /// Waits until `pid`'s leader reads as a zombie.
    fn wait_for_zombie_leader(pid: i32) {
        for _ in 0..200 {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            if status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains('Z'))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the leader of {pid} never became a zombie");
    }

    /// Needs root (the uid switch): skipped otherwise. A process of the
    /// agent user whose leader left with `SYS_exit` while a thread runs on
    /// is stopped and killed, and every thread of it ends.
    #[tokio::test]
    #[ignore = "needs root: see the README, Development"]
    async fn kill_all_ends_a_process_whose_leader_is_a_zombie() {
        needs_root();
        let user = AgentUser {
            uid: 64_125,
            gid: 64_125,
        };
        let mut command = tokio::process::Command::new("python3");
        command
            .args(["-I", "-c", ZOMBIE_LEADER])
            .uid(user.uid)
            .gid(user.gid)
            .current_dir("/")
            .stdin(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        wait_for_zombie_leader(pid);
        assert_eq!(processes_of(user.uid).unwrap(), vec![pid]);
        kill_all(user).await.unwrap();
        assert!(processes_of(user.uid).unwrap().is_empty());
        // Every thread is gone: the group is a plain zombie for its parent.
        let _ = child.wait().await;
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    /// Needs root and perl: skipped otherwise. A `vfork` parent waits, in
    /// uninterruptible sleep, on a child that gets stopped: it never reads
    /// as stopped, and `kill_all` must still end both well within its
    /// patience.
    #[tokio::test]
    #[ignore = "needs root: see the README, Development"]
    async fn kill_all_ends_a_vfork_parent_in_uninterruptible_sleep() {
        needs_root();
        let has_perl = std::process::Command::new("perl")
            .arg("-v")
            .output()
            .is_ok();
        if !has_perl || std::env::consts::ARCH != "x86_64" {
            eprintln!("skipped: needs perl and x86-64");
            return;
        }
        let user = AgentUser {
            uid: 64_126,
            gid: 64_126,
        };
        let mut command = tokio::process::Command::new("perl");
        command
            .args([
                "-e",
                "require POSIX; my $p = syscall(58); if ($p == 0) { sleep 3600; POSIX::_exit(0); } \
                 sleep 3600;",
            ])
            .uid(user.uid)
            .gid(user.gid)
            .current_dir("/")
            .stdin(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        let mut groups = Vec::new();
        for _ in 0..200 {
            groups = live_groups(user.uid).unwrap();
            if groups.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            groups.iter().any(|(_, states)| states.contains(&'D')),
            "no vfork parent in D: {groups:?}"
        );
        let started = std::time::Instant::now();
        kill_all(user).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(processes_of(user.uid).unwrap().is_empty());
        let _ = child.wait().await;
    }

    /// Needs root and a container whose pids limit the bomb can fill
    /// (`LORE_TEST_PID_BOMB=1`, run in the agent image with
    /// `--pids-limit`): skipped otherwise. A process of the agent user that
    /// re-forks into every freed pid holds the whole pids limit, so the
    /// runner cannot start anything; the sweep must still end it all.
    #[tokio::test]
    #[ignore = "needs root, LORE_TEST_PID_BOMB=1 and a pids limit"]
    async fn kill_all_ends_a_fork_bomb_that_holds_every_pid() {
        let limit: Option<u64> = std::fs::read_to_string("/sys/fs/cgroup/pids.max")
            .ok()
            .and_then(|text| text.trim().parse().ok());
        if !can_switch_user()
            || std::env::var("LORE_TEST_PID_BOMB").as_deref() != Ok("1")
            || !limit.is_some_and(|limit| limit <= 4096)
        {
            eprintln!("skipped: needs root, LORE_TEST_PID_BOMB=1 and a pids limit");
            return;
        }
        let user = AgentUser {
            uid: 64_124,
            gid: 64_124,
        };
        let bomb = "import os, time\n\
                    os.setsid()\n\
                    while True:\n\
                    \x20   try:\n\
                    \x20       if os.fork() == 0:\n\
                    \x20           try: os.setsid()\n\
                    \x20           except Exception: pass\n\
                    \x20   except OSError:\n\
                    \x20       time.sleep(0.002)\n";
        let mut command = tokio::process::Command::new("python3");
        command
            .args(["-I", "-c", bomb])
            .uid(user.uid)
            .gid(user.gid)
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        // Until the container is full: nothing more can be started.
        let full = async {
            loop {
                if std::process::Command::new("true").status().is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(60), full)
            .await
            .expect("the bomb never filled the pids limit");
        assert!(processes_of(user.uid).unwrap().len() > 10);
        kill_all(user).await.unwrap();
        assert!(processes_of(user.uid).unwrap().is_empty());
        let _ = child.wait().await;
        assert!(std::process::Command::new("true").status().is_ok());
    }

    /// H3: empty files and directories cost entries and a minimum size, so
    /// a tree of many empty files is cut off instead of copied whole.
    #[test]
    fn empty_files_and_directories_count_against_a_copy() {
        let dir = temp("empties");
        for d in 0..5 {
            let sub = dir.join(format!("d{d}"));
            std::fs::create_dir_all(&sub).unwrap();
            for f in 0..1000 {
                std::fs::write(sub.join(format!("{f}.jsonl")), "").unwrap();
            }
        }
        let copy = temp("empties-copy");
        let limits = CopyLimits {
            bytes: 50 * 1024 * 1024,
            entries: 2000,
            min_cost: 4096,
            looked_at: 20_000,
        };
        let used = copy_plain_tree(&dir, &copy.join("x"), limits, &["jsonl"], false).unwrap();
        assert!(used.entries <= 2000, "{used:?}");
        let (_, kept) = tree_usage(&copy, 100_000);
        assert!(kept <= 2001, "{kept} entries were copied");
        // The walk stops at its bound too.
        assert_eq!(tree_usage(&dir, 100).1, 100);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&copy);
    }

    /// H5: a run, a terminal and an exclusive action (sign-in, credential)
    /// never overlap.
    #[test]
    fn runs_terminals_and_sign_ins_exclude_each_other() {
        let occupancy = Arc::new(Occupancy::default());
        occupancy.start_run().unwrap();
        assert_eq!(occupancy.exclusive("a sign-in").unwrap_err(), RUN_GOING);
        assert!(occupancy.open_terminal().is_err());
        occupancy.end_run();
        let held = occupancy.exclusive("a sign-in").unwrap();
        assert!(occupancy.start_run().is_err());
        assert!(occupancy.open_terminal().is_err());
        assert!(occupancy.exclusive("a credential").is_err());
        drop(held);
        assert_eq!(occupancy.open_terminal(), Ok(true));
        assert_eq!(occupancy.open_terminal(), Ok(false));
        assert!(occupancy.exclusive("a sign-in").is_err());
        assert!(occupancy.start_run().is_err());
        occupancy.close_terminal();
        occupancy.close_terminal();
        occupancy.start_run().unwrap();
    }

    #[test]
    fn reclaiming_never_follows_a_link_and_deletes_locked_trees() {
        let dir = temp("reclaim");
        let outside = dir.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o400)).unwrap();
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::fs::write(tree.join("a/b/file"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("a/link")).unwrap();
        std::fs::set_permissions(tree.join("a/b"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(tree.join("a"), std::fs::Permissions::from_mode(0o500)).unwrap();
        remove_tree(&tree).unwrap();
        assert!(!tree.exists());
        // The link's target kept its mode.
        assert_eq!(
            std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o400
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_regular_files_are_read_and_copied() {
        let dir = temp("regular");
        std::fs::write(dir.join("ok"), "fine").unwrap();
        std::fs::write(dir.join("big"), "x".repeat(100)).unwrap();
        std::os::unix::fs::symlink(dir.join("ok"), dir.join("link")).unwrap();
        assert_eq!(
            read_regular(&dir.join("ok"), 10).as_deref(),
            Some(&b"fine"[..])
        );
        assert_eq!(read_regular(&dir.join("big"), 10), None);
        assert_eq!(read_regular(&dir.join("link"), 10), None);
        assert_eq!(read_regular(&dir, 10), None);
        let copy = temp("regular-copy");
        let limits = CopyLimits {
            bytes: 50,
            entries: 100,
            min_cost: 0,
            looked_at: 100,
        };
        let used = copy_plain_tree(&dir, &copy, limits, &[], false).unwrap();
        assert_eq!(used.bytes, 4);
        assert!(copy.join("ok").is_file());
        assert!(!copy.join("big").exists());
        assert!(std::fs::symlink_metadata(copy.join("link")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&copy);
    }
}
