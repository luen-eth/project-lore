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
//!   [`kill_all`] ends every process of that user (a `kill(-1, SIGKILL)` made
//!   as that user, which the kernel carries out atomically, so a process
//!   that forks or calls `setsid` cannot slip away), and
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

/// The live processes of `uid` (real, effective or saved), from `/proc`,
/// this process excepted. Zombies are dead and left out.
pub fn processes_of(uid: u32) -> Vec<i32> {
    let me = std::process::id() as i32;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            if pid == me {
                return None;
            }
            let status = std::fs::read_to_string(entry.path().join("status")).ok()?;
            let mut zombie = false;
            let mut matches = false;
            for line in status.lines() {
                if let Some(state) = line.strip_prefix("State:") {
                    zombie = state.trim_start().starts_with('Z');
                } else if let Some(ids) = line.strip_prefix("Uid:") {
                    matches = ids
                        .split_whitespace()
                        .take(3)
                        .any(|id| id.parse::<u32>() == Ok(uid));
                }
            }
            (matches && !zombie).then_some(pid)
        })
        .collect()
}

/// Ends every process of the agent user and waits until none is left.
/// The killing is done by a `kill(-1, SIGKILL)` made as that user: the
/// kernel signals every process the caller may signal in one pass, under
/// the task list lock, so nothing forks its way out. Errors when some
/// process is still alive after a few seconds.
pub async fn kill_all(user: AgentUser) -> Result<()> {
    for _ in 0..3 {
        if processes_of(user.uid).is_empty() {
            return Ok(());
        }
        // `true`, started as the agent user, sends SIGKILL to pid -1 between
        // fork and exec (`kill(-1, SIGKILL)`: every process that user may
        // signal, itself excepted), then has nothing left to do.
        let mut command = tokio::process::Command::new("true");
        // SAFETY: two system calls between fork and exec, through rustix,
        // which neither allocates nor takes locks.
        unsafe {
            command.pre_exec(|| {
                // Only once the switch to the agent user happened: as root
                // this would end the runner too.
                if !rustix::process::geteuid().is_root()
                    && let Some(all) = rustix::process::Pid::from_raw(1)
                {
                    let _ = rustix::process::kill_process_group(all, rustix::process::Signal::KILL);
                }
                Ok(())
            });
        }
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .uid(user.uid)
            .gid(user.gid)
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // It reports an error when it found nothing to kill: that is fine.
        let _ = tokio::time::timeout(Duration::from_secs(10), command.status()).await;
        for _ in 0..50 {
            if processes_of(user.uid).is_empty() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }
    let left = processes_of(user.uid);
    if left.is_empty() {
        Ok(())
    } else {
        bail!("{} process(es) of the agent user would not end", left.len())
    }
}

/// Between runs and after the last terminal: every process of the agent
/// user ends and what it left in the shared temporary directories goes.
pub async fn sweep(user: AgentUser) -> Result<()> {
    let killed = kill_all(user).await;
    for dir in ["/tmp", "/dev/shm"] {
        wipe_owned(Path::new(dir), user.uid);
    }
    killed
}

/// What is going on in one container: a run, and how many terminals are
/// open. A run and a terminal never overlap, so that ending every process
/// of the agent user after one never cuts the other short.
#[derive(Debug, Default)]
pub struct Occupancy {
    run: std::sync::atomic::AtomicBool,
    terminals: std::sync::atomic::AtomicUsize,
}

impl Occupancy {
    /// Takes the run slot; false when a run or a terminal holds the
    /// container.
    pub fn start_run(&self) -> Result<(), &'static str> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.terminals.load(SeqCst) > 0 {
            return Err("a terminal is open in this container");
        }
        if self
            .run
            .compare_exchange(false, true, SeqCst, SeqCst)
            .is_err()
        {
            return Err("another run is still going in this container");
        }
        if self.terminals.load(SeqCst) > 0 {
            self.run.store(false, SeqCst);
            return Err("a terminal is open in this container");
        }
        Ok(())
    }

    pub fn end_run(&self) {
        self.run.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn run_going(&self) -> bool {
        self.run.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Counts a terminal in; false while a run holds the container.
    pub fn open_terminal(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        self.terminals.fetch_add(1, SeqCst);
        if self.run.load(SeqCst) {
            self.terminals.fetch_sub(1, SeqCst);
            return false;
        }
        true
    }

    /// Counts a terminal out; answers how many are still open.
    pub fn close_terminal(&self) -> usize {
        use std::sync::atomic::Ordering::SeqCst;
        self.terminals.fetch_sub(1, SeqCst).saturating_sub(1)
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

/// The total size of the regular files under `path`, symbolic links not
/// followed.
pub fn tree_size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| tree_size(&entry.path()))
                .sum()
        })
        .unwrap_or(0)
}

/// Copies the regular files under `from` into `to`, keeping the layout,
/// skipping symbolic links and anything else, every file `0600` and every
/// directory `0700`, up to `budget` bytes in all. With `only`, a file is
/// copied only when its extension is one of them. Answers what was copied.
pub fn copy_plain_tree(from: &Path, to: &Path, budget: u64, only: &[&str]) -> io::Result<u64> {
    let mut used = 0;
    copy_into(from, to, budget, only, &mut used, 0)?;
    Ok(used)
}

fn copy_into(
    from: &Path,
    to: &Path,
    budget: u64,
    only: &[&str],
    used: &mut u64,
    depth: usize,
) -> io::Result<()> {
    if depth > 12 {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(from)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::create_dir_all(to)?;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_into(
                &entry.path(),
                &to.join(entry.file_name()),
                budget,
                only,
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
    if !meta.is_file() || !wanted || *used + meta.len() > budget {
        return Ok(());
    }
    let Some(bytes) = read_regular(from, budget - *used) else {
        return Ok(());
    };
    *used += bytes.len() as u64;
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
        assert!(processes_of(me).contains(&pid));
        assert!(!processes_of(me).contains(&(std::process::id() as i32)));
        assert!(!processes_of(me.wrapping_add(4242)).contains(&pid));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!processes_of(me).contains(&pid));
    }

    /// Needs root (the uid switch): skipped otherwise. A process of the
    /// agent user that left its session and double-forked is still ended.
    #[tokio::test]
    async fn kill_all_ends_every_process_of_the_agent_user() {
        if !can_switch_user() {
            eprintln!("skipped: needs root to start processes as another user");
            return;
        }
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
        assert!(!processes_of(user.uid).is_empty());
        kill_all(user).await.unwrap();
        assert!(processes_of(user.uid).is_empty());
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
        let used = copy_plain_tree(&dir, &copy, 50, &[]).unwrap();
        assert_eq!(used, 4);
        assert!(copy.join("ok").is_file());
        assert!(!copy.join("big").exists());
        assert!(std::fs::symlink_metadata(copy.join("link")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&copy);
    }
}
