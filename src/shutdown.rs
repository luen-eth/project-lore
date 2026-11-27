//! Stopping lore when it is asked to (`SIGTERM` from `docker stop`,
//! `Ctrl-C`).
//!
//! [`watch_signals`] turns the signal into one process-wide flag. Every
//! listener stops accepting when it is set ([`stopping`] is their graceful
//! shutdown), and the streams that never end on their own (the admin
//! page's live events) end with it, so that requests in flight finish
//! within [`GRACE`] and `main` can close the database cleanly and exit
//! well before Docker's 10 seconds run out and it kills the container.

use std::{sync::OnceLock, time::Duration};

use tokio::sync::watch;

/// How long requests still in flight get once the signal came; whatever is
/// still open then is closed.
pub const GRACE: Duration = Duration::from_secs(3);

/// The most the closing checkpoint of the database may take.
pub const CHECKPOINT: Duration = Duration::from_secs(2);

/// The most blocking work still running may hold the process after that.
pub const RUNTIME: Duration = Duration::from_secs(1);

// Signal to exit: at most GRACE + WORK + CHECKPOINT + RUNTIME (7 seconds),
// inside Docker's 10.

fn flag() -> &'static watch::Sender<bool> {
    static FLAG: OnceLock<watch::Sender<bool>> = OnceLock::new();
    FLAG.get_or_init(|| watch::channel(false).0)
}

/// Starts the shutdown: every [`stopping`] completes.
pub fn begin() {
    flag().send_replace(true);
}

/// Whether the shutdown has started: background work that would start
/// something new (a run, a claim) checks this first.
pub fn is_stopping() -> bool {
    *flag().borrow()
}

/// Detached work that must not be cut short (a push's ref records): the
/// shutdown waits for it, within its budget, while a [`Work`] is held.
fn in_flight() -> &'static watch::Sender<usize> {
    static COUNT: OnceLock<watch::Sender<usize>> = OnceLock::new();
    COUNT.get_or_init(|| watch::channel(0).0)
}

/// Held by detached work the shutdown should wait for.
#[derive(Debug)]
pub struct Work(());

impl Work {
    pub fn start() -> Self {
        in_flight().send_modify(|count| *count += 1);
        Self(())
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        in_flight().send_modify(|count| *count = count.saturating_sub(1));
    }
}

/// Completes once no [`Work`] is held.
pub async fn work_done() {
    let mut receiver = in_flight().subscribe();
    let _ = receiver.wait_for(|count| *count == 0).await;
}

/// How long the shutdown waits for held [`Work`] once the listeners are
/// done.
pub const WORK: Duration = Duration::from_secs(1);

/// Completes once the shutdown has started (at once if it has already).
pub async fn stopping() {
    let mut receiver = flag().subscribe();
    let _ = receiver.wait_for(|stopping| *stopping).await;
}

/// Waits for `SIGTERM` or `SIGINT` (`Ctrl-C`) in the background, then
/// [`begin`]s the shutdown. A second signal, once the shutdown has started,
/// ends the process at once.
pub fn watch_signals() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).ok();
    let mut interrupt = signal(SignalKind::interrupt()).ok();
    tokio::spawn(async move {
        next_signal(&mut terminate, &mut interrupt).await;
        tracing::info!("shutting down");
        begin();
        next_signal(&mut terminate, &mut interrupt).await;
        tracing::warn!("a second signal: exiting at once, without waiting");
        std::process::exit(EXIT_ON_SECOND_SIGNAL);
    });
}

/// The exit code after a second signal.
pub const EXIT_ON_SECOND_SIGNAL: i32 = 130;

async fn next_signal(
    terminate: &mut Option<tokio::signal::unix::Signal>,
    interrupt: &mut Option<tokio::signal::unix::Signal>,
) {
    async fn one(signal: &mut Option<tokio::signal::unix::Signal>) {
        match signal.as_mut() {
            Some(signal) => {
                signal.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    }
    tokio::select! {
        () = one(terminate) => {}
        () = one(interrupt) => {}
    }
}

/// Ends `stream` when the shutdown starts: for responses that would
/// otherwise stay open for as long as the client keeps them.
pub fn until_stopping<S: futures_util::Stream>(
    stream: S,
) -> impl futures_util::Stream<Item = S::Item> {
    futures_util::StreamExt::take_until(stream, Box::pin(stopping()))
}
