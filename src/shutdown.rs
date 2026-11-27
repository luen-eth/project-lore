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

fn flag() -> &'static watch::Sender<bool> {
    static FLAG: OnceLock<watch::Sender<bool>> = OnceLock::new();
    FLAG.get_or_init(|| watch::channel(false).0)
}

/// Starts the shutdown: every [`stopping`] completes.
pub fn begin() {
    flag().send_replace(true);
}

/// Completes once the shutdown has started (at once if it has already).
pub async fn stopping() {
    let mut receiver = flag().subscribe();
    let _ = receiver.wait_for(|stopping| *stopping).await;
}

/// Waits for `SIGTERM` or `Ctrl-C` in the background, then [`begin`]s
/// the shutdown.
pub fn watch_signals() {
    tokio::spawn(async {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = ctrl_c => {}
            _ = async {
                match terminate.as_mut() {
                    Some(signal) => { signal.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
        tracing::info!("shutting down");
        begin();
    });
}

/// Ends `stream` when the shutdown starts: for responses that would
/// otherwise stay open for as long as the client keeps them.
pub fn until_stopping<S: futures_util::Stream>(
    stream: S,
) -> impl futures_util::Stream<Item = S::Item> {
    futures_util::StreamExt::take_until(stream, Box::pin(stopping()))
}
