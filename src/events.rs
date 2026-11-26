//! Live fan-out of agent activity to open admin pages, and of the
//! built-in agents' runs (their start, their redacted output, their end).

use tokio::sync::broadcast;

use crate::db::Activity;

/// A broadcast channel of agent actions, and one of run events. Cloning
/// shares the channels.
#[derive(Clone)]
pub struct Events {
    sender: broadcast::Sender<Activity>,
    runs: broadcast::Sender<serde_json::Value>,
}

impl Events {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        let (runs, _) = broadcast::channel(1024);
        Self { sender, runs }
    }

    /// Sends an action to every listener. Having no listener is not an error.
    pub fn publish(&self, activity: Activity) {
        let _ = self.sender.send(activity);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Activity> {
        self.sender.subscribe()
    }

    /// Sends a run event (already redacted) to every open admin page.
    pub fn publish_run(&self, event: serde_json::Value) {
        let _ = self.runs.send(event);
    }

    pub fn subscribe_runs(&self) -> broadcast::Receiver<serde_json::Value> {
        self.runs.subscribe()
    }
}
