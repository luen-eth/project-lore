//! Live fan-out of agent activity to open admin pages.

use tokio::sync::broadcast;

use crate::db::Activity;

/// A broadcast channel of agent actions. Cloning shares the channel.
#[derive(Clone)]
pub struct Events {
    sender: broadcast::Sender<Activity>,
}

impl Events {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }

    /// Sends an action to every listener. Having no listener is not an error.
    pub fn publish(&self, activity: Activity) {
        let _ = self.sender.send(activity);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Activity> {
        self.sender.subscribe()
    }
}
