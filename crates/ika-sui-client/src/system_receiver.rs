use crate::SuiConnectorClient;
use ika_types::sui::SystemInner;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct SystemReceiver {
    receiver: watch::Receiver<Option<SystemInner>>,
}

impl SystemReceiver {
    pub fn new(receiver: watch::Receiver<Option<SystemInner>>) -> Self {
        Self { receiver }
    }

    pub async fn must_get_system_inner(&self) -> SystemInner {
        loop {
            match self.receiver.borrow().clone() {
                Some(system_inner) => return system_inner,
                None => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}

pub struct SystemFetcher {
    sender: watch::Sender<Option<SystemInner>>,
    sui_client: Arc<SuiConnectorClient>,
}

impl SystemFetcher {
    pub fn new(
        sender: watch::Sender<Option<SystemInner>>,
        sui_client: Arc<SuiConnectorClient>,
    ) -> Self {
        Self { sender, sui_client }
    }

    /// periodically fetch the system inner and update the sender
    pub async fn spawn(&self) {
        let interval = std::time::Duration::from_secs(5);
        loop {
            match self.sui_client.get_system_inner().await {
                Ok(system_inner) => {
                    if self.sender.send(Some(system_inner)).is_err() {
                        tracing::warn!("Failed to send system inner update");
                    }
                }
                Err(e) => {
                    tracing::error!(?e, "failed to fetch system inner");
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}
