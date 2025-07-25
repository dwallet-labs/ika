// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::ValidatorProxy;
use std::sync::Arc;
use std::time::Duration;
use ika_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use tokio::sync::oneshot::Sender;
use tokio::sync::watch;
use tokio::sync::watch::Receiver;
use tokio::time;
use tokio::time::Instant;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct SystemState {
    pub computation_price_per_unit_size: u64,
    pub protocol_config: Option<ProtocolConfig>,
}

#[derive(Debug)]
pub struct SystemStateObserver {
    pub state: Receiver<SystemState>,
    pub _sender: Sender<()>,
}

impl SystemStateObserver {
    pub fn new(proxy: Arc<dyn ValidatorProxy + Send + Sync>) -> Self {
        let (sender, mut recv) = tokio::sync::oneshot::channel();
        let mut interval = tokio::time::interval_at(Instant::now(), Duration::from_secs(60));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let (tx, rx) = watch::channel(SystemState {
            computation_price_per_unit_size: 1u64,
            protocol_config: None,
        });
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match proxy.get_latest_system_state_object().await {
                            Ok(result) => {
                                let p = ProtocolConfig::get_for_version(ProtocolVersion::new(result.protocol_version), Chain::Unknown);
                                if tx.send(SystemState {computation_price_per_unit_size: result.computation_price_per_unit_size,protocol_config: Some(p)}).is_ok() {
                                    info!("Computation price per unit size = {:?}", result.computation_price_per_unit_size    );
                                }
                            }
                            Err(err) => {
                                error!("Failed to get system state object: {:?}", err);
                            }
                        }
                    }
                    _ = &mut recv => break,
                }
            }
        });
        Self {
            state: rx,
            _sender: sender,
        }
    }
}
