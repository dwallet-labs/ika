// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use ika_types::noa_checkpoint::{CertifiedNOACheckpointMessage, NOACheckpointKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const NOA_CHECKPOINT_SYNC_CHANNEL_SIZE: usize = 1024;

/// Cloneable handle for sending certified NOA checkpoints to the sync component.
#[derive(Clone)]
pub struct NOACheckpointSyncHandle<K: NOACheckpointKind> {
    sender: mpsc::Sender<CertifiedNOACheckpointMessage<K>>,
}

impl<K: NOACheckpointKind> NOACheckpointSyncHandle<K> {
    pub fn send(&self, checkpoint: CertifiedNOACheckpointMessage<K>) {
        if let Err(e) = self.sender.try_send(checkpoint) {
            error!(
                kind = K::NAME,
                "Failed to send certified NOA checkpoint to sync: {e}",
            );
        }
    }
}

/// Receives certified NOA checkpoints and stores them in-memory.
pub struct NOACheckpointSync<K: NOACheckpointKind> {
    receiver: mpsc::Receiver<CertifiedNOACheckpointMessage<K>>,
    checkpoints: HashMap<u64, CertifiedNOACheckpointMessage<K>>,
    highest_sequence_number: Option<u64>,
}

impl<K: NOACheckpointKind> NOACheckpointSync<K> {
    pub fn new() -> (NOACheckpointSyncHandle<K>, Self) {
        let (sender, receiver) = mpsc::channel(NOA_CHECKPOINT_SYNC_CHANNEL_SIZE);
        let handle = NOACheckpointSyncHandle { sender };
        let sync = Self {
            receiver,
            checkpoints: HashMap::new(),
            highest_sequence_number: None,
        };
        (handle, sync)
    }

    pub async fn run(mut self) {
        info!(kind = K::NAME, "Starting NOACheckpointSync");

        while let Some(checkpoint) = self.receiver.recv().await {
            let seq = checkpoint.checkpoint.sequence_number;

            if self.highest_sequence_number.is_some_and(|h| seq <= h) {
                warn!(
                    kind = K::NAME,
                    sequence_number = seq,
                    highest = ?self.highest_sequence_number,
                    "Received NOA checkpoint with non-monotonic sequence number, skipping",
                );
                continue;
            }

            info!(
                kind = K::NAME,
                sequence_number = seq,
                epoch = checkpoint.checkpoint.epoch,
                "NOACheckpointSync received certified checkpoint",
            );

            self.highest_sequence_number = Some(seq);
            self.checkpoints.insert(seq, checkpoint);
        }

        info!(
            kind = K::NAME,
            "NOACheckpointSync channel closed, shutting down",
        );
    }
}
