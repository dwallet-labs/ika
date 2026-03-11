// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::error::IkaResult;
use ika_types::noa_checkpoint::{CertifiedNOACheckpointMessage, NOACheckpointKind};
use tracing::info;

use ika_network::state_sync::noa_sync::NOACheckpointSyncHandle;

/// Trait for handling certified (NOA-signed) checkpoints.
pub trait CertifiedNOACheckpointOutput<K: NOACheckpointKind>: Send + Sync + 'static {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult;
}

/// Logs certified NOA checkpoints.
pub struct LogNOACheckpointOutput;

impl<K: NOACheckpointKind> CertifiedNOACheckpointOutput<K> for LogNOACheckpointOutput {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult {
        info!(
            kind = K::NAME,
            epoch = checkpoint.checkpoint.epoch,
            sequence_number = checkpoint.checkpoint.sequence_number,
            signatures_count = checkpoint.signatures.len(),
            "Certified NOA checkpoint created",
        );
        Ok(())
    }
}

/// Sends certified NOA checkpoints to the generic NOA checkpoint sync component.
pub struct SendNOACheckpointToStateSync<K: NOACheckpointKind> {
    handle: NOACheckpointSyncHandle<K>,
}

impl<K: NOACheckpointKind> SendNOACheckpointToStateSync<K> {
    pub fn new(handle: NOACheckpointSyncHandle<K>) -> Self {
        Self { handle }
    }
}

impl<K: NOACheckpointKind> CertifiedNOACheckpointOutput<K> for SendNOACheckpointToStateSync<K> {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult {
        self.handle.send(checkpoint.clone());
        Ok(())
    }
}

/// Notifies the finalizer when a checkpoint is certified (initial or retry).
/// Sends the sequence number over a bounded channel.
pub struct NotifyFinalizerOutput {
    sender: tokio::sync::mpsc::Sender<u64>,
}

impl NotifyFinalizerOutput {
    pub fn new(sender: tokio::sync::mpsc::Sender<u64>) -> Self {
        Self { sender }
    }
}

impl<K: NOACheckpointKind> CertifiedNOACheckpointOutput<K> for NotifyFinalizerOutput {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult {
        let seq = checkpoint.checkpoint.sequence_number;
        self.sender.try_send(seq).map_err(|e| {
            ika_types::error::IkaError::GenericAuthorityError {
                error: format!("Failed to notify finalizer of certified checkpoint seq={seq}: {e}"),
            }
        })?;
        Ok(())
    }
}

/// Forwards certified checkpoints to multiple outputs.
pub struct CompositeOutput<K: NOACheckpointKind> {
    inner: Vec<Box<dyn CertifiedNOACheckpointOutput<K>>>,
}

impl<K: NOACheckpointKind> CompositeOutput<K> {
    pub fn new(inner: Vec<Box<dyn CertifiedNOACheckpointOutput<K>>>) -> Self {
        Self { inner }
    }
}

impl<K: NOACheckpointKind> CertifiedNOACheckpointOutput<K> for CompositeOutput<K> {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult {
        for output in &self.inner {
            output.certified_checkpoint_created(checkpoint)?;
        }
        Ok(())
    }
}
