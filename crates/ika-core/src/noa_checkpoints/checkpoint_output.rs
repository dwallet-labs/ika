// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::error::IkaResult;
use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, ChainDestination, NOACheckpointKind, NOACheckpointMessage,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use ika_network::state_sync::noa_sync::NOACheckpointSyncHandle;

/// Trait for handling newly built NOA checkpoints.
pub trait NOACheckpointOutput<K: NOACheckpointKind>: Send + Sync + 'static {
    fn checkpoint_created(
        &self,
        checkpoint: &NOACheckpointMessage<K>,
        chain_context: &<K::Destination as ChainDestination>::Context,
        noa_public_key: &[u8],
    ) -> IkaResult;
}

/// Submits newly built checkpoints to the NOA MPC signing pipeline.
pub struct SubmitCheckpointToNOASign<K: NOACheckpointKind> {
    sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    _marker: std::marker::PhantomData<K>,
}

impl<K: NOACheckpointKind> SubmitCheckpointToNOASign<K> {
    pub fn new(sender: UnboundedSender<NetworkOwnedAddressSignRequest>) -> Self {
        Self {
            sender,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<K: NOACheckpointKind> NOACheckpointOutput<K> for SubmitCheckpointToNOASign<K> {
    fn checkpoint_created(
        &self,
        checkpoint: &NOACheckpointMessage<K>,
        chain_context: &<K::Destination as ChainDestination>::Context,
        noa_public_key: &[u8],
    ) -> IkaResult {
        let all_tx_bytes = K::signable_bytes(checkpoint, chain_context, noa_public_key);

        info!(
            kind = K::NAME,
            sequence_number = checkpoint.sequence_number,
            epoch = checkpoint.epoch,
            messages_count = checkpoint.messages.len(),
            tx_count = all_tx_bytes.len(),
            "Submitting NOA checkpoint to MPC signing pipeline",
        );

        for tx_bytes in &all_tx_bytes {
            let request = NetworkOwnedAddressSignRequest {
                message: tx_bytes.clone(),
                curve: K::curve(),
                signature_algorithm: K::signature_algorithm(),
                hash_scheme: K::hash_scheme(),
            };

            if let Err(e) = self.sender.send(request) {
                error!(
                    kind = K::NAME,
                    sequence_number = checkpoint.sequence_number,
                    error = %e,
                    "Failed to send NOA checkpoint sign request",
                );
            }
        }

        Ok(())
    }
}

/// Trait for handling certified (NOA-signed) checkpoints.
pub trait CertifiedNOACheckpointOutput<K: NOACheckpointKind>: Send + Sync + 'static {
    fn certified_checkpoint_created(
        &self,
        checkpoint: &CertifiedNOACheckpointMessage<K>,
    ) -> IkaResult;
}

/// Logs certified NOA checkpoints.
pub struct LogNOACheckpointOutput;

impl<K: NOACheckpointKind> NOACheckpointOutput<K> for LogNOACheckpointOutput {
    fn checkpoint_created(
        &self,
        checkpoint: &NOACheckpointMessage<K>,
        _chain_context: &<K::Destination as ChainDestination>::Context,
        _noa_public_key: &[u8],
    ) -> IkaResult {
        info!(
            kind = K::NAME,
            epoch = checkpoint.epoch,
            sequence_number = checkpoint.sequence_number,
            messages_count = checkpoint.messages.len(),
            "NOA checkpoint created",
        );
        Ok(())
    }
}

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
