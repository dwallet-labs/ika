// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::error::IkaResult;
use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, ChainDestination, NOACheckpointKind, NOACheckpointMessage,
};

use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

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
        let signable_bytes = K::to_signable_bytes(checkpoint, chain_context, noa_public_key);

        let request = NetworkOwnedAddressSignRequest {
            sequence_number: checkpoint.sequence_number,
            message: signable_bytes,
            curve: K::curve(),
            signature_algorithm: K::signature_algorithm(),
            hash_scheme: K::hash_scheme(),
        };

        info!(
            kind = K::NAME,
            sequence_number = checkpoint.sequence_number,
            epoch = checkpoint.epoch,
            messages_count = checkpoint.messages.len(),
            "Submitting NOA checkpoint to MPC signing pipeline",
        );

        if let Err(e) = self.sender.send(request) {
            error!(
                kind = K::NAME,
                sequence_number = checkpoint.sequence_number,
                error = %e,
                "Failed to send NOA checkpoint sign request",
            );
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
            signature_len = checkpoint.signature.len(),
            "Certified NOA checkpoint created",
        );
        Ok(())
    }
}

/// Sends certified NOA checkpoints to state sync.
pub struct SendNOACheckpointToStateSync {
    handle: Arc<ika_network::state_sync::Handle>,
}

impl SendNOACheckpointToStateSync {
    pub fn new(handle: Arc<ika_network::state_sync::Handle>) -> Self {
        Self { handle }
    }
}
