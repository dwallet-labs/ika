// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use async_trait::async_trait;
use ika_types::error::IkaResult;
use ika_types::noa_checkpoint::{
    CertifiedNOACheckpointMessage, ChainDestination, NOACheckpointKind, NOACheckpointMessage,
};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::dwallet_checkpoints::DWalletCheckpointStore;
use crate::dwallet_checkpoints::dwallet_checkpoint_output::DWalletCheckpointOutput;
use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use crate::noa_checkpoints::NOACheckpointLocalStore;
use crate::system_checkpoints::SystemCheckpointStore;
use crate::system_checkpoints::system_checkpoint_output::SystemCheckpointOutput;
use ika_network::state_sync::noa_sync::NOACheckpointSyncHandle;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointMessage;
use ika_types::messages_system_checkpoints::SystemCheckpointMessage;
use ika_types::noa_checkpoint;

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

// === V1 trait bridges: DWallet checkpoint builder → NOA MPC signing ===

/// Bridges the existing DWalletCheckpointBuilder to the NOA MPC signing pipeline.
/// Implements the V1 `DWalletCheckpointOutput` trait so it can be plugged directly
/// into the existing builder without any builder changes.
pub struct SubmitDWalletCheckpointToNOASign {
    noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    noa_store: Arc<NOACheckpointLocalStore<noa_checkpoint::DWallet>>,
}

impl SubmitDWalletCheckpointToNOASign {
    pub fn new(
        noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
        noa_store: Arc<NOACheckpointLocalStore<noa_checkpoint::DWallet>>,
    ) -> Self {
        Self {
            noa_sign_sender,
            noa_store,
        }
    }
}

#[async_trait]
impl DWalletCheckpointOutput for SubmitDWalletCheckpointToNOASign {
    async fn dwallet_checkpoint_created(
        &self,
        checkpoint_message: &DWalletCheckpointMessage,
        _epoch_store: &Arc<AuthorityPerEpochStore>,
        _checkpoint_store: &Arc<DWalletCheckpointStore>,
    ) -> IkaResult {
        let noa_checkpoint_msg = NOACheckpointMessage {
            epoch: checkpoint_message.epoch,
            sequence_number: checkpoint_message.sequence_number,
            messages: checkpoint_message.messages.clone(),
        };

        // Use BCS serialization as placeholder until real Sui tx construction is implemented.
        let signable_bytes = bcs::to_bytes(&noa_checkpoint_msg).unwrap_or_default();

        self.noa_store
            .insert_pending(signable_bytes.clone(), noa_checkpoint_msg);

        let request = NetworkOwnedAddressSignRequest {
            message: signable_bytes,
            curve: noa_checkpoint::DWallet::curve(),
            signature_algorithm: noa_checkpoint::DWallet::signature_algorithm(),
            hash_scheme: noa_checkpoint::DWallet::hash_scheme(),
        };

        info!(
            sequence_number = checkpoint_message.sequence_number,
            epoch = checkpoint_message.epoch,
            messages_count = checkpoint_message.messages.len(),
            "Submitting DWallet NOA checkpoint to MPC signing pipeline",
        );

        if let Err(e) = self.noa_sign_sender.send(request) {
            error!(error = %e, "Failed to send DWallet NOA checkpoint sign request");
        }

        Ok(())
    }
}

/// Bridges the existing SystemCheckpointBuilder to the NOA MPC signing pipeline.
pub struct SubmitSystemCheckpointToNOASign {
    noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
    noa_store: Arc<NOACheckpointLocalStore<noa_checkpoint::System>>,
}

impl SubmitSystemCheckpointToNOASign {
    pub fn new(
        noa_sign_sender: UnboundedSender<NetworkOwnedAddressSignRequest>,
        noa_store: Arc<NOACheckpointLocalStore<noa_checkpoint::System>>,
    ) -> Self {
        Self {
            noa_sign_sender,
            noa_store,
        }
    }
}

#[async_trait]
impl SystemCheckpointOutput for SubmitSystemCheckpointToNOASign {
    async fn system_checkpoint_created(
        &self,
        checkpoint_message: &SystemCheckpointMessage,
        _epoch_store: &Arc<AuthorityPerEpochStore>,
        _system_checkpoint_store: &Arc<SystemCheckpointStore>,
    ) -> IkaResult {
        let noa_checkpoint_msg = NOACheckpointMessage {
            epoch: checkpoint_message.epoch,
            sequence_number: checkpoint_message.sequence_number,
            messages: checkpoint_message.messages.clone(),
        };

        // Use BCS serialization as placeholder until real Sui tx construction is implemented.
        let signable_bytes = bcs::to_bytes(&noa_checkpoint_msg).unwrap_or_default();

        self.noa_store
            .insert_pending(signable_bytes.clone(), noa_checkpoint_msg);

        let request = NetworkOwnedAddressSignRequest {
            message: signable_bytes,
            curve: noa_checkpoint::System::curve(),
            signature_algorithm: noa_checkpoint::System::signature_algorithm(),
            hash_scheme: noa_checkpoint::System::hash_scheme(),
        };

        info!(
            sequence_number = checkpoint_message.sequence_number,
            epoch = checkpoint_message.epoch,
            messages_count = checkpoint_message.messages.len(),
            "Submitting System NOA checkpoint to MPC signing pipeline",
        );

        if let Err(e) = self.noa_sign_sender.send(request) {
            error!(error = %e, "Failed to send System NOA checkpoint sign request");
        }

        Ok(())
    }
}

// === Composite outputs: run both BLS and NOA outputs ===

/// Dispatches to multiple `DWalletCheckpointOutput` implementations.
pub struct CompositeDWalletCheckpointOutput {
    pub outputs: Vec<Box<dyn DWalletCheckpointOutput>>,
}

#[async_trait]
impl DWalletCheckpointOutput for CompositeDWalletCheckpointOutput {
    async fn dwallet_checkpoint_created(
        &self,
        summary: &DWalletCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        checkpoint_store: &Arc<DWalletCheckpointStore>,
    ) -> IkaResult {
        for output in &self.outputs {
            output
                .dwallet_checkpoint_created(summary, epoch_store, checkpoint_store)
                .await?;
        }
        Ok(())
    }
}

/// Dispatches to multiple `SystemCheckpointOutput` implementations.
pub struct CompositeSystemCheckpointOutput {
    pub outputs: Vec<Box<dyn SystemCheckpointOutput>>,
}

#[async_trait]
impl SystemCheckpointOutput for CompositeSystemCheckpointOutput {
    async fn system_checkpoint_created(
        &self,
        summary: &SystemCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        system_checkpoint_store: &Arc<SystemCheckpointStore>,
    ) -> IkaResult {
        for output in &self.outputs {
            output
                .system_checkpoint_created(summary, epoch_store, system_checkpoint_store)
                .await?;
        }
        Ok(())
    }
}
