// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{SystemCheckpointMetrics, SystemCheckpointStore};
use crate::authority::StableSyncAuthoritySigner;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use async_trait::async_trait;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message_envelope::Message;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_system_checkpoints::{
    CertifiedSystemCheckpointMessage, SignedSystemCheckpointMessage, SystemCheckpointMessage,
    SystemCheckpointSignatureMessage, VerifiedSystemCheckpointMessage,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, trace};

#[async_trait]
pub trait SystemCheckpointOutput: Sync + Send + 'static {
    async fn system_checkpoint_created(
        &self,
        summary: &SystemCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        system_checkpoint_store: &Arc<SystemCheckpointStore>,
    ) -> IkaResult;
}

#[async_trait]
pub trait CertifiedSystemCheckpointOutput: Sync + Send + 'static {
    async fn certified_system_checkpoint_message_created(
        &self,
        summary: &CertifiedSystemCheckpointMessage,
    ) -> IkaResult;
}

pub struct SubmitSystemCheckpointToConsensus<T> {
    pub sender: T,
    pub signer: StableSyncAuthoritySigner,
    pub authority: AuthorityName,
    pub metrics: Arc<SystemCheckpointMetrics>,
}

pub struct LogSystemCheckpointOutput;

impl LogSystemCheckpointOutput {
    pub fn boxed() -> Box<dyn SystemCheckpointOutput> {
        Box::new(Self)
    }

    pub fn boxed_certified() -> Box<dyn CertifiedSystemCheckpointOutput> {
        Box::new(Self)
    }
}

#[async_trait]
impl<T: SubmitToConsensus> SystemCheckpointOutput for SubmitSystemCheckpointToConsensus<T> {
    /// This is the only submission of our signature for this checkpoint —
    /// same restart-loss decision as `SubmitDWalletCheckpointToConsensus::
    /// dwallet_checkpoint_created`: a signature lost to process death is
    /// never re-sent; quorum certification and state sync absorb it.
    #[instrument(level = "debug", skip_all)]
    async fn system_checkpoint_created(
        &self,
        system_checkpoint: &SystemCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        system_checkpoint_store: &Arc<SystemCheckpointStore>,
    ) -> IkaResult {
        LogSystemCheckpointOutput
            .system_checkpoint_created(system_checkpoint, epoch_store, system_checkpoint_store)
            .await?;

        let system_checkpoint_seq = system_checkpoint.sequence_number;

        let highest_verified_system_checkpoint = system_checkpoint_store
            .get_highest_verified_system_checkpoint()?
            .map(|x| *x.sequence_number());

        if Some(system_checkpoint_seq) > highest_verified_system_checkpoint {
            debug!(
                ?system_checkpoint,
                "Sending system checkpoint signature to consensus."
            );

            let summary = SignedSystemCheckpointMessage::new(
                epoch_store.epoch(),
                system_checkpoint.clone(),
                &*self.signer,
                self.authority,
            );

            let message = SystemCheckpointSignatureMessage {
                checkpoint_message: summary,
            };
            let transaction =
                ConsensusTransaction::new_system_checkpoint_signature_message(message);
            self.sender
                .submit_to_consensus(&[transaction], epoch_store)
                .await?;
            self.metrics
                .last_sent_system_checkpoint_signature
                .set(system_checkpoint_seq as i64);
        } else {
            debug!(
                "SystemCheckpoint at sequence {system_checkpoint_seq} is already certified, skipping signature submission to consensus",
            );
            self.metrics
                .last_skipped_system_checkpoint_signature_submission
                .set(system_checkpoint_seq as i64);
        }

        Ok(())
    }
}
// ?
#[async_trait]
impl SystemCheckpointOutput for LogSystemCheckpointOutput {
    async fn system_checkpoint_created(
        &self,
        system_checkpoint: &SystemCheckpointMessage,
        _epoch_store: &Arc<AuthorityPerEpochStore>,
        _system_checkpoint_store: &Arc<SystemCheckpointStore>,
    ) -> IkaResult {
        trace!(
            "Including following transactions in system_checkpoint {}: {:#?}",
            system_checkpoint.sequence_number, system_checkpoint.messages,
        );
        info!(
            "Creating system_checkpoint {:?} at epoch {}, sequence {}, messages count {}",
            system_checkpoint.digest(),
            system_checkpoint.epoch,
            system_checkpoint.sequence_number,
            system_checkpoint.messages.len(),
        );

        Ok(())
    }
}

#[async_trait]
impl CertifiedSystemCheckpointOutput for LogSystemCheckpointOutput {
    async fn certified_system_checkpoint_message_created(
        &self,
        summary: &CertifiedSystemCheckpointMessage,
    ) -> IkaResult {
        info!(
            "Certified system_checkpoint with sequence {} and digest {}",
            summary.sequence_number,
            summary.digest()
        );
        Ok(())
    }
}

pub struct SendSystemCheckpointToStateSync {
    handle: ika_network::state_sync::Handle,
}

impl SendSystemCheckpointToStateSync {
    pub fn new(handle: ika_network::state_sync::Handle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl CertifiedSystemCheckpointOutput for SendSystemCheckpointToStateSync {
    #[instrument(level = "debug", skip_all)]
    async fn certified_system_checkpoint_message_created(
        &self,
        system_checkpoint: &CertifiedSystemCheckpointMessage,
    ) -> IkaResult {
        info!(
            "Certified system_checkpoint with sequence {} and digest {}",
            system_checkpoint.sequence_number,
            system_checkpoint.digest(),
        );
        self.handle
            .send_system_checkpoint(VerifiedSystemCheckpointMessage::new_unchecked(
                system_checkpoint.to_owned(),
            ))
            .await;

        Ok(())
    }
}
