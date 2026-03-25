// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{DWalletCheckpointMetrics, DWalletCheckpointStore};
use crate::authority::StableSyncAuthoritySigner;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use async_trait::async_trait;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message_envelope::Message;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_checkpoint::{
    CertifiedDWalletCheckpointMessage, DWalletCheckpointMessage, DWalletCheckpointSignatureMessage,
    SignedDWalletCheckpointMessage, VerifiedDWalletCheckpointMessage,
};
use std::sync::Arc;
use tracing::{debug, info, instrument, trace};

#[async_trait]
pub trait DWalletCheckpointOutput: Sync + Send + 'static {
    async fn dwallet_checkpoint_created(
        &self,
        summary: &DWalletCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        checkpoint_store: &Arc<DWalletCheckpointStore>,
    ) -> IkaResult;
}

#[async_trait]
pub trait CertifiedDWalletCheckpointMessageOutput: Sync + Send + 'static {
    async fn certified_dwallet_checkpoint_message_created(
        &self,
        summary: &CertifiedDWalletCheckpointMessage,
    ) -> IkaResult;
}

pub struct SubmitDWalletCheckpointToConsensus<T> {
    pub sender: T,
    pub signer: StableSyncAuthoritySigner,
    pub authority: AuthorityName,
    pub metrics: Arc<DWalletCheckpointMetrics>,
}

pub struct LogDWalletCheckpointOutput;

impl LogDWalletCheckpointOutput {
    pub fn boxed() -> Box<dyn DWalletCheckpointOutput> {
        Box::new(Self)
    }

    pub fn boxed_certified() -> Box<dyn CertifiedDWalletCheckpointMessageOutput> {
        Box::new(Self)
    }
}

#[async_trait]
impl<T: SubmitToConsensus> DWalletCheckpointOutput for SubmitDWalletCheckpointToConsensus<T> {
    #[instrument(level = "debug", skip_all)]
    async fn dwallet_checkpoint_created(
        &self,
        checkpoint_message: &DWalletCheckpointMessage,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        checkpoint_store: &Arc<DWalletCheckpointStore>,
    ) -> IkaResult {
        LogDWalletCheckpointOutput
            .dwallet_checkpoint_created(checkpoint_message, epoch_store, checkpoint_store)
            .await?;

        let checkpoint_seq = checkpoint_message.sequence_number;

        let highest_verified_checkpoint = checkpoint_store
            .get_highest_verified_dwallet_checkpoint()?
            .map(|x| *x.sequence_number());

        if Some(checkpoint_seq) > highest_verified_checkpoint {
            debug!(
                ?checkpoint_message,
                "Sending dwallet checkpoint signature to consensus."
            );

            let summary = SignedDWalletCheckpointMessage::new(
                epoch_store.epoch(),
                checkpoint_message.clone(),
                &*self.signer,
                self.authority,
            );

            let message = DWalletCheckpointSignatureMessage {
                checkpoint_message: summary,
            };
            let transaction =
                ConsensusTransaction::new_dwallet_checkpoint_signature_message(message);
            self.sender
                .submit_to_consensus(&[transaction], epoch_store)
                .await?;
            self.metrics
                .last_sent_dwallet_checkpoint_signature
                .set(checkpoint_seq as i64);
        } else {
            debug!(
                "Dwallet checkpoint at sequence {checkpoint_seq} is already certified, skipping signature submission to consensus",
            );
            self.metrics
                .last_skipped_dwallet_checkpoint_signature_submission
                .set(checkpoint_seq as i64);
        }

        Ok(())
    }
}

#[async_trait]
impl DWalletCheckpointOutput for LogDWalletCheckpointOutput {
    async fn dwallet_checkpoint_created(
        &self,
        checkpoint_message: &DWalletCheckpointMessage,
        _epoch_store: &Arc<AuthorityPerEpochStore>,
        _checkpoint_store: &Arc<DWalletCheckpointStore>,
    ) -> IkaResult {
        trace!(
            "Including following transactions in dwallet checkpoint {}: {:#?}",
            checkpoint_message.sequence_number, checkpoint_message.messages,
        );
        info!(
            "Creating dwallet checkpoint {:?} at epoch {}, sequence {}, messages count {}",
            checkpoint_message.digest(),
            checkpoint_message.epoch,
            checkpoint_message.sequence_number,
            checkpoint_message.messages.len(),
        );

        Ok(())
    }
}

#[async_trait]
impl CertifiedDWalletCheckpointMessageOutput for LogDWalletCheckpointOutput {
    async fn certified_dwallet_checkpoint_message_created(
        &self,
        summary: &CertifiedDWalletCheckpointMessage,
    ) -> IkaResult {
        info!(
            "Certified dwallet checkpoint with sequence {} and digest {}",
            summary.sequence_number,
            summary.digest()
        );
        Ok(())
    }
}

pub struct SendDWalletCheckpointToStateSync {
    handle: ika_network::state_sync::Handle,
}

impl SendDWalletCheckpointToStateSync {
    pub fn new(handle: ika_network::state_sync::Handle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl CertifiedDWalletCheckpointMessageOutput for SendDWalletCheckpointToStateSync {
    #[instrument(level = "debug", skip_all)]
    async fn certified_dwallet_checkpoint_message_created(
        &self,
        checkpoint_message: &CertifiedDWalletCheckpointMessage,
    ) -> IkaResult {
        info!(
            "Certified dwallet checkpoint with sequence {} and digest {}",
            checkpoint_message.sequence_number,
            checkpoint_message.digest(),
        );
        self.handle
            .send_dwallet_checkpoint(VerifiedDWalletCheckpointMessage::new_unchecked(
                checkpoint_message.to_owned(),
            ))
            .await;

        Ok(())
    }
}
