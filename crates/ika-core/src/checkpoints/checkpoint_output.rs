// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::CheckpointStore;
use super::checkpoint_metrics::CheckpointMetrics;
use crate::authority::StableSyncAuthoritySigner;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::SubmitToConsensus;
use async_trait::async_trait;
use ika_types::checkpoint::{
    CertifiedCheckpointMessage, CheckpointKind, CheckpointMessage, CheckpointSignatureMessage,
    SignedCheckpointMessage, VerifiedCheckpointMessage,
};
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message_envelope::Message;
use ika_types::messages_consensus::ConsensusTransaction;
use std::sync::Arc;
use tracing::{debug, info, instrument, trace};

#[async_trait]
pub trait CheckpointOutput<K: CheckpointKind>: Sync + Send + 'static {
    async fn checkpoint_created(
        &self,
        summary: &CheckpointMessage<K>,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        checkpoint_store: &Arc<CheckpointStore<K>>,
    ) -> IkaResult;
}

#[async_trait]
pub trait CertifiedCheckpointOutput<K: CheckpointKind>: Sync + Send + 'static {
    async fn certified_checkpoint_created(
        &self,
        summary: &CertifiedCheckpointMessage<K>,
    ) -> IkaResult;
}

pub struct SubmitCheckpointToConsensus<K: CheckpointKind, T> {
    pub sender: T,
    pub signer: StableSyncAuthoritySigner,
    pub authority: AuthorityName,
    pub metrics: Arc<CheckpointMetrics>,
    pub _kind: std::marker::PhantomData<K>,
}

pub struct LogCheckpointOutput<K: CheckpointKind>(std::marker::PhantomData<K>);

impl<K: CheckpointKind> LogCheckpointOutput<K> {
    pub fn boxed() -> Box<dyn CheckpointOutput<K>> {
        Box::new(Self(std::marker::PhantomData))
    }

    pub fn boxed_certified() -> Box<dyn CertifiedCheckpointOutput<K>> {
        Box::new(Self(std::marker::PhantomData))
    }
}

/// Trait to create the correct `ConsensusTransaction` variant per checkpoint kind.
pub trait CheckpointConsensusAdapter: CheckpointKind {
    fn consensus_transaction(msg: CheckpointSignatureMessage<Self>) -> ConsensusTransaction;
}

impl CheckpointConsensusAdapter for ika_types::checkpoint::DWallet {
    fn consensus_transaction(msg: CheckpointSignatureMessage<Self>) -> ConsensusTransaction {
        ConsensusTransaction::new_dwallet_checkpoint_signature_message(msg)
    }
}

impl CheckpointConsensusAdapter for ika_types::checkpoint::System {
    fn consensus_transaction(msg: CheckpointSignatureMessage<Self>) -> ConsensusTransaction {
        ConsensusTransaction::new_system_checkpoint_signature_message(msg)
    }
}

/// Trait to send a certified checkpoint to state sync per checkpoint kind.
pub trait CheckpointStateSyncAdapter: CheckpointKind {
    fn send_to_state_sync(
        handle: &ika_network::state_sync::Handle,
        checkpoint: VerifiedCheckpointMessage<Self>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

impl CheckpointStateSyncAdapter for ika_types::checkpoint::DWallet {
    async fn send_to_state_sync(
        handle: &ika_network::state_sync::Handle,
        checkpoint: VerifiedCheckpointMessage<Self>,
    ) {
        handle.send_dwallet_checkpoint(checkpoint).await;
    }
}

impl CheckpointStateSyncAdapter for ika_types::checkpoint::System {
    async fn send_to_state_sync(
        handle: &ika_network::state_sync::Handle,
        checkpoint: VerifiedCheckpointMessage<Self>,
    ) {
        handle.send_system_checkpoint(checkpoint).await;
    }
}

#[async_trait]
impl<K, T> CheckpointOutput<K> for SubmitCheckpointToConsensus<K, T>
where
    K: CheckpointConsensusAdapter,
    T: SubmitToConsensus,
{
    #[instrument(level = "debug", skip_all)]
    async fn checkpoint_created(
        &self,
        checkpoint_message: &CheckpointMessage<K>,
        epoch_store: &Arc<AuthorityPerEpochStore>,
        checkpoint_store: &Arc<CheckpointStore<K>>,
    ) -> IkaResult {
        LogCheckpointOutput::<K>::boxed()
            .checkpoint_created(checkpoint_message, epoch_store, checkpoint_store)
            .await?;

        let checkpoint_seq = checkpoint_message.sequence_number;

        let highest_verified_checkpoint = checkpoint_store
            .get_highest_verified_checkpoint()?
            .map(|x| *x.sequence_number());

        if Some(checkpoint_seq) > highest_verified_checkpoint {
            debug!(
                ?checkpoint_message,
                "Sending {} signature to consensus.",
                K::NAME,
            );

            let summary = SignedCheckpointMessage::<K>::new(
                epoch_store.epoch(),
                checkpoint_message.clone(),
                &*self.signer,
                self.authority,
            );

            let message = CheckpointSignatureMessage {
                checkpoint_message: summary,
            };
            let transaction = K::consensus_transaction(message);
            self.sender
                .submit_to_consensus(&[transaction], epoch_store)
                .await?;
            self.metrics
                .last_sent_checkpoint_signature
                .set(checkpoint_seq as i64);
        } else {
            debug!(
                "{} at sequence {checkpoint_seq} is already certified, skipping signature submission to consensus",
                K::NAME,
            );
            self.metrics
                .last_skipped_checkpoint_signature_submission
                .set(checkpoint_seq as i64);
        }

        Ok(())
    }
}

#[async_trait]
impl<K: CheckpointKind> CheckpointOutput<K> for LogCheckpointOutput<K> {
    async fn checkpoint_created(
        &self,
        checkpoint_message: &CheckpointMessage<K>,
        _epoch_store: &Arc<AuthorityPerEpochStore>,
        _checkpoint_store: &Arc<CheckpointStore<K>>,
    ) -> IkaResult {
        trace!(
            "Including following transactions in {} {}: {:#?}",
            K::NAME,
            checkpoint_message.sequence_number,
            checkpoint_message.messages,
        );
        info!(
            "Creating {} {:?} at epoch {}, sequence {}, messages count {}",
            K::NAME,
            checkpoint_message.digest(),
            checkpoint_message.epoch,
            checkpoint_message.sequence_number,
            checkpoint_message.messages.len(),
        );

        Ok(())
    }
}

#[async_trait]
impl<K: CheckpointKind> CertifiedCheckpointOutput<K> for LogCheckpointOutput<K> {
    async fn certified_checkpoint_created(
        &self,
        summary: &CertifiedCheckpointMessage<K>,
    ) -> IkaResult {
        info!(
            "Certified {} with sequence {} and digest {}",
            K::NAME,
            summary.sequence_number,
            summary.digest()
        );
        Ok(())
    }
}

pub struct SendCheckpointToStateSync<K: CheckpointKind> {
    handle: ika_network::state_sync::Handle,
    _kind: std::marker::PhantomData<K>,
}

impl<K: CheckpointKind> SendCheckpointToStateSync<K> {
    pub fn new(handle: ika_network::state_sync::Handle) -> Self {
        Self {
            handle,
            _kind: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<K: CheckpointStateSyncAdapter> CertifiedCheckpointOutput<K> for SendCheckpointToStateSync<K> {
    #[instrument(level = "debug", skip_all)]
    async fn certified_checkpoint_created(
        &self,
        checkpoint_message: &CertifiedCheckpointMessage<K>,
    ) -> IkaResult {
        info!(
            "Certified {} with sequence {} and digest {}",
            K::NAME,
            checkpoint_message.sequence_number,
            checkpoint_message.digest(),
        );
        K::send_to_state_sync(
            &self.handle,
            VerifiedCheckpointMessage::new_unchecked(checkpoint_message.to_owned()),
        )
        .await;

        Ok(())
    }
}
