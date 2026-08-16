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
    /// This is the only submission of our signature for this checkpoint:
    /// the builder never re-invokes the output for an already-built height,
    /// and `submit_to_consensus` only hands the tx to an in-memory retry
    /// task. A process death before sequencing therefore loses the
    /// signature for good. Deliberate: certification needs a stake quorum,
    /// not any specific signer, so one validator's lost signature is
    /// absorbed — and if our own aggregator never certifies the height,
    /// the certified checkpoint still arrives via state sync.
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

        // Suppress against SETTLED state, not against how far this node got.
        // A restart rebuilds every checkpoint of the epoch from the consensus
        // commits, so without this gate each restart would re-sign an epoch's
        // worth of checkpoints into the DAG. The key is "a stake quorum has
        // already certified this sequence number" — an observation about the
        // network that converges across validators — which is why local
        // aggregation counts here alongside state sync, and why no
        // how-far-did-I-get watermark is involved.
        let highest_settled_checkpoint =
            checkpoint_store.get_highest_settled_dwallet_checkpoint_seq()?;

        if Some(checkpoint_seq) > highest_settled_checkpoint {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
    use crate::authority::authority_per_epoch_store::EpochStoreParams;
    use crate::authority::epoch_start_configuration::EpochStartConfiguration;
    use crate::dwallet_checkpoints::DWalletCheckpointMetrics;
    use crate::epoch::epoch_metrics::EpochMetrics;
    use ika_types::committee::Committee;
    use ika_types::crypto::{AuthorityKeyPair, AuthoritySignInfo, AuthorityStrongQuorumSignInfo};
    use ika_types::digests::ChainIdentifier;
    use ika_types::intent::{Intent, IntentScope};
    use ika_types::messages_consensus::ConsensusTransactionKind;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::EpochStartSystem;
    use prometheus::Registry;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CollectingSubmit {
        submitted: Mutex<Vec<ConsensusTransaction>>,
    }

    #[async_trait]
    impl SubmitToConsensus for Arc<CollectingSubmit> {
        async fn submit_to_consensus(
            &self,
            transactions: &[ConsensusTransaction],
            _epoch_store: &Arc<AuthorityPerEpochStore>,
        ) -> IkaResult {
            self.submitted
                .lock()
                .unwrap()
                .extend_from_slice(transactions);
            Ok(())
        }
    }

    fn checkpoint_message(epoch: u64, sequence_number: u64) -> DWalletCheckpointMessage {
        DWalletCheckpointMessage {
            epoch,
            sequence_number,
            messages: Vec::new(),
        }
    }

    /// A certificate over `message`, signed by the whole test committee. Only
    /// its existence matters here — `insert_certified_checkpoint` stores it
    /// without re-verifying, and the suppression key reads back the sequence
    /// number.
    fn certify(
        message: DWalletCheckpointMessage,
        committee: &Committee,
        keys: &[AuthorityKeyPair],
    ) -> VerifiedDWalletCheckpointMessage {
        let sign_infos: Vec<AuthoritySignInfo> = committee
            .names()
            .zip(keys.iter())
            .map(|(name, key)| {
                AuthoritySignInfo::new(
                    committee.epoch,
                    &message,
                    Intent::ika_app(IntentScope::DWalletCheckpointMessage),
                    *name,
                    key,
                )
            })
            .collect();
        let quorum =
            AuthorityStrongQuorumSignInfo::new_from_auth_sign_infos(sign_infos, committee).unwrap();
        VerifiedDWalletCheckpointMessage::new_unchecked(
            CertifiedDWalletCheckpointMessage::new_from_data_and_sig(message, quorum),
        )
    }

    /// Replay rebuilds every checkpoint of the epoch, so without suppression
    /// each restart sprays an epoch of signature re-submissions into the DAG.
    ///
    /// The suppression key has to be observed settled state — a certificate
    /// exists only if a stake quorum signed it — and NOT a record of how far
    /// this node got, which is exactly the second truth the event-sourced epoch
    /// removes. This is also why local aggregation counts: the state-sync
    /// watermark alone leaves a node that certified but has not synced past its
    /// own certificate re-signing an epoch's worth of checkpoints.
    #[tokio::test]
    async fn a_rebuilt_checkpoint_is_not_re_signed_once_a_quorum_has_certified_it() {
        let (committee, keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let name = *committee.names().next().unwrap();
        let epoch_dir = tempfile::tempdir().unwrap();
        let epoch_store = AuthorityPerEpochStore::new(EpochStoreParams {
            name,
            committee: committee.clone(),
            parent_path: epoch_dir.path().to_path_buf(),
            db_options: None,
            metrics: EpochMetrics::new(&Registry::new()),
            epoch_start_configuration: EpochStartConfiguration::new(
                EpochStartSystem::new_for_testing_with_epoch(0),
            )
            .unwrap(),
            chain_identifier: ChainIdentifier::default(),
            packages_config: IkaNetworkConfig::new_for_testing(),
        })
        .unwrap();

        let checkpoint_dir = tempfile::tempdir().unwrap();
        let checkpoint_store = DWalletCheckpointStore::new(checkpoint_dir.path());

        // Settled through sequence 5, by this node's own aggregation only —
        // `insert_certified_checkpoint` deliberately leaves the state-sync
        // watermark alone, which is the case the old key missed.
        for sequence_number in 1..=5 {
            checkpoint_store
                .insert_certified_checkpoint(&certify(
                    checkpoint_message(0, sequence_number),
                    &committee,
                    &keys,
                ))
                .unwrap();
        }
        assert!(
            checkpoint_store
                .get_highest_verified_dwallet_checkpoint()
                .unwrap()
                .is_none(),
            "the fixture must exercise locally-certified-but-not-synced, or it proves nothing \
             beyond the pre-existing state-sync guard",
        );
        assert_eq!(
            checkpoint_store
                .get_highest_settled_dwallet_checkpoint_seq()
                .unwrap(),
            Some(5),
        );

        let collector = Arc::new(CollectingSubmit::default());
        let signer: StableSyncAuthoritySigner = Arc::pin(keys.into_iter().next().unwrap());
        let output = SubmitDWalletCheckpointToConsensus {
            sender: collector.clone(),
            signer,
            authority: name,
            metrics: DWalletCheckpointMetrics::new_for_tests(),
        };

        // The restart re-builds the whole epoch: sequences 1..=5 are settled,
        // 6 and 7 are new work.
        for sequence_number in 1..=7 {
            output
                .dwallet_checkpoint_created(
                    &checkpoint_message(0, sequence_number),
                    &epoch_store,
                    &checkpoint_store,
                )
                .await
                .unwrap();
        }

        let submitted: Vec<u64> = collector
            .submitted
            .lock()
            .unwrap()
            .iter()
            .map(|transaction| match &transaction.kind {
                ConsensusTransactionKind::DWalletCheckpointSignature(message) => {
                    message.checkpoint_message.data().sequence_number
                }
                other => panic!("unexpected consensus transaction: {other:?}"),
            })
            .collect();
        assert_eq!(
            submitted,
            vec![6, 7],
            "a restart re-signed already-certified checkpoints; every restart would spray an \
             epoch of re-submissions into the DAG",
        );
    }
}
