// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Concrete `AnnouncementRelay` impl for the Anemo
//! `SubmitMpcDataAnnouncement` RPC.
//!
//! Joiners who aren't in the consensus committee yet can't submit
//! their own `ValidatorMpcDataAnnouncement` to consensus directly.
//! They fan out the signed announcement to every current-committee
//! validator over the new RPC; whichever validator accepts it
//! forwards it as a `ConsensusTransaction`. One honest relayer per
//! announcement is sufficient.
//!
//! This impl runs:
//! 1. Cheap envelope checks (sig epoch == announcement epoch,
//!    announcement.validator == sig.authority).
//! 2. The pure verifier
//!    `verify_joiner_announcement` against the currently-installed
//!    `JoinerPubkeyProvider`. Rejection here stops spam from
//!    abusing us as a one-way pipe.
//! 3. Consensus submission of the wrapped
//!    `ConsensusTransaction::new_relayed_validator_mpc_data_announcement`.
//! 4. A bounded wait until the announcement is observed in consensus
//!    output — the joiner counts `Accepted` responses and stops
//!    fanning out, so the ack must mean "sequenced", not "handed to
//!    a background submitter" (issue #1943).

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::blob_cache::BlobCache;
use crate::consensus_adapter::SubmitToConsensus;
use crate::consensus_handler::SequencedConsensusTransactionKey;
use crate::validator_metadata::{
    JoinerAnnouncementVerdict, PeerBlobVerdict, verify_joiner_announcement,
    verify_peer_blob_for_relay,
};
use ika_network::mpc_artifacts::AnnouncementRelay;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::SignedValidatorMpcDataAnnouncement;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::{debug, info};

/// How long `relay` waits for the relayed announcement to be observed
/// in consensus output before telling the joiner to retry. Under a
/// healthy consensus, sequencing takes well under a second; the slack
/// covers submission backpressure. On expiry the joiner gets a
/// `Rejected` and its fan-out loop keeps trying — over-waiting here
/// only ties up an RPC slot, while under-waiting only costs a
/// redundant, verify-time-deduped re-relay.
const SEQUENCING_ACK_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ConsensusBackedAnnouncementRelay {
    epoch_store: Weak<AuthorityPerEpochStore>,
    consensus_adapter: Arc<dyn SubmitToConsensus>,
    blob_cache: Arc<BlobCache>,
    sequencing_ack_timeout: Duration,
}

impl ConsensusBackedAnnouncementRelay {
    pub fn new(
        epoch_store: Weak<AuthorityPerEpochStore>,
        consensus_adapter: Arc<dyn SubmitToConsensus>,
        blob_cache: Arc<BlobCache>,
    ) -> Self {
        Self {
            epoch_store,
            consensus_adapter,
            blob_cache,
            sequencing_ack_timeout: SEQUENCING_ACK_TIMEOUT,
        }
    }

    /// Test hook: shrink the sequencing-ack bound so the timeout path
    /// is exercisable without a 30s wait.
    #[cfg(test)]
    fn with_sequencing_ack_timeout(mut self, sequencing_ack_timeout: Duration) -> Self {
        self.sequencing_ack_timeout = sequencing_ack_timeout;
        self
    }
}

#[async_trait::async_trait]
impl AnnouncementRelay for ConsensusBackedAnnouncementRelay {
    async fn relay(
        &self,
        announcement: SignedValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
    ) -> Result<(), String> {
        let Some(epoch_store) = self.epoch_store.upgrade() else {
            debug!("rejecting joiner announcement relay: epoch ended");
            return Err("epoch ended".to_string());
        };
        let current_epoch = epoch_store.epoch();
        let next_epoch = current_epoch.saturating_add(1);
        // Joiner announcements target `next_epoch`. Current-epoch
        // announcements would come from validators that are
        // already in the committee and can submit themselves —
        // refuse to relay those.
        if announcement.announcement.epoch != next_epoch {
            debug!(
                joiner = ?announcement.announcement.validator,
                announcement_epoch = announcement.announcement.epoch,
                next_epoch,
                "rejecting joiner announcement relay: wrong epoch"
            );
            return Err(format!(
                "announcement epoch {} is not next_epoch {next_epoch}",
                announcement.announcement.epoch
            ));
        }
        let Some(provider) = epoch_store.joiner_pubkey_provider() else {
            debug!(
                joiner = ?announcement.announcement.validator,
                "rejecting joiner announcement relay: joiner pubkey provider not installed"
            );
            return Err("joiner pubkey provider not installed".to_string());
        };
        match verify_joiner_announcement(&announcement, provider.as_ref().as_ref(), next_epoch) {
            JoinerAnnouncementVerdict::Accept => {}
            verdict => {
                debug!(
                    joiner = ?announcement.announcement.validator,
                    ?verdict,
                    "rejecting joiner announcement relay: joiner verification failed"
                );
                return Err(format!("joiner verify rejected: {verdict:?}"));
            }
        }
        // Cache the pushed blob write-through. The joiner isn't in our
        // peer set, so neither we nor the rest of the committee can
        // fetch its `mpc_data` back from it — pushing it on the relay
        // is the only path. Verify it commits to the signed digest and
        // decodes to valid mpc_data before trusting it (the joiner's
        // signature binds `blob_hash`, so a hash mismatch is a
        // protocol violation; hash-matching-but-undecodable bytes
        // would poison our serve cache, so refuse both). Once cached,
        // the in-memory mirror lets the rest of the committee resolve
        // the joiner via the existing content-addressed P2P fetch.
        let digest = announcement.announcement.blob_hash;
        match verify_peer_blob_for_relay(&blob, &digest) {
            PeerBlobVerdict::Accept => {}
            verdict => {
                debug!(
                    joiner = ?announcement.announcement.validator,
                    ?verdict,
                    "rejecting joiner announcement relay: blob verification failed"
                );
                return Err(format!("joiner blob rejected: {verdict:?}"));
            }
        }
        self.blob_cache
            .insert(digest, blob.clone())
            .map_err(|e| format!("cache joiner blob failed: {e}"))?;
        let joiner = announcement.announcement.validator;
        let joiner_epoch = announcement.announcement.epoch;
        let blob_len = blob.len();
        // Carry the joiner's blob in-band on the consensus relay so the
        // whole committee obtains the bytes via consensus replication
        // rather than each member fetching them peer-to-peer.
        let tx =
            ConsensusTransaction::new_relayed_validator_mpc_data_announcement(announcement, blob);
        let sequencing_key = SequencedConsensusTransactionKey::External(tx.key());
        self.consensus_adapter
            .submit_to_consensus(&[tx], &epoch_store)
            .await
            .map_err(|e| format!("consensus submit failed: {e}"))?;
        // The relay is the ONLY path a joiner's mpc_data enters consensus;
        // without this record the committee side has no trace of having
        // accepted + forwarded it. Bounded: an honest joiner stops fanning
        // out once `min_accepts` relayers accept.
        //
        // Ack only once the announcement is OBSERVED in consensus output,
        // not when the submission task takes it: `submit_to_consensus`
        // only hands the tx to an in-memory retry loop that dies with the
        // process, this handler keeps no record, and the joiner — who
        // can't read consensus — permanently stops fanning out after
        // `min_accepts` acks. A submit-level ack therefore let a relayer
        // crash inside the ack-to-sequencing window silently lose the
        // announcement (issue #1943). The key is shared by every relayer
        // of this announcement, so anyone's copy landing releases us; on
        // timeout the joiner gets a `Rejected` and keeps fanning out, and
        // any late-landing duplicate dedups at verify time.
        match tokio::time::timeout(
            self.sequencing_ack_timeout,
            epoch_store.consensus_messages_processed_notify(vec![sequencing_key]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(format!(
                    "waiting for relayed announcement to sequence failed: {e}"
                ));
            }
            Err(_elapsed) => {
                return Err(format!(
                    "relayed announcement not observed in consensus within {:?}; joiner should retry",
                    self.sequencing_ack_timeout
                ));
            }
        }
        info!(
            joiner = ?joiner,
            epoch = joiner_epoch,
            blob_hash = ?digest,
            blob_len,
            "relayed joiner mpc_data announcement into consensus"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityMetrics;
    use crate::authority::authority_per_epoch_store::{
        ConsensusStats, ExecutionIndices, ExecutionIndicesWithStats,
    };
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::authority::epoch_start_configuration::EpochStartConfiguration;
    use crate::consensus_handler::{ConsensusCommitInfo, VerifiedSequencedConsensusTransaction};
    use crate::dwallet_checkpoints::DWalletCheckpointService;
    use crate::epoch::epoch_metrics::EpochMetrics;
    use crate::system_checkpoints::SystemCheckpointService;
    use crate::validator_metadata::{
        StaticJoinerPubkeyProvider, derive_mpc_data_blob, sign_validator_mpc_data_announcement,
    };
    use dwallet_rng::RootSeed;
    use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519Signature};
    use fastcrypto::traits::{KeyPair as _, ToFromBytes};
    use ika_network::mpc_artifacts::{InMemoryBlobStore, mpc_data_blob_hash};
    use ika_types::committee::Committee;
    use ika_types::crypto::AuthorityName;
    use ika_types::digests::ChainIdentifier;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::epoch_start_system::EpochStartSystem;
    use prometheus::Registry;

    struct NoopAdapter;
    #[async_trait::async_trait]
    impl SubmitToConsensus for NoopAdapter {
        async fn submit_to_consensus(
            &self,
            _transactions: &[ConsensusTransaction],
            _epoch_store: &Arc<AuthorityPerEpochStore>,
        ) -> ika_types::error::IkaResult {
            Ok(())
        }
    }

    /// A current-epoch (epoch 0) store whose relayer would accept a
    /// joiner announcement for epoch 1, plus that signed announcement
    /// and its (real, decode-valid) mpc_data blob.
    fn relay_fixture() -> (
        Arc<AuthorityPerEpochStore>,
        SignedValidatorMpcDataAnnouncement,
        Vec<u8>,
        ConsensusBackedAnnouncementRelay,
    ) {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(1);
        let committee = Arc::new(committee);
        let member = *committee.names().next().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let epoch_store = AuthorityPerEpochStore::new_retaining_derived_state_for_testing(
            member,
            committee,
            dir.path(),
            None,
            EpochMetrics::new(&Registry::new()),
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap(),
            ChainIdentifier::default(),
            IkaNetworkConfig::new_for_testing(),
        )
        .unwrap();
        std::mem::forget(dir); // keep the DB path alive for the test

        let joiner = AuthorityName([7; 32]);
        let joiner_keypair =
            Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&[3u8; 32]).unwrap());
        epoch_store.install_joiner_pubkey_provider(Box::new(
            StaticJoinerPubkeyProvider::from_iter([(joiner, joiner_keypair.public().clone())]),
        ));

        let blob = derive_mpc_data_blob(&RootSeed::new([7; 32])).expect("derive blob");
        let digest = mpc_data_blob_hash(&blob);
        let signed = sign_validator_mpc_data_announcement(
            joiner,
            1, // relays are accepted for next_epoch == current + 1
            42,
            digest,
            &joiner_keypair,
        )
        .expect("sign announcement");

        let perpetual_dir = tempfile::TempDir::new().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
        std::mem::forget(perpetual_dir);
        let relay = ConsensusBackedAnnouncementRelay::new(
            Arc::downgrade(&epoch_store),
            Arc::new(NoopAdapter),
            BlobCache::new(InMemoryBlobStore::new(), perpetual),
        );
        (epoch_store, signed, blob, relay)
    }

    /// The core of issue #1943: `Accepted` must mean "the announcement
    /// was observed in consensus output", not "handed to the in-memory
    /// submitter". The relay must stay pending until the announcement's
    /// consensus key is processed, then resolve Ok.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_acks_only_after_announcement_is_sequenced() {
        let (epoch_store, signed, blob, relay) = relay_fixture();

        let handle = {
            let signed = signed.clone();
            let blob = blob.clone();
            tokio::spawn(async move { relay.relay(signed, blob).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !handle.is_finished(),
            "relay acked before the announcement was sequenced — the joiner \
             would stop fanning out on a submit-level ack"
        );

        // The announcement lands: drive the same tx through the real
        // commit boundary, which marks its key processed and notifies.
        let tx = ConsensusTransaction::new_relayed_validator_mpc_data_announcement(signed, blob);
        epoch_store
            .process_consensus_transactions_and_commit_boundary(
                vec![VerifiedSequencedConsensusTransaction::new_test(tx)],
                &ExecutionIndicesWithStats {
                    index: ExecutionIndices {
                        last_committed_round: 1,
                        sub_dag_index: 0,
                        transaction_index: 0,
                    },
                    hash: 0,
                    stats: ConsensusStats::default(),
                },
                &None::<Arc<DWalletCheckpointService>>,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(1, 1_000, true),
                &Arc::new(AuthorityMetrics::new(&Registry::new())),
            )
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("relay must resolve once the announcement is sequenced")
            .unwrap();
        assert_eq!(result, Ok(()));
    }

    /// A rejected relay must not consume the joiner's consensus key.
    ///
    /// The key is `(joiner, epoch, timestamp)` — the joiner's identity, not
    /// the relayer's — and this message kind carries no sender constraint,
    /// because any committee member may legitimately relay for any joiner.
    /// The joiner's signature can only be checked when the record handler
    /// runs, not at admission, since the pubkey provider may not be installed
    /// yet. So if a rejected copy were recorded as processed, one member could
    /// relay a corrupted duplicate first and every honest relay of the genuine
    /// announcement — which shares that key — would be dropped as already
    /// processed. The joiner cannot notice: its success signal is the
    /// relayer's accept, not consensus inclusion.
    #[tokio::test]
    async fn a_rejected_relay_leaves_the_joiners_key_free_for_the_genuine_one() {
        let (epoch_store, signed, blob, _relay) = relay_fixture();

        // Same envelope — so the same consensus key — with a corrupted
        // signature. This is what a censoring relayer would submit.
        let mut corrupted = signed.clone();
        let mut signature_bytes = corrupted.joiner_sig.as_ref().to_vec();
        signature_bytes[0] ^= 0xFF;
        corrupted.joiner_sig = Ed25519Signature::from_bytes(&signature_bytes)
            .expect("a corrupted signature still decodes");

        let key = ConsensusTransaction::new_relayed_validator_mpc_data_announcement(
            signed.clone(),
            blob.clone(),
        )
        .key();
        let sequenced_key = SequencedConsensusTransactionKey::External(key);

        drive_commit(&epoch_store, corrupted, blob.clone(), 1).await;
        assert!(
            !epoch_store
                .is_consensus_message_processed(&sequenced_key)
                .unwrap(),
            "a rejected copy must not burn the joiner's key"
        );

        // The genuine announcement, relayed after, must still land.
        drive_commit(&epoch_store, signed.clone(), blob, 2).await;
        assert!(
            epoch_store
                .is_consensus_message_processed(&sequenced_key)
                .unwrap(),
            "the genuine announcement must be processed, not skipped as a duplicate"
        );
        assert!(
            epoch_store
                .get_validator_mpc_data_announcement(&signed.announcement.validator)
                .unwrap()
                .is_some(),
            "the joiner's announcement must be recorded"
        );
    }

    /// Drive one relayed announcement through the real commit boundary.
    async fn drive_commit(
        epoch_store: &Arc<AuthorityPerEpochStore>,
        signed: SignedValidatorMpcDataAnnouncement,
        blob: Vec<u8>,
        round: u64,
    ) {
        let tx = ConsensusTransaction::new_relayed_validator_mpc_data_announcement(signed, blob);
        epoch_store
            .process_consensus_transactions_and_commit_boundary(
                vec![VerifiedSequencedConsensusTransaction::new_test(tx)],
                &ExecutionIndicesWithStats {
                    index: ExecutionIndices {
                        last_committed_round: round,
                        sub_dag_index: 0,
                        transaction_index: 0,
                    },
                    hash: 0,
                    stats: ConsensusStats::default(),
                },
                &None::<Arc<DWalletCheckpointService>>,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(round, 1_000 * round, true),
                &Arc::new(AuthorityMetrics::new(&Registry::new())),
            )
            .await
            .unwrap();
    }

    /// If the announcement never lands, the relay must reject rather
    /// than ack, so the joiner keeps fanning out to other relayers.
    #[tokio::test]
    async fn relay_times_out_when_announcement_never_sequences() {
        let (_epoch_store, signed, blob, relay) = relay_fixture();
        let relay = relay.with_sequencing_ack_timeout(Duration::from_millis(50));
        let err = relay
            .relay(signed, blob)
            .await
            .expect_err("relay must reject when the announcement never sequences");
        assert!(
            err.contains("not observed in consensus"),
            "unexpected rejection reason: {err}"
        );
    }
}
