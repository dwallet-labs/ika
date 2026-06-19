// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Sui committee ratchet.
//!
//! `OcsVerifyingClient` now carries just the ratchet (committee chain
//! advance + pruning fallback) plus references to the raw transport and
//! the [`CommitteeStore`]. End-to-end verified reads moved to
//! [`crate::sui_connector::verified_reader::OcsVerifiedReader`], which
//! is built on top of an
//! [`ika_network::proof_provider::ProofProvider`].
//!
//! Requires the upstream Sui chain to have
//! `include_checkpoint_artifacts_digest_in_summary` enabled (Sui
//! protocol v122+). Testnet and devnet have it on; mainnet is still on
//! v121 as of 2026-05.

use std::sync::Arc;

use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use ika_sui_client::transport::{SuiTransport, TransportError};

use crate::sui_connector::committee_store::{
    CommitteeStore, CommitteeTransition, CommitteeTransitionError,
};
use crate::sui_connector::ocs_metrics::OcsMetrics;

#[derive(thiserror::Error, Debug)]
pub enum OcsError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("missing Sui committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("checkpoint {0} signature verification failed: {1}")]
    BadCheckpointSig(CheckpointSequenceNumber, String),
    #[error("checkpoint {0} is not end-of-epoch")]
    NotEndOfEpoch(CheckpointSequenceNumber),
    #[error(
        "proof chain broken at epoch {epoch}: the end-of-epoch checkpoint is pruned upstream so \
         the next committee cannot be BLS-verified; re-anchor closer to the current epoch (set \
         sui_trusted_anchor AND clear the node's OCS committee tables — perpetual state otherwise \
         wins over the configured anchor), or set allow_unverified_committee_fallback to accept \
         degraded trust"
    )]
    ProofChainBroken { epoch: u64 },
    #[error(
        "unverified committee fallback returned a committee for epoch {returned} when epoch \
         {requested} was requested; refusing to install it"
    )]
    FallbackEpochMismatch { requested: u64, returned: u64 },
    #[error(
        "the BLS-verified end-of-epoch checkpoint committed to a committee for epoch {returned} \
         when epoch {requested} was expected; refusing to install it"
    )]
    RatchetEpochMismatch { requested: u64, returned: u64 },
    #[error("ika error: {0}")]
    Ika(String),
}

impl From<ika_types::error::IkaError> for OcsError {
    fn from(e: ika_types::error::IkaError) -> Self {
        Self::Ika(e.to_string())
    }
}

impl OcsError {
    /// Whether retrying the same operation could plausibly succeed *without
    /// operator intervention*. Only transport failures qualify: the relay or a
    /// peer may recover, or an as-yet-unindexed checkpoint may appear on a
    /// later attempt. Every other variant is a determinate condition that a
    /// retry cannot heal — a pruned/broken proof chain (`ProofChainBroken`), a
    /// checkpoint that fails BLS verification (`BadCheckpointSig`) or isn't
    /// end-of-epoch (`NotEndOfEpoch`), a committee installed at the wrong epoch
    /// (`FallbackEpochMismatch`/`RatchetEpochMismatch`), or a missing local committee
    /// (`MissingCommittee`/`Ika`) — and needs the operator to act (typically
    /// re-anchor). A caller that loops on the ratchet (the peer-only boot
    /// ratchet) MUST stop and surface a fatal error on a non-retryable result
    /// rather than spin forever against an unhealable condition.
    pub fn is_retryable(&self) -> bool {
        matches!(self, OcsError::Transport(_))
    }
}

pub struct OcsVerifyingClient {
    transport: Arc<dyn SuiTransport>,
    committees: Arc<CommitteeStore>,
    metrics: Arc<OcsMetrics>,
    /// When the end-of-epoch checkpoint is pruned upstream, fall back to an
    /// *unverified* direct committee fetch instead of erroring. Default off —
    /// the un-verified fallback re-roots the proof chain on the endpoint's
    /// word (see `OcsError::ProofChainBroken`).
    allow_unverified_committee_fallback: bool,
    /// Coalesces concurrent ratchet calls to one: the periodic ratchet, the
    /// boot ratchet, and the reactive (`missing_committee`) push ratchet all
    /// share this. A caller that finds a ratchet already in flight returns
    /// `Ok` and lets the in-flight one advance the head (the push handler then
    /// re-`verify()`s against the possibly-advanced store).
    ratchet_lock: Mutex<()>,
}

impl OcsVerifyingClient {
    pub fn new(
        transport: Arc<dyn SuiTransport>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
        allow_unverified_committee_fallback: bool,
    ) -> Self {
        Self {
            transport,
            committees,
            metrics,
            allow_unverified_committee_fallback,
            ratchet_lock: Mutex::new(()),
        }
    }

    pub fn transport(&self) -> &Arc<dyn SuiTransport> {
        &self.transport
    }

    pub fn committees(&self) -> &Arc<CommitteeStore> {
        &self.committees
    }

    /// Walk forward from the current `head_epoch` of [`CommitteeStore`] to the
    /// upstream's current epoch, BLS-verifying each end-of-epoch checkpoint
    /// against the previous epoch's committee and installing the next one.
    ///
    /// Pruning behaviour: if `get_full_checkpoint(last_of_E)` returns
    /// `NotFound` because the end-of-epoch checkpoint was pruned upstream, the
    /// `E → E+1` transition can't be BLS-verified. By default this is a hard
    /// `ProofChainBroken` error (the operator must re-anchor); only with
    /// `allow_unverified_committee_fallback` does it fetch `committee[E+1]`
    /// directly and install it unverified (trust degraded to the endpoint).
    ///
    /// Coalesced via `ratchet_lock`: concurrent callers return `Ok` and let
    /// the in-flight ratchet advance the head.
    pub async fn ratchet_to_current_epoch(&self) -> Result<(), OcsError> {
        let _guard = match self.ratchet_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                debug!("ratchet already in flight; coalescing");
                return Ok(());
            }
        };
        // `get_current_epoch` is a relay-claimed, unverified passthrough, but
        // it only sets the loop's *target* — it can't forge progress. Every
        // step below BLS-verifies the end-of-epoch checkpoint against
        // committee[head], derives committee[head+1] from that verified summary,
        // and asserts `next.epoch == head + 1`. So a malicious relay claiming a
        // far-future epoch can't walk the verified head faster than one real,
        // committee-signed epoch per step: at worst its checkpoint fetches fail
        // and the ratchet stalls (or takes the unverified fallback, gated by
        // `allow_unverified_committee_fallback`) — never a forged advance.
        let target = self.transport.get_current_epoch().await?;
        self.metrics.chain_latest_epoch.set(target as i64);
        loop {
            let head = self.committees.head_epoch();
            if head >= target {
                break;
            }
            let last_seq = self.transport.last_checkpoint_of_epoch(head).await?;
            let data = match self.transport.get_full_checkpoint(last_seq).await {
                Ok(d) => d,
                Err(TransportError::NotFound(reason)) => {
                    if !self.allow_unverified_committee_fallback {
                        error!(
                            head,
                            last_seq,
                            target,
                            ?reason,
                            "ratchet: end-of-epoch checkpoint pruned upstream and the unverified \
                             fallback is disabled — proof chain broken; re-anchor required"
                        );
                        return Err(OcsError::ProofChainBroken { epoch: head });
                    }
                    error!(
                        security_critical = true,
                        head,
                        last_seq,
                        target,
                        ?reason,
                        "ratchet: end-of-epoch checkpoint pruned upstream; installing committee[E+1] \
                         via UNVERIFIED direct fetch — trust degraded to the endpoint's word"
                    );
                    self.metrics.unverified_committee_fallback_total.inc();
                    let next = self.transport.get_committee(Some(head + 1)).await?;
                    // Even in unverified mode the endpoint doesn't get to pick
                    // the epoch: `install_next` keys the store by the
                    // committee's own epoch field, so an endpoint returning a
                    // mislabeled committee could jump the ratchet head past
                    // epochs that were never installed.
                    if next.epoch != head + 1 {
                        return Err(OcsError::FallbackEpochMismatch {
                            requested: head + 1,
                            returned: next.epoch,
                        });
                    }
                    self.committees.install_next(next, None)?;
                    info!(
                        epoch = head + 1,
                        "ratcheted Sui committee (UNVERIFIED direct-fetch fallback)"
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // The single audited verify + derive + assert + persist step,
            // shared with the pusher's eager capture
            // (`CommitteeStore::install_next_from_checkpoint`). `data` is the
            // end-of-epoch checkpoint of `head`, so this installs
            // `committee[head + 1]`.
            match self.committees.install_next_from_checkpoint(&data) {
                Ok(CommitteeTransition::Installed(epoch)) => {
                    info!(epoch, last_seq, "ratcheted Sui committee");
                }
                // The relay returned a checkpoint at `last_checkpoint_of_epoch(head)`
                // that isn't the end-of-epoch checkpoint of `head` (wrong epoch
                // or not end-of-epoch) — a broken proof chain, non-retryable.
                Ok(CommitteeTransition::NotNextTransition) => {
                    return Err(OcsError::NotEndOfEpoch(last_seq));
                }
                Err(CommitteeTransitionError::MissingCommittee(e)) => {
                    return Err(OcsError::MissingCommittee(e));
                }
                Err(
                    CommitteeTransitionError::BadSignature { error, .. }
                    | CommitteeTransitionError::Extract { error, .. },
                ) => {
                    return Err(OcsError::BadCheckpointSig(last_seq, error));
                }
                Err(CommitteeTransitionError::EpochMismatch { expected, got }) => {
                    return Err(OcsError::RatchetEpochMismatch {
                        requested: expected,
                        returned: got,
                    });
                }
                Err(CommitteeTransitionError::Store(e)) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction, SubmittedTransaction};
    use sui_light_client::proof::committee::extract_new_committee_info;
    use sui_types::base_types::{
        ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest,
    };
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::full_checkpoint_content::CheckpointData;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointContents, CheckpointSummary, EndOfEpochData,
    };
    use sui_types::object::Object;
    use sui_types::transaction::Transaction;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;

    /// An end-of-epoch `CheckpointData` for `committee.epoch()` at `seq`,
    /// signed by `committee`/`keys` and committing to the SAME members at
    /// epoch `E+1`. Mirrors the helper in `push_worker`'s tests: the signing
    /// committee determines the epoch, so chaining one per epoch lets the
    /// ratchet walk forward verifying each transition.
    fn end_of_epoch_checkpoint(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CheckpointData {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: Some(EndOfEpochData {
                next_epoch_committee: committee.voting_rights.clone(),
                next_epoch_protocol_version: ProtocolVersion::MIN,
                epoch_commitments: vec![],
            }),
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    /// Re-key the same members to `epoch` so the same keypairs sign the
    /// end-of-epoch summary of every epoch (`new_from_keypairs_for_testing`
    /// signs as `committee.epoch()`). Derived via `extract_new_committee_info`
    /// off a self-signed transition, so the voting weights stay normalized.
    fn committee_at_epoch(base: &Committee, keys: &[AuthorityKeyPair], epoch: u64) -> Committee {
        if epoch == base.epoch() {
            return base.clone();
        }
        let mut current = base.clone();
        // Walk one epoch at a time; each derived committee keeps the same
        // members, only the epoch number advances.
        for _ in base.epoch()..epoch {
            let eoe = end_of_epoch_checkpoint(&current, keys, 0);
            current = extract_new_committee_info(&eoe.checkpoint_summary).unwrap();
        }
        current
    }

    /// Outcome the ratchet's transport asks of the mock for a given
    /// `get_full_checkpoint(seq)`. `CheckpointData` is boxed so the variants
    /// stay similarly sized.
    enum FullCheckpointOutcome {
        Data(Box<CheckpointData>),
        NotFound,
        Network,
    }

    /// Configurable transport for the committee ratchet. Records every
    /// `get_committee` call so a test can assert the fallback was (not) taken.
    struct RatchetMock {
        target_epoch: u64,
        /// `last_checkpoint_of_epoch(E)` -> seq. Defaults to `E` when absent.
        full_checkpoints: HashMap<CheckpointSequenceNumber, FullCheckpointOutcome>,
        /// Committee handed back by the unverified `get_committee(Some(_))`
        /// fallback, keyed by requested epoch.
        committees: HashMap<u64, Committee>,
        get_committee_calls: StdMutex<Vec<Option<u64>>>,
    }

    impl RatchetMock {
        fn new(target_epoch: u64) -> Self {
            Self {
                target_epoch,
                full_checkpoints: HashMap::new(),
                committees: HashMap::new(),
                get_committee_calls: StdMutex::new(Vec::new()),
            }
        }
        fn get_committee_call_count(&self) -> usize {
            self.get_committee_calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl SuiTransport for RatchetMock {
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            Ok(self.target_epoch)
        }
        async fn last_checkpoint_of_epoch(
            &self,
            epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            // Identity mapping epoch->seq keeps the test's checkpoint map simple.
            Ok(epoch)
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            match self.full_checkpoints.get(&seq) {
                Some(FullCheckpointOutcome::Data(d)) => Ok((**d).clone()),
                Some(FullCheckpointOutcome::NotFound) => {
                    Err(TransportError::NotFound(format!("checkpoint {seq} pruned")))
                }
                Some(FullCheckpointOutcome::Network) => {
                    Err(TransportError::Network(format!("relay down at {seq}")))
                }
                None => Err(TransportError::NotFound(format!("no checkpoint {seq}"))),
            }
        }
        async fn get_committee(&self, epoch: Option<u64>) -> Result<Committee, TransportError> {
            self.get_committee_calls.lock().unwrap().push(epoch);
            let requested = epoch.expect("ratchet fallback always pins an epoch");
            self.committees
                .get(&requested)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("no committee {requested}")))
        }

        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_owned_gas_coins(
            &self,
            _address: SuiAddress,
        ) -> Result<Vec<ObjectRef>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
        async fn get_transaction_checkpoint(
            &self,
            _tx: TransactionDigest,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn execute_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<SubmittedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// Open a committee store bootstrapped from `committee[0]` over fresh
    /// perpetual tables. The `TempDir` is returned so it outlives the store.
    fn store_with_genesis(committee: Committee) -> (tempfile::TempDir, Arc<CommitteeStore>) {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store = Arc::new(
            CommitteeStore::open(
                perpetual,
                Some(CommitteeBootstrap::UnsafeGenesis(committee)),
            )
            .unwrap(),
        );
        (dir, store)
    }

    /// With the unverified fallback enabled, a pruned end-of-epoch checkpoint
    /// triggers a direct `get_committee` fetch -- but if the endpoint returns a
    /// committee for the wrong epoch the ratchet refuses to install it
    /// (`FallbackEpochMismatch`), the head does NOT advance, and the
    /// security-critical fallback metric was incremented BEFORE the guard fired
    /// (so operators still see the attempted degradation).
    #[tokio::test]
    async fn unverified_fallback_rejects_epoch_mismatch() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        assert_eq!(store.head_epoch(), 0);

        // head=0, target=1: the ratchet reaches for last_checkpoint_of_epoch(0)
        // (seq 0), which the endpoint reports as pruned -> unverified fallback.
        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::NotFound);
        // The endpoint returns a committee labelled epoch 2 when epoch 1 was
        // requested -- a mislabel that would jump the head past epoch 1.
        let wrong = committee_at_epoch(&committee, &_keys, 2);
        mock.committees.insert(1, wrong);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), true);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(
                err,
                OcsError::FallbackEpochMismatch {
                    requested: 1,
                    returned: 2
                }
            ),
            "expected FallbackEpochMismatch, got {err:?}"
        );
        assert_eq!(store.head_epoch(), 0, "head must not advance on mismatch");
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            1,
            "the fallback metric increments before the epoch guard fires"
        );
        assert_eq!(
            mock.get_committee_call_count(),
            1,
            "the fallback fetched the committee exactly once"
        );
    }

    /// The unverified fallback keys STRICTLY on `NotFound`. A `Network` error
    /// from `get_full_checkpoint` is retryable, so the ratchet surfaces it as
    /// `Transport(..)` WITHOUT taking the degraded direct-fetch path:
    /// `get_committee` is never called and the fallback metric stays 0.
    #[tokio::test]
    async fn ratchet_does_not_fall_back_on_network_error() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee);
        assert_eq!(store.head_epoch(), 0);

        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::Network);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), true);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::Transport(TransportError::Network(_))),
            "a transient network error must stay retryable, got {err:?}"
        );
        assert!(err.is_retryable());
        assert_eq!(store.head_epoch(), 0, "head must not advance");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "fallback must NOT be taken on a network error"
        );
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            0,
            "the fallback metric stays 0 on a network error"
        );
    }

    /// finding-17 core, trusted-only posture: with the unverified fallback
    /// DISABLED (the default), a pruned end-of-epoch checkpoint
    /// (`get_full_checkpoint` -> NotFound) makes the ratchet fail with a TERMINAL
    /// `ProofChainBroken` rather than silently fetch `committee[E+1]` from the
    /// untrusted endpoint. The head does not advance, `get_committee` is never
    /// called, and the error is non-retryable (the operator must re-anchor). This
    /// is the in-process proxy for the cluster "peer-only bootstrap aborts on a
    /// pruned end-of-epoch" scenario — the real-pruning version is not expressible
    /// in the in-process Sui test cluster.
    #[tokio::test]
    async fn ratchet_pruned_end_of_epoch_is_fatal_without_fallback() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee);
        assert_eq!(store.head_epoch(), 0);

        // head=0, target=1: the end-of-epoch checkpoint of epoch 0 (seq 0) is
        // pruned upstream.
        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::NotFound);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        // allow_unverified_committee_fallback = false (the default, trust-preserving).
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::ProofChainBroken { epoch: 0 }),
            "a pruned end-of-epoch with fallback disabled must be a terminal \
             ProofChainBroken, got {err:?}"
        );
        assert!(
            !err.is_retryable(),
            "ProofChainBroken is fatal (operator must re-anchor), not retryable"
        );
        assert_eq!(store.head_epoch(), 0, "head must not advance");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "the trusted-only path must never fetch a committee from the endpoint"
        );
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            0,
            "no fallback was attempted"
        );
    }

    /// Driving the ratchet from head E to target E+2 over correctly-chained,
    /// committee-signed end-of-epoch checkpoints installs exactly E+1 then E+2
    /// -- head advances by exactly one per verified step, never skipping. A
    /// summary whose derived next committee is for the wrong epoch surfaces
    /// `RatchetEpochMismatch`.
    #[tokio::test]
    async fn ratchet_advances_epoch_by_one_per_step() {
        let (committee0, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee0.clone());
        assert_eq!(store.head_epoch(), 0);

        // Chain: committee[E] signs the end-of-epoch checkpoint of epoch E,
        // committing to committee[E+1]. seq == epoch under the mock's identity
        // last_checkpoint_of_epoch mapping.
        let committee1 = committee_at_epoch(&committee0, &keys, 1);
        let eoe0 = end_of_epoch_checkpoint(&committee0, &keys, 0);
        let eoe1 = end_of_epoch_checkpoint(&committee1, &keys, 1);

        let mut mock = RatchetMock::new(2);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::Data(Box::new(eoe0)));
        mock.full_checkpoints
            .insert(1, FullCheckpointOutcome::Data(Box::new(eoe1)));
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        // Fallback OFF: every step must verify, no degraded path.
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(store.head_epoch(), 2, "advanced exactly E+1 then E+2");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "verified path never touches the unverified fallback"
        );
        assert_eq!(metrics.unverified_committee_fallback_total.get(), 0);

        // Never skipping: a checkpoint served at last_checkpoint_of_epoch(head)
        // that is NOT the end-of-epoch transition of `head` is rejected, head
        // does not move. Here the relay serves the (validly committee-signed)
        // end-of-epoch checkpoint of epoch 3 when the head is 2 -- its epoch
        // doesn't match the head, so install treats it as not-the-next
        // transition and the ratchet surfaces the determinate NotEndOfEpoch.
        //
        // Note `RatchetEpochMismatch` (the EpochMismatch belt-and-suspenders in
        // the store's install step) is unreachable from the ratchet with any
        // committee-signed summary: the install head-guard fires first when
        // `summary.epoch() != head`, and when it does match, the derived next
        // epoch is always `head + 1` (Sui's `extract_new_committee_info` sets it
        // to `summary.epoch() + 1`). So the reachable "wrong epoch served at the
        // head boundary" outcome is NotEndOfEpoch, asserted here.
        let committee3 = committee_at_epoch(&committee0, &keys, 3);
        let wrong_epoch_eoe = end_of_epoch_checkpoint(&committee3, &keys, 2);
        let mut mock2 = RatchetMock::new(3);
        mock2
            .full_checkpoints
            .insert(2, FullCheckpointOutcome::Data(Box::new(wrong_epoch_eoe)));
        let mock2 = Arc::new(mock2);
        let client2 = OcsVerifyingClient::new(mock2, store.clone(), metrics, false);
        let err = client2.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::NotEndOfEpoch(2)),
            "a non-transition checkpoint at the head boundary must surface \
             NotEndOfEpoch, got {err:?}"
        );
        assert!(!err.is_retryable(), "the mismatch is a determinate failure");
        assert_eq!(store.head_epoch(), 2, "head stays at 2 on the mismatch");
    }

    // The peer-only boot ratchet loops on this classification: only transport
    // failures are retried, every determinate (proof/committee) failure must be
    // fatal so boot fails fast instead of spinning forever.
    #[test]
    fn only_transport_errors_are_retryable() {
        // Transport failures may clear on a later attempt (relay/peer recovers,
        // checkpoint gets indexed) — retryable.
        assert!(OcsError::Transport(TransportError::Network("relay down".into())).is_retryable());
        assert!(
            OcsError::Transport(TransportError::NotFound("not indexed yet".into())).is_retryable()
        );

        // Determinate conditions a retry cannot heal — must be fatal.
        assert!(!OcsError::ProofChainBroken { epoch: 7 }.is_retryable());
        assert!(
            !OcsError::FallbackEpochMismatch {
                requested: 8,
                returned: 9,
            }
            .is_retryable()
        );
        assert!(!OcsError::NotEndOfEpoch(42).is_retryable());
        assert!(!OcsError::BadCheckpointSig(42, "bad bls".into()).is_retryable());
        assert!(!OcsError::MissingCommittee(3).is_retryable());
        assert!(!OcsError::Ika("store write failed".into()).is_retryable());
    }
}
