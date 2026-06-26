// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mirror-side receiver for the changeset stream.
//!
//! A mirrored / peer-only node keeps its [`ChangesetIndex`] caught up to a
//! relay's head by repeatedly pulling [`ChangesetPage`](ika_network::sui_state_mirror)
//! and folding each entry. The index is the currency authority the read path
//! consults; this loop is the only writer. Pulls are committee-bound on arrival
//! ([`ChangesetIndex::absorb`] re-derives the artifacts digest after a BLS
//! verify), so the relay is fully untrusted.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use ika_network::sui_state_mirror::{ChangesetEntry, SuiMirrorTransport};
use ika_sui_client::transport::TransportError;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;

use crate::sui_connector::committee_store::CommitteeStore;
use crate::sui_connector::ocs_currency::{AbsorbOutcome, ChangesetError, ChangesetIndex};

/// Shared, mutable changeset index — written only by the receiver, read by the
/// read path's currency check.
pub type SharedChangesetIndex = Arc<RwLock<ChangesetIndex>>;

/// Source of changeset pages. Abstracts the relay RPC so the receiver is
/// unit-testable; implemented by [`SuiMirrorTransport`].
#[async_trait]
pub trait ChangesetSource: Send + Sync {
    async fn changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
    ) -> Result<Vec<ChangesetEntry>, TransportError>;
}

#[async_trait]
impl ChangesetSource for SuiMirrorTransport {
    async fn changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
    ) -> Result<Vec<ChangesetEntry>, TransportError> {
        Ok(SuiMirrorTransport::changeset_page(self, from_seq, limit)
            .await?
            .entries)
    }
}

/// Pull the next contiguous page — from `contiguous head + 1`, or
/// `bootstrap_from` when the index is empty — BLS-verify each entry against its
/// epoch committee, and fold it. Returns the number of entries that *advanced*
/// the contiguous frontier (0 = caught up to the source's head, or the page
/// made no progress).
///
/// BLS verification runs *outside* the index lock so the read path's currency
/// queries aren't blocked on it; only the fold takes a brief write lock.
pub async fn pump_changesets(
    index: &SharedChangesetIndex,
    source: &dyn ChangesetSource,
    committees: &CommitteeStore,
    page_limit: u32,
    bootstrap_from: CheckpointSequenceNumber,
) -> Result<usize, ChangesetError> {
    let from_seq = index
        .read()
        .highest_contiguous_seq()
        .map(|seq| seq + 1)
        .unwrap_or(bootstrap_from);
    let page = source
        .changeset_page(from_seq, page_limit)
        .await
        .map_err(|e| ChangesetError::Internal(e.to_string()))?;

    // Bound the page length before the per-entry BLS verify loop below. The
    // server clamps to `MAX_CHANGESET_PAGE`, but a byzantine peer can ignore its
    // own cap and over-stuff the page; reject up front so it can't force
    // unbounded verify work. (Absorb drops non-contiguous extras anyway — but
    // only after we'd already paid to verify them.)
    if page.len() > page_limit as usize {
        return Err(ChangesetError::Internal(format!(
            "changeset page returned {} entries, over the {page_limit} requested",
            page.len()
        )));
    }

    let mut advanced = 0;
    for entry in page {
        committees
            .verify_summary(entry.summary.clone())
            .map_err(|e| ChangesetError::Unverified(e.to_string()))?;
        if let AbsorbOutcome::Advanced { .. } =
            index.write().absorb(&entry.summary, entry.object_states)?
        {
            advanced += 1;
        }
    }
    Ok(advanced)
}

/// Background loop that keeps a mirrored node's [`ChangesetIndex`] caught up to
/// a relay's head. Spawned by the node and aborted on shutdown (it loops
/// forever, like the other `sui_connector` pumps).
pub struct ChangesetReceiver {
    index: SharedChangesetIndex,
    source: Arc<dyn ChangesetSource>,
    committees: Arc<CommitteeStore>,
    page_limit: u32,
    bootstrap_from: CheckpointSequenceNumber,
    poll_interval: Duration,
}

impl ChangesetReceiver {
    pub fn new(
        index: SharedChangesetIndex,
        source: Arc<dyn ChangesetSource>,
        committees: Arc<CommitteeStore>,
        page_limit: u32,
        bootstrap_from: CheckpointSequenceNumber,
        poll_interval: Duration,
    ) -> Self {
        Self {
            index,
            source,
            committees,
            page_limit,
            bootstrap_from,
            poll_interval,
        }
    }

    pub async fn run(self) {
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            bootstrap_from = self.bootstrap_from,
            "ChangesetReceiver starting"
        );
        let mut tick = tokio::time::interval(self.poll_interval);
        loop {
            tick.tick().await;
            // Drain: keep pulling within a tick until caught up (no further
            // advance) or an error, so a node that's behind catches up promptly
            // instead of one page per interval.
            loop {
                match pump_changesets(
                    &self.index,
                    self.source.as_ref(),
                    &self.committees,
                    self.page_limit,
                    self.bootstrap_from,
                )
                .await
                {
                    Ok(0) => break,
                    Ok(advanced) => {
                        debug!(advanced, "ChangesetReceiver folded changesets");
                    }
                    Err(e) => {
                        warn!(error = ?e, "ChangesetReceiver tick failed; will retry");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber};
    use sui_types::committee::Committee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::{CheckpointContentsDigest, CheckpointDigest};
    use sui_types::gas::GasCostSummary;
    use sui_types::message_envelope::Message;
    use sui_types::messages_checkpoint::{
        CheckpointArtifacts, CheckpointCommitment, CheckpointSummary,
    };

    type States = BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>;

    fn modified(byte: u8, version: u64) -> (ObjectID, (SequenceNumber, ObjectDigest)) {
        (
            ObjectID::from_single_byte(byte),
            (SequenceNumber::from(version), ObjectDigest::new([byte; 32])),
        )
    }

    fn signed_entry(
        committee: &Committee,
        keypairs: &[AuthorityKeyPair],
        seq: u64,
        previous: Option<CheckpointDigest>,
        object_states: States,
    ) -> (ChangesetEntry, CheckpointDigest) {
        let artifacts = CheckpointArtifacts::from_object_states(object_states.clone());
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: previous,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts.digest().unwrap())],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let digest = summary.digest();
        let summary =
            sui_types::messages_checkpoint::CertifiedCheckpointSummary::new_from_keypairs_for_testing(
                summary, keypairs, committee,
            );
        (
            ChangesetEntry {
                summary,
                object_states,
            },
            digest,
        )
    }

    /// A source serving a fixed, contiguous list of entries: returns those whose
    /// seq falls in `[from_seq, from_seq + limit)`.
    struct VecSource(Vec<ChangesetEntry>);

    #[async_trait]
    impl ChangesetSource for VecSource {
        async fn changeset_page(
            &self,
            from_seq: CheckpointSequenceNumber,
            limit: u32,
        ) -> Result<Vec<ChangesetEntry>, TransportError> {
            Ok(self
                .0
                .iter()
                .filter(|e| {
                    let seq = *e.summary.sequence_number();
                    seq >= from_seq && seq < from_seq.saturating_add(limit as u64)
                })
                .cloned()
                .collect())
        }
    }

    fn committee_store(committee: Committee) -> (tempfile::TempDir, Arc<CommitteeStore>) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store =
            CommitteeStore::open(tables, Some(CommitteeBootstrap::UnsafeGenesis(committee)))
                .unwrap();
        (dir, Arc::new(store))
    }

    /// A page of committee-signed changesets folds, advancing the index from the
    /// bootstrap seq; a subsequent pump starts at `head + 1` and is caught up.
    #[tokio::test]
    async fn pump_folds_a_committee_signed_page() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());

        let (e10, d10) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        let (e11, d11) = signed_entry(&committee, &keys, 11, Some(d10), [modified(0xB2, 1)].into());
        let (e12, _d12) =
            signed_entry(&committee, &keys, 12, Some(d11), [modified(0xC3, 1)].into());
        let source = VecSource(vec![e10, e11, e12]);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let advanced = pump_changesets(&index, &source, &store, 64, 10)
            .await
            .unwrap();
        assert_eq!(advanced, 3);
        assert_eq!(index.read().highest_contiguous_seq(), Some(12));

        // Caught up: next pull starts at 13 and finds nothing.
        let advanced = pump_changesets(&index, &source, &store, 64, 10)
            .await
            .unwrap();
        assert_eq!(advanced, 0);
        assert_eq!(index.read().highest_contiguous_seq(), Some(12));
    }

    /// A foreign-signed entry is rejected at the BLS gate and not folded.
    #[tokio::test]
    async fn pump_rejects_a_foreign_signed_entry() {
        let (store_committee, _) = Committee::new_simple_test_committee_of_size(4);
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let (_dir, store) = committee_store(store_committee);

        let (e10, _d10) = signed_entry(
            &foreign,
            &foreign_keys,
            10,
            None,
            [modified(0xA1, 1)].into(),
        );
        let source = VecSource(vec![e10]);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let result = pump_changesets(&index, &source, &store, 64, 10).await;
        assert!(matches!(result, Err(ChangesetError::Unverified(_))));
        assert_eq!(index.read().highest_contiguous_seq(), None);
    }

    /// A correctly committee-signed page whose summary commits to the artifacts
    /// of `{A, B}` but whose shipped `object_states` carries only `{A}` is
    /// rejected past the BLS gate: `absorb` re-derives the artifacts digest of
    /// the shipped set and finds it doesn't match the summary's commitment, so
    /// `pump_changesets` surfaces `ArtifactsMismatch`. Nothing is folded — the
    /// contiguous frontier is unchanged. A relay can't strip ids out from under
    /// a genuine signature.
    #[tokio::test]
    async fn forged_object_states_are_rejected_and_not_folded() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());

        // Summary signed over the artifacts of {A, B}.
        let honest: States = [modified(0xA1, 1), modified(0xB2, 1)].into();
        let (entry, _digest) = signed_entry(&committee, &keys, 10, None, honest);
        // ...but the page ships only {A}: drop B while keeping the {A, B} signature.
        let forged_states: States = [modified(0xA1, 1)].into();
        let forged_entry = ChangesetEntry {
            summary: entry.summary,
            object_states: forged_states,
        };
        let source = VecSource(vec![forged_entry]);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let result = pump_changesets(&index, &source, &store, 64, 10).await;

        // Past BLS, the artifacts re-derivation rejects the dropped id.
        assert_eq!(result, Err(ChangesetError::ArtifactsMismatch(10)));
        // Nothing folded: the frontier is untouched.
        assert_eq!(index.read().highest_contiguous_seq(), None);
    }

    /// A page whose seq 11 carries a wrong `previous_digest` halts the fold:
    /// seq 10 folds, then `absorb` rejects 11 with `BrokenChain` and
    /// `pump_changesets` surfaces it. The contiguous frontier stays at 10, and
    /// re-pumping the same forked page makes no further progress — a persistent
    /// byzantine fork is a stuck retry loop, never a silent advance past the gap.
    #[tokio::test]
    async fn broken_chain_halts_the_fold_without_advancing() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());

        let (e10, _d10) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        // 11 is correctly signed but does NOT chain onto 10's digest (a fork).
        let forked_previous = CheckpointDigest::new([0x99; 32]);
        let (e11, _d11) = signed_entry(
            &committee,
            &keys,
            11,
            Some(forked_previous),
            [modified(0xB2, 1)].into(),
        );
        let source = VecSource(vec![e10, e11]);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));

        // First pump folds 10, then hits the broken chain at 11.
        let result = pump_changesets(&index, &source, &store, 64, 10).await;
        assert_eq!(result, Err(ChangesetError::BrokenChain { seq: 11 }));
        assert_eq!(
            index.read().highest_contiguous_seq(),
            Some(10),
            "10 folded; the fork at 11 must not advance the frontier"
        );

        // Re-pump (now from 11): the persistent fork makes no progress.
        let result = pump_changesets(&index, &source, &store, 64, 10).await;
        assert_eq!(result, Err(ChangesetError::BrokenChain { seq: 11 }));
        assert_eq!(index.read().highest_contiguous_seq(), Some(10));
    }

    /// A page `[seq10 valid, seq11 foreign-signed, seq12 valid]`: 10 folds, the
    /// BLS gate rejects 11 (`Unverified`) and `pump_changesets` returns Err
    /// *before* 12 is ever folded. Neither 11 nor 12 is persisted — the frontier
    /// is 10 — and a retry resumes from 11. A single bad BLS signature mid-page
    /// can't be skipped over to fold a later valid entry out of order.
    #[tokio::test]
    async fn partial_page_bls_failure_does_not_advance_or_persist() {
        let (committee, keys) = Committee::new_simple_test_committee_of_size(4);
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let (_dir, store) = committee_store(committee.clone());

        let (e10, d10) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        // 11 chains correctly onto 10 but is signed by a foreign committee — it
        // dies at the BLS gate before `absorb` is even reached.
        let (e11, d11) = signed_entry(
            &foreign,
            &foreign_keys,
            11,
            Some(d10),
            [modified(0xB2, 1)].into(),
        );
        // 12 is valid and chains onto 11, but is never reached this page.
        let (e12, _d12) =
            signed_entry(&committee, &keys, 12, Some(d11), [modified(0xC3, 1)].into());
        let source = VecSource(vec![e10, e11, e12]);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let result = pump_changesets(&index, &source, &store, 64, 10).await;

        // The foreign signature at 11 fails the gate; 12 is never folded.
        assert!(matches!(result, Err(ChangesetError::Unverified(_))));
        assert_eq!(
            index.read().highest_contiguous_seq(),
            Some(10),
            "only 10 folded; 11/12 must not be persisted"
        );

        // A retry resumes from 11 and stalls there again (the fork is persistent).
        let result = pump_changesets(&index, &source, &store, 64, 10).await;
        assert!(matches!(result, Err(ChangesetError::Unverified(_))));
        assert_eq!(index.read().highest_contiguous_seq(), Some(10));
    }

    /// The receiver's drain catches up in one pass even when the page limit is
    /// far smaller than the backlog: a source holding seqs 10..30 with
    /// `page_limit = 5` is fully folded by repeatedly pumping until a pump
    /// reports no advance (`Ok(0)`) — exactly the inner loop `run()` runs each
    /// tick. A node that fell behind by many pages catches up promptly, not one
    /// page per poll interval.
    #[tokio::test]
    async fn pump_drains_all_available_pages_in_one_pass() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());

        // Chain seqs 10..30 (20 contiguous entries).
        let mut entries = Vec::new();
        let mut previous = None;
        for seq in 10u64..30 {
            let (entry, digest) = signed_entry(
                &committee,
                &keys,
                seq,
                previous,
                [modified(seq as u8, 1)].into(),
            );
            entries.push(entry);
            previous = Some(digest);
        }
        let source = VecSource(entries);

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let page_limit = 5; // smaller than the 20-entry span.

        // Mirror the receiver's per-tick drain: pump until a pump advances nothing.
        let mut total_advanced = 0;
        let mut pumps = 0;
        loop {
            let advanced = pump_changesets(&index, &source, &store, page_limit, 10)
                .await
                .unwrap();
            if advanced == 0 {
                break;
            }
            total_advanced += advanced;
            pumps += 1;
        }

        // All 20 folded in the single drain pass, spanning multiple pages.
        assert_eq!(total_advanced, 20);
        assert!(pumps > 1, "the backlog must span more than one page");
        assert_eq!(index.read().highest_contiguous_seq(), Some(29));
    }
}
