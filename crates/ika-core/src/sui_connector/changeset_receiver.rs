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
}
