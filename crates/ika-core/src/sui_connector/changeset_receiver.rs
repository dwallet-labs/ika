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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use ika_network::sui_state_mirror::{ChangesetEntry, SuiMirrorTransport};
use ika_sui_client::transport::TransportError;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;

use crate::sui_connector::committee_store::{
    CommitteeStore, CommitteeTransition, SummaryVerifyError,
};
use crate::sui_connector::ocs_currency::{AbsorbOutcome, ChangesetError, ChangesetIndex};
use crate::sui_connector::ocs_metrics::OcsMetrics;

/// Shared, mutable changeset index — written only by the receiver, read by the
/// read path's currency check.
pub type SharedChangesetIndex = Arc<RwLock<ChangesetIndex>>;

/// How long the changeset frontier may go without advancing before the
/// receiver asks every relay for the next checkpoint instead of only the one
/// it prefers. Sui makes checkpoints continuously and a healthy receiver
/// advances on every poll, so half a minute without an advance means the
/// preferred relay has nothing newer: it has stopped, or cannot serve the next
/// checkpoint. Otherwise such a relay is indistinguishable from being caught
/// up, and in automatic peer mode the first relay that answers keeps being
/// preferred. A relay that is behind but still advancing is not passed over.
const SEEK_SUCCESSOR_AFTER: Duration = Duration::from_secs(30);
/// While the frontier stays stalled, how often every relay is asked again.
const SEEK_SUCCESSOR_INTERVAL: Duration = Duration::from_secs(30);
/// How long the frontier may go without advancing before the receiver reports
/// that no relay is serving it anything new. The log text says "5 minutes";
/// keep it in step.
const UPSTREAM_FROZEN_AFTER: Duration = Duration::from_secs(5 * 60);

/// Unix seconds now, for the `*_timestamp_seconds` gauges.
fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Source of changeset pages. Abstracts the relay RPC so the receiver is
/// unit-testable; implemented by [`SuiMirrorTransport`].
#[async_trait]
pub trait ChangesetSource: Send + Sync {
    async fn changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
        require_contiguous: bool,
        known_gap: bool,
    ) -> Result<Vec<ChangesetEntry>, TransportError>;

    /// Pass over the source of the last page: one of its entries failed
    /// verification. The default does nothing.
    fn reject_last_page(&self) {}

    /// Leave the source of the last page out of the pulls until the frontier
    /// advances, without demoting it: one of its entries cannot be checked
    /// yet. The default does nothing.
    fn pass_over_last_page(&self) {}

    /// The frontier advanced: sources passed over may be asked again. The
    /// default does nothing.
    fn frontier_advanced(&self) {}
}

#[async_trait]
impl ChangesetSource for SuiMirrorTransport {
    async fn changeset_page(
        &self,
        from_seq: CheckpointSequenceNumber,
        limit: u32,
        require_contiguous: bool,
        known_gap: bool,
    ) -> Result<Vec<ChangesetEntry>, TransportError> {
        Ok(
            SuiMirrorTransport::changeset_page(
                self,
                from_seq,
                limit,
                require_contiguous,
                known_gap,
            )
            .await?
            .entries,
        )
    }

    fn reject_last_page(&self) {
        self.reject_last_changeset_source();
    }

    fn pass_over_last_page(&self) {
        self.pass_over_last_changeset_source();
    }

    fn frontier_advanced(&self) {
        self.changeset_frontier_advanced();
    }
}

/// Pull the next contiguous page — from `contiguous head + 1`, or
/// `bootstrap_from` when the index is empty — BLS-verify each entry against its
/// epoch committee, and fold it. Returns the number of entries that *advanced*
/// the contiguous frontier (0 = empty page or already folded by concurrent
/// gossip). A non-contiguous page is an explicit error, never caught-up.
///
/// `seek_successor` asks every serving relay for the next checkpoint, as a
/// known gap does: a relay with nothing newer is passed over (and demoted)
/// rather than taken as caught up. When none has anything newer, that is the
/// answer, not a failure: the page is empty.
///
/// A page with an entry that fails verification (committee signature,
/// artifacts binding or chain link) has its source passed over
/// ([`ChangesetSource::reject_last_page`]), so the next pull asks another
/// relay.
///
/// BLS verification runs *outside* the index lock so the read path's currency
/// queries aren't blocked on it; only the fold takes the write lock. The fold
/// re-derives the entry's artifacts digest over every object state under that
/// lock, so for a large part-read entry (up to 2 million states) the lock is
/// held for as long as that takes.
pub async fn pump_changesets(
    index: &SharedChangesetIndex,
    source: &dyn ChangesetSource,
    committees: &CommitteeStore,
    page_limit: u32,
    bootstrap_from: CheckpointSequenceNumber,
    seek_successor: bool,
) -> Result<usize, ChangesetError> {
    let (head, highest_seen) = {
        let index = index.read();
        (index.highest_contiguous_seq(), index.highest_seen_seq())
    };
    let known_gap = highest_seen > head;
    let from_seq = head.map(|seq| seq + 1).unwrap_or(bootstrap_from);
    let page = match source
        .changeset_page(
            from_seq,
            page_limit,
            head.is_some(),
            known_gap || seek_successor,
        )
        .await
    {
        Ok(page) => page,
        // Every serving relay was asked for `from_seq` and none had it: none
        // is ahead of this node.
        Err(TransportError::NotFound(_)) if seek_successor && !known_gap => Vec::new(),
        Err(e) => return Err(ChangesetError::Internal(e.to_string())),
    };

    if page.is_empty()
        && let Some(received) = highest_seen.filter(|_| known_gap)
    {
        return Err(ChangesetError::Gap {
            expected: from_seq,
            received,
        });
    }

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
    let mut expected = head.map(|_| from_seq);
    for entry in page {
        let received = *entry.summary.sequence_number();
        if let Some(expected) = expected
            && received != expected
        {
            return Err(ChangesetError::Gap { expected, received });
        }
        expected = Some(received.saturating_add(1));
        match committees.verify_summary(entry.summary.clone()) {
            Ok(_) => {}
            Err(e @ SummaryVerifyError::MissingCommittee(epoch)) => {
                let store_head = committees.head_epoch();
                // An epoch at or below the store's head without a committee
                // is this node's own gap, not the relay's.
                if epoch <= store_head {
                    return Err(ChangesetError::Unverified(e.to_string()));
                }
                // The entry's epoch has no committee installed, so its
                // signature cannot be checked. It is plausible only while the
                // index is bootstrapping, when it may begin in a later epoch
                // than the committee ratchet has reached, or right after the
                // end-of-epoch checkpoint of the store's head epoch, when the
                // next committee's install (below, or the ratchet's) is still
                // to come. That is a wait: this relay is left out of the pulls
                // until the frontier advances, without being demoted, so
                // relays serving entries that cannot be checked yet cannot hold
                // the receiver on them while another relay can serve.
                let (bootstrapping, head_ends_epoch) = {
                    let index = index.read();
                    (
                        index.highest_contiguous_seq().is_none(),
                        index.head_ends_epoch(),
                    )
                };
                if bootstrapping || (epoch == store_head + 1 && head_ends_epoch == Some(store_head))
                {
                    source.pass_over_last_page();
                    return Err(ChangesetError::AwaitingCommittee {
                        seq: received,
                        epoch,
                    });
                }
                // Anything else claims an epoch the chain cannot have reached
                // after the index head: the relay served a forged entry.
                source.reject_last_page();
                return Err(ChangesetError::Unverified(e.to_string()));
            }
            // A bad signature: the relay served a forged entry.
            Err(e) => {
                source.reject_last_page();
                return Err(ChangesetError::Unverified(e.to_string()));
            }
        }
        let absorbed = index.write().absorb(&entry.summary, entry.object_states);
        match absorbed {
            Ok(AbsorbOutcome::Advanced { .. }) => advanced += 1,
            Ok(_) => {}
            Err(
                e @ (ChangesetError::ArtifactsMismatch(_) | ChangesetError::BrokenChain { .. }),
            ) => {
                source.reject_last_page();
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        // A folded end-of-epoch checkpoint carries the next epoch's committee:
        // install it now, so the entries after it verify without waiting for
        // the committee ratchet. The install is head-guarded and verifies the
        // summary against the head committee itself; any other checkpoint is a
        // no-op.
        if entry.summary.end_of_epoch_data.is_some() {
            match committees.install_next_from_summary(&entry.summary) {
                Ok(CommitteeTransition::Installed(epoch)) => info!(
                    epoch,
                    seq = received,
                    "installed the next Sui committee from a folded end-of-epoch changeset"
                ),
                Ok(CommitteeTransition::NotNextTransition) => {}
                Err(error) => warn!(
                    seq = received,
                    %error,
                    "could not install the next Sui committee from a folded end-of-epoch \
                     changeset; the committee ratchet installs it"
                ),
            }
        }
    }
    if advanced > 0 {
        source.frontier_advanced();
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
    metrics: Arc<OcsMetrics>,
    /// When the tick-failure warn last fired (it is rate limited).
    last_warning: Option<Instant>,
    /// The epoch whose missing committee was last logged as a wait, so a
    /// wait logs once per epoch.
    awaiting_committee_logged: Option<u64>,
    /// Whether the relays are still serving this node new checkpoints.
    frontier: FrontierWatch,
}

/// Whether the changeset frontier is still advancing. A relay whose own
/// fullnode is dead or stuck answers with empty pages, which read exactly like
/// being caught up, so only time tells: Sui makes checkpoints continuously,
/// and a frontier that has not moved for [`SEEK_SUCCESSOR_AFTER`] means the
/// preferred relay has nothing newer.
struct FrontierWatch {
    /// When the frontier last advanced; the receiver's start until it first
    /// does. Tokio's clock, so tests drive it with paused time.
    advanced_at: tokio::time::Instant,
    /// When every relay was last asked for the next checkpoint, in the current
    /// stall.
    last_seek: Option<tokio::time::Instant>,
    /// The latest failed pull's error, cleared by a pull that succeeds.
    last_error: Option<String>,
    /// Whether the frozen error has fired for the current stall: a transition
    /// latch, so a stall that lasts logs once and once more when it ends.
    frozen_reported: bool,
}

impl ChangesetReceiver {
    pub fn new(
        index: SharedChangesetIndex,
        source: Arc<dyn ChangesetSource>,
        committees: Arc<CommitteeStore>,
        page_limit: u32,
        bootstrap_from: CheckpointSequenceNumber,
        poll_interval: Duration,
        metrics: Arc<OcsMetrics>,
    ) -> Self {
        // A node that started the clock at boot keeps that start.
        metrics.start_changeset_upstream_clock();
        Self {
            index,
            source,
            committees,
            page_limit,
            bootstrap_from,
            poll_interval,
            metrics,
            last_warning: None,
            awaiting_committee_logged: None,
            frontier: FrontierWatch {
                advanced_at: tokio::time::Instant::now(),
                last_seek: None,
                last_error: None,
                frozen_reported: false,
            },
        }
    }

    pub async fn run(mut self) {
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            bootstrap_from = self.bootstrap_from,
            "ChangesetReceiver starting"
        );
        let mut tick = tokio::time::interval(self.poll_interval);
        loop {
            tick.tick().await;
            self.tick().await;
        }
    }

    /// One poll. Drain: keep pulling until caught up (no further advance) or
    /// an error, so a node that's behind catches up promptly instead of one
    /// page per interval. Once the frontier has stalled for
    /// [`SEEK_SUCCESSOR_AFTER`], the first pull of a tick asks every relay for
    /// the next checkpoint, at most every [`SEEK_SUCCESSOR_INTERVAL`].
    async fn tick(&mut self) {
        let now = tokio::time::Instant::now();
        let mut seek =
            now.saturating_duration_since(self.frontier.advanced_at) >= SEEK_SUCCESSOR_AFTER
                && self.frontier.last_seek.is_none_or(|last| {
                    now.saturating_duration_since(last) >= SEEK_SUCCESSOR_INTERVAL
                });
        if seek {
            self.frontier.last_seek = Some(now);
            debug!(
                contiguous_head = ?self.index.read().highest_contiguous_seq(),
                "changeset frontier has stalled; asking every relay for the next checkpoint"
            );
        }
        let mut advanced_total = 0;
        loop {
            match pump_changesets(
                &self.index,
                self.source.as_ref(),
                &self.committees,
                self.page_limit,
                self.bootstrap_from,
                seek,
            )
            .await
            {
                Ok(advanced) => {
                    self.frontier.last_error = None;
                    if seek {
                        self.count_seek(if advanced > 0 { "advanced" } else { "none" });
                        seek = false;
                    }
                    if advanced == 0 {
                        break;
                    }
                    advanced_total += advanced;
                    // Noted per page, not once the drain ends: a node far
                    // behind (after a restart it can start hundreds of
                    // thousands of checkpoints back) drains for hours, and the
                    // last-advance gauge must move with it.
                    self.note_frontier(true);
                    debug!(advanced, "ChangesetReceiver folded changesets");
                }
                Err(e @ ChangesetError::AwaitingCommittee { .. }) => {
                    // A wait: no failure counted, logged once per epoch.
                    if seek {
                        self.count_seek("none");
                    }
                    if let ChangesetError::AwaitingCommittee { seq, epoch } = &e
                        && self.awaiting_committee_logged != Some(*epoch)
                    {
                        self.awaiting_committee_logged = Some(*epoch);
                        info!(
                            seq,
                            epoch,
                            "changeset waits for the next Sui epoch's committee to be installed"
                        );
                    }
                    self.frontier.last_error = Some(e.to_string());
                    break;
                }
                Err(e) => {
                    if seek {
                        self.count_seek("failed");
                    }
                    match &e {
                        ChangesetError::Gap { .. } => self.metrics.changeset_gap_total.inc(),
                        ChangesetError::Internal(_) => {
                            self.metrics.changeset_fetch_failures_total.inc()
                        }
                        _ => {}
                    }
                    if self
                        .last_warning
                        .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
                    {
                        self.last_warning = Some(Instant::now());
                        warn!(error = ?e, "ChangesetReceiver tick failed; will retry");
                    }
                    self.frontier.last_error = Some(e.to_string());
                    break;
                }
            }
        }
        if advanced_total == 0 {
            self.note_frontier(false);
        }
    }

    fn count_seek(&self, outcome: &str) {
        self.metrics
            .changeset_successor_seeks_total
            .with_label_values(&[outcome])
            .inc();
    }

    /// Record whether the frontier advanced: called on every page that
    /// advances it, and once at the end of a tick that advanced nothing.
    /// Reports a frozen upstream on the transition past
    /// [`UPSTREAM_FROZEN_AFTER`] without an advance, and once more when the
    /// frontier advances again.
    fn note_frontier(&mut self, advanced: bool) {
        let now = tokio::time::Instant::now();
        let previous_advance = self.frontier.advanced_at;
        if advanced {
            self.frontier.advanced_at = now;
            self.frontier.last_seek = None;
            self.metrics
                .changeset_upstream_last_advance_timestamp_seconds
                .set(unix_now_secs());
        }
        let frozen_for = now.saturating_duration_since(self.frontier.advanced_at);
        let frozen = frozen_for >= UPSTREAM_FROZEN_AFTER;
        if frozen == self.frontier.frozen_reported {
            return;
        }
        self.frontier.frozen_reported = frozen;
        let contiguous_head = self
            .index
            .read()
            .highest_contiguous_seq()
            .map_or_else(|| "none yet".to_owned(), |seq| seq.to_string());
        if frozen {
            error!(
                %contiguous_head,
                frozen_secs = frozen_for.as_secs(),
                last_relay_error = self.frontier.last_error.as_deref().unwrap_or(
                    "none: the relays answer, but none has a newer checkpoint"
                ),
                "no Sui state relay is advancing: no relay has served this node a Sui \
                 checkpoint past its changeset frontier for over 5 minutes, so the changeset \
                 index that verified reads check currency against is not moving. Every \
                 reachable relay is asked for the next checkpoint every 30 seconds. Check this \
                 node's p2p connectivity to sui-state-direct validators, and the \
                 sui-state-mirror-peers list if one is set (logged once until a relay serves \
                 a newer checkpoint)"
            );
        } else {
            info!(
                %contiguous_head,
                was_frozen_secs = now.saturating_duration_since(previous_advance).as_secs(),
                "a Sui state relay is serving new checkpoints again; the changeset frontier \
                 is moving"
            );
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
            _require_contiguous: bool,
            _known_gap: bool,
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
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee))).unwrap();
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
        let advanced = pump_changesets(&index, &source, &store, 64, 10, false)
            .await
            .unwrap();
        assert_eq!(advanced, 3);
        assert_eq!(index.read().highest_contiguous_seq(), Some(12));

        // Caught up: next pull starts at 13 and finds nothing.
        let advanced = pump_changesets(&index, &source, &store, 64, 10, false)
            .await
            .unwrap();
        assert_eq!(advanced, 0);
        assert_eq!(index.read().highest_contiguous_seq(), Some(12));
    }

    #[tokio::test]
    async fn retention_gap_is_not_caught_up_and_verified_successor_recovers() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let (first, digest) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        let (missing, digest) = signed_entry(
            &committee,
            &keys,
            11,
            Some(digest),
            [modified(0xA1, 2)].into(),
        );
        let (later, _) = signed_entry(
            &committee,
            &keys,
            12,
            Some(digest),
            [modified(0xA1, 3)].into(),
        );
        let index = Arc::new(RwLock::new(ChangesetIndex::new()));
        pump_changesets(&index, &VecSource(vec![first]), &store, 64, 10, false)
            .await
            .unwrap();
        assert_eq!(
            pump_changesets(
                &index,
                &VecSource(vec![later.clone()]),
                &store,
                64,
                10,
                false
            )
            .await,
            Err(ChangesetError::Gap {
                expected: 11,
                received: 12
            }),
            "a retained later checkpoint must surface a gap, not caught-up"
        );
        assert_eq!(index.read().highest_contiguous_seq(), Some(10));
        assert_eq!(
            pump_changesets(
                &index,
                &VecSource(vec![missing, later]),
                &store,
                64,
                10,
                false
            )
            .await
            .unwrap(),
            2
        );
        assert_eq!(index.read().highest_contiguous_seq(), Some(12));
    }

    #[tokio::test]
    async fn empty_index_can_bootstrap_at_relay_retention_floor() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let (entry, _) = signed_entry(&committee, &keys, 30, None, [modified(0xA1, 1)].into());
        let index = Arc::new(RwLock::new(ChangesetIndex::new()));
        assert_eq!(
            pump_changesets(&index, &VecSource(vec![entry]), &store, 64, 10, false)
                .await
                .unwrap(),
            1
        );
        assert_eq!(index.read().highest_contiguous_seq(), Some(30));
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
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;
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
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;

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
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;
        assert_eq!(result, Err(ChangesetError::BrokenChain { seq: 11 }));
        assert_eq!(
            index.read().highest_contiguous_seq(),
            Some(10),
            "10 folded; the fork at 11 must not advance the frontier"
        );

        // Re-pump (now from 11): the persistent fork makes no progress.
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;
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
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;

        // The foreign signature at 11 fails the gate; 12 is never folded.
        assert!(matches!(result, Err(ChangesetError::Unverified(_))));
        assert_eq!(
            index.read().highest_contiguous_seq(),
            Some(10),
            "only 10 folded; 11/12 must not be persisted"
        );

        // A retry resumes from 11 and stalls there again (the fork is persistent).
        let result = pump_changesets(&index, &source, &store, 64, 10, false).await;
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
            let advanced = pump_changesets(&index, &source, &store, page_limit, 10, false)
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

    // ---- a frozen relay ----

    /// The relays as the receiver sees them through the relay client: each
    /// serves the chain up to its own head, in preference order. A plain pull
    /// asks the preferred relay alone and takes "nothing newer" as caught up.
    /// A pull that seeks the successor asks each in turn, demotes a relay with
    /// nothing newer to the back, and answers `NotFound` when none has
    /// anything — what `SuiMirrorTransport::changeset_page` does.
    struct Relays {
        chain: Vec<ChangesetEntry>,
        heads: parking_lot::Mutex<Vec<u64>>,
        unreachable: std::sync::atomic::AtomicBool,
    }

    impl Relays {
        fn page(&self, head: u64, from_seq: u64, limit: u32) -> Vec<ChangesetEntry> {
            self.chain
                .iter()
                .filter(|entry| {
                    let seq = *entry.summary.sequence_number();
                    seq >= from_seq && seq <= head && seq < from_seq + u64::from(limit)
                })
                .cloned()
                .collect()
        }

        fn set_heads(&self, heads: &[u64]) {
            *self.heads.lock() = heads.to_vec();
        }
    }

    #[async_trait]
    impl ChangesetSource for Relays {
        async fn changeset_page(
            &self,
            from_seq: CheckpointSequenceNumber,
            limit: u32,
            _require_contiguous: bool,
            seek_successor: bool,
        ) -> Result<Vec<ChangesetEntry>, TransportError> {
            if self.unreachable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(TransportError::Network(
                    "changeset_page: all peers failed (last: every relay timed out)".into(),
                ));
            }
            let mut heads = self.heads.lock();
            if !seek_successor {
                return Ok(self.page(heads[0], from_seq, limit));
            }
            for _ in 0..heads.len() {
                let page = self.page(heads[0], from_seq, limit);
                if !page.is_empty() {
                    return Ok(page);
                }
                heads.rotate_left(1);
            }
            Err(TransportError::NotFound("changeset page is empty".into()))
        }
    }

    const FROZEN: &str = "no Sui state relay is advancing";
    const RECOVERED: &str = "a Sui state relay is serving new checkpoints again";
    /// What the last-advance gauge is overwritten with, so a tick that
    /// rewrites it shows: real stamps are the current Unix time.
    const STALE_STAMP: i64 = 1;

    struct FrozenRelayFixture {
        relays: Arc<Relays>,
        receiver: ChangesetReceiver,
        index: SharedChangesetIndex,
        metrics: Arc<OcsMetrics>,
        started: i64,
        _dir: tempfile::TempDir,
    }

    impl FrozenRelayFixture {
        /// A receiver bootstrapping at 10 over relays at `heads`, in preference
        /// order, serving one chain from 10 to 120.
        fn new(heads: &[u64]) -> Self {
            Self::with_source(heads, |relays, _| relays)
        }

        /// [`Self::new`], with the receiver pulling through the source that
        /// `source` builds over the relays and the metrics.
        fn with_source(
            heads: &[u64],
            source: impl FnOnce(Arc<Relays>, Arc<OcsMetrics>) -> Arc<dyn ChangesetSource>,
        ) -> Self {
            let (committee, keys) = Committee::new_simple_test_committee();
            let (dir, store) = committee_store(committee.clone());
            let mut chain = Vec::new();
            let mut previous = None;
            for seq in 10u64..=120 {
                let (entry, digest) = signed_entry(
                    &committee,
                    &keys,
                    seq,
                    previous,
                    [modified(seq as u8, 1)].into(),
                );
                chain.push(entry);
                previous = Some(digest);
            }
            let relays = Arc::new(Relays {
                chain,
                heads: parking_lot::Mutex::new(heads.to_vec()),
                unreachable: Default::default(),
            });
            let metrics = OcsMetrics::new_for_testing();
            let index: SharedChangesetIndex = Arc::new(RwLock::new(
                ChangesetIndex::new().with_metrics(metrics.clone()),
            ));
            let started = unix_now_secs();
            let receiver = ChangesetReceiver::new(
                index.clone(),
                source(relays.clone(), metrics.clone()),
                store,
                64,
                10,
                Duration::from_secs(2),
                metrics.clone(),
            );
            Self {
                relays,
                receiver,
                index,
                metrics,
                started,
                _dir: dir,
            }
        }

        /// Ticks the receiver at each of `times` (seconds since the fixture
        /// started, increasing), moving the paused clock to each first.
        async fn tick_at(
            &mut self,
            origin: tokio::time::Instant,
            times: impl Iterator<Item = u64>,
        ) {
            for at in times {
                let target = origin + Duration::from_secs(at);
                tokio::time::advance(target.saturating_duration_since(tokio::time::Instant::now()))
                    .await;
                self.receiver.tick().await;
            }
        }

        fn head(&self) -> Option<u64> {
            self.index.read().highest_contiguous_seq()
        }

        fn seeks(&self, outcome: &str) -> u64 {
            self.metrics
                .changeset_successor_seeks_total
                .with_label_values(&[outcome])
                .get()
        }

        fn last_advance(&self) -> i64 {
            self.metrics
                .changeset_upstream_last_advance_timestamp_seconds
                .get()
        }

        fn stale_last_advance(&self) {
            self.metrics
                .changeset_upstream_last_advance_timestamp_seconds
                .set(STALE_STAMP);
        }
    }

    /// Everything logged on this thread while the guard lives (the tests run
    /// on a current-thread runtime). The idle second dispatcher makes
    /// `tracing` consult every live dispatcher for callsite interest, so a
    /// parallel test without a subscriber cannot cache these callsites as
    /// uninteresting.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn start() -> (Self, (tracing::subscriber::DefaultGuard, tracing::Dispatch)) {
            let idle = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            let logs = Self::default();
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            (logs, (tracing::subscriber::set_default(subscriber), idle))
        }

        fn lines_with(&self, needle: &str) -> Vec<String> {
            String::from_utf8_lossy(&self.0.lock())
                .lines()
                .filter(|line| line.contains(needle))
                .map(str::to_owned)
                .collect()
        }
    }

    fn assert_carries(line: &str, expected: &[&str]) {
        for expected in expected {
            assert!(line.contains(expected), "must carry {expected:?}: {line}");
        }
    }

    /// The preferred relay stops at 12 while another is at 20. Its empty
    /// pages read as caught up, so nothing moves until the frontier has
    /// stalled for 30 seconds; then every relay is asked, the one ahead serves,
    /// and it is preferred from then on (the stalled one was demoted).
    #[tokio::test(start_paused = true)]
    async fn a_stalled_preferred_relay_is_passed_over_for_one_that_is_ahead() {
        let (logs, _guard) = CapturedLogs::start();
        let origin = tokio::time::Instant::now();
        let mut fx = FrozenRelayFixture::new(&[12, 20]);
        fx.tick_at(origin, [0].into_iter()).await;
        assert_eq!(fx.head(), Some(12));

        fx.tick_at(origin, (2..=28).step_by(2)).await;
        assert_eq!(fx.head(), Some(12), "only the preferred relay is asked");
        assert_eq!(fx.seeks("advanced") + fx.seeks("none"), 0);

        fx.stale_last_advance();
        fx.tick_at(origin, [30].into_iter()).await;
        assert_eq!(fx.head(), Some(20), "the relay that is ahead serves");
        assert_eq!(fx.seeks("advanced"), 1);
        assert!(
            fx.last_advance() >= fx.started,
            "an advance stamps the gauge"
        );
        assert_eq!(
            *fx.relays.heads.lock(),
            vec![20, 12],
            "the stalled relay is demoted"
        );

        fx.relays.set_heads(&[25, 12]);
        fx.tick_at(origin, [32].into_iter()).await;
        assert_eq!(
            fx.head(),
            Some(25),
            "the relay ahead is now the preferred one"
        );
        assert_eq!(fx.seeks("advanced") + fx.seeks("none"), 1);
        assert!(logs.lines_with(FROZEN).is_empty());
        assert!(logs.lines_with(RECOVERED).is_empty());
    }

    /// No relay has anything past 12. Every relay is asked again every 30
    /// seconds — a relay with nothing newer is the answer, not a failure — and
    /// once the frontier has stalled for five minutes one ERROR says so.
    #[tokio::test(start_paused = true)]
    async fn when_no_relay_is_ahead_the_freeze_is_reported_once() {
        let (logs, _guard) = CapturedLogs::start();
        let origin = tokio::time::Instant::now();
        let mut fx = FrozenRelayFixture::new(&[12, 12]);
        fx.tick_at(origin, [0].into_iter()).await;
        fx.stale_last_advance();

        fx.tick_at(origin, (2..=298).step_by(2)).await;
        assert!(logs.lines_with(FROZEN).is_empty(), "under the threshold");
        assert_eq!(fx.seeks("none"), 9, "every 30 s from 30 s on");
        fx.tick_at(origin, (300..=400).step_by(2)).await;

        assert_eq!(fx.seeks("none"), 13);
        assert_eq!(fx.seeks("advanced") + fx.seeks("failed"), 0);
        assert_eq!(fx.metrics.changeset_fetch_failures_total.get(), 0);
        assert_eq!(fx.last_advance(), STALE_STAMP, "no advance, no stamp");
        let frozen = logs.lines_with(FROZEN);
        assert_eq!(frozen.len(), 1, "latched to the transition: {frozen:?}");
        assert_carries(
            &frozen[0],
            &[
                "ERROR",
                "contiguous_head=12",
                "frozen_secs=300",
                "none has a newer checkpoint",
            ],
        );
    }

    /// A relay moves again: the next ask of every relay finds it, the stall
    /// ends with one INFO and a fresh stamp, and a later stall is reported
    /// again.
    #[tokio::test(start_paused = true)]
    async fn a_relay_that_moves_again_ends_the_freeze_once() {
        let (logs, _guard) = CapturedLogs::start();
        let origin = tokio::time::Instant::now();
        let mut fx = FrozenRelayFixture::new(&[12, 12]);
        fx.tick_at(origin, (0..=300).step_by(30)).await;
        assert_eq!(logs.lines_with(FROZEN).len(), 1);

        fx.relays.set_heads(&[12, 30]);
        fx.stale_last_advance();
        fx.tick_at(origin, [330].into_iter()).await;
        assert_eq!(fx.head(), Some(30));
        assert!(
            fx.last_advance() >= fx.started,
            "the advance stamps the gauge"
        );
        let recovered = logs.lines_with(RECOVERED);
        assert_eq!(recovered.len(), 1, "{recovered:?}");
        assert_carries(
            &recovered[0],
            &["INFO", "contiguous_head=30", "was_frozen_secs=330"],
        );

        fx.relays.set_heads(&[31, 12]);
        fx.tick_at(origin, [332].into_iter()).await;
        assert_eq!(fx.head(), Some(31));
        assert_eq!(logs.lines_with(RECOVERED).len(), 1, "once per stall");

        fx.tick_at(origin, (362..=632).step_by(30)).await;
        let frozen = logs.lines_with(FROZEN);
        assert_eq!(frozen.len(), 2, "the latch re-arms: {frozen:?}");
        assert_carries(&frozen[1], &["contiguous_head=31", "frozen_secs=300"]);
    }

    /// Relays that do not answer at all: every pull fails and counts, and the
    /// freeze is reported with the relay error.
    #[tokio::test(start_paused = true)]
    async fn unreachable_relays_are_reported_frozen_with_their_error() {
        let (logs, _guard) = CapturedLogs::start();
        let origin = tokio::time::Instant::now();
        let mut fx = FrozenRelayFixture::new(&[12]);
        fx.tick_at(origin, [0].into_iter()).await;
        fx.relays
            .unreachable
            .store(true, std::sync::atomic::Ordering::SeqCst);

        fx.tick_at(origin, (30..=300).step_by(30)).await;

        assert_eq!(fx.metrics.changeset_fetch_failures_total.get(), 10);
        assert_eq!(fx.seeks("failed"), 10);
        let frozen = logs.lines_with(FROZEN);
        assert_eq!(frozen.len(), 1, "{frozen:?}");
        assert_carries(
            &frozen[0],
            &["ERROR", "frozen_secs=300", "every relay timed out"],
        );
    }

    /// A frontier that advances on every poll never asks every relay and never
    /// reports a freeze, and every advance stamps the gauge.
    #[tokio::test(start_paused = true)]
    async fn an_advancing_frontier_never_seeks_nor_reports() {
        let (logs, _guard) = CapturedLogs::start();
        let origin = tokio::time::Instant::now();
        let mut fx = FrozenRelayFixture::new(&[12]);
        fx.tick_at(origin, [0].into_iter()).await;
        for (step, at) in (25..=600).step_by(25).enumerate() {
            fx.relays.set_heads(&[13 + step as u64]);
            fx.stale_last_advance();
            fx.tick_at(origin, [at].into_iter()).await;
            assert!(
                fx.last_advance() >= fx.started,
                "every advance stamps the gauge"
            );
        }

        assert_eq!(fx.head(), Some(36));
        assert_eq!(
            fx.seeks("advanced") + fx.seeks("none") + fx.seeks("failed"),
            0
        );
        assert!(logs.lines_with(FROZEN).is_empty());
        assert!(logs.lines_with(RECOVERED).is_empty());
    }

    /// The relays, recording the last-advance gauge as each pull begins.
    struct GaugeWatchingRelays {
        relays: Arc<Relays>,
        metrics: Arc<OcsMetrics>,
        gauge_at_pull: Arc<parking_lot::Mutex<Vec<i64>>>,
    }

    #[async_trait]
    impl ChangesetSource for GaugeWatchingRelays {
        async fn changeset_page(
            &self,
            from_seq: CheckpointSequenceNumber,
            limit: u32,
            require_contiguous: bool,
            seek_successor: bool,
        ) -> Result<Vec<ChangesetEntry>, TransportError> {
            self.gauge_at_pull.lock().push(
                self.metrics
                    .changeset_upstream_last_advance_timestamp_seconds
                    .get(),
            );
            self.relays
                .changeset_page(from_seq, limit, require_contiguous, seek_successor)
                .await
        }
    }

    /// A node far behind drains page after page in one tick; after a restart
    /// that can take hours. Every page that advances the frontier stamps the
    /// gauge as it folds, not only the end of the drain.
    #[tokio::test(start_paused = true)]
    async fn a_long_catch_up_stamps_the_gauge_on_every_page() {
        let gauge_at_pull = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let pulls = gauge_at_pull.clone();
        let mut fx = FrozenRelayFixture::with_source(&[120], move |relays, metrics| {
            Arc::new(GaugeWatchingRelays {
                relays,
                metrics,
                gauge_at_pull: pulls,
            })
        });
        fx.stale_last_advance();
        fx.tick_at(tokio::time::Instant::now(), [0].into_iter())
            .await;

        assert_eq!(fx.head(), Some(120), "one tick drains the whole chain");
        // Pages of 64 from 10: pulls from 10, 74 and 121, the last one empty.
        let seen = gauge_at_pull.lock().clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(seen[0], STALE_STAMP, "nothing has folded yet");
        assert!(
            seen[1..].iter().all(|stamp| *stamp >= fx.started),
            "each page stamps the gauge as it folds: {seen:?}"
        );
    }

    /// A relay that serves one fixed page, counting how often its pages are
    /// rejected.
    struct RejectCountingSource {
        entries: Vec<ChangesetEntry>,
        rejects: std::sync::atomic::AtomicUsize,
        passed_over: std::sync::atomic::AtomicUsize,
        advances: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ChangesetSource for RejectCountingSource {
        async fn changeset_page(
            &self,
            from_seq: CheckpointSequenceNumber,
            limit: u32,
            _require_contiguous: bool,
            _known_gap: bool,
        ) -> Result<Vec<ChangesetEntry>, TransportError> {
            Ok(self
                .entries
                .iter()
                .filter(|entry| *entry.summary.sequence_number() >= from_seq)
                .take(limit as usize)
                .cloned()
                .collect())
        }

        fn reject_last_page(&self) {
            self.rejects
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn pass_over_last_page(&self) {
            self.passed_over
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn frontier_advanced(&self) {
            self.advances
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl RejectCountingSource {
        fn serving(entries: Vec<ChangesetEntry>) -> Self {
            Self {
                entries,
                rejects: Default::default(),
                passed_over: Default::default(),
                advances: Default::default(),
            }
        }

        fn rejects(&self) -> usize {
            self.rejects.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn passed_over(&self) -> usize {
            self.passed_over.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A page whose entry is signed by another committee, or does not chain
    /// onto the frontier, fails verification and has its source rejected, so
    /// the next pull asks another relay. A page that verifies does not.
    #[tokio::test]
    async fn a_page_that_fails_verification_rejects_its_source() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let (_dir, store) = committee_store(committee.clone());
        let rejects = |source: &RejectCountingSource| {
            source.rejects.load(std::sync::atomic::Ordering::SeqCst)
        };

        let (forged, _) = signed_entry(
            &foreign,
            &foreign_keys,
            10,
            None,
            [modified(0xA1, 1)].into(),
        );
        let source = RejectCountingSource::serving(vec![forged]);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        assert!(matches!(
            pump_changesets(&index, &source, &store, 64, 10, false).await,
            Err(ChangesetError::Unverified(_))
        ));
        assert_eq!(rejects(&source), 1);

        let (e10, _) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        let (unchained, _) = signed_entry(
            &committee,
            &keys,
            11,
            Some(CheckpointDigest::new([7; 32])),
            [modified(0xB2, 1)].into(),
        );
        let source = RejectCountingSource::serving(vec![e10, unchained]);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        assert!(matches!(
            pump_changesets(&index, &source, &store, 64, 10, false).await,
            Err(ChangesetError::BrokenChain { seq: 11 })
        ));
        assert_eq!(rejects(&source), 1);
        assert_eq!(index.read().highest_contiguous_seq(), Some(10));

        let (good, _) = signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
        let source = RejectCountingSource::serving(vec![good]);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        pump_changesets(&index, &source, &store, 64, 10, false)
            .await
            .unwrap();
        assert_eq!(rejects(&source), 0);
    }

    /// A node that started the receiver's clock at boot keeps that start when
    /// its receiver is built late; on its own the receiver starts the clock
    /// when built.
    #[tokio::test]
    async fn a_receiver_built_late_keeps_the_boot_start_of_the_clock() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee);
        let gauge = |metrics: &OcsMetrics| {
            metrics
                .changeset_upstream_last_advance_timestamp_seconds
                .get()
        };
        let build = |metrics: Arc<OcsMetrics>| {
            ChangesetReceiver::new(
                Arc::new(RwLock::new(ChangesetIndex::new())),
                Arc::new(VecSource(vec![])),
                store.clone(),
                64,
                10,
                Duration::from_secs(2),
                metrics,
            )
        };

        let booted = OcsMetrics::new_for_testing();
        booted.start_changeset_upstream_clock();
        assert!(gauge(&booted) > 0);
        booted
            .changeset_upstream_last_advance_timestamp_seconds
            .set(STALE_STAMP);
        build(booted.clone());
        assert_eq!(gauge(&booted), STALE_STAMP, "the boot start is kept");

        let fresh = OcsMetrics::new_for_testing();
        build(fresh.clone());
        assert!(gauge(&fresh) > STALE_STAMP, "started when built");
    }

    /// `signed_entry`, of the end of the committee's epoch: it commits to the
    /// next epoch's committee (the same members).
    fn signed_end_of_epoch_entry(
        committee: &Committee,
        keypairs: &[AuthorityKeyPair],
        seq: u64,
        previous: Option<CheckpointDigest>,
    ) -> (ChangesetEntry, CheckpointDigest) {
        let object_states = States::new();
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
            end_of_epoch_data: Some(sui_types::messages_checkpoint::EndOfEpochData {
                next_epoch_committee: committee.voting_rights.clone(),
                next_epoch_protocol_version: sui_types::committee::ProtocolVersion::MIN,
                epoch_commitments: vec![],
            }),
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

    fn committee_at(committee: &Committee, epoch: u64) -> Committee {
        Committee::new(epoch, committee.voting_rights.iter().cloned().collect())
    }

    /// While the index is bootstrapping, an entry of any later epoch than the
    /// committee store's head cannot be checked yet, and is plausible (the
    /// receiver may begin in a later epoch than the ratchet has reached): a
    /// wait, with its relay left out of the next pass but not demoted, and no
    /// fetch failure counted.
    #[tokio::test]
    async fn a_bootstrapping_entry_of_a_later_epoch_waits_without_blaming_its_relay() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        assert_eq!(store.head_epoch(), 0);
        for epoch in [1, 3] {
            let (later, _) = signed_entry(
                &committee_at(&committee, epoch),
                &keys,
                11,
                None,
                [modified(0xA1, 1)].into(),
            );
            let source = Arc::new(RejectCountingSource::serving(vec![later]));
            let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
            match pump_changesets(&index, source.as_ref(), &store, 64, 11, false).await {
                Err(ChangesetError::AwaitingCommittee {
                    seq: 11,
                    epoch: waited,
                }) => {
                    assert_eq!(waited, epoch)
                }
                other => panic!("epoch {epoch}: expected a wait, got {other:?}"),
            }
            assert_eq!(
                source.rejects(),
                0,
                "epoch {epoch}: an honest relay is not blamed"
            );
            assert_eq!(
                source.passed_over(),
                1,
                "epoch {epoch}: asked elsewhere next"
            );

            let metrics = OcsMetrics::new_for_testing();
            let mut receiver = ChangesetReceiver::new(
                index.clone(),
                source.clone(),
                store.clone(),
                64,
                11,
                Duration::from_secs(2),
                metrics.clone(),
            );
            receiver.tick().await;
            assert_eq!(metrics.changeset_fetch_failures_total.get(), 0);
            assert_eq!(source.rejects(), 0);
        }
    }

    /// Past the bootstrap, an entry whose epoch has no committee is plausible
    /// only right after the end-of-epoch checkpoint of the store's head epoch
    /// (the next committee's install is still to come): a wait, its relay
    /// passed over without demotion. An entry labelled with the next epoch
    /// after any other checkpoint is forged, whatever signs it: here a
    /// foreign committee, which a lookup by the label alone would have left
    /// unchecked. Its relay is rejected, as is one claiming an epoch two past
    /// the head.
    #[tokio::test]
    async fn an_entry_of_an_epoch_without_a_committee_waits_only_after_the_epoch_ends() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);

        // The index head is an ordinary checkpoint of epoch 0.
        let fresh_index = || {
            let (e10, digest) =
                signed_entry(&committee, &keys, 10, None, [modified(0xA1, 1)].into());
            let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
            index
                .write()
                .absorb(&e10.summary, e10.object_states)
                .unwrap();
            (index, digest)
        };
        for (label, signer, signer_keys) in [
            (1, committee_at(&foreign, 1), &foreign_keys),
            (1, committee_at(&committee, 1), &keys),
            (2, committee_at(&committee, 2), &keys),
        ] {
            let (index, digest) = fresh_index();
            let (forged, _) = signed_entry(
                &signer,
                signer_keys,
                11,
                Some(digest),
                [modified(0xB2, 1)].into(),
            );
            assert_eq!(forged.summary.epoch(), label);
            let source = RejectCountingSource::serving(vec![forged]);
            assert!(matches!(
                pump_changesets(&index, &source, &store, 64, 10, false).await,
                Err(ChangesetError::Unverified(_))
            ));
            assert_eq!(
                source.rejects(),
                1,
                "epoch {label} after a mid-epoch head is forged"
            );
            assert_eq!(source.passed_over(), 0);
        }

        // The index head is the end of epoch 0, and the next committee is not
        // installed (here: folded without the receiver's install, as if it
        // failed).
        let (end_of_epoch, digest) = signed_end_of_epoch_entry(&committee, &keys, 10, None);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        index
            .write()
            .absorb(&end_of_epoch.summary, end_of_epoch.object_states)
            .unwrap();
        assert_eq!(store.head_epoch(), 0);
        let (next_epoch, _) = signed_entry(
            &committee_at(&committee, 1),
            &keys,
            11,
            Some(digest),
            [modified(0xB2, 1)].into(),
        );
        let source = RejectCountingSource::serving(vec![next_epoch]);
        assert!(matches!(
            pump_changesets(&index, &source, &store, 64, 10, false).await,
            Err(ChangesetError::AwaitingCommittee { seq: 11, epoch: 1 })
        ));
        assert_eq!(source.rejects(), 0, "an honest relay is not blamed");
        assert_eq!(source.passed_over(), 1, "but another relay is asked next");
    }

    /// A wait is handled as one in the poll: an INFO once per epoch, not the
    /// rate-limited failure WARN, and a pass that asked every relay is
    /// counted `none`, not `failed`.
    #[tokio::test(start_paused = true)]
    async fn a_committee_wait_is_logged_once_and_counted_as_no_successor() {
        let (logs, _guard) = CapturedLogs::start();
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let (next_epoch, _) = signed_entry(
            &committee_at(&committee, 1),
            &keys,
            11,
            None,
            [modified(0xA1, 1)].into(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let mut receiver = ChangesetReceiver::new(
            Arc::new(RwLock::new(
                ChangesetIndex::new().with_metrics(metrics.clone()),
            )),
            Arc::new(RejectCountingSource::serving(vec![next_epoch])),
            store,
            64,
            11,
            Duration::from_secs(2),
            metrics.clone(),
        );
        for _ in 0..20 {
            receiver.tick().await;
            tokio::time::advance(Duration::from_secs(2)).await;
        }

        let seeks = |outcome: &str| {
            metrics
                .changeset_successor_seeks_total
                .with_label_values(&[outcome])
                .get()
        };
        assert!(seeks("none") > 0, "the stall's seek pass is counted");
        assert_eq!(seeks("failed"), 0, "a wait is not a failed pass");
        assert_eq!(
            logs.lines_with("waits for the next Sui epoch's committee")
                .len(),
            1,
            "once per epoch"
        );
        assert!(logs.lines_with("ChangesetReceiver tick failed").is_empty());
    }

    /// Folding the end-of-epoch checkpoint installs the next epoch's
    /// committee, so the entries after it verify in the same page, without
    /// waiting for the committee ratchet.
    #[tokio::test]
    async fn a_folded_end_of_epoch_entry_installs_the_next_committee() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let (end_of_epoch, digest) = signed_end_of_epoch_entry(&committee, &keys, 10, None);
        let (next_epoch, _) = signed_entry(
            &committee_at(&committee, 1),
            &keys,
            11,
            Some(digest),
            [modified(0xA1, 1)].into(),
        );
        let source = RejectCountingSource::serving(vec![end_of_epoch, next_epoch]);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let advanced = pump_changesets(&index, &source, &store, 64, 10, false)
            .await
            .expect("both entries fold");
        assert_eq!(advanced, 2);
        assert_eq!(store.head_epoch(), 1);
        assert_eq!(index.read().highest_contiguous_seq(), Some(11));
        assert_eq!(
            source.advances.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an advance tells the source, so relays passed over are asked again"
        );
    }
}
