// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rebuilding the epoch's derived state by replaying the consensus store.
//!
//! The per-epoch store keeps no record of how far the consensus handler got.
//! On every start the derived tables are deleted
//! (`AuthorityEpochTables::wipe_derived_state`) and this module folds the
//! epoch's commits back through the same handler that processes live commits,
//! in bounded batches, until it reaches the store's last finalized commit.
//! Only then does consensus start, and it starts from exactly that index — so
//! the index consensus is asked to replay after is READ FROM the consensus
//! store rather than remembered beside it, and the two can no longer disagree
//! (ika #2057).
//!
//! Batching is what keeps memory flat on an old epoch: one batch of commits and
//! their blocks is resident at a time, folded, then dropped. The batch size
//! matches consensus-core's own recovery batch so the two paths read the store
//! the same way.
//!
//! The full model — what "derived" means, why the fold is deterministic, and
//! what replay must not re-emit — is `dev-docs/specs/event-sourced-epoch.md`.

use std::path::Path;
use std::time::Instant;

use consensus_core::storage::Store;
use consensus_core::storage::rocksdb_store::RocksDBStore;
use consensus_core::{CommitAPI, CommitIndex, CommittedSubDag, TrustedCommit};
use tracing::{info, warn};

use crate::consensus_handler::ConsensusHandler;
use crate::consensus_manager::ConsensusManagerMetrics;
use crate::dwallet_checkpoints::DWalletCheckpointService;

/// How many commits are read from the store, folded and released before the
/// next read. Mirrors consensus-core's `COMMIT_RECOVERY_BATCH_SIZE` so an
/// operator reasoning about replay memory has one number to reason about.
const REPLAY_BATCH_COMMITS: CommitIndex = 250;

/// Folds every finalized commit of the epoch through `handler` and returns the
/// commit index the fold reached.
///
/// The returned index is what consensus must be started with as both
/// `replay_after_commit_index` and `consumer_last_processed_commit_index`: it
/// is the store's own last finalized commit, so
/// `CommitObserver::recover_and_send_commits` can only ever see
/// `last_commit_index >= replay_after` — the comparison that bricked a
/// validator for a full epoch when the two came from different databases.
///
/// Stops at the last FINALIZED commit rather than the last commit. An
/// unfinalized commit has no stored set of rejected transaction indices, so
/// folding it here would let this validator treat as accepted a transaction its
/// peers reject. Those commits are consensus-core's to deliver, through the
/// commit finalizer, once it starts — and there are only ever a few of them.
pub(crate) async fn replay_epoch_commits(
    consensus_db_path: &Path,
    handler: &mut ConsensusHandler<DWalletCheckpointService>,
    metrics: &ConsensusManagerMetrics,
) -> CommitIndex {
    let started_at = Instant::now();
    let store = RocksDBStore::new(&consensus_db_path.to_string_lossy());

    let last_commit = store
        .read_last_commit()
        .expect("reading the consensus store's last commit must not fail");
    let replay_through = store
        .read_last_finalized_commit()
        .expect("reading the consensus store's last finalized commit must not fail")
        .map_or(0, |commit_ref| commit_ref.index);

    let unfinalized_tail = last_commit
        .as_ref()
        .map_or(0, |commit| commit.index().saturating_sub(replay_through));
    metrics
        .boot_replay_target_commit_index
        .set(replay_through as i64);

    if replay_through == 0 {
        info!(
            unfinalized_tail,
            "no finalized commits in the consensus store for this epoch — starting the epoch's \
             derived state from empty",
        );
        metrics.boot_replay_folded_commit_index.set(0);
        metrics.boot_replay_latency_seconds.set(0);
        return 0;
    }

    info!(
        replay_through,
        unfinalized_tail,
        batch = REPLAY_BATCH_COMMITS,
        "replaying the epoch's consensus commits to rebuild derived state",
    );

    let mut folded_through = 0;
    let mut batch_start: CommitIndex = 1;
    while batch_start <= replay_through {
        let batch_end = batch_start
            .saturating_add(REPLAY_BATCH_COMMITS - 1)
            .min(replay_through);
        let commits = store
            .scan_commits((batch_start..=batch_end).into())
            .expect("scanning the consensus store's commits must not fail");
        // The epoch's commit history has to survive until the boundary for the
        // rebuild to be possible at all, which makes consensus-store retention
        // load-bearing rather than incidental. Assert it instead of assuming
        // it: a hole here means the store was pruned or truncated in the
        // middle, and every derived table this node builds from here on would
        // silently be missing a commit's worth of effects.
        let expected = (batch_end - batch_start + 1) as usize;
        assert_eq!(
            commits.len(),
            expected,
            "the consensus store is missing commits in [{batch_start}..={batch_end}] — the \
             epoch's commit history must be retained until the epoch boundary for derived \
             state to be rebuildable",
        );

        for commit in commits {
            let commit_index = commit.index();
            assert_eq!(
                commit_index,
                folded_through + 1,
                "consensus commit indices must be contiguous during replay",
            );
            handler
                .handle_consensus_commit(load_committed_subdag(&store, commit))
                .await;
            folded_through = commit_index;
        }

        metrics
            .boot_replay_folded_commit_index
            .set(folded_through as i64);
        // Long replays are the point of this design, not an anomaly, so the
        // progress line has to exist — an operator watching a node that will
        // take tens of minutes to reach the store head needs to see it moving.
        info!(
            folded_through,
            replay_through,
            elapsed_secs = started_at.elapsed().as_secs(),
            "consensus commit replay progress",
        );
        batch_start = batch_end + 1;
    }

    let elapsed = started_at.elapsed();
    metrics
        .boot_replay_latency_seconds
        .set(elapsed.as_secs() as i64);
    info!(
        folded_through,
        unfinalized_tail,
        elapsed_secs = elapsed.as_secs_f64(),
        "rebuilt the epoch's derived state from the consensus store",
    );
    if unfinalized_tail > 0 {
        warn!(
            unfinalized_tail,
            "the consensus store's tail is not finalized; those commits are delivered by \
             consensus once it starts, not by the boot replay",
        );
    }

    folded_through
}

/// Rebuilds the committed sub-dag a commit stands for, exactly as
/// consensus-core's own recovery does: the commit's blocks plus, when the
/// commit is finalized, the stored per-block set of rejected transaction
/// indices. `replay_epoch_commits` only ever passes finalized commits, so the
/// rejected set is always the stored one and never an empty stand-in.
fn load_committed_subdag(store: &dyn Store, commit: TrustedCommit) -> CommittedSubDag {
    let blocks = store
        .read_blocks(commit.blocks())
        .expect("reading the blocks a stored commit references must not fail")
        .into_iter()
        .map(|block| {
            block.expect(
                "a stored commit references a block the consensus store no longer has — the \
                 epoch's consensus database is inconsistent and must be removed so the node \
                 can refetch it from peers",
            )
        })
        .collect::<Vec<_>>();
    let leader = blocks
        .iter()
        .map(|block| block.reference())
        .find(|reference| *reference == commit.leader())
        .expect("the leader block must be part of the committed sub-dag");

    let mut subdag =
        CommittedSubDag::new(leader, blocks, commit.timestamp_ms(), commit.reference());
    if let Some(rejected) = store
        .read_rejected_transactions(subdag.commit_ref)
        .expect("reading a finalized commit's rejected transactions must not fail")
    {
        subdag.decided_with_local_blocks = true;
        subdag.recovered_rejected_transactions = true;
        subdag.rejected_transactions_by_block = rejected;
    }
    subdag
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    use arc_swap::ArcSwap;
    use consensus_core::storage::WriteBatch;
    use consensus_core::{CommitAPI, Context, DagBuilder};
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::authority::AuthorityMetrics;
    use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
    use crate::authority::derived_epoch_state::DerivedEpochStatePolicy;
    use crate::authority::epoch_start_configuration::EpochStartConfiguration;
    use crate::consensus_handler::ConsensusCommitSink;
    use crate::consensus_throughput_calculator::ConsensusThroughputCalculator;
    use crate::epoch::epoch_metrics::EpochMetrics;
    use ika_types::committee::Committee;
    use ika_types::digests::ChainIdentifier;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::EpochStartSystem;

    const CONSENSUS_COMMITTEE_SIZE: usize = 4;

    /// A consensus store on disk holding `commits` commits, of which the first
    /// `finalized` are finalized (have a stored rejected-transaction set).
    ///
    /// The blocks carry no transactions: this exercises the replay pipeline —
    /// how far it folds and what index it hands consensus — not the
    /// transaction handling, which the epoch store's own fold tests cover.
    fn consensus_store_with(commits: u32, finalized: u32) -> (TempDir, Arc<Context>) {
        assert!(finalized <= commits);
        let (context, _keys) = Context::new_for_test(CONSENSUS_COMMITTEE_SIZE);
        let context = Arc::new(context);
        let dir = TempDir::new().unwrap();
        let store = RocksDBStore::new(&dir.path().to_string_lossy());

        let mut dag = DagBuilder::new(context.clone());
        // Two block rounds per leader round, so `commits` leader rounds are
        // available to be committed.
        dag.layers(1..=(commits * 2 + 2)).build();
        let produced = dag.get_sub_dag_and_commits(1..=commits);
        assert!(
            produced.len() as u32 >= commits,
            "the test DAG produced {} commits, fewer than the {commits} requested",
            produced.len(),
        );

        for (index, (subdag, commit)) in produced.into_iter().take(commits as usize).enumerate() {
            let finalized_rows = if (index as u32) < finalized {
                vec![(commit.reference(), BTreeMap::new())]
            } else {
                Vec::new()
            };
            store
                .write(WriteBatch::new(
                    subdag.blocks.clone(),
                    vec![commit],
                    Vec::new(),
                    finalized_rows,
                ))
                .unwrap();
        }
        (dir, context)
    }

    fn test_epoch_store(
        dir: &Path,
        policy: DerivedEpochStatePolicy,
    ) -> Arc<AuthorityPerEpochStore> {
        let (committee, _keys) =
            Committee::new_simple_test_committee_of_size(CONSENSUS_COMMITTEE_SIZE);
        let committee = Arc::new(committee);
        let name = *committee.names().next().unwrap();
        AuthorityPerEpochStore::new(
            name,
            committee,
            dir,
            None,
            EpochMetrics::new(&Registry::new()),
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap(),
            ChainIdentifier::default(),
            IkaNetworkConfig::new_for_testing(),
            policy,
        )
        .unwrap()
    }

    fn test_handler(
        epoch_store: Arc<AuthorityPerEpochStore>,
        context: &Context,
    ) -> ConsensusHandler<DWalletCheckpointService> {
        test_handler_with_sink(epoch_store, context, None)
    }

    fn test_handler_with_sink(
        epoch_store: Arc<AuthorityPerEpochStore>,
        context: &Context,
        commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
    ) -> ConsensusHandler<DWalletCheckpointService> {
        let metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
        ConsensusHandler::new(
            epoch_store,
            None,
            None,
            Arc::new(ArcSwap::from_pointee(HashMap::new())),
            context.committee.clone(),
            metrics.clone(),
            Arc::new(ConsensusThroughputCalculator::new(None, metrics)),
            commit_sink,
        )
    }

    #[derive(Default)]
    struct CountingCommitSink {
        rounds: Mutex<Vec<u64>>,
    }

    impl ConsensusCommitSink for CountingCommitSink {
        fn commit_processed(&self, leader_round: u64) {
            self.rounds.lock().unwrap().push(leader_round);
        }
    }

    /// The index handed to consensus must never exceed what the consensus
    /// store actually holds — that inequality, violated because the two came
    /// from different databases, is what crash-looped a validator for a full
    /// epoch (ika #2057). Asserted on every scenario below.
    fn assert_replay_index_is_backed_by_the_store(consensus_dir: &Path, replay_after: CommitIndex) {
        let store = RocksDBStore::new(&consensus_dir.to_string_lossy());
        let last_commit_index = store
            .read_last_commit()
            .unwrap()
            .map_or(0, |commit| commit.index());
        assert!(
            replay_after <= last_commit_index,
            "replay_after {replay_after} is ahead of the consensus store's last commit \
             {last_commit_index}; consensus would assert on start",
        );
    }

    #[tokio::test]
    async fn replay_folds_every_finalized_commit_and_reaches_the_store_head() {
        let (consensus_dir, context) = consensus_store_with(6, 6);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, 6);
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index,
            6,
            "the fold did not advance through every replayed commit",
        );
        assert_replay_index_is_backed_by_the_store(consensus_dir.path(), replayed_through);
    }

    /// The commit-liveness watchdog (ika #2054) arms on the first commit this
    /// process reports and breaches if none follows for ~15 minutes. It was
    /// documented as blind during boot, because a validator that skipped
    /// already-processed commits could come up, process zero commits, and sit
    /// isolated with the watchdog never armed.
    ///
    /// Replay closes that by construction — it goes through the same
    /// `handle_consensus_commit` that reports to the sink — and this asserts
    /// the construction, since the alternative (a separate replay-only fold
    /// that forgets to report) is exactly what would silently reopen the gap.
    #[tokio::test]
    async fn replayed_commits_feed_the_commit_liveness_sink() {
        let (consensus_dir, context) = consensus_store_with(5, 5);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        let sink = Arc::new(CountingCommitSink::default());
        let mut handler = test_handler_with_sink(
            epoch_store,
            &context,
            Some(sink.clone() as Arc<dyn ConsensusCommitSink>),
        );
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        let reported = sink.rounds.lock().unwrap().clone();
        assert_eq!(
            reported.len(),
            5,
            "the watchdog saw {} of 5 replayed commits; a node whose whole boot is replay \
             would leave it unarmed",
            reported.len(),
        );
        assert!(
            reported.windows(2).all(|pair| pair[0] < pair[1]),
            "leader rounds reported out of order: {reported:?}",
        );
    }

    /// More commits than fit in one read batch, so the loop that reads, folds
    /// and releases actually iterates. With a single batch the boundary
    /// arithmetic is never exercised, and an off-by-one there silently drops a
    /// commit's worth of effects from every table the fold writes.
    #[tokio::test]
    async fn replay_crosses_batch_boundaries_without_dropping_a_commit() {
        let commits = REPLAY_BATCH_COMMITS + REPLAY_BATCH_COMMITS / 2;
        let (consensus_dir, context) = consensus_store_with(commits, commits);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, commits);
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index,
            u64::from(commits),
        );
        // One per-round row per replayed commit: a dropped batch boundary shows
        // up here as a hole rather than as a lower final index.
        let rows = epoch_store
            .tables()
            .unwrap()
            .classified_table_rows("dwallet_mpc_messages");
        assert_eq!(
            rows.len(),
            commits as usize,
            "the per-round stream is not dense across the batch boundary",
        );
    }

    /// Unfinalized commits carry no stored rejected-transaction set, so folding
    /// them here could accept a transaction peers reject. The replay must stop
    /// below them and leave them to consensus.
    #[tokio::test]
    async fn replay_stops_below_the_unfinalized_tail() {
        let (consensus_dir, context) = consensus_store_with(6, 4);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, 4);
        assert_replay_index_is_backed_by_the_store(consensus_dir.path(), replayed_through);
    }

    /// The consensus store wiped entirely — the second half of #2057's
    /// recovery story. Consensus asserts that a consumer of an empty store
    /// replays after 0, so the replay must return exactly 0 and the node must
    /// come up on an epoch it rebuilds from nothing.
    #[tokio::test]
    async fn replay_of_an_empty_consensus_store_starts_the_epoch_from_nothing() {
        let (context, _keys) = Context::new_for_test(CONSENSUS_COMMITTEE_SIZE);
        let consensus_dir = TempDir::new().unwrap();
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, 0);
        assert!(
            epoch_store
                .tables()
                .unwrap()
                .get_last_consensus_stats()
                .unwrap()
                .is_none()
        );
    }

    /// The #2057 incident, in process: a per-epoch store that folded through
    /// commit 8 next to a consensus store whose tail was lost at commit 5.
    ///
    /// The old pipeline took `replay_after` from the per-epoch store's own
    /// record, so it asked consensus to replay after 8 against a store holding
    /// 5 — and `CommitObserver::recover_and_send_commits` asserts
    /// `last_commit_index > replay_after_commit_index`, aborting the process
    /// on every boot until the epoch rolled over. Taking the index from the
    /// consensus store itself makes that comparison unfailable: the two are
    /// the same number.
    #[tokio::test]
    async fn a_consensus_store_that_lost_its_tail_replays_to_its_own_head() {
        let (intact_dir, context) = consensus_store_with(8, 8);
        let epoch_dir = TempDir::new().unwrap();

        // The run before the storage incident: folded through commit 8.
        {
            let epoch_store = test_epoch_store(
                epoch_dir.path(),
                DerivedEpochStatePolicy::RebuildFromConsensus,
            );
            let mut handler = test_handler(epoch_store.clone(), &context);
            let metrics = ConsensusManagerMetrics::new(&Registry::new());
            let replayed_through =
                replay_epoch_commits(intact_dir.path(), &mut handler, &metrics).await;
            assert_eq!(replayed_through, 8);
        }
        let stale_watermark = {
            let epoch_store = test_epoch_store(epoch_dir.path(), DerivedEpochStatePolicy::Retain);
            let stale = epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index;
            assert_eq!(stale, 8, "the per-epoch store must survive with its tally");
            stale
        };

        // The incident: the consensus store comes back holding only 5 commits.
        let (truncated_dir, _context) = consensus_store_with(5, 5);
        let truncated_head = {
            let store = RocksDBStore::new(&truncated_dir.path().to_string_lossy());
            store.read_last_commit().unwrap().unwrap().index()
        };
        assert_eq!(truncated_head, 5);
        assert!(
            stale_watermark > u64::from(truncated_head),
            "the fixture must reproduce the torn state: a per-epoch record ahead of the \
             consensus store, which is what the upstream assertion aborts on",
        );

        // The new boot: wipe, replay against whatever the store still has.
        let epoch_store = test_epoch_store(
            epoch_dir.path(),
            DerivedEpochStatePolicy::RebuildFromConsensus,
        );
        assert!(
            epoch_store
                .tables()
                .unwrap()
                .get_last_consensus_stats()
                .unwrap()
                .is_none(),
            "the wipe must have removed the stale tally",
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());
        let replayed_through =
            replay_epoch_commits(truncated_dir.path(), &mut handler, &metrics).await;

        assert_eq!(
            replayed_through, truncated_head,
            "the rebuild must reach the surviving head and hand consensus that index",
        );
        assert_replay_index_is_backed_by_the_store(truncated_dir.path(), replayed_through);
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index,
            u64::from(truncated_head),
            "derived state must be rebuilt to the surviving head, not left at the stale tally",
        );
    }
}
