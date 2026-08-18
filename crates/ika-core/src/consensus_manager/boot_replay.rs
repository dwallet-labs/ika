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
/// next read. Mirrors consensus-core's `COMMIT_RECOVERY_BATCH_SIZE`, including
/// its shrink under `cfg!(test)`, so an operator reasoning about replay memory
/// has one number to reason about and a test does not have to build hundreds
/// of commits to reach the second iteration of the loop.
const REPLAY_BATCH_COMMITS: CommitIndex = if cfg!(test) { 3 } else { 250 };

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

    // Publish the head's leader round BEFORE folding anything: it is the
    // catch-up gate's "how far is there to go", and during replay nothing
    // else can supply it (the replay's own arrivals advance at the drain's
    // pace once the round channel fills).
    if let Some(head) = store
        .scan_commits((replay_through..=replay_through).into())
        .expect("scanning the consensus store's head commit must not fail")
        .first()
    {
        handler.publish_observed_consensus_head(head.leader().round as u64);
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
            let subdag = load_committed_subdag(&store, commit);
            // Arrival, before the fold — same rule as the live loop. This is
            // also what arms the commit-liveness watchdog on a node whose
            // whole boot is replay (#2054's boot-into-isolation gap).
            handler.report_commit_received(&subdag);
            handler.handle_consensus_commit(subdag).await;
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

/// Rebuilds the committed sub-dag a commit stands for, mirroring
/// consensus-core's own `load_committed_subdag_from_store` (`pub(crate)`, so it
/// cannot be called from here): the commit's blocks plus the stored per-block
/// set of rejected transaction indices.
///
/// The rejected set is REQUIRED, not defaulted. `CommittedSubDag::new` leaves
/// `rejected_transactions_by_block` empty, and ika's `ConsensusCommitAPI`
/// reads exactly that map to decide which transactions to skip — so a commit
/// folded without its rejected set accepts transactions the rest of the
/// committee rejected, silently, with no crash and no log. Every commit the
/// replay reaches is at or below the store's last FINALIZED commit and so must
/// have one; that this holds today rests on consensus-core finalizing in
/// order, which is an internal property of the commit finalizer with no API
/// contract behind it. Hence the assertion rather than an `unwrap_or_default`.
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
    let rejected = store
        .read_rejected_transactions(subdag.commit_ref)
        .expect("reading a finalized commit's rejected transactions must not fail")
        .unwrap_or_else(|| {
            panic!(
                "commit {:?} is at or below the consensus store's last finalized commit but has \
                 no stored set of rejected transactions; folding it would accept transactions \
                 the committee rejected",
                subdag.commit_ref,
            )
        });
    subdag.decided_with_local_blocks = true;
    subdag.recovered_rejected_transactions = true;
    subdag.rejected_transactions_by_block = rejected;
    subdag
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use consensus_core::storage::WriteBatch;
    use consensus_core::{CommitAPI, CommitConsumerArgs, Context, DagBuilder};
    use prometheus::Registry;
    use tempfile::TempDir;

    use super::*;
    use crate::authority::AuthorityMetrics;
    use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
    use crate::authority::authority_per_epoch_store::{AuthorityPerEpochStore, EpochStoreParams};
    use crate::authority::epoch_start_configuration::EpochStartConfiguration;
    use crate::authority::round_transport::round_transport;
    use crate::consensus_handler::{ConsensusCommitSink, MysticetiConsensusHandler};
    use crate::consensus_throughput_calculator::ConsensusThroughputCalculator;
    use crate::epoch::epoch_metrics::EpochMetrics;
    use ika_types::committee::Committee;
    use ika_types::digests::ChainIdentifier;
    use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
    use ika_types::sui::EpochStartSystem;
    use std::sync::atomic::AtomicBool;

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

    fn test_epoch_store(dir: &Path) -> Arc<AuthorityPerEpochStore> {
        let (committee, _keys) =
            Committee::new_simple_test_committee_of_size(CONSENSUS_COMMITTEE_SIZE);
        let committee = Arc::new(committee);
        let name = *committee.names().next().unwrap();
        let params = EpochStoreParams {
            name,
            committee,
            parent_path: dir.to_path_buf(),
            db_options: None,
            metrics: EpochMetrics::new(&Registry::new()),
            epoch_start_configuration: EpochStartConfiguration::new(
                EpochStartSystem::new_for_testing_with_epoch(0),
            )
            .unwrap(),
            chain_identifier: ChainIdentifier::default(),
            packages_config: IkaNetworkConfig::new_for_testing(),
        };
        AuthorityPerEpochStore::new(params).unwrap()
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
        fn commit_received(&self, leader_round: u64) {
            self.rounds.lock().unwrap().push(leader_round);
        }
    }

    /// Replays the two assertions `CommitObserver::recover_and_send_commits`
    /// makes against the index it is started with, and requires that neither
    /// can fire.
    ///
    /// Upstream aborts if the store is empty and the index is not zero
    /// (`commit_observer.rs:147`), or if the store's last commit is neither
    /// equal to the index nor strictly ahead of it (:162, with an equality
    /// early-return just above). Those firing on a torn pair of databases is
    /// what crash-looped a validator for a full epoch (ika #2057). Checked on
    /// every scenario, because the whole fix is that the index and the store
    /// are now one source rather than two.
    fn assert_consensus_cannot_assert_on_start(consensus_dir: &Path, replay_after: CommitIndex) {
        let store = RocksDBStore::new(&consensus_dir.to_string_lossy());
        let Some(last_commit) = store.read_last_commit().unwrap() else {
            assert_eq!(
                replay_after, 0,
                "an empty consensus store must be replayed after 0, or consensus aborts",
            );
            return;
        };
        let last_commit_index = last_commit.index();
        assert!(
            last_commit_index >= replay_after,
            "replay_after {replay_after} is ahead of the store's last commit \
             {last_commit_index}; consensus aborts on start",
        );
    }

    #[tokio::test]
    async fn replay_folds_every_finalized_commit_and_reaches_the_store_head() {
        let (consensus_dir, context) = consensus_store_with(6, 6);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(epoch_dir.path());
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
        assert_consensus_cannot_assert_on_start(consensus_dir.path(), replayed_through);
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
        let epoch_store = test_epoch_store(epoch_dir.path());
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
        let epoch_store = test_epoch_store(epoch_dir.path());
        // Count the rounds on the CHANNEL rather than in a table: no
        // per-round table survives, and the channel is where a dropped batch
        // boundary would actually show. Capacity well above the commit count
        // so the fold never blocks — this test is about the batch arithmetic,
        // not about backpressure.
        let (sender, mut receiver) = round_transport(1024, Arc::new(AtomicBool::new(false)));
        epoch_store.install_round_transport(sender);

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

        let mut rounds = Vec::new();
        while let Ok(payload) = receiver.try_recv() {
            rounds.push(payload.round);
        }
        assert_eq!(
            rounds.len(),
            commits as usize,
            "the drain received {} of {commits} rounds; a batch boundary dropped one",
            rounds.len(),
        );
        assert!(
            rounds.windows(2).all(|pair| pair[0] < pair[1]),
            "rounds reached the drain out of order across a batch boundary: {rounds:?}",
        );
    }

    /// Folding the epoch twice through the REAL path — commits read from a
    /// RocksDB consensus store, rebuilt into `CommittedSubDag`s, folded by
    /// `handle_consensus_commit` — must produce byte-identical derived state.
    ///
    /// The two runs differ in nothing but that the second one starts from a
    /// freshly opened store, which is the whole of what a restart now does to
    /// derived state: it is in memory, so a reopen IS the reset.
    ///
    /// The epoch store's own double-fold test covers breadth: it drives many
    /// transaction kinds through the commit boundary and so populates most of
    /// the derived state. It cannot cover the path, because the test DAG's
    /// blocks cannot carry ika transactions (`LayerBuilder::num_transactions`
    /// emits fixed dummy bytes that ika's decoder rejects, and
    /// `TrustedCommit`'s test constructor is `pub(crate)`). This test covers
    /// the path and not the breadth. Neither subsumes the other, and the
    /// property — derived state is a function of the commits and nothing else
    /// — needs both.
    #[tokio::test]
    async fn replaying_the_same_store_twice_rebuilds_identical_derived_state() {
        let (consensus_dir, context) = consensus_store_with(7, 7);
        let epoch_dir = TempDir::new().unwrap();
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        // First run: an empty store folded once per commit, in order — what a
        // validator that never crashed would have built.
        let epoch_store = test_epoch_store(epoch_dir.path());
        let (sender, mut receiver) = round_transport(1024, Arc::new(AtomicBool::new(false)));
        epoch_store.install_round_transport(sender);
        let mut handler = test_handler(epoch_store.clone(), &context);
        let folded = replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;
        assert_eq!(folded, 7);

        // The channel IS the fold's derived output now, so determinism means
        // the round stream it produces is identical too — the state alone
        // would be a thin comparison, since a synthetic commit carrying no ika
        // transactions derives almost nothing.
        let mut first_rounds = Vec::new();
        while let Ok(payload) = receiver.try_recv() {
            first_rounds.push(payload.round);
        }
        assert_eq!(
            first_rounds.len(),
            7,
            "every folded commit must have reached the drain",
        );

        let first = epoch_store.derived_state_snapshot();
        let populated = first
            .iter()
            .filter(|(_, encoded)| !is_empty_encoding(encoded))
            .count();
        assert!(
            populated >= 2,
            "only {populated} pieces of derived state were non-empty after the first fold; \
             the comparison below would be near-vacuous",
        );
        // Release the RocksDB handles before reopening the same path. The
        // handler holds its own `Arc` to the store, so dropping ours is not
        // enough — which is the in-process stand-in for the process exit a
        // real restart would have done.
        drop(handler);
        epoch_store.release_db_handles();
        drop(epoch_store);

        // Second run: the same store, reopened the way a validator boots.
        let epoch_store = test_epoch_store(epoch_dir.path());
        assert!(
            epoch_store
                .derived_state_snapshot()
                .values()
                .all(|encoded| is_empty_encoding(encoded)),
            "a freshly opened store held derived state; the second fold would land on the \
             first run's output",
        );
        let (sender, mut receiver) = round_transport(1024, Arc::new(AtomicBool::new(false)));
        epoch_store.install_round_transport(sender);
        let mut handler = test_handler(epoch_store.clone(), &context);
        let refolded = replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;
        assert_eq!(refolded, folded);

        let mut second_rounds = Vec::new();
        while let Ok(payload) = receiver.try_recv() {
            second_rounds.push(payload.round);
        }
        assert_eq!(
            second_rounds, first_rounds,
            "the round stream handed to the drain differed between two folds of the same \
             consensus store",
        );

        let second = epoch_store.derived_state_snapshot();
        for (field, encoded) in &first {
            assert_eq!(
                second.get(field),
                Some(encoded),
                "`{field}` did not come back identical when the same consensus store was \
                 replayed a second time",
            );
        }
        assert_eq!(
            second.keys().collect::<Vec<_>>(),
            first.keys().collect::<Vec<_>>(),
            "the two snapshots described different sets of derived state",
        );
    }

    /// Whether a BCS-encoded piece of derived state carries nothing: an empty
    /// collection, a `None`, or a `false`. Every one of those encodes to a
    /// single zero byte, and the empty-vs-populated distinction is what the
    /// vacuity guard above rests on.
    fn is_empty_encoding(encoded: &[u8]) -> bool {
        encoded == [0]
    }

    /// The boot replay must publish the consensus store's head round before it
    /// folds anything.
    ///
    /// This is the catch-up gate's only usable input during replay. The gate
    /// engages at a 5,000-round gap and the fold can never be more than the
    /// round channel's capacity (1,024) ahead of the drain, so a gap measured
    /// against the fold — or against the replay's own arrivals, which are its
    /// folds — is pinned below the threshold and the gate silently stops
    /// engaging. Nothing else fails when that happens: the node just spawns
    /// cryptography while hundreds of thousands of rounds behind, which is
    /// exactly what #2023 built the gate to prevent.
    #[tokio::test]
    async fn the_replay_publishes_the_store_head_before_folding() {
        let (consensus_dir, context) = consensus_store_with(6, 6);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(epoch_dir.path());
        assert_eq!(
            epoch_store.observed_consensus_head_round(),
            0,
            "nothing observed before the replay starts",
        );

        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());
        replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        let head = epoch_store.observed_consensus_head_round();
        assert!(
            head > 0,
            "the replay published no head; the catch-up gate would compute a zero gap and              never engage",
        );
        // The head is the LAST commit's leader round, so it must be at least
        // as high as every round the fold went on to process.
        assert!(
            head >= epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .last_committed_round,
            "the published head must not trail the rounds the replay folded",
        );
    }

    /// The boot replay publishes the head once, at boot. A validator that
    /// falls behind WITHOUT restarting needs it published continuously, and
    /// the fold cannot do that: under a blocking transport the fold stops
    /// advancing as soon as the drain falls a channel's-worth behind, so any
    /// head derived from it is pinned within the capacity of the drain's own
    /// cursor — permanently below the gate's entry threshold (#2023).
    ///
    /// So this asserts the property that makes the publisher worth having: it
    /// reports the consensus store's head with **nothing folded at all**. No
    /// commit is ever delivered on the commit channel here, which is what a
    /// fold-derived head would need.
    #[tokio::test]
    async fn the_head_publisher_reports_the_store_head_without_folding_anything() {
        let (consensus_dir, context) = consensus_store_with(6, 6);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(epoch_dir.path());
        let handler = test_handler(epoch_store.clone(), &context);

        let store = RocksDBStore::new(&consensus_dir.path().to_string_lossy());
        let head_round = store
            .read_last_commit()
            .unwrap()
            .expect("the fixture wrote commits")
            .leader()
            .round as u64;
        assert!(head_round > 0, "the fixture must have a head to publish");

        // A real handler, with its commit channel left empty on purpose.
        let (commit_consumer, commit_receiver) = CommitConsumerArgs::new(0, 0);
        let mut mysticeti =
            MysticetiConsensusHandler::new(handler, commit_receiver, commit_consumer.monitor());
        assert_eq!(
            epoch_store.observed_consensus_head_round(),
            0,
            "nothing has published a head yet",
        );

        mysticeti.spawn_observed_head_publisher(Arc::new(store), epoch_store.clone());

        let published = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let head = epoch_store.observed_consensus_head_round();
                if head > 0 {
                    return head;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect(
            "the head publisher reported nothing; the catch-up gate would see a zero gap on a \
             validator that never restarts, however far behind it fell",
        );
        assert_eq!(
            published, head_round,
            "the published head must be the consensus store's own head",
        );
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .sub_dag_index,
            0,
            "nothing may have been folded: the point is that the head does not come from the \
             fold",
        );

        mysticeti.abort().await;
    }

    /// A commit below the last finalized one but missing its rejected-transaction
    /// set must stop the node, not be folded with an empty set.
    ///
    /// `CommittedSubDag::new` leaves `rejected_transactions_by_block` empty and
    /// ika's `ConsensusCommitAPI::transactions` reads exactly that map, so
    /// defaulting here would accept transactions the committee rejected —
    /// silently, with no crash and no log. That this cannot happen today rests
    /// on consensus-core finalizing commits in order, which is internal to the
    /// commit finalizer and carries no API contract, so the replay checks it
    /// rather than trusting it.
    #[tokio::test]
    #[should_panic(expected = "no stored set of rejected transactions")]
    async fn a_finalization_hole_below_the_head_stops_the_replay() {
        let (context, _keys) = Context::new_for_test(CONSENSUS_COMMITTEE_SIZE);
        let context = Arc::new(context);
        let consensus_dir = TempDir::new().unwrap();
        let store = RocksDBStore::new(&consensus_dir.path().to_string_lossy());

        let mut dag = DagBuilder::new(context.clone());
        dag.layers(1..=12).build();
        // Commit 3 is written without a finalized-commits row while 4 and 5
        // have one, so the last finalized commit is 5 and the hole sits under
        // it — the shape in-order finalization is supposed to make impossible.
        for (index, (subdag, commit)) in dag.get_sub_dag_and_commits(1..=5).into_iter().enumerate()
        {
            let finalized = if index == 2 {
                Vec::new()
            } else {
                vec![(commit.reference(), BTreeMap::new())]
            };
            store
                .write(WriteBatch::new(
                    subdag.blocks.clone(),
                    vec![commit],
                    Vec::new(),
                    finalized,
                ))
                .unwrap();
        }
        drop(store);

        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(epoch_dir.path());
        let mut handler = test_handler(epoch_store, &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;
    }

    /// Unfinalized commits carry no stored rejected-transaction set, so folding
    /// them here could accept a transaction peers reject. The replay must stop
    /// below them and leave them to consensus.
    #[tokio::test]
    async fn replay_stops_below_the_unfinalized_tail() {
        let (consensus_dir, context) = consensus_store_with(6, 4);
        let epoch_dir = TempDir::new().unwrap();
        let epoch_store = test_epoch_store(epoch_dir.path());
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, 4);
        assert_consensus_cannot_assert_on_start(consensus_dir.path(), replayed_through);
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
        let epoch_store = test_epoch_store(epoch_dir.path());
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());

        let replayed_through =
            replay_epoch_commits(consensus_dir.path(), &mut handler, &metrics).await;

        assert_eq!(replayed_through, 0);
        assert_consensus_cannot_assert_on_start(consensus_dir.path(), replayed_through);
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .last_committed_round,
            0,
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
            let epoch_store = test_epoch_store(epoch_dir.path());
            let mut handler = test_handler(epoch_store.clone(), &context);
            let metrics = ConsensusManagerMetrics::new(&Registry::new());
            let replayed_through =
                replay_epoch_commits(intact_dir.path(), &mut handler, &metrics).await;
            assert_eq!(replayed_through, 8);
        }
        let stale_watermark = {
            let epoch_store = test_epoch_store(epoch_dir.path());
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
        let epoch_store = test_epoch_store(epoch_dir.path());
        assert_eq!(
            epoch_store
                .get_last_consensus_stats()
                .unwrap()
                .index
                .last_committed_round,
            0,
            "a reopened store must hold no tally to fold onto",
        );
        let mut handler = test_handler(epoch_store.clone(), &context);
        let metrics = ConsensusManagerMetrics::new(&Registry::new());
        let replayed_through =
            replay_epoch_commits(truncated_dir.path(), &mut handler, &metrics).await;

        assert_eq!(
            replayed_through, truncated_head,
            "the rebuild must reach the surviving head and hand consensus that index",
        );
        assert_consensus_cannot_assert_on_start(truncated_dir.path(), replayed_through);
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
