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
