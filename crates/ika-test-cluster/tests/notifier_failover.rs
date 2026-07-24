// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Epoch close survives a dead checkpoint writer (issue #1892).
//!
//! The notifier is the single node submitting certified checkpoints and the
//! epoch-switch calls to Sui. Before the fallback-writer mechanism, killing
//! it froze the network at its current epoch forever: session completions
//! certified by the committee never reached the coordinator, every validator
//! asserted `user_sessions_lag`, and no `advance_epoch` could ever be
//! submitted — the exact shape of the 2026-07 testnet outages, which needed a
//! human to restart the notifier.
//!
//! This test drives both halves of the failover contract
//! (`dev-docs/specs/checkpoint-writer-failover.md`):
//!
//! - **A healthy primary keeps the fallback silent.** The first epoch close
//!   runs with the notifier alive; the fallback validator's takeover counter
//!   must still read zero afterwards.
//! - **A dead primary is survived without human intervention.** The notifier
//!   fullnode is stopped outright; the next TWO closes (counted from the
//!   epoch observed at kill time) can then only happen through the fallback
//!   writer on validator 0, and the takeover counter must show it acted.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": the failover is driven by wall-clock staleness observation against
//! real chain state, and the epoch boundaries run real cryptography.

use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder};
use std::time::Duration;

/// Long enough that the live primary always wins every step during phase 1
/// (its steady-state submission latency is seconds, but the in-process
/// notifier fullnode can lag the validators under bootstrap load); short
/// enough that the phase-2 takeover fits comfortably in the test budget.
const FALLBACK_ACTIVATION_DELAY_SECS: u64 = 45;

/// Ceiling for the two post-kill epoch closes. Generous: the fallback pays
/// the activation delay per pending step (the switch steps are sequential
/// within a close) plus MPC reconfiguration time, twice — still far below the
/// value at which CI would call the network wedged.
const FAILOVER_CLOSE_TIMEOUT: Duration = Duration::from_secs(900);

/// Sum of `ika_sui_connector_fallback_writer_actions_total` across ALL
/// validators. Only the configured fallback writer can ever increment it, but
/// summing avoids depending on handle ordering — `validator_node_handles()`
/// iterates the swarm's node map by authority name, NOT config index, so
/// "the first handle" is usually not the validator that carries the fallback
/// key. Zero means no validator ever took over.
fn fallback_writer_actions(cluster: &IkaTestCluster) -> f64 {
    cluster
        .swarm
        .validator_node_handles()
        .iter()
        .map(|handle| {
            handle.with(|node| {
                node.registry_service_for_testing()
                    .default_registry()
                    .gather()
                    .iter()
                    .filter(|family| {
                        family.name() == "ika_sui_connector_fallback_writer_actions_total"
                    })
                    .flat_map(|family| family.get_metric())
                    .map(|metric| metric.get_counter().value())
                    .sum::<f64>()
            })
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn epoch_close_survives_notifier_death_via_fallback_writer() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .with_fallback_notifier(FALLBACK_ACTIVATION_DELAY_SECS)
        .build()
        .await
        .expect("ika test cluster failed to boot");

    // Phase 1: the healthy primary drives the 0 -> 1 close. The fallback
    // must not have acted — a takeover here means the activation gating is
    // broken (or the delay is inside the primary's real latency envelope).
    cluster.wait_for_epoch(1).await;
    let actions_while_healthy = fallback_writer_actions(&cluster);
    assert_eq!(
        actions_while_healthy, 0.0,
        "fallback writer acted while the primary notifier was healthy"
    );

    // Phase 2: kill the notifier — the only primary writer in the cluster.
    // Without the fallback this freezes the network at its current epoch
    // forever.
    let mut stopped_fullnodes = 0;
    for fullnode in cluster.swarm.fullnodes() {
        fullnode.stop();
        assert!(
            !fullnode.is_running(),
            "notifier fullnode still running after stop()"
        );
        stopped_fullnodes += 1;
    }
    assert_eq!(
        stopped_fullnodes, 1,
        "expected exactly the notifier fullnode in the swarm"
    );

    // Phase 3: two more closes must complete, counted from the epoch at kill
    // time — with 30s epochs and a multi-minute boot the cluster is well past
    // epoch 2 by now, so absolute epoch numbers prove nothing (waiting for
    // epoch 2 here returns instantly, exercising no takeover at all). One
    // close is also not proof: the dying primary may already have submitted
    // that epoch's remaining steps (`advance_epoch` included) before the
    // kill landed. Two closes guarantee at least one full epoch cycle —
    // mid-epoch, reconfiguration, pricing, session lock, advance, and every
    // checkpoint — happened entirely after the primary's death.
    let epoch_at_kill = cluster
        .current_epoch_from_chain()
        .await
        .expect("read current epoch after killing the notifier");
    tokio::time::timeout(
        FAILOVER_CLOSE_TIMEOUT,
        cluster.wait_for_epoch(epoch_at_kill + 2),
    )
    .await
    .expect("epoch did not close after the notifier died — the fallback writer never took over");
    let actions_after_failover = fallback_writer_actions(&cluster);
    assert!(
        actions_after_failover > 0.0,
        "epoch closed with a dead notifier but the fallback takeover counter is zero — \
         something else submitted (test wiring bug?)"
    );
}
