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
//! - **A healthy primary keeps the fallback silent.** The epoch 0 → 1 close
//!   runs with the notifier alive; the fallback validator's takeover counter
//!   must still read zero afterwards.
//! - **A dead primary is survived without human intervention.** The notifier
//!   fullnode is stopped outright; the epoch 1 → 2 close can then only
//!   happen through the fallback writer on validator 0, and the takeover
//!   counter must show it acted.
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

/// Ceiling for the post-kill epoch close. Generous: one activation delay per
/// pending step plus MPC reconfiguration time, far below the value at which
/// CI would call the network wedged.
const FAILOVER_CLOSE_TIMEOUT: Duration = Duration::from_secs(600);

/// Sum of `ika_sui_connector_fallback_writer_actions_total` on validator 0
/// (the configured fallback writer). Zero means it never took over.
fn fallback_writer_actions(cluster: &IkaTestCluster) -> f64 {
    let handle = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .next()
        .expect("swarm must have validator 0");
    handle.with(|node| {
        node.registry_service_for_testing()
            .default_registry()
            .gather()
            .iter()
            .filter(|family| family.name() == "ika_sui_connector_fallback_writer_actions_total")
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_counter().value())
            .sum()
    })
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
    // Without the fallback this freezes the network at epoch 1 forever.
    for fullnode in cluster.swarm.fullnodes() {
        fullnode.stop();
    }

    // Phase 3: the 1 -> 2 close can now only complete through the fallback
    // writer on validator 0.
    tokio::time::timeout(FAILOVER_CLOSE_TIMEOUT, cluster.wait_for_epoch(2))
        .await
        .expect(
            "epoch did not close after the notifier died — the fallback writer never took over",
        );
    let actions_after_failover = fallback_writer_actions(&cluster);
    assert!(
        actions_after_failover > 0.0,
        "epoch closed with a dead notifier but the fallback takeover counter is zero — \
         something else submitted (test wiring bug?)"
    );
}
