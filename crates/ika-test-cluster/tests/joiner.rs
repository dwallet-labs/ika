// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for validator joiner / removal flows on `IkaTestCluster`.
//!
//! `test_joiner_added_at_epoch_2` exercises the happy path: a 5th validator
//! registers as a candidate, gets staked over the minimum, calls
//! `request_add_validator`, and is spun up as an in-memory `IkaNode`. The
//! assertion is that the joiner's node reaches epoch 2 — proving the
//! on-chain committee swap and the off-chain MPC reconfiguration both
//! accepted the new member.
//!
//! `test_validator_removed_at_epoch_2` exercises the mirror flow: an
//! existing validator submits `request_remove_validator`, and the remaining
//! committee advances to epoch 2 without it.
//!
//! `test_sessions_complete_across_epoch_switch` drives a user-initiated
//! dWallet DKG and verifies it completes even when an epoch boundary
//! crosses while the session is in flight. This is the bug-repro test for
//! "sessions get stuck across epoch switch".
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md: these are
//! coordination tests, not scheduling-dependent. Real parallel crypto + no
//! msim slowdown.

use ika_test_cluster::{IkaTestClusterBuilder, wait_for_node_epoch};

#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_added_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Let the initial committee settle into epoch 1 before adding the
    // joiner. Submitting `request_add_validator` from epoch 0 works in
    // principle but adds an extra layer to debug if the test fails.
    cluster.wait_for_epoch(1).await;

    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    // Joiner becomes active at the next epoch boundary. Wait for both
    // the initial set AND the joiner to reach epoch 2 — the initial-set
    // check alone could mask a joiner that's stuck.
    cluster.wait_for_epoch(2).await;
    wait_for_node_epoch(&joiner.node_handle, 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_removed_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    // Validator 0 submits `request_remove_validator`. The on-chain
    // logic keeps it in the active set for the rest of epoch 1 and
    // drops it at the epoch-2 boundary.
    cluster
        .remove_validator(0)
        .await
        .expect("remove_validator failed");

    // Snapshot remaining validators' node handles BEFORE waiting —
    // index 0 might disappear from validator_node_handles() depending
    // on shutdown timing, and we want to assert the survivors reach
    // epoch 2 with the new 3-member committee.
    let remaining: Vec<_> = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .skip(1)
        .collect();
    assert_eq!(
        remaining.len(),
        3,
        "expected 3 surviving validator handles before wait_for_epoch(2)"
    );
    for handle in &remaining {
        wait_for_node_epoch(handle, 2).await;
    }
}

/// Curve enum value for `Secp256k1` (matches the on-chain definition
/// in `coordinator_inner.move`).
const DWALLET_CURVE_SECP256K1: u32 = 0;

#[tokio::test(flavor = "multi_thread")]
async fn test_sessions_complete_across_epoch_switch() {
    telemetry_subscribers::init_for_testing();

    // Short epoch_duration so the epoch boundary lands while the
    // user-initiated DKG is in flight. The bug being probed is
    // "sessions stuck across epoch switch" — keeping epochs short
    // maximizes the chance the boundary crosses mid-DKG.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    // Race the epoch-2 boundary against DKG completion. Both should
    // succeed — the DKG MUST finish despite the epoch switch crossing
    // mid-session.
    //
    // Empirically the MPC computation itself is fast (~100ms per
    // round) but the request → MPC kickoff path queues behind the
    // network-reconfiguration MPC when an epoch boundary lands soon
    // after submission, easily adding 2+ minutes wall before the
    // session even starts. The chain-event emission pipeline
    // (validator output → consensus → checkpoint → Sui tx → emit)
    // adds another few seconds. A 5-minute timeout gives both stages
    // headroom; the failure mode the test cares about is "stuck",
    // not "slow".
    let epoch_2 = cluster.wait_for_epoch(2);
    let dkg_done = cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(300));
    let (_, dkg_result) = tokio::join!(epoch_2, dkg_done);
    dkg_result.expect("dWallet DKG never completed across epoch switch");
}
