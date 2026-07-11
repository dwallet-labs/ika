// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! MPC-degradation window straddling an epoch close, with a user session
//! in flight — the epoch-close undershoot shape under msim.
//!
//! The epoch close locks a target session count and requires every
//! in-target user session to complete before the epoch can advance
//! (`all_epoch_sessions_finished`). Historically, sessions that could not
//! complete while the committee was MPC-degraded pinned that gate forever
//! (undershoot: completed < target, and the close predicate never
//! satisfied). The recovery machinery (computation retries once capacity
//! returns, the internal-presign stale-batch expiry, held-vote re-pull
//! into the next epoch) must instead carry the epoch across.
//!
//! Scenario: a user DKG lands mid-epoch, then two validators go MPC-dead
//! through the epoch's scheduled close and heal INSIDE the next epoch's
//! window. Asserted: the wounded epoch still closes (no permanent
//! undershoot), the user session completes after the heal, and the
//! cluster keeps reconfiguring.

#![cfg(msim)]

use std::collections::HashSet;
use std::time::Duration;

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::{clear_fail_point, register_fail_point_if, sim_test};

const DWALLET_CURVE_SECP256K1: u32 = 0;
const FIRST_VICTIM: usize = 1;
const SECOND_VICTIM: usize = 2;
const EPOCH_MS: u64 = 20_000;

#[sim_test]
async fn sim_degradation_across_epoch_close() {
    telemetry_subscribers::init_for_testing();
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(EPOCH_MS)
        .build()
        .await
        .unwrap();

    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.unwrap();
    cluster.wait_for_epoch(1).await;

    // A user session enters mid-epoch, before the fault: it (or its
    // successors) will be in the close-lock's target set.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x77u8; 32])
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

    // Open the degradation window late in epoch 1 so it straddles the
    // scheduled close (epoch duration 20s; entering epoch 1 + a DKG round
    // trip has consumed a good slice already — the window below covers the
    // remainder of the epoch and the boundary itself).
    let degraded: HashSet<_> = [FIRST_VICTIM, SECOND_VICTIM]
        .iter()
        .map(|&idx| {
            let handle = cluster.validator_handle(idx);
            handle.with(|node| node.get_sim_node_id())
        })
        .collect();
    register_fail_point_if("dwallet-mpc-computation", move || {
        degraded.contains(&sui_simulator::current_simnode_id())
    });

    // Hold sub-quorum across the boundary window, then heal.
    tokio::time::sleep(Duration::from_millis(EPOCH_MS)).await;
    clear_fail_point("dwallet-mpc-computation");

    // The wounded epoch must close despite in-flight/in-target sessions
    // being unservable through its boundary window (no permanent
    // undershoot), the user session must complete after the heal, and the
    // machinery must keep reconfiguring beyond it.
    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, Duration::from_secs(180))
        .await
        .expect("user session straddling the degraded close never completed");
    cluster.wait_for_epoch(3).await;
}
