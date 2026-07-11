// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! User dWallet DKG requested INSIDE an MPC-degradation window under msim.
//!
//! The user-flow face of the two-MPC-degraded-laggards scenario: a dWallet
//! DKG session is requested while two of four validators skip all MPC
//! computations (sub-quorum for the session — it cannot complete), the
//! degradation heals, and the session must then complete from its already
//! on-chain request without any client retry. This is the shape behind the
//! historical SDK-visible "Object does not exist" timeout cascades: user
//! sessions created during a degraded window were the wedge's first
//! victims.
//!
//! Asserted properties:
//! - the DKG completes after the heal (server-side retry/recovery, no
//!   client resubmission);
//! - the epoch that hosted the degradation still closes and the cluster
//!   keeps reconfiguring afterwards.

#![cfg(msim)]

use std::collections::HashSet;
use std::time::Duration;

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::{clear_fail_point, register_fail_point_if, sim_test};

const DWALLET_CURVE_SECP256K1: u32 = 0;
const FIRST_VICTIM: usize = 2;
const SECOND_VICTIM: usize = 3;

#[sim_test]
async fn sim_dkg_requested_inside_degradation_window() {
    telemetry_subscribers::init_for_testing();
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .unwrap();

    // Healthy baseline: network key ready, one boundary crossed.
    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.unwrap();
    cluster.wait_for_epoch(1).await;

    // Open the degradation window: two validators skip all MPC
    // computations (their consensus stays alive).
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

    // Request the DKG INSIDE the window: 2 computing < 3-of-4 threshold,
    // so the session provably cannot complete until the heal.
    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x42u8; 32])
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

    // Keep the session starved for a slice of the epoch — and PROVE it is
    // starved: completion inside the window would mean the fail point
    // injected nothing and every later assertion passes vacuously.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        cluster
            .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, Duration::from_secs(5))
            .await
            .is_err(),
        "DKG completed during the sub-quorum degradation window — the fault \
         injection is not taking effect"
    );
    clear_fail_point("dwallet-mpc-computation");

    // The session must complete WITHOUT client-side retry — recovery is
    // the network's job once quorum computation capacity returns.
    cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, Duration::from_secs(180))
        .await
        .expect("dWallet DKG requested inside the degradation window never completed");

    // And the wounded epoch must not wedge the epoch machinery.
    cluster.wait_for_epoch(3).await;
}
