// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Global-presign traffic across epoch boundaries with an MPC-degradation
//! window mid-stream, under msim.
//!
//! Global presigns are served from the internal presign pool, so this is
//! the flow that dies when the pool starves — the historical wedge chain
//! was: refill batches unable to complete while the committee is
//! MPC-degraded, pool empty, locked-set presigns unservable, epoch pinned.
//! The recovery machinery (stale-batch expiry releasing dead refills,
//! serving resuming once capacity returns, held votes re-pulled across the
//! boundary) must instead carry both the traffic and the epochs.
//!
//! The test streams presign requests across two epoch boundaries, opens a
//! two-validator degradation window in the middle of the stream, heals,
//! and then requires the strongest invariant available on-chain: the
//! coordinator's user-session keeper fully drains (started == completed)
//! and epochs keep advancing. A lost session, a permanently starved pool,
//! or an over/undershot close all fail this drain.

#![cfg(msim)]

use std::collections::HashSet;
use std::time::Duration;

use ika_sui_client::ika_dwallet_transactions::{PaymentCoinArgs, request_global_presign_tx};
use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::{clear_fail_point, register_fail_point_if, sim_test};

const DWALLET_CURVE_SECP256K1: u32 = 0;
const DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1: u32 = 0;
const DEFAULT_DWALLET_TX_GAS_BUDGET: u64 = 5_000_000_000;
const FIRST_VICTIM: usize = 1;
const SECOND_VICTIM: usize = 3;

#[sim_test]
async fn sim_presign_traffic_with_degradation_window() {
    telemetry_subscribers::init_for_testing();
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .unwrap();

    cluster.wait_for_epoch(1).await;
    let (network_key_id, _network_dkg_public_output) =
        cluster.wait_for_network_key().await.unwrap();

    let traffic_start_epoch = cluster.current_epoch_from_chain().await.unwrap();
    let traffic_end_epoch = traffic_start_epoch + 2;

    let degraded: HashSet<_> = [FIRST_VICTIM, SECOND_VICTIM]
        .iter()
        .map(|&idx| {
            let handle = cluster.validator_handle(idx);
            handle.with(|node| node.get_sim_node_id())
        })
        .collect();

    // Stream presigns until two boundaries have crossed with requests in
    // flight; open the degradation window after the first few submissions
    // and heal it mid-stream, so requests land before, during, and after
    // the sub-quorum window.
    let ika_coin_id = cluster.packages.ika_supply_id;
    let mut submitted_count: u64 = 0;
    let mut window_open = false;
    let mut window_closed = false;
    loop {
        let current_epoch = cluster.current_epoch_from_chain().await.unwrap();
        if current_epoch >= traffic_end_epoch {
            break;
        }

        if submitted_count == 3 && !window_open {
            register_fail_point_if("dwallet-mpc-computation", {
                let degraded = degraded.clone();
                move || degraded.contains(&sui_simulator::current_simnode_id())
            });
            window_open = true;
        }
        if submitted_count == 6 && window_open && !window_closed {
            clear_fail_point("dwallet-mpc-computation");
            window_closed = true;
        }

        // Retry submission over Sui object contention on the shared IKA
        // supply coin, like the tokio twin does.
        let session_identifier_bytes: [u8; 32] = rand::random();
        let mut last_error = None;
        for _attempt in 0..30 {
            match request_global_presign_tx(
                cluster.test_cluster.wallet_mut(),
                cluster.packages.ika_dwallet_2pc_mpc_package_id,
                cluster.system.ika_dwallet_coordinator_object_id,
                network_key_id,
                DWALLET_CURVE_SECP256K1,
                DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
                session_identifier_bytes.to_vec(),
                PaymentCoinArgs {
                    ika_coin_id,
                    sui_coin_id: None,
                },
                DEFAULT_DWALLET_TX_GAS_BUDGET,
            )
            .await
            {
                Ok(_) => {
                    submitted_count += 1;
                    last_error = None;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        if let Some(error) = last_error {
            panic!("request_global_presign_tx failed after retries: {error}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(
        submitted_count >= 6,
        "expected enough presigns to straddle the degradation window, got {submitted_count}"
    );
    if window_open && !window_closed {
        // Traffic outpaced the schedule; make sure the window never leaks
        // past the traffic phase.
        clear_fail_point("dwallet-mpc-computation");
    }
    assert!(
        window_open,
        "the degradation window never opened — the fault leg of this test did not run"
    );

    // Epochs must keep advancing with stragglers re-pulled across
    // boundaries...
    tokio::time::timeout(
        Duration::from_secs(420),
        cluster.wait_for_epoch(traffic_end_epoch + 1),
    )
    .await
    .expect("epoch stopped advancing under degraded presign traffic — epoch-close wedge");

    // ...and every submitted user session must eventually complete
    // on-chain: started == completed. Catches a session lost to the lock,
    // a pool that never recovers from the starvation window, and an
    // over/undershot close alike.
    let sui_client = cluster.sui_connector_client().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let (_, inner) = sui_client.must_get_dwallet_coordinator_inner().await;
        let ika_types::sui::DWalletCoordinatorInner::V1(inner) = inner;
        let started = inner
            .sessions_manager
            .user_sessions_keeper
            .started_sessions_count;
        let completed = inner
            .sessions_manager
            .user_sessions_keeper
            .completed_sessions_count;
        if started == completed {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "user sessions never drained after the degradation window: \
             started={started} completed={completed}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
