// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Regression test for the epoch-close session-lock wedges: sustained
//! global-presign traffic across multiple epoch boundaries.
//!
//! Global presigns are the one user-session flow served from the internal
//! presign pool instead of a per-session MPC computation, and historically
//! the one flow whose on-chain completion was not gated by
//! `last_user_initiated_session_to_complete_in_current_epoch`. Two distinct
//! wedges were reproduced with exactly this traffic shape:
//!
//! - **Overshoot**: a presign served after the epoch-close lock froze the
//!   target pushed `completed_sessions_count` past it; the end-of-publish
//!   predicate is a strict equality, so the epoch could never close.
//! - **Undershoot**: one stale entry in a computation-results batch
//!   aborted processing of the whole batch, dropping sibling sessions'
//!   round messages; internal presign sessions starved below the message
//!   threshold, the pool never refilled, and locked-set presigns could
//!   never be served.
//!
//! The test streams global presigns across two epoch boundaries (the lock
//! fires once per epoch, so every boundary has requests astride it), then
//! requires that epochs keep advancing AND every submitted session
//! completes on-chain.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md: this is a
//! coordination test, not scheduling-dependent.

use ika_protocol_config::ProtocolVersion;
use ika_sui_client::ika_dwallet_transactions::{PaymentCoinArgs, request_global_presign_tx};
use ika_test_cluster::IkaTestClusterBuilder;

const DWALLET_CURVE_SECP256K1: u32 = 0;
const DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1: u32 = 0;
const DEFAULT_DWALLET_TX_GAS_BUDGET: u64 = 5_000_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn test_global_presigns_complete_across_epoch_switches() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, _network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let traffic_start_epoch = cluster
        .current_epoch_from_chain()
        .await
        .expect("current_epoch_from_chain failed");
    let traffic_end_epoch = traffic_start_epoch + 2;

    // Stream global presigns until two epoch boundaries have crossed with
    // requests in flight. Submission can hit Sui object contention on the
    // shared IKA supply coin (background staking flows move it); retry like
    // `request_user_dwallet_dkg` does.
    let ika_coin_id = cluster.packages.ika_supply_id;
    let mut submitted_count: u64 = 0;
    loop {
        let current_epoch = cluster
            .current_epoch_from_chain()
            .await
            .expect("current_epoch_from_chain failed");
        if current_epoch >= traffic_end_epoch {
            break;
        }

        // 30 × 2s also rides out the brief window right after key
        // publication where `validate_network_encryption_key_supports_curve`
        // still aborts (per-curve support registers shortly after the DKG
        // output lands).
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
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        if let Some(error) = last_error {
            panic!("request_global_presign_tx failed after retries: {error}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(
        submitted_count >= 4,
        "expected several presigns submitted across two boundaries, got {submitted_count}"
    );

    // The wedge signature is an epoch that never closes: traffic has
    // stopped, so the next boundary must arrive even with stragglers
    // re-pulled into it. The budget covers an end-of-epoch
    // reconfiguration under a 4-way-parallel CI pod (it passed at 180s
    // standalone but timed out in the full suite) — the failure mode
    // this guards against is "never", not "slow".
    tokio::time::timeout(
        std::time::Duration::from_secs(420),
        cluster.wait_for_epoch(traffic_end_epoch + 1),
    )
    .await
    .expect("epoch stopped advancing under global-presign traffic — epoch-close wedge");

    // Drain: every submitted user session must eventually complete
    // on-chain (started == completed). Catches both losing a session to
    // the lock entirely and a starved pool that can never serve it.
    let sui_client = cluster
        .sui_connector_client()
        .await
        .expect("sui_connector_client failed");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
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
            "submitted user sessions never drained: started={started} completed={completed}"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
