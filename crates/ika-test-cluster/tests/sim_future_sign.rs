// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Future-sign across an epoch boundary under msim.
//!
//! Future-sign is the flow whose two halves are DESIGNED to be separated
//! in time: the user pre-commits a signature share against a presign
//! (creating a network-verified `PartialUserSignature`), and an
//! arbitrary later transaction fulfills it into a full signature. This
//! test puts an epoch boundary — committee reconfiguration, network-key
//! handoff, presign-pool turnover — between the two halves: the partial
//! signature and its wrapped presign are created in one epoch and
//! fulfilled in the next, which no other test (tokio or sim) covers.
//! Runs under the deterministic crypto mock, so a seed reproduces any
//! failure exactly.

#![cfg(msim)]

use std::time::Duration;

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::sim_test;

const DWALLET_CURVE_SECP256K1: u32 = 0;
const DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1: u32 = 0;
const HASH_SCHEME_KECCAK256: u32 = 0;
const EPOCH_MS: u64 = 20_000;
// Generous. A session requested astride an epoch close is excluded from
// that close's lock target and re-pulled into the next epoch, so its
// completion can legitimately land an epoch-cycle after the request
// (observed ~295 virtual seconds for the imported-key verification at
// 20-second epochs, which lost a 300-second budget by seconds). The
// budget covers that legitimate re-pull latency with headroom.
const FLOW_TIMEOUT: Duration = Duration::from_secs(600);

#[sim_test]
async fn sim_future_sign_across_boundary() {
    telemetry_subscribers::init_for_testing();
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(EPOCH_MS)
        .build()
        .await
        .unwrap();

    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.unwrap();

    let owner_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x44; 32])
        .await
        .expect("register_user_encryption_key failed");
    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output.clone(),
            &owner_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");
    cluster
        .wait_for_dwallet_dkg_complete(dkg.dwallet_id, FLOW_TIMEOUT)
        .await
        .expect("dwallet DKG never completed");
    cluster
        .accept_dwallet_share(&dkg, &owner_key)
        .await
        .expect("accept_dwallet_share failed");

    // First half, this epoch: presign + pre-committed user signature.
    let presign = cluster
        .request_global_presign(
            network_key_id,
            DWALLET_CURVE_SECP256K1,
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
        )
        .await
        .expect("request_global_presign failed");
    let presign_bytes = cluster
        .wait_for_presign(&presign, FLOW_TIMEOUT)
        .await
        .expect("presign never completed");
    let message = b"ika sim future sign across boundary".to_vec();
    let partial_signature_cap_id = cluster
        .future_sign(
            &dkg.signer(),
            &presign,
            presign_bytes,
            network_dkg_public_output,
            message.clone(),
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
            HASH_SCHEME_KECCAK256,
        )
        .await
        .expect("future_sign failed");
    // The partial signature's verified state is a fieldless enum variant
    // (unobservable through object JSON) — barrier on the coordinator's
    // user-session drain instead: in this single-actor test, all-drained
    // implies the verification session completed in THIS epoch.
    cluster
        .wait_for_user_sessions_drained(FLOW_TIMEOUT)
        .await
        .expect("pre-boundary sessions (incl. partial-signature verification) never drained");

    // Boundary between the halves.
    let epoch = cluster.current_epoch_from_chain().await.unwrap();
    cluster.wait_for_epoch(epoch + 1).await;

    // Second half, next epoch: fulfill into a full network signature.
    let signature = cluster
        .future_sign_fulfill(
            &dkg.signer(),
            partial_signature_cap_id,
            message,
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
            HASH_SCHEME_KECCAK256,
            FLOW_TIMEOUT,
        )
        .await
        .expect("future_sign_fulfill after the boundary failed");
    assert!(!signature.is_empty(), "empty future-sign network signature");

    // Drain check: every session started by the flow completed on-chain.
    cluster
        .wait_for_user_sessions_drained(FLOW_TIMEOUT)
        .await
        .expect("sessions never drained after future-sign fulfill");
}
