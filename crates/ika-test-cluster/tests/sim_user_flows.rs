// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Successful user flows across epoch boundaries under msim — the
//! happy-path twin of the fault-simulation suite.
//!
//! The fault tests prove the machinery survives adversity; this test
//! proves the product works: every user-facing flow (DKG + share
//! acceptance, global-presign sign, imported-key dwallet + dedicated-
//! presign sign, share transfer, make-share-public) completes
//! successfully on one cluster, with dwallets created in one epoch and
//! exercised in later ones. Runs under the deterministic crypto mock,
//! so a seed reproduces any failure exactly.
//!
//! Presign routing mirrors mainnet (the cluster genesises with the
//! `Full` global-presign config): DKG dwallets on secp256k1-ECDSA are
//! global-presign-only, imported-key secp256k1-ECDSA dwallets are
//! dedicated-presign-only — so the two dwallets between them cover both
//! presign paths.

#![cfg(msim)]

use std::time::Duration;

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::sim_test;

const DWALLET_CURVE_SECP256K1: u32 = 0;
const DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1: u32 = 0;
const HASH_SCHEME_KECCAK256: u32 = 0;
const HASH_SCHEME_SHA256: u32 = 1;
const EPOCH_MS: u64 = 20_000;
const FLOW_TIMEOUT: Duration = Duration::from_secs(300);

#[sim_test]
async fn sim_user_flows_across_boundaries() {
    telemetry_subscribers::init_for_testing();
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(EPOCH_MS)
        .build()
        .await
        .unwrap();

    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster.wait_for_network_key().await.unwrap();

    // Two user identities: the dwallet owner and a transfer destination.
    let owner_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x11; 32])
        .await
        .expect("register_user_encryption_key (owner) failed");
    let destination_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x22; 32])
        .await
        .expect("register_user_encryption_key (destination) failed");

    // DKG dwallet; accepting the encrypted share activates it
    // (AwaitingKeyHolderSignature -> Active) — signing needs Active.
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

    // Sign leg one: global presign (the only presign form the genesis
    // config allows for DKG dwallets on secp256k1-ECDSA).
    let global_presign = cluster
        .request_global_presign(
            network_key_id,
            DWALLET_CURVE_SECP256K1,
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
        )
        .await
        .expect("request_global_presign failed");
    let global_presign_bytes = cluster
        .wait_for_presign(&global_presign, FLOW_TIMEOUT)
        .await
        .expect("global presign never completed");
    let signature = cluster
        .sign(
            &dkg.signer(),
            &global_presign,
            global_presign_bytes,
            network_dkg_public_output.clone(),
            b"ika sim sign before boundary".to_vec(),
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
            HASH_SCHEME_KECCAK256,
            FLOW_TIMEOUT,
        )
        .await
        .expect("sign with global presign failed");
    assert!(!signature.is_empty(), "empty network signature");

    // Imported-key dwallet (verification + share acceptance inside the
    // driver), then sign with a DEDICATED presign — the config routes
    // imported-key secp256k1-ECDSA through the per-dwallet path.
    let imported = cluster
        .import_key_dwallet(
            network_key_id,
            network_dkg_public_output.clone(),
            &owner_key,
            &[0x33; 32],
            FLOW_TIMEOUT,
        )
        .await
        .expect("import_key_dwallet failed");
    let dedicated_presign = cluster
        .request_dedicated_presign(
            &imported.signer(),
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
        )
        .await
        .expect("request_dedicated_presign failed");
    let dedicated_presign_bytes = cluster
        .wait_for_presign(&dedicated_presign, FLOW_TIMEOUT)
        .await
        .expect("dedicated presign never completed");
    let signature = cluster
        .sign(
            &imported.signer(),
            &dedicated_presign,
            dedicated_presign_bytes,
            network_dkg_public_output.clone(),
            b"ika sim imported-key sign".to_vec(),
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
            HASH_SCHEME_SHA256,
            FLOW_TIMEOUT,
        )
        .await
        .expect("sign with imported-key dwallet failed");
    assert!(
        !signature.is_empty(),
        "empty imported-key network signature"
    );

    // Cross an epoch boundary with both dwallets live.
    let epoch = cluster.current_epoch_from_chain().await.unwrap();
    cluster.wait_for_epoch(epoch + 1).await;

    // Transfer the DKG dwallet's share to the destination key
    // (re-encrypt, network verification, destination acceptance) — the
    // dwallet was created an epoch ago.
    cluster
        .transfer_share(
            &dkg,
            network_dkg_public_output.clone(),
            &destination_key,
            FLOW_TIMEOUT,
        )
        .await
        .expect("transfer_share failed");

    // Publish the owner share (make-public) in the same post-boundary
    // epoch.
    cluster
        .make_share_public(&dkg.signer())
        .await
        .expect("make_share_public failed");
    cluster
        .wait_for_public_share(dkg.dwallet_id, FLOW_TIMEOUT)
        .await
        .expect("public share never landed on the dwallet");

    // The DKG dwallet must remain signable after the boundary, the
    // transfer, and make-public — with a fresh post-boundary presign.
    let post_boundary_presign = cluster
        .request_global_presign(
            network_key_id,
            DWALLET_CURVE_SECP256K1,
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
        )
        .await
        .expect("post-boundary request_global_presign failed");
    let post_boundary_presign_bytes = cluster
        .wait_for_presign(&post_boundary_presign, FLOW_TIMEOUT)
        .await
        .expect("post-boundary presign never completed");
    let signature = cluster
        .sign(
            &dkg.signer(),
            &post_boundary_presign,
            post_boundary_presign_bytes,
            network_dkg_public_output.clone(),
            b"ika sim sign after boundary".to_vec(),
            DWALLET_SIGNATURE_ALGORITHM_ECDSA_SECP256K1,
            HASH_SCHEME_KECCAK256,
            FLOW_TIMEOUT,
        )
        .await
        .expect("post-boundary sign failed");
    assert!(
        !signature.is_empty(),
        "empty post-boundary network signature"
    );

    // Second boundary, then the strongest on-chain invariant: every user
    // session the flows started must complete (started == completed) —
    // catches a session silently lost anywhere above.
    let epoch = cluster.current_epoch_from_chain().await.unwrap();
    cluster.wait_for_epoch(epoch + 1).await;
    let sui_client = cluster.sui_connector_client().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
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
            "user sessions never drained: started={started} completed={completed}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
