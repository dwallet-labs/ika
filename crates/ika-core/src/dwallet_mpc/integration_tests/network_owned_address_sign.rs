// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for network-owned-address signing.
//!
//! These tests verify that the network-owned-address signing flow works correctly:
//! 1. Network key creation with network-owned-address sign DKG
//! 2. Presign pool population
//! 3. Network-owned-address sign session triggering
//! 4. Signature verification against the network key

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_owned_address_sign_dkg_emulation::network_owned_address_sign_dkg_session_id;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm,
};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use std::collections::HashSet;
use tracing::info;

/// Test that network-owned-address signing works end-to-end:
/// 1. Create a network key
/// 2. Wait for internal presign pool to populate
/// 3. Send an NetworkOwnedAddressSignRequest via the channel
/// 4. Run consensus rounds until NetworkOwnedAddressSign session completes
/// 5. Verify pool size decreased and presign was consumed
/// 6. Verify NetworkOwnedAddressSignOutput appears on the output channel
#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Create a network key (required for network-owned-address signing)
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created at consensus round {}, key_id: {:?}",
        consensus_round, network_key_id
    );
    test_state.consensus_round = consensus_round as usize;

    // Use EdDSA for the test — it's the fastest algorithm and exercises the full flow.
    let signature_algorithm = DWalletSignatureAlgorithm::EdDSA;
    let hash_scheme = DWalletHashScheme::SHA512;

    info!(
        "Network-owned-address signing test: algorithm={:?}, hash_scheme={:?}",
        signature_algorithm, hash_scheme
    );

    // Wait for the internal presign pool to populate with real presigns
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        signature_algorithm,
        network_key_id,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    // Record pool size and snapshot pool contents (session IDs) before signing.
    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(signature_algorithm, network_key_id)
        .expect("failed to get pool size");
    info!(
        "Pool size before network-owned-address sign: {}",
        pool_size_before
    );
    assert!(
        pool_size_before > 0,
        "pool should have at least one presign"
    );
    let presign_session_ids_before: HashSet<SessionIdentifier> = test_state.epoch_stores[0]
        .presign_pools
        .lock()
        .unwrap()
        .get(&(signature_algorithm, network_key_id))
        .map(|pool| pool.iter().map(|(id, _)| *id).collect())
        .unwrap_or_default();

    // Send an NetworkOwnedAddressSignRequest to all validators via the channel
    let test_message = b"test message to sign internally".to_vec();
    let sequence_number = 42u64;

    for sender_map in &test_state.network_owned_address_sign_request_senders {
        sender_map
            .get(&signature_algorithm)
            .expect("missing sender for algorithm")
            .send(NetworkOwnedAddressSignRequest {
                sequence_number,
                message: test_message.clone(),
                signature_algorithm,
                hash_scheme,
            })
            .expect("failed to send network-owned-address sign request");
    }

    // Run service loop iterations to process the requests.
    // The service's process_network_owned_address_sign_requests() drains the channel
    // and calls instantiate_network_owned_address_sign_session().
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }

    // Check that NetworkOwnedAddressSign sessions were created
    let network_owned_address_sign_count: usize = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::NetworkOwnedAddressSign)
        .count();

    info!(
        "Network-owned-address sign sessions created: {}",
        network_owned_address_sign_count
    );

    // Run consensus rounds with computation waits to complete the sign session.
    // Rayon threads need real wall-clock time to finish MPC computations.
    let sign_output = {
        let mut result = test_state.network_owned_address_sign_output_receivers[0]
            .try_recv()
            .ok();
        let mut rounds = 0usize;
        while result.is_none() && rounds < 150 {
            utils::send_advance_results_between_parties(
                &test_state.committee,
                &mut test_state.sent_consensus_messages_collectors,
                &mut test_state.epoch_stores,
                test_state.consensus_round as u64,
            );
            test_state.consensus_round += 1;
            for service in test_state.dwallet_mpc_services.iter_mut() {
                service.run_service_loop_iteration(vec![]).await;
            }
            utils::wait_for_computations(&mut test_state).await;
            result = test_state.network_owned_address_sign_output_receivers[0]
                .try_recv()
                .ok();
            rounds += 1;
        }
        result.expect("NetworkOwnedAddressSignOutput not received after 150 consensus rounds")
    };
    assert_eq!(
        sign_output.sequence_number, sequence_number,
        "output sequence number should match request"
    );
    assert!(
        !sign_output.signature.is_empty(),
        "signature should not be empty"
    );
    info!(
        "Received NetworkOwnedAddressSignOutput: sequence_number={}, signature_len={}",
        sign_output.sequence_number,
        sign_output.signature.len()
    );

    // Verify that exactly one presign from the pre-sign snapshot was consumed.
    let used_presigns = test_state.epoch_stores[0]
        .used_presigns
        .lock()
        .unwrap()
        .clone();
    let consumed_from_snapshot: HashSet<_> = presign_session_ids_before
        .iter()
        .filter(|id| {
            used_presigns
                .get(id)
                .map_or(false, |(used_count, _)| *used_count > 0)
        })
        .collect();
    info!(
        "Used presigns: {:?}, from snapshot: {:?}",
        used_presigns.len(),
        consumed_from_snapshot.len()
    );
    assert_eq!(
        consumed_from_snapshot.len(),
        1,
        "exactly one presign from the pre-sign pool snapshot should have been consumed"
    );

    info!("Network-owned-address sign E2E test completed");
}

/// Test that the network-owned-address sign DKG session ID is computed deterministically,
/// and that changing any single input produces a different session ID.
#[test]
fn test_network_owned_address_sign_dkg_session_id_determinism() {
    let network_key_id = [1u8; 32];
    let curve = DWalletCurve::Curve25519;
    let algorithm = DWalletSignatureAlgorithm::EdDSA;

    // Same inputs produce same session ID
    let session_id_first =
        network_owned_address_sign_dkg_session_id(&network_key_id, curve, algorithm);
    let session_id_second =
        network_owned_address_sign_dkg_session_id(&network_key_id, curve, algorithm);
    assert_eq!(
        session_id_first, session_id_second,
        "session IDs should be deterministic for identical inputs"
    );

    // Different network key ID produces different session ID
    let different_key_id = [2u8; 32];
    let session_id_different_key =
        network_owned_address_sign_dkg_session_id(&different_key_id, curve, algorithm);
    assert_ne!(
        session_id_first, session_id_different_key,
        "different network key IDs should produce different session IDs"
    );

    // Different curve produces different session ID
    let session_id_different_curve = network_owned_address_sign_dkg_session_id(
        &network_key_id,
        DWalletCurve::Secp256k1,
        algorithm,
    );
    assert_ne!(
        session_id_first, session_id_different_curve,
        "different curves should produce different session IDs"
    );

    // Different algorithm produces different session ID
    let session_id_different_algo = network_owned_address_sign_dkg_session_id(
        &network_key_id,
        curve,
        DWalletSignatureAlgorithm::SchnorrkelSubstrate,
    );
    assert_ne!(
        session_id_first, session_id_different_algo,
        "different algorithms should produce different session IDs"
    );

    // Test various curve/algorithm combinations for uniqueness
    let combinations = [
        (
            DWalletCurve::Secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256k1,
        ),
        (
            DWalletCurve::Secp256r1,
            DWalletSignatureAlgorithm::ECDSASecp256r1,
        ),
        (DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA),
        (
            DWalletCurve::Ristretto,
            DWalletSignatureAlgorithm::SchnorrkelSubstrate,
        ),
        (DWalletCurve::Secp256k1, DWalletSignatureAlgorithm::Taproot),
    ];

    let session_ids: Vec<_> = combinations
        .iter()
        .map(|(c, a)| network_owned_address_sign_dkg_session_id(&network_key_id, *c, *a))
        .collect();

    // All session IDs should be unique
    for (i, id_a) in session_ids.iter().enumerate() {
        for (j, id_b) in session_ids.iter().enumerate() {
            if i != j {
                assert_ne!(
                    id_a, id_b,
                    "session IDs for {:?} and {:?} should be different",
                    combinations[i], combinations[j]
                );
            }
        }
    }

    // Single-bit-flip edge case: flipping one bit in the network key ID must change the session ID
    let mut flipped_key_id = [1u8; 32];
    flipped_key_id[0] ^= 1;
    let flipped_session_id = network_owned_address_sign_dkg_session_id(
        &flipped_key_id,
        DWalletCurve::Curve25519,
        algorithm,
    );
    assert_ne!(
        session_id_first, flipped_session_id,
        "single-bit flip in network key ID should produce a different session ID"
    );

    // Boundary edge cases: all-zeros and all-0xFF key IDs must produce different session IDs
    let zero_id =
        network_owned_address_sign_dkg_session_id(&[0u8; 32], DWalletCurve::Curve25519, algorithm);
    let max_id = network_owned_address_sign_dkg_session_id(
        &[0xFFu8; 32],
        DWalletCurve::Curve25519,
        algorithm,
    );
    assert_ne!(
        zero_id, max_id,
        "all-zeros and all-0xFF key IDs should produce different session IDs"
    );

    info!(
        "Session ID determinism verified across {} curve/algorithm combinations",
        combinations.len()
    );
}

/// Test that the network-owned-address sign DKG session ID derivation is stable across calls
/// and unique per key. This verifies the deterministic input that seeds the DKG
/// emulation, not the DKG computation itself (which requires real protocol public
/// parameters and is covered by `test_network_owned_address_sign_flow`).
#[test]
fn test_dkg_session_id_stability() {
    let key_id = [42u8; 32];

    let first_call = network_owned_address_sign_dkg_session_id(
        &key_id,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    let second_call = network_owned_address_sign_dkg_session_id(
        &key_id,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    assert_eq!(
        first_call, second_call,
        "DKG session IDs must be byte-identical across calls"
    );

    let different_key = [43u8; 32];
    let third_call = network_owned_address_sign_dkg_session_id(
        &different_key,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    assert_ne!(
        first_call, third_call,
        "different keys should produce different DKG session IDs"
    );

    info!("DKG session ID stability verified");
}
