// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for network-owned-address signing.
//!
//! These tests verify that the network-owned-address signing flow works correctly
//! for all supported signature algorithms:
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
    IntegrationTestState, build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm,
};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use std::collections::HashSet;
use tracing::info;

/// All (curve, algorithm, hash_scheme) triples for network-owned-address signing E2E tests.
const ALL_SIGNATURE_CONFIGURATIONS: &[(
    DWalletCurve,
    DWalletSignatureAlgorithm,
    DWalletHashScheme,
)] = &[
    (
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::ECDSASecp256k1,
        DWalletHashScheme::Keccak256,
    ),
    (
        DWalletCurve::Secp256r1,
        DWalletSignatureAlgorithm::ECDSASecp256r1,
        DWalletHashScheme::SHA256,
    ),
    (
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
        DWalletHashScheme::SHA512,
    ),
    (
        DWalletCurve::Ristretto,
        DWalletSignatureAlgorithm::SchnorrkelSubstrate,
        DWalletHashScheme::Merlin,
    ),
    (
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::Taproot,
        DWalletHashScheme::SHA256,
    ),
];

/// End-to-end network-owned-address signing helper:
/// 1. Create a network key
/// 2. Wait for internal presign pool to populate for the given algorithm
/// 3. Send a NetworkOwnedAddressSignRequest via the channel
/// 4. Run consensus rounds until NetworkOwnedAddressSign session completes
/// 5. Verify pool size decreased and presign was consumed
/// 6. Verify NetworkOwnedAddressSignOutput appears on the output channel
async fn network_owned_address_sign_flow(
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
    hash_scheme: DWalletHashScheme,
) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Create a network key (required for network-owned-address signing).
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created at consensus round {}, key_id: {:?}",
        consensus_round, network_key_id
    );
    test_state.consensus_round = consensus_round as usize;

    info!(
        ?curve,
        ?signature_algorithm,
        ?hash_scheme,
        "Network-owned-address signing test"
    );

    // Wait for the internal presign pool to populate with real presigns.
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
        pool_size_before,
        "Pool size before network-owned-address sign"
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

    // Send a NetworkOwnedAddressSignRequest to all validators via the channel.
    let test_message = b"test message to sign internally".to_vec();

    for sender in &test_state.network_owned_address_sign_request_senders {
        sender
            .send(NetworkOwnedAddressSignRequest {
                message: test_message.clone(),
                curve,
                signature_algorithm,
                hash_scheme,
            })
            .expect("failed to send network-owned-address sign request");
    }

    // Run service loop iterations to process the requests.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }

    // Check that NetworkOwnedAddressSign sessions were created.
    let network_owned_address_sign_count: usize = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::NetworkOwnedAddressSign)
        .count();

    info!(
        network_owned_address_sign_count,
        "Network-owned-address sign sessions created"
    );

    // Run consensus rounds with computation waits to complete the sign session.
    // Rayon threads need real wall-clock time to finish MPC computations.
    let sign_output = wait_for_network_owned_address_sign_output(&mut test_state).await;

    assert_eq!(
        sign_output.message, test_message,
        "output message should match request"
    );
    assert!(
        !sign_output.signature.is_empty(),
        "signature should not be empty"
    );
    info!(
        ?sign_output.session_identifier,
        signature_len = sign_output.signature.len(),
        "Received NetworkOwnedAddressSignOutput"
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
        used_presigns_count = used_presigns.len(),
        consumed_from_snapshot_count = consumed_from_snapshot.len(),
        "Presign consumption check"
    );
    assert_eq!(
        consumed_from_snapshot.len(),
        1,
        "exactly one presign from the pre-sign pool snapshot should have been consumed"
    );

    info!(
        ?curve,
        ?signature_algorithm,
        "Network-owned-address sign E2E test completed"
    );
}

/// Polls consensus rounds until a `NetworkOwnedAddressSignOutput` is received on the first
/// validator's output channel, or panics after `MAX_SIGN_WAIT_ROUNDS` rounds.
///
/// ECDSA sign protocols have multiple MPC rounds with heavy computations, so we use the
/// same generous limit as the presign pool wait (300 rounds).
async fn wait_for_network_owned_address_sign_output(
    test_state: &mut IntegrationTestState,
) -> crate::dwallet_mpc::NetworkOwnedAddressSignOutput {
    const MAX_SIGN_WAIT_ROUNDS: usize = 300;
    let mut result = test_state.network_owned_address_sign_output_receivers[0]
        .try_recv()
        .ok();
    let mut rounds = 0usize;
    while result.is_none() && rounds < MAX_SIGN_WAIT_ROUNDS {
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
        utils::wait_for_computations(test_state).await;
        result = test_state.network_owned_address_sign_output_receivers[0]
            .try_recv()
            .ok();
        rounds += 1;
    }
    result.unwrap_or_else(|| {
        panic!(
            "NetworkOwnedAddressSignOutput not received after {} consensus rounds",
            MAX_SIGN_WAIT_ROUNDS,
        )
    })
}

// === Per-algorithm E2E tests ===

/// ECDSA centralized party emulation with ZeroRng currently fails with
/// `Commitment(InvalidPublicParameters)` in `SignCentralizedPartyV2`.
///
/// The Schnorr-based protocols (EdDSA, SchnorrkelSubstrate, Taproot) work because their
/// commitment scheme tolerates a zero secret key share, while ECDSA's does not.
///
/// The centralized party partial signature emulation (`emulate_centralized_party_partial_signature`
/// in `input.rs`) runs synchronously on the main thread outside any Rayon context.
/// For Schnorr this is fine (cheap), but for ECDSA it would also be expensive even if
/// the commitment issue were resolved. Two possible fixes:
/// 1. Move the emulation into the Rayon cryptographic computation pipeline so it runs
///    on the Rayon thread pool alongside the decentralized party sign computation.
/// 2. Adapt the Sign protocol to accept a flag that makes it compute the centralized
///    party partial signature internally (within its own Rayon task), eliminating the
///    need to pre-compute it in `session_input_from_request`.
///
/// Unignore once the ECDSA `Commitment(InvalidPublicParameters)` issue is resolved.
#[tokio::test]
#[cfg(test)]
#[ignore = "ECDSA centralized party emulation with ZeroRng fails: Commitment(InvalidPublicParameters)"]
async fn test_network_owned_address_sign_ecdsa_secp256k1() {
    network_owned_address_sign_flow(
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::ECDSASecp256k1,
        DWalletHashScheme::Keccak256,
    )
    .await;
}

/// See [`test_network_owned_address_sign_ecdsa_secp256k1`] for details on why this is ignored.
#[tokio::test]
#[cfg(test)]
#[ignore = "ECDSA centralized party emulation with ZeroRng fails: Commitment(InvalidPublicParameters)"]
async fn test_network_owned_address_sign_ecdsa_secp256r1() {
    network_owned_address_sign_flow(
        DWalletCurve::Secp256r1,
        DWalletSignatureAlgorithm::ECDSASecp256r1,
        DWalletHashScheme::SHA256,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_eddsa() {
    network_owned_address_sign_flow(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
        DWalletHashScheme::SHA512,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_schnorrkel_substrate() {
    network_owned_address_sign_flow(
        DWalletCurve::Ristretto,
        DWalletSignatureAlgorithm::SchnorrkelSubstrate,
        DWalletHashScheme::Merlin,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_taproot() {
    network_owned_address_sign_flow(
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::Taproot,
        DWalletHashScheme::SHA256,
    )
    .await;
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
    let session_ids: Vec<_> = ALL_SIGNATURE_CONFIGURATIONS
        .iter()
        .map(|(c, a, _)| network_owned_address_sign_dkg_session_id(&network_key_id, *c, *a))
        .collect();

    // All session IDs should be unique
    for (i, id_a) in session_ids.iter().enumerate() {
        for (j, id_b) in session_ids.iter().enumerate() {
            if i != j {
                assert_ne!(
                    id_a, id_b,
                    "session IDs for {:?} and {:?} should be different",
                    ALL_SIGNATURE_CONFIGURATIONS[i], ALL_SIGNATURE_CONFIGURATIONS[j]
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
        ALL_SIGNATURE_CONFIGURATIONS.len()
    );
}

/// Test that the network-owned-address sign DKG session ID derivation is stable across calls
/// and unique per key. This verifies the deterministic input that seeds the DKG
/// emulation, not the DKG computation itself (which requires real protocol public
/// parameters and is covered by the per-algorithm E2E tests).
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
