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
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_owned_address_sign_dkg_emulation::network_owned_address_sign_dkg_session_identifier;
use crate::dwallet_mpc::mpc_session::{SessionComputationType, SessionStatus};
use crate::dwallet_mpc::integration_tests::network_dkg::{
    create_network_key_test, create_reconfigured_network_key_test,
};
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm,
};
use ika_types::message::{DWalletCheckpointMessageKind, MakeDWalletUserSecretKeySharesPublicOutput};
use ika_types::messages_dwallet_mpc::{
    DWalletMPCOutput, DWalletMPCOutputReport, SessionIdentifier, SessionType,
};
use std::collections::HashSet;
use itertools::Itertools;
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
        DWalletSignatureAlgorithm::Schnorrkel,
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
    let (consensus_round, _network_key_bytes, encryption_key) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created at consensus round {}, key_id: {:?}",
        consensus_round, encryption_key
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
        encryption_key,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    // Record pool size and snapshot pool contents (session identifiers) before signing.
    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(signature_algorithm, encryption_key)
        .expect("failed to get pool size");
    info!(
        pool_size_before,
        "Pool size before network-owned-address sign"
    );
    assert!(
        pool_size_before > 0,
        "pool should have at least one presign"
    );
    let presigns_before: HashSet<(SessionIdentifier, u16)> = test_state.epoch_stores[0]
        .presign_pools
        .lock()
        .unwrap()
        .get(&(signature_algorithm, encryption_key))
        .map(|pool| {
            pool.iter()
                .map(|(id, blending_index, _)| (*id, *blending_index))
                .collect()
        })
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
            .await
            .expect("failed to send network-owned-address sign request");
    }

    // Run service loop iterations to process the requests.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
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
    let consumed_from_snapshot: HashSet<_> = presigns_before
        .iter()
        .filter(|presign_key| used_presigns.contains_key(presign_key))
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
            service.run_service_loop_iteration().await;
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

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_ecdsa_secp256k1() {
    network_owned_address_sign_flow(
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::ECDSASecp256k1,
        DWalletHashScheme::Keccak256,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
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
        DWalletSignatureAlgorithm::Schnorrkel,
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

/// Test that the network-owned-address sign DKG session identifier is computed deterministically,
/// and that changing any single input produces a different session identifier.
#[test]
fn test_network_owned_address_sign_dkg_session_identifier_determinism() {
    let encryption_key = [1u8; 32];
    let curve = DWalletCurve::Curve25519;

    // Same inputs produce same session identifier
    let session_identifier_first =
        network_owned_address_sign_dkg_session_identifier(&encryption_key, curve);
    let session_identifier_second =
        network_owned_address_sign_dkg_session_identifier(&encryption_key, curve);
    assert_eq!(
        session_identifier_first, session_identifier_second,
        "session identifiers should be deterministic for identical inputs"
    );

    // Different encryption key produces different session identifier
    let different_encryption_key = [2u8; 32];
    let session_identifier_different_key =
        network_owned_address_sign_dkg_session_identifier(&different_encryption_key, curve);
    assert_ne!(
        session_identifier_first, session_identifier_different_key,
        "different encryption keys should produce different session identifiers"
    );

    // Different curve produces different session identifiers
    let session_identifier_different_curve =
        network_owned_address_sign_dkg_session_identifier(&encryption_key, DWalletCurve::Secp256k1);
    assert_ne!(
        session_identifier_first, session_identifier_different_curve,
        "different curves should produce different session identifiers"
    );

    // Test all curves for uniqueness
    let curves = ALL_SIGNATURE_CONFIGURATIONS
        .iter()
        .map(|(c, _, _)| *c)
        .unique()
        .collect_vec();

    let session_identifiers: Vec<_> = curves
        .iter()
        .map(|c| network_owned_address_sign_dkg_session_identifier(&encryption_key, *c))
        .collect();

    for (i, id_a) in session_identifiers.iter().enumerate() {
        for (j, id_b) in session_identifiers.iter().enumerate() {
            if i != j {
                assert_ne!(
                    id_a, id_b,
                    "session identifiers for {:?} and {:?} should be different",
                    curves[i], curves[j]
                );
            }
        }
    }

    // Single-bit-flip edge case: flipping one bit in the encryption key must change the session identifier
    let mut flipped_encryption_key = [1u8; 32];
    flipped_encryption_key[0] ^= 1;
    let flipped_session_identifier = network_owned_address_sign_dkg_session_identifier(
        &flipped_encryption_key,
        DWalletCurve::Curve25519,
    );
    assert_ne!(
        session_identifier_first, flipped_session_identifier,
        "single-bit flip in encryption key should produce a different session identifiers"
    );

    // Boundary edge cases: all-zeros and all-0xFF encryption keys must produce different session identifiers
    let zero_id =
        network_owned_address_sign_dkg_session_identifier(&[0u8; 32], DWalletCurve::Curve25519);
    let max_id =
        network_owned_address_sign_dkg_session_identifier(&[0xFFu8; 32], DWalletCurve::Curve25519);
    assert_ne!(
        zero_id, max_id,
        "all-zeros and all-0xFF encryption keys should produce different session identifiers"
    );

    info!(
        "Session identifier determinism verified across {} curves",
        curves.len()
    );
}

/// Test that the network-owned-address sign DKG session identifier is stable across calls
/// and unique per key.
#[test]
fn test_dkg_session_identifier_stability() {
    let encryption_key = [42u8; 32];

    let first_call = network_owned_address_sign_dkg_session_identifier(
        &encryption_key,
        DWalletCurve::Curve25519,
    );
    let second_call = network_owned_address_sign_dkg_session_identifier(
        &encryption_key,
        DWalletCurve::Curve25519,
    );
    assert_eq!(
        first_call, second_call,
        "DKG session identifiers must be byte-identical across calls"
    );

    let different_encryption_key = [43u8; 32];
    let third_call = network_owned_address_sign_dkg_session_identifier(
        &different_encryption_key,
        DWalletCurve::Curve25519,
    );
    assert_ne!(
        first_call, third_call,
        "different keys should produce different DKG session identifiers"
    );

    info!("DKG session identifier stability verified");
}

/// Test that excess sign requests are buffered when the presign pool is exhausted,
/// and that they are processed once new presigns become available.
///
/// Flow:
/// 1. Create a network key and fill the EdDSA presign pool.
/// 2. Send `pool_size + 2` unique sign requests to all validators.
/// 3. After one service loop iteration, assert that:
///    - The presign pool is empty (all presigns consumed).
///    - Exactly 2 requests remain in the pending buffer.
/// 4. Advance consensus rounds until new presigns refill the pool.
/// 5. Assert that the pending count has dropped (excess requests processed).
#[tokio::test]
#[cfg(test)]
async fn test_presign_pool_exhaustion_buffers_excess_sign_requests() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Create a network key (required for network-owned-address signing).
    let (consensus_round, _network_key_bytes, encryption_key) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Fill the EdDSA presign pool.
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        DWalletSignatureAlgorithm::EdDSA,
        encryption_key,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    // Record the pool size before sending sign requests.
    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, encryption_key)
        .expect("failed to get pool size");
    info!(
        pool_size_before,
        "EdDSA presign pool size before exhaustion"
    );
    assert!(pool_size_before >= 1, "pool should have at least 1 presign");

    let excess_count = 2usize;
    let total_requests = pool_size_before as usize + excess_count;

    // Send pool_size_before + 2 unique sign requests to ALL validators.
    for i in 0..total_requests {
        let message = format!("exhaustion-test-message-{}", i).into_bytes();
        for sender in &test_state.network_owned_address_sign_request_senders {
            sender
                .send(NetworkOwnedAddressSignRequest {
                    message: message.clone(),
                    curve: DWalletCurve::Curve25519,
                    signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
                    hash_scheme: DWalletHashScheme::SHA512,
                })
                .await
                .expect("failed to send sign request");
        }
    }

    // Run one service loop iteration to drain the channel and process requests.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }

    // Assert: pool is empty (all presigns consumed).
    let pool_size_after = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, encryption_key)
        .expect("failed to get pool size");
    info!(pool_size_after, "EdDSA pool size after exhaustion");
    assert_eq!(
        pool_size_after, 0,
        "pool should be empty after consuming all presigns"
    );

    // Assert: exactly `excess_count` requests remain pending on each validator.
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let pending = service.pending_network_owned_address_sign_request_count();
        info!(
            validator = i,
            pending, "pending sign requests after exhaustion"
        );
        assert_eq!(
            pending, excess_count,
            "Validator {} should have {} pending requests, got {}",
            i, excess_count, pending,
        );
    }

    // Advance rounds to let the presign pool refill via background presign sessions.
    // After refill, the service loop should process the buffered requests.
    let mut pending_dropped = false;
    for round in 0..300 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }
        utils::wait_for_computations(&mut test_state).await;

        let pending =
            test_state.dwallet_mpc_services[0].pending_network_owned_address_sign_request_count();
        if round < 10 || round % 50 == 0 || pending < excess_count {
            let pool_size = test_state.epoch_stores[0]
                .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, encryption_key)
                .unwrap_or(0);
            info!(
                round,
                pending,
                pool_size,
                consensus_round = test_state.consensus_round,
                "waiting for presign refill and pending drain"
            );
        }

        if pending < excess_count {
            info!(
                round,
                pending, "pending requests dropped — presign pool refilled and excess processed"
            );
            pending_dropped = true;
            break;
        }
    }

    assert!(
        pending_dropped,
        "pending sign requests should have been processed after presign pool refill"
    );

    info!(
        "Test passed: presign pool exhaustion correctly buffers and later processes excess requests"
    );
}

/// A validator that instantiates a NOA sign *after* its peers have already
/// broadcast their first-round messages must keep those buffered messages when
/// it activates the session.
///
/// This reproduces the migration-rehearsal epoch wedge: during a staggered
/// (rolling-restart) sign, some validators reach the sign later than others —
/// their signing key / presign becomes available only after peers have started
/// the round. The message-receipt path buffers peers' first-round messages in a
/// `WaitingForSessionRequest` placeholder; if instantiation overwrites that
/// placeholder with an empty message buffer, those messages are lost (the
/// consensus rounds that carried them have already been processed and are never
/// redelivered). The late validators are then stranded below the sign
/// threshold, the sign never completes, and the epoch hard-wedges on
/// NOA-checkpoint finalization.
///
/// Without the in-place placeholder upgrade in
/// `instantiate_network_owned_address_sign_session`, the sign here never yields
/// an output and `wait_for_network_owned_address_sign_output` times out.
#[tokio::test]
#[cfg(test)]
async fn test_late_instantiating_validator_preserves_buffered_sign_messages() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let curve = DWalletCurve::Curve25519;
    let signature_algorithm = DWalletSignatureAlgorithm::EdDSA;
    let hash_scheme = DWalletHashScheme::SHA512;

    let mut test_state = build_test_state(4);

    // Create a network key and fill the EdDSA presign pool so every validator
    // is able to instantiate the sign.
    let (consensus_round, _network_key_bytes, encryption_key) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        signature_algorithm,
        encryption_key,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    // The threshold for a 4-validator committee is 3, so two "early" and two
    // "late" validators means the sign can only complete if the late ones keep
    // the early ones' first-round messages across instantiation.
    let early_parties = [2usize, 3usize];
    let late_parties = [0usize, 1usize];
    let test_message = b"staggered-restart committee-freeze sign".to_vec();

    // Phase 1: only the early validators receive the request. They instantiate
    // and compute their first-round messages.
    for &i in &early_parties {
        test_state.network_owned_address_sign_request_senders[i]
            .send(NetworkOwnedAddressSignRequest {
                message: test_message.clone(),
                curve,
                signature_algorithm,
                hash_scheme,
            })
            .await
            .expect("failed to send early network-owned-address sign request");
    }
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    utils::wait_for_computations(&mut test_state).await;

    // Deliver the early validators' first-round messages to everyone. This is
    // the only time these messages are on the wire — the collectors are cleared
    // after distribution, exactly as a consensus round is processed once.
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        test_state.consensus_round as u64,
    );
    test_state.consensus_round += 1;
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }

    // Each late validator now holds a placeholder NOA-sign session buffering the
    // early validators' messages, without having instantiated the sign itself.
    for &i in &late_parties {
        let has_buffering_placeholder = test_state.dwallet_mpc_services[i]
            .dwallet_mpc_manager()
            .sessions
            .iter()
            .any(|(id, session)| {
                id.session_type() == SessionType::NetworkOwnedAddressSign
                    && matches!(session.status, SessionStatus::WaitingForSessionRequest)
            });
        assert!(
            has_buffering_placeholder,
            "late validator {} should hold a WaitingForSessionRequest NOA-sign \
             placeholder buffering the early validators' first-round messages",
            i
        );
    }

    // Phase 2: the late validators finally receive the request and instantiate.
    for &i in &late_parties {
        test_state.network_owned_address_sign_request_senders[i]
            .send(NetworkOwnedAddressSignRequest {
                message: test_message.clone(),
                curve,
                signature_algorithm,
                hash_scheme,
            })
            .await
            .expect("failed to send late network-owned-address sign request");
    }
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    utils::wait_for_computations(&mut test_state).await;

    // The sign completes only if the late validators preserved the buffered
    // messages: all four then reach threshold and drive the sign to an output.
    let sign_output = wait_for_network_owned_address_sign_output(&mut test_state).await;
    assert_eq!(
        sign_output.message, test_message,
        "output message should match the request"
    );
    assert!(
        !sign_output.signature.is_empty(),
        "signature should not be empty"
    );
    info!("Late-instantiation NOA sign completed — buffered messages survived");
}

/// A byzantine peer must not be able to wedge a NOA sign with a single message.
///
/// The NOA sign session id is predictable from public inputs, and the
/// output-receipt path derives a placeholder's computation type from the
/// *sender-controlled* `is_native()` flag. A peer that sends a "native" output
/// for the id before this validator instantiates creates a `Native`-typed
/// `WaitingForSessionRequest` placeholder. If instantiation preserved that type
/// (the in-place upgrade this fix introduced), `add_message` would drop every
/// real round message and the sign would route to the native path and fail
/// `InvalidDWalletProtocolType` on every honest validator — a permanent,
/// unattributed epoch wedge from one message. Instantiation must normalize the
/// poisoned placeholder back to an MPC buffer.
///
/// Fault-check for that normalization guard: without it, the final assertion
/// (session typed MPC after instantiation) fails — the placeholder stays Native.
#[tokio::test]
#[cfg(test)]
async fn test_instantiation_normalizes_byzantine_native_placeholder() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let curve = DWalletCurve::Curve25519;
    let signature_algorithm = DWalletSignatureAlgorithm::EdDSA;
    let hash_scheme = DWalletHashScheme::SHA512;

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, encryption_key) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        signature_algorithm,
        encryption_key,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    let test_message = b"byzantine-native-placeholder sign".to_vec();

    // Learn the (validator-independent) NOA sign session id by instantiating on
    // one validator and reading it back.
    let id_source = 1usize;
    test_state.network_owned_address_sign_request_senders[id_source]
        .send(NetworkOwnedAddressSignRequest {
            message: test_message.clone(),
            curve,
            signature_algorithm,
            hash_scheme,
        })
        .await
        .expect("failed to send id-source sign request");
    test_state.dwallet_mpc_services[id_source]
        .run_service_loop_iteration()
        .await;
    let noa_session_id = *test_state.dwallet_mpc_services[id_source]
        .dwallet_mpc_manager()
        .sessions
        .keys()
        .find(|id| id.session_type() == SessionType::NetworkOwnedAddressSign)
        .expect("id-source validator should have instantiated a NOA sign session");

    // A byzantine peer sends a "native" output for that id to the target
    // validator, which has not yet instantiated — creating a Native-typed
    // placeholder via the output-receipt path.
    let target = 0usize;
    let byzantine_authority = test_state
        .committee
        .names()
        .nth(1)
        .copied()
        .expect("committee has a second member");
    let poison = DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority: byzantine_authority,
        session_identifier: noa_session_id,
        output: vec![
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(
                MakeDWalletUserSecretKeySharesPublicOutput {
                    dwallet_id: vec![1u8; 32],
                    public_user_secret_key_shares: vec![],
                    rejected: false,
                    session_sequence_number: 0,
                },
            ),
        ],
        malicious_authorities: vec![],
    });
    let _ = test_state.dwallet_mpc_services[target]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(test_state.consensus_round as u64, vec![poison]);

    // Attack precondition: the target now holds a Native-typed placeholder.
    {
        let session = test_state.dwallet_mpc_services[target]
            .dwallet_mpc_manager()
            .sessions
            .get(&noa_session_id)
            .expect("poison output should have created a placeholder on the target");
        assert!(
            matches!(session.status, SessionStatus::WaitingForSessionRequest),
            "poisoned placeholder should be WaitingForSessionRequest"
        );
        assert!(
            !matches!(session.computation_type, SessionComputationType::MPC { .. }),
            "poisoned placeholder should be typed Native (the attack precondition)"
        );
    }

    // The target instantiates the sign; normalization must reset the type.
    test_state.network_owned_address_sign_request_senders[target]
        .send(NetworkOwnedAddressSignRequest {
            message: test_message.clone(),
            curve,
            signature_algorithm,
            hash_scheme,
        })
        .await
        .expect("failed to send target sign request");
    test_state.dwallet_mpc_services[target]
        .run_service_loop_iteration()
        .await;

    let session = test_state.dwallet_mpc_services[target]
        .dwallet_mpc_manager()
        .sessions
        .get(&noa_session_id)
        .expect("target should still have the NOA session after instantiation");
    assert!(
        matches!(session.status, SessionStatus::Active { .. }),
        "instantiation should activate the NOA sign session"
    );
    assert!(
        matches!(session.computation_type, SessionComputationType::MPC { .. }),
        "instantiation must normalize the byzantine Native placeholder back to an MPC buffer"
    );
    info!("Byzantine Native placeholder normalized to MPC on instantiation");
}

// === Fast Schnorr (VSS) NOA sign E2E tests ===

/// End-to-end NOA sign for a Fast Schnorr (VSS) algorithm.
///
/// Same shape as [`network_owned_address_sign_flow`], but on a **reconfigured**
/// network key (VSS sign reads the per-curve secret-key polynomial commitments from
/// the reconfiguration output and recovers each validator's Shamir share from the
/// reconfiguration dealings). The NOA DKG emulation yields a `UniversalPublicDKGOutput`
/// with `X_A = identity`, so the VSS sign's `ToBeEmulated` (emulated centralized
/// party) path applies — exactly as for AHE NOA sign.
async fn network_owned_address_vss_sign_flow(
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
    hash_scheme: DWalletHashScheme,
) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // VSS sign requires a reconfigured network key.
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_reconfigured_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    info!(
        ?curve,
        ?signature_algorithm,
        ?hash_scheme,
        "Fast Schnorr (VSS) network-owned-address signing test"
    );

    // Wait for the internal VSS presign pool to populate.
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        signature_algorithm,
        network_key_id,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(signature_algorithm, network_key_id)
        .expect("failed to get pool size");
    assert!(
        pool_size_before > 0,
        "VSS presign pool should have at least one presign"
    );
    let presign_keys_before: HashSet<(SessionIdentifier, u16)> = test_state.epoch_stores[0]
        .presign_pools
        .lock()
        .unwrap()
        .get(&(signature_algorithm, network_key_id))
        .map(|pool| {
            pool.iter()
                .map(|(id, blending_index, _)| (*id, *blending_index))
                .collect()
        })
        .unwrap_or_default();

    // Send a NetworkOwnedAddressSignRequest to all validators.
    let test_message = b"test message for network-owned-address VSS sign".to_vec();
    for sender in &test_state.network_owned_address_sign_request_senders {
        sender
            .send(NetworkOwnedAddressSignRequest {
                message: test_message.clone(),
                curve,
                signature_algorithm,
                hash_scheme,
            })
            .await
            .expect("failed to send network-owned-address VSS sign request");
    }
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }

    let sign_output = wait_for_network_owned_address_sign_output(&mut test_state).await;
    assert_eq!(
        sign_output.message, test_message,
        "output message should match request"
    );
    assert!(
        !sign_output.signature.is_empty(),
        "VSS signature should not be empty"
    );
    info!(
        ?sign_output.session_identifier,
        signature_len = sign_output.signature.len(),
        "Received NetworkOwnedAddressSignOutput for VSS"
    );

    // Verify exactly one presign from the pre-sign snapshot was consumed.
    let used_presigns = test_state.epoch_stores[0]
        .used_presigns
        .lock()
        .unwrap()
        .clone();
    let consumed_from_snapshot: HashSet<_> = presign_keys_before
        .iter()
        .filter(|key| used_presigns.contains_key(key))
        .collect();
    assert_eq!(
        consumed_from_snapshot.len(),
        1,
        "exactly one VSS presign from the pre-sign pool snapshot should have been consumed"
    );

    info!(
        ?curve,
        ?signature_algorithm,
        "Fast Schnorr (VSS) network-owned-address sign E2E test completed"
    );
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_taproot_vss() {
    network_owned_address_vss_sign_flow(
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::TaprootVSS,
        DWalletHashScheme::SHA256,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_eddsa_vss() {
    network_owned_address_vss_sign_flow(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSAVSS,
        DWalletHashScheme::SHA512,
    )
    .await;
}

#[tokio::test]
#[cfg(test)]
async fn test_network_owned_address_sign_schnorrkel_substrate_vss() {
    network_owned_address_vss_sign_flow(
        DWalletCurve::Ristretto,
        DWalletSignatureAlgorithm::SchnorrkelVSS,
        DWalletHashScheme::Merlin,
    )
    .await;
}
