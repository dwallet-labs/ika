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
    IntegrationTestState, build_test_state, create_test_protocol_config_guard_with_noa_checkpoints,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm,
};
use ika_types::message::{DWalletCheckpointMessageKind, MakeDWalletUserSecretKeySharesPublicOutput};
use ika_types::noa_checkpoint::{NOACheckpointKindName, NOACheckpointTxRef, NOAPresignDemandId};
use ika_types::messages_dwallet_mpc::{ConsensusNOAPresignDemand,
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
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

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
                demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                    ika_types::crypto::keccak256_digest(&test_message),
                ),
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
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

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
                    demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                        ika_types::crypto::keccak256_digest(&message),
                    ),
                })
                .await
                .expect("failed to send sign request");
        }
    }

    // One iteration drains the channel into the pending buffer. Under the
    // consensus-ordered flow a request instantiates only after its demand is
    // agreed and assigned a presign (several rounds), so after a single
    // iteration none have instantiated — every request is buffered, none is
    // dropped.
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
    }
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let pending = service.pending_network_owned_address_sign_request_count();
        info!(validator = i, pending, "pending sign requests after drain");
        assert_eq!(
            pending, total_requests,
            "validator {} should have buffered all {} requests before any presign is assigned, got {}",
            i, total_requests, pending,
        );
    }

    // The internal pool holds only `pool_size_before` presigns, so at most that
    // many demands can be assigned before the pool must refill via background
    // presign sessions. Pump rounds until every buffered request has been
    // processed (pending drains to zero): the excess (beyond `pool_size_before`)
    // could only be served AFTER the pool topped up, which proves they were
    // buffered rather than dropped.
    let mut pending_drained = false;
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
        if round < 10 || round % 50 == 0 || pending == 0 {
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

        if pending == 0 {
            info!(
                round,
                "all buffered requests processed — presign pool refilled and excess served"
            );
            pending_drained = true;
            break;
        }
    }

    assert!(
        pending_drained,
        "all buffered sign requests should be processed after presign pool refill"
    );

    // Every request consumed a presign; the count exceeds the initial pool, so
    // the excess were served only after the pool topped up — the deterministic
    // proof that exhaustion buffered them rather than dropping them.
    let consumed = test_state.epoch_stores[0]
        .used_presigns
        .lock()
        .unwrap()
        .len();
    assert!(
        consumed >= total_requests,
        "all {} requests should have consumed a presign (consumed {}, initial pool {}), \
         proving the pool refilled to serve the excess",
        total_requests,
        consumed,
        pool_size_before
    );

    info!(
        "Test passed: presign pool exhaustion correctly buffers and later processes excess requests"
    );
}

/// Drives consensus rounds until `NetworkOwnedAddressSignOutput`s for BOTH
/// `first_message` and `second_message` have appeared on validator 0's output
/// channel (each with a non-empty signature), collecting outputs by message.
/// Panics after `MAX_SIGN_WAIT_ROUNDS` if either is still missing — which is the
/// fault signature when validators pair mismatched presigns (the threshold sign
/// then fails at share combination and never yields an output).
async fn collect_two_noa_sign_outputs(
    test_state: &mut IntegrationTestState,
    first_message: &[u8],
    second_message: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    const MAX_SIGN_WAIT_ROUNDS: usize = 300;
    let mut signatures: std::collections::HashMap<Vec<u8>, Vec<u8>> =
        std::collections::HashMap::new();
    let mut rounds = 0usize;
    while rounds < MAX_SIGN_WAIT_ROUNDS
        && !(signatures.contains_key(first_message) && signatures.contains_key(second_message))
    {
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
        while let Ok(output) = test_state.network_owned_address_sign_output_receivers[0].try_recv()
        {
            signatures.insert(output.message.clone(), output.signature.clone());
        }
        rounds += 1;
    }
    let first = signatures.get(first_message).cloned().unwrap_or_else(|| {
        panic!(
            "no NetworkOwnedAddressSignOutput for the first message after {MAX_SIGN_WAIT_ROUNDS} \
             consensus rounds — validators paired mismatched presigns"
        )
    });
    let second = signatures.get(second_message).cloned().unwrap_or_else(|| {
        panic!(
            "no NetworkOwnedAddressSignOutput for the second message after {MAX_SIGN_WAIT_ROUNDS} \
             consensus rounds — validators paired mismatched presigns"
        )
    });
    (first, second)
}

/// Presign assignment for NOA signs is ordered by CONSENSUS, not by each
/// validator's local receive order.
///
/// Reproduces the cross-validator divergence a local-order assignment causes:
/// four validators receive the SAME two sign demands (M1, M2) but in DIFFERENT
/// local order — validators 0,1 receive [M1, M2]; validators 2,3 receive
/// [M2, M1]. A validator that popped its presign pool in local instantiation
/// order would pair M1 with the pool's first presign on validators 0,1 but with
/// the SECOND on validators 2,3 (and vice-versa for M2). The four validators
/// would then run each threshold sign over two different presigns, and the sign
/// fails at share combination — no output, epoch wedged.
///
/// The fix announces every demand through consensus and assigns presigns in
/// consensus-delivery order (identical on every validator), so both signs pair
/// the same presign with the same message everywhere and complete. This test
/// passes ONLY because of that: reverting
/// `instantiate_network_owned_address_sign_session` to pop the pool locally
/// makes the divergent local order strand both signs and this test times out.
#[tokio::test]
#[cfg(test)]
async fn test_presign_assignment_is_consensus_ordered_not_local() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

    let curve = DWalletCurve::Curve25519;
    let signature_algorithm = DWalletSignatureAlgorithm::EdDSA;
    let hash_scheme = DWalletHashScheme::SHA512;

    let mut test_state = build_test_state(4);

    // Create a network key and fill the EdDSA presign pool.
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

    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(signature_algorithm, encryption_key)
        .expect("failed to get pool size");
    assert!(
        pool_size_before >= 2,
        "test needs at least two presigns to assign to two demands (pool size {pool_size_before})"
    );

    // The two demands, sent to every validator but in DIVERGENT local order.
    let message_one = b"consensus-order-assignment-demand-one".to_vec();
    let message_two = b"consensus-order-assignment-demand-two".to_vec();

    // Validators 0,1 receive [M1, M2]; validators 2,3 receive [M2, M1].
    let local_orders: [[&Vec<u8>; 2]; 4] = [
        [&message_one, &message_two],
        [&message_one, &message_two],
        [&message_two, &message_one],
        [&message_two, &message_one],
    ];
    for (validator_index, order) in local_orders.iter().enumerate() {
        for message in order {
            test_state.network_owned_address_sign_request_senders[validator_index]
                .send(NetworkOwnedAddressSignRequest {
                    message: (*message).clone(),
                    curve,
                    signature_algorithm,
                    hash_scheme,
                    demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                        ika_types::crypto::keccak256_digest(message),
                    ),
                })
                .await
                .expect("failed to send network-owned-address sign request");
        }
    }

    // Drive announce → consensus delivery → consensus-order drain → instantiate
    // → sign, collecting both outputs.
    let (signature_one, signature_two) =
        collect_two_noa_sign_outputs(&mut test_state, &message_one, &message_two).await;

    // Both signs completed with non-empty signatures. This only happens if every
    // validator paired the SAME presign with the SAME message — i.e. the
    // consensus-ordered assignment defeated the divergent local receive order.
    assert!(
        !signature_one.is_empty(),
        "first message's signature should not be empty"
    );
    assert!(
        !signature_two.is_empty(),
        "second message's signature should not be empty"
    );

    // Direct proof of cross-validator agreement: the presign assigned to each
    // demand is IDENTICAL on validators that received the demands in OPPOSITE
    // local order (0 saw [M1,M2]; 2 saw [M2,M1]).
    let digest_one = ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
        ika_types::crypto::keccak256_digest(&message_one),
    )
    .digest();
    let digest_two = ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
        ika_types::crypto::keccak256_digest(&message_two),
    )
    .digest();

    let assigned_one_v0 = test_state.epoch_stores[0]
        .noa_assigned_presign(&digest_one)
        .expect("read assignment")
        .expect("M1 should have been assigned a presign on validator 0");
    let assigned_one_v2 = test_state.epoch_stores[2]
        .noa_assigned_presign(&digest_one)
        .expect("read assignment")
        .expect("M1 should have been assigned a presign on validator 2");
    let assigned_two_v0 = test_state.epoch_stores[0]
        .noa_assigned_presign(&digest_two)
        .expect("read assignment")
        .expect("M2 should have been assigned a presign on validator 0");
    let assigned_two_v2 = test_state.epoch_stores[2]
        .noa_assigned_presign(&digest_two)
        .expect("read assignment")
        .expect("M2 should have been assigned a presign on validator 2");

    // (session_id, blending_index) must match across validators for each demand.
    assert_eq!(
        (assigned_one_v0.0, assigned_one_v0.1),
        (assigned_one_v2.0, assigned_one_v2.1),
        "M1's assigned presign must be identical on validators 0 and 2 despite opposite local order"
    );
    assert_eq!(
        (assigned_two_v0.0, assigned_two_v0.1),
        (assigned_two_v2.0, assigned_two_v2.1),
        "M2's assigned presign must be identical on validators 0 and 2 despite opposite local order"
    );
    // And the two demands got DIFFERENT presigns (no double-assignment).
    assert_ne!(
        (assigned_one_v0.0, assigned_one_v0.1),
        (assigned_two_v0.0, assigned_two_v0.1),
        "M1 and M2 must be assigned distinct presigns"
    );

    info!("consensus-ordered presign assignment defeated divergent local order");
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
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

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
                demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                    ika_types::crypto::keccak256_digest(&test_message),
                ),
            })
            .await
            .expect("failed to send early network-owned-address sign request");
    }

    // NOA sign instantiation is gated on a consensus-ordered presign
    // assignment: the early validators must announce a presign demand, have it
    // agreed through consensus, drain-assign a presign, and only THEN
    // instantiate the sign and emit their first-round messages. That is several
    // consensus rounds, so pump rounds until every late validator has buffered
    // those first-round messages in a `WaitingForSessionRequest` placeholder —
    // the late validators have no request of their own yet, so they never
    // instantiate; they only receive the early validators' messages (each
    // distributed exactly once, collectors cleared after each round, as a
    // consensus round is processed once) and buffer them. This is what the
    // message-loss fix must preserve across the late validators' own later
    // instantiation.
    const MAX_BUFFERING_WAIT_ROUNDS: usize = 40;
    let mut buffering_rounds = 0usize;
    loop {
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }
        utils::wait_for_computations(&mut test_state).await;
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        let all_late_buffering = late_parties.iter().all(|&i| {
            test_state.dwallet_mpc_services[i]
                .dwallet_mpc_manager()
                .sessions
                .iter()
                .any(|(id, session)| {
                    id.session_type() == SessionType::NetworkOwnedAddressSign
                        && matches!(session.status, SessionStatus::WaitingForSessionRequest)
                })
        });
        if all_late_buffering {
            break;
        }
        buffering_rounds += 1;
        assert!(
            buffering_rounds < MAX_BUFFERING_WAIT_ROUNDS,
            "late validators never formed a buffering NOA-sign placeholder within {} \
             rounds (the early validators' first-round messages never reached them)",
            MAX_BUFFERING_WAIT_ROUNDS
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
                demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                    ika_types::crypto::keccak256_digest(&test_message),
                ),
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
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

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
            demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                ika_types::crypto::keccak256_digest(&test_message),
            ),
        })
        .await
        .expect("failed to send id-source sign request");
    // NOA sign instantiation is gated on a consensus-ordered presign
    // assignment (announce -> consensus -> drain -> assign), so id_source needs
    // several rounds to instantiate. Pump until it holds a NOA sign session,
    // then read the (validator-independent) session id. Break BEFORE the round's
    // message distribution, so id_source's first-round messages never reach the
    // target — the target must be clean when the byzantine "native" output
    // arrives, or a stray real message would pre-create an MPC placeholder and
    // defeat the Native-placeholder precondition below. (The demand itself was
    // distributed in prior rounds, so every validator — including the target —
    // has already drained-and-assigned the presign and can instantiate promptly
    // once it receives its own request.)
    const MAX_INSTANTIATE_WAIT_ROUNDS: usize = 40;
    let mut instantiate_rounds = 0usize;
    let noa_session_id = loop {
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }
        utils::wait_for_computations(&mut test_state).await;
        if let Some(id) = test_state.dwallet_mpc_services[id_source]
            .dwallet_mpc_manager()
            .sessions
            .keys()
            .find(|id| id.session_type() == SessionType::NetworkOwnedAddressSign)
            .copied()
        {
            break id;
        }
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;
        instantiate_rounds += 1;
        assert!(
            instantiate_rounds < MAX_INSTANTIATE_WAIT_ROUNDS,
            "id-source validator never instantiated a NOA sign session within {} rounds",
            MAX_INSTANTIATE_WAIT_ROUNDS
        );
    };

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
            demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                ika_types::crypto::keccak256_digest(&test_message),
            ),
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
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

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
                demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                    ika_types::crypto::keccak256_digest(&test_message),
                ),
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

/// A presign demand's signature algorithm is DERIVED from its identity, not
/// taken from the announcement — so a byzantine announcer cannot choose which
/// presign pool a demand draws from.
///
/// The consensus dedup key for a presign-demand announcement is the demand-id
/// digest alone, so the first announcement sequenced for a demand supplies the
/// payload fields for the whole network and the honest duplicates are dropped.
/// A checkpoint demand id names its checkpoint kind, and the kind determines
/// the algorithm, so the drain re-derives it and the announced value carries no
/// authority.
///
/// Both pools are seeded with distinguishable bytes, so this asserts POSITIVELY
/// which one was drawn from rather than inferring it from an empty pool: the
/// assigned presign must be the derived pool's, while the announced pool is
/// left untouched and full.
#[tokio::test]
#[cfg(test)]
async fn test_noa_presign_demand_derives_its_algorithm_over_the_announced_one() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard_with_noa_checkpoints();

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // A checkpoint demand names its kind, and the kind fixes the algorithm.
    let demand_id = NOAPresignDemandId::Checkpoint {
        tx_ref: NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
            sequence_number: 1,
            tx_index: 0,
            epoch: 1,
        },
        retry_round: 0,
    };
    let derived_algorithm = demand_id
        .expected_signature_algorithm()
        .expect("a checkpoint demand determines its own algorithm");
    // Any algorithm the identity does NOT imply serves as the announced lie.
    let announced_algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
    assert_ne!(
        derived_algorithm, announced_algorithm,
        "the test needs the announced algorithm to differ from the derived one"
    );

    // Seed both pools with recognizable, distinct bytes.
    const DERIVED_POOL_MARKER: u8 = 0xD1;
    const ANNOUNCED_POOL_MARKER: u8 = 0xA9;
    let target = 0usize;
    for (algorithm, marker) in [
        (derived_algorithm, DERIVED_POOL_MARKER),
        (announced_algorithm, ANNOUNCED_POOL_MARKER),
    ] {
        test_state.epoch_stores[target]
            .insert_presigns(
                algorithm,
                network_key_id,
                0,
                SessionIdentifier::new(SessionType::InternalPresign, [marker; 32]),
                vec![vec![marker; 16]],
            )
            .expect("seed presign pool");
    }

    // A committee member announces the demand with the WRONG algorithm.
    let byzantine_authority = test_state
        .committee
        .names()
        .nth(1)
        .copied()
        .expect("committee has a second member");
    // Every round gets a row on every validator, so the per-round streams have
    // no gaps to skip; create this round's rows the way the harness does, then
    // plant the demand in the target's row for it.
    let round = test_state.consensus_round as u64;
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round,
    );
    test_state.epoch_stores[target]
        .round_to_noa_presign_demands
        .lock()
        .unwrap()
        .entry(round)
        .or_default()
        .push(ConsensusNOAPresignDemand {
            authority: byzantine_authority,
            demand_id: demand_id.clone(),
            signature_algorithm: announced_algorithm,
            network_encryption_key_id: network_key_id,
        });
    test_state.consensus_round += 1;

    // Drain it: the service walks rounds in order, so keep rounds flowing
    // until it reaches the planted one and assigns.
    const MAX_DRAIN_ROUNDS: usize = 20;
    let digest = demand_id.digest();
    let mut drain_rounds = 0usize;
    loop {
        test_state.dwallet_mpc_services[target]
            .run_service_loop_iteration()
            .await;
        if test_state.epoch_stores[target]
            .has_noa_assigned_presign(&digest)
            .expect("read assignment")
        {
            break;
        }
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;
        drain_rounds += 1;
        assert!(
            drain_rounds < MAX_DRAIN_ROUNDS,
            "the demand was never assigned a presign within {MAX_DRAIN_ROUNDS} rounds"
        );
    }

    let (_session_identifier, _blending_index, presign_bytes, assigned_key_id) = test_state
        .epoch_stores[target]
        .noa_assigned_presign(&digest)
        .expect("read assignment")
        .expect("assignment exists");

    assert_eq!(
        presign_bytes,
        vec![DERIVED_POOL_MARKER; 16],
        "the drain must draw from the pool its demand identity implies, not the announced one"
    );
    assert_eq!(
        assigned_key_id, network_key_id,
        "the announced network key is still authoritative — it is not derivable"
    );
    // The pool the announcement pointed at must be untouched.
    assert_eq!(
        test_state.epoch_stores[target]
            .presign_pool_size(announced_algorithm, network_key_id)
            .expect("pool size"),
        1,
        "nothing should have been drawn from the announced algorithm's pool"
    );

    info!(
        ?derived_algorithm,
        ?announced_algorithm,
        "a mismatched presign-demand announcement drew from the derived pool"
    );
}
