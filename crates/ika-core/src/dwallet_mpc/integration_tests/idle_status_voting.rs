use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_IDLE_SESSION_COUNT_THRESHOLD, build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use ika_protocol_config::ProtocolConfig;
use tracing::info;

/// Creates a protocol config override guard tuned for the idle-status lifecycle test.
///
/// Key differences from the standard test config:
/// - Pool minimum sizes = 1 (pools fill after a single completed session per algorithm).
/// - Consensus round delay = 20 (large gap between instantiation checks, giving
///   sessions time to complete and idle status time to propagate through consensus).
/// - All sessions_to_instantiate = 1 (uniform across algorithms).
///
/// This creates a clear idle window: after the first batch of presign sessions
/// completes and pools reach minimum, no new sessions are created until the next
/// delay-aligned round. During that gap, session count drops to 0, validators
/// report idle, and `network_is_idle()` flips to `true` via consensus majority.
#[cfg(test)]
fn create_idle_status_test_config_guard() -> ika_protocol_config::OverrideGuard {
    let pool_minimum = 1u64;
    let pool_maximum = 12u64;
    let delay = 20u64;
    let sessions_to_instantiate = 1u64;

    ProtocolConfig::apply_overrides_for_testing(move |_version, mut config| {
        config.set_idle_session_count_threshold_for_testing(TEST_IDLE_SESSION_COUNT_THRESHOLD);

        config.set_internal_secp256k1_ecdsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_secp256k1_ecdsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_secp256k1_ecdsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_secp256k1_ecdsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_secp256r1_ecdsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_secp256r1_ecdsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_secp256r1_ecdsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_secp256r1_ecdsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_eddsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_eddsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_eddsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_eddsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
            .set_internal_schnorrkel_substrate_presign_pool_minimum_size_for_testing(pool_minimum);
        config
            .set_internal_schnorrkel_substrate_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_schnorrkel_substrate_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_taproot_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_taproot_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_taproot_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_taproot_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_network_owned_address_ecdsa_secp256k1_presign_pool_minimum_size_for_testing(
            pool_minimum,
        );
        config.set_network_owned_address_ecdsa_secp256k1_presign_pool_maximum_size_for_testing(
            pool_maximum,
        );
        config.set_network_owned_address_ecdsa_secp256k1_presign_consensus_round_delay_for_testing(
            delay,
        );
        config
            .set_network_owned_address_ecdsa_secp256k1_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config.set_network_owned_address_ecdsa_secp256r1_presign_pool_minimum_size_for_testing(
            pool_minimum,
        );
        config.set_network_owned_address_ecdsa_secp256r1_presign_pool_maximum_size_for_testing(
            pool_maximum,
        );
        config.set_network_owned_address_ecdsa_secp256r1_presign_consensus_round_delay_for_testing(
            delay,
        );
        config
            .set_network_owned_address_ecdsa_secp256r1_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config.set_network_owned_address_eddsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_network_owned_address_eddsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_network_owned_address_eddsa_presign_consensus_round_delay_for_testing(delay);
        config.set_network_owned_address_eddsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
            .set_network_owned_address_schnorrkel_substrate_presign_pool_minimum_size_for_testing(
                pool_minimum,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_pool_maximum_size_for_testing(
                pool_maximum,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_consensus_round_delay_for_testing(
                delay,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config
            .set_network_owned_address_taproot_presign_pool_minimum_size_for_testing(pool_minimum);
        config
            .set_network_owned_address_taproot_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_network_owned_address_taproot_presign_consensus_round_delay_for_testing(delay);
        config.set_network_owned_address_taproot_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
    })
}

/// Test that validators correctly compute and report their idle status
/// through the consensus-agreed `network_is_idle()` path, not just the local
/// `compute_is_idle()` function.
///
/// Uses a custom config with pool minimum=1 and delay=20 to create a clear
/// idle window after the first batch of presign sessions fills the pools.
///
/// Asserts:
/// 1. `network_is_idle` starts as `false` (default).
/// 2. `network_is_idle()` undergoes at least 2 transitions through the consensus
///    path, proving a full cycle (e.g. not_idle → idle → not_idle).
/// 3. Status updates submitted to consensus carry the correct `is_idle` flag.
#[tokio::test]
#[cfg(test)]
async fn test_validators_compute_idle_status_correctly() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_idle_status_test_config_guard();

    let mut test_state = build_test_state(4);

    let idle_threshold = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config
        .idle_session_count_threshold();

    info!("Idle threshold from config: {}", idle_threshold);
    assert_eq!(
        idle_threshold, TEST_IDLE_SESSION_COUNT_THRESHOLD,
        "test config should set idle_threshold={}",
        TEST_IDLE_SESSION_COUNT_THRESHOLD
    );

    // Initially, network_is_idle starts as false (default value).
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            !service.network_is_idle(),
            "Validator {} network_is_idle should start as false (default)",
            i,
        );
    }

    // Create network key to enable internal presigns.
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Run enough rounds for the full idle lifecycle.
    //
    // With pool minimum=1, delay=20, 5 algorithm pairs (1 session each):
    //
    // The network goes through at least one full transition cycle via consensus:
    //   not_idle (sessions running) → idle (sessions complete, pools filled)
    //                                → not_idle (idle-fill creates new sessions)
    //
    // We track transitions (state changes) in network_is_idle(). Two transitions
    // prove a full cycle regardless of which state comes first.
    let mut transition_count = 0u32;
    let mut last_idle_state: Option<bool> = None;
    let mut status_updates_received = false;

    for round in 0..80 {
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

        // Give rayon threads time to finish MPC computations between rounds.
        utils::wait_for_computations(&mut test_state).await;

        // Check if idle_status_by_party is populated — confirms status updates
        // have been received and processed from consensus.
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        if !manager.idle_status_by_party.is_empty() {
            status_updates_received = true;
        }

        // Once status updates have propagated, track network_is_idle() transitions.
        if status_updates_received {
            let is_idle = test_state.dwallet_mpc_services[0].network_is_idle();
            if last_idle_state != Some(is_idle) {
                let session_count = manager.sessions.len();
                info!(
                    "network_is_idle() transitioned to {} at round {} (sessions={}, threshold={}, transition #{})",
                    is_idle,
                    test_state.consensus_round,
                    session_count,
                    idle_threshold,
                    transition_count + 1
                );
                last_idle_state = Some(is_idle);
                transition_count += 1;
            }
        }

        // Early exit once we've observed a full cycle (at least 3 transitions):
        // e.g. not_idle → idle → not_idle, proving both directions work.
        if transition_count >= 3 {
            info!(
                "Full idle lifecycle observed by round {} ({} transitions)",
                round, transition_count
            );
            break;
        }
    }

    // Verify status updates were received and processed.
    assert!(
        status_updates_received,
        "expected idle_status_by_party to be populated after consensus rounds"
    );

    // Verify we observed at least 3 transitions, proving a full cycle
    // (not_idle → idle → not_idle) through the consensus-agreed path.
    assert!(
        transition_count >= 3,
        "expected at least 3 network_is_idle() transitions (full not_idle → idle → not_idle cycle), got {}",
        transition_count
    );

    info!("Test passed: validators correctly compute idle status via consensus");
}

/// Test that status updates are properly distributed through consensus and
/// that the service reads and processes them (not just the test harness).
///
/// Verifies:
/// 1. Each validator submits IdleStatusUpdate to consensus each round.
/// 2. After distribution, each validator's epoch store has idle status updates from all others.
/// 3. The service reads these via `next_idle_status_update` and processes them.
#[tokio::test]
#[cfg(test)]
async fn test_status_updates_distributed_through_consensus() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Create network key
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Run several rounds: the service loop submits status updates to consensus,
    // send_advance_results_between_parties distributes them to epoch stores,
    // and the next service loop reads them via next_internal_sessions_status_update.
    for round in 0..10 {
        // First, run service loops to generate status updates
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }

        // Distribute results to all parties
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        if round > 3 {
            // After a few rounds, verify each epoch store has received idle status updates
            for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
                let updates = epoch_store.round_to_idle_status_updates.lock().unwrap();
                let total: usize = updates.values().map(|v| v.len()).sum();
                info!(
                    "Round {}: Validator {} has {} total idle status updates in epoch store",
                    round, i, total
                );
                assert!(
                    total > 0,
                    "Validator {} should have received idle status updates by round {}",
                    i,
                    round
                );
            }
        }
    }

    let num_validators = test_state.dwallet_mpc_services.len();

    // Final verification: the service should have processed status updates.
    // Check that idle_status_by_party in the manager is populated (the service
    // reads from epoch store and calls handle_status_updates which populates this).
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        let idle_status_count = manager.idle_status_by_party.len();
        info!(
            "Validator {}: idle_status_by_party has {} entries",
            i, idle_status_count
        );
        // After enough rounds, each validator should have received idle status from all parties.
        assert_eq!(
            idle_status_count, num_validators,
            "Validator {} should have idle status from all {} parties (got {})",
            i, num_validators, idle_status_count
        );
    }

    // Verify that each validator's idle_status_by_party entries are consistent:
    // all validators should agree on each party's idle status.
    let reference_statuses: Vec<_> = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .idle_status_by_party
        .iter()
        .map(|(party, is_idle)| (*party, *is_idle))
        .collect();
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate().skip(1) {
        let manager = service.dwallet_mpc_manager();
        for (party, expected_idle) in &reference_statuses {
            let actual_idle = manager.idle_status_by_party.get(party);
            assert_eq!(
                actual_idle,
                Some(expected_idle),
                "Validator {} disagrees with validator 0 on party {:?}'s idle status",
                i,
                party
            );
        }
    }

    info!("Test passed: status updates distributed through consensus and processed by service");
}

/// Creates a protocol config override guard for the split idle vote test.
///
/// Key settings:
/// - `idle_session_count_threshold = 1`: a single active session makes a validator
///   report `is_idle = false`, so one sign session is enough to break idle.
/// - Pool minimum = maximum = 1: pools fill to exactly 1 presign and idle-fill
///   never fires (condition `pool < max` is `1 < 1 = false`).
/// - Delay = 2: pools fill quickly after DKG.
/// - Sessions to instantiate = 1.
#[cfg(test)]
fn create_split_idle_test_config_guard() -> ika_protocol_config::OverrideGuard {
    let pool_minimum = 1u64;
    let pool_maximum = 1u64;
    let delay = 2u64;
    let sessions_to_instantiate = 1u64;
    let idle_threshold = 1u64;

    ProtocolConfig::apply_overrides_for_testing(move |_version, mut config| {
        config.set_idle_session_count_threshold_for_testing(idle_threshold);

        config.set_internal_secp256k1_ecdsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_secp256k1_ecdsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_secp256k1_ecdsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_secp256k1_ecdsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_secp256r1_ecdsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_secp256r1_ecdsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_secp256r1_ecdsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_secp256r1_ecdsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_eddsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_eddsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_eddsa_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_eddsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
            .set_internal_schnorrkel_substrate_presign_pool_minimum_size_for_testing(pool_minimum);
        config
            .set_internal_schnorrkel_substrate_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_schnorrkel_substrate_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_internal_taproot_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_taproot_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_taproot_presign_consensus_round_delay_for_testing(delay);
        config.set_internal_taproot_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config.set_network_owned_address_ecdsa_secp256k1_presign_pool_minimum_size_for_testing(
            pool_minimum,
        );
        config.set_network_owned_address_ecdsa_secp256k1_presign_pool_maximum_size_for_testing(
            pool_maximum,
        );
        config.set_network_owned_address_ecdsa_secp256k1_presign_consensus_round_delay_for_testing(
            delay,
        );
        config
            .set_network_owned_address_ecdsa_secp256k1_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config.set_network_owned_address_ecdsa_secp256r1_presign_pool_minimum_size_for_testing(
            pool_minimum,
        );
        config.set_network_owned_address_ecdsa_secp256r1_presign_pool_maximum_size_for_testing(
            pool_maximum,
        );
        config.set_network_owned_address_ecdsa_secp256r1_presign_consensus_round_delay_for_testing(
            delay,
        );
        config
            .set_network_owned_address_ecdsa_secp256r1_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config.set_network_owned_address_eddsa_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_network_owned_address_eddsa_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_network_owned_address_eddsa_presign_consensus_round_delay_for_testing(delay);
        config.set_network_owned_address_eddsa_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
            .set_network_owned_address_schnorrkel_substrate_presign_pool_minimum_size_for_testing(
                pool_minimum,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_pool_maximum_size_for_testing(
                pool_maximum,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_consensus_round_delay_for_testing(
                delay,
            );
        config
            .set_network_owned_address_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
                sessions_to_instantiate,
            );

        config
            .set_network_owned_address_taproot_presign_pool_minimum_size_for_testing(pool_minimum);
        config
            .set_network_owned_address_taproot_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_network_owned_address_taproot_presign_consensus_round_delay_for_testing(delay);
        config.set_network_owned_address_taproot_presign_sessions_to_instantiate_for_testing(
            sessions_to_instantiate,
        );

        config
    })
}

/// Test that a 2-of-4 idle status split does NOT reach consensus quorum.
///
/// With 4 validators and threshold weight requiring 3/4 agreement, a 2-2 split
/// in idle status votes produces `ThresholdNotReached`, which maps to
/// `network_is_idle = false`.
///
/// Uses a custom config with `idle_session_count_threshold = 1` so that a single
/// sign session is enough to make a validator report `is_idle = false`.
///
/// Flow:
/// 1. Create network key, fill presign pools, wait for all validators to reach idle.
/// 2. Send an EdDSA sign request to only validators 0 and 1 via their channels.
/// 3. Advance consensus rounds to propagate the divergent status updates.
/// 4. Assert `network_is_idle() == false` on all validators (2-2 split).
#[tokio::test]
#[cfg(test)]
async fn test_split_idle_status_vote_does_not_reach_consensus() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_split_idle_test_config_guard();

    let mut test_state = build_test_state(4);

    // Initially, network_is_idle starts as false (default).
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            !service.network_is_idle(),
            "Validator {} network_is_idle should start as false",
            i,
        );
    }

    // Create network key to enable internal presigns.
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Fill the EdDSA presign pool (needed for the sign request).
    let start_round = test_state.consensus_round as u64;
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        DWalletSignatureAlgorithm::EdDSA,
        network_key_id,
        start_round,
    )
    .await;
    test_state.consensus_round = consensus_round as usize;

    // Wait for all validators to reach idle via the consensus-agreed path.
    let mut idle_reached = false;
    for round in 0..200 {
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

        if test_state
            .dwallet_mpc_services
            .iter()
            .all(|s| s.network_is_idle())
        {
            info!(
                round,
                consensus_round = test_state.consensus_round,
                "All validators reached idle"
            );
            idle_reached = true;
            break;
        }
    }
    assert!(idle_reached, "all validators should reach idle");

    // Verify the EdDSA pool has a presign available on all validators.
    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
            .unwrap_or(0);
        assert!(
            pool_size >= 1,
            "Validator {} EdDSA pool should have at least 1 presign, got {}",
            i,
            pool_size,
        );
    }

    // Send one EdDSA sign request to validators 0 and 1 ONLY.
    // Validators 2 and 3 don't receive the request, so they remain idle.
    let test_message = b"split-vote-test-message".to_vec();
    for i in 0..2 {
        test_state.network_owned_address_sign_request_senders[i]
            .send(NetworkOwnedAddressSignRequest {
                message: test_message.clone(),
                curve: DWalletCurve::Curve25519,
                signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
                hash_scheme: DWalletHashScheme::SHA512,
            })
            .await
            .expect("failed to send sign request to validator");
    }

    // Advance 2 consensus rounds to:
    // 1. Process the sign request + send status updates (round 1)
    // 2. Distribute and process the divergent status updates (round 2)
    for _ in 0..2 {
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
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
    }

    // Assert: 2-2 split → ThresholdNotReached → network_is_idle = false.
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            !service.network_is_idle(),
            "Validator {} should report network_is_idle=false under 2-2 split",
            i,
        );
    }

    // Verify the split is visible in idle_status_by_party: 2 idle, 2 not-idle.
    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
    let idle_count = manager
        .idle_status_by_party
        .values()
        .filter(|&&v| v)
        .count();
    let not_idle_count = manager
        .idle_status_by_party
        .values()
        .filter(|&&v| !v)
        .count();
    info!(
        idle_count,
        not_idle_count, "idle_status_by_party distribution"
    );
    assert_eq!(
        idle_count, 2,
        "expected 2 validators reporting idle, got {}",
        idle_count
    );
    assert_eq!(
        not_idle_count, 2,
        "expected 2 validators reporting not-idle, got {}",
        not_idle_count
    );

    info!("Test passed: 2-2 split idle status vote does not reach consensus");
}
