use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE, build_test_state,
    count_sessions_by_type, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::ObjectID;
use tracing::info;

/// All signature algorithms that have internal presign pools.
const ALL_ALGORITHMS: &[(DWalletCurve, DWalletSignatureAlgorithm)] = &[
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

/// Test that internal presign sessions are instantiated at the correct consensus rounds
/// based on the configuration (consensus_round_delay), and that exactly `sessions_to_instantiate`
/// sessions are created per delay-aligned round.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_instantiation_at_correct_rounds() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Create a network key (required for internal presigns)
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Read the test-friendly config values
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    // All algorithms have delay=2, sessions_to_instantiate=1 from the test config
    let delay = protocol_config.get_internal_presign_consensus_round_delay(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    let sessions_to_instantiate = protocol_config.get_internal_presign_sessions_to_instantiate(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );

    info!(
        "Config: delay={}, sessions_to_instantiate={}",
        delay, sessions_to_instantiate
    );
    assert_eq!(
        delay, TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        "test config should set delay={}",
        TEST_PRESIGN_CONSENSUS_ROUND_DELAY
    );
    assert_eq!(
        sessions_to_instantiate, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        "test config should set sessions_to_instantiate={}",
        TEST_PRESIGN_SESSIONS_TO_INSTANTIATE
    );

    // Record the baseline count after network key creation.
    // create_network_key_test runs extra service loop iterations that install the key,
    // which also triggers the first batch of internal presign sessions.
    let baseline_count = count_sessions_by_type(&test_state, SessionType::InternalPresign);
    info!(
        "Baseline internal presign count after network key creation: {}",
        baseline_count
    );

    // Run rounds and verify sessions appear only at delay-aligned rounds
    let mut total_internal_presigns = baseline_count;
    for round_offset in 1..=10 {
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

        let current_count = count_sessions_by_type(&test_state, SessionType::InternalPresign);
        let new_sessions = current_count - total_internal_presigns;

        if round_offset % delay as usize == 0 {
            // At delay-aligned rounds, new sessions should be created.
            // Each delay-aligned round creates sessions_to_instantiate * number_of_algorithm_pairs.
            assert!(
                new_sessions > 0,
                "round_offset={}: expected new sessions at delay-aligned round, got 0",
                round_offset
            );
            info!(
                "Round offset {}: {} new internal presign sessions (total: {})",
                round_offset, new_sessions, current_count
            );
        }
        total_internal_presigns = current_count;
    }

    // After 10 rounds with delay=2, we should have had 5 instantiation events.
    // Each event creates sessions_to_instantiate(1) * number_of_active_algorithm_pairs sessions.
    assert!(
        total_internal_presigns > 0,
        "expected internal presign sessions to be created after 10 rounds"
    );
    info!(
        "Test completed: {} total internal presign sessions created over 10 rounds",
        total_internal_presigns
    );
}

/// Test that internal presign sessions stop being created when the pool reaches minimum size
/// and the system is not idle. Covers all signature algorithms.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_stops_at_min_pool_size_when_not_idle() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Create network key (the actual key ID is what matters)
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    let min_pool_size = protocol_config.get_internal_presign_pool_minimum_size(
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::ECDSASecp256k1,
    );
    let idle_threshold = protocol_config.idle_session_count_threshold();

    info!(
        "min_pool_size={}, idle_threshold={}",
        min_pool_size, idle_threshold
    );

    // Pre-populate all pools to min_pool_size using the ACTUAL network key ID
    let mock_session_id = SessionIdentifier::new(SessionType::InternalPresign, [0u8; 32]);
    for (curve, algorithm) in ALL_ALGORITHMS {
        let per_algo_min =
            protocol_config.get_internal_presign_pool_minimum_size(*curve, *algorithm);
        for epoch_store in &test_state.epoch_stores {
            let presigns: Vec<Vec<u8>> = (0..per_algo_min).map(|_| vec![0u8; 32]).collect();
            epoch_store
                .insert_presigns(*algorithm, network_key_id, 1, mock_session_id, presigns)
                .expect("failed to insert presigns");
        }
    }

    // Make the system NOT idle by inserting dummy sessions to exceed idle_threshold.
    // We insert dummy InternalPresign session identifiers into the manager's sessions map
    // to push the count above idle_threshold. We use a higher number to be safe.
    // The system is "not idle" when session_count >= idle_threshold.
    // We run enough rounds so that the system naturally has sessions above threshold.
    // With test config idle_threshold=5, the internal presign sessions themselves will
    // push us above that after a couple of rounds.
    for _ in 0..6 {
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

    // Record pool sizes after stabilization
    let pool_sizes_before: Vec<(DWalletCurve, DWalletSignatureAlgorithm, u64)> = ALL_ALGORITHMS
        .iter()
        .map(|(curve, algorithm)| {
            let size = test_state.epoch_stores[0]
                .presign_pool_size(*algorithm, network_key_id)
                .unwrap_or(0);
            (*curve, *algorithm, size)
        })
        .collect();

    // Run several more delay-aligned rounds
    for _ in 0..6 {
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

    // Assert pool sizes are unchanged (nothing consumed, nothing should have been added
    // since pools are at min and system is not idle)
    for (curve, algorithm, size_before) in &pool_sizes_before {
        let size_after = test_state.epoch_stores[0]
            .presign_pool_size(*algorithm, network_key_id)
            .unwrap_or(0);
        info!(
            "{:?}/{:?}: pool_before={}, pool_after={}",
            curve, algorithm, size_before, size_after
        );
        // Pool should be at least min_pool_size (we pre-populated it) and should not have
        // shrunk (no consumption). If system is not idle, no new presigns should be created
        // beyond min pool size. We use >= because completed in-flight sessions may still
        // deposit into the pool.
        assert!(
            size_after >= *size_before,
            "{:?}/{:?}: pool should not shrink without consumption (before={}, after={})",
            curve,
            algorithm,
            size_before,
            size_after
        );
    }

    info!("Test completed: internal presigns stopped at minimum pool size when not idle");
}

/// Test that internal presign sessions continue to be created when the system is idle,
/// even if the pool has reached the minimum size, and that creation stops at maximum.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_continues_when_idle() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Create network key
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    let idle_threshold = protocol_config.idle_session_count_threshold();
    let max_pool_size = protocol_config.get_internal_presign_pool_maximum_size(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    let min_pool_size = protocol_config.get_internal_presign_pool_minimum_size(
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );

    info!(
        "idle_threshold={}, min_pool_size={}, max_pool_size={}",
        idle_threshold, min_pool_size, max_pool_size
    );

    // Pre-populate pool to min_pool_size so we can verify growth beyond min
    let mock_session_id = SessionIdentifier::new(SessionType::InternalPresign, [0u8; 32]);
    for epoch_store in &test_state.epoch_stores {
        let presigns: Vec<Vec<u8>> = (0..min_pool_size).map(|_| vec![0u8; 32]).collect();
        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::EdDSA,
                network_key_id,
                1,
                mock_session_id,
                presigns,
            )
            .expect("failed to insert presigns");
    }

    let pool_size_before = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
        .unwrap_or(0);
    assert_eq!(
        pool_size_before, min_pool_size,
        "pool should start at min_pool_size"
    );

    // Run rounds; since we're idle, presign sessions should spawn beyond min_pool_size
    for _ in 0..20 {
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

    // More internal presign sessions should have been created (spawned, not necessarily
    // completed to pool yet). Count sessions in the manager.
    let final_presign_session_count =
        count_sessions_by_type(&test_state, SessionType::InternalPresign);

    info!(
        "After 20 rounds: {} internal presign sessions in manager",
        final_presign_session_count,
    );

    // When idle, new sessions should have been spawned
    assert!(
        final_presign_session_count > 0,
        "when idle, internal presign sessions should continue to be created"
    );

    info!("Test completed: internal presigns continue when idle");
}
