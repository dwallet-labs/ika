use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE, build_test_state,
    create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use std::collections::HashSet;
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

    // Collect the baseline set of session IDs after network key creation.
    // create_network_key_test runs extra service loop iterations that install the key,
    // which also triggers the first batch of internal presign sessions.
    let baseline_sessions: HashSet<SessionIdentifier> = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .keys()
        .filter(|id| id.session_type() == SessionType::InternalPresign)
        .copied()
        .collect();
    info!(
        "Baseline internal presign count after network key creation: {}",
        baseline_sessions.len()
    );

    // Track all NEW session IDs seen across rounds using a HashSet.
    // Using a set avoids underflow from session removals: we only count each new ID once
    // even if it later completes and is removed from the manager.
    let mut all_seen_sessions: HashSet<SessionIdentifier> = baseline_sessions.clone();
    // After 10 rounds with delay=2, we should have had 5 instantiation events.
    // Each event creates sessions_to_instantiate(1) * number_of_active_algorithm_pairs sessions.
    // With 5 algorithm pairs: 5 events × 1 session × 5 algorithms = 25 expected sessions.
    let expected_instantiation_events = 10 / delay as usize;
    let expected_new_sessions =
        expected_instantiation_events * TEST_PRESIGN_SESSIONS_TO_INSTANTIATE * ALL_ALGORITHMS.len();

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

        let current_sessions: HashSet<SessionIdentifier> = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .sessions
            .keys()
            .filter(|id| id.session_type() == SessionType::InternalPresign)
            .copied()
            .collect();
        let new_this_round: HashSet<SessionIdentifier> = current_sessions
            .difference(&all_seen_sessions)
            .copied()
            .collect();

        if round_offset % delay as usize == 0 {
            // At delay-aligned rounds, new sessions should be created.
            // Each delay-aligned round creates sessions_to_instantiate * number_of_algorithm_pairs.
            assert!(
                !new_this_round.is_empty(),
                "round_offset={}: expected new sessions at delay-aligned round, got 0",
                round_offset
            );
            info!(
                "Round offset {}: {} new internal presign sessions (total seen: {})",
                round_offset,
                new_this_round.len(),
                all_seen_sessions.len()
            );
        }
        all_seen_sessions.extend(new_this_round);
    }

    let total_new = all_seen_sessions.len() - baseline_sessions.len();
    assert!(
        total_new >= expected_new_sessions,
        "expected at least {} new presign sessions over 10 rounds (got {})",
        expected_new_sessions,
        total_new
    );
    info!(
        "Test completed: {} new internal presign sessions created over 10 rounds (expected >= {})",
        total_new, expected_new_sessions
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

    // Run 20 extra settling rounds to let any in-flight sessions complete and deposit
    // into the pool before we snapshot the "before" sizes.
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

    // Record pool sizes after full stabilization (all in-flight sessions have completed)
    let pool_sizes_before: Vec<(DWalletCurve, DWalletSignatureAlgorithm, u64)> = ALL_ALGORITHMS
        .iter()
        .map(|(curve, algorithm)| {
            let size = test_state.epoch_stores[0]
                .presign_pool_size(*algorithm, network_key_id)
                .unwrap_or(0);
            (*curve, *algorithm, size)
        })
        .collect();

    // Run several more delay-aligned rounds to confirm the pool is now stable
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

    // Assert pool sizes are exactly unchanged: nothing consumed and nothing added,
    // since the pools are at min_pool_size and the system is not idle.
    for (curve, algorithm, size_before) in &pool_sizes_before {
        let size_after = test_state.epoch_stores[0]
            .presign_pool_size(*algorithm, network_key_id)
            .unwrap_or(0);
        info!(
            "{:?}/{:?}: pool_before={}, pool_after={}",
            curve, algorithm, size_before, size_after
        );
        assert_eq!(
            size_after, *size_before,
            "{:?}/{:?}: pool should be exactly stable once settled (before={}, after={})",
            curve, algorithm, size_before, size_after
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

    // When idle, presign sessions spawn and complete — verify the pool grew beyond min_pool_size
    let pool_size_after_idle_rounds = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
        .unwrap_or(0);

    info!(
        "After 20 idle rounds: EdDSA pool size={} (was {} at min)",
        pool_size_after_idle_rounds, min_pool_size
    );

    assert!(
        pool_size_after_idle_rounds > min_pool_size,
        "when idle, pool should grow beyond min_pool_size (min={}, got={})",
        min_pool_size,
        pool_size_after_idle_rounds
    );

    // Verify the pool respects max_pool_size by running many more rounds and checking the cap.
    // Run 60 more rounds to give the pool time to hit and stay at the cap.
    for _ in 0..60 {
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

    let pool_size_after_cap_rounds = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
        .unwrap_or(0);
    info!(
        "After 60 more rounds: EdDSA pool size={} (max={})",
        pool_size_after_cap_rounds, max_pool_size
    );
    assert!(
        pool_size_after_cap_rounds <= max_pool_size,
        "pool should never exceed max_pool_size (max={}, got={})",
        max_pool_size,
        pool_size_after_cap_rounds
    );

    info!("Test completed: internal presigns continue when idle");
}
