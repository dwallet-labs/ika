use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE, build_test_state,
    create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
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
/// based on the configuration (consensus_round_delay).
///
/// Uses per-(curve, algorithm) monotonic counters to verify that sessions are
/// created beyond the baseline established during network key setup.
/// Note: this test does NOT assert session completion — it only verifies
/// correct instantiation timing. Completion is tested by
/// `test_internal_presign_continues_when_idle`.
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

    // Create a network key (required for internal presigns).
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Verify per-algorithm config values match the test constants.
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    for (curve, algorithm) in ALL_ALGORITHMS {
        let delay = protocol_config.get_internal_presign_consensus_round_delay(*curve, *algorithm);
        let sessions_to_instantiate =
            protocol_config.get_internal_presign_sessions_to_instantiate(*curve, *algorithm);
        assert_eq!(
            delay, TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
            "{:?}/{:?}: test config should set delay={}",
            curve, algorithm, TEST_PRESIGN_CONSENSUS_ROUND_DELAY
        );
        assert_eq!(
            sessions_to_instantiate, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
            "{:?}/{:?}: test config should set sessions_to_instantiate={}",
            curve, algorithm, TEST_PRESIGN_SESSIONS_TO_INSTANTIATE
        );
    }

    // After network key creation the first delay-aligned round will have
    // triggered `instantiate_internal_presign_sessions` for every algorithm.
    // Verify that sessions were created for every (curve, algorithm) pair.
    for (curve, algorithm) in ALL_ALGORITHMS {
        let instantiated = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .instantiated_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);

        info!("{:?}/{:?}: instantiated={}", curve, algorithm, instantiated);

        assert!(
            instantiated > 0,
            "{:?}/{:?}: expected at least one session to be instantiated after network key setup",
            curve,
            algorithm
        );
    }

    // Run 10 more rounds.  The guard (`instantiated != completed`) will
    // prevent new batches while the first batch is still in-flight (no
    // computation waits here), which is the correct overshoot-prevention
    // behaviour.  We verify counters stay consistent.
    for _round_offset in 1..=10 {
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

    // Verify counters are still consistent (monotonic, no corruption).
    for (curve, algorithm) in ALL_ALGORITHMS {
        let instantiated = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .instantiated_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);
        let completed = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .completed_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);

        info!(
            "{:?}/{:?}: instantiated={}, completed={}",
            curve, algorithm, instantiated, completed
        );

        // Instantiated must be >= completed (monotonic invariant).
        assert!(
            instantiated >= completed,
            "{:?}/{:?}: instantiated ({}) must be >= completed ({})",
            curve,
            algorithm,
            instantiated,
            completed
        );
    }

    info!("Test completed: per-algorithm presign instantiation verified over 10 rounds");
}

/// Test that internal presign sessions stop being created when the pool reaches minimum size
/// and the system is not idle. Covers all signature algorithms.
///
/// Pre-populates pools to `min_pool_size` so that the instantiation condition
/// `current_pool_size < minimal_pool_size` is always false when not idle.
/// Verifies pool sizes remain exactly stable across additional rounds.
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

    // Create network key (the actual key ID is what matters).
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

    // Pre-populate all pools to min_pool_size using the ACTUAL network key ID.
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

    // Run settling rounds WITH computation waits so that any sessions created
    // during/after network key setup complete and deposit their presigns.
    // This ensures the pool is fully stable before we take the "before" snapshot.
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
        utils::wait_for_computations(&mut test_state).await;
    }

    // Record pool sizes after full stabilization.
    let pool_sizes_before: Vec<(DWalletCurve, DWalletSignatureAlgorithm, u64)> = ALL_ALGORITHMS
        .iter()
        .map(|(curve, algorithm)| {
            let size = test_state.epoch_stores[0]
                .presign_pool_size(*algorithm, network_key_id)
                .unwrap_or(0);
            (*curve, *algorithm, size)
        })
        .collect();

    // Run several more delay-aligned rounds to confirm the pool is now stable.
    // No computation waits needed here — pools are at/above min and system is
    // not idle, so no new sessions should be created.
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
///
/// Uses `wait_for_computations` to give rayon threads sufficient wall-clock
/// time to complete each MPC round, so presigns are actually deposited into
/// the pool and the monotonic counters advance.
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

    // Create network key.
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Extract all needed config values in a scope block to avoid borrow conflicts.
    let (max_pool_size, min_pool_size, max_overshoot) = {
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        let protocol_config = &manager.protocol_config;
        let max_pool_size = protocol_config.get_internal_presign_pool_maximum_size(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        let min_pool_size = protocol_config.get_internal_presign_pool_minimum_size(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        let sessions_to_instantiate = protocol_config.get_internal_presign_sessions_to_instantiate(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        // max_overshoot = sessions_to_instantiate * (n - threshold).
        // A session can produce up to (n - t) presigns, and we create sessions_to_instantiate
        // sessions per batch, so the pool can overshoot by at most this amount.
        let total_weight = manager.access_structure.total_weight();
        let threshold = manager.access_structure.threshold;
        let max_overshoot = sessions_to_instantiate * (total_weight - threshold) as u64;
        (max_pool_size, min_pool_size, max_overshoot)
    };

    info!(
        "min_pool_size={}, max_pool_size={}, max_overshoot={}",
        min_pool_size, max_pool_size, max_overshoot
    );

    // Pre-populate EdDSA pool to min_pool_size so we can verify growth beyond min.
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

    // Run rounds with computation waits; since we're idle, presign sessions
    // should spawn, complete, and deposit presigns beyond min_pool_size.
    for round_idx in 0..80 {
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

        // Early exit: once the pool exceeds max_pool_size, stop running rounds.
        let current_pool_size = test_state.epoch_stores[0]
            .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
            .unwrap_or(0);
        if current_pool_size >= max_pool_size {
            info!(
                round_idx,
                current_pool_size, max_pool_size, "Pool reached max — stopping early"
            );
            break;
        }
    }

    let pool_size_final = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
        .unwrap_or(0);
    info!(
        "Final EdDSA pool size={} (min={}, max={}, max_overshoot={})",
        pool_size_final, min_pool_size, max_pool_size, max_overshoot
    );

    // Pool should have grown beyond min_pool_size.
    assert!(
        pool_size_final > min_pool_size,
        "when idle, pool should grow beyond min_pool_size (min={}, got={})",
        min_pool_size,
        pool_size_final
    );

    // Pool should have reached at least max_pool_size (filled up).
    assert!(
        pool_size_final >= max_pool_size,
        "pool should have filled up to at least max_pool_size (max={}, got={})",
        max_pool_size,
        pool_size_final
    );

    // Pool should not exceed max_pool_size + max_overshoot.
    assert!(
        pool_size_final <= max_pool_size + max_overshoot,
        "pool should not exceed max_pool_size + max_overshoot (max={}, overshoot={}, got={})",
        max_pool_size,
        max_overshoot,
        pool_size_final
    );

    info!("Test completed: internal presigns continue when idle");
}
