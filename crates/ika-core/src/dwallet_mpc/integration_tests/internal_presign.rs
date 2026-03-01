use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::InternalSignRequest;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_INTERNAL_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE, TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
    TEST_PRESIGN_POOL_MAXIMUM_SIZE, TEST_PRESIGN_POOL_MINIMUM_SIZE,
    TEST_PRESIGN_SESSIONS_TO_INSTANTIATE, build_test_state, create_test_protocol_config_guard,
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

/// Test that internal presign sessions are instantiated at exactly the correct consensus
/// rounds based on the production logic in `mpc_manager.rs:instantiate_internal_presign_sessions`.
///
/// For each (curve, algorithm) pair, verifies round-by-round that:
/// - Sessions fire only when the in-flight guard is open (instantiated == completed)
/// - AND either (delay-aligned AND pool < min_pool) OR (network_is_idle AND pool < max_pool)
/// - The exact number of sessions created matches `sessions_to_instantiate` from config
///
/// Also verifies cross-service consistency and the monotonic invariant.
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
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Read per-(curve, algo) config. The production code uses `internal_sign_presign_*`
    // config for the (internal_signing_curve, internal_signing_algorithm) pair, and
    // per-algorithm config for everything else.
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    let internal_signing_curve = protocol_config.internal_signing_curve();
    let internal_signing_algorithm = protocol_config.internal_signing_algorithm();

    // Verify test config constants match what the protocol config returns.
    for (curve, algorithm) in ALL_ALGORITHMS {
        let is_internal_signing =
            *curve == internal_signing_curve && *algorithm == internal_signing_algorithm;
        let delay = if is_internal_signing {
            protocol_config.internal_sign_presign_consensus_round_delay()
        } else {
            protocol_config.get_internal_presign_consensus_round_delay(*curve, *algorithm)
        };
        let sessions_to_instantiate = if is_internal_signing {
            protocol_config.internal_sign_presign_sessions_to_instantiate()
        } else {
            protocol_config.get_internal_presign_sessions_to_instantiate(*curve, *algorithm)
        };
        let min_pool = if is_internal_signing {
            protocol_config.internal_sign_presign_pool_minimum_size()
        } else {
            protocol_config.get_internal_presign_pool_minimum_size(*curve, *algorithm)
        };
        let max_pool = if is_internal_signing {
            protocol_config.internal_sign_presign_pool_maximum_size()
        } else {
            protocol_config.get_internal_presign_pool_maximum_size(*curve, *algorithm)
        };
        assert_eq!(
            delay, TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
            "{:?}/{:?}: delay should be {}",
            curve, algorithm, TEST_PRESIGN_CONSENSUS_ROUND_DELAY
        );
        let expected_sessions = if is_internal_signing {
            TEST_INTERNAL_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE
        } else {
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE
        };
        assert_eq!(
            sessions_to_instantiate, expected_sessions,
            "{:?}/{:?}: sessions_to_instantiate should be {}",
            curve, algorithm, expected_sessions
        );
        assert_eq!(
            min_pool, TEST_PRESIGN_POOL_MINIMUM_SIZE,
            "{:?}/{:?}: min_pool should be {}",
            curve, algorithm, TEST_PRESIGN_POOL_MINIMUM_SIZE
        );
        assert_eq!(
            max_pool, TEST_PRESIGN_POOL_MAXIMUM_SIZE,
            "{:?}/{:?}: max_pool should be {}",
            curve, algorithm, TEST_PRESIGN_POOL_MAXIMUM_SIZE
        );
    }

    info!(
        baseline_rounds = test_state.dwallet_mpc_services[0].number_of_consensus_rounds(),
        "Starting round-by-round verification"
    );

    // Run 16 rounds, verifying exact instantiation predictions each round.
    //
    // Key timing: within `process_consensus_rounds_from_storage`:
    //   1. number_of_consensus_rounds += 1
    //   2. process status updates → update network_is_idle
    //   3. instantiate_internal_presign_sessions (reads pool from epoch_store)
    //   4. handle messages/outputs (step 5 — deposits presigns into epoch_store)
    //
    // Step 3 sees pool BEFORE step 4 deposits. So we must read pool BEFORE
    // run_service_loop_iteration, not after.
    for round_offset in 1..=16u64 {
        // Distribute inter-party messages/outputs from previous round.
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        // Snapshot pre-loop state: this is exactly what step 3 sees for
        // pool_size, instantiated, and completed (nothing modifies them
        // between this read and step 3 within run_service_loop_iteration).
        let pre_loop_snapshots: Vec<_> = ALL_ALGORITHMS
            .iter()
            .map(|(curve, algorithm)| {
                let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
                let instantiated = manager
                    .instantiated_internal_presign_sessions
                    .get(&(*curve, *algorithm))
                    .copied()
                    .unwrap_or(0);
                let completed = manager
                    .completed_internal_presign_sessions
                    .get(&(*curve, *algorithm))
                    .copied()
                    .unwrap_or(0);
                let pool_size = test_state.epoch_stores[0]
                    .presign_pool_size(*algorithm, network_key_id)
                    .unwrap_or(0);
                (*curve, *algorithm, instantiated, completed, pool_size)
            })
            .collect();

        // Run service loop for all services (processes the consensus round).
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }

        // Read post-loop values that were set DURING round processing
        // (before step 3 ran): number_of_consensus_rounds and network_is_idle.
        let post_number_of_rounds = test_state.dwallet_mpc_services[0].number_of_consensus_rounds();
        let post_is_idle = test_state.dwallet_mpc_services[0].network_is_idle();

        // Wait for rayon crypto to complete so outputs flow through consensus.
        utils::wait_for_computations(&mut test_state).await;

        // Verify per-(curve, algo) instantiation delta matches prediction.
        for (curve, algorithm, pre_instantiated, pre_completed, pre_pool) in &pre_loop_snapshots {
            let is_internal_signing =
                *curve == internal_signing_curve && *algorithm == internal_signing_algorithm;
            let delay = TEST_PRESIGN_CONSENSUS_ROUND_DELAY;
            let min_pool = TEST_PRESIGN_POOL_MINIMUM_SIZE;
            let max_pool = TEST_PRESIGN_POOL_MAXIMUM_SIZE;
            let sessions_to_instantiate = if is_internal_signing {
                TEST_INTERNAL_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE
            } else {
                TEST_PRESIGN_SESSIONS_TO_INSTANTIATE
            };

            let post_instantiated = test_state.dwallet_mpc_services[0]
                .dwallet_mpc_manager()
                .instantiated_internal_presign_sessions
                .get(&(*curve, *algorithm))
                .copied()
                .unwrap_or(0);
            let delta_instantiated = post_instantiated - pre_instantiated;

            // Predict using exactly the state step 3 saw:
            // - guard: pre_instantiated == pre_completed (unchanged before step 3)
            // - delay: post_number_of_rounds (incremented before step 3)
            // - pool: pre_pool (read from epoch_store before step 5 deposits)
            // - idle: post_is_idle (updated from status updates before step 3)
            let guard_open = pre_instantiated == pre_completed;
            let delay_aligned = post_number_of_rounds % delay == 0;
            let should_instantiate = guard_open
                && ((delay_aligned && (*pre_pool) < min_pool)
                    || (post_is_idle && (*pre_pool) < max_pool));
            let expected_delta = if should_instantiate {
                sessions_to_instantiate
            } else {
                0
            };

            info!(
                round_offset,
                ?curve,
                ?algorithm,
                post_number_of_rounds,
                guard_open,
                delay_aligned,
                pre_pool,
                post_is_idle,
                pre_instantiated,
                pre_completed,
                delta_instantiated,
                expected_delta,
                "Round prediction"
            );

            assert_eq!(
                delta_instantiated, expected_delta,
                "round {round_offset}, {:?}/{:?}: expected delta={expected_delta} but got \
                 delta={delta_instantiated} (guard_open={guard_open}, delay_aligned={delay_aligned}, \
                 pre_pool={pre_pool}, post_idle={post_is_idle}, rounds={post_number_of_rounds})",
                curve, algorithm,
            );
        }
    }

    // Final: all 4 services must agree on instantiated/completed counters.
    for (curve, algorithm) in ALL_ALGORITHMS {
        let reference_instantiated = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .instantiated_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);
        let reference_completed = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .completed_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);

        // Monotonic invariant.
        assert!(
            reference_instantiated >= reference_completed,
            "{:?}/{:?}: instantiated ({}) must be >= completed ({})",
            curve,
            algorithm,
            reference_instantiated,
            reference_completed
        );

        // Cross-service consistency.
        for (service_idx, service) in test_state.dwallet_mpc_services.iter().enumerate().skip(1) {
            let instantiated = service
                .dwallet_mpc_manager()
                .instantiated_internal_presign_sessions
                .get(&(*curve, *algorithm))
                .copied()
                .unwrap_or(0);
            let completed = service
                .dwallet_mpc_manager()
                .completed_internal_presign_sessions
                .get(&(*curve, *algorithm))
                .copied()
                .unwrap_or(0);
            assert_eq!(
                instantiated, reference_instantiated,
                "{:?}/{:?}: service {} instantiated ({}) != service 0 ({})",
                curve, algorithm, service_idx, instantiated, reference_instantiated
            );
            assert_eq!(
                completed, reference_completed,
                "{:?}/{:?}: service {} completed ({}) != service 0 ({})",
                curve, algorithm, service_idx, completed, reference_completed
            );
        }
    }

    info!(
        "Test completed: round-by-round presign instantiation predictions verified over 16 rounds"
    );
}

/// Test that internal presign sessions stop being created when the pool reaches minimum size
/// and the system is not idle.
///
/// Makes the system non-idle by sending `InternalSignRequest`s through the channel, which
/// creates real `InternalSign` sessions that count toward the idle threshold. These sessions
/// only consume presigns from the Curve25519/EdDSA pool (the internal signing curve), so
/// non-EdDSA pools remain unaffected.
///
/// The internal signing curve (Curve25519/EdDSA) is excluded from all assertions because
/// InternalSign sessions consume its presigns and its pool uses separate config
/// (`internal_sign_presign_*`) with different `sessions_to_instantiate`.
///
/// Test flow:
/// 1. Create network key, let all pools fill (system is idle).
/// 2. Send InternalSignRequests → creates active InternalSign sessions → system becomes non-idle.
/// 3. Snapshot non-EdDSA pool sizes, run more rounds, assert they stay exactly stable.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_stops_at_min_pool_size_when_not_idle() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Create network key (required for internal presigns).
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Extract config values needed throughout the test.
    let (non_internal_sign_algorithms, per_algo_min_sizes, internal_signing_algorithm) = {
        let protocol_config = &test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .protocol_config;

        let internal_signing_curve = protocol_config.internal_signing_curve();
        let internal_signing_algorithm = protocol_config.internal_signing_algorithm();
        let non_internal_sign_algorithms: Vec<(DWalletCurve, DWalletSignatureAlgorithm)> =
            ALL_ALGORITHMS
                .iter()
                .filter(|(curve, algorithm)| {
                    !(*curve == internal_signing_curve && *algorithm == internal_signing_algorithm)
                })
                .copied()
                .collect();

        let per_algo_min_sizes: Vec<u64> = non_internal_sign_algorithms
            .iter()
            .map(|(curve, algorithm)| {
                protocol_config.get_internal_presign_pool_minimum_size(*curve, *algorithm)
            })
            .collect();

        info!(
            "idle_threshold={}, excluded=({:?}/{:?})",
            protocol_config.idle_session_count_threshold(),
            internal_signing_curve,
            internal_signing_algorithm
        );

        (
            non_internal_sign_algorithms,
            per_algo_min_sizes,
            internal_signing_algorithm,
        )
    };

    // === Phase 1: Let all pools fill while the system is idle ===
    // Run rounds with computation waits until all non-EdDSA pools reach min_pool_size
    // AND the EdDSA pool has presigns (needed for InternalSign requests later).
    for _ in 0..80 {
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

        let all_non_eddsa_at_min = non_internal_sign_algorithms
            .iter()
            .zip(per_algo_min_sizes.iter())
            .all(|((_, algorithm), min_size)| {
                test_state.epoch_stores[0]
                    .presign_pool_size(*algorithm, network_key_id)
                    .unwrap_or(0)
                    >= *min_size
            });
        let eddsa_has_presigns = test_state.epoch_stores[0]
            .presign_pool_size(internal_signing_algorithm, network_key_id)
            .unwrap_or(0)
            > 0;
        if all_non_eddsa_at_min && eddsa_has_presigns {
            info!("All pools ready — moving to make system non-idle");
            break;
        }
    }

    // Verify all non-EdDSA pools reached min.
    for ((curve, algorithm), min_size) in non_internal_sign_algorithms
        .iter()
        .zip(per_algo_min_sizes.iter())
    {
        let pool_size = test_state.epoch_stores[0]
            .presign_pool_size(*algorithm, network_key_id)
            .unwrap_or(0);
        info!(
            "{:?}/{:?}: pool_size={}, min={}",
            curve, algorithm, pool_size, min_size
        );
        assert!(
            pool_size >= *min_size,
            "{:?}/{:?}: pool should have reached min_pool_size (min={}, got={})",
            curve,
            algorithm,
            min_size,
            pool_size
        );
    }

    // === Phase 2: Make the system non-idle with real InternalSign sessions ===
    // Send InternalSignRequests to all validators. Each one that gets instantiated
    // creates an Active InternalSign session, which counts toward the idle threshold.
    // These only consume presigns from the EdDSA pool (excluded from assertions).
    let num_sign_requests = 6u64;
    for sequence_number in 0..num_sign_requests {
        for sender in &test_state.internal_sign_request_senders {
            sender
                .send(InternalSignRequest {
                    sequence_number,
                    message: format!("idle-breaker-{}", sequence_number).into_bytes(),
                })
                .expect("failed to send internal sign request");
        }
    }

    // Run a few rounds to process the requests and let InternalSign sessions become active.
    for _ in 0..4 {
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

    // Verify system is now non-idle.
    assert!(
        !test_state.dwallet_mpc_services[0].network_is_idle(),
        "system should be non-idle after sending InternalSign requests"
    );

    // === Phase 3: Verify non-EdDSA pools are stable when non-idle + at/above min ===
    let pool_sizes_before: Vec<(DWalletCurve, DWalletSignatureAlgorithm, u64)> =
        non_internal_sign_algorithms
            .iter()
            .map(|(curve, algorithm)| {
                let size = test_state.epoch_stores[0]
                    .presign_pool_size(*algorithm, network_key_id)
                    .unwrap_or(0);
                (*curve, *algorithm, size)
            })
            .collect();

    // Run several more rounds — no computation waits needed since no new sessions are expected.
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

    // Assert pool sizes are exactly unchanged for non-internal-sign algorithms.
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
            "{:?}/{:?}: pool should be exactly stable once at min (before={}, after={})",
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
