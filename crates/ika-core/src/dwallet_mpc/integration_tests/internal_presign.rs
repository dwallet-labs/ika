use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::NetworkOwnedAddressSignRequest;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_POOL_MAXIMUM_SIZE,
    TEST_PRESIGN_POOL_MINIMUM_SIZE, build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
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

    // Create a network key (required for internal presigns).
    // create_network_key_test sets last_session_to_complete_in_current_epoch internally.
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Read per-algorithm config. Since there is only one network key in the test,
    // it is the NOA signing key, so ALL algorithms use `network_owned_address_sign_*_presign_*` config.
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;

    // Verify test config constants match what the protocol config returns.
    for (_curve, algorithm) in ALL_ALGORITHMS {
        let delay =
            protocol_config.get_network_owned_address_presign_consensus_round_delay(*algorithm);
        let sessions_to_instantiate =
            protocol_config.get_network_owned_address_presign_sessions_to_instantiate(*algorithm);
        let min_pool =
            protocol_config.get_network_owned_address_presign_pool_minimum_size(*algorithm);
        let max_pool =
            protocol_config.get_network_owned_address_presign_pool_maximum_size(*algorithm);
        assert_eq!(
            delay, TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
            "{:?}: delay should be {}",
            algorithm, TEST_PRESIGN_CONSENSUS_ROUND_DELAY
        );
        assert_eq!(
            sessions_to_instantiate,
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
            "{:?}: sessions_to_instantiate should be {}",
            algorithm,
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE
        );
        assert_eq!(
            min_pool, TEST_PRESIGN_POOL_MINIMUM_SIZE,
            "{:?}: min_pool should be {}",
            algorithm, TEST_PRESIGN_POOL_MINIMUM_SIZE
        );
        assert_eq!(
            max_pool, TEST_PRESIGN_POOL_MAXIMUM_SIZE,
            "{:?}: max_pool should be {}",
            algorithm, TEST_PRESIGN_POOL_MAXIMUM_SIZE
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
        // Since there is only one network key and it IS the NOA signing key,
        // all algorithms use NOA sign presign config.
        for (curve, algorithm, pre_instantiated, pre_completed, pre_pool) in &pre_loop_snapshots {
            let delay = TEST_PRESIGN_CONSENSUS_ROUND_DELAY;
            let min_pool = TEST_PRESIGN_POOL_MINIMUM_SIZE;
            let max_pool = TEST_PRESIGN_POOL_MAXIMUM_SIZE;
            let sessions_to_instantiate =
                TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE;

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
            let delay_aligned = post_number_of_rounds.is_multiple_of(delay);
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
/// Makes the system non-idle by sending `NetworkOwnedAddressSignRequest`s through the EdDSA
/// channel, which creates real `NetworkOwnedAddressSign` sessions that count toward the idle
/// threshold. These sessions only consume presigns from the EdDSA pool, so
/// non-EdDSA pools remain unaffected.
///
/// EdDSA is excluded from pool stability assertions because NetworkOwnedAddressSign sessions
/// consume its presigns.
///
/// Test flow:
/// 1. Create network key, let all pools fill (system is idle).
/// 2. Send NetworkOwnedAddressSignRequests via EdDSA channel → creates active sessions → system becomes non-idle.
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
    // We send NOA sign requests via the EdDSA channel, so exclude EdDSA from pool stability checks.
    let noa_sign_algorithm = DWalletSignatureAlgorithm::EdDSA;
    let noa_sign_hash_scheme = DWalletHashScheme::SHA512;

    let (non_eddsa_algorithms, per_algo_min_sizes) = {
        let protocol_config = &test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .protocol_config;

        let non_eddsa_algorithms: Vec<(DWalletCurve, DWalletSignatureAlgorithm)> = ALL_ALGORITHMS
            .iter()
            .filter(|(_, algorithm)| *algorithm != noa_sign_algorithm)
            .copied()
            .collect();

        // Since there is only one key and it IS the NOA signing key,
        // all algorithms use NOA sign presign config.
        let per_algo_min_sizes: Vec<u64> = non_eddsa_algorithms
            .iter()
            .map(|(_, algorithm)| {
                protocol_config.get_network_owned_address_presign_pool_minimum_size(*algorithm)
            })
            .collect();

        info!(
            "idle_threshold={}, excluded={:?}",
            protocol_config.idle_session_count_threshold(),
            noa_sign_algorithm
        );

        (non_eddsa_algorithms, per_algo_min_sizes)
    };

    // === Phase 1: Let all pools fill while the system is idle ===
    // Run rounds with computation waits until all non-EdDSA pools reach min_pool_size
    // AND the EdDSA pool has presigns (needed for NetworkOwnedAddressSign requests later).
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

        let all_non_eddsa_at_min = non_eddsa_algorithms
            .iter()
            .zip(per_algo_min_sizes.iter())
            .all(|((_, algorithm), min_size)| {
                test_state.epoch_stores[0]
                    .presign_pool_size(*algorithm, network_key_id)
                    .unwrap_or(0)
                    >= *min_size
            });
        let eddsa_has_presigns = test_state.epoch_stores[0]
            .presign_pool_size(noa_sign_algorithm, network_key_id)
            .unwrap_or(0)
            > 0;
        if all_non_eddsa_at_min && eddsa_has_presigns {
            info!("All pools ready — moving to make system non-idle");
            break;
        }
    }

    // Verify all non-EdDSA pools reached min.
    for ((curve, algorithm), min_size) in non_eddsa_algorithms.iter().zip(per_algo_min_sizes.iter())
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

    // === Phase 2: Make the system non-idle with real NetworkOwnedAddressSign sessions ===
    // Send NetworkOwnedAddressSignRequests to all validators. Each one that gets instantiated
    // creates an Active NetworkOwnedAddressSign session, which counts toward the idle threshold.
    // These only consume presigns from the EdDSA pool (excluded from assertions).
    let num_sign_requests = 20u64;
    for idx in 0..num_sign_requests {
        for sender in &test_state.network_owned_address_sign_request_senders {
            sender
                .send(NetworkOwnedAddressSignRequest {
                    message: format!("idle-breaker-{}", idx).into_bytes(),
                    curve: DWalletCurve::Curve25519,
                    signature_algorithm: noa_sign_algorithm,
                    hash_scheme: noa_sign_hash_scheme,
                })
                .await
                .expect("failed to send network-owned-address sign request");
        }
    }

    // Run enough rounds to process the requests, let NetworkOwnedAddressSign sessions become active,
    // and for the non-idle status to propagate through consensus voting.
    for _ in 0..10 {
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
        "system should be non-idle after sending NetworkOwnedAddressSign requests"
    );

    // === Phase 3: Verify non-EdDSA pools are stable when non-idle + at/above min ===
    let pool_sizes_before: Vec<(DWalletCurve, DWalletSignatureAlgorithm, u64)> =
        non_eddsa_algorithms
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

    // Verify network stayed non-idle throughout Phase 3 — confirms pool stability
    // was due to the non-idle guard, not coincidence (e.g. no delay-aligned round firing).
    assert!(
        !test_state.dwallet_mpc_services[0].network_is_idle(),
        "system should still be non-idle after Phase 3 rounds"
    );

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
///
/// Phase 1: Run rounds until the EdDSA pool naturally reaches min_pool_size.
/// Phase 2: Verify `network_is_idle()` is true, then continue running rounds
///          until the pool grows to max_pool_size.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_continues_when_idle() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // Extract all needed config values before creating the network key.
    // Since there is only one key in the test and it IS the NOA signing key,
    // use NOA sign presign config.
    let (max_pool_size, min_pool_size) = {
        let protocol_config = &test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .protocol_config;
        let max_pool_size = protocol_config
            .get_network_owned_address_presign_pool_maximum_size(DWalletSignatureAlgorithm::EdDSA);
        let min_pool_size = protocol_config
            .get_network_owned_address_presign_pool_minimum_size(DWalletSignatureAlgorithm::EdDSA);
        (max_pool_size, min_pool_size)
    };

    info!(
        "min_pool_size={}, max_pool_size={}",
        min_pool_size, max_pool_size
    );

    // Create network key.
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Run rounds with computation waits. The pool fills naturally:
    // 1. Pool grows to min_pool_size (always happens, regardless of idle status).
    // 2. Presign sessions complete, session count drops, validators report idle.
    // 3. Idle status propagates through consensus voting → network_is_idle flips to true.
    // 4. Pool continues growing to max_pool_size (only happens when idle).
    let mut reached_min = false;
    let mut became_idle = false;
    let mut pool_size_when_idle_above_min: Option<u64> = None;
    for round_idx in 0..150 {
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

        let current_pool_size = test_state.epoch_stores[0]
            .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
            .unwrap_or(0);

        if current_pool_size >= min_pool_size && !reached_min {
            reached_min = true;
            info!(
                round_idx,
                current_pool_size, min_pool_size, "EdDSA pool reached min_pool_size"
            );
        }

        if test_state.dwallet_mpc_services[0].network_is_idle() && !became_idle {
            became_idle = true;
            info!(
                round_idx,
                "network_is_idle flipped to true — pool should now grow toward max"
            );
        }

        if reached_min && became_idle && pool_size_when_idle_above_min.is_none() {
            pool_size_when_idle_above_min = Some(current_pool_size);
            info!(
                round_idx,
                current_pool_size, "Both reached_min and became_idle true — snapshotting pool size"
            );
        }

        if current_pool_size >= max_pool_size {
            info!(
                round_idx,
                current_pool_size, max_pool_size, "Pool reached max — stopping early"
            );
            break;
        }
    }
    assert!(
        reached_min,
        "EdDSA pool should naturally reach min_pool_size={} via real presign sessions",
        min_pool_size
    );
    assert!(
        became_idle,
        "network_is_idle should have flipped to true after presign sessions completed"
    );

    let pool_size_final = test_state.epoch_stores[0]
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, network_key_id)
        .unwrap_or(0);
    info!(
        "Final EdDSA pool size={} (min={}, max={})",
        pool_size_final, min_pool_size, max_pool_size
    );

    // Directly prove: after the pool was at/above min AND the network was idle,
    // presigns continued to be created (pool grew beyond the snapshot).
    let snapshot = pool_size_when_idle_above_min
        .expect("pool should have been above min while idle at some point");
    assert!(
        pool_size_final > snapshot,
        "pool should grow after being at/above min while idle (snapshot={}, final={})",
        snapshot,
        pool_size_final
    );

    // The pool can overshoot max_pool_size because multipresign sessions produce
    // presigns in batches — a session started when pool < max can complete and deposit
    // multiple presigns, pushing the pool past max by up to
    // sessions_to_instantiate * (n - threshold).
    let max_overshoot = TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE
        * (test_state.dwallet_mpc_services.len() as u64
            - test_state.committee.quorum_threshold() as u64);
    assert!(
        pool_size_final >= max_pool_size,
        "pool should reach at least max_pool_size (max={}, got={})",
        max_pool_size,
        pool_size_final
    );
    assert!(
        pool_size_final <= max_pool_size + max_overshoot,
        "pool should not overshoot beyond max_pool_size + max_overshoot (max={}, overshoot={}, got={})",
        max_pool_size,
        max_overshoot,
        pool_size_final
    );

    // Verify idle-fill triggered for all algorithms by checking instantiation counts.
    // We can't assert pool sizes because ECDSA presigns are multi-round with class
    // groups — EdDSA reaches max before ECDSA sessions complete enough batches.
    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
    for (curve, algorithm) in ALL_ALGORITHMS {
        if *curve == DWalletCurve::Curve25519 && *algorithm == DWalletSignatureAlgorithm::EdDSA {
            continue; // Already verified above.
        }
        let instantiated = manager
            .instantiated_internal_presign_sessions
            .get(&(*curve, *algorithm))
            .copied()
            .unwrap_or(0);
        assert!(
            instantiated > 0,
            "{:?}/{:?}: idle-fill should have instantiated at least one presign session (got={})",
            curve,
            algorithm,
            instantiated
        );
        let algo_pool = test_state.epoch_stores[0]
            .presign_pool_size(*algorithm, network_key_id)
            .unwrap_or(0);
        info!(
            "{:?}/{:?}: instantiated={}, pool_size={}",
            curve, algorithm, instantiated, algo_pool
        );
    }

    info!("Test completed: internal presigns continue when idle");
}
