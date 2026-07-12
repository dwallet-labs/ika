use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_POOL_MAXIMUM_SIZE,
    TEST_PRESIGN_POOL_MINIMUM_SIZE, apply_test_presign_pool_overrides, build_test_state,
    create_test_protocol_config_guard,
};
use crate::dwallet_mpc::mpc_manager::ParkedInternalPresignRequest;
use crate::dwallet_mpc::mpc_session::SessionStatus;
use crate::dwallet_mpc::{NetworkOwnedAddressSignRequest, ValidatorMpcKeysByPartyId};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use ika_protocol_config::ProtocolConfig;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState, SessionIdentifier,
    SessionType,
};
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::info;

/// The Fast Schnorr (VSS) signature algorithms — their internal presign pools
/// are driven alongside [`ALL_ALGORITHMS`] when `fast_schnorr_supported` is on,
/// and their presign inputs additionally require the epoch's off-chain VSS
/// validator key set to have been ingested.
const VSS_ALGORITHMS: &[(DWalletCurve, DWalletSignatureAlgorithm)] = &[
    (
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::TaprootVSS,
    ),
    (
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSAVSS,
    ),
    (
        DWalletCurve::Ristretto,
        DWalletSignatureAlgorithm::SchnorrkelVSS,
    ),
];

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
        DWalletSignatureAlgorithm::Schnorrkel,
    ),
    (DWalletCurve::Secp256k1, DWalletSignatureAlgorithm::Taproot),
];

/// Consensus rounds after which an in-flight top-up batch is presumed dead in
/// [`test_internal_presign_stale_batch_expiry`] — small so the test reaches
/// the expiry within a handful of service-loop iterations.
const TEST_STALE_BATCH_EXPIRY_ROUNDS: u64 = 12;

/// Reads the (instantiated, completed) internal-presign counters of one
/// service for one (network key, curve, algorithm) pool.
fn presign_batch_counters(
    test_state: &IntegrationTestState,
    service_index: usize,
    network_key_object_id: ObjectID,
    curve: DWalletCurve,
    algorithm: DWalletSignatureAlgorithm,
) -> (u64, u64) {
    let manager = test_state.dwallet_mpc_services[service_index].dwallet_mpc_manager();
    // The counters are keyed by the content-derived NetworkKeyId; resolve it
    // from the key's ObjectID the same way production does.
    let Some(network_key_id) = manager.internal_presign_network_key_id(&network_key_object_id)
    else {
        return (0, 0);
    };
    (
        manager
            .instantiated_internal_presign_sessions
            .get(&(network_key_id, curve, algorithm))
            .copied()
            .unwrap_or(0),
        manager
            .completed_internal_presign_sessions
            .get(&(network_key_id, curve, algorithm))
            .copied()
            .unwrap_or(0),
    )
}

/// Runs one consensus round across all services, first discarding every
/// pending consensus message so nothing the validators produced is ever
/// delivered — the round advances, but every in-flight MPC session is dead.
/// Waits for rayon computations BEFORE discarding so a slow computation
/// cannot deposit its message after the discard and leak into the next
/// delivery.
async fn run_one_round_discarding_all_messages(test_state: &mut IntegrationTestState) {
    utils::wait_for_computations(test_state).await;
    for collector in &test_state.sent_consensus_messages_collectors {
        collector.submitted_messages.lock().unwrap().clear();
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

/// Runs one consensus round across all services with normal message delivery.
async fn run_one_round_delivering_messages(test_state: &mut IntegrationTestState) {
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
}

/// Test the stale-batch expiry of the internal-presign top-up guard.
///
/// A top-up batch whose sessions die without ever reaching an output quorum
/// (in production: internal-presign refill sessions failing their first
/// computation round on every validator at epoch entry) never advances the
/// completion counter, and the in-flight guard would block that pool's
/// top-up for the rest of the epoch — the pool starves. The expiry presumes
/// such a batch dead after `internal_presign_stale_batch_expiry_rounds`
/// consensus rounds, reconciles the counters, and lets the pool top up again.
///
/// Simulates the dead batch by discarding ALL consensus messages once the
/// first batch instantiates (rounds keep flowing; no MPC message or output
/// is ever delivered), then asserts:
/// - the guard stays closed (no new instantiation) before the expiry;
/// - after the expiry the counters reconcile and a new batch fires;
/// - with delivery restored, the retried batch completes and the starved
///   pool actually fills;
/// - all four validators agree on the counters throughout (the top-up
///   decision derives the deterministic session identifiers every validator
///   computes independently, so it must be committee-uniform).
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_stale_batch_expiry() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    // One guard carrying the standard small pools PLUS the small expiry:
    // `apply_overrides_for_testing` replaces the previous override closure,
    // so the standard guard and an expiry-only guard would not compose.
    let _guard = ProtocolConfig::apply_overrides_for_testing(|_version, mut config| {
        apply_test_presign_pool_overrides(&mut config);
        config.set_internal_presign_stale_batch_expiry_rounds_for_testing(
            TEST_STALE_BATCH_EXPIRY_ROUNDS,
        );
        config
    });

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Track EdDSA: its presign protocol is single-round, so it is the batch
    // most likely to complete by accident — proving IT stays dead under the
    // discard covers the slower protocols a fortiori.
    let (curve, algorithm) = (DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);
    let batch_size = TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE;

    // === Phase 1: discard from the start; run until the first batch fires ===
    // Discarding from the very first round means the batch is dead from
    // birth — its computations run, but their messages are never delivered.
    let mut batch_seen = false;
    for _ in 0..12 {
        run_one_round_discarding_all_messages(&mut test_state).await;
        let (instantiated, completed) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        if instantiated > 0 {
            assert_eq!(instantiated, batch_size, "exactly one batch should fire");
            assert_eq!(completed, 0, "the dead batch must never complete");
            batch_seen = true;
            break;
        }
    }
    assert!(batch_seen, "the first top-up batch never instantiated");

    // === Phase 2: the guard must hold while the batch is within the expiry ===
    // The batch fired at most one round before detection; asserting over
    // expiry-minus-three rounds keeps the window strictly inside the expiry
    // regardless of that lag.
    for round_offset in 0..(TEST_STALE_BATCH_EXPIRY_ROUNDS - 3) {
        run_one_round_discarding_all_messages(&mut test_state).await;
        let (instantiated, completed) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        assert_eq!(
            (instantiated, completed),
            (batch_size, 0),
            "guard must block new top-ups while the dead batch is within the \
             expiry window (round offset {round_offset})"
        );
    }

    // === Phase 3: past the expiry, the counters reconcile and a new batch fires ===
    let mut refired = false;
    for _ in 0..(TEST_STALE_BATCH_EXPIRY_ROUNDS + 10) {
        run_one_round_discarding_all_messages(&mut test_state).await;
        let (instantiated, _) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        if instantiated > batch_size {
            refired = true;
            break;
        }
    }
    assert!(
        refired,
        "the pool must top up again after the stale-batch expiry"
    );
    for service_index in 0..test_state.dwallet_mpc_services.len() {
        let (instantiated, completed) =
            presign_batch_counters(&test_state, service_index, network_key_id, curve, algorithm);
        assert_eq!(
            (instantiated, completed),
            (batch_size * 2, batch_size),
            "service {service_index}: expiry must reconcile the dead batch \
             (completed := instantiated) before the new batch fires"
        );
    }

    // === Phase 4: with delivery restored, the retried batch heals the pool ===
    let mut pool_size = 0;
    for _ in 0..30 {
        run_one_round_delivering_messages(&mut test_state).await;
        pool_size = test_state.epoch_stores[0]
            .presign_pool_size(algorithm, network_key_id)
            .unwrap_or(0);
        let (instantiated, completed) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        if pool_size > 0 && instantiated == completed {
            break;
        }
    }
    assert!(
        pool_size > 0,
        "the retried batch must complete and refill the starved pool"
    );

    // Final cross-service consistency: instantiation is consensus-driven, so
    // every validator must hold identical counters.
    let reference = presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
    for service_index in 1..test_state.dwallet_mpc_services.len() {
        assert_eq!(
            presign_batch_counters(&test_state, service_index, network_key_id, curve, algorithm),
            reference,
            "service {service_index}: counters diverged from service 0"
        );
    }

    info!("Test completed: stale-batch expiry releases a starved pool and the retry heals it");
}

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
                let (instantiated, completed) =
                    presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm);
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

            let post_instantiated =
                presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm).0;
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
        let (reference_instantiated, reference_completed) =
            presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm);

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
        for (service_idx, _service) in test_state.dwallet_mpc_services.iter().enumerate().skip(1) {
            let (instantiated, completed) = presign_batch_counters(
                &test_state,
                service_idx,
                network_key_id,
                *curve,
                *algorithm,
            );
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
    for (curve, algorithm) in ALL_ALGORITHMS {
        if *curve == DWalletCurve::Curve25519 && *algorithm == DWalletSignatureAlgorithm::EdDSA {
            continue; // Already verified above.
        }
        let instantiated =
            presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm).0;
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

/// Counts terminally-Failed sessions across one service's session map.
fn failed_session_count(test_state: &IntegrationTestState, service_index: usize) -> usize {
    test_state.dwallet_mpc_services[service_index]
        .dwallet_mpc_manager()
        .sessions
        .values()
        .filter(|session| matches!(session.status, SessionStatus::Failed))
        .count()
}

/// Test that VSS internal presign batches instantiated before the epoch's
/// off-chain validator key set is ingested PARK (and later complete) instead
/// of failing terminally.
///
/// At epoch entry the manager starts with an empty off-chain validator key
/// set: the network key itself is adopted quickly from the handoff data, but
/// the consensus-frozen key set is ingested later (its assembly and the
/// network key's VSS derivation run asynchronously). Internal presign top-ups
/// fire as soon as the network key is installed, so the VSS pools' input
/// construction fails with the not-ready error class in that window. Mapping
/// that failure to `SessionStatus::Failed` starved the EdDSA/Schnorrkel/
/// Taproot VSS pools after every epoch transition (the batch died on every
/// validator, blocking top-ups until the stale-batch expiry).
///
/// Flow:
/// 1. Create the network key normally, then re-open the epoch-entry window on
///    every validator: forget the ingested key set and empty the delivery
///    channel (exactly the state a fresh manager is in before
///    `ingest_offchain_mpc_keys` first succeeds).
/// 2. Run rounds until the first VSS top-up batches fire; assert every
///    validator PARKS them — no terminally-Failed session anywhere — and that
///    parked batches are counted exactly once (no duplicate parking, no
///    re-instantiation while parked).
/// 3. Close the window (restore the ingested key set — the exact effect of
///    `ingest_offchain_mpc_keys`); assert the parked batches activate,
///    complete, and fill the previously starved pools, with counters uniform
///    across validators.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_vss_parks_until_off_chain_keys_ingested() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // No internal presign top-up has fired yet: batches only instantiate
    // while processing a consensus round AFTER the network key is installed,
    // and `create_network_key_test` returns without distributing such a
    // round. Verified here so the window below provably opens before the
    // first VSS batch.
    for (curve, algorithm) in VSS_ALGORITHMS {
        let (instantiated, _) =
            presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm);
        assert_eq!(
            instantiated, 0,
            "{curve:?}/{algorithm:?}: no VSS batch should have fired before the first post-install round"
        );
    }

    // Expected first-batch sizes: the single test key IS the NOA signing key,
    // so all pools use the NOA presign config.
    let batch_size = TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE;
    let expected_parked = batch_size as usize * VSS_ALGORITHMS.len();

    // === Phase 1: re-open the epoch-entry window on every validator ===
    let saved_keys: Vec<ValidatorMpcKeysByPartyId> = test_state
        .dwallet_mpc_services
        .iter_mut()
        .zip(&test_state.sui_data_senders)
        .map(|(service, senders)| {
            // Empty the delivery channel first so the next
            // `ingest_offchain_mpc_keys` finds nothing to ingest.
            let _ = senders.current_epoch_mpc_keys_sender.send(None);
            let manager = service.dwallet_mpc_manager_mut();
            let saved = manager.validator_mpc_keys_by_party_id.clone();
            manager.validator_mpc_keys_by_party_id = ValidatorMpcKeysByPartyId::empty();
            manager.current_epoch_keys_ingested = false;
            saved
        })
        .collect();

    // === Phase 2: first VSS top-up batches fire into the open window ===
    let mut all_parked = false;
    for _ in 0..12 {
        run_one_round_delivering_messages(&mut test_state).await;
        all_parked = test_state.dwallet_mpc_services.iter().all(|service| {
            service
                .dwallet_mpc_manager()
                .internal_presign_requests_pending_for_network_key_data
                .len()
                == expected_parked
        });
        if all_parked {
            break;
        }
    }
    assert!(
        all_parked,
        "every validator should park exactly {expected_parked} VSS internal presign requests \
         while the off-chain key set is not ingested"
    );

    for service_index in 0..test_state.dwallet_mpc_services.len() {
        assert_eq!(
            failed_session_count(&test_state, service_index),
            0,
            "validator {service_index}: VSS batches hitting the not-ready window must park, \
             not create terminally-Failed sessions"
        );
        for (curve, algorithm) in VSS_ALGORITHMS {
            assert_eq!(
                presign_batch_counters(
                    &test_state,
                    service_index,
                    network_key_id,
                    *curve,
                    *algorithm
                ),
                (batch_size, 0),
                "validator {service_index}: {curve:?}/{algorithm:?} batch must be counted \
                 instantiated exactly once while parked"
            );
        }
    }

    // Parked batches must be invisible to the top-up decision: more rounds
    // with the window still open must not re-instantiate, duplicate-park, or
    // fill the pool.
    for _ in 0..4 {
        run_one_round_delivering_messages(&mut test_state).await;
    }
    for service_index in 0..test_state.dwallet_mpc_services.len() {
        assert_eq!(
            test_state.dwallet_mpc_services[service_index]
                .dwallet_mpc_manager()
                .internal_presign_requests_pending_for_network_key_data
                .len(),
            expected_parked,
            "validator {service_index}: parked requests must not duplicate while the window is open"
        );
        for (curve, algorithm) in VSS_ALGORITHMS {
            assert_eq!(
                presign_batch_counters(
                    &test_state,
                    service_index,
                    network_key_id,
                    *curve,
                    *algorithm
                ),
                (batch_size, 0),
                "validator {service_index}: {curve:?}/{algorithm:?} guard must hold while parked"
            );
        }
    }
    for (_, algorithm) in VSS_ALGORITHMS {
        assert_eq!(
            test_state.epoch_stores[0]
                .presign_pool_size(*algorithm, network_key_id)
                .unwrap_or(0),
            0,
            "{algorithm:?}: pool must stay empty while its only batch is parked"
        );
    }

    // === Phase 3: close the window — the exact effect of `ingest_offchain_mpc_keys` ===
    for (service, keys) in test_state
        .dwallet_mpc_services
        .iter_mut()
        .zip(saved_keys.into_iter())
    {
        let manager = service.dwallet_mpc_manager_mut();
        manager.validator_mpc_keys_by_party_id = keys;
        manager.current_epoch_keys_ingested = true;
    }

    // The parked batches activate on the next service iteration and then run
    // the full multi-round VSS presign protocol to completion.
    let mut healed = false;
    for _ in 0..80 {
        run_one_round_delivering_messages(&mut test_state).await;
        let parked_drained = test_state.dwallet_mpc_services.iter().all(|service| {
            service
                .dwallet_mpc_manager()
                .internal_presign_requests_pending_for_network_key_data
                .is_empty()
        });
        let first_batches_completed = VSS_ALGORITHMS.iter().all(|(curve, algorithm)| {
            (0..test_state.dwallet_mpc_services.len()).all(|service_index| {
                let (_, completed) = presign_batch_counters(
                    &test_state,
                    service_index,
                    network_key_id,
                    *curve,
                    *algorithm,
                );
                completed >= batch_size
            })
        });
        let pools_filled = VSS_ALGORITHMS.iter().all(|(_, algorithm)| {
            test_state.epoch_stores[0]
                .presign_pool_size(*algorithm, network_key_id)
                .unwrap_or(0)
                > 0
        });
        if parked_drained && first_batches_completed && pools_filled {
            healed = true;
            break;
        }
    }
    assert!(
        healed,
        "once the off-chain key set lands, the parked VSS batches must activate, complete, \
         and fill the previously starved pools"
    );

    // The not-ready window must never have produced a terminal failure.
    for service_index in 0..test_state.dwallet_mpc_services.len() {
        assert_eq!(
            failed_session_count(&test_state, service_index),
            0,
            "validator {service_index}: no session may end terminally Failed in this flow"
        );
    }

    // Cross-service counter consistency (identifier derivation is
    // committee-uniform, so the counters must be too).
    for (curve, algorithm) in VSS_ALGORITHMS {
        let reference = presign_batch_counters(&test_state, 0, network_key_id, *curve, *algorithm);
        for service_index in 1..test_state.dwallet_mpc_services.len() {
            assert_eq!(
                presign_batch_counters(
                    &test_state,
                    service_index,
                    network_key_id,
                    *curve,
                    *algorithm
                ),
                reference,
                "validator {service_index}: {curve:?}/{algorithm:?} counters diverged from validator 0"
            );
        }
    }

    info!(
        "Test completed: VSS internal presign batches park through the off-chain-key ingest \
         window and complete once it closes"
    );
}

/// Per-validator map of every internal-presign session whose request is bound
/// (sequence number known): `session_identifier → sequence number`. Excludes
/// message/output stubs still in `WaitingForSessionRequest` with no request —
/// a stub proves a peer derived the identifier, not that THIS validator did.
/// Equality of these maps across validators is the invariant the shared
/// sequence counter must preserve: a validator that skips a top-up other
/// validators perform would bind different sequence numbers to different
/// identifiers from that point on.
fn bound_internal_presign_sessions(
    test_state: &IntegrationTestState,
    service_index: usize,
) -> HashMap<SessionIdentifier, u64> {
    test_state.dwallet_mpc_services[service_index]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(_, session)| session.session_type == Some(SessionType::InternalPresign))
        .filter_map(|(session_identifier, session)| {
            session
                .session_sequence_number
                .map(|sequence_number| (*session_identifier, sequence_number))
        })
        .collect()
}

/// Test that a validator whose network-key INSTALLATION lags behind its peers
/// in a multi-key epoch parks the affected internal presign batches with the
/// sequence numbers consumed — instead of skipping them — so session
/// identifier derivation stays committee-uniform.
///
/// The internal presign sequence counters are keyed per (network key, curve,
/// signature algorithm) pool, and the top-up loop iterates every ADOPTED key
/// while installation into `network_keys` completes asynchronously per
/// validator. Before the fix, a validator in the adopted-but-not-installed
/// window early-returned without consuming the sequence number (while the
/// caller still advanced the instantiated counter) — permanently
/// desynchronizing every subsequent internal presign identifier in that pool
/// from its peers'.
///
/// Flow:
/// 1. K0 bootstraps normally; K1 is a second same-epoch DKG (both adopted +
///    installed everywhere). K1's id is forced above K0's so the NOA-key
///    tie-break deterministically keeps K0 as the NOA signing key.
/// 2. Remove K1's INSTALLED data on validator 0 only (its adoption stays) —
///    exactly the adopted-but-not-installed window. The manager re-spawns the
///    installation in the background, which later heals the window naturally.
/// 3. Run rounds: K1's first pool batches fire committee-wide. Validator 0
///    must PARK them (identity from the pre-instantiation mapping, input
///    construction not-ready) while peers activate them.
/// 4. Run until the re-install heals validator 0: parked entries activate,
///    and the bound identifier→sequence maps converge to equality across all
///    validators, with no terminally-Failed session anywhere.
/// 5. Coda: a fabricated key that is adopted but has NO installed data and NO
///    `ObjectID → NetworkKeyId` mapping anywhere has an unresolvable
///    content-derived `NetworkKeyId`, so the top-up loop SKIPS it uniformly on
///    every validator — no batch parked, no sequence number consumed, no
///    session failed. (Adoption defers an unmapped key in production, so this
///    is a should-never-happen the loop must handle deterministically rather
///    than fall back to a divergent identity.)
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_multi_key_install_lag_keeps_identifiers_uniform() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);
    let (next_round_after_k0, _k0_bytes, k0_id) = create_network_key_test(&mut test_state).await;
    let k0_data = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .adopted_network_key_data
        .get(&k0_id)
        .expect("K0 must be adopted after create_network_key_test")
        .clone();

    // === Phase 1: K1 — a second network DKG in the same epoch ===
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("at least one service should exist")
        .epoch;
    // Force k1_id > k0_id: with equal `dkg_at_epoch` the NOA-key selection
    // tie-breaks by key id, so K0 stays the NOA signing key on every
    // validator regardless of which keys are installed at decision time.
    let k1_id = loop {
        let candidate = ObjectID::random();
        if candidate > k0_id {
            break candidate;
        }
    };
    let all_parties: Vec<usize> = (0..test_state.sui_data_senders.len()).collect();
    utils::send_configurable_start_network_dkg_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [2u8; 32],
        2,
        &all_parties,
        k1_id,
    );
    let (round_after_k1, k1_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, next_round_after_k0).await;
    let mut k1_bytes = Vec::new();
    for message in k1_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(message) = message
        else {
            continue;
        };
        k1_bytes.extend(message.public_output.clone());
    }
    assert!(
        !k1_bytes.is_empty(),
        "K1 network DKG checkpoint should carry non-empty public output"
    );

    // Publish BOTH keys to the overlay so every validator adopts + installs K1.
    let both_keys = Arc::new(HashMap::from([
        (k0_id, k0_data),
        (
            k1_id,
            DWalletNetworkEncryptionKeyData {
                id: k1_id,
                current_epoch: epoch_id,
                dkg_at_epoch: epoch_id,
                current_reconfiguration_public_output: vec![],
                network_dkg_public_output: k1_bytes.clone(),
                state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
            },
        ),
    ]));
    test_state.sui_data_senders.iter().for_each(|sender| {
        let _ = sender.network_keys_sender.send(both_keys.clone());
    });
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round_after_k1 + 1,
    );
    test_state.consensus_round = (round_after_k1 + 2) as usize;
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration(vec![]).await;
    }
    utils::run_service_loops_until_network_key_installed(
        &mut test_state.dwallet_mpc_services,
        k1_id,
    )
    .await;

    // No K1 pool batch has fired yet: top-ups only run while processing a
    // consensus round after installation, and the install-wait loop above
    // distributes no new rounds. Verified so the window below provably opens
    // before K1's first batch.
    let lagging_validator = 0usize;
    let k1_active_sessions = test_state.dwallet_mpc_services[lagging_validator]
        .dwallet_mpc_manager()
        .sessions
        .values()
        .filter(|session| {
            matches!(&session.status, SessionStatus::Active { request, .. }
                if request.protocol_data.network_encryption_key_id() == Some(k1_id))
        })
        .count();
    assert_eq!(
        k1_active_sessions, 0,
        "no K1 presign session should exist before the first post-install round"
    );

    // === Phase 2: open the install-lag window on validator 0 ===
    // Remove K1's INSTALLED data (adoption stays — the top-up loop keeps
    // iterating K1). `instantiate_adopted_network_keys` re-spawns the
    // installation on the next service iteration, and that async re-install
    // is exactly what heals the window later — the production shape.
    test_state.dwallet_mpc_services[lagging_validator]
        .dwallet_mpc_manager_mut()
        .network_keys
        .network_encryption_keys
        .remove(&k1_id)
        .expect("K1 must be installed on validator 0 before the window opens");

    // === Phase 3: K1's first batches fire; validator 0 must park them ===
    let mut saw_parked_on_lagging_validator = false;
    let mut healed = false;
    for _ in 0..60 {
        run_one_round_delivering_messages(&mut test_state).await;

        let parked: usize = test_state.dwallet_mpc_services[lagging_validator]
            .dwallet_mpc_manager()
            .internal_presign_requests_pending_for_network_key_data
            .len();
        if parked > 0 {
            saw_parked_on_lagging_validator = true;
        }

        // No validator may ever fail a session terminally in this flow.
        for service_index in 0..test_state.dwallet_mpc_services.len() {
            assert_eq!(
                failed_session_count(&test_state, service_index),
                0,
                "validator {service_index}: install lag must never terminally fail a session"
            );
        }

        // THE invariant: the per-pool sequence counters read identically on
        // every validator after every processed round — parking consumes the
        // number, so even the validator missing K1's data stays in step. The
        // whole per-(key,curve,algo) map must match (a stronger check than a
        // single shared counter: it also proves no pool's stream leaked into
        // another's).
        let reference_next_sequence_number = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .next_internal_presign_sequence_number
            .clone();
        for (service_index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
            assert_eq!(
                service
                    .dwallet_mpc_manager()
                    .next_internal_presign_sequence_number,
                reference_next_sequence_number,
                "validator {service_index}: internal presign sequence counters diverged during \
                 the install-lag window"
            );
        }

        // Healed: the window saw parking and the re-install drained it (a
        // parked entry whose session a peer quorum completed meanwhile is
        // legitimately dropped unbound — bound maps are compared as
        // subset-consistency below, not equality).
        let parked_everywhere_empty = test_state.dwallet_mpc_services.iter().all(|service| {
            service
                .dwallet_mpc_manager()
                .internal_presign_requests_pending_for_network_key_data
                .is_empty()
        });
        if saw_parked_on_lagging_validator && parked_everywhere_empty {
            healed = true;
            break;
        }
    }
    assert!(
        saw_parked_on_lagging_validator,
        "validator 0 should have parked K1's presign batches while K1 was not installed locally"
    );
    assert!(
        healed,
        "the re-install must drain validator 0's parked K1 batches with the shared sequence \
         counter identical across all validators"
    );

    // Bound identifier→sequence consistency: every session the lagging
    // validator bound must be bound to the SAME sequence number on every
    // peer (peers never parked, so they bound every batch). A pre-fix skip
    // shifts the lagging validator's counter and binds later batches to
    // identifiers no peer derives.
    let lagging_bound = bound_internal_presign_sessions(&test_state, lagging_validator);
    assert!(
        !lagging_bound.is_empty(),
        "validator 0 should have bound internal presign sessions after healing"
    );
    for peer_index in 1..test_state.dwallet_mpc_services.len() {
        let peer_bound = bound_internal_presign_sessions(&test_state, peer_index);
        for (session_identifier, sequence_number) in &lagging_bound {
            assert_eq!(
                peer_bound.get(session_identifier),
                Some(sequence_number),
                "validator {peer_index}: session {session_identifier:?} bound to a different \
                 sequence number than on validator 0 — identifier derivation diverged"
            );
        }
    }

    // === Phase 4: coda — an adopted key with NO resolvable NetworkKeyId ===
    // Adopted on every validator, junk DKG bytes so its installation fails,
    // and a random id that never underwent DKG so no `ObjectID → NetworkKeyId`
    // mapping exists for it anywhere. The session identifier and the per-pool
    // counters both key by the content-derived `NetworkKeyId`, which is
    // therefore unresolvable — the top-up loop must SKIP the key uniformly (a
    // should-never-happen: adoption defers an unmapped key in production), not
    // park it, fail it, or move any counter. Force k2_id above k1_id so the
    // NOA-key tie-break still keeps K0 as the signing key (equal
    // `dkg_at_epoch` → smallest id wins) and this coda leaves the pool roles
    // established above untouched.
    let k2_id = loop {
        let candidate = ObjectID::random();
        if candidate > k1_id {
            break candidate;
        }
    };
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service
            .dwallet_mpc_manager_mut()
            .adopted_network_key_data
            .insert(
                k2_id,
                DWalletNetworkEncryptionKeyData {
                    id: k2_id,
                    current_epoch: epoch_id,
                    dkg_at_epoch: epoch_id,
                    current_reconfiguration_public_output: vec![],
                    network_dkg_public_output: vec![7u8; 64],
                    state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
                },
            );
    }
    // Sanity: the key really is unresolvable on every validator (no installed
    // data, no mapping), so the skip branch is the one under test.
    for (service_index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        assert!(
            service
                .dwallet_mpc_manager()
                .internal_presign_network_key_id(&k2_id)
                .is_none(),
            "validator {service_index}: K2 must have no resolvable NetworkKeyId"
        );
    }

    // Counts K2-referencing parked batches on one validator — must stay zero
    // (the key is skipped before any request is built, so it never parks).
    let k2_parked_count = |test_state: &IntegrationTestState, service_index: usize| -> usize {
        test_state.dwallet_mpc_services[service_index]
            .dwallet_mpc_manager()
            .internal_presign_requests_pending_for_network_key_data
            .iter()
            .filter(|ParkedInternalPresignRequest(request)| {
                request.protocol_data.network_encryption_key_id() == Some(k2_id)
            })
            .count()
    };
    for _ in 0..3 {
        run_one_round_delivering_messages(&mut test_state).await;
        // The unresolvable key contributes nothing on any validator, so the
        // per-pool sequence counters (advanced only by the installed K0/K1
        // pools) stay identical committee-wide — the whole test's invariant.
        let reference_next_sequence_number = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .next_internal_presign_sequence_number
            .clone();
        for (service_index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
            assert_eq!(
                service
                    .dwallet_mpc_manager()
                    .next_internal_presign_sequence_number,
                reference_next_sequence_number,
                "validator {service_index}: sequence counters diverged after adopting the \
                 unresolvable key"
            );
            assert_eq!(
                k2_parked_count(&test_state, service_index),
                0,
                "validator {service_index}: an unresolvable adopted key must be skipped, not parked"
            );
            assert_eq!(
                failed_session_count(&test_state, service_index),
                0,
                "validator {service_index}: an unresolvable adopted key must not fail a session"
            );
        }
    }

    info!(
        "Test completed: multi-key install lag parks internal presign batches with sequence \
         numbers consumed, and an unresolvable adopted key is skipped uniformly, keeping \
         identifier derivation committee-uniform"
    );
}
