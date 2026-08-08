use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
    TEST_PRESIGN_CONSENSUS_ROUND_DELAY, TEST_PRESIGN_POOL_MAXIMUM_SIZE,
    TEST_PRESIGN_POOL_MINIMUM_SIZE, apply_test_presign_pool_overrides, build_test_state,
    create_test_protocol_config_guard,
};
use crate::dwallet_mpc::mpc_diagnostics::SessionOrigin;
use crate::dwallet_mpc::mpc_manager::{
    DWalletMPCManager, InternalPresignCompletionKey, ParkedInternalPresignRequest,
};
use crate::dwallet_mpc::mpc_session::{SessionComputationType, SessionStatus};
use crate::dwallet_mpc::{NetworkOwnedAddressSignRequest, ValidatorMpcKeysByPartyId};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::validator_metadata::OffChainCommitteeBundles;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm, NetworkKeyId,
};
use dwallet_rng::RootSeed;
use ika_protocol_config::ProtocolConfig;
use ika_types::crypto::AuthorityName;
use ika_types::message::{
    DWalletCheckpointMessageKind, MakeDWalletUserSecretKeySharesPublicOutput,
};
use ika_types::messages_dwallet_mpc::{
    DWalletMPCOutput, DWalletMPCOutputReport, DWalletNetworkEncryptionKeyData,
    DWalletNetworkEncryptionKeyState, SessionIdentifier, SessionType,
};
use std::collections::{BTreeSet, HashMap};
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
        service.run_service_loop_iteration().await;
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
        service.run_service_loop_iteration().await;
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
            service.run_service_loop_iteration().await;
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
            service.run_service_loop_iteration().await;
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
        let message = format!("idle-breaker-{}", idx).into_bytes();
        for sender in &test_state.network_owned_address_sign_request_senders {
            sender
                .send(NetworkOwnedAddressSignRequest {
                    message: message.clone(),
                    curve: DWalletCurve::Curve25519,
                    signature_algorithm: noa_sign_algorithm,
                    hash_scheme: noa_sign_hash_scheme,
                    demand_id: ika_types::noa_checkpoint::NOAPresignDemandId::GrpcAttestation(
                        ika_types::crypto::keccak256_digest(&message),
                    ),
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
            service.run_service_loop_iteration().await;
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
            service.run_service_loop_iteration().await;
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
            service.run_service_loop_iteration().await;
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
        * (test_state.dwallet_mpc_services.len() as u64 - test_state.committee.quorum_threshold());
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
        service.run_service_loop_iteration().await;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        round_after_k1 + 1,
    );
    test_state.consensus_round = (round_after_k1 + 2) as usize;
    for service in test_state.dwallet_mpc_services.iter_mut() {
        service.run_service_loop_iteration().await;
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

    // === Phase 5: completion-path classification ===
    // A completed internal-presign output whose key does not resolve moves no
    // counter either way, so the ONLY difference between "genuine invariant
    // violation" and "ordinary pre-adoption replay after a restart" is how
    // it is classified. Pin both directions: K2 is adopted-but-unresolvable
    // (the real should-never-happen), while an identical unresolvable key
    // that was never adopted is the post-restart replay shape — the one that
    // used to raise a false `should_never_happen=true` alarm on every
    // binary-swap restart (a burst of them in the v1.2.7 upgrade scenario).
    let never_adopted_id = ObjectID::random();
    for (service_index, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        assert!(
            manager
                .internal_presign_network_key_id(&never_adopted_id)
                .is_none(),
            "validator {service_index}: the never-adopted key must be unresolvable, so the two \
             cases differ only by adoption"
        );
        assert_eq!(
            manager.classify_internal_presign_completion(&k2_id),
            InternalPresignCompletionKey::AdoptedUnresolvable,
            "validator {service_index}: an ADOPTED key that cannot resolve is a genuine \
             should-never-happen"
        );
        assert_eq!(
            manager.classify_internal_presign_completion(&never_adopted_id),
            InternalPresignCompletionKey::NotAdopted,
            "validator {service_index}: a not-yet-adopted key is an ordinary pre-adoption \
             replay, not an invariant violation"
        );
        // The installed, adopted keys still resolve — the classification did
        // not turn the healthy path into a silent skip.
        assert!(
            matches!(
                manager.classify_internal_presign_completion(&k0_id),
                InternalPresignCompletionKey::Resolved(_)
            ),
            "validator {service_index}: an installed adopted key must still resolve"
        );
    }

    info!(
        "Test completed: multi-key install lag parks internal presign batches with sequence \
         numbers consumed, and an unresolvable adopted key is skipped uniformly, keeping \
         identifier derivation committee-uniform"
    );
}

/// The deterministic identifier every committee member derives for one
/// internal-presign ordinal of a (key, curve, algorithm) pool.
fn internal_presign_identifier_at(
    epoch_id: u64,
    ordinal: u64,
    curve: DWalletCurve,
    algorithm: DWalletSignatureAlgorithm,
    network_key_object_id: ObjectID,
    counter_network_key_id: NetworkKeyId,
) -> SessionIdentifier {
    DWalletSessionRequest::new_internal_presign(
        epoch_id,
        ordinal,
        curve,
        algorithm,
        network_key_object_id,
        &counter_network_key_id.0,
    )
    .session_identifier
}

/// Ordinals of one pool this manager MINTED itself (activated a local
/// request — `SessionOrigin::LocalRequest`), as opposed to entries
/// reconstructed from replayed consensus artifacts. Pool membership is proven
/// by re-deriving the identifier from the bound ordinal: a session whose
/// identifier matches is this pool's ordinal by construction.
fn locally_minted_pool_ordinals(
    manager: &DWalletMPCManager,
    curve: DWalletCurve,
    algorithm: DWalletSignatureAlgorithm,
    network_key_object_id: ObjectID,
    counter_network_key_id: NetworkKeyId,
) -> BTreeSet<u64> {
    manager
        .sessions
        .iter()
        .filter(|(_, session)| session.origin == SessionOrigin::LocalRequest)
        .filter_map(|(session_identifier, session)| {
            let ordinal = session.session_sequence_number?;
            (internal_presign_identifier_at(
                manager.epoch_id,
                ordinal,
                curve,
                algorithm,
                network_key_object_id,
                counter_network_key_id,
            ) == *session_identifier)
                .then_some(ordinal)
        })
        .collect()
}

/// Replaces validator 0's service with a fresh one over its EXISTING epoch
/// store — the in-process mid-epoch restart. Every channel end is replaced (a
/// fresh process re-creates them); the epoch store is the only survivor.
/// `last_session_to_complete_in_current_epoch` is restored directly, exactly
/// as the tests around network-key creation set it.
fn restart_validator_zero(
    test_state: &mut IntegrationTestState,
    seeds: &HashMap<AuthorityName, RootSeed>,
    bundles: &OffChainCommitteeBundles,
) {
    let authority = test_state.dwallet_mpc_services[0].name;
    let (service, senders, collector, notify, sign_request_sender, sign_output_receiver) =
        utils::create_dwallet_mpc_service_over_epoch_store(
            &authority,
            test_state.committee.clone(),
            seeds[&authority].clone(),
            bundles.clone(),
            test_state.epoch_stores[0].clone(),
        );
    test_state.dwallet_mpc_services[0] = service;
    test_state.sui_data_senders[0] = senders;
    test_state.sent_consensus_messages_collectors[0] = collector;
    test_state.notify_services[0] = notify;
    test_state.network_owned_address_sign_request_senders[0] = sign_request_sender;
    test_state.network_owned_address_sign_output_receivers[0] = sign_output_receiver;
    test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager_mut()
        .last_session_to_complete_in_current_epoch = 400;
}

/// Regression test for issue #1952: `next_internal_presign_sequence_number`
/// is in-memory, so a mid-epoch restart used to restart a pool's ordinal
/// stream at 1 — every post-restart mint re-minted an ordinal the committee
/// had already completed, each dead mint was "released" only by a live peer
/// completion, and the validator trailed the live ordinal window (sitting out
/// registry-driven instantiation) for the rest of the epoch. The fix lazily
/// seeds a pool's counter on first touch from the persisted
/// `filled_presign_pool_slots` high-water (+1), and the mint path
/// fast-forwards across ordinals whose replayed sessions are already
/// terminal.
///
/// Flow:
/// 1. Live committee fills the EdDSA pool; capture the persisted high-water H
///    and pin the live counter at H+1 (the rejoin target).
/// 2. Restart validator 0 over its surviving epoch store. Its EdDSA pool is
///    stuffed to max FIRST so the replay provably cannot mint for that pool
///    under either top-up condition — proving the seed is LAZY (first-mint),
///    not replay-driven.
/// 3. Replay the persisted history; assert the counter is still unseeded and
///    nothing was locally minted (history is reconstructed, never re-minted).
/// 4. Drain every validator's EdDSA pool and drive live rounds: the restarted
///    validator's first mint must land at EXACTLY H+1 (never 1), the pool's
///    counter must read identically committee-wide after every round, every
///    minted ordinal must bind to the same identifier on every peer, and the
///    new ordinals' fills must advance the persisted high-water past H.
/// 5. Coda (fast-forward): restart validator 0 once more with terminal
///    sessions planted at the two ordinals PAST the persisted high-water (the
///    shape where the seed read lags the replay frontier) and drive one
///    top-up directly: the mint must skip the terminal ordinals without
///    counting them against the batch guard, and park the live batch just
///    past them.
#[tokio::test]
#[cfg(test)]
async fn test_mid_epoch_restart_resumes_internal_presign_ordinals_from_pool_high_water() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    // Seeds are kept to rebuild validator 0 with the same identity (the same
    // class-groups decryption shares) after the simulated restarts.
    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services_with_committee_and_seeds(
        committee.clone(),
        seeds.clone(),
        bundles.clone(),
    );
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    };

    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // EdDSA: single-round presign, so its pool provably fills (and its
    // batches quorum-complete) within a few delivered rounds.
    let (curve, algorithm) = (DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);
    let epoch_id = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .epoch_id;
    let counter_network_key_id = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .internal_presign_network_key_id(&network_key_id)
        .expect("the DKG'd key must have a resolvable NetworkKeyId");
    let counter_key = (counter_network_key_id, curve, algorithm);

    // === Phase 1: live fills establish the persisted high-water ===
    // Run until the pool has persisted fills AND the batch guard is closed:
    // with every minted ordinal quorum-completed and deposited, the persisted
    // high-water IS the last live ordinal.
    let mut high_water = None;
    for _ in 0..60 {
        run_one_round_delivering_messages(&mut test_state).await;
        let (instantiated, completed) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        high_water = test_state.epoch_stores[0]
            .max_filled_presign_pool_slot(algorithm, network_key_id)
            .expect("max_filled_presign_pool_slot");
        if high_water.is_some() && instantiated > 0 && instantiated == completed {
            break;
        }
    }
    let high_water = high_water.expect("EdDSA fills should land within the phase 1 budget");

    // Precondition tying the persisted high-water to the live counter: the
    // restarted validator must rejoin exactly here.
    let live_next = *test_state.dwallet_mpc_services[1]
        .dwallet_mpc_manager()
        .next_internal_presign_sequence_number
        .get(&counter_key)
        .expect("peers must have minted EdDSA ordinals in phase 1");
    assert_eq!(
        live_next,
        high_water + 1,
        "precondition: with the guard closed, the persisted high-water is one behind the live counter"
    );

    // What the production syncer re-fetches for a fresh process: the network
    // key overlay (taken from a live peer's adopted view).
    let network_key_data = test_state.dwallet_mpc_services[1]
        .dwallet_mpc_manager()
        .adopted_network_key_data
        .get(&network_key_id)
        .expect("peers must have adopted the network key")
        .clone();

    // === Phase 2: restart validator 0 over its surviving epoch store ===
    // Stuff the restarting validator's EdDSA pool to max first: with the pool
    // at/above both thresholds, neither top-up condition can fire during the
    // replay, so an unseeded counter after the full replay proves the seed is
    // lazy. Slot 1 keeps the persisted high-water untouched.
    let stuffing: Vec<Vec<u8>> = (0..TEST_PRESIGN_POOL_MAXIMUM_SIZE)
        .map(|index| vec![index as u8; 8])
        .collect();
    test_state.epoch_stores[0]
        .insert_presigns(
            algorithm,
            network_key_id,
            1,
            SessionIdentifier::new(SessionType::InternalPresign, [77u8; 32]),
            stuffing,
        )
        .expect("insert_presigns");

    restart_validator_zero(&mut test_state, &seeds, &bundles);
    assert!(
        test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .next_internal_presign_sequence_number
            .is_empty(),
        "a fresh process must start with no in-memory ordinal state"
    );
    let _ = test_state.sui_data_senders[0]
        .network_keys_sender
        .send(Arc::new(HashMap::from([(
            network_key_id,
            network_key_data.clone(),
        )])));

    // Replay: the first iteration processes every persisted consensus round;
    // the key install completes asynchronously on later ticks.
    test_state.dwallet_mpc_services[0]
        .run_service_loop_iteration()
        .await;
    utils::run_service_loops_until_network_key_installed(
        &mut test_state.dwallet_mpc_services[0..1],
        network_key_id,
    )
    .await;
    assert_eq!(
        test_state.dwallet_mpc_services[0].last_read_consensus_round(),
        test_state.dwallet_mpc_services[1].last_read_consensus_round(),
        "the replay must catch the restarted validator up to its peers"
    );

    {
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        assert!(
            !manager
                .next_internal_presign_sequence_number
                .contains_key(&counter_key),
            "the ordinal stream must be seeded on first MINT, not by the replay"
        );
        assert!(
            locally_minted_pool_ordinals(
                manager,
                curve,
                algorithm,
                network_key_id,
                counter_network_key_id
            )
            .is_empty(),
            "the replay must reconstruct history, never mint"
        );
    }

    // === Phase 3: the restarted validator rejoins the live ordinal window ===
    // Drain every validator's EdDSA pool so the next delay-aligned round
    // provably fires the same top-up committee-wide.
    for epoch_store in &test_state.epoch_stores {
        while epoch_store
            .pop_presign(algorithm, network_key_id)
            .expect("pop_presign")
            .is_some()
        {}
    }

    let mut resumed = false;
    for _ in 0..40 {
        run_one_round_delivering_messages(&mut test_state).await;

        // Whenever the restarted validator's counter exists it must read
        // identically on every live peer — a pre-fix restart reads ~1 here
        // while the peers read H+1+k.
        let restarted_next = test_state.dwallet_mpc_services[0]
            .dwallet_mpc_manager()
            .next_internal_presign_sequence_number
            .get(&counter_key)
            .copied();
        if let Some(restarted_next) = restarted_next {
            assert!(
                restarted_next > high_water,
                "the restarted validator's ordinal counter must resume past the persisted \
                 high-water {high_water}, got {restarted_next}"
            );
            for peer_index in 1..test_state.dwallet_mpc_services.len() {
                assert_eq!(
                    test_state.dwallet_mpc_services[peer_index]
                        .dwallet_mpc_manager()
                        .next_internal_presign_sequence_number
                        .get(&counter_key)
                        .copied(),
                    Some(restarted_next),
                    "validator {peer_index}: the pool's ordinal counter diverged from the \
                     restarted validator's"
                );
            }
        }

        let (instantiated, completed) =
            presign_batch_counters(&test_state, 0, network_key_id, curve, algorithm);
        let refilled_high_water = test_state.epoch_stores[0]
            .max_filled_presign_pool_slot(algorithm, network_key_id)
            .expect("max_filled_presign_pool_slot")
            .unwrap_or(0);
        if instantiated > 0 && instantiated == completed && refilled_high_water > high_water {
            resumed = true;
            break;
        }
    }
    assert!(
        resumed,
        "the restarted validator must mint, complete, and persist fills at post-high-water ordinals"
    );

    let minted = locally_minted_pool_ordinals(
        test_state.dwallet_mpc_services[0].dwallet_mpc_manager(),
        curve,
        algorithm,
        network_key_id,
        counter_network_key_id,
    );
    assert_eq!(
        minted.first(),
        Some(&(high_water + 1)),
        "the first post-restart mint must land exactly one past the persisted high-water"
    );
    assert!(
        minted.iter().all(|&ordinal| ordinal > high_water),
        "post-restart mints re-used already-completed ordinals: {minted:?} (high-water {high_water})"
    );
    // Identifier uniformity: every ordinal the restarted validator minted is
    // bound to the SAME identifier on every live peer — the committee-wide
    // invariant a from-1 restart breaks.
    for peer_index in 1..test_state.dwallet_mpc_services.len() {
        let peer_manager = test_state.dwallet_mpc_services[peer_index].dwallet_mpc_manager();
        for &ordinal in &minted {
            let session_identifier = internal_presign_identifier_at(
                epoch_id,
                ordinal,
                curve,
                algorithm,
                network_key_id,
                counter_network_key_id,
            );
            assert_eq!(
                peer_manager
                    .sessions
                    .get(&session_identifier)
                    .and_then(|session| session.session_sequence_number),
                Some(ordinal),
                "validator {peer_index}: ordinal {ordinal} is not bound to the same session \
                 identifier as on the restarted validator"
            );
        }
    }

    // === Coda: fast-forward across terminal ordinals past the seed ===
    // The high-water is read ONCE, at the pool's first touch; fills whose
    // replay lands after that read leave terminal sessions at ordinals PAST
    // the seed. The mint path must skip them (they can never produce a
    // completion again) without counting them against the batch guard.
    let coda_high_water = test_state.epoch_stores[0]
        .max_filled_presign_pool_slot(algorithm, network_key_id)
        .expect("max_filled_presign_pool_slot")
        .expect("phase 3 refilled the pool");
    restart_validator_zero(&mut test_state, &seeds, &bundles);
    while test_state.epoch_stores[0]
        .pop_presign(algorithm, network_key_id)
        .expect("pop_presign")
        .is_some()
    {}

    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager_mut();
    // Adopt directly — the coda drives the top-up loop below without service
    // iterations, so no install ever completes: the live batch must PARK with
    // its ordinals consumed (the install-lag shape covered above).
    manager
        .adopted_network_key_data
        .insert(network_key_id, network_key_data.clone());
    let terminal_ordinals = [coda_high_water + 1, coda_high_water + 2];
    for &ordinal in &terminal_ordinals {
        let session_identifier = internal_presign_identifier_at(
            epoch_id,
            ordinal,
            curve,
            algorithm,
            network_key_id,
            counter_network_key_id,
        );
        manager.new_session(
            &session_identifier,
            SessionStatus::Completed,
            None,
            SessionComputationType::MPC {
                messages_by_consensus_round: HashMap::new(),
            },
        );
    }

    let batch_size = TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE;
    let coda_round = test_state.consensus_round as u64;
    manager.instantiate_internal_presign_sessions(
        coda_round,
        TEST_PRESIGN_CONSENSUS_ROUND_DELAY * 100,
        false,
    );

    assert_eq!(
        manager
            .next_internal_presign_sequence_number
            .get(&counter_key)
            .copied(),
        Some(coda_high_water + 2 + batch_size + 1),
        "the mint must seed at high-water+1, skip the two terminal ordinals, and mint the \
         batch just past them"
    );
    assert_eq!(
        manager
            .instantiated_internal_presign_sessions
            .get(&counter_key)
            .copied()
            .unwrap_or(0),
        batch_size,
        "only live mints may count against the batch guard — a fast-forwarded ordinal never \
         produces a completion"
    );
    for &ordinal in &terminal_ordinals {
        let session_identifier = internal_presign_identifier_at(
            epoch_id,
            ordinal,
            curve,
            algorithm,
            network_key_id,
            counter_network_key_id,
        );
        assert!(
            matches!(
                manager
                    .sessions
                    .get(&session_identifier)
                    .map(|session| &session.status),
                Some(SessionStatus::Completed)
            ),
            "ordinal {ordinal}: a terminal session must be skipped, not re-activated"
        );
    }
    let parked_pool_ordinals: BTreeSet<u64> = manager
        .internal_presign_requests_pending_for_network_key_data
        .iter()
        .filter_map(|ParkedInternalPresignRequest(request)| {
            let ordinal = request.session_sequence_number?;
            (internal_presign_identifier_at(
                epoch_id,
                ordinal,
                curve,
                algorithm,
                network_key_id,
                counter_network_key_id,
            ) == request.session_identifier)
                .then_some(ordinal)
        })
        .collect();
    let expected_live_ordinals: BTreeSet<u64> =
        (coda_high_water + 3..=coda_high_water + 2 + batch_size).collect();
    assert_eq!(
        parked_pool_ordinals, expected_live_ordinals,
        "the live batch must park (no install on the fresh manager) at exactly the ordinals \
         past the terminal run"
    );

    // The batch guard must see the parked live mints as in-flight: a second
    // delay-aligned pass may not mint again until they complete.
    manager.instantiate_internal_presign_sessions(
        coda_round + TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        TEST_PRESIGN_CONSENSUS_ROUND_DELAY * 101,
        false,
    );
    assert_eq!(
        manager
            .next_internal_presign_sequence_number
            .get(&counter_key)
            .copied(),
        Some(coda_high_water + 2 + batch_size + 1),
        "the guard must hold while the parked live batch is outstanding"
    );

    info!(
        "Test completed: a mid-epoch restart resumes the internal-presign ordinal stream from \
         the persisted pool-slot high-water, and the mint path fast-forwards terminal ordinals \
         without wedging the batch guard"
    );
}

/// Reads one pool's `(next mint ordinal, consensus completion frontier)` on
/// one validator. Both are `None` until that validator has, respectively,
/// minted for the pool and seen one of its completions in the consensus
/// stream.
fn pool_ordinal_state(
    test_state: &IntegrationTestState,
    service_index: usize,
    counter_key: (NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm),
) -> (Option<u64>, Option<u64>) {
    let manager = test_state.dwallet_mpc_services[service_index].dwallet_mpc_manager();
    (
        manager
            .next_internal_presign_sequence_number
            .get(&counter_key)
            .copied(),
        manager
            .highest_completed_internal_presign_ordinal
            .get(&counter_key)
            .copied(),
    )
}

/// The two internal-presign ordinal-convergence metrics of one validator for
/// one pool: `(lag gauge, fast-forwarded ordinals counter)`.
fn pool_ordinal_metrics(
    test_state: &IntegrationTestState,
    service_index: usize,
    curve: DWalletCurve,
    algorithm: DWalletSignatureAlgorithm,
    key_role: &str,
) -> (i64, u64) {
    let metrics = &test_state.dwallet_mpc_services[service_index]
        .dwallet_mpc_manager()
        .dwallet_mpc_metrics;
    let labels = [
        curve.to_string(),
        algorithm.to_string(),
        key_role.to_string(),
    ];
    let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
    (
        metrics
            .internal_presign_ordinal_lag
            .with_label_values(&labels)
            .get(),
        metrics
            .internal_presign_ordinals_fast_forwarded_total
            .with_label_values(&labels)
            .get(),
    )
}

/// Fills one validator's pool past its maximum so no top-up condition can fire
/// for it — pinning it OUT of minting while its peers keep going. The stuffing
/// occupies one pool slot, so a distinct `slot` (and identifier) is needed per
/// call: both the real store and this harness treat a re-filled slot as a
/// replay and drop it.
fn pin_validator_out_of_minting(
    test_state: &IntegrationTestState,
    service_index: usize,
    algorithm: DWalletSignatureAlgorithm,
    network_key_object_id: ObjectID,
    slot: u64,
) {
    let stuffing: Vec<Vec<u8>> = (0..TEST_PRESIGN_POOL_MAXIMUM_SIZE)
        .map(|index| vec![index as u8; 8])
        .collect();
    test_state.epoch_stores[service_index]
        .insert_presigns(
            algorithm,
            network_key_object_id,
            slot,
            SessionIdentifier::new(SessionType::InternalPresign, [slot as u8; 32]),
            stuffing,
        )
        .expect("insert_presigns");
}

/// Empties the given validators' pool for one algorithm, so the next
/// delay-aligned round fires their top-up.
fn drain_pools(
    test_state: &IntegrationTestState,
    service_indices: impl IntoIterator<Item = usize>,
    algorithm: DWalletSignatureAlgorithm,
    network_key_object_id: ObjectID,
) {
    for service_index in service_indices {
        while test_state.epoch_stores[service_index]
            .pop_presign(algorithm, network_key_object_id)
            .expect("pop_presign")
            .is_some()
        {}
    }
}

/// Regression test for issue #1830: a per-pool internal-presign ordinal
/// counter that has fallen inside already-completed history must rejoin the
/// committee's live window from the consensus output stream alone.
///
/// The counters are in-memory while a pool's ordinal stream belongs to the
/// epoch, so a validator can end up minting identifiers the committee
/// finished long ago. Those mints can never produce live work (peers
/// early-return on an already-resolved identifier), and the offset advances in
/// lockstep with the live window — constant offset, zero closing speed — so
/// the validator contributes nothing to that pool for the rest of the epoch
/// while every event-driven path still looks healthy. Above f stake in that
/// state starves the pool below the MPC threshold.
///
/// The heal: every completed internal-presign output carries its
/// `session_sequence_number`, so the committee's completion frontier is
/// consensus-anchored data every validator holds regardless of what it
/// instantiated, what its store persisted, or whether it was in the pool when
/// the ordinal was minted. A counter at-or-below that frontier jumps past it.
///
/// **The diverged counter is constructed directly here.** The pre-existing
/// (#1952) machinery already converges the reachable in-process topologies —
/// it seeds a pool's counter from the persisted fill high-water and walks past
/// terminal replayed sessions — but both of its sources are local, and both
/// are consulted only at a pool's first mint or while a top-up is firing. What
/// this test pins is the rule that has neither restriction: whatever put the
/// counter inside completed history (a seed source that was unavailable or
/// behind at the pool's one seeding opportunity, a store holding none of the
/// epoch's fills, a future regression), a live counter is repaired from
/// consensus data, without a mint of its own and in one step.
///
/// Flow:
/// 1. The committee advances the pool's ordinal stream past its first batch
///    and quiesces with the in-flight batch guard closed.
/// 2. Validator 0 is pinned out of minting (pool stuffed to its maximum) and
///    its counter is dragged back to ordinal 1. Driving the top-up loop must
///    export the full distance to the frontier on the
///    `internal_presign_ordinal_lag` gauge — the divergence signal that did
///    not exist while this defect sat open.
/// 3. Peers resume minting. Their completions alone must fast-forward the
///    counter to the frontier — with no mint on validator 0, which is pinned —
///    the fast-forward counter must record the skipped ordinals, and the gauge
///    must return to 0.
/// 4. Unpinned, validator 0 must then mint LIVE ordinals that every peer binds
///    to the same session identifier: the rejoin is usable, not just a number.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_ordinal_stream_rejoins_from_consensus_completions() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // EdDSA: single-round presign, so its batches provably quorum-complete
    // within a handful of delivered rounds.
    let (curve, algorithm) = (DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);
    let batch_size = TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE;
    let epoch_id = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .epoch_id;
    let counter_network_key_id = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .internal_presign_network_key_id(&network_key_id)
        .expect("the DKG'd key must have a resolvable NetworkKeyId");
    let counter_key = (counter_network_key_id, curve, algorithm);
    // The only key of this epoch serves network-owned-address signing, so its
    // pools carry that `key_role` metric label.
    let key_role = "network_owned_address_signing";
    let peer_indices: Vec<usize> = (1..test_state.dwallet_mpc_services.len()).collect();

    // === Phase 1: the committee advances the pool's ordinal stream ===
    // More than one batch deep, so ordinal 1 is provably inside completed
    // history; guard closed, so the committee's next ordinal is exactly one
    // past its completion frontier.
    let mut advanced = false;
    for _ in 0..80 {
        run_one_round_delivering_messages(&mut test_state).await;
        let (instantiated, completed) =
            presign_batch_counters(&test_state, 1, network_key_id, curve, algorithm);
        let (_, frontier) = pool_ordinal_state(&test_state, 1, counter_key);
        if instantiated > 0
            && instantiated == completed
            && frontier.is_some_and(|frontier| frontier > batch_size + 1)
        {
            advanced = true;
            break;
        }
    }
    assert!(
        advanced,
        "the committee should have completed more than one EdDSA presign batch within the \
         phase 1 budget"
    );
    let (live_next, live_frontier) = pool_ordinal_state(&test_state, 1, counter_key);
    let live_next = live_next.expect("peers minted in phase 1");
    let live_frontier = live_frontier.expect("peers completed in phase 1");
    assert_eq!(
        live_next,
        live_frontier + 1,
        "precondition: with the guard closed the committee's next ordinal is one past its \
         completion frontier"
    );

    // === Phase 2: validator 0's stream is inside completed history ===
    pin_validator_out_of_minting(&test_state, 0, algorithm, network_key_id, 1);
    let minted_while_diverged = locally_minted_pool_ordinals(
        test_state.dwallet_mpc_services[0].dwallet_mpc_manager(),
        curve,
        algorithm,
        network_key_id,
        counter_network_key_id,
    );
    let diverged_round = test_state.consensus_round as u64;
    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager_mut();
    manager
        .next_internal_presign_sequence_number
        .insert(counter_key, 1);
    let pinned_frontier = manager
        .highest_completed_internal_presign_ordinal
        .get(&counter_key)
        .copied()
        .expect("validator 0 has observed this pool's completions");
    // Drive the export site (the top-up loop) with the counter still behind:
    // the heal closes the gap inside the same call that observes a completion,
    // so this is the only way to sample the gauge mid-divergence.
    manager.instantiate_internal_presign_sessions(
        diverged_round,
        TEST_PRESIGN_CONSENSUS_ROUND_DELAY * 200,
        false,
    );
    let (diverged_lag, fast_forwarded_before_heal) =
        pool_ordinal_metrics(&test_state, 0, curve, algorithm, key_role);
    assert_eq!(
        diverged_lag, pinned_frontier as i64,
        "the ordinal-lag gauge must report the full distance from the local stream to the \
         committee's completed frontier"
    );
    assert_eq!(
        locally_minted_pool_ordinals(
            test_state.dwallet_mpc_services[0].dwallet_mpc_manager(),
            curve,
            algorithm,
            network_key_id,
            counter_network_key_id,
        ),
        minted_while_diverged,
        "precondition: a validator whose pool is full must not mint, so any repair below comes \
         from the output stream"
    );

    // === Phase 3: the peers' completions alone must heal it ===
    drain_pools(&test_state, peer_indices.clone(), algorithm, network_key_id);
    let mut healed = None;
    let mut saw_positive_lag = false;
    for _ in 0..60 {
        run_one_round_delivering_messages(&mut test_state).await;
        // The top-up loop exports the gauge from the state it sees at the top
        // of the round, so a round that heals still publishes the divergence
        // it started with — the shape an operator scrapes.
        let (lag, _) = pool_ordinal_metrics(&test_state, 0, curve, algorithm, key_role);
        saw_positive_lag |= lag > 0;
        let (next, frontier) = pool_ordinal_state(&test_state, 0, counter_key);
        if let (Some(next), Some(frontier)) = (next, frontier)
            && next > live_frontier
        {
            healed = Some((next, frontier));
            break;
        }
    }
    let (healed_next, healed_frontier) = healed.expect(
        "a counter sitting inside already-completed history must be fast-forwarded to the \
         committee's frontier by the consensus output stream",
    );
    assert_eq!(
        healed_next,
        healed_frontier + 1,
        "the fast-forward must land exactly one past the observed completion frontier"
    );
    assert_eq!(
        locally_minted_pool_ordinals(
            test_state.dwallet_mpc_services[0].dwallet_mpc_manager(),
            curve,
            algorithm,
            network_key_id,
            counter_network_key_id,
        ),
        minted_while_diverged,
        "the pinned validator must not have minted: the repair came from the output stream, not \
         from the mint path"
    );
    assert!(
        saw_positive_lag,
        "the ordinal-lag gauge must publish the divergence while the stream is inside \
         already-completed history"
    );
    // The gauge is published by the top-up loop, so it settles one export
    // after the jump that healed the counter.
    let mut lag_settled = false;
    for _ in 0..10 {
        run_one_round_delivering_messages(&mut test_state).await;
        if pool_ordinal_metrics(&test_state, 0, curve, algorithm, key_role).0 == 0 {
            lag_settled = true;
            break;
        }
    }
    assert!(
        lag_settled,
        "the ordinal-lag gauge must return to 0 once the stream has rejoined the frontier"
    );
    let (_, fast_forwarded_after_heal) =
        pool_ordinal_metrics(&test_state, 0, curve, algorithm, key_role);
    assert!(
        fast_forwarded_after_heal > fast_forwarded_before_heal,
        "the fast-forward counter must record the skipped ordinals ({fast_forwarded_after_heal} \
         vs {fast_forwarded_before_heal})"
    );

    // === Phase 4: the rejoined stream mints ordinals the committee agrees on ===
    drain_pools(
        &test_state,
        0..test_state.dwallet_mpc_services.len(),
        algorithm,
        network_key_id,
    );
    let mut minted_live = None;
    for _ in 0..60 {
        run_one_round_delivering_messages(&mut test_state).await;
        let live_minted: BTreeSet<u64> = locally_minted_pool_ordinals(
            test_state.dwallet_mpc_services[0].dwallet_mpc_manager(),
            curve,
            algorithm,
            network_key_id,
            counter_network_key_id,
        )
        .into_iter()
        .filter(|&ordinal| ordinal > live_frontier)
        .collect();
        // Bound to the same identifier on every peer: an identifier the
        // committee does not derive identically is the divergence this pool
        // cannot have.
        let bound_everywhere = live_minted.iter().all(|&ordinal| {
            let session_identifier = internal_presign_identifier_at(
                epoch_id,
                ordinal,
                curve,
                algorithm,
                network_key_id,
                counter_network_key_id,
            );
            peer_indices.iter().all(|&peer_index| {
                test_state.dwallet_mpc_services[peer_index]
                    .dwallet_mpc_manager()
                    .sessions
                    .get(&session_identifier)
                    .and_then(|session| session.session_sequence_number)
                    == Some(ordinal)
            })
        });
        if !live_minted.is_empty() && bound_everywhere {
            minted_live = Some(live_minted);
            break;
        }
    }
    let minted_live = minted_live.expect(
        "after the heal the rejoined validator must mint LIVE ordinals that every peer binds to \
         the same session identifier",
    );
    let (final_lag, _) = pool_ordinal_metrics(&test_state, 0, curve, algorithm, key_role);
    assert_eq!(
        final_lag, 0,
        "a validator minting live ordinals must report no internal-presign ordinal lag"
    );

    info!(
        ?minted_live,
        "Test completed: an internal-presign ordinal counter dragged into already-completed \
         history rejoined the committee's live window from the consensus output stream alone, \
         and the divergence was exported as a gauge while it lasted"
    );
}

/// A byzantine peer must not be able to strand an internal-presign ordinal by
/// pre-claiming its session with a "native" output.
///
/// Internal-presign session identifiers are derived from public data alone
/// (epoch, pool ordinal, curve, algorithm, network key), so any committee
/// member can compute a future ordinal's identifier and report an output for it
/// before anyone has instantiated the session. The output-receipt path creates
/// a placeholder whose computation type comes from the SENDER's `is_native()`
/// flag, so that placeholder can arrive typed `Native`.
///
/// Instantiation then finds the placeholder and upgrades it in place. If the
/// upgrade leaves the type alone, the session runs `Active` + `Native`: every
/// peer's round message is dropped by `add_message`, and the computation routes
/// to the native path and fails `InvalidDWalletProtocolType` on every tick. The
/// ordinal never completes, so the pool's in-flight top-up guard stays closed
/// until the stale-batch expiry — one message per ordinal, from one validator,
/// starving the pool that user presigns are served from.
///
/// Asserts the placeholder really is `Native` before instantiation (the
/// precondition the attack needs), that instantiation normalizes it back to a
/// fresh MPC buffer, and that the ordinal then goes on to complete.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_instantiation_normalizes_byzantine_native_placeholder() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);
    let (consensus_round, _network_key_bytes, network_key_object_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    let curve = DWalletCurve::Secp256k1;
    let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
    let target = 0usize;
    let byzantine_authority = test_state
        .committee
        .names()
        .nth(1)
        .copied()
        .expect("committee has a second member");

    // Derive the identifier of the ordinal the target will mint next, from the
    // same public inputs an attacker has — nothing here observes the target.
    let (poisoned_identifier, poisoned_ordinal) = {
        let manager = test_state.dwallet_mpc_services[target].dwallet_mpc_manager();
        let counter_network_key_id = manager
            .internal_presign_network_key_id(&network_key_object_id)
            .expect("the bootstrapped network key must resolve a NetworkKeyId");
        let ordinal = manager
            .next_internal_presign_sequence_number
            .get(&(counter_network_key_id, curve, algorithm))
            .copied()
            .unwrap_or(1);
        (
            internal_presign_identifier_at(
                manager.epoch_id,
                ordinal,
                curve,
                algorithm,
                network_key_object_id,
                counter_network_key_id,
            ),
            ordinal,
        )
    };
    assert!(
        !test_state.dwallet_mpc_services[target]
            .dwallet_mpc_manager()
            .sessions
            .contains_key(&poisoned_identifier),
        "ordinal {poisoned_ordinal} must not be instantiated yet for the attack to apply"
    );

    // The byzantine peer reports an output for that not-yet-requested ordinal.
    let poison = DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority: byzantine_authority,
        session_identifier: poisoned_identifier,
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
            .get(&poisoned_identifier)
            .expect("the poison output should have created a placeholder on the target");
        assert!(
            matches!(session.status, SessionStatus::WaitingForSessionRequest),
            "the poisoned placeholder should be WaitingForSessionRequest"
        );
        assert!(
            !matches!(session.computation_type, SessionComputationType::MPC { .. }),
            "the poisoned placeholder should be typed Native (the attack precondition)"
        );
    }

    // Run until the target mints that ordinal and leaves the placeholder state.
    const MAX_ACTIVATION_ROUNDS: usize = 40;
    let mut activation_rounds = 0usize;
    while matches!(
        test_state.dwallet_mpc_services[target]
            .dwallet_mpc_manager()
            .sessions
            .get(&poisoned_identifier)
            .map(|session| &session.status),
        Some(SessionStatus::WaitingForSessionRequest)
    ) {
        run_one_round_delivering_messages(&mut test_state).await;
        activation_rounds += 1;
        assert!(
            activation_rounds < MAX_ACTIVATION_ROUNDS,
            "the target never instantiated ordinal {poisoned_ordinal} within \
             {MAX_ACTIVATION_ROUNDS} rounds"
        );
    }

    // Instantiation must have discarded the poisoned type.
    {
        let session = test_state.dwallet_mpc_services[target]
            .dwallet_mpc_manager()
            .sessions
            .get(&poisoned_identifier)
            .expect("the target should still hold the session after instantiation");
        assert!(
            matches!(session.computation_type, SessionComputationType::MPC { .. }),
            "instantiation must normalize the byzantine Native placeholder back to an MPC buffer"
        );
    }

    // And the ordinal must go on to complete: normalizing the type is only
    // worth anything if the session it unblocks actually produces its presign.
    const MAX_COMPLETION_ROUNDS: usize = 40;
    let mut completion_rounds = 0usize;
    loop {
        let status_is_complete = {
            let session = test_state.dwallet_mpc_services[target]
                .dwallet_mpc_manager()
                .sessions
                .get(&poisoned_identifier)
                .expect("the target should still hold the session");
            assert!(
                !matches!(session.status, SessionStatus::Failed),
                "the poisoned ordinal must not fail after normalization"
            );
            matches!(
                session.status,
                SessionStatus::Completed | SessionStatus::ComputationCompleted
            )
        };
        if status_is_complete {
            break;
        }
        run_one_round_delivering_messages(&mut test_state).await;
        completion_rounds += 1;
        assert!(
            completion_rounds < MAX_COMPLETION_ROUNDS,
            "the normalized ordinal {poisoned_ordinal} never completed within \
             {MAX_COMPLETION_ROUNDS} rounds"
        );
    }

    info!(
        poisoned_ordinal,
        activation_rounds,
        completion_rounds,
        "a byzantine Native placeholder on an internal-presign ordinal was normalized at \
         instantiation and the ordinal completed"
    );
}
