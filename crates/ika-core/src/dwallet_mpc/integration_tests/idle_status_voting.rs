use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_IDLE_SESSION_COUNT_THRESHOLD, build_test_state, create_test_protocol_config_guard,
};
use ika_protocol_config::ProtocolConfig;
use ika_types::messages_consensus::ConsensusTransactionKind;
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

        config.set_internal_sign_presign_pool_minimum_size_for_testing(pool_minimum);
        config.set_internal_sign_presign_pool_maximum_size_for_testing(pool_maximum);
        config.set_internal_sign_presign_consensus_round_delay_for_testing(delay);
        config
            .set_internal_sign_presign_sessions_to_instantiate_for_testing(sessions_to_instantiate);

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

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

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

    // Also verify that status updates were submitted to consensus with the correct is_idle flag.
    let mut found_idle_true = false;
    let mut found_idle_false = false;
    for collector in &test_state.sent_consensus_messages_collectors {
        let messages = collector.submitted_messages.lock().unwrap();
        for msg in messages.iter() {
            if let ConsensusTransactionKind::InternalSessionsStatusUpdate(update) = &msg.kind {
                if update.is_idle {
                    found_idle_true = true;
                } else {
                    found_idle_false = true;
                }
            }
        }
    }

    // We expect to have seen both idle=true and idle=false in status updates
    // distributed through the epoch stores.
    for epoch_store in &test_state.epoch_stores {
        let status_updates = epoch_store.round_to_status_updates.lock().unwrap();
        for updates in status_updates.values() {
            for update in updates {
                if update.is_idle {
                    found_idle_true = true;
                } else {
                    found_idle_false = true;
                }
            }
        }
    }

    assert!(
        found_idle_true,
        "expected at least one status update with is_idle=true"
    );
    assert!(
        found_idle_false,
        "expected at least one status update with is_idle=false after sessions exceeded threshold"
    );

    info!("Test passed: validators correctly compute idle status via consensus");
}

/// Test that status updates are properly distributed through consensus and
/// that the service reads and processes them (not just the test harness).
///
/// Verifies:
/// 1. Each validator submits InternalSessionsStatusUpdate to consensus each round.
/// 2. After distribution, each validator's epoch store has status updates from all others.
/// 3. The service reads these via `next_internal_sessions_status_update` and processes them.
#[tokio::test]
#[cfg(test)]
async fn test_status_updates_distributed_through_consensus() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

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

        // Count status updates submitted by each validator
        let status_update_count: usize = test_state
            .sent_consensus_messages_collectors
            .iter()
            .map(|collector| {
                collector
                    .submitted_messages
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|msg| {
                        matches!(
                            msg.kind,
                            ConsensusTransactionKind::InternalSessionsStatusUpdate(_)
                        )
                    })
                    .count()
            })
            .sum();

        // Distribute results to all parties
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        if round > 3 {
            // After a few rounds, verify each epoch store has received status updates
            for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
                let updates = epoch_store.round_to_status_updates.lock().unwrap();
                let total: usize = updates.values().map(|v| v.len()).sum();
                info!(
                    "Round {}: Validator {} has {} total status updates in epoch store",
                    round, i, total
                );
                assert!(
                    total > 0,
                    "Validator {} should have received status updates by round {}",
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
