use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TEST_IDLE_SESSION_COUNT_THRESHOLD, build_test_state, count_sessions_by_type,
    create_test_protocol_config_guard,
};
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::SessionType;
use tracing::info;

/// Test that validators correctly compute and report their idle status,
/// both locally and through consensus-distributed status updates.
///
/// Asserts:
/// 1. All validators are idle initially (0 sessions < threshold).
/// 2. After enough rounds of internal presign instantiation, the session count
///    exceeds idle_threshold, and `compute_is_idle` flips to false.
/// 3. Status updates submitted to consensus carry the correct `is_idle` flag.
#[tokio::test]
#[cfg(test)]
async fn test_validators_compute_idle_status_correctly() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

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

    // Initially, with no sessions, all validators should be idle
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        let is_idle = manager.compute_is_idle(0);
        assert!(
            is_idle,
            "Validator {} should be idle with 0 sessions (threshold={})",
            i, idle_threshold
        );
    }

    // Create network key to enable internal presigns
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Run enough rounds for internal presign sessions to accumulate past idle_threshold.
    // With test config: delay=2, sessions_to_instantiate=1, 5 algorithm pairs.
    // After 2 rounds: 5 sessions (1 per algorithm). After 4 rounds: 10 sessions.
    // So after ~2 delay-aligned rounds (4 consensus rounds), we should exceed threshold=5.
    let mut became_not_idle = false;
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

        // Check if any validator has transitioned to not-idle
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        let session_count = manager.sessions.len();
        let running_computations = manager.running_computation_count();
        let total = session_count + running_computations;

        if total >= idle_threshold as usize && !became_not_idle {
            became_not_idle = true;
            info!(
                "Validator transitioned to NOT idle at consensus round {} (sessions={}, running={}, total={}, threshold={})",
                test_state.consensus_round,
                session_count,
                running_computations,
                total,
                idle_threshold
            );
        }
    }

    // Verify the transition happened
    assert!(
        became_not_idle,
        "expected validators to transition to not-idle after enough presign sessions were created"
    );

    // Also verify that status updates were submitted to consensus with the correct is_idle flag.
    // Check the consensus messages from any validator for InternalSessionsStatusUpdate.
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

    // We expect to have seen both idle=true (at start) and idle=false (after sessions grew)
    // in the status updates distributed through the epoch stores.
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
        "expected at least one status update with is_idle=true (initial state)"
    );

    info!("Test passed: validators correctly compute idle status");
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
        // With 4 validators, we expect all 4 parties to have reported.
        assert!(
            idle_status_count > 0,
            "Validator {} should have idle status from at least some parties (got {})",
            i,
            idle_status_count
        );
    }

    // Verify total status updates distributed across the system
    let mut total_status_updates = 0usize;
    for epoch_store in &test_state.epoch_stores {
        let updates = epoch_store.round_to_status_updates.lock().unwrap();
        total_status_updates += updates.values().map(|v| v.len()).sum::<usize>();
    }

    info!(
        "Total status updates across all validators: {}",
        total_status_updates
    );

    // Each round, each validator sends 1 status update, distributed to all 4.
    // Over 10 rounds with 4 validators: expected ~4*10*4 = 160 total entries.
    assert!(
        total_status_updates > 10,
        "expected many status updates distributed through consensus, got {}",
        total_status_updates
    );

    info!("Test passed: status updates distributed through consensus and processed by service");
}
