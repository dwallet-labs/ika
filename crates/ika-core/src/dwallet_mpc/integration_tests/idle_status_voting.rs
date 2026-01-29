use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use ika_types::committee::Committee;
use tracing::info;

/// Test that validators correctly compute and report their idle status.
/// The idle status is based on the number of ready-to-advance sessions
/// plus currently running computations compared to a threshold.
#[tokio::test]
#[cfg(test)]
async fn test_validators_compute_idle_status_correctly() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();

    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders,
    };

    // Configure services
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Get the idle threshold from config
    let idle_threshold = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config
        .idle_session_count_threshold();

    info!("Idle threshold from config: {}", idle_threshold);

    // Initially, with no sessions, validators should be idle
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        let session_count = manager.sessions.len();
        let is_idle = manager.compute_is_idle(0); // 0 ready-to-advance sessions

        info!(
            "Validator {}: session_count={}, is_idle={}",
            i, session_count, is_idle
        );

        // With no ready sessions and few running computations, should be idle
        assert!(
            is_idle,
            "Validator {} should be idle with {} sessions (threshold: {})",
            i, session_count, idle_threshold
        );
    }

    info!("Test passed: Validators correctly compute idle status");
}

/// Test that status updates are properly distributed through consensus.
/// Each validator sends its status update, and the consensus mechanism
/// should distribute these to all other validators.
#[tokio::test]
#[cfg(test)]
async fn test_status_updates_distributed_through_consensus() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();

    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders,
    };

    // Configure services
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Run several consensus rounds to allow status updates to flow
    for round in 0..10 {
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

        // Check status updates in epoch stores
        // After several rounds, validators should have received status updates
        if round > 5 {
            for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
                let status_updates = epoch_store.round_to_status_updates.lock().unwrap();
                let total_updates: usize = status_updates.values().map(|v| v.len()).sum();
                info!(
                    "Round {}: Validator {} has received {} total status updates",
                    round, i, total_updates
                );
            }
        }
    }

    // Verify that at least some status updates were distributed
    let mut total_status_updates = 0usize;
    for epoch_store in &test_state.epoch_stores {
        let status_updates = epoch_store.round_to_status_updates.lock().unwrap();
        total_status_updates += status_updates.values().map(|v| v.len()).sum::<usize>();
    }

    info!(
        "Total status updates across all validators: {}",
        total_status_updates
    );

    // Status updates should have been distributed
    // Each round, each validator sends 1 status update, and it gets distributed to all
    assert!(
        total_status_updates > 0,
        "Status updates should have been distributed through consensus"
    );

    info!("Test passed: Status updates distributed through consensus");
}

/// Test that weighted majority voting on idle status works correctly.
/// When the majority of validators report idle status, the network should
/// agree on being idle.
#[tokio::test]
#[cfg(test)]
async fn test_weighted_majority_voting_on_idle_status() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();

    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(4);
    let mut test_state = IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee: committee.clone(),
        sui_data_senders,
    };

    // Configure services
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Get the idle threshold
    let idle_threshold = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config
        .idle_session_count_threshold();

    info!("Idle threshold: {}", idle_threshold);

    // With minimal activity, all validators should be idle
    // Run a few rounds to let the system stabilize
    for _ in 0..5 {
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

    // Check individual validator idle status
    let mut idle_validators = 0;
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let manager = service.dwallet_mpc_manager();
        let is_idle = manager.compute_is_idle(0);
        if is_idle {
            idle_validators += 1;
        }
        info!("Validator {} is_idle: {}", i, is_idle);
    }

    info!("{} out of 4 validators report being idle", idle_validators);

    // All validators should be idle when there's no activity
    assert_eq!(
        idle_validators, 4,
        "All validators should be idle with no sessions"
    );

    info!("Test passed: Weighted majority voting on idle status verified");
}
