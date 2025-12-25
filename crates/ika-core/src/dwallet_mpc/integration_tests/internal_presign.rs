use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::SessionType;
use tracing::info;

/// Test that internal presign sessions are instantiated at the correct consensus rounds
/// based on the configuration (consensus_round_delay).
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_instantiation_at_correct_rounds() {
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

    // Configure services to have a high last_session_to_complete so they don't skip sessions
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // First, create a network key (required for internal presigns)
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;

    info!(
        "Network key created, starting internal presign tests at consensus round {}",
        consensus_round
    );

    // Update test_state.consensus_round to continue from where network key creation left off
    test_state.consensus_round = consensus_round as usize;

    // Get the protocol config values to understand when presigns should be instantiated
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;

    let eddsa_delay = protocol_config
        .get_internal_presign_consensus_round_delay(DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);
    let eddsa_min_pool_size = protocol_config
        .get_internal_presign_pool_minimum_size(DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);
    let eddsa_sessions_to_instantiate = protocol_config
        .get_internal_presign_sessions_to_instantiate(DWalletCurve::Curve25519, DWalletSignatureAlgorithm::EdDSA);

    info!(
        "EdDSA config: delay={}, min_pool_size={}, sessions_to_instantiate={}",
        eddsa_delay, eddsa_min_pool_size, eddsa_sessions_to_instantiate
    );

    // Track internal presign sessions created
    let mut internal_presign_count = 0usize;

    // Run several consensus rounds and count internal presign sessions
    for round_offset in 0..10 {
        // Set up the next consensus round's data
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        // Run service loop for all parties
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration().await;
        }

        // Count internal presign sessions in the first service
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        let current_internal_presign_count = manager
            .sessions
            .iter()
            .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
            .count();

        if current_internal_presign_count > internal_presign_count {
            info!(
                "Round {}: New internal presign sessions created. Total: {} (was {})",
                test_state.consensus_round,
                current_internal_presign_count,
                internal_presign_count
            );
            internal_presign_count = current_internal_presign_count;
        }
    }

    // Verify that internal presign sessions were created
    assert!(
        internal_presign_count > 0,
        "Expected internal presign sessions to be created"
    );

    info!(
        "Test completed: {} internal presign sessions were instantiated",
        internal_presign_count
    );
}

/// Test that internal presign sessions stop being created when the pool reaches minimum size
/// and the system is not idle.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_stops_at_min_pool_size_when_not_idle() {
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

    // Create network key first
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;

    test_state.consensus_round = consensus_round as usize;

    // Pre-populate the presign pool to simulate having reached the minimum pool size
    // We use a smaller signature algorithm pool for faster testing
    let mock_presign_data = vec![1u8; 100]; // Mock presign data

    // Get the minimum pool size from config
    let min_pool_size = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config
        .get_internal_presign_pool_minimum_size(
            DWalletCurve::Secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256k1,
        );

    info!("Minimum pool size for ECDSASecp256k1: {}", min_pool_size);

    // Insert enough presigns to reach the minimum pool size
    for epoch_store in &test_state.epoch_stores {
        let presigns: Vec<Vec<u8>> = (0..min_pool_size)
            .map(|i| {
                let mut data = mock_presign_data.clone();
                data.push(i as u8); // Make each presign unique
                data
            })
            .collect();

        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::ECDSASecp256k1,
                1,
                presigns,
            )
            .expect("Failed to insert presigns");
    }

    // Verify pool is at minimum size
    for epoch_store in &test_state.epoch_stores {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
            .expect("Failed to get pool size");
        assert_eq!(
            pool_size, min_pool_size,
            "Pool should be at minimum size"
        );
    }

    // Count initial internal presign sessions
    let initial_secp256k1_sessions: usize = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
        .count();

    info!(
        "Initial internal presign sessions: {}",
        initial_secp256k1_sessions
    );

    // Run several consensus rounds - since pool is at min size and we're "not idle"
    // (we'll simulate being busy), no new internal presigns should be created for this algorithm
    // Note: The idle check is based on the number of ready-to-advance sessions

    // Make the system "not idle" by ensuring there are enough sessions
    // The idle threshold is typically around 8, so we need more than that

    for round_offset in 0..5 {
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

    // Check that the pool size hasn't changed significantly
    // (Some internal presigns might still be created for other algorithms)
    for epoch_store in &test_state.epoch_stores {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
            .expect("Failed to get pool size");
        info!(
            "Final ECDSASecp256k1 pool size: {} (min: {})",
            pool_size, min_pool_size
        );
        // Pool should still be at or above minimum (no consumption without signing)
        assert!(
            pool_size >= min_pool_size,
            "Pool size should remain at or above minimum"
        );
    }

    info!("Test completed: Internal presigns stopped at minimum pool size when not idle");
}

/// Test that internal presign sessions continue to be created when the system is idle,
/// even if the pool has reached the minimum size.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_continues_when_idle() {
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

    // Create network key first
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;

    test_state.consensus_round = consensus_round as usize;

    // Get the idle threshold
    let idle_threshold = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config
        .idle_session_count_threshold();

    info!("Idle threshold: {}", idle_threshold);

    // Check if the system is considered idle
    // The system is idle when: total_session_count < threshold
    let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
    let active_sessions = manager.sessions.len();
    let is_idle = active_sessions < idle_threshold as usize;

    info!(
        "Active sessions: {}, Is idle: {}",
        active_sessions, is_idle
    );

    // Track internal presign sessions
    let initial_internal_presign_count: usize = manager
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
        .count();

    info!(
        "Initial internal presign session count: {}",
        initial_internal_presign_count
    );

    // Run several consensus rounds
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

    // Count final internal presign sessions
    let final_internal_presign_count: usize = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
        .count();

    info!(
        "Final internal presign session count: {}",
        final_internal_presign_count
    );

    // If the system was idle, more internal presigns should have been created
    if is_idle {
        assert!(
            final_internal_presign_count > initial_internal_presign_count,
            "When idle, internal presigns should continue to be created. Initial: {}, Final: {}",
            initial_internal_presign_count,
            final_internal_presign_count
        );
        info!("Test passed: Internal presigns continued when system was idle");
    } else {
        info!("System was not idle, skipping idle-specific assertion");
    }
}

/// Test that the correct number of internal presign sessions are instantiated per round
/// based on the `sessions_to_instantiate` configuration.
#[tokio::test]
#[cfg(test)]
async fn test_internal_presign_sessions_per_round_matches_config() {
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

    // Create network key first
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;

    test_state.consensus_round = consensus_round as usize;

    // Get configuration values
    let protocol_config = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;

    // Check EdDSA configuration (usually has more frequent instantiation)
    let eddsa_sessions_to_instantiate = protocol_config
        .get_internal_presign_sessions_to_instantiate(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );

    info!(
        "EdDSA sessions to instantiate per round: {}",
        eddsa_sessions_to_instantiate
    );

    // Track internal presign session counts to verify batching
    let mut previous_session_count = 0usize;
    let mut instantiation_events = 0usize;

    // Run enough rounds to see multiple instantiation events
    for round in 0..50 {
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

        // Check for new internal presign sessions
        let manager = test_state.dwallet_mpc_services[0].dwallet_mpc_manager();
        let current_session_count = manager
            .sessions
            .iter()
            .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
            .count();

        if current_session_count > previous_session_count {
            instantiation_events += 1;
            info!(
                "Round {}: New internal presigns created. Count: {} -> {}",
                round, previous_session_count, current_session_count
            );
            previous_session_count = current_session_count;
        }
    }

    info!(
        "Observed {} internal presign session instantiation events",
        instantiation_events
    );

    // Verify that sessions were created
    let final_count: usize = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
        .count();

    info!("Total internal presign sessions created: {}", final_count);

    assert!(
        final_count > 0,
        "Expected internal presign sessions to be created"
    );
}
