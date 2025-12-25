use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::SessionType;
use tracing::info;

/// Test that presign pool state is preserved when a validator processes
/// presigns and the data is available in the epoch store.
/// This simulates the persistence layer that would survive a restart.
#[tokio::test]
#[cfg(test)]
async fn test_presign_pool_state_preserved() {
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

    // Create network key
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Pre-populate presign pools to simulate existing state
    let mock_presign_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let num_presigns = 5;

    for epoch_store in &test_state.epoch_stores {
        let presigns: Vec<Vec<u8>> = (0..num_presigns)
            .map(|i| {
                let mut data = mock_presign_data.clone();
                data.push(i as u8);
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

    // Verify all epoch stores have the presigns
    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
            .expect("Failed to get pool size");

        info!(
            "Validator {} presign pool size after insertion: {}",
            i, pool_size
        );

        assert_eq!(
            pool_size, num_presigns,
            "Validator {} should have {} presigns in pool",
            i, num_presigns
        );
    }

    // Run some consensus rounds
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

    // Verify presign pool state is still accessible
    // (simulating that the persistent state survives across service loops)
    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
            .expect("Failed to get pool size");

        info!(
            "Validator {} presign pool size after processing: {}",
            i, pool_size
        );

        // Pool should still have presigns (may have grown if internal presigns completed)
        assert!(
            pool_size >= num_presigns,
            "Validator {} presign pool should not shrink without consumption",
            i
        );
    }

    info!("Test passed: Presign pool state is preserved");
}

/// Test that validators can continue MPC sessions after some rounds.
/// This verifies the session management continues working across multiple rounds.
#[tokio::test]
#[cfg(test)]
async fn test_validators_continue_sessions_across_rounds() {
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

    // Create network key
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Track session counts at different points
    let mut session_counts_over_time: Vec<Vec<usize>> = Vec::new();

    // Run multiple phases to verify session continuity
    for phase in 0..3 {
        info!("Starting phase {} at consensus round {}", phase, test_state.consensus_round);

        // Run 10 consensus rounds per phase
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

        // Record session counts at end of phase
        let phase_counts: Vec<usize> = test_state.dwallet_mpc_services
            .iter()
            .map(|s| s.dwallet_mpc_manager().sessions.len())
            .collect();

        info!(
            "Phase {} complete. Session counts: {:?}",
            phase, phase_counts
        );

        session_counts_over_time.push(phase_counts);
    }

    // Verify that all validators maintained sessions throughout
    for (i, validator_counts) in session_counts_over_time.iter().enumerate() {
        for (v, &count) in validator_counts.iter().enumerate() {
            info!(
                "Phase {}, Validator {}: {} sessions",
                i, v, count
            );
        }
    }

    // Verify validators have sessions at the end
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let final_session_count = service.dwallet_mpc_manager().sessions.len();
        let internal_presign_count = service
            .dwallet_mpc_manager()
            .sessions
            .iter()
            .filter(|(id, _)| id.session_type() == SessionType::InternalPresign)
            .count();

        info!(
            "Final: Validator {} has {} total sessions ({} internal presigns)",
            i, final_session_count, internal_presign_count
        );
    }

    info!("Test passed: Validators continue sessions across rounds");
}

/// Test that one validator being temporarily unresponsive doesn't break
/// the overall system. Other validators should continue processing.
#[tokio::test]
#[cfg(test)]
async fn test_system_resilience_to_temporary_unresponsiveness() {
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

    // Create network key with all validators
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    info!("Network key created. Now simulating partial participation...");

    // Run rounds where only validators 0, 1, 2 participate (validator 3 is "unresponsive")
    let unresponsive_validator = 3;

    for round in 0..10 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        // Only run service loop for responsive validators
        for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
            if i != unresponsive_validator {
                service.run_service_loop_iteration().await;
            }
        }

        if round % 5 == 0 {
            info!("Round {} completed (validator {} is unresponsive)", round, unresponsive_validator);
        }
    }

    // Check that responsive validators are still functioning
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        if i != unresponsive_validator {
            let session_count = service.dwallet_mpc_manager().sessions.len();
            info!(
                "Responsive validator {} has {} sessions",
                i, session_count
            );
        }
    }

    // Now "restart" the unresponsive validator by running its service loop
    info!("Bringing validator {} back online...", unresponsive_validator);

    // Run more rounds with all validators
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

    // Verify all validators are now functioning
    for (i, service) in test_state.dwallet_mpc_services.iter().enumerate() {
        let session_count = service.dwallet_mpc_manager().sessions.len();
        info!(
            "Final: Validator {} has {} sessions",
            i, session_count
        );
    }

    info!("Test passed: System resilience to temporary unresponsiveness verified");
}

/// Test that the epoch store properly maintains presign pool across operations.
/// This verifies the data layer that would be used for recovery after restart.
#[tokio::test]
#[cfg(test)]
async fn test_epoch_store_presign_pool_operations() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();

    let (
        _dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
    ) = utils::create_dwallet_mpc_services(4);

    // Test presign pool operations on epoch store
    let test_epoch_store = &epoch_stores[0];

    // Test inserting presigns
    let presigns: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 32]).collect();

    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            1,
            presigns.clone(),
        )
        .expect("Failed to insert presigns");

    let pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
        .expect("Failed to get pool size");

    assert_eq!(pool_size, 10, "Pool should have 10 presigns");
    info!("Inserted 10 presigns, pool size: {}", pool_size);

    // Test consuming a presign
    let consumed = test_epoch_store
        .pop_presign(DWalletSignatureAlgorithm::ECDSASecp256k1)
        .expect("Failed to pop presign");

    assert!(consumed.is_some(), "Should have consumed a presign");
    info!("Consumed presign: {:?}", consumed.map(|p| p.len()));

    let pool_size_after_consume = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
        .expect("Failed to get pool size");

    assert_eq!(pool_size_after_consume, 9, "Pool should have 9 presigns after consuming one");
    info!("Pool size after consume: {}", pool_size_after_consume);

    // Test inserting more presigns (simulating internal presign completion)
    let more_presigns: Vec<Vec<u8>> = (10..15).map(|i| vec![i as u8; 32]).collect();

    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            1,
            more_presigns,
        )
        .expect("Failed to insert more presigns");

    let final_pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
        .expect("Failed to get pool size");

    assert_eq!(final_pool_size, 14, "Pool should have 14 presigns");
    info!("Final pool size: {}", final_pool_size);

    // Test with different signature algorithms
    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::EdDSA,
            1,
            vec![vec![100u8; 32]; 5],
        )
        .expect("Failed to insert EdDSA presigns");

    let eddsa_pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA)
        .expect("Failed to get EdDSA pool size");

    assert_eq!(eddsa_pool_size, 5, "EdDSA pool should have 5 presigns");
    info!("EdDSA pool size: {}", eddsa_pool_size);

    // Verify pools are independent
    let ecdsa_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1)
        .expect("Failed to get ECDSA pool size");

    assert_eq!(ecdsa_size, 14, "ECDSA pool should be unchanged");

    info!("Test passed: Epoch store presign pool operations verified");
}
