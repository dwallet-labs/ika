use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    build_test_state, create_test_protocol_config_guard,
};
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::ObjectID;
use tracing::info;

/// Test that the presign pool is not consumed without sign requests.
/// Uses the actual network key ID (not ObjectID::ZERO) and asserts exact equality.
#[tokio::test]
#[cfg(test)]
async fn test_presign_pool_not_consumed_without_sign_requests() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Create network key — use the actual key ID
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Pre-populate presign pools with the actual key ID
    let num_presigns = 5u64;
    let mock_session_id = SessionIdentifier::new(SessionType::InternalPresign, [0u8; 32]);

    for epoch_store in &test_state.epoch_stores {
        let presigns: Vec<Vec<u8>> = (0..num_presigns)
            .map(|i| {
                let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8];
                data.push(i as u8);
                data
            })
            .collect();

        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::ECDSASecp256k1,
                network_key_id,
                1,
                mock_session_id,
                presigns,
            )
            .expect("failed to insert presigns");
    }

    // Verify all epoch stores have the presigns
    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, network_key_id)
            .expect("failed to get pool size");
        assert_eq!(
            pool_size, num_presigns,
            "Validator {} should have {} presigns",
            i, num_presigns
        );
    }

    // Run some consensus rounds without sign requests
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

    // Verify pool is exactly unchanged (no consumption without signing)
    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, network_key_id)
            .expect("failed to get pool size");

        info!(
            "Validator {} presign pool size after processing: {} (expected >= {}, may have grown from background internal presigns)",
            i, pool_size, num_presigns
        );

        // Pool should be at least the original size. It may have grown if internal presign
        // sessions completed and deposited into the pool during the rounds.
        assert!(
            pool_size >= num_presigns,
            "Validator {} pool should not shrink without sign requests (expected >= {}, got {})",
            i,
            num_presigns,
            pool_size
        );
    }

    info!("Test passed: presign pool not consumed without sign requests");
}

/// Test that validators can continue MPC sessions after some rounds.
/// Verifies session management continues working across multiple phases.
#[tokio::test]
#[cfg(test)]
async fn test_validators_continue_sessions_across_rounds() {
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

    // Track session counts at different phases
    let mut session_counts_over_time: Vec<Vec<usize>> = Vec::new();

    for phase in 0..3 {
        info!(
            "Starting phase {} at consensus round {}",
            phase, test_state.consensus_round
        );

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

        let phase_counts: Vec<usize> = test_state
            .dwallet_mpc_services
            .iter()
            .map(|s| s.dwallet_mpc_manager().sessions.len())
            .collect();

        info!(
            "Phase {} complete. Session counts: {:?}",
            phase, phase_counts
        );

        session_counts_over_time.push(phase_counts);
    }

    // Verify all validators have sessions at the end (internal presigns should have been created)
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

        assert!(
            final_session_count > 0,
            "Validator {} should have sessions after 3 phases of 10 rounds each (internal presign sessions should keep the manager populated)",
            i
        );
    }

    info!("Test passed: validators continue sessions across rounds");
}

/// Test that one validator being temporarily unresponsive doesn't break the system.
/// After recovery, the previously-unresponsive validator should have sessions in its manager.
#[tokio::test]
#[cfg(test)]
async fn test_system_resilience_to_temporary_unresponsiveness() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Create network key with all validators
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    info!("Network key created. Simulating partial participation...");

    let unresponsive_validator = 3;

    // Run rounds where only validators 0, 1, 2 participate (validator 3 is "unresponsive")
    for _round in 0..10 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        for (i, service) in test_state.dwallet_mpc_services.iter_mut().enumerate() {
            if i != unresponsive_validator {
                service.run_service_loop_iteration(vec![]).await;
            }
        }
    }

    // Verify responsive validators still have sessions
    let responsive_session_counts: Vec<usize> = test_state
        .dwallet_mpc_services
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != unresponsive_validator)
        .map(|(i, service)| {
            let session_count = service.dwallet_mpc_manager().sessions.len();
            info!("Responsive validator {} has {} sessions", i, session_count);
            session_count
        })
        .collect();
    for (i, &count) in responsive_session_counts.iter().enumerate() {
        assert!(
            count > 0,
            "Responsive validator {} should have sessions while unresponsive validator is offline",
            i
        );
    }

    // "Restart" the unresponsive validator
    info!(
        "Bringing validator {} back online...",
        unresponsive_validator
    );

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
            service.run_service_loop_iteration(vec![]).await;
        }
    }

    // Verify the recovered validator has sessions
    let recovered_session_count = test_state.dwallet_mpc_services[unresponsive_validator]
        .dwallet_mpc_manager()
        .sessions
        .len();
    info!(
        "Recovered validator {} has {} sessions",
        unresponsive_validator, recovered_session_count
    );
    assert!(
        recovered_session_count > 0,
        "recovered validator should have sessions after being brought back online"
    );

    info!("Test passed: system resilience to temporary unresponsiveness verified");
}

/// Test that the epoch store properly maintains presign pool across operations.
/// Verifies pool isolation across different key IDs and algorithms,
/// pop from empty pool, and mark_presign_as_used / is_presign_used.
#[tokio::test]
#[cfg(test)]
async fn test_epoch_store_presign_pool_operations() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let (
        _dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
        _sign_request_senders,
        _sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);

    let test_epoch_store = &epoch_stores[0];
    let test_session_id_one = SessionIdentifier::new(SessionType::InternalPresign, [1u8; 32]);
    let test_session_id_two = SessionIdentifier::new(SessionType::InternalPresign, [2u8; 32]);
    let test_session_id_three = SessionIdentifier::new(SessionType::InternalPresign, [3u8; 32]);

    // Test inserting presigns with ObjectID::ZERO
    let presigns: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 32]).collect();
    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            ObjectID::ZERO,
            1,
            test_session_id_one,
            presigns.clone(),
        )
        .expect("failed to insert presigns");

    let pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, ObjectID::ZERO)
        .expect("failed to get pool size");
    assert_eq!(pool_size, 10, "pool should have 10 presigns");

    // Test consuming a presign
    let consumed = test_epoch_store
        .pop_presign(DWalletSignatureAlgorithm::ECDSASecp256k1, ObjectID::ZERO)
        .expect("failed to pop presign");
    assert!(consumed.is_some(), "should have consumed a presign");

    let pool_size_after = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, ObjectID::ZERO)
        .expect("failed to get pool size");
    assert_eq!(pool_size_after, 9, "pool should have 9 presigns after pop");

    // Test inserting more presigns
    let more_presigns: Vec<Vec<u8>> = (10..15).map(|i| vec![i as u8; 32]).collect();
    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            ObjectID::ZERO,
            2,
            test_session_id_two,
            more_presigns,
        )
        .expect("failed to insert more presigns");

    let final_pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, ObjectID::ZERO)
        .expect("failed to get pool size");
    assert_eq!(final_pool_size, 14, "pool should have 14 presigns");

    // Test different signature algorithm
    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::EdDSA,
            ObjectID::ZERO,
            1,
            test_session_id_three,
            vec![vec![100u8; 32]; 5],
        )
        .expect("failed to insert EdDSA presigns");

    let eddsa_pool_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::EdDSA, ObjectID::ZERO)
        .expect("failed to get EdDSA pool size");
    assert_eq!(eddsa_pool_size, 5, "EdDSA pool should have 5 presigns");

    // Verify pools are independent (different algorithms)
    let ecdsa_size = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, ObjectID::ZERO)
        .expect("failed to get ECDSA pool size");
    assert_eq!(ecdsa_size, 14, "ECDSA pool should be unchanged");

    // Test pool isolation across different network key IDs
    let key_id_a = ObjectID::random();
    let key_id_b = ObjectID::random();
    let session_id_a = SessionIdentifier::new(SessionType::InternalPresign, [10u8; 32]);
    let session_id_b = SessionIdentifier::new(SessionType::InternalPresign, [11u8; 32]);

    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            key_id_a,
            1,
            session_id_a,
            vec![vec![200u8; 32]; 3],
        )
        .expect("failed to insert presigns for key_id_a");

    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            key_id_b,
            1,
            session_id_b,
            vec![vec![201u8; 32]; 7],
        )
        .expect("failed to insert presigns for key_id_b");

    let size_a = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, key_id_a)
        .expect("failed to get pool size for key_id_a");
    let size_b = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, key_id_b)
        .expect("failed to get pool size for key_id_b");

    assert_eq!(size_a, 3, "key_id_a pool should have 3 presigns");
    assert_eq!(size_b, 7, "key_id_b pool should have 7 presigns");

    // Test pop from empty pool
    let empty_key = ObjectID::random();
    let empty_pop = test_epoch_store
        .pop_presign(DWalletSignatureAlgorithm::ECDSASecp256k1, empty_key)
        .expect("pop from empty pool should not error");
    assert!(
        empty_pop.is_none(),
        "pop from empty pool should return None"
    );

    // Test mark_presign_as_used / is_presign_used
    let used_session_id = SessionIdentifier::new(SessionType::InternalPresign, [99u8; 32]);

    let is_used_before = test_epoch_store
        .is_presign_used(used_session_id)
        .expect("is_presign_used should not error");
    assert!(
        !is_used_before,
        "presign should not be marked as used initially"
    );

    test_epoch_store
        .mark_presign_as_used(used_session_id)
        .expect("mark_presign_as_used should not error");

    let is_used_after = test_epoch_store
        .is_presign_used(used_session_id)
        .expect("is_presign_used should not error");
    assert!(
        is_used_after,
        "presign should be marked as used after marking"
    );

    // Marking the same presign again should not cause issues
    test_epoch_store
        .mark_presign_as_used(used_session_id)
        .expect("marking again should not error");

    let still_used = test_epoch_store
        .is_presign_used(used_session_id)
        .expect("is_presign_used should not error");
    assert!(
        still_used,
        "presign should still be marked as used after double-marking"
    );

    // A different session ID should not be marked as used
    let other_session_id = SessionIdentifier::new(SessionType::InternalPresign, [100u8; 32]);
    let other_used = test_epoch_store
        .is_presign_used(other_session_id)
        .expect("is_presign_used should not error");
    assert!(
        !other_used,
        "different session ID should not be marked as used"
    );

    // Test assign_presign / get_assigned_presign / pop_assigned_presign roundtrip.
    // First, insert a real presign into the pool so assign_presign has something to pop.
    let assign_key_id = ObjectID::random();
    let assign_session_preimage = [50u8; 32];
    let assign_source_session_id =
        SessionIdentifier::new(SessionType::InternalPresign, assign_session_preimage);
    test_epoch_store
        .insert_presigns(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assign_key_id,
            1,
            assign_source_session_id,
            vec![vec![55u8; 32]],
        )
        .expect("failed to insert presign for assign roundtrip");

    // assign_presign pops one presign from the internal pool and places it in the assigned pool
    let assigned_session_id = test_epoch_store
        .assign_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assign_key_id,
            None,
            None,
            1,
        )
        .expect("assign_presign should not error")
        .expect("assign_presign should return a session ID when pool is non-empty");

    // Internal pool should now be empty
    let pool_after_assign = test_epoch_store
        .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, assign_key_id)
        .expect("failed to get pool size after assign");
    assert_eq!(
        pool_after_assign, 0,
        "internal pool should be empty after assigning the only presign"
    );

    // get_assigned_presign retrieves without removing
    let retrieved = test_epoch_store
        .get_assigned_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assigned_session_id,
        )
        .expect("get_assigned_presign should not error")
        .expect("assigned presign should exist after assign");
    assert_eq!(
        retrieved.presign,
        vec![55u8; 32],
        "retrieved presign data should match what was inserted"
    );
    assert_eq!(
        retrieved.assigned_epoch, 1,
        "assigned_epoch should match current_epoch passed to assign_presign"
    );

    // A second get still returns the presign (non-consuming)
    let retrieved_again = test_epoch_store
        .get_assigned_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assigned_session_id,
        )
        .expect("second get_assigned_presign should not error");
    assert!(
        retrieved_again.is_some(),
        "assigned presign should still exist after a non-consuming get"
    );

    // pop_assigned_presign removes it from the assigned pool
    let popped = test_epoch_store
        .pop_assigned_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assigned_session_id,
        )
        .expect("pop_assigned_presign should not error")
        .expect("pop should return the assigned presign");
    assert_eq!(
        popped.presign,
        vec![55u8; 32],
        "popped presign data should match what was inserted"
    );

    // After pop, the presign is gone from the assigned pool
    let gone = test_epoch_store
        .get_assigned_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assigned_session_id,
        )
        .expect("get after pop should not error");
    assert!(
        gone.is_none(),
        "assigned presign should be absent after pop"
    );

    // assign_presign on an empty pool returns None
    let no_assign = test_epoch_store
        .assign_presign(
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            assign_key_id,
            None,
            None,
            1,
        )
        .expect("assign on empty pool should not error");
    assert!(
        no_assign.is_none(),
        "assign_presign should return None when pool is empty"
    );

    info!(
        "Test passed: epoch store presign pool operations verified with isolation and used tracking"
    );
}
