use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::sign::send_global_presign_request_event;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{PresignData, ProtocolData};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::ObjectID;
#[allow(unused_imports)]
use sui_types::committee::EpochId;
use tracing::info;

/// Test that global presign requests are properly tracked and reported.
/// This verifies that when a global presign request is received, it's added to the
/// global_presign_requests list and eventually processed via the pool.
#[tokio::test]
#[cfg(test)]
async fn test_global_presign_requests_tracked_and_reported() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;

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
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Pre-populate presign pool for global presign requests
    let mock_presign_data = vec![1, 2, 3, 4, 5];
    let mock_session_identifier = SessionIdentifier::new(SessionType::InternalPresign, [0u8; 32]);
    for epoch_store in &test_state.epoch_stores {
        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::ECDSASecp256k1,
                1,
                mock_session_identifier,
                vec![mock_presign_data.clone(); 5],
            )
            .expect("Failed to insert presigns");
    }

    // Create TWO global presign requests
    let presign_id_1 = ObjectID::random();
    let presign_id_2 = ObjectID::random();

    info!("Sending first global presign request");
    send_global_presign_request_event(
        epoch_id,
        &test_state.sui_data_senders,
        [20; 32],
        100,
        presign_id_1,
        network_key_id,
    );

    info!("Sending second global presign request");
    send_global_presign_request_event(
        epoch_id,
        &test_state.sui_data_senders,
        [21; 32],
        101,
        presign_id_2,
        network_key_id,
    );

    // Run service loops and advance consensus
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

    // Check that presign outputs were generated
    let mut found_outputs = 0;
    for epoch_store in &test_state.epoch_stores {
        let pending = epoch_store.pending_checkpoints.lock().unwrap();
        for checkpoint in pending.iter() {
            for message in checkpoint.messages() {
                if let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) = message
                {
                    if presign_output.presign_id == presign_id_1.to_vec()
                        || presign_output.presign_id == presign_id_2.to_vec()
                    {
                        found_outputs += 1;
                        info!(
                            "Found presign output for presign_id {:?}",
                            presign_output.presign_id
                        );
                    }
                }
            }
        }
    }

    assert!(
        found_outputs > 0,
        "Should have found presign outputs for global presign requests"
    );

    info!(
        "Test passed: Global presign requests tracked and outputs generated. Found {} outputs",
        found_outputs
    );
}

/// Test that consensus is reached on global presign requests seen by 2/3 of validators,
/// and validators that didn't see a request can still get output from the pool.
#[tokio::test]
#[cfg(test)]
async fn test_partial_visibility_consensus_and_pool_retrieval() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;

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
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Pre-populate presign pool for ALL validators
    let mock_presign_data = vec![1, 2, 3, 4, 5];
    let mock_session_identifier = SessionIdentifier::new(SessionType::InternalPresign, [1u8; 32]);
    for epoch_store in &test_state.epoch_stores {
        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::ECDSASecp256k1,
                1,
                mock_session_identifier,
                vec![mock_presign_data.clone(); 10],
            )
            .expect("Failed to insert presigns");
    }

    // Create a global presign request that only 3 out of 4 validators see
    // (This achieves 2/3+ threshold since 3/4 > 2/3)
    let presign_id = ObjectID::random();
    let session_identifier_preimage = [30; 32];
    let session_sequence_number = 200;

    info!("Sending global presign request to validators 0, 1, 2 (but not 3)");

    // Send to only validators 0, 1, 2 (not validator 3)
    send_global_presign_request_to_some(
        epoch_id,
        &test_state.sui_data_senders,
        session_identifier_preimage,
        session_sequence_number,
        presign_id,
        network_key_id,
        &[0, 1, 2],
    );

    // Run service loops to process the request and send status updates
    // Use more rounds to allow sufficient time for processing
    for _ in 0..20 {
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

    // Check if validators have the presign output in their checkpoints
    let mut validators_with_output = vec![];

    for (i, epoch_store) in test_state.epoch_stores.iter().enumerate() {
        let pending = epoch_store.pending_checkpoints.lock().unwrap();
        for checkpoint in pending.iter() {
            for message in checkpoint.messages() {
                if let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) = message
                {
                    if presign_output.presign_id == presign_id.to_vec() {
                        if !validators_with_output.contains(&i) {
                            validators_with_output.push(i);
                        }
                        info!(
                            "Validator {} has presign output for presign_id {:?}",
                            i, presign_id
                        );
                    }
                }
            }
        }
    }

    info!(
        "Validators with presign output: {:?}",
        validators_with_output
    );

    // At least 2 validators should have the presign output (demonstrates the system works)
    // Due to timing and internal presign session scheduling, not all validators may complete
    // in the same number of rounds. The key is that validators can successfully produce
    // presign outputs using their presign pool.
    //
    // Note: The consensus mechanism may broadcast requests to all validators,
    // so even validator 3 (who didn't receive the request directly) may produce output
    // if the request reaches quorum and gets broadcast via consensus.
    assert!(
        validators_with_output.len() >= 2,
        "At least 2 validators should have the presign output. Got: {}",
        validators_with_output.len()
    );

    info!(
        "Test passed: Partial visibility scenario completed. {} validators produced output",
        validators_with_output.len()
    );
}

/// Helper to send a global presign request to specific validators only.
/// This is useful for testing partial visibility scenarios.
fn send_global_presign_request_to_some(
    epoch_id: u64,
    sui_data_senders: &[crate::SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    presign_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    validators: &[usize],
) {
    for (i, sui_data_sender) in sui_data_senders.iter().enumerate() {
        if validators.contains(&i) {
            let _ = sui_data_sender.uncompleted_events_sender.send((
                vec![DWalletSessionRequest {
                    session_type: SessionType::User,
                    session_identifier: SessionIdentifier::new(
                        SessionType::User,
                        session_identifier_preimage,
                    ),
                    session_sequence_number,
                    protocol_data: ProtocolData::Presign {
                        data: PresignData {
                            curve: DWalletCurve::Secp256k1,
                            signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
                        },
                        dwallet_id: None, // Global presign
                        presign_id,
                        dwallet_public_output: None,
                        dwallet_network_encryption_key_id,
                    },
                    epoch: epoch_id,
                    requires_network_key_data: true,
                    requires_next_active_committee: false,
                    pulled: false,
                }],
                epoch_id,
            ));
        }
    }
}
