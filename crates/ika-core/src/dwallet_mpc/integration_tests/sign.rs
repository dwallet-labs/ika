use crate::SuiDataSenders;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::integration_tests::create_dwallet::{
    DWalletTestResult, create_dwallet_test_inner,
};
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    PartialSignatureVerificationData, PresignData, ProtocolData, SignData,
};
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, network_dkg_public_output_to_protocol_pp_inner,
};
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use group::HashScheme;
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::{EpochId, ObjectID};
use tracing::info;

#[tokio::test]
#[cfg(test)]
/// Tests the full sign flow using EdDSA (Curve25519).
/// Uses the internal presign pool (global presign) rather than per-dWallet external presign,
/// which is the correct flow for standard (universal) dWallets.
/// EdDSA presigns are used because they complete quickly (no class groups), making this
/// test feasible within a reasonable time budget.
async fn sign_flow_test() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard();
    let epoch_id = 1;
    let mut test_state = utils::build_test_state(4);
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // Verify test protocol config is in effect.
    let pc = &test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .protocol_config;
    info!(
        delay = pc.get_internal_presign_consensus_round_delay(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        ),
        min_pool = pc.get_internal_presign_pool_minimum_size(
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        ),
        enabled = pc.internal_presign_sessions_enabled(),
        "sign_flow_test: EdDSA presign config"
    );

    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    // Use Curve25519 (EdDSA): EdDSA presigns do not require class groups operations and
    // complete quickly, whereas ECDSA (secp256k1) presigns are computationally too expensive
    // for integration tests.
    let DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_output: decentralized_party_dkg_public_output,
        dwallet_secret_key_share: dwallet_secret_share,
        ..
    } = create_dwallet_test_inner(
        &mut test_state,
        consensus_round,
        network_key_id,
        network_key_bytes.clone(),
        DWalletCurve::Curve25519,
    )
    .await;
    info!("EdDSA dWallet DKG completed");
    // Wait for internal EdDSA presigns to populate the pool.
    // These run automatically in the background once the network key is available.
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        DWalletSignatureAlgorithm::EdDSA,
        network_key_id,
        consensus_round + 1,
    )
    .await;
    info!("EdDSA presign pool populated, sending global presign request");
    let presign_id = ObjectID::random();
    send_global_presign_request_event(
        epoch_id,
        &test_state.sui_data_senders,
        [4; 32],
        4,
        presign_id,
        network_key_id,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    // advance_rounds_while_presign_pool_empty already returns the next round to use.
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet presign output message");
    };
    // curve=2 (Curve25519), signature_algorithm=0 (EdDSA for Curve25519), hash_scheme=0 (SHA512)
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(
        DWalletCurve::Curve25519 as u32,
        network_key_bytes,
    )
    .unwrap();
    let message_to_sign = bcs::to_bytes("Hello World!").unwrap();
    let centralized_sign = advance_centralized_sign_party(
        protocol_pp,
        decentralized_party_dkg_public_output.output.clone(),
        dwallet_secret_share,
        presign_output.presign.clone(),
        message_to_sign.clone(),
        DWalletCurve::Curve25519 as u32,
        0, // EdDSA is index 0 within Curve25519
        0, // SHA512 is index 0 for EdDSA
    )
    .unwrap();
    send_start_sign_event(
        epoch_id,
        &test_state.sui_data_senders,
        [5; 32],
        5,
        network_key_id,
        ObjectID::from_bytes(decentralized_party_dkg_public_output.dwallet_id).unwrap(),
        decentralized_party_dkg_public_output.output,
        presign_output.presign,
        centralized_sign,
        message_to_sign,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
        HashScheme::SHA512,
    );
    let (_, sign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round + 1).await;
    let DWalletCheckpointMessageKind::RespondDWalletSign(_sign_output) =
        sign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet sign output message");
    };
}

#[tokio::test]
#[cfg(test)]
/// Tests the full future sign flow using EdDSA (Curve25519).
/// Uses the internal presign pool (global presign) rather than per-dWallet external presign,
/// which is the correct flow for standard (universal) dWallets.
/// EdDSA presigns are used because they complete quickly (no class groups), making this
/// test feasible within a reasonable time budget.
async fn future_sign_flow_test() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard();
    let epoch_id = 1;
    let mut test_state = utils::build_test_state(4);
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }
    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    // Use Curve25519 (EdDSA): EdDSA presigns do not require class groups operations and
    // complete quickly, whereas ECDSA (secp256k1) presigns are computationally too expensive
    // for integration tests.
    let DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_output: decentralized_party_dkg_public_output,
        dwallet_secret_key_share: dwallet_secret_share,
        ..
    } = create_dwallet_test_inner(
        &mut test_state,
        consensus_round,
        network_key_id,
        network_key_bytes.clone(),
        DWalletCurve::Curve25519,
    )
    .await;
    info!("EdDSA dWallet DKG completed");
    // Wait for internal EdDSA presigns to populate the pool.
    // These run automatically in the background once the network key is available.
    let consensus_round = utils::advance_rounds_while_presign_pool_empty(
        &mut test_state,
        DWalletSignatureAlgorithm::EdDSA,
        network_key_id,
        consensus_round + 1,
    )
    .await;
    info!("EdDSA presign pool populated, sending global presign request");
    let presign_id = ObjectID::random();
    send_global_presign_request_event(
        epoch_id,
        &test_state.sui_data_senders,
        [4; 32],
        4,
        presign_id,
        network_key_id,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
    );
    // advance_rounds_while_presign_pool_empty already returns the next round to use.
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet presign output message");
    };
    // curve=2 (Curve25519), signature_algorithm=0 (EdDSA for Curve25519), hash_scheme=0 (SHA512)
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(
        DWalletCurve::Curve25519 as u32,
        network_key_bytes,
    )
    .unwrap();
    let message_to_sign = bcs::to_bytes("Hello World!").unwrap();
    let centralized_sign = advance_centralized_sign_party(
        protocol_pp,
        decentralized_party_dkg_public_output.output.clone(),
        dwallet_secret_share,
        presign_output.presign.clone(),
        message_to_sign.clone(),
        DWalletCurve::Curve25519 as u32,
        0, // EdDSA is index 0 within Curve25519
        0, // SHA512 is index 0 for EdDSA
    )
    .unwrap();
    send_start_partial_signature_verification_event(
        epoch_id,
        &test_state.sui_data_senders,
        [5; 32],
        5,
        network_key_id,
        ObjectID::from_bytes(decentralized_party_dkg_public_output.dwallet_id.clone()).unwrap(),
        decentralized_party_dkg_public_output.output.clone(),
        presign_output.presign.clone(),
        centralized_sign.clone(),
        message_to_sign.clone(),
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
        HashScheme::SHA512,
    );
    let (consensus_round, sign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round + 1).await;
    let DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(
        _sign_output,
    ) = sign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet future sign output message");
    };
    send_start_future_sign_event(
        epoch_id,
        &test_state.sui_data_senders,
        [6; 32],
        6,
        network_key_id,
        ObjectID::from_bytes(decentralized_party_dkg_public_output.dwallet_id).unwrap(),
        decentralized_party_dkg_public_output.output,
        presign_output.presign,
        centralized_sign,
        message_to_sign,
        DWalletCurve::Curve25519,
        DWalletSignatureAlgorithm::EdDSA,
        HashScheme::SHA512,
    );
    let (_, sign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round + 1).await;
    let DWalletCheckpointMessageKind::RespondDWalletSign(_sign_output) =
        sign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet future sign output message");
    };
}

pub(crate) fn send_start_sign_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
    presign: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    message: Vec<u8>,
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
    hash_scheme: HashScheme,
) {
    let sign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::Sign {
                    data: SignData {
                        curve,
                        hash_scheme,
                        signature_algorithm,
                    },
                    dwallet_id,
                    sign_id,
                    is_future_sign: false,
                    dwallet_network_encryption_key_id,
                    dwallet_decentralized_public_output: dwallet_public_output.clone(),
                    message: message.clone(),
                    presign: presign.clone(),
                    message_centralized_signature: message_centralized_signature.clone(),
                },
                epoch: epoch_id,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_future_sign_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
    presign: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    message: Vec<u8>,
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
    hash_scheme: HashScheme,
) {
    let sign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::Sign {
                    data: SignData {
                        curve,
                        hash_scheme,
                        signature_algorithm,
                    },
                    dwallet_id,
                    sign_id,
                    is_future_sign: true,
                    dwallet_network_encryption_key_id,
                    dwallet_decentralized_public_output: dwallet_public_output.clone(),
                    message: message.clone(),
                    presign: presign.clone(),
                    message_centralized_signature: message_centralized_signature.clone(),
                },
                epoch: epoch_id,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_partial_signature_verification_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
    presign: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    message: Vec<u8>,
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
    hash_scheme: HashScheme,
) {
    let sign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::PartialSignatureVerification {
                    data: PartialSignatureVerificationData {
                        curve,
                        message: message.clone(),
                        hash_scheme,
                        signature_algorithm,
                        dwallet_decentralized_output: dwallet_public_output.clone(),
                        presign: presign.clone(),
                        partially_signed_message: message_centralized_signature.clone(),
                    },
                    dwallet_id,
                    partial_centralized_signed_message_id: sign_id,
                    dwallet_network_encryption_key_id,
                },
                epoch: epoch_id,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_presign_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
) {
    let presign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::Presign {
                    data: PresignData {
                        curve: DWalletCurve::Secp256k1,
                        signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
                    },
                    dwallet_id: None,
                    presign_id,
                    dwallet_public_output: None,
                    dwallet_network_encryption_key_id,
                },
                epoch: 1,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_direct_presign_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
) {
    let presign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::Presign {
                    data: PresignData {
                        curve: DWalletCurve::Secp256k1,
                        signature_algorithm: DWalletSignatureAlgorithm::ECDSASecp256k1,
                    },
                    dwallet_id: Some(dwallet_id),
                    presign_id,
                    dwallet_public_output: Some(dwallet_public_output.clone()),
                    dwallet_network_encryption_key_id,
                },
                epoch: 1,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

/// Sends a global presign request event with a specific presign_id that can be verified later.
pub(crate) fn send_global_presign_request_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    presign_id: ObjectID,
    dwallet_network_encryption_key_id: ObjectID,
    curve: DWalletCurve,
    signature_algorithm: DWalletSignatureAlgorithm,
) {
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number: Some(session_sequence_number),
                protocol_data: ProtocolData::Presign {
                    data: PresignData {
                        curve,
                        signature_algorithm,
                    },
                    // No dwallet_id and no dwallet_public_output makes this a global presign request
                    dwallet_id: None,
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
    });
}

#[tokio::test]
#[cfg(test)]
/// Tests that a global presign request correctly takes a presign from the internal presign pool
/// and returns it with the correct session_sequence_number and presign_id.
async fn global_presign_request_uses_correct_metadata_test() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(4);
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
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }

    // First, create a network key
    let (consensus_round, _network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    // Update test_state.consensus_round to continue from where network key creation left off.
    // consensus_round (5) is the round at which the checkpoint was found, but send_advance_results
    // was only called up to round 4. So we start from round 5 to ensure consecutive rounds.
    test_state.consensus_round = consensus_round as usize;

    // Pre-populate the presign pool with a mock presign for all epoch stores
    let mock_presign_data = vec![1, 2, 3, 4, 5];
    let mock_session_identifier = SessionIdentifier::new(SessionType::InternalPresign, [0u8; 32]);
    for epoch_store in &test_state.epoch_stores {
        epoch_store
            .insert_presigns(
                DWalletSignatureAlgorithm::ECDSASecp256k1,
                network_key_id,
                1, // session_sequence_number for internal presigns
                mock_session_identifier,
                vec![mock_presign_data.clone()],
            )
            .expect("Failed to insert presign into pool");
    }

    // Verify pool has the presign
    for epoch_store in &test_state.epoch_stores {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, network_key_id)
            .expect("Failed to get pool size");
        assert_eq!(pool_size, 1, "Pool should have one presign");
    }

    // Create the global presign request with specific identifiers we want to verify
    let expected_presign_id = ObjectID::random();
    let expected_session_sequence_number = 42u64;
    let session_identifier_preimage = [10; 32];

    info!(
        "Sending global presign request with presign_id={:?}, session_sequence_number={}",
        expected_presign_id, expected_session_sequence_number
    );

    send_global_presign_request_event(
        epoch_id,
        &test_state.sui_data_senders,
        session_identifier_preimage,
        expected_session_sequence_number,
        expected_presign_id,
        network_key_id,
        DWalletCurve::Secp256k1,
        DWalletSignatureAlgorithm::ECDSASecp256k1,
    );

    // Run a few service iterations to process the request and send status updates
    // Call send_advance_results_between_parties FIRST to set up the next round's data,
    // then run the services which will read that round.
    for _ in 0..5 {
        // Set up the next consensus round's data (distributes messages/outputs/status_updates)
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;
        // Now services can read from the round we just set up
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
    }

    // Check the pending checkpoints for the presign output
    let mut found_presign_output = false;
    for epoch_store in &test_state.epoch_stores {
        let pending = epoch_store.pending_checkpoints.lock().unwrap();
        for checkpoint in pending.iter() {
            for message in checkpoint.messages() {
                if let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) = message
                {
                    info!(
                        "Found presign output: presign_id={:?}, session_sequence_number={}",
                        presign_output.presign_id, presign_output.session_sequence_number
                    );

                    // Verify the presign_id matches
                    assert_eq!(
                        presign_output.presign_id,
                        expected_presign_id.to_vec(),
                        "Presign output should have the correct presign_id from the global presign request"
                    );

                    // Verify the session_sequence_number matches
                    assert_eq!(
                        presign_output.session_sequence_number, expected_session_sequence_number,
                        "Presign output should have the correct session_sequence_number from the global presign request"
                    );

                    // Verify dwallet_id is None (global presign)
                    assert!(
                        presign_output.dwallet_id.is_none(),
                        "Global presign should have no dwallet_id"
                    );

                    found_presign_output = true;
                }
            }
        }
    }

    assert!(
        found_presign_output,
        "Should have found a presign output from the global presign request"
    );

    // Verify the pool was consumed
    for epoch_store in &test_state.epoch_stores {
        let pool_size = epoch_store
            .presign_pool_size(DWalletSignatureAlgorithm::ECDSASecp256k1, network_key_id)
            .expect("Failed to get pool size");
        assert_eq!(
            pool_size, 0,
            "Pool should be empty after consuming the presign"
        );
    }

    info!("Global presign request test completed successfully!");
}
