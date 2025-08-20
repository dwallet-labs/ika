use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::create_dwallet::{
    DWalletTestResult, create_dwallet_test,
};
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, network_dkg_public_output_to_protocol_pp_inner,
};
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::test_helpers::new_dwallet_session_event;
use ika_types::messages_dwallet_mpc::{DBSuiEvent, DWalletSessionEvent, DWalletSessionEventTrait, FutureSignRequestEvent, IkaNetworkConfig, PresignRequestEvent, SessionIdentifier, SessionType, SignRequestEvent};
use sui_types::base_types::{EpochId, ObjectID};
use tracing::info;
use dwallet_mpc_types::dwallet_mpc::{DWalletMPCNetworkKeyScheme, SignatureAlgorithm};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{PresignData, ProtocolData};

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn sign() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        mut sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        notify_services,
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
    };
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 400;
    }
    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    let DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_second_round_output: dwallet_dkg_second_round_output,
        dwallet_secret_key_share: dwallet_secret_share,
        ..
    } = create_dwallet_test(
        &mut test_state,
        consensus_round,
        network_key_id,
        network_key_bytes.clone(),
    )
    .await;
    info!("DWallet DKG second round completed");
    let presign_session_identifier = [4; 32];
    send_start_presign_event(
        epoch_id,
        &test_state.sui_data_senders,
        presign_session_identifier,
        4,
        network_key_id,
        Some(ObjectID::from_bytes(&dwallet_dkg_second_round_output.dwallet_id).unwrap()),
        Some(dwallet_dkg_second_round_output.output.clone()),
    );
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet presign output message");
    };
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(network_key_bytes).unwrap();
    let message_to_sign = bcs::to_bytes("Hello World!").unwrap();
    let centralized_sign = advance_centralized_sign_party(
        protocol_pp,
        dwallet_dkg_second_round_output.output.clone(),
        dwallet_secret_share,
        presign_output.presign.clone(),
        message_to_sign.clone(),
        0,
    )
    .unwrap();
    send_start_sign_event(
        epoch_id,
        &test_state.sui_data_senders,
        [5; 32],
        5,
        network_key_id,
        ObjectID::from_bytes(dwallet_dkg_second_round_output.dwallet_id).unwrap(),
        dwallet_dkg_second_round_output.output,
        presign_output.presign,
        centralized_sign,
        message_to_sign,
    );
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletSign(sign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet sign output message");
    };
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn future_sign() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        mut sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        notify_services,
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
    };
    for service in &mut test_state.dwallet_mpc_services {
        service
            .dwallet_mpc_manager_mut()
            .last_session_to_complete_in_current_epoch = 4;
    }
    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    let DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_second_round_output: dwallet_dkg_second_round_output,
        dwallet_secret_key_share: dwallet_secret_share,
        ..
    } = create_dwallet_test(
        &mut test_state,
        consensus_round,
        network_key_id,
        network_key_bytes.clone(),
    )
    .await;
    info!("DWallet DKG second round completed");
    let presign_session_identifier = [4; 32];
    send_start_presign_event(
        &ika_network_config,
        epoch_id,
        &test_state.sui_data_senders,
        presign_session_identifier,
        4,
        network_key_id,
        Some(ObjectID::from_bytes(&dwallet_dkg_second_round_output.dwallet_id).unwrap()),
        Some(dwallet_dkg_second_round_output.output.clone()),
    );
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletPresign(presign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet presign output message");
    };
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(network_key_bytes).unwrap();
    let message_to_sign = bcs::to_bytes("Hello World!").unwrap();
    let centralized_sign = advance_centralized_sign_party(
        protocol_pp,
        dwallet_dkg_second_round_output.output.clone(),
        dwallet_secret_share,
        presign_output.presign.clone(),
        message_to_sign.clone(),
        0,
    )
    .unwrap();
    send_start_future_sign_event(
        &ika_network_config,
        epoch_id,
        &test_state.sui_data_senders,
        [5; 32],
        5,
        network_key_id,
        ObjectID::from_bytes(dwallet_dkg_second_round_output.dwallet_id).unwrap(),
        dwallet_dkg_second_round_output.output,
        presign_output.presign,
        centralized_sign,
        message_to_sign,
    );
    let (consensus_round, presign_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(sign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet future sign output message");
    };
}

pub(crate) fn send_start_sign_event(
    ika_network_config: &IkaNetworkConfig,
    epoch_id: EpochId,
    sui_data_senders: &Vec<SuiDataSenders>,
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
    presign: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    message: Vec<u8>,
) {
    let presign_id = ObjectID::random();
    let sign_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DBSuiEvent {
                type_: DWalletSessionEvent::<SignRequestEvent>::type_(&ika_network_config),
                contents: bcs::to_bytes(&new_dwallet_session_event(
                    true,
                    session_sequence_number,
                    session_identifier_preimage.to_vec().clone(),
                    SignRequestEvent {
                        sign_id,
                        dwallet_id,
                        presign_id,
                        presign: presign.clone(),
                        message_centralized_signature: message_centralized_signature.clone(),
                        dwallet_network_encryption_key_id,
                        curve: 0,
                        signature_algorithm: 0,
                        hash_scheme: 0,
                        dwallet_decentralized_public_output: dwallet_public_output.clone(),
                        message: message.clone(),
                        is_future_sign: false,
                    },
                ))
                .unwrap(),
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_future_sign_event(
    ika_network_config: &IkaNetworkConfig,
    epoch_id: EpochId,
    sui_data_senders: &Vec<SuiDataSenders>,
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    dwallet_public_output: Vec<u8>,
    presign: Vec<u8>,
    message_centralized_signature: Vec<u8>,
    message: Vec<u8>,
) {
    let partial_centralized_signed_message_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DBSuiEvent {
                type_: DWalletSessionEvent::<FutureSignRequestEvent>::type_(&ika_network_config),
                contents: bcs::to_bytes(&new_dwallet_session_event(
                    true,
                    session_sequence_number,
                    session_identifier_preimage.to_vec().clone(),
                    FutureSignRequestEvent {
                        dwallet_id,
                        presign: presign.clone(),
                        message_centralized_signature: message_centralized_signature.clone(),
                        dwallet_network_encryption_key_id,
                        curve: 0,
                        signature_algorithm: 0,
                        hash_scheme: 0,
                        message: message.clone(),
                        partial_centralized_signed_message_id:
                            partial_centralized_signed_message_id.clone(),
                        dkg_output: dwallet_public_output.clone(),
                    },
                ))
                .unwrap(),
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_presign_event(
    epoch_id: EpochId,
    sui_data_senders: &Vec<SuiDataSenders>,
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: Option<ObjectID>,
    dwallet_public_output: Option<Vec<u8>>,
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
                session_sequence_number,
                protocol_data: ProtocolData::Presign {
                    data: PresignData {
                        curve: DWalletMPCNetworkKeyScheme::Secp256k1,
                        signature_algorithm: SignatureAlgorithm::ECDSA,
                    },
                    dwallet_id,
                    presign_id,
                    dwallet_public_output: dwallet_public_output.clone(),
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
