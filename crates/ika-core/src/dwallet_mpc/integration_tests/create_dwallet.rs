use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_dwallet_dkg_first_round_event,
    send_start_dwallet_dkg_second_round_event, send_start_network_dkg_event_to_all_parties,
};
use dwallet_mpc_centralized_party::{
    encrypt_secret_key_share_and_prove, generate_secp256k1_cg_keypair_from_seed_internal,
    network_dkg_public_output_to_protocol_pp_inner,
};
use ika_types::committee::Committee;
use ika_types::message::{DKGSecondRoundOutput, DWalletCheckpointMessageKind};
use ika_types::messages_dwallet_mpc::test_helpers::new_dwallet_session_event;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletNetworkEncryptionKeyData,
    DWalletNetworkEncryptionKeyState, DWalletSessionEvent, DWalletSessionEventTrait,
    IkaNetworkConfig, SessionIdentifier, SessionType,
};
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use sui_types::messages_consensus::Round;
use tracing::info;

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn dwallet_dkg_first_round() {
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
    let mut test_state = utils::IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
    };
    send_start_network_dkg_event_to_all_parties(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
    );
    let (consensus_round, network_key_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, 1).await;
    info!(?network_key_checkpoint, "Network key checkpoint received");
    let mut network_key_bytes = vec![];
    let mut key_id = None;
    for message in network_key_checkpoint.messages() {
        let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(message) = message
        else {
            continue;
        };
        key_id =
            Some(ObjectID::from_bytes(message.dwallet_network_encryption_key_id.clone()).unwrap());
        network_key_bytes.extend(message.public_output.clone())
    }
    test_state
        .sui_data_senders
        .iter()
        .for_each(|mut sui_data_sender| {
            let _ = sui_data_sender
                .network_keys_sender
                .send(Arc::new(HashMap::from([(
                    key_id.clone().unwrap(),
                    DWalletNetworkEncryptionKeyData {
                        id: key_id.clone().unwrap(),
                        current_epoch: 1,
                        current_reconfiguration_public_output: vec![],
                        network_dkg_public_output: network_key_bytes.clone(),
                        state: DWalletNetworkEncryptionKeyState::NetworkDKGCompleted,
                    },
                )])));
        });
    let dwallet_dkg_session_identifier = [2; 32];
    send_start_dwallet_dkg_first_round_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        dwallet_dkg_session_identifier,
        2,
        key_id.unwrap(),
    );
    info!("Starting DWallet DKG first round");
    let (consensus_round, mut dkg_first_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(
        dwallet_dkg_first_round_output,
    ) = dkg_first_round_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet DKG first round output message");
    };
    info!("DWallet DKG first round completed");
}

pub(crate) struct DWalletTestResult {
    pub(crate) flow_completion_consensus_round: Round,
    pub(crate) dkg_second_round_output: DKGSecondRoundOutput,
    pub(crate) dwallet_secret_key_share: Vec<u8>,
    pub(crate) class_groups_encryption_key: Vec<u8>,
    pub(crate) class_groups_decryption_key: Vec<u8>,
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn create_dwallet() {
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
    let (consensus_round, network_key_bytes, key_id) =
        create_network_key_test(&mut test_state).await;
    let result =
        create_dwallet_test(&mut test_state, consensus_round, key_id, network_key_bytes).await;
    info!("DWallet DKG second round completed");
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn create_imported_dwallet() {
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
    let (consensus_round, network_key_bytes, key_id) =
        create_network_key_test(&mut test_state).await;
    let result =
        create_dwallet_test(&mut test_state, consensus_round, key_id, network_key_bytes).await;
    info!("DWallet DKG second round completed");
}

pub(crate) async fn create_dwallet_test(
    mut test_state: &mut IntegrationTestState,
    start_consensus_round: Round,
    network_key_id: ObjectID,
    network_key_bytes: Vec<u8>,
) -> DWalletTestResult {
    let mut consensus_round = start_consensus_round;
    let dwallet_dkg_session_identifier = [2; 32];
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("At least one service should exist")
        .epoch;
    let ika_network_config = test_state
        .dwallet_mpc_services
        .first()
        .expect("At least one service should exist")
        .dwallet_mpc_manager()
        .packages_config
        .clone();
    send_start_dwallet_dkg_first_round_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        dwallet_dkg_session_identifier,
        2,
        network_key_id,
    );
    info!("Starting DWallet DKG first round");
    let (consensus_round, mut dkg_first_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(
        dwallet_dkg_first_round_output,
    ) = dkg_first_round_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet DKG first round output message");
    };
    info!("DWallet DKG first round completed");
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(network_key_bytes).unwrap();
    let centralized_dwallet_dkg_result = dwallet_mpc_centralized_party::create_dkg_output(
        protocol_pp.clone(),
        dwallet_dkg_first_round_output.output.clone(),
        SessionIdentifier::new(SessionType::User, dwallet_dkg_session_identifier).to_vec(),
    )
    .unwrap();
    let (encryption_key, decryption_key) =
        generate_secp256k1_cg_keypair_from_seed_internal([1; 32]).unwrap();
    let encrypted_secret_key_share_and_proof = encrypt_secret_key_share_and_prove(
        centralized_dwallet_dkg_result
            .centralized_secret_output
            .clone(),
        encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_dwallet_dkg_second_round_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        [3; 32],
        3,
        network_key_id,
        ObjectID::from_bytes(&dwallet_dkg_first_round_output.dwallet_id).unwrap(),
        dwallet_dkg_first_round_output.output,
        centralized_dwallet_dkg_result.public_key_share_and_proof,
        encrypted_secret_key_share_and_proof,
        encryption_key.clone(),
        centralized_dwallet_dkg_result.public_output,
    );
    let (consensus_round, dwallet_second_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(
        dwallet_dkg_second_round_output,
    ) = dwallet_second_round_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet DKG second round output message");
    };
    info!("DWallet DKG second round completed");
    DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_second_round_output: dwallet_dkg_second_round_output.clone(),
        dwallet_secret_key_share: centralized_dwallet_dkg_result.centralized_secret_output,
        class_groups_encryption_key: encryption_key,
        class_groups_decryption_key: decryption_key,
    }
}
