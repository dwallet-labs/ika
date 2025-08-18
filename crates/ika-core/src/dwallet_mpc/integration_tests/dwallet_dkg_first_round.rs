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
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::test_helpers::new_dwallet_session_event;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletNetworkEncryptionKeyData,
    DWalletNetworkEncryptionKeyState, DWalletSessionEvent, DWalletSessionEventTrait,
    IkaNetworkConfig,
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

    // log the length of the parameters passed to the next function call copilot
    info!(
        network_key_bytes_length =? network_key_bytes.len(),
        dwalllet_dkg_first_round_output_length =? dwallet_dkg_first_round_output.output.len(),
        dwallet_dkg_session_identifier_length =? dwallet_dkg_session_identifier.len(),
        "paramters to next call length",
    );
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(network_key_bytes).unwrap();
    let centralized_dwallet_dkg_result = dwallet_mpc_centralized_party::create_dkg_output(
        protocol_pp.clone(),
        dwallet_dkg_first_round_output.output.clone(),
        dwallet_dkg_session_identifier.to_vec(),
    )
    .unwrap();
    let (encryption_key, decryption_key) =
        generate_secp256k1_cg_keypair_from_seed_internal([1; 32]).unwrap();
    let encrypted_secret_key_share_and_proof = encrypt_secret_key_share_and_prove(
        centralized_dwallet_dkg_result.centralized_secret_output,
        encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_dwallet_dkg_second_round_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        dwallet_dkg_session_identifier,
        3,
        key_id.unwrap(),
        ObjectID::from_bytes(&dwallet_dkg_first_round_output.dwallet_id).unwrap(),
        dwallet_dkg_first_round_output.output,
        centralized_dwallet_dkg_result.public_key_share_and_proof,
        encrypted_secret_key_share_and_proof,
        encryption_key,
        centralized_dwallet_dkg_result.public_output,
    );
    info!("DWallet DKG first round completed");
}

// ts Preparing DKG second round with protocolPublicParameters length: 19129658, networkFirstRoundOutput length: 1136, sessionDigest length: 32
// rust paramters to next call length network_key_bytes_length=12891 dwalllet_dkg_first_round_output_length=1136 dwallet_dkg_session_identifier_length=32
