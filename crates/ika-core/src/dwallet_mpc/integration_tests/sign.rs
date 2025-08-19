use crate::dwallet_mpc::integration_tests::create_dwallet::create_dwallet_test;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_presign_event, send_start_sign_event,
};
use dwallet_mpc_centralized_party::{
    advance_centralized_sign_party, network_dkg_public_output_to_protocol_pp_inner,
};
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use sui_types::base_types::ObjectID;
use tracing::info;

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
            .last_session_to_complete_in_current_epoch = 4;
    }
    let (consensus_round, network_key_bytes, network_key_id) =
        create_network_key_test(&mut test_state).await;
    let (consensus_round, dwallet_dkg_second_round_output, dwallet_secret_share) =
        create_dwallet_test(
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
    send_start_sign_event(
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
    let DWalletCheckpointMessageKind::RespondDWalletSign(sign_output) =
        presign_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet sign output message");
    };
}
