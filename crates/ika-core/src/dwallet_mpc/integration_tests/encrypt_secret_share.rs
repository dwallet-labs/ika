use crate::dwallet_mpc::integration_tests::create_dwallet::create_dwallet_test;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_encrypt_secret_share_event,
};
use dwallet_mpc_centralized_party::{
    encrypt_secret_key_share_and_prove, network_dkg_public_output_to_protocol_pp_inner,
};
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use sui_types::base_types::ObjectID;
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn encrypt_secret_share() {
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
    let dwallet_test_result = create_dwallet_test(
        &mut test_state,
        consensus_round,
        key_id,
        network_key_bytes.clone(),
    )
    .await;
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(network_key_bytes).unwrap();
    let encrypted_secret_share = encrypt_secret_key_share_and_prove(
        dwallet_test_result.dwallet_secret_key_share.clone(),
        dwallet_test_result.class_groups_encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_encrypt_secret_share_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        [4; 32],
        4,
        key_id,
        ObjectID::from_bytes(
            dwallet_test_result
                .dkg_second_round_output
                .dwallet_id
                .clone(),
        )
        .unwrap(),
        encrypted_secret_share,
        dwallet_test_result.dkg_second_round_output.output,
        dwallet_test_result.class_groups_encryption_key.clone(),
    );
    let (consensus_round, encrypted_secret_share_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(
        encrypted_secret_share_output,
    ) = encrypted_secret_share_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet encrypted secret share output message");
    };
    assert!(
        !encrypted_secret_share_output.rejected,
        "Encrypted secret share was rejected"
    );
    info!("Encrypted secret share flow completed successfully");
}
