use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_dwallet_dkg_first_round_event,
    send_start_network_dkg_event_to_all_parties,
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
    let mut consensus_round = 1;
    let mut network_key_checkpoint = None;
    consensus_round = advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let Some(network_key_checkpoint) = network_key_checkpoint else {
        panic!("Network key checkpoint should not be None");
    };
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
    send_start_dwallet_dkg_first_round_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        [2; 32],
        2,
        key_id.unwrap(),
    );
    info!("Starting DWallet DKG first round");
    consensus_round = advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    info!("DWallet DKG first round completed");
}

pub(crate) async fn advance_mpc_flow_until_completion(
    mut test_state: &mut IntegrationTestState,
    start_consensus_round: Round,
) -> Round {
    let mut consensus_round = start_consensus_round;
    loop {
        if let Some(pending_checkpoint) = utils::advance_all_parties_and_wait_for_completions(
            &test_state.committee,
            &mut test_state.dwallet_mpc_services,
            &mut test_state.sent_consensus_messages_collectors,
            &test_state.epoch_stores,
            &test_state.notify_services,
        )
        .await
        {
            info!(?pending_checkpoint, "MPC flow completed successfully");
            return consensus_round;
        }

        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
    }
}
