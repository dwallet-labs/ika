use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    send_start_dwallet_dkg_first_round_event, send_start_network_dkg_event_to_all_parties,
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
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn network_key_received_after_start_event() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();

    let parties_that_receive_network_key_after_start_event = vec![0, 1];

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
        committee: committee.clone(),
        sui_data_senders,
    };

    send_start_network_dkg_event_to_all_parties(epoch_id, &mut test_state).await;
    let mut consensus_round = 1;
    let mut network_key_checkpoint = None;
    loop {
        if let Some(pending_checkpoint) = utils::advance_all_parties_and_wait_for_completions(
            &committee,
            &mut test_state.dwallet_mpc_services,
            &mut test_state.sent_consensus_messages_collectors,
            &test_state.epoch_stores,
            &test_state.notify_services,
        )
        .await
        {
            assert_eq!(
                consensus_round, 5,
                "Network DKG should complete after 4 rounds"
            );
            info!(?pending_checkpoint, "MPC flow completed successfully");
            network_key_checkpoint = Some(pending_checkpoint);
            break;
        }

        utils::send_advance_results_between_parties(
            &committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
    }
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
    let parties_that_receive_network_key_early = (0..committee.voting_rights.len())
        .filter(|i| !parties_that_receive_network_key_after_start_event.contains(i))
        .collect::<Vec<_>>();
    send_network_key_to_parties(
        parties_that_receive_network_key_early,
        &mut test_state.sui_data_senders,
        network_key_bytes.clone(),
        key_id,
    );
    send_start_dwallet_dkg_first_round_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [2; 32],
        2,
        key_id.unwrap(),
    );
    for dwallet_mpc_service in test_state.dwallet_mpc_services.iter_mut() {
        dwallet_mpc_service.run_service_loop_iteration().await;
    }
    send_network_key_to_parties(
        parties_that_receive_network_key_after_start_event,
        &mut test_state.sui_data_senders,
        network_key_bytes,
        key_id,
    );
    info!("Starting DWallet DKG first round");
    loop {
        if let Some(pending_checkpoint) = utils::advance_all_parties_and_wait_for_completions(
            &committee,
            &mut test_state.dwallet_mpc_services,
            &mut test_state.sent_consensus_messages_collectors,
            &test_state.epoch_stores,
            &test_state.notify_services,
        )
        .await
        {
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }

        utils::send_advance_results_between_parties(
            &committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
    }
    info!("DWallet DKG first round completed");
}

pub(crate) fn send_network_key_to_parties(
    parties_to_send_network_key_to: Vec<usize>,
    sui_data_senders: &mut Vec<SuiDataSenders>,
    network_key_bytes: Vec<u8>,
    key_id: Option<ObjectID>,
) {
    sui_data_senders
        .iter()
        .enumerate()
        .filter(|(i, _)| parties_to_send_network_key_to.contains(i))
        .for_each(|(i, mut sui_data_sender)| {
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
}
