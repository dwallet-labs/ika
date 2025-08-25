use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    send_start_dwallet_dkg_first_round_event, send_start_network_dkg_event_to_all_parties,
    send_start_network_dkg_event_to_some_parties,
};
use crate::dwallet_mpc::mpc_session::SessionStatus;
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
/// Make some parties receive session's MPC messages before its start event
async fn some_parties_receive_mpc_message_before_session_start_event() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let ika_network_config = IkaNetworkConfig::new_for_testing();

    let parties_that_receive_session_message_before_start_event = vec![0, 1];
    let parties_that_receive_session_message_after_start_event = (0..committee.voting_rights.len())
        .filter(|i| !parties_that_receive_session_message_before_start_event.contains(i))
        .collect::<Vec<_>>();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        mut sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(4);
    let network_key_id = ObjectID::random();

    send_start_network_dkg_event_to_some_parties(
        &ika_network_config,
        epoch_id,
        &mut sui_data_senders,
        &parties_that_receive_session_message_after_start_event,
        network_key_id,
    );
    let mut consensus_round = 1;
    utils::advance_some_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
        &epoch_stores,
        &notify_services,
        &parties_that_receive_session_message_after_start_event,
    )
    .await;
    utils::send_advance_results_between_parties(
        &committee,
        &mut sent_consensus_messages_collectors,
        &mut epoch_stores,
        consensus_round,
    );
    for dwallet_mpc_service in dwallet_mpc_services.iter_mut() {
        dwallet_mpc_service.run_service_loop_iteration().await;
    }
    consensus_round += 1;
    for i in &parties_that_receive_session_message_before_start_event {
        let dwallet_mpc_service = &mut dwallet_mpc_services[*i];
        let pending_event_session = dwallet_mpc_service
            .dwallet_mpc_manager()
            .mpc_sessions
            .values()
            .next()
            .clone()
            .unwrap();
        assert!(matches!(
            pending_event_session.status,
            SessionStatus::WaitingForSessionRequest
        ));
    }
    send_start_network_dkg_event_to_some_parties(
        &ika_network_config,
        epoch_id,
        &mut sui_data_senders,
        &parties_that_receive_session_message_before_start_event,
        network_key_id,
    );
    utils::advance_some_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
        &epoch_stores,
        &notify_services,
        &parties_that_receive_session_message_before_start_event,
    )
    .await;
    utils::send_advance_results_between_parties(
        &committee,
        &mut sent_consensus_messages_collectors,
        &mut epoch_stores,
        consensus_round,
    );
    consensus_round += 1;
    loop {
        if let Some(pending_checkpoint) = utils::advance_all_parties_and_wait_for_completions(
            &committee,
            &mut dwallet_mpc_services,
            &mut sent_consensus_messages_collectors,
            &epoch_stores,
            &notify_services,
        )
        .await
        {
            assert_eq!(
                consensus_round, 6,
                "Network DKG should complete after 4 rounds, and one round was added for the delayed parties"
            );
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }

        utils::send_advance_results_between_parties(
            &committee,
            &mut sent_consensus_messages_collectors,
            &mut epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
    }
    info!("MPC flow completed successfully");
}
