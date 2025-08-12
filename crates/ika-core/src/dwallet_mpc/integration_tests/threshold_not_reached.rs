use crate::SuiDataSenders;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    TestingAuthorityPerEpochStore, TestingDWalletCheckpointNotify, TestingSubmitToConsensus,
};
use ika_types::committee::Committee;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent,
    DWalletSessionEventTrait, IkaNetworkConfig,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::EpochId;
use sui_types::messages_consensus::Round;
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn test_threshold_not_reached_n_times_flow_succeeds() {
    let committee_size = 4;
    let crypto_round_to_malicious_parties: HashMap<usize, Vec<usize>> =
        HashMap::from([(1, [0].to_vec())]);
    let crypto_round_to_delayed_parties: HashMap<usize, Vec<usize>> =
        HashMap::from([(1, [1].to_vec())]);
    // let crypto_round_to_delayed_parties: HashMap<usize, Vec<usize>> =
    //     HashMap::from([]);

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
    let all_malicious_parties = crypto_round_to_malicious_parties
        .values()
        .flatten()
        .collect_vec();
    let all_flow_malicious_parties_len = all_malicious_parties.len();
    assert!(
        committee_size - all_flow_malicious_parties_len >= committee.quorum_threshold as usize,
        "There should be a quorum of honest parties for the flow to succeed"
    );
    assert_eq!(
        committee.voting_rights.len(),
        committee_size,
        "Committee size should match the expected size"
    );
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    let (
        mut dwallet_mpc_services,
        mut sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);
    utils::send_start_network_dkg_event(&ika_network_config, epoch_id, &mut sui_data_senders);
    let mut test_state = utils::IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
    };
    loop {
        let previous_rounds_malicious_parties = crypto_round_to_malicious_parties
            .iter()
            .filter(|(round, _)| *round < &test_state.crypto_round)
            .map(|(_, parties)| parties)
            .flatten()
            .collect_vec();
        // We don't want to advance parties that acted maliciously in previous rounds, as their behavior is unexpected.
        let active_parties = (0..committee_size)
            .collect_vec()
            .into_iter()
            .filter(|party_index| !previous_rounds_malicious_parties.contains(&party_index))
            .collect_vec();
        let round_delayed_parties = crypto_round_to_delayed_parties
            .get(&test_state.crypto_round)
            .cloned()
            .unwrap_or_default();
        let round_non_delayed_parties = active_parties
            .into_iter()
            .filter(|party_index| !round_delayed_parties.contains(party_index))
            .collect_vec();
        let round_malicious_parties = crypto_round_to_malicious_parties
            .get(&test_state.crypto_round)
            .cloned()
            .unwrap_or_default();
        if advance_parties_and_send_result_messages(
            &mut test_state,
            &round_non_delayed_parties,
            &round_malicious_parties,
        )
        .await
        {
            info!("MPC flow completed successfully");
            break;
        }
        if !round_delayed_parties.is_empty() {
            test_state.consensus_round += 1;
            if advance_parties_and_send_result_messages(
                &mut test_state,
                &round_delayed_parties,
                &round_malicious_parties,
            )
            .await
            {
                info!("MPC flow completed successfully");
                break;
            }
        }
        test_state.crypto_round += 1;
        test_state.consensus_round += 1;
    }
    for malicious_party_index in all_malicious_parties.clone() {
        let malicious_actor_name = test_state.dwallet_mpc_services[*malicious_party_index].name;
        assert!(
            test_state
                .dwallet_mpc_services
                .iter()
                .enumerate()
                .all(|(index, service)| service
                    .dwallet_mpc_manager()
                    .is_malicious_actor(&malicious_actor_name)
                    || all_malicious_parties.contains(&&index)),
            "All services should recognize the malicious actor: {}",
            malicious_actor_name
        );
    }
}

pub(crate) async fn advance_parties_and_send_result_messages(
    mut test_state: &mut utils::IntegrationTestState,
    parties_to_advance: &[usize],
    malicious_parties: &[usize],
) -> bool {
    if let Some(pending_checkpoint) = utils::advance_some_parties_and_wait_for_completions(
        &test_state.committee,
        &mut test_state.dwallet_mpc_services,
        &mut test_state.sent_consensus_messages_collectors,
        &test_state.epoch_stores,
        &test_state.notify_services,
        &parties_to_advance,
    )
    .await
    {
        info!(?pending_checkpoint, "MPC flow completed successfully");
        return true;
    }
    let existing_messages = test_state
        .sent_consensus_messages_collectors
        .iter()
        .filter_map(|collector| {
            collector
                .submitted_messages
                .lock()
                .unwrap()
                .first()
                .cloned()
        })
        .filter_map(|message| {
            if let ConsensusTransactionKind::DWalletMPCMessage(msg) = &message.kind {
                Some(msg.message.clone())
            } else {
                None
            }
        })
        .collect_vec();
    if !existing_messages.is_empty() {
        utils::override_message_with_one_of_messages(
            malicious_parties,
            &mut test_state.sent_consensus_messages_collectors,
            existing_messages,
        );
    } else {
        utils::override_legit_messages_with_false_messages(
            malicious_parties,
            &mut test_state.sent_consensus_messages_collectors,
            test_state.crypto_round as u64,
        )
    }

    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        test_state.consensus_round as Round,
    );
    false
}
