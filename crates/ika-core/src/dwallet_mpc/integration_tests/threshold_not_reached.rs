use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use ika_types::committee::Committee;
use ika_types::messages_consensus::ConsensusTransactionKind;
use itertools::Itertools;
use std::collections::HashMap;
use sui_types::messages_consensus::Round;
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn test_threshold_not_reached_n_times_flow_succeeds() {
    let committee_size = 4;
    let crypto_round_to_malicious_parties: HashMap<usize, Vec<usize>> =
        HashMap::from([(3, [0].to_vec())]);
    let crypto_round_to_delayed_parties: HashMap<usize, Vec<usize>> =
        HashMap::from([(3, [1].to_vec())]);
    let expected_threshold_not_reached_occurrences_crypto_rounds = [4];

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
    let epoch_id = 1;
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);
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
    utils::send_start_network_dkg_event_to_all_parties(epoch_id, &mut test_state).await;
    loop {
        let previous_rounds_malicious_parties = crypto_round_to_malicious_parties
            .iter()
            .filter(|(round, _)| *round < &test_state.crypto_round)
            .flat_map(|(_, parties)| parties)
            .collect_vec();
        let active_parties = (0..committee_size)
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
        let round_honest_parties = round_non_delayed_parties
            .iter()
            .filter(|party_index| !round_malicious_parties.contains(party_index))
            .cloned()
            .collect_vec();
        let expects_threshold_not_reached_messages =
            expected_threshold_not_reached_occurrences_crypto_rounds
                .contains(&test_state.crypto_round);
        if advance_parties_and_replace_malicious_parties_messages(
            &mut test_state,
            &round_non_delayed_parties,
            &round_malicious_parties,
            *round_honest_parties.first().unwrap(),
            expects_threshold_not_reached_messages,
        )
        .await
        {
            info!("MPC flow completed successfully");
            break;
        }
        if !round_delayed_parties.is_empty() {
            test_state.consensus_round += 1;
            if advance_parties_and_send_results(&mut test_state, &round_delayed_parties).await {
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
    let network_dkg_mpc_rounds = 5;
    assert_eq!(
        test_state.crypto_round,
        network_dkg_mpc_rounds + expected_threshold_not_reached_occurrences_crypto_rounds.len(),
        "Consensus round should be equal to the number of network DKG rounds plus the expected threshold not reached occurrences"
    )
}

/// To mimic malicious behavior, we make the malicious parties copy their round message from the honest party.
pub(crate) async fn advance_parties_and_replace_malicious_parties_messages(
    test_state: &mut IntegrationTestState,
    parties_to_advance: &[usize],
    malicious_parties: &[usize],
    honest_party: usize,
    expects_threshold_not_reached_messages: bool,
) -> bool {
    assert!(
        !malicious_parties.contains(&honest_party),
        "Honest party should not be in the malicious parties"
    );

    if let Some(pending_checkpoint) = utils::advance_some_parties_and_wait_for_completions(
        &test_state.committee,
        &mut test_state.dwallet_mpc_services,
        &mut test_state.sent_consensus_messages_collectors,
        &test_state.epoch_stores,
        &test_state.notify_services,
        parties_to_advance,
    )
    .await
    {
        info!(?pending_checkpoint, "MPC flow completed successfully");
        return true;
    }

    if expects_threshold_not_reached_messages {
        for (index, message_collector) in test_state
            .sent_consensus_messages_collectors
            .iter()
            .enumerate()
        {
            if !parties_to_advance.contains(&index) {
                continue;
            }
            let last_message = message_collector
                .submitted_messages
                .lock()
                .unwrap()
                .clone()
                .pop()
                .unwrap();
            let ConsensusTransactionKind::DWalletMPCMessage(msg) = last_message.kind else {
                panic!("Expected a DWalletMPCMessage, got: {:?}", last_message.kind);
            };
            assert_eq!(
                msg.message[0], 1,
                "Expected a threshold not reached message (the first byte in such messages is 1)"
            );
        }
    }

    for party in malicious_parties {
        utils::replace_party_message_with_other_party_message(
            *party,
            honest_party,
            test_state.crypto_round as u64,
            &mut test_state.sent_consensus_messages_collectors,
        );
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        test_state.consensus_round as Round,
    );
    false
}

pub(crate) async fn advance_parties_and_send_results(
    test_state: &mut IntegrationTestState,
    parties_to_advance: &[usize],
) -> bool {
    info!(
        "Advancing parties: {:?} in crypto round: {}",
        parties_to_advance, test_state.crypto_round
    );
    if let Some(pending_checkpoint) = utils::advance_some_parties_and_wait_for_completions(
        &test_state.committee,
        &mut test_state.dwallet_mpc_services,
        &mut test_state.sent_consensus_messages_collectors,
        &test_state.epoch_stores,
        &test_state.notify_services,
        parties_to_advance,
    )
    .await
    {
        info!(?pending_checkpoint, "MPC flow completed successfully");
        return true;
    }
    utils::send_advance_results_between_parties(
        &test_state.committee,
        &mut test_state.sent_consensus_messages_collectors,
        &mut test_state.epoch_stores,
        test_state.consensus_round as Round,
    );
    false
}
