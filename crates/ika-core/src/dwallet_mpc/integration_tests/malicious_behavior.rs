use crate::dwallet_mpc::integration_tests::utils;
use ika_types::committee::Committee;
use ika_types::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind};
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent,
    DWalletSessionEventTrait, IkaNetworkConfig,
};
use itertools::Itertools;
use std::collections::HashMap;
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn test_some_malicious_validators_flows_succeed() {
    let committee_size = 7;
    let malicious_parties = [1, 2];

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
    assert!(
        committee_size - malicious_parties.len() >= committee.quorum_threshold as usize,
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
        sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        mut notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DBSuiEvent {
                type_: DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(
                    &ika_network_config,
                ),
                // The base64 encoding of an actual start network DKG event.
                contents: base64::decode("Z7MmXd0I4lvGWLDA969YOVo7wrZlXr21RMvixIFabCqAU3voWC2pRFG3QwPYD+ta0sX5poLEkq77ovCi3BBQDgEAAAAAAAAAgFN76FgtqURRt0MD2A/rWtLF+aaCxJKu+6LwotwQUA4BAQAAAAAAAAAggZwXRQsb/ha4mk5xZZfqItaokplduZGMnsuEQzdm7UTt2Z+ktotfGXHn2YVaxxqVhDM8UaafXejIDXnaPLxaMAA=").unwrap(),
                pulled: true,
            }],
            epoch_id,
        ));
    });
    let mut mpc_round = 1;
    utils::advance_all_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
        &epoch_stores,
        &notify_services,
    )
    .await;

    for malicious_party_index in malicious_parties {
        // Create a malicious message for round 1, and set it as the patty's message.
        let mut original_message = sent_consensus_messages_collectors[malicious_party_index]
            .submitted_messages
            .lock()
            .unwrap()
            .remove(0);
        let ConsensusTransactionKind::DWalletMPCMessage(ref mut msg) = original_message.kind else {
            panic!("Network DKG first round should produce a DWalletMPCMessage");
        };
        let mut new_message: Vec<u8> = vec![0];
        new_message.extend(bcs::to_bytes::<u64>(&1).unwrap());
        new_message.extend([3; 48]);
        msg.message = new_message;
        sent_consensus_messages_collectors[malicious_party_index]
            .submitted_messages
            .lock()
            .unwrap()
            .push(original_message);
    }

    utils::send_advance_results_between_parties(
        &committee,
        &mut sent_consensus_messages_collectors,
        &mut epoch_stores,
        mpc_round,
    );
    mpc_round += 1;
    info!("Starting malicious behavior test");
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
            assert_eq!(mpc_round, 5, "Network DKG should complete after 4 rounds");
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }
        info!(?mpc_round, "Advanced MPC round");
        utils::send_advance_results_between_parties(
            &committee,
            &mut sent_consensus_messages_collectors,
            &mut epoch_stores,
            mpc_round,
        );
        info!(?mpc_round, "Sent advance results for MPC round");
        mpc_round += 1;
    }
    for malicious_party_index in malicious_parties {
        let malicious_actor_name = dwallet_mpc_services[malicious_party_index].name;
        assert!(
            dwallet_mpc_services.iter().all(|service| service
                .dwallet_mpc_manager()
                .is_malicious_actor(&malicious_actor_name)),
            "All services should recognize the malicious actor: {}",
            malicious_actor_name
        );
    }
}

#[tokio::test]
#[cfg(test)]
async fn test_party_copies_other_party_message_dkg_round() {
    let committee_size = 4;
    let copying_parties = HashMap::from([(1, 2)]); // Party 1 copies party 2's message

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
    let all_malicious_parties = copying_parties.keys().collect_vec();
    let all_flow_malicious_parties_len = all_malicious_parties.len();
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    assert!(
        committee_size - all_malicious_parties.len() >= committee.quorum_threshold as usize,
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
        sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
        mut notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DBSuiEvent {
                type_: DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(
                    &ika_network_config,
                ),
                // The base64 encoding of an actual start network DKG event.
                contents: base64::decode("Z7MmXd0I4lvGWLDA969YOVo7wrZlXr21RMvixIFabCqAU3voWC2pRFG3QwPYD+ta0sX5poLEkq77ovCi3BBQDgEAAAAAAAAAgFN76FgtqURRt0MD2A/rWtLF+aaCxJKu+6LwotwQUA4BAQAAAAAAAAAggZwXRQsb/ha4mk5xZZfqItaokplduZGMnsuEQzdm7UTt2Z+ktotfGXHn2YVaxxqVhDM8UaafXejIDXnaPLxaMAA=").unwrap(),
                pulled: true,
            }],
            epoch_id,
        ));
    });
    let mut mpc_round = 1;
    utils::advance_all_parties_and_wait_for_completions(
        &committee,
        &mut dwallet_mpc_services,
        &mut sent_consensus_messages_collectors,
        &epoch_stores,
        &notify_services,
    )
    .await;

    for (copying_party, copied_party) in copying_parties.iter() {
        utils::replace_party_message_with_other_party_message(
            *copying_party as usize,
            *copied_party as usize,
            mpc_round,
            &mut sent_consensus_messages_collectors,
        );
    }

    utils::send_advance_results_between_parties(
        &committee,
        &mut sent_consensus_messages_collectors,
        &mut epoch_stores,
        mpc_round,
    );
    mpc_round += 1;
    info!("Starting malicious behavior test");
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
            assert_eq!(mpc_round, 5, "Network DKG should complete after 4 rounds");
            info!(?pending_checkpoint, "MPC flow completed successfully");
            break;
        }
        info!(?mpc_round, "Advanced MPC round");
        utils::send_advance_results_between_parties(
            &committee,
            &mut sent_consensus_messages_collectors,
            &mut epoch_stores,
            mpc_round,
        );
        info!(?mpc_round, "Sent advance results for MPC round");
        mpc_round += 1;
    }
    for malicious_party_index in all_malicious_parties {
        let malicious_actor_name = dwallet_mpc_services[*malicious_party_index as usize].name;
        assert!(
            dwallet_mpc_services.iter().all(|service| service
                .dwallet_mpc_manager()
                .is_malicious_actor(&malicious_actor_name)),
            "All services should recognize the malicious actor: {}",
            malicious_actor_name
        );
    }
}
