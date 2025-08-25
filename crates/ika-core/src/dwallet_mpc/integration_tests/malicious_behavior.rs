use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::TestingSubmitToConsensus;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{NetworkEncryptionKeyDkgData, ProtocolData};
use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
use ika_types::committee::Committee;
use ika_types::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind};
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent,
    DWalletSessionEventTrait, IkaNetworkConfig, SessionIdentifier, SessionType,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;
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
    let network_key_id = ObjectID::random();
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::System,
                session_identifier: SessionIdentifier::new(SessionType::System, [1; 32]),
                session_sequence_number: 1,
                protocol_data: ProtocolData::NetworkEncryptionKeyDkg {
                    data: NetworkEncryptionKeyDkgData {
                        key_scheme: DWalletMPCNetworkKeyScheme::Secp256k1,
                    },
                    dwallet_network_encryption_key_id: network_key_id,
                },
                epoch: 1,
                requires_network_key_data: false,
                requires_next_active_committee: false,
                pulled: false,
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
            assert_eq!(mpc_round, 5, "Network DKG should complete after 5 rounds");
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
    let network_key_id = ObjectID::random();
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::System,
                session_identifier: SessionIdentifier::new(SessionType::System, [1; 32]),
                session_sequence_number: 1,
                protocol_data: ProtocolData::NetworkEncryptionKeyDkg {
                    data: NetworkEncryptionKeyDkgData {
                        key_scheme: DWalletMPCNetworkKeyScheme::Secp256k1,
                    },
                    dwallet_network_encryption_key_id: network_key_id,
                },
                epoch: 1,
                requires_network_key_data: false,
                requires_next_active_committee: false,
                pulled: false,
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
        replace_party_message_with_other_party_message(
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

pub(crate) fn replace_party_message_with_other_party_message(
    party_to_replace: usize,
    other_party: usize,
    crypto_round: u64,
    sent_consensus_messages_collectors: &mut Vec<Arc<TestingSubmitToConsensus>>,
) {
    let original_message = sent_consensus_messages_collectors[party_to_replace]
        .submitted_messages
        .lock()
        .unwrap()
        .pop()
        .unwrap();

    let mut other_party_message = sent_consensus_messages_collectors[other_party]
        .submitted_messages
        .lock()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let ConsensusTransactionKind::DWalletMPCMessage(ref mut other_party_message_content) =
        other_party_message.kind
    else {
        panic!("Only DWalletMPCMessage messages can be replaced with other party messages");
    };
    let ConsensusTransactionKind::DWalletMPCMessage(mut original_message) = original_message.kind
    else {
        panic!("Only DWalletMPCMessage messages can be replaced with other party messages");
    };
    other_party_message_content.authority = original_message.authority;
    sent_consensus_messages_collectors[party_to_replace]
        .submitted_messages
        .lock()
        .unwrap()
        .push(other_party_message)
}
