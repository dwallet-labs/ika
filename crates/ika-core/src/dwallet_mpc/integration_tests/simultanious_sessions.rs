use crate::dwallet_mpc::integration_tests::utils;
use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletSessionEvent,
    DWalletSessionEventTrait, IkaNetworkConfig,
};
use itertools::Itertools;
use std::collections::HashMap;
use tracing::info;

fn create_test_state(committee_size: usize) -> utils::IntegrationTestState {
    let (committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);
    utils::IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
    }
}

#[tokio::test]
#[cfg(test)]
async fn test_malicious_parties_detected_in_correct_time() {
    let committee_size = 4;
    let crypto_round_to_malicious_parties: HashMap<usize, Vec<usize>> =
        HashMap::from([(1, [0].to_vec())]);
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut test_state = create_test_state(committee_size);
    let all_malicious_parties = crypto_round_to_malicious_parties
        .values()
        .flatten()
        .collect_vec();
    let all_flow_malicious_parties_len = all_malicious_parties.len();
    assert!(
        committee_size - all_flow_malicious_parties_len
            >= test_state.committee.quorum_threshold as usize,
        "There should be a quorum of honest parties for the flow to succeed"
    );
    assert_eq!(
        test_state.committee.voting_rights.len(),
        committee_size,
        "Committee size should match the expected size"
    );
    let ika_network_config = IkaNetworkConfig::new_for_testing();
    let epoch_id = 1;
    utils::send_configurable_start_network_dkg_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        [1; 32],
        1,
    );
    utils::send_configurable_start_network_dkg_event(
        &ika_network_config,
        epoch_id,
        &mut test_state.sui_data_senders,
        [2; 32],
        2,
    );
    loop {
        let active_parties = (0..committee_size).collect_vec();
        let round_malicious_parties = crypto_round_to_malicious_parties
            .get(&test_state.crypto_round)
            .cloned()
            .unwrap_or_default();
        if utils::advance_parties_and_send_result_messages(
            &mut test_state,
            &active_parties,
            &round_malicious_parties,
        )
        .await
        {
            info!("MPC flow completed successfully");
            break;
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
