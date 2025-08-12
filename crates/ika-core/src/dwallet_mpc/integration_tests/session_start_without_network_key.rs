use crate::dwallet_mpc::generate_access_structure_from_committee;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::network_dkg::instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output;
use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use itertools::Itertools;
use std::collections::HashMap;
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn test_session_start_before_network_key_is_available() {
    let committee_size = 4;

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
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
        committee: committee.clone(),
    };
    let all_parties: Vec<usize> = (0..committee_size).collect();
    loop {
        if let Some(network_dkg_output_checkpoint) =
            utils::advance_parties_and_send_result_messages(&mut test_state, &all_parties, &[])
                .await
        {
            let mut network_key_bytes = Vec::new();
            for checkpoint_message in network_dkg_output_checkpoint
                .messages()
                .into_iter()
                .filter_map(|message| {
                    if let DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(
                        network_dkg_output,
                    ) = message
                    {
                        Some(network_dkg_output)
                    } else {
                        None
                    }
                })
            {
                network_key_bytes.push(checkpoint_message.public_output.clone());
            }
            let key =
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
                    1,
                    DWalletMPCNetworkKeyScheme::Secp256k1,
                    &generate_access_structure_from_committee(&committee).unwrap(),
                    &network_key_bytes.into_iter().flatten().collect_vec(),
                )
                .unwrap();
            info!("MPC flow completed successfully");
            break;
        }
        test_state.crypto_round += 1;
        test_state.consensus_round += 1;
    }
}
