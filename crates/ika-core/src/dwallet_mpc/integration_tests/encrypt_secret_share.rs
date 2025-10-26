use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::create_dwallet::create_dwallet_test;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{EncryptedShareVerificationData, ProtocolData};
use dwallet_mpc_centralized_party::{
    encrypt_secret_key_share_and_prove_v1, network_dkg_public_output_to_protocol_pp_inner,
};
use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use ika_types::committee::Committee;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::{EpochId, ObjectID};
use tracing::info;

#[tokio::test]
#[cfg(test)]
async fn encrypt_secret_share() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
    let epoch_id = 1;
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
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
            .last_session_to_complete_in_current_epoch = 40;
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
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(0, network_key_bytes).unwrap();
    let encrypted_secret_share = encrypt_secret_key_share_and_prove_v1(
        dwallet_test_result.dwallet_secret_key_share.clone(),
        dwallet_test_result.class_groups_encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_encrypt_secret_share_event(
        epoch_id,
        &test_state.sui_data_senders,
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
    let (_, encrypted_secret_share_checkpoint) = utils::advance_mpc_flow_until_completion(
        &mut test_state,
        dwallet_test_result.flow_completion_consensus_round,
    )
    .await;
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

pub(crate) fn send_start_encrypt_secret_share_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    decentralized_public_output: Vec<u8>,
    encryption_key: Vec<u8>,
) {
    let random_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number,
                protocol_data: ProtocolData::EncryptedShareVerification {
                    data: EncryptedShareVerificationData {
                        curve: DWalletCurve::Secp256k1,
                        encrypted_centralized_secret_share_and_proof:
                            encrypted_centralized_secret_share_and_proof.clone(),
                        decentralized_public_output: decentralized_public_output.clone(),
                        encryption_key: encryption_key.clone(),
                    },
                    dwallet_id,
                    encrypted_user_secret_key_share_id: random_id,
                    dwallet_network_encryption_key_id,
                },
                epoch: epoch_id,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}
