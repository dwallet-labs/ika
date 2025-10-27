use crate::SuiDataSenders;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    IntegrationTestState, send_start_dwallet_dkg_first_round_event,
    send_start_dwallet_dkg_second_round_event,
};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    ImportedKeyVerificationData, MakeDWalletUserSecretKeySharesPublicData, ProtocolData,
};
use dwallet_mpc_centralized_party::{
    create_imported_dwallet_centralized_step_inner_v1,
    create_imported_dwallet_centralized_step_inner_v2, encrypt_secret_key_share_and_prove_v1,
    encrypt_secret_key_share_and_prove_v2, generate_cg_keypair_from_seed,
    network_dkg_public_output_to_protocol_pp_inner, sample_dwallet_keypair_inner,
};
use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use ika_types::committee::Committee;
use ika_types::message::{DWalletCheckpointMessageKind, DWalletDKGSecondRoundOutput};
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::messages_consensus::Round;
use tracing::info;

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn dwallet_dkg_first_round() {
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
    let (consensus_round, _, key_id) = create_network_key_test(&mut test_state).await;
    let dwallet_dkg_session_identifier = [2; 32];
    send_start_dwallet_dkg_first_round_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        dwallet_dkg_session_identifier,
        2,
        key_id,
    );
    info!("Starting DWallet DKG first round");
    let (_, dkg_first_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(
        _dwallet_dkg_first_round_output,
    ) = dkg_first_round_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet DKG first round output message");
    };
    info!("DWallet DKG first round completed");
}

pub(crate) struct DWalletTestResult {
    pub(crate) flow_completion_consensus_round: Round,
    pub(crate) dkg_second_round_output: DWalletDKGSecondRoundOutput,
    pub(crate) dwallet_secret_key_share: Vec<u8>,
    pub(crate) class_groups_encryption_key: Vec<u8>,
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn create_dwallet() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, _) = Committee::new_simple_test_committee();
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
            .last_session_to_complete_in_current_epoch = 400;
    }
    let (consensus_round, network_key_bytes, key_id) =
        create_network_key_test(&mut test_state).await;
    create_dwallet_test(&mut test_state, consensus_round, key_id, network_key_bytes).await;
    info!("DWallet DKG second round completed");
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn make_dwallet_public() {
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
    let result =
        create_dwallet_test(&mut test_state, consensus_round, key_id, network_key_bytes).await;
    send_make_dwallet_public_event(
        epoch_id,
        &test_state.sui_data_senders,
        [4; 32],
        4,
        key_id,
        ObjectID::from_bytes(&result.dkg_second_round_output.dwallet_id).unwrap(),
        result.dkg_second_round_output.output,
        result.dwallet_secret_key_share,
    );
    let (_, verified_dwallet_checkpoint) = utils::advance_mpc_flow_until_completion(
        &mut test_state,
        result.flow_completion_consensus_round,
    )
    .await;
    let DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(
        make_dwallet_public_output,
    ) = verified_dwallet_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet make public output message");
    };
    assert!(
        !make_dwallet_public_output.rejected,
        "Make DWallet public output should not be rejected"
    );
    info!("DWallet DKG second round completed");
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn create_imported_dwallet() {
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
    let protocol_pp =
        network_dkg_public_output_to_protocol_pp_inner(0, network_key_bytes.clone()).unwrap();
    let (dwallet_secret_key, _) = sample_dwallet_keypair_inner(protocol_pp.clone()).unwrap();
    let import_dwallet_session_id = [2; 32];
    let (user_secret_share, _, user_message) = create_imported_dwallet_centralized_step_inner_v1(
        &protocol_pp,
        &SessionIdentifier::new(SessionType::User, import_dwallet_session_id).to_vec(),
        &dwallet_secret_key,
    )
    .unwrap();
    let (encryption_key, _) = generate_cg_keypair_from_seed(0, [1; 32]).unwrap();
    let encrypted_secret_key_share_and_proof = encrypt_secret_key_share_and_prove_v1(
        user_secret_share,
        encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_imported_dwallet_verification_event(
        epoch_id,
        &test_state.sui_data_senders,
        import_dwallet_session_id,
        2,
        key_id,
        ObjectID::random(),
        encrypted_secret_key_share_and_proof,
        user_message,
        encryption_key,
    );
    let (_, verified_dwallet_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(
        imported_key_verification_output,
    ) = verified_dwallet_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet imported key verification output message");
    };
    assert!(
        !imported_key_verification_output.rejected,
        "Imported DWallet key verification should not be rejected"
    );
    info!("DWallet DKG second round completed");
}

#[tokio::test]
#[cfg(test)]
/// Runs a network DKG and then uses the resulting network key to run the DWallet DKG first round.
async fn create_imported_dwallet_v2() {
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
    let protocol_pp =
        network_dkg_public_output_to_protocol_pp_inner(0, network_key_bytes.clone()).unwrap();
    let (dwallet_secret_key, _) = sample_dwallet_keypair_inner(protocol_pp.clone()).unwrap();
    let import_dwallet_session_id = [2; 32];
    let (user_secret_share, _, user_message) = create_imported_dwallet_centralized_step_inner_v2(
        0,
        &protocol_pp,
        &SessionIdentifier::new(SessionType::User, import_dwallet_session_id).to_vec(),
        &dwallet_secret_key,
    )
    .unwrap();
    let (encryption_key, _) = generate_cg_keypair_from_seed(0, [1; 32]).unwrap();
    let encrypted_secret_key_share_and_proof = encrypt_secret_key_share_and_prove_v2(
        0,
        user_secret_share,
        encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_imported_dwallet_verification_event(
        epoch_id,
        &test_state.sui_data_senders,
        import_dwallet_session_id,
        2,
        key_id,
        ObjectID::random(),
        encrypted_secret_key_share_and_proof,
        user_message,
        encryption_key,
    );
    let (_, verified_dwallet_checkpoint) =
        utils::advance_mpc_flow_until_completion(&mut test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(
        imported_key_verification_output,
    ) = verified_dwallet_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet imported key verification output message");
    };
    assert!(
        !imported_key_verification_output.rejected,
        "Imported DWallet key verification should not be rejected"
    );
    info!("DWallet DKG second round completed");
}

pub(crate) async fn create_dwallet_test(
    test_state: &mut IntegrationTestState,
    start_consensus_round: Round,
    network_key_id: ObjectID,
    network_key_bytes: Vec<u8>,
) -> DWalletTestResult {
    let consensus_round = start_consensus_round;
    let dwallet_dkg_session_identifier = [2; 32];
    let epoch_id = test_state
        .dwallet_mpc_services
        .first()
        .expect("At least one service should exist")
        .epoch;
    send_start_dwallet_dkg_first_round_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        dwallet_dkg_session_identifier,
        2,
        network_key_id,
    );
    info!("Starting DWallet DKG first round");
    let (consensus_round, dkg_first_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(
        dwallet_dkg_first_round_output,
    ) = dkg_first_round_checkpoint.messages().clone().pop().unwrap()
    else {
        panic!("Expected DWallet DKG first round output message");
    };
    info!("DWallet DKG first round completed");
    let protocol_pp = network_dkg_public_output_to_protocol_pp_inner(0, network_key_bytes).unwrap();
    let centralized_dwallet_dkg_result = dwallet_mpc_centralized_party::create_dkg_output_v1(
        protocol_pp.clone(),
        dwallet_dkg_first_round_output.output.clone(),
    )
    .unwrap();
    let (encryption_key, _) = generate_cg_keypair_from_seed(0, [1; 32]).unwrap();
    let encrypted_secret_key_share_and_proof = encrypt_secret_key_share_and_prove_v1(
        centralized_dwallet_dkg_result
            .centralized_secret_output
            .clone(),
        encryption_key.clone(),
        protocol_pp,
    )
    .unwrap();
    send_start_dwallet_dkg_second_round_event(
        epoch_id,
        &test_state.sui_data_senders,
        [3; 32],
        3,
        network_key_id,
        ObjectID::from_bytes(&dwallet_dkg_first_round_output.dwallet_id).unwrap(),
        dwallet_dkg_first_round_output.output,
        centralized_dwallet_dkg_result.public_key_share_and_proof,
        encrypted_secret_key_share_and_proof,
        encryption_key.clone(),
    );
    let (consensus_round, dwallet_second_round_checkpoint) =
        utils::advance_mpc_flow_until_completion(test_state, consensus_round).await;
    let DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(
        decentralized_party_dkg_public_output,
    ) = dwallet_second_round_checkpoint
        .messages()
        .clone()
        .pop()
        .unwrap()
    else {
        panic!("Expected DWallet DKG second round output message");
    };
    info!("DWallet DKG second round completed");
    DWalletTestResult {
        flow_completion_consensus_round: consensus_round,
        dkg_second_round_output: decentralized_party_dkg_public_output.clone(),
        dwallet_secret_key_share: centralized_dwallet_dkg_result.centralized_secret_output,
        class_groups_encryption_key: encryption_key,
    }
}

pub(crate) fn send_start_imported_dwallet_verification_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    centralized_party_message: Vec<u8>,
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
                protocol_data: ProtocolData::ImportedKeyVerification {
                    data: ImportedKeyVerificationData {
                        curve: DWalletCurve::Secp256k1,
                        encrypted_centralized_secret_share_and_proof:
                            encrypted_centralized_secret_share_and_proof.clone(),
                        encryption_key: encryption_key.clone(),
                    },
                    dwallet_id,
                    encrypted_user_secret_key_share_id: random_id,
                    dwallet_network_encryption_key_id,
                    centralized_party_message: centralized_party_message.clone(),
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

pub(crate) fn send_make_dwallet_public_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    public_output: Vec<u8>,
    public_user_secret_key_shares: Vec<u8>,
) {
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number,
                protocol_data: ProtocolData::MakeDWalletUserSecretKeySharesPublic {
                    data: MakeDWalletUserSecretKeySharesPublicData {
                        curve: DWalletCurve::Secp256k1,
                        public_user_secret_key_shares: public_user_secret_key_shares.clone(),
                        dwallet_decentralized_output: public_output.clone(),
                    },
                    dwallet_id,
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
