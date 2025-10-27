use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::IntegrationTestState;
use crate::dwallet_mpc::mpc_session::SessionStatus;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::ProtocolData;
use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use ika_types::committee::Committee;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use sui_types::base_types::ObjectID;

#[tokio::test]
#[cfg(test)]
async fn test_handle_mpc_request_with_invalid_protocol_data_returns_failed() {
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

    let committee_size = 4;
    let (_committee, _) = Committee::new_simple_test_committee_of_size(committee_size);
    let (
        _dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        _epoch_stores,
        _notify_services,
    ) = utils::create_dwallet_mpc_services(committee_size);

    let (_, _, key_id) = create_network_key_test(&mut test_state).await;

    for service in &mut test_state.dwallet_mpc_services {
        let mpc_manager = service.dwallet_mpc_manager_mut();
        // Create a request with invalid protocol data that will cause deserialization to fail
        let request = DWalletSessionRequest {
            session_type: SessionType::User,
            session_identifier: SessionIdentifier::new(SessionType::User, [3u8; 32]),
            session_sequence_number: 3,
            protocol_data: ProtocolData::ImportedKeyVerification {
                data: crate::request_protocol_data::ImportedKeyVerificationData {
                    curve: DWalletCurve::Secp256k1,
                    encrypted_centralized_secret_share_and_proof: vec![], // Empty data will cause deserialization to fail
                    encryption_key: vec![], // Empty data will cause deserialization to fail
                },
                dwallet_id: ObjectID::from_bytes([1; 32]).unwrap(),
                encrypted_user_secret_key_share_id: ObjectID::from_bytes([1; 32]).unwrap(),
                dwallet_network_encryption_key_id: key_id,
                centralized_party_message: vec![], // Empty data will cause deserialization to fail
            },
            epoch: 1,
            requires_network_key_data: true,
            requires_next_active_committee: false,
            pulled: false,
        };

        let result = mpc_manager.handle_mpc_request(request);

        // Should return Some(SessionStatus::Failed) due to invalid protocol data
        assert_eq!(result, Some(SessionStatus::Failed));
    }
}
