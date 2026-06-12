use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::integration_tests::network_dkg::create_network_key_test;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::{
    build_test_state, create_test_protocol_config_guard,
};
use crate::dwallet_mpc::mpc_session::SessionStatus;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::collections::HashMap;
use tracing::info;

/// Regression test for the batch-abandoning bug in
/// `handle_computation_results_and_submit_to_consensus`: a result for a
/// missing (or non-active) session must skip ONLY that result — it used to
/// `return`, dropping every other session's round messages in the same
/// batch, which starved those sessions below the message threshold
/// network-wide and wedged the epoch close.
///
/// The batch is a `HashMap`, so iteration order is arbitrary: with six
/// stale entries mixed into six real ones, the buggy `return` drops at
/// least one real message unless every real entry happens to come first
/// (probability 6!*6!/12! < 0.2%). The fixed code is deterministic.
#[tokio::test]
#[cfg(test)]
async fn computation_results_batch_survives_stale_entries() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let mut test_state = build_test_state(4);

    // A network key is required for internal presign sessions to instantiate.
    let (consensus_round, _network_key_bytes, _network_key_id) =
        create_network_key_test(&mut test_state).await;
    test_state.consensus_round = consensus_round as usize;

    // Run a few rounds so internal presign sessions instantiate and are Active.
    for _ in 0..10 {
        utils::send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            test_state.consensus_round as u64,
        );
        test_state.consensus_round += 1;

        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
    }

    let active_session_identifiers: Vec<SessionIdentifier> = test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(session_identifier, session)| {
            session_identifier.session_type() == SessionType::InternalPresign
                && matches!(session.status, SessionStatus::Active { .. })
        })
        .map(|(session_identifier, _)| *session_identifier)
        .take(6)
        .collect();
    assert!(
        !active_session_identifiers.is_empty(),
        "expected active internal presign sessions to exist"
    );
    info!(
        count = active_session_identifiers.len(),
        "collected active internal presign sessions"
    );

    let mut batch: HashMap<
        ComputationId,
        ika_types::dwallet_mpc_error::DwalletMPCResult<GuaranteedOutputDeliveryRoundResult>,
    > = HashMap::new();
    for session_identifier in &active_session_identifiers {
        batch.insert(
            ComputationId {
                session_identifier: *session_identifier,
                mpc_round: Some(2),
                attempt_number: 1,
                consensus_round: test_state.consensus_round as u64,
            },
            Ok(GuaranteedOutputDeliveryRoundResult::Advance {
                message: vec![9u8; 8],
            }),
        );
    }
    // Stale entries: sessions that don't exist in the manager (e.g., a
    // result landing after its session completed via the peers' quorum).
    for stale_index in 0..6u8 {
        batch.insert(
            ComputationId {
                session_identifier: SessionIdentifier::new(
                    SessionType::InternalPresign,
                    [200 + stale_index; 32],
                ),
                mpc_round: Some(2),
                attempt_number: 1,
                consensus_round: test_state.consensus_round as u64,
            },
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message: vec![1u8] }),
        );
    }

    test_state.sent_consensus_messages_collectors[0]
        .submitted_messages
        .lock()
        .unwrap()
        .clear();

    test_state.dwallet_mpc_services[0]
        .handle_computation_results_and_submit_to_consensus(batch)
        .await;

    let submitted_session_identifiers: Vec<SessionIdentifier> = test_state
        .sent_consensus_messages_collectors[0]
        .submitted_messages
        .lock()
        .unwrap()
        .iter()
        .filter_map(|transaction| match &transaction.kind {
            ConsensusTransactionKind::DWalletMPCMessage(message) => {
                Some(message.session_identifier)
            }
            _ => None,
        })
        .collect();

    for session_identifier in &active_session_identifiers {
        assert!(
            submitted_session_identifiers.contains(session_identifier),
            "round message for active session {session_identifier:?} was dropped from the batch \
             (a stale entry aborted batch processing)"
        );
    }
}
