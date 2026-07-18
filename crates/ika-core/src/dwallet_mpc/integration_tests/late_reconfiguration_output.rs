// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Regression tests for the honest-straggler ordering that made the literal
//! v1.1.8 mixed-rollout release gate nondeterministic:
//!
//! 1. three old authorities finalize a network-key reconfiguration with
//!    identical outputs;
//! 2. this validator is still computing;
//! 3. the quorum closes the session (`complete_mpc_session`);
//! 4. this validator's computation returns `Finalize` shortly afterwards.
//!
//! Production correctly discards the late result without submitting it — but
//! it must record the discarded output's raw-bytes digest next to the
//! quorum-agreed output's raw-bytes digest, because that comparison is the
//! only remaining byte-level compatibility evidence for this validator. These
//! tests pin the whole discard-site contract: nothing is submitted, the
//! session stays completed, the digests are recorded and exported, a matching
//! digest is flagged as a match, and divergent bytes are flagged loudly.

use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::TestingSubmitToConsensus;
use crate::dwallet_mpc::mpc_diagnostics::{
    MpcAnomalyKind, SessionDiagnosticEvent, raw_output_digest,
};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::request_protocol_data::{NetworkEncryptionKeyReconfigurationData, ProtocolData};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::message::{DWalletCheckpointMessageKind, MPCNetworkReconfigurationOutput};
use ika_types::messages_dwallet_mpc::{
    DWalletMPCOutput, DWalletMPCOutputReport, SessionIdentifier, SessionType,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;

fn network_key_id() -> ObjectID {
    ObjectID::from_single_byte(9)
}

/// A submitted network-key reconfiguration output report, chunked through the
/// REAL production chunker (`slice_public_output_into_messages`), so the
/// quorum-side raw-bytes digest is pinned against production's actual slicing
/// rather than a test copy that could drift.
fn reconfiguration_report(
    authority: AuthorityName,
    session_identifier: SessionIdentifier,
    output_bytes: &[u8],
) -> DWalletMPCOutputReport {
    let output = DWalletMPCService::slice_public_output_into_messages(
        output_bytes.to_vec(),
        |public_output, is_last| {
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(
                MPCNetworkReconfigurationOutput {
                    dwallet_network_encryption_key_id: network_key_id().to_vec(),
                    public_output,
                    supported_curves: vec![],
                    is_last,
                    rejected: false,
                    session_sequence_number: 3,
                },
            )
        },
    );
    DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority,
        session_identifier,
        output,
        malicious_authorities: vec![],
    })
}

fn reconfiguration_request(session_identifier: SessionIdentifier) -> DWalletSessionRequest {
    DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: SessionType::System,
        session_identifier,
        session_sequence_number: Some(3),
        protocol_data: ProtocolData::NetworkEncryptionKeyReconfiguration {
            data: NetworkEncryptionKeyReconfigurationData {},
            dwallet_network_encryption_key_id: network_key_id(),
        },
        epoch: 1,
        requires_network_key_data: true,
        requires_next_active_committee: true,
        pulled: false,
    }
}

fn reconfiguration_protocol_name(request: &DWalletSessionRequest) -> String {
    DWalletSessionRequestMetricData::from(&request.protocol_data)
        .name()
        .to_owned()
}

/// Bring service 0 to the exact pre-straggler state: three peers finalized
/// identical outputs at `quorum_round` and the quorum completed the session
/// while this validator produced nothing. When `request_observed` the session
/// carries the reconfiguration request metadata first (the same calls the
/// real request-arrival path performs), which is what arms the late-output
/// capture.
fn setup_quorum_completed_session(
    session_identifier: SessionIdentifier,
    output_bytes: &[u8],
    quorum_round: u64,
    request_observed: bool,
) -> (
    Vec<DWalletMPCService>,
    Vec<Arc<TestingSubmitToConsensus>>,
    DWalletSessionRequest,
) {
    let (mut services, _, sent_consensus_messages_collectors, _, _, _, _) =
        utils::create_dwallet_mpc_services(4);
    let authorities: Vec<AuthorityName> = services[0].committee.names().copied().collect();
    let request = reconfiguration_request(session_identifier);
    if request_observed {
        // One below-quorum output creates the session entry to stamp.
        services[0].dwallet_mpc_manager_mut().handle_output(
            quorum_round - 2,
            reconfiguration_report(authorities[1], session_identifier, output_bytes),
        );
        let session = services[0]
            .dwallet_mpc_manager_mut()
            .sessions
            .get_mut(&session_identifier)
            .expect("session exists after the first output");
        session.set_request_diagnostic_metadata(&request);
        session.set_protocol_name(reconfiguration_protocol_name(&request));
    }
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| reconfiguration_report(*authority, session_identifier, output_bytes))
        .collect();
    let (_, completed) = services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(quorum_round, reports);
    assert_eq!(completed, vec![session_identifier]);
    (services, sent_consensus_messages_collectors, request)
}

/// Inject the straggler's late `Finalize` (~195ms after quorum in the
/// observed CI failure) and assert the invariant every variant shares: a
/// completed session's late result is never submitted to consensus.
async fn submit_late_finalize(
    service: &mut DWalletMPCService,
    collector: &Arc<TestingSubmitToConsensus>,
    session_identifier: SessionIdentifier,
    quorum_round: u64,
    output_bytes: Vec<u8>,
) {
    let result: DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> =
        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: vec![],
            public_output_value: output_bytes,
        });
    collector.submitted_messages.lock().unwrap().clear();
    service
        .handle_computation_results_and_submit_to_consensus(HashMap::from([(
            ComputationId {
                session_identifier,
                mpc_round: Some(3),
                attempt_number: 1,
                consensus_round: quorum_round,
            },
            result,
        )]))
        .await;
    assert!(
        collector.submitted_messages.lock().unwrap().is_empty(),
        "a late finalize for a completed session must not submit anything to consensus"
    );
}

#[tokio::test]
#[cfg(test)]
async fn late_reconfiguration_finalize_after_quorum_records_digest_without_submitting() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let session_identifier = SessionIdentifier::new(SessionType::System, [21; 32]);
    // Multiple chunks (>5 KB) so the quorum-side digest exercises in-order
    // chunk reassembly, not just the single-chunk case.
    let output_bytes: Vec<u8> = (0..12_000u32).map(|byte| (byte % 251) as u8).collect();
    let quorum_round = 5_902;
    let (mut services, collectors, request) =
        setup_quorum_completed_session(session_identifier, &output_bytes, quorum_round, true);

    let expected_digest = raw_output_digest(&output_bytes);
    {
        let session = services[0]
            .dwallet_mpc_manager()
            .sessions
            .get(&session_identifier)
            .unwrap();
        assert_eq!(
            session.quorum_raw_output_digest,
            Some(expected_digest),
            "quorum completion must stash the winning output's raw-bytes digest \
             (reassembled from the in-order chunks) before the session goes non-active"
        );
        assert!(session.late_output.is_none());
    }

    // The local computation returns `Finalize` with the SAME bytes the quorum
    // agreed on. The session is non-active, so the result is discarded — but
    // its digest must be recorded and compared.
    submit_late_finalize(
        &mut services[0],
        &collectors[0],
        session_identifier,
        quorum_round,
        output_bytes.clone(),
    )
    .await;

    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    let late_output = session.late_output.as_ref().expect("late output recorded");
    assert_eq!(late_output.digest, expected_digest);
    assert_eq!(late_output.reported_malicious_count, 0);
    let snapshot = session
        .last_anomaly_snapshot()
        .expect("the discard site emits a ComputationUpdateAfterSessionCompletion snapshot");
    assert_eq!(
        snapshot.anomaly_kind,
        MpcAnomalyKind::ComputationUpdateAfterSessionCompletion
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"late_network_key_output_matched_quorum"),
        "matching bytes must be flagged as a match: {:?}",
        snapshot.trigger_conditions
    );
    assert!(snapshot.recent_trace.iter().any(|event| matches!(
        event,
        SessionDiagnosticEvent::LateOutputAfterCompletion {
            matches_quorum: Some(true),
            reported_malicious_count: 0,
            ..
        }
    )));

    // The digest pair must be scrapeable: this is what lets the release-gate
    // harness accept the boundary as conclusive compatibility evidence.
    services[0]
        .dwallet_mpc_manager_mut()
        .refresh_observability_metrics();
    let manager = services[0].dwallet_mpc_manager();
    let protocol_name = reconfiguration_protocol_name(&request);
    let session_id_label = hex::encode(session_identifier.as_ref());
    let authority_label = services[0].name.to_string();
    let digest_label = hex::encode(expected_digest);
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .session_late_output_info
            .with_label_values(&[
                &protocol_name,
                &session_id_label,
                &authority_label,
                &digest_label,
                &digest_label,
            ])
            .get(),
        1,
        "the late/quorum raw-digest pair must be exported for the compatibility harness"
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .session_late_output_malicious_actors
            .with_label_values(&[&protocol_name, &session_id_label, &authority_label])
            .get(),
        0
    );
}

/// Fault injection for the digest comparison itself: identical ordering, but
/// the late computation returns DIFFERENT bytes. The discard site must flag
/// the divergence (trigger + trace + exported digest pair with unequal
/// labels) while still submitting nothing — the release-gate harness turns
/// that unequal exported pair into a hard failure.
#[tokio::test]
#[cfg(test)]
async fn late_reconfiguration_finalize_with_divergent_bytes_is_flagged() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let session_identifier = SessionIdentifier::new(SessionType::System, [22; 32]);
    let output_bytes = vec![7u8; 6_000];
    let quorum_round = 6_002;
    let (mut services, collectors, request) =
        setup_quorum_completed_session(session_identifier, &output_bytes, quorum_round, true);

    // The upgraded validator really did compute different bytes.
    let mut divergent_bytes = output_bytes.clone();
    divergent_bytes[100] ^= 0xFF;
    submit_late_finalize(
        &mut services[0],
        &collectors[0],
        session_identifier,
        quorum_round,
        divergent_bytes.clone(),
    )
    .await;

    let quorum_digest = raw_output_digest(&output_bytes);
    let divergent_digest = raw_output_digest(&divergent_bytes);
    assert_ne!(quorum_digest, divergent_digest);
    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert_eq!(
        session.late_output.as_ref().map(|late| late.digest),
        Some(divergent_digest)
    );
    assert_eq!(session.quorum_raw_output_digest, Some(quorum_digest));
    let snapshot = session.last_anomaly_snapshot().unwrap();
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"late_network_key_output_diverged_from_quorum"),
        "divergent bytes must be flagged: {:?}",
        snapshot.trigger_conditions
    );
    assert!(snapshot.recent_trace.iter().any(|event| matches!(
        event,
        SessionDiagnosticEvent::LateOutputAfterCompletion {
            matches_quorum: Some(false),
            ..
        }
    )));

    // The exported pair carries UNEQUAL digest labels — the harness-side
    // classification fails hard on exactly this shape.
    services[0]
        .dwallet_mpc_manager_mut()
        .refresh_observability_metrics();
    let manager = services[0].dwallet_mpc_manager();
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .session_late_output_info
            .with_label_values(&[
                &reconfiguration_protocol_name(&request),
                &hex::encode(session_identifier.as_ref()),
                &services[0].name.to_string(),
                &hex::encode(divergent_digest),
                &hex::encode(quorum_digest),
            ])
            .get(),
        1
    );
}

/// A late finalize for a session whose reconfiguration request was never
/// observed must not record or export anything — the capture is deliberately
/// scoped to the network-key reconfiguration compatibility boundary to keep
/// the per-session metric cardinality bounded. It is also the expected
/// honest-straggler race, so no anomaly snapshot may be emitted for it; the
/// occurrence lands on the plain completion-race counter instead.
#[tokio::test]
#[cfg(test)]
async fn late_finalize_for_non_reconfiguration_session_records_nothing() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let session_identifier = SessionIdentifier::new(SessionType::System, [23; 32]);
    let output_bytes = vec![5u8; 64];
    let quorum_round = 7_002;
    let (mut services, collectors, _) =
        setup_quorum_completed_session(session_identifier, &output_bytes, quorum_round, false);

    submit_late_finalize(
        &mut services[0],
        &collectors[0],
        session_identifier,
        quorum_round,
        output_bytes,
    )
    .await;

    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert!(session.late_output.is_none());
    assert_eq!(session.emitted_anomaly_count(), 0);
    assert!(session.last_anomaly_snapshot().is_none());
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .completion_races_total
            .with_label_values(&[
                "local_computation_update_received_after_session_became_non_active",
                "system",
            ])
            .get(),
        1
    );
}
