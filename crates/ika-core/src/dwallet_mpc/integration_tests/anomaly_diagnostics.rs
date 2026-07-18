use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::mpc_diagnostics::{
    LocalAuthorityMaliciousReason, LocalComputationState, MpcAnomalyContext, MpcAnomalyKind,
    SessionOrigin, output_digest, report_digest,
};
use crate::dwallet_mpc::mpc_manager::MAX_UNTRACKED_ANOMALIES;
use crate::dwallet_mpc::mpc_session::DWalletMPCSessionOutput;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use group::PartyID;
use ika_types::crypto::AuthorityName;
use ika_types::message::{DWalletCheckpointMessageKind, SignOutput};
use ika_types::messages_dwallet_mpc::{
    DWalletInternalMPCOutput, DWalletInternalMPCOutputKind, DWalletMPCOutput, DWalletMPCOutputKind,
    DWalletMPCOutputReport, SessionIdentifier, SessionType,
};
use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;

fn internal_output_kind(
    session_identifier: SessionIdentifier,
    marker: Vec<u8>,
) -> DWalletMPCOutputKind {
    DWalletMPCOutputKind::Internal {
        output: DWalletInternalMPCOutputKind::NetworkOwnedAddressSign {
            output: marker,
            session_identifier,
            message: vec![],
            curve: DWalletCurve::Curve25519,
            signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
            hash_scheme: DWalletHashScheme::SHA512,
        },
    }
}

fn session_output(
    session_identifier: SessionIdentifier,
    marker: Vec<u8>,
    malicious_authorities: Vec<AuthorityName>,
) -> DWalletMPCSessionOutput {
    let output = internal_output_kind(session_identifier, marker);
    DWalletMPCSessionOutput {
        output_digest: output_digest(&output).unwrap(),
        report_digest: report_digest(&output, &malicious_authorities).unwrap(),
        output,
        malicious_authorities,
        rejected: false,
    }
}

fn internal_report(
    authority: AuthorityName,
    session_identifier: SessionIdentifier,
    marker: Vec<u8>,
    malicious_authorities: Vec<AuthorityName>,
) -> DWalletMPCOutputReport {
    DWalletMPCOutputReport::Internal(DWalletInternalMPCOutput {
        authority,
        session_identifier,
        output: match internal_output_kind(session_identifier, marker) {
            DWalletMPCOutputKind::Internal { output } => output,
            DWalletMPCOutputKind::External { .. } => unreachable!(),
        },
        malicious_authorities,
    })
}

fn rejected_report(
    authority: AuthorityName,
    session_identifier: SessionIdentifier,
) -> DWalletMPCOutputReport {
    DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority,
        session_identifier,
        output: vec![DWalletCheckpointMessageKind::RespondDWalletSign(
            SignOutput {
                signature: vec![],
                dwallet_id: vec![1; 32],
                is_future_sign: false,
                sign_id: vec![2; 32],
                rejected: true,
                session_sequence_number: 7,
            },
        )],
        malicious_authorities: vec![],
    })
}

fn authorities(service_index: usize) -> (Vec<AuthorityName>, Vec<DWalletMPCService>) {
    let (services, _, _, _, _, _, _) = utils::create_dwallet_mpc_services(4);
    let authorities = services[service_index].committee.names().copied().collect();
    (authorities, services)
}

#[test]
fn normal_quorum_emits_no_anomaly_snapshot() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [10; 32]);
    let reports = authorities
        .iter()
        .take(3)
        .map(|authority| internal_report(*authority, session_identifier, vec![1], vec![]))
        .collect();

    let (_, completed) = services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(10, reports);

    assert_eq!(completed, vec![session_identifier]);
    let session = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap();
    assert_eq!(session.emitted_anomaly_count(), 0);
    assert!(session.last_anomaly_snapshot().is_none());
    assert_eq!(
        services[0]
            .dwallet_mpc_manager()
            .dwallet_mpc_metrics
            .anomaly_snapshots_total
            .with_label_values(&["quorum_anomaly", "system", "warn"])
            .get(),
        0
    );
}

#[test]
fn quorum_rejection_is_explicit_in_snapshot() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [11; 32]);
    let reports = authorities
        .iter()
        .take(3)
        .map(|authority| rejected_report(*authority, session_identifier))
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(22, reports);

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"rejected_output_reached_quorum")
    );
    assert!(snapshot.local_output_rejected.unwrap());
    assert!(snapshot.vote.as_ref().unwrap().rejected);
}

#[test]
fn local_rejected_output_snapshot_includes_safe_error_code_and_metrics() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [17; 32]);
    services[0].dwallet_mpc_manager_mut().handle_output(
        23,
        internal_report(authorities[0], session_identifier, vec![1], vec![]),
    );
    services[0]
        .dwallet_mpc_manager_mut()
        .sessions
        .get_mut(&session_identifier)
        .unwrap()
        .record_local_output_produced(Some(23), Some([8; 32]), true);
    services[0].dwallet_mpc_manager_mut().emit_session_anomaly(
        session_identifier,
        MpcAnomalyKind::LocalRejectedOutput,
        MpcAnomalyContext {
            current_consensus_round: Some(23),
            trigger_conditions: vec!["local_validator_submitting_rejected_output"],
            error_code: Some("mpc_error"),
            ..Default::default()
        },
    );

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(snapshot.local_output_rejected, Some(true));
    assert_eq!(snapshot.error_code, Some("mpc_error"));
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"local_validator_submitting_rejected_output")
    );
    let snapshot_json = snapshot.to_json().unwrap();
    let snapshot_value: serde_json::Value = serde_json::from_str(&snapshot_json).unwrap();
    assert_eq!(snapshot_value["schema_version"], 1);
    assert_eq!(snapshot_value["anomaly_kind"], "local_rejected_output");
    assert_eq!(
        snapshot_value["session_id"],
        hex::encode(session_identifier.into_bytes())
    );
    assert!(!snapshot_json.contains(&hex::encode([17; 32])));
    let manager = services[0].dwallet_mpc_manager();
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_snapshots_total
            .with_label_values(&["local_rejected_output", "system", "warn"])
            .get(),
        1
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_triggers_total
            .with_label_values(&["local_validator_submitting_rejected_output", "system"])
            .get(),
        1
    );
}

#[test]
fn split_vote_reports_groups_weights_winner_and_local_malicious_voter() {
    let (_, mut services) = authorities(0);
    let local_authority = services[0].name;
    let session_identifier = SessionIdentifier::new(SessionType::System, [12; 32]);
    let outputs = HashMap::from([
        (1, session_output(session_identifier, vec![9], vec![])),
        (2, session_output(session_identifier, vec![7], vec![])),
        (3, session_output(session_identifier, vec![7], vec![])),
        (4, session_output(session_identifier, vec![7], vec![])),
    ]);
    let result = services[0]
        .dwallet_mpc_manager_mut()
        .build_outputs_to_finalize(&session_identifier, BTreeMap::from([(31, outputs)]))
        .unwrap();
    let vote = result.vote_diagnostics;

    assert_eq!(vote.vote_groups.len(), 2);
    assert_eq!(
        vote.total_observed_weight,
        vote.vote_groups
            .iter()
            .map(|group| group.voting_weight)
            .sum::<PartyID>()
    );
    assert!(vote.winning_weight >= vote.threshold_required);
    assert_eq!(
        vote.local_authority_malicious_reason,
        Some(LocalAuthorityMaliciousReason::MaliciousVoter)
    );
    assert!(result.malicious_voters.contains(&local_authority));
    assert!(result.reported_malicious_authorities.is_empty());
}

#[test]
fn winning_report_blame_is_separate_from_disagreeing_voters() {
    let (_, mut services) = authorities(0);
    let local_authority = services[0].name;
    let session_identifier = SessionIdentifier::new(SessionType::System, [13; 32]);
    let winning = session_output(session_identifier, vec![7], vec![local_authority]);
    let outputs = HashMap::from([(1, winning.clone()), (2, winning.clone()), (3, winning)]);
    let result = services[0]
        .dwallet_mpc_manager_mut()
        .build_outputs_to_finalize(&session_identifier, BTreeMap::from([(32, outputs)]))
        .unwrap();

    assert!(result.malicious_voters.is_empty());
    assert!(
        result
            .reported_malicious_authorities
            .contains(&local_authority)
    );
    assert_eq!(
        result.vote_diagnostics.local_authority_malicious_reason,
        Some(LocalAuthorityMaliciousReason::ReportedByMajorityOutput)
    );
}

#[test]
fn malicious_other_authority_emits_snapshot_with_self_flag_false() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [19; 32]);
    let malicious_authority = authorities[3];
    let reports = authorities
        .iter()
        .take(3)
        .map(|authority| {
            internal_report(
                *authority,
                session_identifier,
                vec![5],
                vec![malicious_authority],
            )
        })
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(33, reports);

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert!(!snapshot.local_authority_malicious);
    assert!(
        snapshot
            .vote
            .as_ref()
            .unwrap()
            .final_malicious_authorities
            .contains(&malicious_authority)
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"malicious_authority_identified")
    );
}

#[test]
fn self_malicious_service_exit_records_termination_reason() {
    let (authorities, mut services) = authorities(0);
    let local_authority = services[0].name;
    let session_identifier = SessionIdentifier::new(SessionType::System, [18; 32]);
    let reports = authorities
        .iter()
        .take(3)
        .map(|authority| {
            internal_report(
                *authority,
                session_identifier,
                vec![4],
                vec![local_authority],
            )
        })
        .collect();
    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(33, reports);
    assert!(
        services[0]
            .dwallet_mpc_manager()
            .recognized_self_as_malicious
    );
    services[0]
        .dwallet_mpc_manager_mut()
        .emit_self_malicious_service_exit_anomaly(Some(34));

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(
        snapshot.service_loop_termination_reason,
        Some("local_validator_recognized_as_malicious")
    );
    assert!(snapshot.local_authority_malicious);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&snapshot.to_json().unwrap()).unwrap()["local_authority_malicious"],
        true
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"mpc_service_exit_after_self_malicious_recognition")
    );
}

/// Quorum forming before this validator's own output or computation catches
/// up is normal threshold-MPC behavior, not a defect: no anomaly snapshot may
/// be emitted, and the races land on the plain completion-race counter
/// instead (per-session dedup times high session churn flooded the anomaly
/// taxonomy otherwise). The race is only a race for a locally requested
/// session, so the session's origin is upgraded before quorum here.
#[test]
fn benign_quorum_race_counts_without_anomaly_snapshot() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [14; 32]);
    services[0]
        .dwallet_mpc_manager_mut()
        .cryptographic_computations_orchestrator
        .currently_running_cryptographic_computations
        .insert(ComputationId {
            session_identifier,
            consensus_round: 40,
            mpc_round: Some(3),
            attempt_number: 0,
        });
    services[0].dwallet_mpc_manager_mut().handle_output(
        40,
        internal_report(authorities[1], session_identifier, vec![3], vec![]),
    );
    services[0]
        .dwallet_mpc_manager_mut()
        .sessions
        .get_mut(&session_identifier)
        .unwrap()
        .origin = SessionOrigin::LocalRequest;
    let reports = authorities
        .iter()
        .skip(2)
        .take(2)
        .map(|authority| internal_report(*authority, session_identifier, vec![3], vec![]))
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(41, reports);

    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert_eq!(session.emitted_anomaly_count(), 0);
    assert!(session.last_anomaly_snapshot().is_none());
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_snapshots_total
            .with_label_values(&["quorum_anomaly", "system", "warn"])
            .get(),
        0
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .completion_races_total
            .with_label_values(&["quorum_reached_before_local_output_observed", "system"])
            .get(),
        1
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .completion_races_total
            .with_label_values(&["local_computation_pending_at_session_completion", "system"])
            .get(),
        1
    );
}

/// A session known only from peer outputs (its request never activated
/// locally — the dominant shape after a restart) can never have local
/// output; quorum on it is a reconstruction, not a completion race. It
/// lands on `sessions_reconstructed_total` at creation and must not touch
/// the race counter or the anomaly taxonomy at quorum.
#[test]
fn reconstructed_session_quorum_counts_reconstruction_not_race() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [14; 32]);
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| internal_report(*authority, session_identifier, vec![3], vec![]))
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(41, reports);

    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert_eq!(session.origin, SessionOrigin::ReconstructedFromConsensus);
    assert_eq!(session.emitted_anomaly_count(), 0);
    assert!(session.last_anomaly_snapshot().is_none());
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .sessions_reconstructed_total
            .with_label_values(&["system"])
            .get(),
        1
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .completion_races_total
            .with_label_values(&["quorum_reached_before_local_output_observed", "system"])
            .get(),
        0
    );
}

/// When a defect trigger fires for the same quorum on a locally requested
/// session, the snapshot is emitted and carries the benign race conditions
/// as context, the running-computation state, and no protocol payload.
#[test]
fn defect_quorum_snapshot_keeps_race_context_and_redacts_payload() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [14; 32]);
    let malicious_authority = authorities[3];
    let secret_marker = b"PRIVATE_OUTPUT_MUST_NOT_APPEAR".to_vec();
    services[0]
        .dwallet_mpc_manager_mut()
        .cryptographic_computations_orchestrator
        .currently_running_cryptographic_computations
        .insert(ComputationId {
            session_identifier,
            consensus_round: 40,
            mpc_round: Some(3),
            attempt_number: 0,
        });
    services[0].dwallet_mpc_manager_mut().handle_output(
        40,
        internal_report(
            authorities[1],
            session_identifier,
            secret_marker.clone(),
            vec![malicious_authority],
        ),
    );
    services[0]
        .dwallet_mpc_manager_mut()
        .sessions
        .get_mut(&session_identifier)
        .unwrap()
        .origin = SessionOrigin::LocalRequest;
    let reports = authorities
        .iter()
        .skip(2)
        .take(2)
        .map(|authority| {
            internal_report(
                *authority,
                session_identifier,
                secret_marker.clone(),
                vec![malicious_authority],
            )
        })
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(41, reports);

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(snapshot.session_origin, SessionOrigin::LocalRequest);
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"malicious_authority_identified")
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"quorum_reached_before_local_output_observed")
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"local_computation_pending_at_session_completion")
    );
    assert!(!snapshot.local_output_observed);
    assert!(snapshot.quorum_reached_without_local_output);
    assert_eq!(
        snapshot.local_computation_state,
        LocalComputationState::Running
    );
    let rendered = snapshot.to_json().unwrap();
    assert!(!rendered.contains(&format!("{:?}", secret_marker)));
    assert!(!rendered.contains("PRIVATE_OUTPUT_MUST_NOT_APPEAR"));
}

/// The same defect on a session this validator only reconstructed from peer
/// outputs still snapshots — but its missing local output is definitional,
/// so the race-context condition is omitted and `session_origin` lets triage
/// split the populations. The factual state fields are unaffected.
#[test]
fn defect_snapshot_on_reconstructed_session_omits_race_context() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [14; 32]);
    let malicious_authority = authorities[3];
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| {
            internal_report(
                *authority,
                session_identifier,
                vec![6],
                vec![malicious_authority],
            )
        })
        .collect();

    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(41, reports);

    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(
        snapshot.session_origin,
        SessionOrigin::ReconstructedFromConsensus
    );
    assert!(
        snapshot
            .trigger_conditions
            .contains(&"malicious_authority_identified")
    );
    assert!(
        !snapshot
            .trigger_conditions
            .contains(&"quorum_reached_before_local_output_observed")
    );
    assert!(!snapshot.local_output_observed);
    assert!(snapshot.quorum_reached_without_local_output);
    assert!(
        serde_json::from_str::<serde_json::Value>(&snapshot.to_json().unwrap()).unwrap()["session_origin"]
            == "reconstructed_from_consensus"
    );
}

#[test]
fn invalid_output_is_deduplicated_and_submission_error_keeps_session_context() {
    let (authorities, mut services) = authorities(0);
    let session_identifier = SessionIdentifier::new(SessionType::System, [15; 32]);
    let invalid = DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority: authorities[1],
        session_identifier,
        output: vec![],
        malicious_authorities: vec![],
    });
    services[0]
        .dwallet_mpc_manager_mut()
        .handle_output(50, invalid.clone());
    services[0]
        .dwallet_mpc_manager_mut()
        .handle_output(51, invalid);
    assert_eq!(
        services[0].dwallet_mpc_manager().untracked_anomaly_count(),
        1
    );

    let valid_session = SessionIdentifier::new(SessionType::System, [16; 32]);
    services[0].dwallet_mpc_manager_mut().handle_output(
        52,
        internal_report(authorities[0], valid_session, vec![1], vec![]),
    );
    services[0].dwallet_mpc_manager_mut().handle_output(
        53,
        DWalletMPCOutputReport::External(DWalletMPCOutput {
            authority: authorities[1],
            session_identifier: valid_session,
            output: vec![],
            malicious_authorities: vec![],
        }),
    );
    let invalid_snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&valid_session)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(invalid_snapshot.source_authority, Some(authorities[1]));
    assert!(invalid_snapshot.source_party_id.is_some());
    assert_eq!(invalid_snapshot.current_consensus_round, Some(53));

    services[0].dwallet_mpc_manager_mut().emit_session_anomaly(
        valid_session,
        MpcAnomalyKind::OutputSubmissionFailed,
        MpcAnomalyContext {
            current_consensus_round: Some(52),
            trigger_conditions: vec!["mpc_output_submission_to_consensus_failed"],
            error_code: Some("consensus_submission"),
            ..Default::default()
        },
    );
    let snapshot = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&valid_session)
        .unwrap()
        .last_anomaly_snapshot()
        .unwrap();
    assert_eq!(snapshot.session_id, valid_session.into_bytes());
    assert_eq!(snapshot.local_authority, services[0].name);
    assert_eq!(snapshot.current_consensus_round, Some(52));
    assert_eq!(snapshot.error_code, Some("consensus_submission"));
    assert!(
        !snapshot
            .to_json()
            .unwrap()
            .contains("test consensus failure")
    );
}

#[test]
fn untracked_anomaly_capacity_reports_drops_without_growing_state() {
    let (_, mut services) = authorities(0);
    let manager = services[0].dwallet_mpc_manager_mut();
    let session_identifier = |index: usize| {
        let mut preimage = [0; 32];
        preimage[..size_of::<usize>()].copy_from_slice(&index.to_le_bytes());
        SessionIdentifier::new(SessionType::System, preimage)
    };

    for index in 0..MAX_UNTRACKED_ANOMALIES {
        manager.emit_session_anomaly(
            session_identifier(index),
            MpcAnomalyKind::InvalidOutputReceived,
            MpcAnomalyContext::default(),
        );
    }
    assert_eq!(manager.untracked_anomaly_count(), MAX_UNTRACKED_ANOMALIES);
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_snapshots_dropped_total
            .with_label_values(&["untracked_capacity"])
            .get(),
        0
    );

    manager.emit_session_anomaly(
        session_identifier(MAX_UNTRACKED_ANOMALIES),
        MpcAnomalyKind::InvalidOutputReceived,
        MpcAnomalyContext::default(),
    );
    assert_eq!(manager.untracked_anomaly_count(), MAX_UNTRACKED_ANOMALIES);
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_snapshots_dropped_total
            .with_label_values(&["untracked_capacity"])
            .get(),
        1
    );

    manager.emit_session_anomaly(
        session_identifier(0),
        MpcAnomalyKind::InvalidOutputReceived,
        MpcAnomalyContext::default(),
    );
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .anomaly_snapshots_dropped_total
            .with_label_values(&["untracked_capacity"])
            .get(),
        1
    );
}
