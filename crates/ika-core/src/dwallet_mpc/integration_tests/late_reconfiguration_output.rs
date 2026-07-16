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
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::mpc_diagnostics::{
    MpcAnomalyKind, SessionDiagnosticEvent, raw_output_digest,
};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::request_protocol_data::{NetworkEncryptionKeyReconfigurationData, ProtocolData};
use ika_types::crypto::AuthorityName;
use ika_types::message::{DWalletCheckpointMessageKind, MPCNetworkReconfigurationOutput};
use ika_types::messages_dwallet_mpc::{
    DWalletMPCOutput, DWalletMPCOutputReport, SessionIdentifier, SessionType,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::collections::HashMap;
use sui_types::base_types::ObjectID;

/// A submitted network-key reconfiguration output report, chunked exactly the
/// way production slices one output's bytes across checkpoint message kinds
/// (`slice_public_output_into_messages` — in-order 5 KB chunks), so the
/// raw-bytes digest of the reassembled envelope must equal the digest of the
/// unsliced bytes.
fn reconfiguration_report(
    authority: AuthorityName,
    session_identifier: SessionIdentifier,
    key_id: ObjectID,
    output_bytes: &[u8],
) -> DWalletMPCOutputReport {
    let chunks: Vec<&[u8]> = output_bytes.chunks(5 * 1024).collect();
    let chunk_count = chunks.len();
    let output = chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(
                MPCNetworkReconfigurationOutput {
                    dwallet_network_encryption_key_id: key_id.to_vec(),
                    public_output: chunk.to_vec(),
                    supported_curves: vec![],
                    is_last: index == chunk_count - 1,
                    rejected: false,
                    session_sequence_number: 3,
                },
            )
        })
        .collect();
    DWalletMPCOutputReport::External(DWalletMPCOutput {
        authority,
        session_identifier,
        output,
        malicious_authorities: vec![],
    })
}

fn reconfiguration_request(
    session_identifier: SessionIdentifier,
    key_id: ObjectID,
) -> DWalletSessionRequest {
    DWalletSessionRequest {
        counterparty_chain: Some(CounterpartyChainKind::Sui),
        session_type: SessionType::System,
        session_identifier,
        session_sequence_number: Some(3),
        protocol_data: ProtocolData::NetworkEncryptionKeyReconfiguration {
            data: NetworkEncryptionKeyReconfigurationData {},
            dwallet_network_encryption_key_id: key_id,
        },
        epoch: 1,
        requires_network_key_data: true,
        requires_next_active_committee: true,
        pulled: false,
    }
}

fn late_finalize(
    output_bytes: Vec<u8>,
) -> Result<GuaranteedOutputDeliveryRoundResult, ika_types::dwallet_mpc_error::DwalletMPCError> {
    Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
        malicious_parties: vec![],
        private_output: vec![],
        public_output_value: output_bytes,
    })
}

#[tokio::test]
#[cfg(test)]
async fn late_reconfiguration_finalize_after_quorum_records_digest_without_submitting() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (services, _, sent_consensus_messages_collectors, _, _, _, _) =
        utils::create_dwallet_mpc_services(4);
    let mut services = services;
    let authorities: Vec<AuthorityName> = services[0].committee.names().copied().collect();
    let session_identifier = SessionIdentifier::new(SessionType::System, [21; 32]);
    let key_id = ObjectID::from_single_byte(9);
    // Multiple chunks (>5 KB) so the quorum-side digest exercises in-order
    // chunk reassembly, not just the single-chunk case.
    let output_bytes: Vec<u8> = (0..12_000u32).map(|byte| (byte % 251) as u8).collect();

    // The session request was observed earlier in the epoch — production
    // stamps the reconfiguration metadata off it when the session is created.
    // One below-quorum output creates the session entry; the metadata call is
    // the same one the real request-arrival path performs.
    services[0].dwallet_mpc_manager_mut().handle_output(
        5_900,
        reconfiguration_report(authorities[1], session_identifier, key_id, &output_bytes),
    );
    let request = reconfiguration_request(session_identifier, key_id);
    {
        let session = services[0]
            .dwallet_mpc_manager_mut()
            .sessions
            .get_mut(&session_identifier)
            .expect("session exists after the first output");
        session.set_request_diagnostic_metadata(&request);
        session.set_protocol_name(
            DWalletSessionRequestMetricData::from(&request.protocol_data)
                .name()
                .to_owned(),
        );
    }

    // Three old authorities finalize with identical outputs; the quorum
    // closes the session while this validator is still computing.
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| {
            reconfiguration_report(*authority, session_identifier, key_id, &output_bytes)
        })
        .collect();
    let (_, completed) = services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(5_902, reports);
    assert_eq!(completed, vec![session_identifier]);

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
        assert!(session.late_output_digest.is_none());
    }

    // ~195ms later: the local computation returns `Finalize` with the SAME
    // bytes the quorum agreed on. The session is non-active, so the result is
    // discarded — but its digest must be recorded and compared.
    sent_consensus_messages_collectors[0]
        .submitted_messages
        .lock()
        .unwrap()
        .clear();
    services[0]
        .handle_computation_results_and_submit_to_consensus(HashMap::from([(
            ComputationId {
                session_identifier,
                mpc_round: Some(3),
                attempt_number: 1,
                consensus_round: 5_902,
            },
            late_finalize(output_bytes.clone()),
        )]))
        .await;

    assert!(
        sent_consensus_messages_collectors[0]
            .submitted_messages
            .lock()
            .unwrap()
            .is_empty(),
        "a late finalize for a completed session must not submit anything to consensus"
    );
    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert_eq!(session.late_output_digest, Some(expected_digest));
    assert_eq!(session.late_output_reported_malicious_count, Some(0));
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
    let protocol_name = DWalletSessionRequestMetricData::from(&request.protocol_data)
        .name()
        .to_owned();
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
    let (services, _, sent_consensus_messages_collectors, _, _, _, _) =
        utils::create_dwallet_mpc_services(4);
    let mut services = services;
    let authorities: Vec<AuthorityName> = services[0].committee.names().copied().collect();
    let session_identifier = SessionIdentifier::new(SessionType::System, [22; 32]);
    let key_id = ObjectID::from_single_byte(9);
    let output_bytes = vec![7u8; 6_000];

    services[0].dwallet_mpc_manager_mut().handle_output(
        6_000,
        reconfiguration_report(authorities[1], session_identifier, key_id, &output_bytes),
    );
    let request = reconfiguration_request(session_identifier, key_id);
    {
        let session = services[0]
            .dwallet_mpc_manager_mut()
            .sessions
            .get_mut(&session_identifier)
            .unwrap();
        session.set_request_diagnostic_metadata(&request);
        session.set_protocol_name(
            DWalletSessionRequestMetricData::from(&request.protocol_data)
                .name()
                .to_owned(),
        );
    }
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| {
            reconfiguration_report(*authority, session_identifier, key_id, &output_bytes)
        })
        .collect();
    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(6_002, reports);

    // The upgraded validator really computed different bytes.
    let mut divergent_bytes = output_bytes.clone();
    divergent_bytes[100] ^= 0xFF;
    sent_consensus_messages_collectors[0]
        .submitted_messages
        .lock()
        .unwrap()
        .clear();
    services[0]
        .handle_computation_results_and_submit_to_consensus(HashMap::from([(
            ComputationId {
                session_identifier,
                mpc_round: Some(3),
                attempt_number: 1,
                consensus_round: 6_002,
            },
            late_finalize(divergent_bytes.clone()),
        )]))
        .await;

    assert!(
        sent_consensus_messages_collectors[0]
            .submitted_messages
            .lock()
            .unwrap()
            .is_empty(),
        "even a divergent late output must never be submitted"
    );
    let quorum_digest = raw_output_digest(&output_bytes);
    let divergent_digest = raw_output_digest(&divergent_bytes);
    assert_ne!(quorum_digest, divergent_digest);
    let manager = services[0].dwallet_mpc_manager();
    let session = manager.sessions.get(&session_identifier).unwrap();
    assert_eq!(session.late_output_digest, Some(divergent_digest));
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
    let protocol_name = DWalletSessionRequestMetricData::from(&request.protocol_data)
        .name()
        .to_owned();
    assert_eq!(
        manager
            .dwallet_mpc_metrics
            .session_late_output_info
            .with_label_values(&[
                &protocol_name,
                &hex::encode(session_identifier.as_ref()),
                &services[0].name.to_string(),
                &hex::encode(divergent_digest),
                &hex::encode(quorum_digest),
            ])
            .get(),
        1
    );
}

/// A late finalize for a NON-reconfiguration session must not record or
/// export anything — the capture is deliberately scoped to the network-key
/// reconfiguration compatibility boundary to keep the per-session metric
/// cardinality bounded.
#[tokio::test]
#[cfg(test)]
async fn late_finalize_for_non_reconfiguration_session_records_nothing() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (services, _, sent_consensus_messages_collectors, _, _, _, _) =
        utils::create_dwallet_mpc_services(4);
    let mut services = services;
    let authorities: Vec<AuthorityName> = services[0].committee.names().copied().collect();
    let session_identifier = SessionIdentifier::new(SessionType::System, [23; 32]);
    let key_id = ObjectID::from_single_byte(9);
    let output_bytes = vec![5u8; 64];

    // Quorum completes the session, but its request metadata was never
    // observed — `network_key_reconfiguration` stays false, like any user
    // protocol session would.
    let reports = authorities
        .iter()
        .skip(1)
        .take(3)
        .map(|authority| {
            reconfiguration_report(*authority, session_identifier, key_id, &output_bytes)
        })
        .collect();
    services[0]
        .dwallet_mpc_manager_mut()
        .handle_consensus_round_outputs(7_002, reports);

    sent_consensus_messages_collectors[0]
        .submitted_messages
        .lock()
        .unwrap()
        .clear();
    services[0]
        .handle_computation_results_and_submit_to_consensus(HashMap::from([(
            ComputationId {
                session_identifier,
                mpc_round: Some(3),
                attempt_number: 1,
                consensus_round: 7_002,
            },
            late_finalize(output_bytes),
        )]))
        .await;

    let session = services[0]
        .dwallet_mpc_manager()
        .sessions
        .get(&session_identifier)
        .unwrap();
    assert!(session.late_output_digest.is_none());
    assert!(session.late_output_reported_malicious_count.is_none());
    assert!(
        sent_consensus_messages_collectors[0]
            .submitted_messages
            .lock()
            .unwrap()
            .is_empty()
    );
}
