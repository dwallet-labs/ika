// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Bounded, metadata-only diagnostics for abnormal MPC sessions.
//!
//! These types deliberately cannot contain protocol payloads, private outputs,
//! secret shares, or private MPC state. Callers record identifiers, digests,
//! sizes, rounds, party IDs, state transitions, and sanitized error strings.

use fastcrypto::hash::HashFunction;
use group::PartyID;
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::messages_dwallet_mpc::{DWalletMPCOutputKind, SessionIdentifier, SessionType};
use std::collections::{HashSet, VecDeque};
use sui_types::base_types::ObjectID;

/// The maximum number of recent metadata-only events retained by one session.
/// A session can receive arbitrarily many protocol messages, so this must stay
/// fixed rather than tracking the complete transcript.
pub(crate) const MAX_SESSION_DIAGNOSTIC_EVENTS: usize = 64;

pub(crate) fn output_digest(output: &DWalletMPCOutputKind) -> Option<[u8; 32]> {
    bcs::to_bytes(output)
        .ok()
        .map(|bytes| DefaultHash::digest(&bytes).into())
}

/// Digest the exact value voted on by `weighted_majority_vote`: public output
/// plus the embedded malicious-authority vector. This is separate from
/// `output_digest`, which intentionally excludes the report envelope.
pub(crate) fn report_digest(
    output: &DWalletMPCOutputKind,
    reported_malicious_authorities: &[AuthorityName],
) -> Option<[u8; 32]> {
    bcs::to_bytes(&(output, reported_malicious_authorities))
        .ok()
        .map(|bytes| DefaultHash::digest(&bytes).into())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MpcAnomalyKind {
    LocalComputationFailed,
    LocalRejectedOutput,
    OwnRejectedOutputObserved,
    ConflictingOutputDigests,
    InvalidOutputReceived,
    ProtocolMessageSubmissionFailed,
    OutputSubmissionFailed,
    RejectedOutputSubmissionFailed,
    ComputationUpdateAfterSessionCompletion,
    VotingFailure,
    QuorumAnomaly,
    ServiceExitSelfMalicious,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalComputationState {
    NotStarted,
    Running,
    WaitingForProtocolInput,
    OutputProduced,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalAuthorityMaliciousReason {
    MaliciousVoter,
    ReportedByMajorityOutput,
    MaliciousVoterAndReportedByMajorityOutput,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionDiagnosticEvent {
    SessionCreated {
        status: String,
    },
    RequestMetadataObserved {
        epoch: u64,
        session_type: SessionType,
        session_sequence_number: Option<u64>,
        protocol: String,
        network_encryption_key_id: Option<ObjectID>,
        network_key_reconfiguration: bool,
    },
    MessageReceived {
        consensus_round: u64,
        sender_party_id: PartyID,
        message_size_bytes: usize,
    },
    MessageSubmitted {
        consensus_round: Option<u64>,
        mpc_round: Option<u64>,
        attempt_number: u64,
        message_size_bytes: usize,
    },
    ComputationStarted {
        consensus_round: u64,
        mpc_round: Option<u64>,
        attempt_number: u64,
    },
    ComputationCompleted {
        consensus_round: u64,
        mpc_round: Option<u64>,
        attempt_number: u64,
        result: &'static str,
        error_kind: Option<String>,
    },
    OutputProduced {
        consensus_round: Option<u64>,
        output_digest: Option<[u8; 32]>,
        rejected: bool,
    },
    OutputSubmissionFinished {
        consensus_round: Option<u64>,
        output_digest: Option<[u8; 32]>,
        rejected: bool,
        succeeded: bool,
        error_kind: Option<String>,
    },
    OutputObserved {
        consensus_round: u64,
        sender_party_id: PartyID,
        output_digest: Option<[u8; 32]>,
        report_digest: Option<[u8; 32]>,
        rejected: bool,
        reported_malicious_count: usize,
        valid: bool,
    },
    QuorumReached {
        consensus_round: u64,
        winning_output_digest: [u8; 32],
        rejected: bool,
        local_output_observed: bool,
    },
    StatusTransition {
        from: String,
        to: String,
    },
    QuorumOutputCached {
        without_local_output: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputReportDiagnostic {
    pub(crate) sender_party_id: PartyID,
    pub(crate) sender_authority: AuthorityName,
    pub(crate) consensus_round: u64,
    pub(crate) output_digest: [u8; 32],
    pub(crate) report_digest: [u8; 32],
    pub(crate) rejected: bool,
    pub(crate) voting_weight: PartyID,
    pub(crate) reported_malicious_authorities: Vec<AuthorityName>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputVoteGroupDiagnostic {
    pub(crate) report_digest: [u8; 32],
    pub(crate) output_digest: [u8; 32],
    pub(crate) voter_party_ids: Vec<PartyID>,
    pub(crate) voter_authorities: Vec<AuthorityName>,
    pub(crate) voting_weight: PartyID,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputVoteDiagnostics {
    pub(crate) reports: Vec<OutputReportDiagnostic>,
    pub(crate) vote_groups: Vec<OutputVoteGroupDiagnostic>,
    pub(crate) threshold_required: PartyID,
    pub(crate) total_observed_weight: PartyID,
    pub(crate) winning_weight: PartyID,
    pub(crate) winning_output_digest: [u8; 32],
    pub(crate) winning_report_digest: [u8; 32],
    pub(crate) local_output_digest: Option<[u8; 32]>,
    pub(crate) local_output_matches_winner: Option<bool>,
    pub(crate) rejected: bool,
    pub(crate) malicious_voters: Vec<AuthorityName>,
    pub(crate) reported_malicious_authorities: Vec<AuthorityName>,
    pub(crate) final_malicious_authorities: Vec<AuthorityName>,
    pub(crate) local_authority_malicious_reason: Option<LocalAuthorityMaliciousReason>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MpcAnomalyContext {
    pub(crate) current_consensus_round: Option<u64>,
    pub(crate) source_authority: Option<AuthorityName>,
    pub(crate) source_party_id: Option<PartyID>,
    pub(crate) trigger_conditions: Vec<&'static str>,
    pub(crate) error: Option<String>,
    pub(crate) error_kind: Option<String>,
    pub(crate) running_computation_count: usize,
    pub(crate) vote: Option<OutputVoteDiagnostics>,
    pub(crate) quorum_output_cached_without_local_output: bool,
    pub(crate) service_loop_termination_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MpcAnomalySnapshot {
    pub(crate) session_identifier: SessionIdentifier,
    pub(crate) session_type: SessionType,
    pub(crate) computation_type: &'static str,
    pub(crate) protocol: Option<String>,
    pub(crate) session_sequence_number: Option<u64>,
    pub(crate) epoch: u64,
    pub(crate) local_authority: AuthorityName,
    pub(crate) local_party_id: PartyID,
    pub(crate) session_start_consensus_round: Option<u64>,
    pub(crate) current_consensus_round: Option<u64>,
    pub(crate) source_authority: Option<AuthorityName>,
    pub(crate) source_party_id: Option<PartyID>,
    pub(crate) local_output_submission_round: Option<u64>,
    pub(crate) local_output_consensus_round: Option<u64>,
    pub(crate) quorum_consensus_round: Option<u64>,
    pub(crate) lifecycle_status: String,
    pub(crate) local_computation_state: LocalComputationState,
    pub(crate) local_computation_attempts_started: u64,
    pub(crate) local_computation_attempts_completed: u64,
    pub(crate) local_computation_attempts_failed: u64,
    pub(crate) running_computation_count: usize,
    pub(crate) local_output_produced: bool,
    pub(crate) local_output_submitted: bool,
    pub(crate) local_output_submission_succeeded: Option<bool>,
    pub(crate) local_output_observed: bool,
    pub(crate) local_output_rejected: Option<bool>,
    pub(crate) local_output_digest: Option<[u8; 32]>,
    pub(crate) quorum_reached_without_local_output: bool,
    pub(crate) network_key_reconfiguration: bool,
    pub(crate) network_encryption_key_id: Option<ObjectID>,
    pub(crate) vote: Option<OutputVoteDiagnostics>,
    pub(crate) quorum_output_cached_without_local_output: bool,
    pub(crate) trigger_conditions: Vec<&'static str>,
    pub(crate) error: Option<String>,
    pub(crate) error_kind: Option<String>,
    pub(crate) service_loop_termination_reason: Option<&'static str>,
    pub(crate) recent_trace_dropped_events: u64,
    pub(crate) recent_trace: Vec<SessionDiagnosticEvent>,
}

#[derive(Clone)]
pub(crate) struct BoundedSessionDiagnostics {
    events: VecDeque<SessionDiagnosticEvent>,
    dropped_events: u64,
    emitted_anomalies: HashSet<MpcAnomalyKind>,
}

impl BoundedSessionDiagnostics {
    pub(crate) fn new(initial_status: String) -> Self {
        let mut diagnostics = Self {
            events: VecDeque::with_capacity(MAX_SESSION_DIAGNOSTIC_EVENTS),
            dropped_events: 0,
            emitted_anomalies: HashSet::new(),
        };
        diagnostics.record(SessionDiagnosticEvent::SessionCreated {
            status: initial_status,
        });
        diagnostics
    }

    pub(crate) fn record(&mut self, event: SessionDiagnosticEvent) {
        if self.events.len() == MAX_SESSION_DIAGNOSTIC_EVENTS {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(event);
    }

    pub(crate) fn begin_anomaly(&mut self, anomaly: MpcAnomalyKind) -> bool {
        self.emitted_anomalies.insert(anomaly)
    }

    pub(crate) fn events(&self) -> Vec<SessionDiagnosticEvent> {
        self.events.iter().cloned().collect()
    }

    pub(crate) fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub(crate) fn clear_trace(&mut self) {
        self.events.clear();
        self.dropped_events = 0;
    }

    #[cfg(test)]
    pub(crate) fn emitted_anomaly_count(&self) -> usize {
        self.emitted_anomalies.len()
    }

    #[cfg(test)]
    pub(crate) fn event_count(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_is_bounded_and_anomalies_are_deduplicated() {
        let mut diagnostics = BoundedSessionDiagnostics::new("Active".to_string());
        for consensus_round in 0..(MAX_SESSION_DIAGNOSTIC_EVENTS as u64 + 20) {
            diagnostics.record(SessionDiagnosticEvent::MessageReceived {
                consensus_round,
                sender_party_id: 1,
                message_size_bytes: 32,
            });
        }

        assert_eq!(diagnostics.event_count(), MAX_SESSION_DIAGNOSTIC_EVENTS);
        assert_eq!(diagnostics.dropped_events(), 21);
        assert!(diagnostics.begin_anomaly(MpcAnomalyKind::InvalidOutputReceived));
        assert!(!diagnostics.begin_anomaly(MpcAnomalyKind::InvalidOutputReceived));
        assert_eq!(diagnostics.emitted_anomaly_count(), 1);
    }

    #[test]
    fn clearing_trace_releases_buffered_events() {
        let mut diagnostics = BoundedSessionDiagnostics::new("Active".to_string());
        diagnostics.record(SessionDiagnosticEvent::MessageReceived {
            consensus_round: 1,
            sender_party_id: 2,
            message_size_bytes: 16,
        });
        diagnostics.clear_trace();

        assert_eq!(diagnostics.event_count(), 0);
        assert_eq!(diagnostics.dropped_events(), 0);
    }
}
