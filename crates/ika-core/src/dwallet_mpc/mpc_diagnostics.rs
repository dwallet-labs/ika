// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Bounded, metadata-only diagnostics for abnormal MPC sessions.
//!
//! These types deliberately cannot contain protocol payloads, private outputs,
//! secret shares, or private MPC state. Callers record identifiers, digests,
//! sizes, rounds, party IDs, state transitions, sanitized error codes, and
//! bounded crypto-library backtraces.

use fastcrypto::hash::HashFunction;
use group::PartyID;
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{DWalletMPCOutputKind, SessionType};
use serde::{Serialize, Serializer};
use std::backtrace::{Backtrace, BacktraceStatus};
use std::collections::{HashSet, VecDeque};
use sui_types::base_types::ObjectID;

/// The maximum number of recent metadata-only events retained by one session.
/// A session can receive arbitrarily many protocol messages, so this must stay
/// fixed rather than tracking the complete transcript.
pub(crate) const MAX_SESSION_DIAGNOSTIC_EVENTS: usize = 64;

/// Backtraces identify the crypto call path without formatting the error kind,
/// whose variants may contain private caller-provided strings. Keep the stored
/// representation bounded independently from the session event ring buffer.
pub(crate) const MAX_MPC_ERROR_BACKTRACE_BYTES: usize = 16 * 1024;

pub(crate) fn output_digest(output: &DWalletMPCOutputKind) -> Option<[u8; 32]> {
    bcs::to_bytes(output)
        .ok()
        .map(|bytes| DefaultHash::digest(&bytes).into())
}

/// Digest of raw output bytes as produced by a local computation
/// (`GuaranteedOutputDeliveryRoundResult::Finalize::public_output_value`),
/// before any consensus envelope is built around them. Comparable only with
/// [`network_key_reconfiguration_raw_output_digest`] — deliberately NOT with
/// [`output_digest`], which hashes the `DWalletMPCOutputKind` envelope.
pub(crate) fn raw_output_digest(output: &[u8]) -> [u8; 32] {
    DefaultHash::digest(output).into()
}

/// Digest of the raw network-key reconfiguration output bytes carried by a
/// quorum-agreed output envelope. Non-rejected reconfiguration chunks are
/// hashed in envelope order; chunking (`slice_public_output_into_messages`)
/// splits one output's bytes in order, so this equals
/// [`raw_output_digest`] of the original unsliced output. Returns `None` for
/// envelopes carrying no non-rejected network-key reconfiguration chunk
/// (other protocols, rejection envelopes, internal outputs).
pub(crate) fn network_key_reconfiguration_raw_output_digest(
    output: &DWalletMPCOutputKind,
) -> Option<[u8; 32]> {
    let DWalletMPCOutputKind::External { output: kinds } = output else {
        return None;
    };
    let mut chunks =
        kinds
            .iter()
            .filter_map(|kind| match kind {
                DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(
                    chunk,
                ) if !chunk.rejected => Some(&chunk.public_output),
                _ => None,
            })
            .peekable();
    chunks.peek()?;
    let hasher = chunks.fold(DefaultHash::default(), |mut hasher, chunk| {
        hasher.update(chunk);
        hasher
    });
    Some(hasher.finalize().into())
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

pub(crate) const MPC_ANOMALY_SCHEMA_VERSION: u64 = 1;

fn serialize_digest<S>(digest: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(digest))
}

fn serialize_optional_digest<S>(digest: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match digest {
        Some(digest) => serializer.serialize_some(&hex::encode(digest)),
        None => serializer.serialize_none(),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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

impl MpcAnomalyKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LocalComputationFailed => "local_computation_failed",
            Self::LocalRejectedOutput => "local_rejected_output",
            Self::OwnRejectedOutputObserved => "own_rejected_output_observed",
            Self::ConflictingOutputDigests => "conflicting_output_digests",
            Self::InvalidOutputReceived => "invalid_output_received",
            Self::ProtocolMessageSubmissionFailed => "protocol_message_submission_failed",
            Self::OutputSubmissionFailed => "output_submission_failed",
            Self::RejectedOutputSubmissionFailed => "rejected_output_submission_failed",
            Self::ComputationUpdateAfterSessionCompletion => {
                "computation_update_after_session_completion"
            }
            Self::VotingFailure => "voting_failure",
            Self::QuorumAnomaly => "quorum_anomaly",
            Self::ServiceExitSelfMalicious => "service_exit_self_malicious",
        }
    }

    pub(crate) const fn severity(self) -> &'static str {
        match self {
            Self::LocalComputationFailed
            | Self::RejectedOutputSubmissionFailed
            | Self::ServiceExitSelfMalicious => "error",
            _ => "warn",
        }
    }
}

/// How this validator first learned of a session. `LocalRequest` means the
/// session request itself was processed locally (at creation, or by
/// activating a `WaitingForSessionRequest` entry later);
/// `ReconstructedFromConsensus` means the session exists only because peer
/// artifacts (messages, outputs, a replayed completion) arrived through
/// consensus — dominant after a restart, when pre-restart sessions are
/// rebuilt from consensus outputs this validator can never have local
/// output for. Missing local output is definitional for a reconstructed
/// session, never a completion race.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionOrigin {
    LocalRequest,
    ReconstructedFromConsensus,
}

impl SessionOrigin {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LocalRequest => "local_request",
            Self::ReconstructedFromConsensus => "reconstructed_from_consensus",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalComputationState {
    NotStarted,
    Running,
    WaitingForProtocolInput,
    OutputProduced,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalAuthorityMaliciousReason {
    MaliciousVoter,
    ReportedByMajorityOutput,
    MaliciousVoterAndReportedByMajorityOutput,
}

impl LocalAuthorityMaliciousReason {
    /// A bounded, fixed label for `ika_dwallet_mpc_self_malicious_total`. The
    /// variants are the whole label domain — never derive this from anything
    /// operator- or session-specific.
    pub(crate) fn metric_label(self) -> &'static str {
        match self {
            Self::MaliciousVoter => "malicious_voter",
            Self::ReportedByMajorityOutput => "reported_by_majority_output",
            Self::MaliciousVoterAndReportedByMajorityOutput => {
                "malicious_voter_and_reported_by_majority_output"
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
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
        error_code: Option<&'static str>,
        error_party_ids: Vec<PartyID>,
    },
    OutputProduced {
        consensus_round: Option<u64>,
        #[serde(serialize_with = "serialize_optional_digest")]
        output_digest: Option<[u8; 32]>,
        rejected: bool,
    },
    OutputSubmissionFinished {
        consensus_round: Option<u64>,
        #[serde(serialize_with = "serialize_optional_digest")]
        output_digest: Option<[u8; 32]>,
        rejected: bool,
        succeeded: bool,
        error_code: Option<&'static str>,
    },
    OutputObserved {
        consensus_round: u64,
        sender_party_id: PartyID,
        #[serde(serialize_with = "serialize_optional_digest")]
        output_digest: Option<[u8; 32]>,
        #[serde(serialize_with = "serialize_optional_digest")]
        report_digest: Option<[u8; 32]>,
        rejected: bool,
        reported_malicious_count: usize,
        valid: bool,
    },
    QuorumReached {
        consensus_round: u64,
        #[serde(serialize_with = "serialize_digest")]
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
    /// A local network-key reconfiguration computation returned `Finalize`
    /// after the session had already completed via the peers' output quorum.
    /// Production correctly discards the result without submitting it; this
    /// event preserves the raw-output digest so the discarded bytes can still
    /// be compared against the quorum-agreed output.
    LateOutputAfterCompletion {
        #[serde(serialize_with = "serialize_digest")]
        output_digest: [u8; 32],
        #[serde(serialize_with = "serialize_optional_digest")]
        quorum_output_digest: Option<[u8; 32]>,
        reported_malicious_count: usize,
        matches_quorum: Option<bool>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct OutputReportDiagnostic {
    pub(crate) sender_party_id: PartyID,
    pub(crate) sender_authority: AuthorityName,
    pub(crate) consensus_round: u64,
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) output_digest: [u8; 32],
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) report_digest: [u8; 32],
    pub(crate) rejected: bool,
    pub(crate) voting_weight: PartyID,
    pub(crate) reported_malicious_authorities: Vec<AuthorityName>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct OutputVoteGroupDiagnostic {
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) report_digest: [u8; 32],
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) output_digest: [u8; 32],
    pub(crate) voter_party_ids: Vec<PartyID>,
    pub(crate) voter_authorities: Vec<AuthorityName>,
    pub(crate) voting_weight: PartyID,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct OutputVoteDiagnostics {
    pub(crate) reports: Vec<OutputReportDiagnostic>,
    pub(crate) vote_groups: Vec<OutputVoteGroupDiagnostic>,
    pub(crate) threshold_required: PartyID,
    pub(crate) total_observed_weight: PartyID,
    pub(crate) winning_weight: PartyID,
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) winning_output_digest: [u8; 32],
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) winning_report_digest: [u8; 32],
    #[serde(serialize_with = "serialize_optional_digest")]
    pub(crate) local_output_digest: Option<[u8; 32]>,
    pub(crate) local_output_matches_winner: Option<bool>,
    pub(crate) rejected: bool,
    pub(crate) malicious_voters: Vec<AuthorityName>,
    pub(crate) reported_malicious_authorities: Vec<AuthorityName>,
    pub(crate) final_malicious_authorities: Vec<AuthorityName>,
    pub(crate) local_authority_malicious_reason: Option<LocalAuthorityMaliciousReason>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct MpcAnomalyContext {
    pub(crate) current_consensus_round: Option<u64>,
    pub(crate) source_authority: Option<AuthorityName>,
    pub(crate) source_party_id: Option<PartyID>,
    pub(crate) trigger_conditions: Vec<&'static str>,
    pub(crate) error_code: Option<&'static str>,
    pub(crate) error_party_ids: Vec<PartyID>,
    pub(crate) error_backtrace: Option<String>,
    pub(crate) error_backtrace_truncated: bool,
    pub(crate) running_computation_count: usize,
    pub(crate) vote: Option<OutputVoteDiagnostics>,
    pub(crate) local_authority_malicious: bool,
    pub(crate) quorum_output_cached_without_local_output: bool,
    pub(crate) service_loop_termination_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct MpcAnomalySnapshot {
    pub(crate) schema_version: u64,
    pub(crate) anomaly_kind: MpcAnomalyKind,
    /// The derived session ID only. The `SessionIdentifier` preimage is deliberately
    /// excluded from the locally persisted diagnostic representation.
    #[serde(serialize_with = "serialize_digest")]
    pub(crate) session_id: [u8; 32],
    pub(crate) session_type: SessionType,
    pub(crate) session_origin: SessionOrigin,
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
    #[serde(serialize_with = "serialize_optional_digest")]
    pub(crate) local_output_digest: Option<[u8; 32]>,
    pub(crate) quorum_reached_without_local_output: bool,
    pub(crate) network_key_reconfiguration: bool,
    pub(crate) network_encryption_key_id: Option<ObjectID>,
    pub(crate) vote: Option<OutputVoteDiagnostics>,
    /// Whether this anomaly identifies the local validator as malicious. For quorum
    /// snapshots, this is membership in `vote.final_malicious_authorities`.
    /// It stays explicit so operators do not need to compare authority encodings.
    pub(crate) local_authority_malicious: bool,
    pub(crate) quorum_output_cached_without_local_output: bool,
    pub(crate) trigger_conditions: Vec<&'static str>,
    pub(crate) error_code: Option<&'static str>,
    pub(crate) error_party_ids: Vec<PartyID>,
    /// A bounded rendering of `mpc::Error::backtrace`. The error kind is never
    /// formatted because some variants contain arbitrary, potentially private data.
    pub(crate) error_backtrace: Option<String>,
    pub(crate) error_backtrace_truncated: bool,
    pub(crate) service_loop_termination_reason: Option<&'static str>,
    pub(crate) recent_trace_dropped_events: u64,
    pub(crate) recent_trace: Vec<SessionDiagnosticEvent>,
}

impl MpcAnomalySnapshot {
    /// Serialize the privacy-safe schema as one bounded JSON value. `tracing` records
    /// this as a single field, so JSON and text log sinks both keep one line per anomaly.
    pub(crate) fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MpcErrorDiagnostic {
    pub(crate) error_code: &'static str,
    pub(crate) party_ids: Vec<PartyID>,
    pub(crate) backtrace: Option<String>,
    pub(crate) backtrace_truncated: bool,
}

fn bounded_backtrace(backtrace: &Backtrace) -> (Option<String>, bool) {
    if backtrace.status() != BacktraceStatus::Captured {
        return (None, false);
    }
    bounded_backtrace_string(backtrace.to_string())
}

fn bounded_backtrace_string(backtrace: String) -> (Option<String>, bool) {
    if backtrace.is_empty() {
        return (None, false);
    }
    if backtrace.len() <= MAX_MPC_ERROR_BACKTRACE_BYTES {
        return (Some(backtrace), false);
    }

    let boundary = backtrace
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_MPC_ERROR_BACKTRACE_BYTES)
        .last()
        .unwrap_or(0);
    (Some(backtrace[..boundary].to_owned()), true)
}

/// Convert an MPC error into allow-listed diagnostic metadata. Never format the
/// complete error: `Serialization` and `Consumer` can contain arbitrary strings.
/// The crypto backtrace is safe to render separately because it contains call
/// locations rather than the error kind or its values.
pub(crate) fn mpc_error_diagnostic(error: &mpc::Error) -> MpcErrorDiagnostic {
    let (error_code, party_ids) = match &error.kind {
        mpc::ErrorKind::InvalidParameters => ("invalid_parameters", vec![]),
        mpc::ErrorKind::DecryptionFailed => ("decryption_failed", vec![]),
        mpc::ErrorKind::IdentityEphemeralKey => ("identity_ephemeral_key", vec![]),
        mpc::ErrorKind::TorsionEphemeralKey => ("torsion_ephemeral_key", vec![]),
        mpc::ErrorKind::ThresholdNotReached => ("threshold_not_reached", vec![]),
        mpc::ErrorKind::NonParticipatingParty => ("non_participating_party", vec![]),
        mpc::ErrorKind::UnresponsiveParties(party_ids) => {
            ("unresponsive_parties", party_ids.clone())
        }
        mpc::ErrorKind::InvalidMessage(party_ids) => ("invalid_message", party_ids.clone()),
        mpc::ErrorKind::MaliciousMessage(party_ids) => ("malicious_message", party_ids.clone()),
        mpc::ErrorKind::MaliciousMessageAsync => ("malicious_message_async", vec![]),
        mpc::ErrorKind::MaliciousMessagePreventsAdvance => {
            ("malicious_message_prevents_advance", vec![])
        }
        mpc::ErrorKind::InactiveSession => ("inactive_session", vec![]),
        mpc::ErrorKind::Group(_) => ("group", vec![]),
        mpc::ErrorKind::InternalError => ("internal_error", vec![]),
        mpc::ErrorKind::Bcs(_) => ("bcs", vec![]),
        mpc::ErrorKind::Serialization(_) => ("serialization", vec![]),
        mpc::ErrorKind::Consumer(_) => ("consumer", vec![]),
    };
    let (backtrace, backtrace_truncated) = bounded_backtrace(&error.backtrace);
    MpcErrorDiagnostic {
        error_code,
        party_ids,
        backtrace,
        backtrace_truncated,
    }
}

pub(crate) fn dwallet_mpc_error_diagnostic(error: &DwalletMPCError) -> MpcErrorDiagnostic {
    match error {
        DwalletMPCError::MPCError(error) | DwalletMPCError::FailedToAdvanceMPC(error) => {
            mpc_error_diagnostic(error)
        }
        _ => MpcErrorDiagnostic {
            error_code: error.kind(),
            party_ids: vec![],
            backtrace: None,
            backtrace_truncated: false,
        },
    }
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
    use ika_types::message::MPCNetworkReconfigurationOutput;
    use std::sync::Arc;

    fn reconfiguration_chunk(
        public_output: Vec<u8>,
        rejected: bool,
    ) -> DWalletCheckpointMessageKind {
        DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(
            MPCNetworkReconfigurationOutput {
                dwallet_network_encryption_key_id: vec![9; 32],
                public_output,
                supported_curves: vec![],
                is_last: false,
                rejected,
                session_sequence_number: 3,
            },
        )
    }

    /// The whole point of the raw-bytes digest domain: hashing the winning
    /// envelope's in-order chunks must equal hashing the unsliced
    /// `public_output_value` a local computation returns, or the late-output
    /// comparison would report false divergence.
    #[test]
    fn chunked_reconfiguration_digest_equals_unsliced_raw_digest() {
        let output_bytes: Vec<u8> = (0..12_000u32).map(|byte| (byte % 251) as u8).collect();
        let envelope = DWalletMPCOutputKind::External {
            output: output_bytes
                .chunks(5 * 1024)
                .map(|chunk| reconfiguration_chunk(chunk.to_vec(), false))
                .collect(),
        };

        assert_eq!(
            network_key_reconfiguration_raw_output_digest(&envelope),
            Some(raw_output_digest(&output_bytes))
        );
    }

    #[test]
    fn rejected_chunks_and_foreign_envelopes_produce_no_digest() {
        let rejected_only = DWalletMPCOutputKind::External {
            output: vec![reconfiguration_chunk(vec![1, 2, 3], true)],
        };
        assert_eq!(
            network_key_reconfiguration_raw_output_digest(&rejected_only),
            None
        );
        let no_reconfiguration_chunks = DWalletMPCOutputKind::External { output: vec![] };
        assert_eq!(
            network_key_reconfiguration_raw_output_digest(&no_reconfiguration_chunks),
            None
        );
    }

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

    #[test]
    fn mpc_error_diagnostics_do_not_format_arbitrary_error_content() {
        let secret_marker = "PRIVATE_MPC_VALUE_MUST_NOT_APPEAR";
        let error = mpc::Error {
            kind: mpc::ErrorKind::Serialization(secret_marker.to_string()),
            backtrace: Arc::new(Backtrace::force_capture()),
        };

        let diagnostic = mpc_error_diagnostic(&error);

        assert_eq!(diagnostic.error_code, "serialization");
        assert!(diagnostic.party_ids.is_empty());
        assert!(
            diagnostic
                .backtrace
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(!diagnostic.backtrace_truncated);
        assert!(
            !serde_json::to_string(&diagnostic.backtrace)
                .unwrap()
                .contains(secret_marker)
        );
    }

    #[test]
    fn mpc_error_diagnostics_preserve_only_exposed_party_ids() {
        let error = mpc::Error::from(mpc::ErrorKind::InvalidMessage(vec![2, 5]));

        let diagnostic = mpc_error_diagnostic(&error);

        assert_eq!(diagnostic.error_code, "invalid_message");
        assert_eq!(diagnostic.party_ids, vec![2, 5]);
    }

    #[test]
    fn mpc_error_backtrace_is_bounded_on_a_utf8_boundary() {
        let oversized = format!("{}é", "a".repeat(MAX_MPC_ERROR_BACKTRACE_BYTES));

        let (backtrace, truncated) = bounded_backtrace_string(oversized);
        let backtrace = backtrace.unwrap();

        assert!(truncated);
        assert_eq!(backtrace.len(), MAX_MPC_ERROR_BACKTRACE_BYTES);
    }

    #[test]
    fn disabled_mpc_error_backtrace_is_not_persisted_as_a_placeholder() {
        let (backtrace, truncated) = bounded_backtrace(&Backtrace::disabled());

        assert!(backtrace.is_none());
        assert!(!truncated);
    }
}
