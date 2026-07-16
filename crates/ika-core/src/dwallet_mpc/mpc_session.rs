// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

mod input;

use dwallet_mpc_types::dwallet_mpc::{MPCMessage, MPCPrivateInput};
use group::PartyID;
use ika_types::crypto::{AuthorityName, AuthorityPublicKeyBytes};
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletMPCMessage, DWalletMPCOutputKind, DWalletMPCOutputReport, GlobalPresignRequest,
    SessionIdentifier, SessionType,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry::Vacant;
use std::time::Instant;
use sui_types::base_types::ObjectID;
use tracing::{debug, error, info, warn};

use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::mpc_diagnostics::{
    BoundedSessionDiagnostics, LocalComputationState, MPC_ANOMALY_SCHEMA_VERSION,
    MpcAnomalyContext, MpcAnomalyKind, MpcAnomalySnapshot, SessionDiagnosticEvent, output_digest,
    report_digest,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::request_protocol_data::ProtocolData;
use ika_types::error::{IkaError, IkaResult};
pub(crate) use input::{PublicInput, session_input_from_request};
use std::fmt::{Debug, Formatter};
use std::{fmt, mem};
use tokio::sync::broadcast;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct DWalletMPCSessionOutput {
    pub(crate) output: DWalletMPCOutputKind,
    pub(crate) malicious_authorities: Vec<AuthorityName>,
    pub(crate) output_digest: [u8; 32],
    pub(crate) report_digest: [u8; 32],
    pub(crate) rejected: bool,
}

#[derive(Debug)]
pub(crate) enum AddOutputResult {
    Accepted {
        conflicting_output_digests: bool,
        own_rejected_output: bool,
    },
    Invalid {
        error_code: &'static str,
    },
}

#[derive(Clone)]
pub(crate) struct SessionOutputObservation {
    pub(crate) digests: HashSet<[u8; 32]>,
    pub(crate) malicious_actor_count: usize,
    pub(crate) rejected: bool,
}

/// A dWallet session. Encapsulates computation done by validators,
/// whose output is being agreed upon in consensus,
/// then being transmitted onto the Sui chain as part of a checkpoint,
/// in which a quorum of signatures by the current committee is validated before acceptance.
///
/// This computation could either be a Native one, meaning it is akin to a Rust function call whose result is agreed upon in a decentralized manner,
/// or a special MPC computation, which could involve secrets distributed between the validators and span across multiple rounds,
/// with messages being sent as part of the consensus in-between rounds.
#[derive(Clone)]
pub(crate) struct DWalletSession {
    pub(super) session_identifier: SessionIdentifier,
    validator_name: AuthorityPublicKeyBytes,
    pub(crate) party_id: PartyID,

    /// Which counterparty chain this session belongs to. `None` for internal sessions or
    /// sessions created before the request arrives (WaitingForSessionRequest).
    pub(super) counterparty_chain: Option<CounterpartyChainKind>,

    /// The status of the MPC session.
    pub(super) status: SessionStatus,

    pub(super) computation_type: SessionComputationType,

    /// BTreeMap is required here (not HashMap) to guarantee deterministic iteration
    /// order by consensus round. `build_outputs_to_finalize` uses "last output wins"
    /// semantics — all validators must agree on which round's output is "last" for
    /// each party, which requires ordered iteration.
    outputs_by_consensus_round: BTreeMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,

    /// Monotonic-clock timestamp of when this session entry was first created on this
    /// validator. Feeds the "session has been Active for N seconds" age-bucket metric.
    pub(super) created_at: Instant,

    /// Sequence number of this session on chain. `None` if the session was first observed
    /// via a stray message/output (i.e. created in `WaitingForSessionRequest`) and no
    /// request has arrived since. Populated as soon as we ever see a `DWalletSessionRequest`
    /// for this session, and *preserved* across status transitions to ComputationCompleted /
    /// Completed / Failed (whose variants are unit and drop the request). Used by metrics
    /// to label sessions by sequence number.
    pub(super) session_sequence_number: Option<u64>,

    /// Same idea — set to `Some(_)` once we've seen a request, preserved across transitions.
    pub(super) session_type: Option<SessionType>,

    /// Stable protocol name from the session request. Outputs can arrive before
    /// their request, so this remains `None` until the request is observed and
    /// is then preserved across terminal status transitions.
    pub(super) protocol_name: Option<String>,

    // -------- per-session timing/diagnostic counters --------
    // All of these are populated in this process's lifetime only — pre-restart events
    // do not contribute. They feed the `ika_dwallet_mpc_user_session_*` per-seq gauges.
    /// Earliest consensus round (since this process started) at which *any* validator's
    /// output for this session was received. `None` until the first output arrives.
    pub(super) first_output_consensus_round: Option<u64>,

    /// Consensus round at which this validator saw its own output loop back through
    /// consensus (i.e., the round in which we transitioned to `ComputationCompleted`).
    pub(super) self_output_consensus_round: Option<u64>,

    /// Consensus round at which 2/3 quorum was first reached on this session's output
    /// (`mpc_manager::handle_consensus_round_outputs` saw the output agreed). `None` if
    /// quorum was never observed during this process's lifetime — either it really hasn't
    /// been reached or it was reached before we restarted.
    pub(super) quorum_consensus_round: Option<u64>,

    /// Set of authorities that submitted an output for this session this lifetime.
    /// `.len()` is exposed as the `_distinct_output_authorities` metric.
    pub(super) distinct_output_authorities: HashSet<AuthorityName>,

    /// Whether the output *this* validator submitted to consensus was `rejected: true`.
    /// `None` until we submit an output; `Some(true)` for an MPC failure /
    /// `submit_failed_session` path; `Some(false)` for a normal `Finalize`.
    pub(super) local_output_rejected: Option<bool>,

    /// Distinct output digests seen this lifetime for this session. `len() > 1` ⇒ vote
    /// split: validators submitted different output content. The digest is `DefaultHash`
    /// over the BCS bytes of the `DWalletMPCOutputKind` (sender and malicious-authorities
    /// envelope excluded), so identical outputs from different validators collapse to one
    /// digest.
    pub(super) distinct_output_digests: HashSet<[u8; 32]>,

    /// Canonical submitted output observed from each authority through
    /// consensus. This is protocol-agnostic and preserves individual votes
    /// that a later weighted majority would otherwise hide.
    pub(super) output_observations: HashMap<AuthorityName, SessionOutputObservation>,

    /// Bounded metadata-only history, flushed only for abnormal sessions.
    pub(super) diagnostics: BoundedSessionDiagnostics,

    pub(super) request_epoch: Option<u64>,
    pub(super) protocol: Option<String>,
    pub(super) network_encryption_key_id: Option<ObjectID>,
    pub(super) network_key_reconfiguration: bool,
    pub(super) session_start_consensus_round: Option<u64>,
    pub(super) local_computation_attempts_started: u64,
    pub(super) local_computation_attempts_completed: u64,
    pub(super) local_computation_attempts_failed: u64,
    pub(super) local_computation_last_failed: bool,
    pub(super) local_output_produced: bool,
    pub(super) local_output_submitted: bool,
    pub(super) local_output_submission_succeeded: Option<bool>,
    pub(super) local_output_submission_round: Option<u64>,
    pub(super) local_output_digest: Option<[u8; 32]>,
    #[cfg(test)]
    last_anomaly_snapshot: Option<MpcAnomalySnapshot>,
}

/// Possible statuses of a session:
///
/// - `WaitingForSessionRequest`:
///   Either a message was received before the session request was received
///   or session loaded from tables.
///
/// - `Active`:
///   The session is currently running, and new messages are forwarded to it
///   for processing.
///
/// - `Finished`:
///   The session has been removed from the active instances.
///   Incoming messages are no longer forwarded to the session,
///   but they are not flagged as malicious.
///
/// - `Failed`:
///   The session has failed due to an unrecoverable error.
///   This status indicates that the session cannot proceed further.
#[derive(Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SessionStatus {
    Active {
        public_input: PublicInput,
        private_input: MPCPrivateInput,
        request: DWalletSessionRequest,
    },
    WaitingForSessionRequest,
    ComputationCompleted,
    Completed,
    Failed,
}

impl SessionStatus {
    /// The session's ordinal sequence number when its request is available
    /// (set for presign sessions; `None` while still awaiting the request).
    pub(crate) fn session_sequence_number(&self) -> Option<u64> {
        match self {
            SessionStatus::Active { request, .. } => request.session_sequence_number,
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SessionComputationType {
    #[allow(clippy::upper_case_acronyms)]
    MPC {
        /// All the messages that have been received for this session from each party, by consensus round and then by MPC round.
        /// Used to build the input of messages to advance each round of the session.
        messages_by_consensus_round: HashMap<u64, HashMap<PartyID, MPCMessage>>,
    },
    Native,
}

#[derive(Clone, Debug)]
pub enum ComputationResultData {
    #[allow(clippy::upper_case_acronyms)]
    MPC {
        mpc_round: u64,
    },
    Native,
}

impl DWalletSession {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        status: SessionStatus,
        session_identifier: SessionIdentifier,
        party_id: PartyID,
        counterparty_chain: Option<CounterpartyChainKind>,
        computation_type: SessionComputationType,
    ) -> Self {
        // If the new session is created with an Active status the request is right there;
        // pull seq/type out of it so they survive any later transition to a unit variant.
        let (session_sequence_number, session_type, protocol_name) = match &status {
            SessionStatus::Active { request, .. } => (
                request.session_sequence_number,
                Some(request.session_type),
                Some(
                    DWalletSessionRequestMetricData::from(&request.protocol_data)
                        .name()
                        .to_owned(),
                ),
            ),
            _ => (None, None, None),
        };
        let diagnostics = BoundedSessionDiagnostics::new(status.to_string());
        let mut session = Self {
            status,
            outputs_by_consensus_round: BTreeMap::new(),
            session_identifier,
            party_id,
            counterparty_chain,
            validator_name,
            computation_type,
            created_at: Instant::now(),
            session_sequence_number,
            session_type,
            protocol_name,
            first_output_consensus_round: None,
            self_output_consensus_round: None,
            quorum_consensus_round: None,
            distinct_output_authorities: HashSet::new(),
            local_output_rejected: None,
            distinct_output_digests: HashSet::new(),
            output_observations: HashMap::new(),
            diagnostics,
            request_epoch: None,
            protocol: None,
            network_encryption_key_id: None,
            network_key_reconfiguration: false,
            session_start_consensus_round: None,
            local_computation_attempts_started: 0,
            local_computation_attempts_completed: 0,
            local_computation_attempts_failed: 0,
            local_computation_last_failed: false,
            local_output_produced: false,
            local_output_submitted: false,
            local_output_submission_succeeded: None,
            local_output_submission_round: None,
            local_output_digest: None,
            #[cfg(test)]
            last_anomaly_snapshot: None,
        };
        if let SessionStatus::Active { request, .. } = &session.status {
            let request = request.clone();
            session.set_request_diagnostic_metadata(&request);
        }
        session
    }

    /// Records the session's on-chain identity (sequence number + type) on this session
    /// entry so it survives status transitions to the unit variants (which drop the
    /// request). Idempotent; a `Some` sequence number is never clobbered by `None`.
    pub(crate) fn set_request_metadata(
        &mut self,
        session_sequence_number: Option<u64>,
        session_type: SessionType,
    ) {
        self.session_sequence_number = self.session_sequence_number.or(session_sequence_number);
        self.session_type = Some(session_type);
    }

    pub(crate) fn set_protocol_name(&mut self, protocol_name: String) {
        if self.protocol_name.is_none() {
            self.protocol_name = Some(protocol_name);
        }
    }

    pub(crate) fn set_request_diagnostic_metadata(&mut self, request: &DWalletSessionRequest) {
        self.request_epoch = Some(request.epoch);
        self.protocol =
            Some(DWalletSessionRequestMetricData::from(&request.protocol_data).to_string());
        self.network_encryption_key_id = request.protocol_data.network_encryption_key_id();
        self.network_key_reconfiguration = matches!(
            request.protocol_data,
            ProtocolData::NetworkEncryptionKeyReconfiguration { .. }
        );
        self.diagnostics
            .record(SessionDiagnosticEvent::RequestMetadataObserved {
                epoch: request.epoch,
                session_type: request.session_type,
                session_sequence_number: request.session_sequence_number,
                protocol: self.protocol.clone().unwrap_or_default(),
                network_encryption_key_id: self.network_encryption_key_id,
                network_key_reconfiguration: self.network_key_reconfiguration,
            });
    }

    pub(crate) fn clear_data(&mut self) {
        self.computation_type = match self.computation_type {
            SessionComputationType::MPC { .. } => SessionComputationType::MPC {
                messages_by_consensus_round: HashMap::new(),
            },
            SessionComputationType::Native => SessionComputationType::Native,
        };

        self.outputs_by_consensus_round = BTreeMap::new();
        self.diagnostics.clear_trace();
    }

    /// Adds an incoming message.
    /// Done in sync, as our state mutates in sync with the view of the
    /// consensus, which is shared with the other validators.
    ///
    /// This function performs no checks, it simply stores the message in the map.
    ///
    /// If a party sent a message twice, the second message will be ignored.
    /// Whilst that is malicious, it has no effect since the messages come in order,
    /// so all validators end up seeing the same map.
    ///
    /// Other malicious activities like sending a message for a wrong round are also not
    /// reported since they have no practical impact for similar reasons.
    pub(crate) fn add_message(
        &mut self,
        consensus_round: u64,
        sender_party_id: PartyID,
        message: DWalletMPCMessage,
    ) {
        let metric_data = match &self.status {
            SessionStatus::Active { request, .. } => Some(DWalletSessionRequestMetricData::from(
                &request.protocol_data,
            )),
            SessionStatus::WaitingForSessionRequest | SessionStatus::ComputationCompleted => None,
            SessionStatus::Completed | SessionStatus::Failed => {
                warn!(
                    session_identifier=?self.session_identifier,
                    "tried to add a message to a non-active MPC session"
                );
                return;
            }
        };

        let protocol_name = metric_data.as_ref().map_or("Unknown", |d| d.name());
        let curve = metric_data
            .as_ref()
            .map_or_else(|| "Unknown".to_string(), |d| d.curve());
        let hash_scheme = metric_data
            .as_ref()
            .map_or_else(|| "Unknown".to_string(), |d| d.hash_scheme());
        let signature_algorithm = metric_data
            .as_ref()
            .map_or_else(|| "Unknown".to_string(), |d| d.signature_algorithm());

        debug!(
            session_identifier=?message.session_identifier,
            from_authority=?message.authority,
            receiving_authority=?self.validator_name,
            consensus_round=?consensus_round,
            message_size_bytes=?message.message.len(),
            %protocol_name,
            %curve,
            %hash_scheme,
            %signature_algorithm,
            "Received a dWallet MPC message",
        );
        self.session_start_consensus_round
            .get_or_insert(consensus_round);
        self.diagnostics
            .record(SessionDiagnosticEvent::MessageReceived {
                consensus_round,
                sender_party_id,
                message_size_bytes: message.message.len(),
            });

        let SessionComputationType::MPC {
            messages_by_consensus_round,
        } = &mut self.computation_type
        else {
            warn!(
                session_identifier=?self.session_identifier,
                sender_authority=?message.authority,
                receiver_authority=?self.validator_name,
                consensus_round=?consensus_round,
                "got a message for a non-MPC session, ignoring",
            );

            return;
        };

        let consensus_round_messages_map = messages_by_consensus_round
            .entry(consensus_round)
            .or_default();

        if let Vacant(e) = consensus_round_messages_map.entry(sender_party_id) {
            e.insert(message.message);
        }
    }

    /// Add an output received from a party for the current consensus round.
    /// If the party already sent an output for this consensus round, it is ignored.
    /// This is used to collect outputs from different parties for the same consensus round,
    ///
    /// If we got an output from ourselves, mark the session as computation completed.
    pub(crate) fn add_output(
        &mut self,
        consensus_round: u64,
        sender_party_id: PartyID,
        output: DWalletMPCOutputReport,
    ) -> AddOutputResult {
        debug!(
            session_identifier=?output.session_identifier(),
            from_authority=?output.authority(),
            receiving_authority=?self.validator_name,
            output=?output,
            consensus_round,
            status =? self.status,
            "Received a dWallet MPC output",
        );

        // Diagnostic counters for the per-session metrics. Updated even for sessions in
        // non-Active state — the data is meaningful for sessions stuck in
        // `ComputationCompleted` awaiting quorum. These never decrement.
        self.first_output_consensus_round = Some(
            self.first_output_consensus_round
                .map_or(consensus_round, |previous| previous.min(consensus_round)),
        );
        self.session_start_consensus_round
            .get_or_insert(consensus_round);
        let authority = output.authority();
        self.distinct_output_authorities.insert(authority);
        let rejected = output.rejected();

        if sender_party_id == self.party_id {
            // First occurrence wins — a later retransmission of our output shouldn't
            // overwrite the round in which it originally looped back.
            self.self_output_consensus_round
                .get_or_insert(consensus_round);
            self.local_output_rejected = Some(rejected);

            // Received an output from ourselves from the consensus, so it's safe to mark the session as computation completed.
            info!(
                session_identifier = ?self.session_identifier,
                session_sequence_number = ?self.status.session_sequence_number(),
                authority = ?self.validator_name,
                consensus_round,
                rejected,
                "Received our output from consensus, marking session as computation completed",
            );

            self.mark_mpc_session_as_computation_completed()
        }

        let malicious_authorities = output.malicious_authorities();
        let output = match output.output() {
            Ok(output) => output,
            Err(_) => {
                self.diagnostics
                    .record(SessionDiagnosticEvent::OutputObserved {
                        consensus_round,
                        sender_party_id,
                        output_digest: None,
                        report_digest: None,
                        rejected,
                        reported_malicious_count: malicious_authorities.len(),
                        valid: false,
                    });
                return AddOutputResult::Invalid {
                    error_code: "invalid_output_envelope",
                };
            }
        };
        let Some(output_digest) = output_digest(&output) else {
            self.diagnostics
                .record(SessionDiagnosticEvent::OutputObserved {
                    consensus_round,
                    sender_party_id,
                    output_digest: None,
                    report_digest: None,
                    rejected,
                    reported_malicious_count: malicious_authorities.len(),
                    valid: false,
                });
            return AddOutputResult::Invalid {
                error_code: "output_digest_failed",
            };
        };
        let Some(report_digest) = report_digest(&output, &malicious_authorities) else {
            self.diagnostics
                .record(SessionDiagnosticEvent::OutputObserved {
                    consensus_round,
                    sender_party_id,
                    output_digest: Some(output_digest),
                    report_digest: None,
                    rejected,
                    reported_malicious_count: malicious_authorities.len(),
                    valid: false,
                });
            return AddOutputResult::Invalid {
                error_code: "report_digest_failed",
            };
        };
        self.distinct_output_digests.insert(output_digest);
        self.output_observations
            .entry(authority)
            .and_modify(|observation| {
                observation.digests.insert(output_digest);
                observation.malicious_actor_count = observation
                    .malicious_actor_count
                    .max(malicious_authorities.len());
                observation.rejected |= rejected;
            })
            .or_insert_with(|| SessionOutputObservation {
                digests: HashSet::from([output_digest]),
                malicious_actor_count: malicious_authorities.len(),
                rejected,
            });
        if sender_party_id == self.party_id {
            self.local_output_digest = self.local_output_digest.or(Some(output_digest));
        }
        self.diagnostics
            .record(SessionDiagnosticEvent::OutputObserved {
                consensus_round,
                sender_party_id,
                output_digest: Some(output_digest),
                report_digest: Some(report_digest),
                rejected,
                reported_malicious_count: malicious_authorities.len(),
                valid: true,
            });
        let consensus_round_output_map = self
            .outputs_by_consensus_round
            .entry(consensus_round)
            .or_default();
        if let Vacant(e) = consensus_round_output_map.entry(sender_party_id) {
            e.insert(DWalletMPCSessionOutput {
                output,
                malicious_authorities,
                output_digest,
                report_digest,
                rejected,
            });
        }

        AddOutputResult::Accepted {
            conflicting_output_digests: self.distinct_output_digests.len() > 1,
            own_rejected_output: sender_party_id == self.party_id && rejected,
        }
    }

    pub(crate) fn outputs_by_consensus_round(
        &self,
    ) -> &BTreeMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>> {
        &self.outputs_by_consensus_round
    }

    pub(crate) fn mark_mpc_session_as_completed(&mut self) {
        self.record_status_transition("Completed");
        self.status = SessionStatus::Completed;
    }

    pub(crate) fn mark_mpc_session_as_computation_completed(&mut self) {
        self.record_status_transition("Computation Completed");
        self.status = SessionStatus::ComputationCompleted;
    }

    pub(crate) fn set_status(&mut self, status: SessionStatus) {
        self.record_status_transition(&status.to_string());
        self.status = status;
    }

    fn record_status_transition(&mut self, to: &str) {
        let from = self.status.to_string();
        if from != to {
            self.diagnostics
                .record(SessionDiagnosticEvent::StatusTransition {
                    from,
                    to: to.to_string(),
                });
        }
    }

    pub(crate) fn record_computation_started(
        &mut self,
        consensus_round: u64,
        mpc_round: Option<u64>,
        attempt_number: u64,
    ) {
        self.session_start_consensus_round
            .get_or_insert(consensus_round);
        self.local_computation_attempts_started =
            self.local_computation_attempts_started.saturating_add(1);
        self.local_computation_last_failed = false;
        self.diagnostics
            .record(SessionDiagnosticEvent::ComputationStarted {
                consensus_round,
                mpc_round,
                attempt_number,
            });
    }

    pub(crate) fn record_computation_completed(
        &mut self,
        consensus_round: u64,
        mpc_round: Option<u64>,
        attempt_number: u64,
        result: &'static str,
        error_code: Option<&'static str>,
        error_party_ids: Vec<PartyID>,
    ) {
        self.local_computation_attempts_completed =
            self.local_computation_attempts_completed.saturating_add(1);
        if error_code.is_some() {
            self.local_computation_attempts_failed =
                self.local_computation_attempts_failed.saturating_add(1);
            self.local_computation_last_failed = true;
        }
        self.diagnostics
            .record(SessionDiagnosticEvent::ComputationCompleted {
                consensus_round,
                mpc_round,
                attempt_number,
                result,
                error_code,
                error_party_ids,
            });
    }

    pub(crate) fn record_message_submission(
        &mut self,
        consensus_round: Option<u64>,
        mpc_round: Option<u64>,
        attempt_number: u64,
        message_size_bytes: usize,
    ) {
        self.diagnostics
            .record(SessionDiagnosticEvent::MessageSubmitted {
                consensus_round,
                mpc_round,
                attempt_number,
                message_size_bytes,
            });
    }

    pub(crate) fn record_local_output_produced(
        &mut self,
        consensus_round: Option<u64>,
        output_digest: Option<[u8; 32]>,
        rejected: bool,
    ) {
        self.local_output_produced = true;
        if let Some(consensus_round) = consensus_round {
            self.session_start_consensus_round
                .get_or_insert(consensus_round);
        }
        self.local_output_digest = output_digest;
        self.local_output_rejected = Some(rejected);
        self.diagnostics
            .record(SessionDiagnosticEvent::OutputProduced {
                consensus_round,
                output_digest,
                rejected,
            });
    }

    pub(crate) fn record_local_output_submission(
        &mut self,
        consensus_round: Option<u64>,
        output_digest: Option<[u8; 32]>,
        rejected: bool,
        succeeded: bool,
        error_code: Option<&'static str>,
    ) {
        self.local_output_submitted = true;
        self.local_output_submission_round = self.local_output_submission_round.or(consensus_round);
        self.local_output_digest = self.local_output_digest.or(output_digest);
        self.local_output_rejected = Some(rejected);
        self.local_output_submission_succeeded = Some(succeeded);
        self.diagnostics
            .record(SessionDiagnosticEvent::OutputSubmissionFinished {
                consensus_round,
                output_digest,
                rejected,
                succeeded,
                error_code,
            });
    }

    pub(crate) fn record_quorum(
        &mut self,
        consensus_round: u64,
        winning_output_digest: [u8; 32],
        rejected: bool,
    ) {
        self.quorum_consensus_round.get_or_insert(consensus_round);
        self.diagnostics
            .record(SessionDiagnosticEvent::QuorumReached {
                consensus_round,
                winning_output_digest,
                rejected,
                local_output_observed: self.self_output_consensus_round.is_some(),
            });
    }

    pub(crate) fn record_quorum_output_cached(&mut self) {
        self.diagnostics
            .record(SessionDiagnosticEvent::QuorumOutputCached {
                without_local_output: self.self_output_consensus_round.is_none(),
            });
    }

    pub(crate) fn anomaly_snapshot(
        &mut self,
        anomaly: MpcAnomalyKind,
        manager_epoch: u64,
        context: MpcAnomalyContext,
    ) -> Option<MpcAnomalySnapshot> {
        if !self.diagnostics.begin_anomaly(anomaly) {
            return None;
        }

        let local_computation_state = if context.running_computation_count > 0 {
            LocalComputationState::Running
        } else if self.local_output_produced {
            LocalComputationState::OutputProduced
        } else if self.local_computation_last_failed {
            LocalComputationState::Failed
        } else if self.local_computation_attempts_started > 0 {
            LocalComputationState::WaitingForProtocolInput
        } else {
            LocalComputationState::NotStarted
        };

        let snapshot = MpcAnomalySnapshot {
            schema_version: MPC_ANOMALY_SCHEMA_VERSION,
            anomaly_kind: anomaly,
            session_id: self.session_identifier.into_bytes(),
            session_type: self
                .session_type
                .unwrap_or_else(|| self.session_identifier.session_type()),
            computation_type: match &self.computation_type {
                SessionComputationType::MPC { .. } => "MPC",
                SessionComputationType::Native => "Native",
            },
            protocol: self.protocol.clone(),
            session_sequence_number: self.session_sequence_number,
            epoch: self.request_epoch.unwrap_or(manager_epoch),
            local_authority: self.validator_name,
            local_party_id: self.party_id,
            session_start_consensus_round: self.session_start_consensus_round,
            current_consensus_round: context.current_consensus_round,
            source_authority: context.source_authority,
            source_party_id: context.source_party_id,
            local_output_submission_round: self.local_output_submission_round,
            local_output_consensus_round: self.self_output_consensus_round,
            quorum_consensus_round: self.quorum_consensus_round,
            lifecycle_status: self.status.to_string(),
            local_computation_state,
            local_computation_attempts_started: self.local_computation_attempts_started,
            local_computation_attempts_completed: self.local_computation_attempts_completed,
            local_computation_attempts_failed: self.local_computation_attempts_failed,
            running_computation_count: context.running_computation_count,
            local_output_produced: self.local_output_produced,
            local_output_submitted: self.local_output_submitted,
            local_output_submission_succeeded: self.local_output_submission_succeeded,
            local_output_observed: self.self_output_consensus_round.is_some(),
            local_output_rejected: self.local_output_rejected,
            local_output_digest: self.local_output_digest,
            quorum_reached_without_local_output: self.quorum_consensus_round.is_some()
                && self.self_output_consensus_round.is_none(),
            network_key_reconfiguration: self.network_key_reconfiguration,
            network_encryption_key_id: self.network_encryption_key_id,
            vote: context.vote,
            local_authority_malicious: context.local_authority_malicious,
            quorum_output_cached_without_local_output: context
                .quorum_output_cached_without_local_output,
            trigger_conditions: context.trigger_conditions,
            error_code: context.error_code,
            error_party_ids: context.error_party_ids,
            service_loop_termination_reason: context.service_loop_termination_reason,
            recent_trace_dropped_events: self.diagnostics.dropped_events(),
            recent_trace: self.diagnostics.events(),
        };
        #[cfg(test)]
        {
            self.last_anomaly_snapshot = Some(snapshot.clone());
        }
        Some(snapshot)
    }

    #[cfg(test)]
    pub(crate) fn emitted_anomaly_count(&self) -> usize {
        self.diagnostics.emitted_anomaly_count()
    }

    #[cfg(test)]
    pub(crate) fn last_anomaly_snapshot(&self) -> Option<&MpcAnomalySnapshot> {
        self.last_anomaly_snapshot.as_ref()
    }

    pub(crate) fn request_metric_data(&self) -> Option<DWalletSessionRequestMetricData> {
        let SessionStatus::Active { request, .. } = &self.status else {
            return None;
        };
        Some((&request.protocol_data).into())
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SessionStatus::Active { .. } => write!(f, "Active"),
            SessionStatus::WaitingForSessionRequest => write!(f, "Waiting for Session Request"),
            SessionStatus::ComputationCompleted => write!(f, "Computation Completed"),
            SessionStatus::Completed => write!(f, "Completed"),
            SessionStatus::Failed => write!(f, "Failed"),
        }
    }
}

impl Debug for SessionStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<&ProtocolData> for SessionComputationType {
    fn from(value: &ProtocolData) -> Self {
        match value {
            ProtocolData::MakeDWalletUserSecretKeySharesPublic { .. }
            | ProtocolData::EncryptedShareVerification { .. }
            | ProtocolData::PartialSignatureVerification { .. } => SessionComputationType::Native,
            _ => SessionComputationType::MPC {
                messages_by_consensus_round: HashMap::new(),
            },
        }
    }
}

impl TryFrom<&DWalletCheckpointMessageKind> for SessionComputationType {
    type Error = ();

    fn try_from(value: &DWalletCheckpointMessageKind) -> Result<Self, Self::Error> {
        match value {
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(_)
            | DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(_) => {
                Ok(SessionComputationType::Native)
            }

            DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(_)
            | DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(_)
            | DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(_)
            | DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(_)
            | DWalletCheckpointMessageKind::RespondDWalletPresign(_)
            | DWalletCheckpointMessageKind::RespondDWalletSign(_)
            | DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(_)
            | DWalletCheckpointMessageKind::RespondDWalletDKGOutput(_)
            | DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(_) => {
                Ok(SessionComputationType::MPC {
                    messages_by_consensus_round: HashMap::new(),
                })
            }

            DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(_)
            | DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(_)
            | DWalletCheckpointMessageKind::EndOfPublish => Err(()),
        }
    }
}

impl DWalletMPCManager {
    /// Handle a batch of MPC requests.
    ///
    /// This function might be called more than once for a given session, as we periodically
    /// check for uncompleted requests - in which case the event will be ignored.
    ///
    /// A new MPC session is only created once at the first time the request was received
    /// (per-epoch and assuming we didn't crash; if it was uncompleted in the previous epoch,
    /// it will be created again for the next one.)
    ///
    /// If the request already exists in `self.mpc_sessions`, we do not add it.
    ///
    /// If there is no `session_request`, and we've got it in this call,
    /// we update that field in the open session.
    pub(crate) async fn handle_mpc_request_batch(
        &mut self,
        requests: Vec<DWalletSessionRequest>,
    ) -> Vec<DWalletSessionRequest> {
        // We only update `next_active_committee` in this block. Once it's set,
        // there will no longer be any pending events targeting it for this epoch.
        let mut failed_sessions_waiting_to_send_reject = vec![];
        if self.next_active_committee.is_none() {
            let got_next_active_committee = self.try_receiving_next_active_committee();
            if got_next_active_committee {
                // The next committee's off-chain PVSS/VSS keys arrive on a separate
                // channel, so receiving the committee does not imply they're
                // ingested yet (the committee can land before the keys). We do NOT
                // ingest here: any reconfig request drained below whose
                // `next_epoch_validator_mpc_keys` isn't populated yet hits the
                // off-chain freeze gate, parks on `requests_pending_for_frozen_mpc_data`,
                // and re-drains on a later cycle once the top-of-loop
                // `ingest_offchain_mpc_keys` (`dwallet_mpc_service`) fills it in.
                let events_pending_for_next_active_committee =
                    mem::take(&mut self.requests_pending_for_next_active_committee);

                for request in events_pending_for_next_active_committee {
                    if Some(SessionStatus::Failed) == self.handle_mpc_request(request.clone()) {
                        failed_sessions_waiting_to_send_reject.push(request.clone());
                    }
                    tokio::task::yield_now().await;
                }
            }
        }

        // Drain requests parked on a network key whose public data is now
        // locally available. LEVEL-triggered on data presence (re-checked
        // every cycle), NOT edge-triggered on the consensus-round key
        // instantiation: the key can materialize through paths that never
        // emit that edge — on a fresh boot the cert-less chain-copy adoption
        // registers the key's public data without ever passing through
        // `poll_pending_network_key_instantiations`' newly-instantiated
        // list. Under the old edge-triggered drain, a reshare in flight
        // across a restart parked here forever: the session never activated,
        // no output was ever produced, and the epoch could not close
        // (issue #1834). Same discipline as the frozen-mpc-data queue below.
        let ready_key_ids: Vec<ObjectID> = self
            .requests_pending_for_network_key
            .keys()
            .filter(|key_id| self.network_keys.key_public_data_exists(key_id))
            .copied()
            .collect();
        for key_id in ready_key_ids {
            let events_pending_for_newly_updated_network_key = self
                .requests_pending_for_network_key
                .remove(&key_id)
                .unwrap_or_default();
            info!(
                network_encryption_key_id=?key_id,
                drained = events_pending_for_newly_updated_network_key.len(),
                "network key public data is now available; draining requests parked on it"
            );
            for request in events_pending_for_newly_updated_network_key {
                // We know this won't fail on a missing network key,
                // but it could be waiting for the next committee,
                // in which case it would be added to that queue,
                // and handled in a subsequent call to this function.
                if Some(SessionStatus::Failed) == self.handle_mpc_request(request.clone()) {
                    failed_sessions_waiting_to_send_reject.push(request.clone());
                }
            }
            tokio::task::yield_now().await;
        }

        // Drain DKG / reconfig requests parked on the off-chain
        // freeze gate. We retry every cycle because the gate's
        // satisfaction signal (a fresh quorum) doesn't trigger us
        // directly — it shows up in the per-epoch store, which we
        // re-read inside `handle_mpc_request`. Requests that still
        // don't pass get re-queued.
        let pending_freeze = mem::take(&mut self.requests_pending_for_frozen_mpc_data);
        for request in pending_freeze {
            if Some(SessionStatus::Failed) == self.handle_mpc_request(request.clone()) {
                failed_sessions_waiting_to_send_reject.push(request.clone());
            }
            tokio::task::yield_now().await;
        }

        // Handle the new requests batch.
        // `handle_mpc_request()` may fail on the condition of either waiting for the next committee or network key information,
        // in which case it would be added to the corresponding queue,
        // and handled in a subsequent call to this function.
        for request in requests {
            if Some(SessionStatus::Failed) == self.handle_mpc_request(request.clone()) {
                failed_sessions_waiting_to_send_reject.push(request.clone());
            }

            tokio::task::yield_now().await;
        }
        failed_sessions_waiting_to_send_reject
    }

    /// Handle an MPC request.
    ///
    /// This function might be called more than once for a given session, as we periodically
    /// check for uncompleted events.
    ///
    /// A new MPC session is only created once at the first time the event was received
    /// (per-epoch, if it was uncompleted in the previous epoch, it will be created again for the next one.)
    ///
    /// If the event already exists in `self.mpc_sessions`, we do not add it.
    ///
    /// If there is no `session_request`, and we've got it in this call,
    /// we update that field in the open session.
    pub(crate) fn handle_mpc_request(
        &mut self,
        request: DWalletSessionRequest,
    ) -> Option<SessionStatus> {
        let session_identifier = request.session_identifier;

        if !request.should_run_in_current_epoch(self.epoch_id) {
            warn!(
                session_identifier=?session_identifier,
                session_request=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
                session_source=?request.session_type,
                event_epoch=?request.epoch,
                "received an event for a different epoch, skipping"
            );

            return None;
        }

        if request.requires_network_key_data
            && let Some(network_encryption_key_id) =
                request.protocol_data.network_encryption_key_id()
            && !self
                .network_keys
                .key_public_data_exists(&network_encryption_key_id)
        {
            // We don't yet have the data for this network encryption key,
            // so we add it to the queue.
            let request_pending_for_this_network_key = self
                .requests_pending_for_network_key
                .entry(network_encryption_key_id)
                .or_default();

            if request_pending_for_this_network_key
                .iter()
                .all(|e| e.session_identifier != session_identifier)
            {
                // Add an event with this session ID only if it doesn't exist.
                // INFO (not debug), once per parked request: a silently
                // stranded park here was a multi-hour diagnosis (issue
                // #1834) — the deferral must be visible in default logs.
                info!(
                    session_request=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
                    session_source=?request.session_type,
                    session_identifier=?session_identifier,
                    network_encryption_key_id=?network_encryption_key_id,
                    "network key public data not yet available; parking request until it is"
                );
                request_pending_for_this_network_key.push(request);
            }

            return None;
        }

        if request.requires_next_active_committee && self.next_active_committee.is_none() {
            // We don't have the next active committee yet,
            // so we have to add this request to the pending queue until it arrives.
            if self
                .requests_pending_for_next_active_committee
                .iter()
                .all(|e| e.session_identifier != session_identifier)
            {
                // Add a request with this session ID only if it doesn't exist.
                // INFO, once per parked request — see the network-key park
                // above for why these deferrals must be visible.
                info!(
                    session_request=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
                    session_identifier=?request.session_identifier,
                    session_source=?request.session_type,
                    "next-epoch active committee not yet available; parking request until it is"
                );
                self.requests_pending_for_next_active_committee
                    .push(request);
            }

            return None;
        }

        // Off-chain mpc_data freeze gate: both network DKG and
        // reconfiguration sessions wait until the per-epoch mpc_data
        // input set is frozen. The freeze itself is decided at the
        // consensus commit boundary (quorum of ready-signals AND full
        // coverage-or-grace; see
        // `process_consensus_transactions_and_commit_boundary`) so the
        // frozen set is identical on every validator; this gate just
        // reads it. A deferred request re-drains every cycle (see the
        // drain loop above), so the session starts on the first cycle
        // after the freeze lands.
        //
        // Bypassed entirely when the off-chain validator metadata
        // protocol feature is disabled — legacy chain-only behavior.
        // Gate also requires the agreed (frozen) off-chain key set to be ingested
        // — `is_mpc_data_frozen` says the set is decided, but the keys arrive on
        // a separate channel; without this a DKG could start after the freeze but
        // before the keys land and run against an empty key map. DKG needs the
        // current-epoch set; reconfiguration needs the next-epoch set.
        let off_chain_gate_passes = match &request.protocol_data {
            ProtocolData::NetworkEncryptionKeyDkg { .. } => {
                !self.epoch_store.off_chain_validator_metadata_enabled()
                    || (self.epoch_store.is_mpc_data_frozen().unwrap_or(false)
                        && self.current_epoch_keys_ingested)
            }
            ProtocolData::NetworkEncryptionKeyReconfiguration { .. } => {
                !self.epoch_store.off_chain_validator_metadata_enabled()
                    || (self.epoch_store.is_mpc_data_frozen().unwrap_or(false)
                        && self.next_epoch_validator_mpc_keys.is_some())
            }
            _ => true,
        };
        if !off_chain_gate_passes {
            debug!(
                session_request=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
                session_identifier=?session_identifier,
                "off-chain mpc_data freeze gate not satisfied — deferring"
            );
            if self
                .requests_pending_for_frozen_mpc_data
                .iter()
                .all(|e| e.session_identifier != session_identifier)
            {
                self.requests_pending_for_frozen_mpc_data.push(request);
            }
            return None;
        }

        if let Some(session) = self.sessions.get(&session_identifier)
            && !matches!(session.status, SessionStatus::WaitingForSessionRequest)
        {
            // The corresponding session already has its data set, nothing to do.
            return None;
        }

        // Global presigns are served from the internal presign pool — but the
        // pool only exists once `internal_presign_sessions` activates (the
        // whole request/fulfill pipeline is gated on that flag, see
        // `next_global_presign_request` in the service). Before activation —
        // i.e. while running at the previous protocol version right after an
        // upgrade, with the on-chain `GlobalPresignConfig` already routing
        // presigns to global — diverting the request here would strand it:
        // no pool to serve it, no MPC session spawned, and the session is
        // locked into its epoch (`all_current_epoch_sessions_completed`
        // blocks `advance_epoch`), wedging the network below the version
        // that could serve it. So pre-activation, fall through and run the
        // request as a user-requested MPC session — the pre-pool serving
        // behavior (the dwallet-output-less presign computation path).
        if self.protocol_config.internal_presign_sessions_enabled()
            && let Some((presign_id, curve, signature_algorithm, dwallet_network_encryption_key_id)) =
                request.protocol_data.is_global_presign()
        {
            if request.session_sequence_number.is_none() {
                error!(
                    should_never_happen = true,
                    session_identifier = ?request.session_identifier,
                    "internal presign session missing session_sequence_number",
                );
            }
            let global_presign_request = GlobalPresignRequest {
                session_identifier: request.session_identifier,
                session_sequence_number: request
                    .session_sequence_number
                    .expect("internal presign sessions always have a session sequence number"),
                presign_id,
                curve,
                signature_algorithm,
                dwallet_network_encryption_key_id,
            };

            if !self
                .global_presign_requests
                .contains(&global_presign_request)
            {
                self.global_presign_requests.push(global_presign_request);
            }

            // Don't create a session for global presign, we will take it from the internal pools.
            return None;
        }

        let status = self.session_status_from_request(request.clone(), false);
        let protocol_name = DWalletSessionRequestMetricData::from(&request.protocol_data)
            .name()
            .to_owned();

        self.dwallet_mpc_metrics
            .add_received_request_start(&(&request.protocol_data).into());

        let new_type = SessionComputationType::from(&request.protocol_data);

        if let Some(session) = self.sessions.get_mut(&session_identifier) {
            session.set_status(status.clone());
            session.counterparty_chain = request.counterparty_chain;
            // Record seq + type on the session entry so they survive future transitions to
            // unit-variant states (ComputationCompleted/Completed/Failed) which would
            // otherwise discard this information.
            session.set_request_metadata(request.session_sequence_number, request.session_type);
            session.set_protocol_name(protocol_name.clone());
            session.set_request_diagnostic_metadata(&request);

            // We only trust the session type that we deduce ourselves from the session request.
            // However, it is not safe to override the session status in all cases.
            //
            // Specifically, if this is an MPC session, it could be that we received the session request after we have already received messages for it,
            // as the Ika consensus and Sui aren't in sync. In this case, we don't override the session type,
            // as it encapsulates messages that we don't want to drop.
            if let SessionComputationType::MPC { .. } = &session.computation_type {
                if !matches!(new_type, SessionComputationType::MPC { .. }) {
                    session.computation_type = new_type;
                }
            } else {
                session.computation_type = new_type;
            }
        } else {
            self.new_session(
                &session_identifier,
                status.clone(),
                request.counterparty_chain,
                new_type,
            );
            // `DWalletSession::new` pulls seq/type out of an Active status itself; the
            // explicit set covers the non-Active creation path (e.g. Failed).
            if let Some(session) = self.sessions.get_mut(&session_identifier) {
                session.set_request_metadata(request.session_sequence_number, request.session_type);
                session.set_protocol_name(protocol_name);
                session.set_request_diagnostic_metadata(&request);
            }
        }
        Some(status)
    }
}

impl DWalletMPCService {
    /// Proactively pull uncompleted requests from the Sui network.
    /// We do that to ensure we don't miss any requests.
    /// These requests might be from a different Epoch, not necessarily the current one
    pub(crate) async fn load_uncompleted_requests(&mut self) -> Vec<DWalletSessionRequest> {
        let new_requests_fetched = self
            .sui_data_requests
            .uncompleted_requests_receiver
            .has_changed()
            .unwrap_or_else(|err| {
                error!(
                    error=?err,
                    "failed to check if uncompleted requests receiver has changed"
                );

                false
            });

        if !new_requests_fetched {
            return vec![];
        }

        let (uncompleted_requests, epoch_id) = self
            .sui_data_requests
            .uncompleted_requests_receiver
            .borrow_and_update()
            .clone();

        if epoch_id != self.epoch {
            info!(
                ?epoch_id,
                our_epoch_id = self.epoch,
                "Received uncompleted requests from a different epoch, processing anyway"
            );
        }

        uncompleted_requests
    }

    pub(crate) fn receive_new_sui_requests(&mut self) -> IkaResult<Vec<DWalletSessionRequest>> {
        match self.sui_data_requests.new_requests_receiver.try_recv() {
            Ok(requests) => {
                for request in &requests {
                    debug!(
                        request_type=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
                        session_identifier=?request.session_identifier,
                        current_epoch=?self.epoch,
                        "Received a request from Sui"
                    );
                }

                Ok(requests)
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                debug!("No new requests to process");

                Ok(vec![])
            }
            Err(e) => Err(IkaError::ReceiverError(e.to_string())),
        }
    }
}
