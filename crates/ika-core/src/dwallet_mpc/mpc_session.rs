// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

mod input;
mod mpc_event_data;

use dwallet_mpc_types::dwallet_mpc::{MPCMessage, MPCSessionStatus};
use group::PartyID;
use ika_types::crypto::{AuthorityName, AuthorityPublicKeyBytes};
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{DWalletMPCMessage, DWalletMPCOutput, SessionIdentifier};
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info};

pub(crate) use crate::dwallet_mpc::mpc_session::mpc_event_data::MPCEventData;
pub(crate) use input::{PublicInput, session_input_from_event};

pub(crate) type MPCRoundToMessagesHashMap = HashMap<u64, HashMap<PartyID, MPCMessage>>;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct DWalletMPCSessionOutput {
    pub(crate) output: Vec<DWalletCheckpointMessageKind>,
    pub(crate) malicious_authorities: Vec<AuthorityName>,
}

/// A dWallet MPC session.
#[derive(Clone)]
pub(crate) struct DWalletMPCSession {
    pub(super) session_identifier: SessionIdentifier,
    validator_name: AuthorityPublicKeyBytes,
    pub(crate) party_id: PartyID,

    /// The status of the MPC session.
    pub(super) status: MPCSessionStatus,

    /// The current MPC round number of the session.
    /// Starts at `1` and increments after each successful advance of the session.
    /// In round `1` We start the flow, without messages, from the event trigger.
    pub(super) current_mpc_round: u64,

    /// A map between an MPC round, and the list of consensus rounds at which we tried to
    /// advance and failed.
    /// The total number of attempts to advance that failed in the session can be
    /// computed by summing the number of failed attempts.
    pub(crate) mpc_round_to_threshold_not_reached_consensus_rounds: HashMap<u64, HashSet<u64>>,

    pub(crate) mpc_event_data: Option<MPCEventData>,

    /// All the messages that have been received for this session from each party, by consensus round and then by MPC round.
    /// Used to build the input of messages to advance each round of the session.
    pub(super) messages_by_consensus_round: HashMap<u64, MPCRoundToMessagesHashMap>,

    outputs_by_consensus_round: HashMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
}

impl DWalletMPCSession {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        status: MPCSessionStatus,
        session_identifier: SessionIdentifier,
        party_id: PartyID,
        mpc_event_data: Option<MPCEventData>,
    ) -> Self {
        Self {
            status,
            messages_by_consensus_round: HashMap::new(),
            outputs_by_consensus_round: HashMap::new(),
            session_identifier,
            current_mpc_round: 1,
            mpc_round_to_threshold_not_reached_consensus_rounds: HashMap::new(),
            party_id,
            mpc_event_data,
            validator_name,
        }
    }

    pub(crate) fn clear_data(&mut self) {
        self.mpc_event_data = None;
        self.messages_by_consensus_round = HashMap::new();
        self.outputs_by_consensus_round = HashMap::new();
    }

    /// Adds an incoming message, and increases the `current_mpc_round` upon seeing a message
    /// sent from us for the current round.
    /// This guarantees we are in sync, as our state mutates in sync with the view of the
    /// consensus, which is shared with the other validators.
    ///
    /// This function performs no checks, it simply stores the message in the map.
    ///
    /// If a party sent a message twice, the second message will be ignored.
    /// Whilst that is malicious, it has no effect since the messages come in order,
    /// so all validators end up seeing the same map.
    /// Other malicious activities like sending a message for a wrong round are also not
    /// reported since they have no practical impact for similar reasons.
    pub(crate) fn add_message(
        &mut self,
        consensus_round: u64,
        mpc_round_number: u64,
        sender_party_id: PartyID,
        message: DWalletMPCMessage,
    ) {
        let mpc_protocol = self
            .mpc_event_data
            .as_ref()
            .map(|event_data| event_data.request_input.to_string())
            .unwrap_or_default();
        debug!(
            session_identifier=?message.session_identifier,
            from_authority=?message.authority,
            receiving_authority=?self.validator_name,
            mpc_round=?mpc_round_number,
            message_size_bytes=?message.message.len(),
            ?mpc_protocol,
            "Received a dWallet MPC message",
        );

        if sender_party_id == self.party_id && self.current_mpc_round <= mpc_round_number {
            // Received a message from ourselves from the consensus, so it's safe to advance the round.
            let new_mpc_round = mpc_round_number + 1;
            info!(
                session_identifier=?message.session_identifier,
                authority=?self.validator_name,
                message_mpc_round=?mpc_round_number,
                current_mpc_round=self.current_mpc_round,
                new_mpc_round,
                mpc_protocol,
                "Advancing current MPC round",
            );

            self.current_mpc_round = new_mpc_round;
        }

        let consensus_round_messages_map = self
            .messages_by_consensus_round
            .entry(consensus_round)
            .or_default();

        let mpc_round_messages_map = consensus_round_messages_map
            .entry(mpc_round_number)
            .or_default();

        if let Vacant(e) = mpc_round_messages_map.entry(sender_party_id) {
            e.insert(message.message);
        }
    }

    /// Computes the current *total* attempt number, meaning the number of thresholds
    /// not reached from any mpc round in this session, plus 1.
    pub(crate) fn get_attempt_number(&self) -> u64 {
        let threshold_not_reached_consensus_rounds = self
            .mpc_round_to_threshold_not_reached_consensus_rounds
            .values()
            .flatten()
            .collect::<Vec<_>>();
        let threshold_not_reached_count = threshold_not_reached_consensus_rounds.len();

        // Safe to cast here, as each threshold not reached must be unique for a consensus round, which is `u64` itself.
        (threshold_not_reached_count + 1) as u64
    }

    /// Records a threshold not reached error that we got when advancing
    /// this session with messages up to `consensus_round`.
    pub(crate) fn record_threshold_not_reached(&mut self, consensus_round: u64) {
        let request_input = &self.mpc_event_data.as_ref().unwrap().request_input;

        error!(
            mpc_protocol=?request_input,
            validator=?self.validator_name,
            session_identifier=?self.session_identifier,
            mpc_round=?self.current_mpc_round,
            "threshold was not reached for session"
        );

        self.mpc_round_to_threshold_not_reached_consensus_rounds
            .entry(self.current_mpc_round)
            .or_default()
            .insert(consensus_round);
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
        output: DWalletMPCOutput,
    ) {
        let mpc_protocol = self
            .mpc_event_data
            .as_ref()
            .map(|event_data| event_data.request_input.to_string())
            .unwrap_or_default();
        debug!(
            session_identifier=?output.session_identifier,
            from_authority=?output.authority,
            receiving_authority=?self.validator_name,
            output_messages=?output.output,
            consensus_round,
            ?mpc_protocol,
            "Received a dWallet MPC output",
        );

        if sender_party_id == self.party_id {
            // Received an output from ourselves from the consensus, so it's safe to mark the session as computation completed.
            info!(
                authority=?self.validator_name,
                current_mpc_round=self.current_mpc_round,
                mpc_protocol,
                "Received our output from consensus, marking MPC session as computation completed",
            );

            self.mark_mpc_session_as_computation_completed()
        }

        let consensus_round_output_map = self
            .outputs_by_consensus_round
            .entry(consensus_round)
            .or_default();

        if let Vacant(e) = consensus_round_output_map.entry(sender_party_id) {
            e.insert(DWalletMPCSessionOutput {
                output: output.output,
                malicious_authorities: output.malicious_authorities,
            });
        }
    }

    pub(crate) fn outputs_by_consensus_round(
        &self,
    ) -> &HashMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>> {
        &self.outputs_by_consensus_round
    }

    pub(crate) fn mark_mpc_session_as_completed(&mut self) {
        self.status = MPCSessionStatus::Completed;
    }

    pub(crate) fn mark_mpc_session_as_computation_completed(&mut self) {
        self.status = MPCSessionStatus::ComputationCompleted;
    }

    pub(crate) fn mpc_event_data(&self) -> Option<&MPCEventData> {
        self.mpc_event_data.as_ref()
    }
}
