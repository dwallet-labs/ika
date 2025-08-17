// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

mod input;
mod mpc_event_data;

use dwallet_mpc_types::dwallet_mpc::{MPCMessage, MPCPrivateInput};
use group::PartyID;
use ika_types::crypto::{AuthorityName, AuthorityPublicKeyBytes};
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{DWalletMPCMessage, DWalletMPCOutput, SessionIdentifier};
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info, warn};

use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
pub(crate) use crate::dwallet_mpc::mpc_session::mpc_event_data::MPCEventData;
use crate::dwallet_mpc::session_request::DWalletSessionRequest;
use ika_types::error::{IkaError, IkaResult};
pub(crate) use input::{PublicInput, session_input_from_request};
use std::{fmt, mem};
use tokio::sync::broadcast;

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

    // Yael: check if this could be party of the status
    pub(crate) request_data: Option<DWalletSessionRequest>,

    /// All the messages that have been received for this session from each party, by consensus round and then by MPC round.
    /// Used to build the input of messages to advance each round of the session.
    pub(super) messages_by_consensus_round: HashMap<u64, HashMap<PartyID, MPCMessage>>,

    outputs_by_consensus_round: HashMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
}

impl DWalletMPCSession {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        status: MPCSessionStatus,
        session_identifier: SessionIdentifier,
        party_id: PartyID,
        request_data: Option<DWalletSessionRequest>,
    ) -> Self {
        Self {
            status,
            messages_by_consensus_round: HashMap::new(),
            outputs_by_consensus_round: HashMap::new(),
            session_identifier,
            current_mpc_round: 1,
            mpc_round_to_threshold_not_reached_consensus_rounds: HashMap::new(),
            party_id,
            request_data,
            validator_name,
        }
    }

    pub(crate) fn clear_data(&mut self) {
        self.request_data = None;
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
            .request_data
            .as_ref()
            .map(|event_data| event_data.protocol_specific_data.to_string())
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

        // let mpc_round_messages_map = consensus_round_messages_map
        //     .entry(mpc_round_number)
        //     .or_default();

        if let Vacant(e) = consensus_round_messages_map.entry(sender_party_id) {
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
        let request_input = &self
            .request_data
            .as_ref()
            .unwrap()
            .protocol_specific_data
            .to_string();

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
            .request_data
            .as_ref()
            .map(|event_data| event_data.protocol_specific_data.to_string())
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

    pub(crate) fn request_data(&self) -> Option<&DWalletSessionRequest> {
        self.request_data.as_ref()
    }
}

/// Possible statuses of an MPC Session:
///
/// - `Pending`:
///   The instance is queued because the maximum number of active MPC instances
///   [`DWalletMPCManager::max_active_mpc_instances`] has been reached.
///   It is waiting for active instances to complete before activation.
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
#[derive(Clone, PartialEq, Debug)]
pub enum MPCSessionStatus {
    Active {
        public_input: PublicInput,
        private_input: MPCPrivateInput,
    },
    WaitingForSessionRequest,
    ComputationCompleted,
    Completed,
    Failed,
}

impl fmt::Display for MPCSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MPCSessionStatus::Active { .. } => write!(f, "Active"),
            MPCSessionStatus::WaitingForSessionRequest => write!(f, "Waiting for Session Request"),
            MPCSessionStatus::ComputationCompleted => write!(f, "Computation Completed"),
            MPCSessionStatus::Completed => write!(f, "Completed"),
            MPCSessionStatus::Failed => write!(f, "Failed"),
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
    /// (per-epoch, if it was uncompleted in the previous epoch,
    /// it will be created again for the next one.)
    ///
    /// If the request already exists in `self.mpc_sessions`, we do not add it.
    ///
    /// If there is no `session_request`, and we've got it in this call,
    /// we update that field in the open session.
    pub(crate) async fn handle_mpc_request_batch(&mut self, requests: Vec<DWalletSessionRequest>) {
        // We only update `next_active_committee` in this block. Once it's set,
        // there will no longer be any pending events targeting it for this epoch.
        if self.next_active_committee.is_none() {
            let got_next_active_committee = self.try_receiving_next_active_committee();
            if got_next_active_committee {
                let events_pending_for_next_active_committee =
                    mem::take(&mut self.requests_pending_for_next_active_committee);

                for request in events_pending_for_next_active_committee {
                    self.handle_mpc_request(request);
                    tokio::task::yield_now().await;
                }
            }
        }

        // First, try to update the network keys.
        let newly_updated_network_keys_ids = self.maybe_update_network_keys().await;

        // Now handle events for which we've just received the corresponding public data.
        // Since events are only queued in `events_pending_for_network_key` within this function,
        // receiving the network key ensures no further events will be pending for that key.
        // Therefore, it's safe to process them now, as the queue will remain empty afterward.
        for key_id in newly_updated_network_keys_ids {
            let events_pending_for_newly_updated_network_key = self
                .requests_pending_for_network_key
                .remove(&key_id)
                .unwrap_or_default();

            for event in events_pending_for_newly_updated_network_key {
                // We know this won't fail on a missing network key,
                // but it could be waiting for the next committee,
                // in which case it would be added to that queue.
                // in which case it would be added to that queue.
                self.handle_mpc_request(event);
            }
            tokio::task::yield_now().await;
        }

        for event in requests {
            self.handle_mpc_request(event);
            tokio::task::yield_now().await;
        }
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
    fn handle_mpc_request(&mut self, request: DWalletSessionRequest) {
        let session_identifier = request.session_identifier;

        // Avoid instantiation of completed events by checking they belong to the current epoch.
        // We only pull uncompleted events, so we skip the check for those,
        // but pushed events might be completed.
        if !request.pulled && request.epoch != self.epoch_id {
            warn!(
                session_identifier=?session_identifier,
                session_request=?request.protocol_specific_data.to_string(),
                session_type=?request.session_type,
                event_epoch=?request.epoch,
                "received an event for a different epoch, skipping"
            );

            return;
        }

        if request.requires_network_key_data {
            if let Some(network_encryption_key_id) =
                request.protocol_specific_data.network_encryption_key_id()
            {
                if !self
                    .network_keys
                    .key_public_data_exists(&network_encryption_key_id)
                {
                    // We don't yet have the data for this network encryption key,
                    // so we add it to the queue.
                    debug!(
                        session_request=?request.protocol_specific_data.to_string(),
                        session_type=?request.session_type,
                        network_encryption_key_id=?network_encryption_key_id,
                        "Adding request to pending for the network key"
                    );

                    let request_pending_for_this_network_key = self
                        .requests_pending_for_network_key
                        .entry(network_encryption_key_id)
                        .or_default();

                    if request_pending_for_this_network_key
                        .iter()
                        .all(|e| e.session_identifier != session_identifier)
                    {
                        // Add an event with this session ID only if it doesn't exist.
                        request_pending_for_this_network_key.push(request);
                    }

                    return;
                }
            }
        }

        if request.requires_next_active_committee && self.next_active_committee.is_none() {
            // We don't have the next active committee yet,
            // so we have to add this request to the pending queue until it arrives.
            debug!(
                session_request=?request.protocol_specific_data.to_string(),
                session_type=?request.session_type,
                "Adding request to pending for the next epoch active committee"
            );

            if self
                .requests_pending_for_next_active_committee
                .iter()
                .all(|e| e.session_identifier != session_identifier)
            {
                // Add a request with this session ID only if it doesn't exist.
                self.requests_pending_for_next_active_committee
                    .push(request);
            }

            return;
        }

        // Yael: change this to work with the active status that contains the PublicInput enum
        if let Some(session) = self.mpc_sessions.get(&session_identifier) {
            if session.request_data.is_some() {
                // The corresponding session already has its data set, nothing to do.
                return;
            }
        }

        let (public_input, private_input) = match session_input_from_request(
            &request,
            &self.access_structure,
            &self.committee,
            &self.network_keys,
            self.next_active_committee.clone(),
            self.validators_class_groups_public_keys_and_proofs.clone(),
        ) {
            Ok((public_input, private_input)) => (public_input, private_input),
            Err(e) => {
                error!(error=?e, ?request, "create session input from dWallet request with error");
                return;
            }
        };

        let status = MPCSessionStatus::Active {
            public_input,
            private_input,
        };

        self.dwallet_mpc_metrics
            .add_received_request_start(&request.protocol_specific_data);

        if let Some(session) = self.mpc_sessions.get_mut(&session_identifier) {
            session.request_data = Some(request);
            session.status = status;
        } else {
            // Yael: I first want to make the code work with the optional request data, later with the active status
            self.new_mpc_session(&session_identifier, Some(request), status);
        }
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
                "Received uncompleted requests for a different epoch, ignoring"
            );
            return vec![];
        }
        uncompleted_requests
    }

    pub(crate) fn receive_new_sui_requests(&mut self) -> IkaResult<Vec<DWalletSessionRequest>> {
        match self.sui_data_requests.new_requests_receiver.try_recv() {
            Ok(requests) => {
                for request in &requests {
                    debug!(
                        request_type=?request.protocol_specific_data.to_string(),
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
