// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::mpc_computations::build_messages_to_advance;
use crate::dwallet_mpc::crytographic_computation::{
    ComputationId, ComputationRequest, CryptographicComputationsOrchestrator,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_session::{DWalletMPCSession, DWalletMPCSessionOutput, MPCEventData};
use crate::dwallet_mpc::network_dkg::instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, ValidatorPrivateDecryptionKeyData};
use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
    get_validators_class_groups_public_keys_and_proofs, party_id_to_authority_name,
};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::{DWalletMPCNetworkKeyScheme, MPCSessionStatus};
use group::PartyID;
use ika_config::NodeConfig;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletMPCEvent, DWalletMPCMessage, DWalletMPCOutput, DWalletNetworkEncryptionKeyData,
    IkaNetworkConfig, MPCRequestInput, SessionIdentifier, SessionType,
};
use itertools::Itertools;
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tokio::sync::watch;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

/// The [`DWalletMPCManager`] manages MPC sessions:
/// — Keeping track of all MPC sessions,
/// — Executing all active sessions, and
/// — (De)activating sessions.
///
/// The correct way to use the manager is to create it along with all other Ika components
/// at the start of each epoch.
/// Ensuring it is destroyed when the epoch ends and providing a clean slate for each new epoch.
pub(crate) struct DWalletMPCManager {
    /// The party ID of the current authority. Based on the authority index in the committee.
    pub(crate) party_id: PartyID,
    /// A map of all MPC sessions that start execution in this epoch.
    /// These include completed sessions, and they are never to be removed from this
    /// mapping until the epoch advances.
    pub(crate) mpc_sessions: HashMap<SessionIdentifier, DWalletMPCSession>,
    pub(crate) epoch_id: EpochId,
    pub(crate) packages_config: IkaNetworkConfig,
    validator_name: AuthorityPublicKeyBytes,
    pub(crate) committee: Arc<Committee>,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    pub(crate) validators_class_groups_public_keys_and_proofs:
        HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
    pub(crate) cryptographic_computations_orchestrator: CryptographicComputationsOrchestrator,

    /// The set of malicious actors that were agreed upon by a quorum of validators.
    /// This agreement is done synchronically, and thus is it safe to filter malicious actors.
    /// Any message/output from these authorities will be ignored.
    /// This list is maintained during the Epoch.
    /// This happens automatically because the [`DWalletMPCManager`]
    /// is part of the [`AuthorityPerEpochStore`].
    malicious_actors: HashSet<AuthorityName>,

    pub(crate) last_session_to_complete_in_current_epoch: u64,
    pub(crate) recognized_self_as_malicious: bool,
    pub(crate) network_keys: Box<DwalletMPCNetworkKeys>,
    network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    /// Events that wait for the network key to update.
    /// Once we get the network key, these events will be executed.
    pub(crate) events_pending_for_network_key: HashMap<ObjectID, Vec<DWalletMPCEvent>>,
    pub(crate) events_pending_for_next_active_committee: Vec<DWalletMPCEvent>,
    pub(crate) next_epoch_committee_receiver: watch::Receiver<Committee>,
    pub(crate) next_active_committee: Option<Committee>,
    pub(crate) dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,

    network_dkg_third_round_delay: u64,
    decryption_key_reconfiguration_third_round_delay: u64,
}

impl DWalletMPCManager {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        committee: Arc<Committee>,
        epoch_id: EpochId,
        packages_config: IkaNetworkConfig,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        next_epoch_committee_receiver: Receiver<Committee>,
        node_config: NodeConfig,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> Self {
        Self::try_new(
            validator_name,
            committee,
            epoch_id,
            packages_config,
            network_keys_receiver,
            next_epoch_committee_receiver,
            node_config.clone(),
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            dwallet_mpc_metrics,
        )
        .unwrap_or_else(|err| {
            error!(error=?err, "Failed to create DWalletMPCManager.");
            // We panic on purpose, this should not happen.
            panic!("DWalletMPCManager initialization failed: {err:?}");
        })
    }

    pub fn try_new(
        validator_name: AuthorityPublicKeyBytes,
        committee: Arc<Committee>,
        epoch_id: EpochId,
        packages_config: IkaNetworkConfig,
        network_keys_receiver: Receiver<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        next_epoch_committee_receiver: watch::Receiver<Committee>,
        node_config: NodeConfig,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    ) -> DwalletMPCResult<Self> {
        let root_seed = node_config
            .root_seed_key_pair
            .clone()
            .ok_or(DwalletMPCError::MissingRootSeed)?
            .root_seed()
            .clone();

        let access_structure = generate_access_structure_from_committee(&committee)?;

        let mpc_computations_orchestrator =
            CryptographicComputationsOrchestrator::try_new(root_seed.clone())?;
        let party_id = authority_name_to_party_id_from_committee(&committee, &validator_name)?;

        let class_groups_key_pair = ClassGroupsKeyPairAndProof::from_seed(&root_seed);

        let validator_private_data = ValidatorPrivateDecryptionKeyData {
            party_id,
            class_groups_decryption_key: class_groups_key_pair.decryption_key(),
            validator_decryption_key_shares: HashMap::new(),
        };
        let dwallet_network_keys = DwalletMPCNetworkKeys::new(validator_private_data);

        // Re-initialize the malicious handler every epoch. This is done intentionally:
        // We want to "forget" the malicious actors from the previous epoch and start from scratch.
        Ok(Self {
            mpc_sessions: HashMap::new(),
            party_id: authority_name_to_party_id_from_committee(&committee, &validator_name)?,
            epoch_id,
            packages_config,
            access_structure,
            validators_class_groups_public_keys_and_proofs:
                get_validators_class_groups_public_keys_and_proofs(&committee)?,
            cryptographic_computations_orchestrator: mpc_computations_orchestrator,
            malicious_actors: HashSet::new(),
            last_session_to_complete_in_current_epoch: 0,
            recognized_self_as_malicious: false,
            network_keys: Box::new(dwallet_network_keys),
            network_keys_receiver,
            next_epoch_committee_receiver,
            events_pending_for_next_active_committee: Vec::new(),
            events_pending_for_network_key: HashMap::new(),
            dwallet_mpc_metrics,
            next_active_committee: None,
            validator_name,
            committee,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
        })
    }

    pub(crate) fn sync_last_session_to_complete_in_current_epoch(
        &mut self,
        previous_value_for_last_session_to_complete_in_current_epoch: u64,
    ) {
        if previous_value_for_last_session_to_complete_in_current_epoch
            > self.last_session_to_complete_in_current_epoch
        {
            self.last_session_to_complete_in_current_epoch =
                previous_value_for_last_session_to_complete_in_current_epoch;
        }
    }

    /// Handle the messages of a given consensus round.
    pub fn handle_consensus_round_messages(
        &mut self,
        consensus_round: u64,
        messages: Vec<DWalletMPCMessage>,
    ) {
        for (_, session) in self.mpc_sessions.iter_mut() {
            if !session.messages_by_consensus_round.is_empty() {
                // Set the `messages_by_consensus_round` for every open MPC session for the current consensus round to an empty map.
                // This is important, as we count on the `messages_by_consensus_round` to hold entries for all consensus rounds since the session's inception,
                // when we check for delay.
                //
                // Do this only from the first received message, for synchronicity between validators.
                session
                    .messages_by_consensus_round
                    .insert(consensus_round, HashMap::new());
            }
        }

        for message in messages {
            self.handle_message(consensus_round, message);
        }
    }

    /// Handle the outputs of a given consensus round.
    pub fn handle_consensus_round_outputs(
        &mut self,
        consensus_round: u64,
        outputs: Vec<DWalletMPCOutput>,
    ) -> (Vec<DWalletCheckpointMessageKind>, Vec<SessionIdentifier>) {
        // Not let's move to process MPC outputs for the current round.
        let mut checkpoint_messages = vec![];
        let mut completed_sessions = vec![];
        for output in &outputs {
            let session_identifier = output.session_identifier;

            let output_result = self.handle_output(consensus_round, output.clone());
            match output_result {
                Some((malicious_authorities, output_result)) => {
                    self.complete_mpc_session(&session_identifier);
                    let output_digest = output_result.iter().map(|m| m.digest()).collect_vec();
                    checkpoint_messages.extend(output_result);
                    completed_sessions.push(session_identifier);
                    info!(
                        ?output_digest,
                        consensus_round,
                        ?session_identifier,
                        ?malicious_authorities,
                        "MPC output reached quorum"
                    );
                }
                None => {
                    debug!(
                        consensus_round,
                        ?session_identifier,
                        ?output,
                        "MPC output did not reach quorum"
                    );
                }
            };
        }

        (checkpoint_messages, completed_sessions)
    }

    /// Handles a message by forwarding it to the relevant MPC session.
    pub(crate) fn handle_message(&mut self, consensus_round: u64, message: DWalletMPCMessage) {
        let session_identifier = message.session_identifier;
        let sender_authority = message.authority;
        let Some(mpc_round_number) = (match message.message.first() {
            Some(0) => {
                let serialized_mpc_round_number = &message.message[1..=8];
                bcs::from_bytes::<u64>(serialized_mpc_round_number).ok()
            }
            Some(1) => {
                warn!(
                    session_identifier=?session_identifier,
                    sender_authority=?sender_authority,
                    receiver_authority=?self.validator_name,
                    serialized_message=?message.message,
                    "got a threshold not reached message, ignoring",
                );

                return;
            }
            _ => None,
        }) else {
            error!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                serialized_message=?message.message,
                "got a short message, ignoring",
            );

            return;
        };

        let Ok(sender_party_id) =
            authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
        else {
            error!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                mpc_round_number=?mpc_round_number,
                "got a message for an authority without party ID",
            );

            return;
        };

        info!(
            session_identifier=?session_identifier,
            sender_authority=?sender_authority,
            receiver_authority=?self.validator_name,
            mpc_round_number=?mpc_round_number,
            "Received an MPC message for session",
        );

        debug!(
            session_identifier=?session_identifier,
            sender_authority=?sender_authority,
            receiver_authority=?self.validator_name,
            mpc_round_number=?mpc_round_number,
            message_bytes=?message.message,
            "Received an MPC message for session with contents",
        );

        if self.is_malicious_actor(&sender_authority) {
            info!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                mpc_round_number=?mpc_round_number,
                "Ignoring message from malicious authority",
            );

            return;
        }

        let session = match self.mpc_sessions.entry(session_identifier) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(_) => {
                info!(
                    ?session_identifier,
                    sender_authority=?sender_authority,
                    receiver_authority=?self.validator_name,
                    mpc_round_number=?mpc_round_number,
                    "received a message for an MPC session before receiving an event requesting it"
                );

                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_mpc_session(&session_identifier, None);
                // Safe to `unwrap()`: we just created the session.
                self.mpc_sessions.get_mut(&session_identifier).unwrap()
            }
        };

        if session.status == MPCSessionStatus::Active {
            session.add_message(consensus_round, mpc_round_number, sender_party_id, message);
        }
    }

    /// Creates a new session with SID `session_identifier`,
    /// and insert it into the MPC session map `self.mpc_sessions`.
    pub(super) fn new_mpc_session(
        &mut self,
        session_identifier: &SessionIdentifier,
        mpc_event_data: Option<MPCEventData>,
    ) {
        info!(
            "Received start MPC flow event for session identifier {:?}",
            session_identifier
        );
        let with_mpc_event_data = mpc_event_data.is_some();

        let new_session = DWalletMPCSession::new(
            self.validator_name,
            MPCSessionStatus::Active,
            *session_identifier,
            self.party_id,
            mpc_event_data,
        );

        info!(
            party_id=self.party_id,
            authority=?self.validator_name,
            with_mpc_event_data,
            ?session_identifier,
            last_session_to_complete_in_current_epoch=?self.last_session_to_complete_in_current_epoch,
            "Adding a new MPC session to the active sessions map",
        );

        self.mpc_sessions.insert(*session_identifier, new_session);
    }

    /// Spawns all ready MPC cryptographic computations on separate threads using Rayon.
    /// If no local CPUs are available, computations will execute as CPUs are freed.
    ///
    /// A session must have its `mpc_event_data` set in order to be advanced.
    ///
    /// System sessions are always advanced if a CPU is free, user sessions are only advanced
    /// if they come before the last session to complete in the current epoch (at the current time).
    ///
    /// System sessions are always advanced before any user session,
    /// and both system and user sessions are ordered internally by their sequence numbers.
    ///
    /// The messages to advance with are built on the spot, assuming they satisfy required conditions.
    /// They are put on a `ComputationRequest` and forwarded to the `orchestrator` for execution.
    ///
    /// Returns the completed computation results.
    pub(crate) async fn perform_cryptographic_computation(
        &mut self,
    ) -> HashMap<ComputationId, DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>> {
        let mut ready_to_advance_sessions: Vec<_> = self
            .mpc_sessions
            .iter()
            .filter(|(_, session)| session.status == MPCSessionStatus::Active)
            .filter_map(|(_, session)| {
                // Only sessions with MPC event data should be advanced
                session.mpc_event_data.clone().and_then(|mpc_event_data| {
                    // Always advance system sessions, and only advance user session
                    // if they come before the last session to complete in the current epoch (at the current time).
                    let should_advance = match mpc_event_data.session_type {
                        SessionType::User => {
                            mpc_event_data.session_sequence_number
                                <= self.last_session_to_complete_in_current_epoch
                        }
                        SessionType::System => true,
                    };

                    if should_advance {
                        Some((session, mpc_event_data))
                    } else {
                        None
                    }
                })
            })
            .collect();

        ready_to_advance_sessions.sort_by(|(_, mpc_event_data), (_, other_mpc_event_data)| {
            mpc_event_data.cmp(other_mpc_event_data)
        });

        let computation_requests: Vec<_> = ready_to_advance_sessions
            .into_iter()
            .flat_map(|(session, mpc_event_data)| {
                let rounds_to_delay = self.consensus_rounds_delay_for_mpc_round(
                    session.current_mpc_round,
                    &mpc_event_data,
                );

                build_messages_to_advance(
                    session.current_mpc_round,
                    rounds_to_delay,
                    session
                        .mpc_round_to_threshold_not_reached_consensus_rounds
                        .clone(),
                    session.messages_by_consensus_round.clone(),
                    &self.access_structure,
                )
                .map(|(consensus_round, messages_for_advance)| {
                    let attempt_number = session.get_attempt_number();

                    // Safe to `unwrap()`, as the session is ready to advance so `mpc_event_data` must be `Some()`.
                    let mpc_event_data = session.mpc_event_data.clone().unwrap();

                    let computation_id = ComputationId {
                        session_identifier: session.session_identifier,
                        consensus_round,
                        mpc_round: session.current_mpc_round,
                        attempt_number,
                    };

                    let computation_request = ComputationRequest {
                        party_id: self.party_id,
                        validator_name: self.validator_name,
                        committee: self.committee.clone(),
                        access_structure: self.access_structure.clone(),
                        request_input: mpc_event_data.request_input,
                        private_input: mpc_event_data.private_input,
                        public_input: mpc_event_data.public_input,
                        decryption_key_shares: mpc_event_data.decryption_key_shares,
                        messages: messages_for_advance,
                    };

                    (computation_id, computation_request)
                })
            })
            .collect();

        let completed_computation_results = self
            .cryptographic_computations_orchestrator
            .receive_completed_computations(self.dwallet_mpc_metrics.clone());
        for (computation_id, computation_request) in computation_requests {
            let computation_executing = self
                .cryptographic_computations_orchestrator
                .try_spawn_cryptographic_computation(
                    computation_id,
                    computation_request,
                    self.dwallet_mpc_metrics.clone(),
                )
                .await;

            if !computation_executing {
                return completed_computation_results;
            }
        }

        completed_computation_results
    }

    pub(crate) fn try_receiving_next_active_committee(&mut self) -> bool {
        match self.next_epoch_committee_receiver.has_changed() {
            Ok(has_changed) => {
                if has_changed {
                    let committee = self
                        .next_epoch_committee_receiver
                        .borrow_and_update()
                        .clone();

                    if committee.epoch == self.epoch_id + 1 {
                        self.next_active_committee = Some(committee);

                        return true;
                    }
                }
            }
            Err(err) => {
                error!(error=?err, "failed to check next epoch committee receiver");
            }
        }

        false
    }

    pub(crate) async fn maybe_update_network_keys(&mut self) -> Vec<ObjectID> {
        match self.network_keys_receiver.has_changed() {
            Ok(has_changed) => {
                if has_changed {
                    let new_keys = self.borrow_and_update_network_keys();

                    let mut results = vec![];
                    for (key_id, key_data) in new_keys {
                        let res = instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
                            key_data.current_epoch,
                            DWalletMPCNetworkKeyScheme::Secp256k1,
                            self.access_structure.clone(),
                            key_data,
                        ).await;

                        results.push((key_id, res))
                    }

                    let mut new_key_ids = vec![];
                    for (key_id, res) in results {
                        match res {
                            Ok(key) => {
                                info!(key_id=?key_id, "Updating (decrypting new shares) network key for key_id");
                                if let Err(e) = self
                                    .network_keys
                                    .update_network_key(key_id, &key, &self.access_structure)
                                    .await
                                {
                                    error!(error=?e, key_id=?key_id, "failed to update the network key");
                                } else {
                                    new_key_ids.push(key_id);
                                }
                            }
                            Err(err) => {
                                error!(
                                    error=?err,
                                    key_id=?key_id,
                                    "failed to instantiate network decryption key shares from public output for"
                                );
                            }
                        }
                    }

                    new_key_ids
                } else {
                    vec![]
                }
            }
            Err(err) => {
                error!(error=?err, "failed to check network keys receiver");

                vec![]
            }
        }
    }

    // This has to be a function to solve compilation errors with async.
    fn borrow_and_update_network_keys(
        &mut self,
    ) -> HashMap<ObjectID, DWalletNetworkEncryptionKeyData> {
        let new_keys = self.network_keys_receiver.borrow_and_update();

        new_keys
            .iter()
            .map(|(&key_id, key_data)| (key_id, key_data.clone()))
            .collect()
    }

    pub(crate) fn handle_output(
        &mut self,
        consensus_round: u64,
        output: DWalletMPCOutput,
    ) -> Option<(HashSet<AuthorityName>, Vec<DWalletCheckpointMessageKind>)> {
        let session_identifier = output.session_identifier;
        let sender_authority = output.authority;

        let Ok(sender_party_id) =
            authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
        else {
            error!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                "got a output for an authority without party ID",
            );

            return None;
        };

        let session = match self.mpc_sessions.entry(session_identifier) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(_) => {
                info!(
                    ?session_identifier,
                    sender_authority=?sender_authority,
                    receiver_authority=?self.validator_name,
                    "received a output for an MPC session before receiving an event requesting it"
                );

                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_mpc_session(&session_identifier, None);
                // Safe to `unwrap()`: we just created the session.
                self.mpc_sessions.get_mut(&session_identifier).unwrap()
            }
        };

        session.add_output(consensus_round, sender_party_id, output);

        let outputs_by_consensus_round = session.outputs_by_consensus_round().clone();

        let built_outputs_to_finalize =
            self.build_outputs_to_finalize(&session_identifier, outputs_by_consensus_round);

        match built_outputs_to_finalize {
            Some((malicious_authorities, majority_vote)) => {
                self.malicious_actors.extend(malicious_authorities.clone());

                Some((malicious_authorities, majority_vote))
            }
            None => None,
        }
    }

    pub(crate) fn record_threshold_not_reached(
        &mut self,
        consensus_round: u64,
        session_identifier: SessionIdentifier,
    ) {
        if let Some(session) = self.mpc_sessions.get_mut(&session_identifier) {
            session.record_threshold_not_reached(consensus_round)
        }
    }

    pub(crate) fn is_malicious_actor(&self, authority: &AuthorityName) -> bool {
        self.malicious_actors.contains(authority)
    }

    /// Records malicious actors that were identified as part of the execution of an MPC session.
    pub(crate) fn record_malicious_actors(&mut self, authorities: &[AuthorityName]) {
        self.malicious_actors.extend(authorities);

        if self.is_malicious_actor(&self.validator_name) {
            self.recognized_self_as_malicious = true;

            error!(
                authority=?self.validator_name,
                "node recognized itself as malicious"
            );
        }
    }

    /// Returns the number of additional (delay) consensus rounds the session should wait for before advancing.
    ///
    /// This method returns the protocol-specific delay for certain MPC rounds in specific protocols
    /// (NetworkDkg, DecryptionKeyReconfiguration).
    ///
    /// - **NetworkDkg protocol**: requires delay for the third round
    ///   using `network_dkg_third_round_delay` config.
    /// - **DecryptionKeyReconfiguration protocol**: requires delay for the third round
    ///   using `decryption_key_reconfiguration_third_round_delay` config.
    /// - **Other protocols**: No delay required, always ready to advance
    pub(crate) fn consensus_rounds_delay_for_mpc_round(
        &self,
        current_mpc_round: u64,
        mpc_event_data: &MPCEventData,
    ) -> u64 {
        match mpc_event_data.request_input {
            MPCRequestInput::NetworkEncryptionKeyDkg(_, _) if current_mpc_round == 3 => {
                self.network_dkg_third_round_delay
            }
            MPCRequestInput::NetworkEncryptionKeyReconfiguration(_) if current_mpc_round == 3 => {
                self.decryption_key_reconfiguration_third_round_delay
            }
            _ => 0,
        }
    }

    /// Builds the outputs to finalize based on the outputs received in the consensus rounds.
    /// If a majority vote is reached, it returns the malicious voters (didn't vote with majority) and the majority vote.
    /// If the threshold is not reached, it returns `None`.
    pub(crate) fn build_outputs_to_finalize(
        &self,
        session_identifier: &SessionIdentifier,
        outputs_by_consensus_round: HashMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
    ) -> Option<(HashSet<AuthorityName>, Vec<DWalletCheckpointMessageKind>)> {
        let mut outputs_to_finalize: HashMap<PartyID, DWalletMPCSessionOutput> = HashMap::new();

        for (_, outputs) in outputs_by_consensus_round {
            for (sender_party_id, output) in outputs {
                // take the last output from each sender party ID
                outputs_to_finalize.insert(sender_party_id, output);
            }
        }

        match outputs_to_finalize.weighted_majority_vote(&self.access_structure) {
            Ok((malicious_voters, majority_vote)) => {
                let output = majority_vote.output;
                let malicious_authorities_options = malicious_voters
                    .iter()
                    .map(|party_id| party_id_to_authority_name(*party_id, &self.committee))
                    .collect_vec();
                let any_not_found_malicious_voters =
                    malicious_authorities_options.iter().any(|ma| ma.is_none());
                let malicious_authorities: HashSet<AuthorityName> = malicious_authorities_options
                    .into_iter()
                    .flatten()
                    .collect();
                if any_not_found_malicious_voters {
                    error!(
                        ?session_identifier,
                        ?malicious_voters,
                        ?malicious_authorities,
                        committee=?self.committee,
                        "Failed to convert some malicious party IDs to authority names"
                    );
                }
                let malicious_authorities: HashSet<AuthorityName> = malicious_authorities
                    .into_iter()
                    .chain(majority_vote.malicious_authorities)
                    .collect();
                Some((malicious_authorities, output))
            }
            Err(mpc::Error::ThresholdNotReached) => None,
            Err(e) => {
                error!(
                    ?session_identifier,
                    "Failed to build outputs to finalize: {e}"
                );
                None
            }
        }
    }

    pub(crate) fn complete_mpc_session(&mut self, session_identifier: &SessionIdentifier) {
        if let Some(session) = self.mpc_sessions.get_mut(session_identifier) {
            session.mark_mpc_session_as_completed();
            if let Some(mpc_event_data) = session.mpc_event_data() {
                self.dwallet_mpc_metrics
                    .add_completion(&mpc_event_data.request_input);
            }
            session.clear_data();
        }
    }

    pub(crate) fn complete_computation_mpc_session_and_create_if_not_exists(
        &mut self,
        session_identifier: &SessionIdentifier,
    ) {
        let session = match self.mpc_sessions.entry(*session_identifier) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(_) => {
                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_mpc_session(session_identifier, None);
                // Safe to `unwrap()`: we just created the session.
                self.mpc_sessions.get_mut(session_identifier).unwrap()
            }
        };

        session.mark_mpc_session_as_computation_completed();
    }
}
