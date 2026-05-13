// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::{
    ComputationId, ComputationRequest, CryptographicComputationsOrchestrator,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_session::{
    DWalletMPCSessionOutput, DWalletSession, SessionComputationType, SessionStatus,
};
use crate::dwallet_mpc::network_dkg::instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, ValidatorPrivateDecryptionKeyData};
use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
    get_validators_class_groups_public_keys_and_proofs, party_id_to_authority_name,
};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::{SuiDataReceivers, debug_variable_chunks};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    DWalletMPCMessage, DWalletMPCOutput, DWalletNetworkEncryptionKeyData, SessionIdentifier,
    SessionType,
};
use itertools::Itertools;
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use sui_types::base_types::ConciseableName;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::{debug, error, info, warn};

use crate::dwallet_mpc::dwallet_mpc_metrics::{
    AGE_BUCKETS, AGE_BUCKET_OVERFLOW, SESSION_STATE_ACTIVE, SESSION_STATE_COMPLETED,
    SESSION_STATE_COMPUTATION_COMPLETED, SESSION_STATE_FAILED, SESSION_STATE_WAITING_FOR_REQUEST,
    SESSION_TYPE_SYSTEM, SESSION_TYPE_USER,
};

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
    /// A map of all sessions that start execution in this epoch.
    /// These include completed sessions, and they are never to be removed from this
    /// mapping until the epoch advances.
    pub(crate) sessions: HashMap<SessionIdentifier, DWalletSession>,
    pub(crate) epoch_id: EpochId,
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
    /// Events that wait for the network key to update.
    /// Once we get the network key, these events will be executed.
    pub(crate) requests_pending_for_network_key: HashMap<ObjectID, Vec<DWalletSessionRequest>>,
    pub(crate) requests_pending_for_next_active_committee: Vec<DWalletSessionRequest>,
    pub(crate) next_active_committee: Option<Committee>,
    pub(crate) dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,

    pub(crate) network_dkg_third_round_delay: u64,
    pub(crate) decryption_key_reconfiguration_third_round_delay: u64,
    sui_data_receivers: SuiDataReceivers,
    pub(crate) protocol_config: ProtocolConfig,

    /// User-session sequence numbers that were last emitted to
    /// `dwallet_mpc_user_session_state`. Used to zero out series for sessions that have left
    /// `self.sessions` (e.g. after epoch advance) so dashboards don't read stale "this
    /// session is still in state X" forever.
    previously_emitted_user_session_seqs: HashSet<u64>,
}

impl DWalletMPCManager {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        committee: Arc<Committee>,
        epoch_id: EpochId,
        root_seed: RootSeed,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        sui_data_receivers: SuiDataReceivers,
        protocol_config: ProtocolConfig,
    ) -> Self {
        Self::try_new(
            validator_name,
            committee,
            epoch_id,
            root_seed,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            dwallet_mpc_metrics,
            sui_data_receivers,
            protocol_config,
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
        root_seed: RootSeed,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        sui_data_receivers: SuiDataReceivers,
        protocol_config: ProtocolConfig,
    ) -> DwalletMPCResult<Self> {
        let access_structure = generate_access_structure_from_committee(&committee)?;

        let mpc_computations_orchestrator =
            CryptographicComputationsOrchestrator::try_new(root_seed.clone())?;
        let party_id = authority_name_to_party_id_from_committee(&committee, &validator_name)?;

        let class_groups_key_pair_and_proof = ClassGroupsKeyPairAndProof::from_seed(&root_seed);

        let validator_private_data = ValidatorPrivateDecryptionKeyData {
            party_id,
            class_groups_decryption_key: class_groups_key_pair_and_proof.decryption_key(),
            validator_decryption_key_shares: HashMap::new(),
        };
        let dwallet_network_keys = DwalletMPCNetworkKeys::new(validator_private_data);

        // Re-initialize the malicious handler every epoch. This is done intentionally:
        // We want to "forget" the malicious actors from the previous epoch and start from scratch.
        Ok(Self {
            sessions: HashMap::new(),
            party_id: authority_name_to_party_id_from_committee(&committee, &validator_name)?,
            epoch_id,
            access_structure,
            validators_class_groups_public_keys_and_proofs:
                get_validators_class_groups_public_keys_and_proofs(&committee)?,
            cryptographic_computations_orchestrator: mpc_computations_orchestrator,
            malicious_actors: HashSet::new(),
            last_session_to_complete_in_current_epoch: 0,
            recognized_self_as_malicious: false,
            network_keys: Box::new(dwallet_network_keys),
            sui_data_receivers,
            requests_pending_for_next_active_committee: Vec::new(),
            requests_pending_for_network_key: HashMap::new(),
            dwallet_mpc_metrics,
            next_active_committee: None,
            validator_name,
            committee,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            protocol_config,
            previously_emitted_user_session_seqs: HashSet::new(),
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
                    // Stamp the quorum round on the session *before* `complete_mpc_session`
                    // clears its data — first-write-wins so retries don't overwrite the
                    // original quorum point. This feeds the
                    // `dwallet_mpc_user_session_quorum_consensus_round` per-seq gauge.
                    if let Some(session) = self.sessions.get_mut(&session_identifier) {
                        let was_already_recorded = session.quorum_consensus_round.is_some();
                        session.quorum_consensus_round.get_or_insert(consensus_round);
                        // Observe self → quorum latency only on the first transition, and only
                        // for sessions where we submitted our own output (otherwise the
                        // latency is meaningless from this node's perspective).
                        if !was_already_recorded {
                            if let Some(self_round) = session.self_output_consensus_round {
                                let delta = consensus_round.saturating_sub(self_round);
                                self.dwallet_mpc_metrics
                                    .self_output_to_quorum_consensus_rounds
                                    .observe(delta as f64);
                            }
                        }
                    }
                    self.complete_mpc_session(&session_identifier);
                    let output_digest = output_result.iter().map(|m| m.digest()).collect_vec();
                    checkpoint_messages.extend(output_result);
                    completed_sessions.push(session_identifier);
                    info!(
                        ?output_digest,
                        consensus_round,
                        ?session_identifier,
                        ?malicious_authorities,
                        rejected = output.rejected(),
                        "MPC output reached quorum"
                    );
                }
                None => {
                    debug!(
                        consensus_round,
                        ?session_identifier,
                        ?output,
                        rejected = output.rejected(),
                        "MPC output yet to reach quorum"
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

        let Ok(sender_party_id) =
            authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
        else {
            error!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                consensus_round=?consensus_round,
                "got a message for an authority without party ID",
            );

            return;
        };
        let mut message_hasher = DefaultHash::default();
        message_hasher.update(&message.message);
        info!(
            session_identifier=?session_identifier,
            sender_authority=?sender_authority,
            receiver_authority=?self.validator_name,
            consensus_round=?consensus_round,
            message_hash=?message_hasher.finalize().digest,
            "Received an MPC message for session",
        );

        if self.is_malicious_actor(&sender_authority) {
            info!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                consensus_round=?consensus_round,
                "Ignoring message from malicious authority",
            );

            return;
        }

        let session = match self.sessions.entry(session_identifier) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(_) => {
                info!(
                    ?session_identifier,
                    sender_authority=?sender_authority,
                    receiver_authority=?self.validator_name,
                    consensus_round=?consensus_round,
                    "received a message for an MPC session before receiving an event requesting it"
                );

                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_session(
                    &session_identifier,
                    SessionStatus::WaitingForSessionRequest,
                    // only MPC sessions have messages.
                    SessionComputationType::MPC {
                        messages_by_consensus_round: HashMap::new(),
                    },
                );
                // Safe to `unwrap()`: we just created the session.
                self.sessions.get_mut(&session_identifier).unwrap()
            }
        };

        session.add_message(consensus_round, sender_party_id, message);
    }

    /// Creates a new session with SID `session_identifier`,
    /// and insert it into the MPC session map `self.mpc_sessions`.
    pub(super) fn new_session(
        &mut self,
        session_identifier: &SessionIdentifier,
        status: SessionStatus,
        session_type: SessionComputationType,
    ) {
        info!(
            status=?status,
            "Received start MPC flow request for session identifier {:?}",
            session_identifier,
        );
        let active = matches!(status, SessionStatus::Active { .. });

        let new_session = DWalletSession::new(
            self.validator_name,
            status,
            *session_identifier,
            self.party_id,
            session_type,
        );

        info!(
            party_id=self.party_id,
            authority=?self.validator_name,
            active,
            ?session_identifier,
            last_session_to_complete_in_current_epoch=?self.last_session_to_complete_in_current_epoch,
            "Adding a new MPC session to the active sessions map",
        );

        self.sessions.insert(*session_identifier, new_session);
    }

    /// Spawns all ready MPC cryptographic computations on separate threads using Rayon.
    /// If no local CPUs are available, computations will execute as CPUs are freed.
    ///
    /// A session must have its `request_data` set in order to be advanced.
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
        last_read_consensus_round: u64,
    ) -> HashMap<ComputationId, DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>> {
        let mut ready_to_advance_sessions: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(_, session)| {
                let SessionStatus::Active { request, .. } = &session.status else {
                    return None;
                };

                // Always advance system sessions, and only advance user session
                // if they come before the last session to complete in the current epoch (at the current time).
                let should_advance = match request.session_type {
                    SessionType::User => {
                        request.session_sequence_number
                            <= self.last_session_to_complete_in_current_epoch
                    }
                    SessionType::System => true,
                };

                if should_advance {
                    Some((session, request))
                } else {
                    None
                }
            })
            .collect();

        ready_to_advance_sessions
            .sort_by(|(_, request), (_, other_request)| request.cmp(other_request));

        let computation_requests: Vec<_> = ready_to_advance_sessions
            .into_iter()
            .flat_map(|(session, _)| {
                let SessionStatus::Active {
                    public_input,
                    private_input: _,
                    request,
                } = &session.status
                else {
                    error!(
                        should_never_happen=true,
                        session_identifier=?session.session_identifier,
                        "session is not active, cannot perform cryptographic computation",
                    );

                    return None;
                };

                let protocol_data_result = self.generate_protocol_cryptographic_data(
                    &session.computation_type,
                    &request.protocol_data,
                    last_read_consensus_round,
                    public_input.clone(),
                    &self.protocol_config,
                );
                let protocol_cryptographic_data_opt = match protocol_data_result {
                    Ok(opt) => opt,
                    Err(err) => {
                        // Previously a silent `.ok()?` — that's how a stuck session can sit
                        // in `self.sessions` indefinitely with neither an Advance nor a Reject
                        // ever being submitted. Emit a warn + counter so this is visible.
                        let protocol_metric_data = crate::dwallet_session_request::DWalletSessionRequestMetricData::from(
                            &request.protocol_data,
                        );
                        let protocol_name = protocol_metric_data.name();
                        self.dwallet_mpc_metrics
                            .protocol_data_generation_errors_total
                            .with_label_values(&[protocol_name, err.kind()])
                            .inc();
                        warn!(
                            session_identifier = ?session.session_identifier,
                            session_sequence_number = request.session_sequence_number,
                            session_type = ?request.session_type,
                            protocol_name,
                            error = ?err,
                            error_kind = err.kind(),
                            "generate_protocol_cryptographic_data failed; session will be retried silently next tick"
                        );
                        return None;
                    }
                };
                protocol_cryptographic_data_opt
                .map(|protocol_cryptographic_data| {
                    let attempt_number = protocol_cryptographic_data.get_attempt_number();
                    let mpc_round = protocol_cryptographic_data.get_mpc_round();

                    let computation_id = ComputationId {
                        session_identifier: session.session_identifier,
                        consensus_round: last_read_consensus_round,
                        mpc_round,
                        attempt_number,
                    };

                    let computation_request = ComputationRequest {
                        party_id: self.party_id,
                        protocol_data: (&request.protocol_data).into(),
                        validator_name: self.validator_name,
                        access_structure: self.access_structure.clone(),
                        protocol_cryptographic_data,
                    };

                    (computation_id, computation_request)
                })
            })
            .collect();

        let completed_computation_results = self
            .cryptographic_computations_orchestrator
            .receive_completed_computations(self.dwallet_mpc_metrics.clone());
        for (computation_id, computation_request) in computation_requests {
            let spawned_computation = self
                .cryptographic_computations_orchestrator
                .try_spawn_cryptographic_computation(
                    computation_id,
                    computation_request,
                    self.dwallet_mpc_metrics.clone(),
                )
                .await;

            if !spawned_computation {
                return completed_computation_results;
            }
        }

        completed_computation_results
    }

    pub(crate) fn try_receiving_next_active_committee(&mut self) -> bool {
        match self
            .sui_data_receivers
            .next_epoch_committee_receiver
            .has_changed()
        {
            Ok(has_changed) => {
                if has_changed {
                    let committee = self
                        .sui_data_receivers
                        .next_epoch_committee_receiver
                        .borrow_and_update()
                        .clone();

                    debug!(
                        committee=?committee,
                        "Received next (upcoming) active committee"
                    );

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
        match self.sui_data_receivers.network_keys_receiver.has_changed() {
            Ok(has_changed) => {
                if has_changed {
                    let new_keys = self.borrow_and_update_network_keys();

                    let mut results = vec![];
                    for (key_id, key_data) in new_keys {
                        info!(key_id=?key_id, "Instantiating network key");
                        if let Ok(key_data_bcs) = bcs::to_bytes(&key_data) {
                            debug_variable_chunks(
                                format!("Instantiating network key {:?}", key_id).as_str(),
                                "key_data",
                                &key_data_bcs,
                            );
                        }

                        let res = instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
                            key_data.current_epoch,
                            self.access_structure.clone(),
                            key_data,
                        ).await;

                        results.push((key_id, res))
                    }

                    let mut new_key_ids = vec![];
                    for (key_id, res) in results {
                        match res {
                            Ok(key) => {
                                if key.epoch() != self.epoch_id {
                                    info!(
                                        key_id=?key_id,
                                        epoch=?key.epoch(),
                                        "Network key epoch does not match current epoch, ignoring"
                                    );

                                    continue;
                                }
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
        let new_keys = self
            .sui_data_receivers
            .network_keys_receiver
            .borrow_and_update();

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

        let session = match self.sessions.entry(session_identifier) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(_) => {
                info!(
                    ?session_identifier,
                    sender_authority=?sender_authority,
                    receiver_authority=?self.validator_name,
                    "received a output for an MPC session before receiving an event requesting it"
                );

                // All output kinds are constructed from the same type, so we can safely use the first one.
                let Ok(session_computation_type) = SessionComputationType::try_from(
                    output.output.first().expect("output must have a kind"),
                ) else {
                    error!(
                        session_identifier=?session_identifier,
                        sender_authority=?sender_authority,
                        receiver_authority=?self.validator_name,
                        "got a output for an invalid computation type",
                    );

                    return None;
                };

                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_session(
                    &session_identifier,
                    SessionStatus::WaitingForSessionRequest,
                    session_computation_type.clone(),
                );
                // Safe to `unwrap()`: we just created the session.
                self.sessions.get_mut(&session_identifier).unwrap()
            }
        };

        session.add_output(consensus_round, sender_party_id, output);

        let outputs_by_consensus_round = session.outputs_by_consensus_round().clone();

        match self.build_outputs_to_finalize(&session_identifier, outputs_by_consensus_round) {
            Some((malicious_authorities, majority_vote)) => {
                self.record_malicious_actors(&malicious_authorities);

                Some((malicious_authorities, majority_vote))
            }
            None => None,
        }
    }

    pub(crate) fn is_malicious_actor(&self, authority: &AuthorityName) -> bool {
        self.malicious_actors.contains(authority)
    }

    /// Records malicious actors that were identified as part of the execution of an MPC session.
    pub(crate) fn record_malicious_actors(&mut self, authorities: &HashSet<AuthorityName>) {
        if !authorities.is_empty() {
            self.malicious_actors.extend(authorities);

            if self.is_malicious_actor(&self.validator_name) {
                self.recognized_self_as_malicious = true;

                error!(
                    authority=?self.validator_name,
                    "node recognized itself as malicious"
                );
            }

            error!(
                authority=?self.validator_name,
                malicious_authorities =? authorities,
                malicious_actors_size = self.malicious_actors.len(),
                "malicious actors identified & recorded"
            );
            self.dwallet_mpc_metrics
                .malicious_actors_size
                .set(self.malicious_actors.len() as i64);
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
                let malicious_authorities = malicious_voters
                    .iter()
                    .flat_map(|party_id| party_id_to_authority_name(*party_id, &self.committee))
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
        if let Some(session) = self.sessions.get_mut(session_identifier) {
            if let Some(request_data) = session.request_metric_data() {
                self.dwallet_mpc_metrics.add_completion(&request_data);
            }
            session.mark_mpc_session_as_completed();
            session.clear_data();
        }
    }

    pub(crate) fn complete_computation_mpc_session_and_create_if_not_exists(
        &mut self,
        session_identifier: &SessionIdentifier,
        session_type: SessionComputationType,
        session_sequence_number: Option<u64>,
        on_chain_session_type: Option<ika_types::messages_dwallet_mpc::SessionType>,
    ) {
        match self.sessions.entry(*session_identifier) {
            Entry::Occupied(session) => {
                let session = session.into_mut();
                session.mark_mpc_session_as_computation_completed();
                if let (Some(seq), Some(ty)) = (session_sequence_number, on_chain_session_type) {
                    session.set_request_metadata(seq, ty);
                }
            }
            Entry::Vacant(_) => {
                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_session(
                    session_identifier,
                    SessionStatus::ComputationCompleted,
                    session_type,
                );
                if let (Some(seq), Some(ty)) = (session_sequence_number, on_chain_session_type) {
                    if let Some(session) = self.sessions.get_mut(session_identifier) {
                        session.set_request_metadata(seq, ty);
                    }
                }
            }
        };
    }

    /// Refresh the gauges that summarize the in-memory `sessions` map and the parking lots.
    /// Cheap (O(sessions) per call) and idempotent; intended to be called once per service tick.
    /// We deliberately re-emit zeros for every label so a previously-non-zero gauge for an
    /// age bucket / state / network key clears out when nothing falls in that bucket anymore.
    pub(crate) fn refresh_observability_metrics(&mut self) {
        let m = &self.dwallet_mpc_metrics;
        let now = std::time::Instant::now();

        // ----- active sessions by (session_type, age_bucket) -----
        let mut user_counts = vec![0i64; AGE_BUCKETS.len() + 1];
        let mut system_counts = vec![0i64; AGE_BUCKETS.len() + 1];
        // ----- session state counts -----
        let mut state_active = 0i64;
        let mut state_waiting = 0i64;
        let mut state_comp_completed = 0i64;
        let mut state_completed = 0i64;
        let mut state_failed = 0i64;

        for session in self.sessions.values() {
            // For age, only Active sessions are meaningful — Completed/Failed sessions are
            // tracked separately and don't represent in-flight work.
            match &session.status {
                SessionStatus::Active { request, .. } => {
                    state_active += 1;
                    let age = now.saturating_duration_since(session.created_at);
                    let counts = match request.session_type {
                        SessionType::User => &mut user_counts,
                        SessionType::System => &mut system_counts,
                    };
                    let mut placed = false;
                    for (idx, (_, threshold)) in AGE_BUCKETS.iter().enumerate() {
                        if age < *threshold {
                            counts[idx] += 1;
                            placed = true;
                            break;
                        }
                    }
                    if !placed {
                        counts[AGE_BUCKETS.len()] += 1;
                    }
                }
                SessionStatus::WaitingForSessionRequest => state_waiting += 1,
                SessionStatus::ComputationCompleted => state_comp_completed += 1,
                SessionStatus::Completed => state_completed += 1,
                SessionStatus::Failed => state_failed += 1,
            }
        }

        // Emit per (session_type, age_bucket). We emit a 0 explicitly for empty buckets so a
        // stale "1" from a previous tick doesn't linger.
        for (idx, (bucket_label, _)) in AGE_BUCKETS.iter().enumerate() {
            m.active_sessions_by_age
                .with_label_values(&[SESSION_TYPE_USER, bucket_label])
                .set(user_counts[idx]);
            m.active_sessions_by_age
                .with_label_values(&[SESSION_TYPE_SYSTEM, bucket_label])
                .set(system_counts[idx]);
        }
        m.active_sessions_by_age
            .with_label_values(&[SESSION_TYPE_USER, AGE_BUCKET_OVERFLOW])
            .set(user_counts[AGE_BUCKETS.len()]);
        m.active_sessions_by_age
            .with_label_values(&[SESSION_TYPE_SYSTEM, AGE_BUCKET_OVERFLOW])
            .set(system_counts[AGE_BUCKETS.len()]);

        m.session_state_count
            .with_label_values(&[SESSION_STATE_ACTIVE])
            .set(state_active);
        m.session_state_count
            .with_label_values(&[SESSION_STATE_WAITING_FOR_REQUEST])
            .set(state_waiting);
        m.session_state_count
            .with_label_values(&[SESSION_STATE_COMPUTATION_COMPLETED])
            .set(state_comp_completed);
        m.session_state_count
            .with_label_values(&[SESSION_STATE_COMPLETED])
            .set(state_completed);
        m.session_state_count
            .with_label_values(&[SESSION_STATE_FAILED])
            .set(state_failed);

        // ----- parking lots -----
        for (key_id, requests) in &self.requests_pending_for_network_key {
            m.requests_pending_for_network_key
                .with_label_values(&[&key_id.to_string()])
                .set(requests.len() as i64);
        }
        m.requests_pending_for_next_active_committee
            .set(self.requests_pending_for_next_active_committee.len() as i64);

        // Keep malicious_actors_size fresh in case the only update path
        // (record_malicious_actors) hasn't fired this epoch.
        m.malicious_actors_size
            .set(self.malicious_actors.len() as i64);

        // Per-network-encryption-key loaded-epoch. Drift between this and `epoch_id` is the
        // silent-skip cause in `mpc_manager.rs:527` ("Network key epoch does not match
        // current epoch, ignoring"). Operators can alert on:
        //   abs(dwallet_mpc_network_key_loaded_epoch - <current epoch>) > 0
        for (key_id, data) in self.network_keys.network_encryption_keys.iter() {
            m.network_key_loaded_epoch
                .with_label_values(&[&key_id.to_string()])
                .set(data.epoch() as i64);
        }

        // ----- per-user-session state, labeled by sequence number -----
        // For every user session this validator is tracking, emit five series
        // (one per state) where exactly one is 1. For sessions that have left
        // `self.sessions` since the last tick, emit one final round of zeros so
        // dashboards don't read a stale "1" forever.
        const ALL_STATES: &[&str] = &[
            SESSION_STATE_ACTIVE,
            SESSION_STATE_WAITING_FOR_REQUEST,
            SESSION_STATE_COMPUTATION_COMPLETED,
            SESSION_STATE_COMPLETED,
            SESSION_STATE_FAILED,
        ];
        let mut current_seqs: HashSet<u64> = HashSet::new();
        let mut sessions_with_self_output_no_quorum: i64 = 0;
        for session in self.sessions.values() {
            let (Some(seq), Some(ty)) =
                (session.session_sequence_number, session.session_type)
            else {
                // Session entry exists but hasn't seen a request yet — we can't label it
                // by sequence number. It will be exposed once its request arrives.
                continue;
            };
            if !matches!(ty, ika_types::messages_dwallet_mpc::SessionType::User) {
                continue;
            }
            let current_state = match &session.status {
                SessionStatus::Active { .. } => SESSION_STATE_ACTIVE,
                SessionStatus::WaitingForSessionRequest => SESSION_STATE_WAITING_FOR_REQUEST,
                SessionStatus::ComputationCompleted => SESSION_STATE_COMPUTATION_COMPLETED,
                SessionStatus::Completed => SESSION_STATE_COMPLETED,
                SessionStatus::Failed => SESSION_STATE_FAILED,
            };
            let seq_str = seq.to_string();
            for state in ALL_STATES {
                let value = if *state == current_state { 1 } else { 0 };
                m.user_session_state
                    .with_label_values(&[seq_str.as_str(), state])
                    .set(value);
            }

            // Per-session timing gauges — emit as i64 with -1 as the "not set" sentinel.
            let first_output = session
                .first_output_consensus_round
                .map(|v| v as i64)
                .unwrap_or(-1);
            let self_output = session
                .self_output_consensus_round
                .map(|v| v as i64)
                .unwrap_or(-1);
            let quorum_round = session
                .quorum_consensus_round
                .map(|v| v as i64)
                .unwrap_or(-1);
            let rejected_int = match session.local_output_rejected {
                None => -1,
                Some(false) => 0,
                Some(true) => 1,
            };
            m.user_session_first_output_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(first_output);
            m.user_session_self_output_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(self_output);
            m.user_session_quorum_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(quorum_round);
            m.user_session_distinct_output_authorities
                .with_label_values(&[seq_str.as_str()])
                .set(session.distinct_output_authorities.len() as i64);
            m.user_session_local_output_rejected
                .with_label_values(&[seq_str.as_str()])
                .set(rejected_int);
            m.user_session_distinct_output_digests
                .with_label_values(&[seq_str.as_str()])
                .set(session.distinct_output_digests.len() as i64);

            // Per (session, authority) gauge — 1 if we received an output from this authority
            // for this session in our current process lifetime, 0 otherwise. Iterates the
            // *entire* committee so "missing submitters" can be queried directly.
            for authority_name in self.committee.names() {
                let received = session
                    .distinct_output_authorities
                    .contains(authority_name);
                let authority_label = authority_name.concise().to_string();
                m.user_session_output_received_from
                    .with_label_values(&[seq_str.as_str(), authority_label.as_str()])
                    .set(if received { 1 } else { 0 });
            }

            // "Submitted but no quorum" aggregate — counts sessions where we did our part
            // and have not seen quorum during this process. The single most useful gauge
            // for "are we stuck waiting on quorum from peers".
            if session.self_output_consensus_round.is_some()
                && session.quorum_consensus_round.is_none()
            {
                sessions_with_self_output_no_quorum += 1;
            }

            current_seqs.insert(seq);
        }
        m.sessions_with_self_output_no_quorum
            .set(sessions_with_self_output_no_quorum);

        // Sessions that disappeared from `self.sessions` between this tick and the previous
        // — flip the state series to zero and the timing gauges to -1 so dashboards
        // reflect "no longer tracked here".
        for stale_seq in self
            .previously_emitted_user_session_seqs
            .difference(&current_seqs)
            .copied()
            .collect::<Vec<_>>()
        {
            let seq_str = stale_seq.to_string();
            for state in ALL_STATES {
                m.user_session_state
                    .with_label_values(&[seq_str.as_str(), state])
                    .set(0);
            }
            m.user_session_first_output_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(-1);
            m.user_session_self_output_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(-1);
            m.user_session_quorum_consensus_round
                .with_label_values(&[seq_str.as_str()])
                .set(-1);
            m.user_session_distinct_output_authorities
                .with_label_values(&[seq_str.as_str()])
                .set(0);
            m.user_session_local_output_rejected
                .with_label_values(&[seq_str.as_str()])
                .set(-1);
            m.user_session_distinct_output_digests
                .with_label_values(&[seq_str.as_str()])
                .set(0);
            for authority_name in self.committee.names() {
                let authority_label = authority_name.concise().to_string();
                m.user_session_output_received_from
                    .with_label_values(&[seq_str.as_str(), authority_label.as_str()])
                    .set(0);
            }
        }
        self.previously_emitted_user_session_seqs = current_seqs;
    }
}
