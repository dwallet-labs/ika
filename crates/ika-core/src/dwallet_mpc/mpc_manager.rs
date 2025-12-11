// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::{
    ComputationId, ComputationRequest, CryptographicComputationsOrchestrator,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_session::{
    DWalletMPCSessionOutput, DWalletSession, SessionComputationType, SessionStatus,
    session_input_from_request,
};
use crate::dwallet_mpc::network_dkg::instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, ValidatorPrivateDecryptionKeyData};
use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
    get_validators_class_groups_public_keys_and_proofs, party_id_to_authority_name,
};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::request_protocol_data::ProtocolData;
use crate::{SuiDataReceivers, debug_variable_chunks};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, DWalletInternalMPCOutputKind, DWalletMPCMessage, DWalletMPCOutputKind,
    DWalletMPCOutputReport, DWalletNetworkEncryptionKeyData, RistrettoSchnorrkelSubstrateProtocol,
    Secp256k1ECDSAProtocol, Secp256k1TaprootProtocol, Secp256r1ECDSAProtocol, SessionIdentifier,
    SessionType,
};
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::{debug, error, info};

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
    pub(crate) schnorr_presign_second_round_delay: u64,
    sui_data_receivers: SuiDataReceivers,
    pub(crate) protocol_config: ProtocolConfig,

    // The sequence number of the next internal presign session.
    // Starts from 1 in every epoch, and increases as they are spawned.
    // Different epochs will see repeating values of this variable,
    // but that is safe as they are synced within an epoch and
    // the session identifier is derived from the epoch as well.
    next_internal_presign_sequence_number: u64,

    internal_presign_pool_ecdsa_secp256k1: Vec<Vec<u8>>,
    internal_presign_pool_taproot: Vec<Vec<u8>>,
    internal_presign_pool_eddsa: Vec<Vec<u8>>,
    internal_presign_pool_schnorrkel_substrate: Vec<Vec<u8>>,
    internal_presign_pool_ecdsa_secp256r1: Vec<Vec<u8>>,
}

impl DWalletMPCManager {
    pub(crate) fn new(
        validator_name: AuthorityPublicKeyBytes,
        committee: Arc<Committee>,
        epoch_id: EpochId,
        root_seed: RootSeed,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        schnorr_presign_second_round_delay: u64,
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
            schnorr_presign_second_round_delay,
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
        schnorr_presign_second_round_delay: u64,
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
            schnorr_presign_second_round_delay,
            protocol_config,
            next_internal_presign_sequence_number: 1,
            internal_presign_pool_ecdsa_secp256k1: Vec::new(),
            internal_presign_pool_taproot: Vec::new(),
            internal_presign_pool_eddsa: Vec::new(),
            internal_presign_pool_schnorrkel_substrate: Vec::new(),
            internal_presign_pool_ecdsa_secp256r1: Vec::new(),
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
        outputs: Vec<DWalletMPCOutputReport>,
    ) -> (Vec<DWalletMPCOutputKind>, Vec<SessionIdentifier>) {
        // Not let's move to process MPC outputs for the current round.
        let mut agreed_outputs = vec![];
        let mut completed_sessions = vec![];
        for output in &outputs {
            let session_identifier = output.session_identifier();
            let is_internal = output.is_internal();

            let output_result = self.handle_output(consensus_round, output.clone());
            match output_result {
                Some((malicious_authorities, output_result)) => {
                    self.complete_mpc_session(&session_identifier);
                    agreed_outputs.push(output_result);
                    completed_sessions.push(session_identifier);
                    info!(
                        consensus_round,
                        ?session_identifier,
                        ?malicious_authorities,
                        ?is_internal,
                        rejected = output.rejected(),
                        "MPC output reached quorum"
                    );
                }
                None => {
                    debug!(
                        consensus_round,
                        ?session_identifier,
                        ?output,
                        ?is_internal,
                        rejected = output.rejected(),
                        "MPC output yet to reach quorum"
                    );
                }
            };
        }

        (agreed_outputs, completed_sessions)
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

    pub(super) fn session_status_from_request(
        &self,
        request: DWalletSessionRequest,
        is_internal: bool,
    ) -> SessionStatus {
        match session_input_from_request(
            &request,
            &self.access_structure,
            &self.committee,
            &self.network_keys,
            self.next_active_committee.clone(),
            self.validators_class_groups_public_keys_and_proofs.clone(),
        ) {
            Ok((public_input, private_input)) => SessionStatus::Active {
                public_input,
                private_input,
                request,
            },
            Err(e) => {
                if is_internal {
                    error!(                        should_never_happen =? true, error=?e, ?request, "create internal session input from dWallet request with error");
                } else {
                    error!(error=?e, ?request, "create session input from dWallet request with error");
                }
                SessionStatus::Failed
            }
        }
    }

    /// Instantiates internal presign sessions based on predefined logic that is
    /// synced with the consensus and thus with the other validators.
    pub(super) fn instantiate_internal_presign_sessions(&mut self, consensus_round: u64) {
        // TODO: do we want numbers here as consts in the code, or configrables?
        // TODO: don't use consensus round for this, instead count the consensus round seen or something, as they might not be sequential
        if consensus_round.is_multiple_of(40) {
            // TODO: check amount of presigns in the pool

            // TODO: put this in a func and call it for different session types & counts

            // TODO: decide how to get first key - but that's outside? we want the checkpoint separately for the first
            // TODO: make sure this is correct still

            if let Some((dwallet_network_encryption_key_id, _)) = self
                .network_keys
                .network_encryption_keys
                .iter()
                .min_by(|(_, a), (_, b)| a.dkg_at_epoch.cmp(&b.dkg_at_epoch))
            {
                let request = DWalletSessionRequest::new_internal_presign(
                    self.epoch_id,
                    consensus_round,
                    self.next_internal_presign_sequence_number,
                    // TODO: separate to func and take as parameter, loop on them
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                    *dwallet_network_encryption_key_id,
                );

                let session_identifier = request.session_identifier;
                let status = self.session_status_from_request(request, true);

                let session_computation_type = SessionComputationType::MPC {
                    messages_by_consensus_round: HashMap::new(),
                };

                info!(
                    status=?status,
                    consensus_round,
                    ?session_identifier,
                    "instantiating new internal presign session",
                );

                self.new_session(&session_identifier, status, session_computation_type);

                // TODO: if we don't want to create the sessions here, than we need to update this value other way
                self.next_internal_presign_sequence_number += 1;
            }
        }
    }

    /// Creates a new session with SID `session_identifier`,
    /// and insert it into the MPC session map `self.mpc_sessions`.
    pub(super) fn new_session(
        &mut self,
        session_identifier: &SessionIdentifier,
        status: SessionStatus,
        session_computation_type: SessionComputationType,
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
            session_computation_type,
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

                // Always advance system and internal sessions, and only advance user session
                // if they come before the last session to complete in the current epoch (at the current time).
                let should_advance = match request.session_type {
                    SessionType::User => {
                        request.session_sequence_number
                            <= self.last_session_to_complete_in_current_epoch
                    }
                    SessionType::System => true,
                    SessionType::InternalPresign => true,
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
                        should_never_happen =? true,
                        session_identifier=?session.session_identifier,
                        "session is not active, cannot perform cryptographic computation",
                    );

                    return None;
                };

                self.generate_protocol_cryptographic_data(
                    &session.computation_type,
                    &request.protocol_data,
                    last_read_consensus_round,
                    public_input.clone(),
                    &self.protocol_config,
                )
                .ok()?
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
        output_report: DWalletMPCOutputReport,
    ) -> Option<(HashSet<AuthorityName>, DWalletMPCOutputKind)> {
        let session_identifier = output_report.session_identifier();
        let sender_authority = output_report.authority();
        let is_internal = output_report.is_internal();

        let Ok(sender_party_id) =
            authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
        else {
            error!(
                session_identifier=?session_identifier,
                sender_authority=?sender_authority,
                receiver_authority=?self.validator_name,
                ?is_internal,
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
                    ?is_internal,
                    "received an output for an MPC session before receiving an event requesting it"
                );

                let session_computation_type = match output_report.is_native() {
                    Ok(true) => SessionComputationType::Native,
                    Ok(false) => SessionComputationType::MPC {
                        messages_by_consensus_round: HashMap::new(),
                    },
                    Err(e) => {
                        error!(
                            session_identifier=?session_identifier,
                            sender_authority=?sender_authority,
                            receiver_authority=?self.validator_name,
                            error=?e,
                            ?is_internal,
                            "got an output for an invalid computation type",
                        );

                        return None;
                    }
                };

                // This can happen if the session is not in the active sessions,
                // but we still want to store the output.
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

        session.add_output(consensus_round, sender_party_id, output_report);

        let outputs_by_consensus_round = session.outputs_by_consensus_round().clone();

        if let Some((malicious_authorities, majority_vote)) =
            self.build_outputs_to_finalize(&session_identifier, outputs_by_consensus_round)
        {
            self.record_malicious_actors(&malicious_authorities);

            match majority_vote.clone() {
                DWalletMPCOutputKind::Internal { output } => {
                    self.handle_mpc_internal_output(output);
                }
                DWalletMPCOutputKind::External { .. } => {}
            }

            Some((malicious_authorities, majority_vote))
        } else {
            None
        }
    }

    fn handle_mpc_internal_output(&mut self, output: DWalletInternalMPCOutputKind) {
        match output {
            DWalletInternalMPCOutputKind::InternalPresign {
                output,
                signature_algorithm,
                ..
            } => {
                match signature_algorithm {
                    DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                        self.record_internal_presign_output::<Secp256k1ECDSAProtocol>(
                            signature_algorithm,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                        self.record_internal_presign_output::<Secp256r1ECDSAProtocol>(
                            signature_algorithm,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::EdDSA => {
                        self.record_internal_presign_output::<Curve25519EdDSAProtocol>(
                            signature_algorithm,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                        self.record_internal_presign_output::<RistrettoSchnorrkelSubstrateProtocol>(signature_algorithm, output);
                    }
                    DWalletSignatureAlgorithm::Taproot => {
                        self.record_internal_presign_output::<Secp256k1TaprootProtocol>(
                            signature_algorithm,
                            output,
                        );
                    }
                }
            }
            DWalletInternalMPCOutputKind::InternalSign { output, .. } => {
                todo!()
            }
        }
    }

    fn record_internal_presign_output<P: twopc_mpc::presign::Protocol>(
        &mut self,
        signature_algorithm: DWalletSignatureAlgorithm,
        public_output: Vec<u8>,
    ) {
        if let Ok(presigns) = bcs::from_bytes::<Vec<P::Presign>>(&public_output) {
            if let Ok(serialized_presigns) = presigns
                .into_iter()
                .map(|public_output| bcs::to_bytes(&public_output))
                .collect::<bcs::Result<Vec<_>>>()
            {
                let number_of_new_presigns = serialized_presigns.len();
                match signature_algorithm {
                    DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                        self.internal_presign_pool_ecdsa_secp256k1
                            .extend(serialized_presigns);
                        let pool_new_size = self.internal_presign_pool_ecdsa_secp256k1.len();
                        info!(
                            ?number_of_new_presigns,
                            ?pool_new_size,
                            ?signature_algorithm,
                            "Added presigns to the internal presign pool"
                        );
                    }
                    DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                        self.internal_presign_pool_ecdsa_secp256r1
                            .extend(serialized_presigns);
                        let pool_new_size = self.internal_presign_pool_ecdsa_secp256r1.len();
                        info!(
                            ?number_of_new_presigns,
                            ?pool_new_size,
                            ?signature_algorithm,
                            "Added presigns to the internal presign pool"
                        );
                    }
                    DWalletSignatureAlgorithm::EdDSA => {
                        self.internal_presign_pool_eddsa.extend(serialized_presigns);
                        let pool_new_size = self.internal_presign_pool_eddsa.len();
                        info!(
                            ?number_of_new_presigns,
                            ?pool_new_size,
                            ?signature_algorithm,
                            "Added presigns to the internal presign pool"
                        );
                    }
                    DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                        self.internal_presign_pool_schnorrkel_substrate
                            .extend(serialized_presigns);
                        let pool_new_size = self.internal_presign_pool_schnorrkel_substrate.len();
                        info!(
                            ?number_of_new_presigns,
                            ?pool_new_size,
                            ?signature_algorithm,
                            "Added presigns to the internal presign pool"
                        );
                    }
                    DWalletSignatureAlgorithm::Taproot => {
                        self.internal_presign_pool_taproot
                            .extend(serialized_presigns);
                        let pool_new_size = self.internal_presign_pool_taproot.len();
                        info!(
                            ?number_of_new_presigns,
                            ?pool_new_size,
                            ?signature_algorithm,
                            "Added presigns to the internal presign pool"
                        );
                    }
                }
            } else {
                error!(
                    should_never_happen =? true,
                    "failed to serialize an internal presign output"
                );
            }
        } else {
            error!(
                should_never_happen =? true,
                "failed to deserialize an internal presign output"
            );
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
                "malicious actors identified & recorded"
            );
        }
    }

    /// Builds the outputs to finalize based on the outputs received in the consensus rounds.
    /// If a majority vote is reached, it returns the malicious voters (didn't vote with majority) and the majority vote.
    /// If the threshold is not reached, it returns `None`.
    pub(crate) fn build_outputs_to_finalize(
        &self,
        session_identifier: &SessionIdentifier,
        outputs_by_consensus_round: HashMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
    ) -> Option<(HashSet<AuthorityName>, DWalletMPCOutputKind)> {
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
    ) {
        match self.sessions.entry(*session_identifier) {
            Entry::Occupied(session) => session
                .into_mut()
                .mark_mpc_session_as_computation_completed(),
            Entry::Vacant(_) => {
                // This can happen if the session is not in the active sessions,
                // but we still want to store the message.
                // We will create a new session for it.
                self.new_session(
                    session_identifier,
                    SessionStatus::ComputationCompleted,
                    session_type,
                );
            }
        };
    }
}
