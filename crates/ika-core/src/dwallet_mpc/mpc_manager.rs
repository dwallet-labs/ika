// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::SuiDataReceivers;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
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
use crate::dwallet_session_request::DWalletSessionRequest;
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
    DWalletMPCOutputReport, DWalletNetworkEncryptionKeyData, GlobalPresignRequest,
    InternalSessionsStatusUpdate, RistrettoSchnorrkelSubstrateProtocol, Secp256k1ECDSAProtocol,
    Secp256k1TaprootProtocol, Secp256r1ECDSAProtocol, SessionIdentifier, SessionType,
};
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::ObjectID;
use tracing::{debug, error, info, warn};

/// Result of majority voting on status updates.
#[derive(Debug, Clone)]
pub struct AgreedStatusUpdate {
    /// Whether the majority of validators are idle.
    pub is_idle: bool,
    /// The presign session requests that reached quorum agreement.
    pub global_presign_requests: Vec<GlobalPresignRequest>,
    /// Network key data that reached quorum agreement via weighted majority vote.
    pub agreed_network_key_data: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
}

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

    /// The epoch store for persisting presign pools to disk.
    epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,

    /// Tracks the idle status of each party, overwritten on each status update.
    /// At the end of processing status updates for a consensus round, we majority vote
    /// to determine the network's idle status.
    idle_status_by_party: HashMap<PartyID, bool>,

    /// Tracks which parties have seen each presign request.
    /// When a presign request reaches majority, it's moved to `completed_presign_session_identifiers`.
    user_requests_of_internal_resources: HashMap<SessionIdentifier, HashSet<PartyID>>,

    /// Session identifiers of presign requests that have reached majority vote.
    /// Once completed, we don't record new votes for these requests.
    completed_presign_session_identifiers: HashSet<SessionIdentifier>,

    /// Global presign requests collected from Sui events, to be broadcast in status updates.
    pub(crate) global_presign_requests: Vec<GlobalPresignRequest>,

    /// Session identifiers of presign requests that have already been sent through consensus.
    /// When we receive our own status update back from consensus, we mark those requests as sent.
    /// This prevents sending the same request multiple times.
    sent_presign_requests: HashSet<SessionIdentifier>,

    /// Per-key voting: maps each key ID to a map from data values to the set of parties that voted for that data.
    network_key_data_votes:
        HashMap<ObjectID, HashMap<DWalletNetworkEncryptionKeyData, HashSet<PartyID>>>,

    /// Most recently consensus-agreed network key data (via inline is_authorized_subset check).
    agreed_network_key_data: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
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
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
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
            epoch_store,
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
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
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
            epoch_store,
            idle_status_by_party: HashMap::new(),
            user_requests_of_internal_resources: HashMap::new(),
            completed_presign_session_identifiers: HashSet::new(),
            global_presign_requests: Vec::new(),
            sent_presign_requests: HashSet::new(),
            network_key_data_votes: HashMap::new(),
            agreed_network_key_data: HashMap::new(),
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

    /// Handle status updates for a consensus round.
    ///
    /// For each status update:
    /// - Override the sender's idle status in `idle_status_by_party`
    /// - For each presign request, add the sender to `user_requests_of_internal_resources`
    ///   and immediately check if majority is reached
    ///
    /// At the end, perform majority vote on idle status using `idle_status_by_party`.
    pub fn handle_status_updates(
        &mut self,
        consensus_round: u64,
        status_updates: Vec<InternalSessionsStatusUpdate>,
    ) -> Option<AgreedStatusUpdate> {
        let mut agreed_presign_requests = Vec::new();

        for status_update in status_updates {
            let sender_authority = status_update.authority;

            let Ok(sender_party_id) =
                authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
            else {
                error!(
                    sender_authority=?sender_authority,
                    consensus_round,
                    should_never_happen =? true,
                    "got a status update for an authority without party ID",
                );
                continue;
            };

            // When we receive our own status update back from consensus,
            // mark the presign requests as sent to avoid re-sending them.
            if sender_authority == self.validator_name {
                for request in &status_update.global_presign_requests {
                    self.sent_presign_requests
                        .insert(request.session_identifier);
                }
            }

            // Override the idle status for this party.
            self.idle_status_by_party
                .insert(sender_party_id, status_update.is_idle);

            // Process each presign request and check for majority immediately.
            for request in status_update.global_presign_requests {
                let session_identifier = request.session_identifier;

                // Skip if this presign request has already reached majority.
                if self
                    .completed_presign_session_identifiers
                    .contains(&session_identifier)
                {
                    continue;
                }

                // Add this party's vote for this presign request.
                let parties = self
                    .user_requests_of_internal_resources
                    .entry(session_identifier)
                    .or_default();
                parties.insert(sender_party_id);

                // Check if the parties that voted form an authorized subset.
                if self.access_structure.is_authorized_subset(parties).is_ok() {
                    // Majority reached - mark as completed and add to result.
                    self.completed_presign_session_identifiers
                        .insert(session_identifier);
                    agreed_presign_requests.push(request);
                    info!(
                        ?session_identifier,
                        consensus_round, "Presign request reached majority vote"
                    );
                }
            }

            // Vote on network key data with inline is_authorized_subset check.
            for key_data in status_update.network_key_data {
                let key_id = key_data.id;

                // Skip if this key has already reached agreement.
                if self.agreed_network_key_data.contains_key(&key_id) {
                    continue;
                }

                // Add this party's vote for this specific key data.
                let parties = self
                    .network_key_data_votes
                    .entry(key_id)
                    .or_default()
                    .entry(key_data.clone())
                    .or_default();
                parties.insert(sender_party_id);

                // Check if the parties that voted for this data form an authorized subset.
                if self.access_structure.is_authorized_subset(parties).is_ok() {
                    self.agreed_network_key_data.insert(key_id, key_data);
                    info!(
                        ?key_id,
                        consensus_round, "Network key data has been agreed upon"
                    );
                }
            }
        }

        // Perform majority vote on idle status at the end of processing.
        let network_is_idle = self.compute_idle_status_majority_vote();

        Some(AgreedStatusUpdate {
            is_idle: network_is_idle,
            global_presign_requests: agreed_presign_requests,
            agreed_network_key_data: self.agreed_network_key_data.clone(),
        })
    }

    /// Compute majority vote for idle status using the accumulated `idle_status_by_party`.
    fn compute_idle_status_majority_vote(&self) -> bool {
        if self.idle_status_by_party.is_empty() {
            return false;
        }

        match self
            .idle_status_by_party
            .clone()
            .weighted_majority_vote(&self.access_structure)
        {
            Ok((_, majority_vote)) => majority_vote,
            Err(mpc::Error::ThresholdNotReached) => false,
            Err(e) => {
                error!(
                    error = %e,
                    "Failed to compute idle status majority vote"
                );
                false
            }
        }
    }

    /// Returns presign requests that haven't been sent through consensus yet.
    pub(crate) fn get_unsent_presign_requests(&self) -> Vec<GlobalPresignRequest> {
        self.global_presign_requests
            .iter()
            .filter(|request| {
                !self
                    .sent_presign_requests
                    .contains(&request.session_identifier)
            })
            .cloned()
            .collect()
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

    fn get_supported_curve_to_signature_algorithm()
    -> Vec<(DWalletCurve, Vec<DWalletSignatureAlgorithm>)> {
        vec![
            (
                DWalletCurve::Secp256k1,
                vec![
                    DWalletSignatureAlgorithm::ECDSASecp256k1,
                    DWalletSignatureAlgorithm::Taproot,
                ],
            ),
            (
                DWalletCurve::Secp256r1,
                vec![DWalletSignatureAlgorithm::ECDSASecp256r1],
            ),
            (
                DWalletCurve::Curve25519,
                vec![DWalletSignatureAlgorithm::EdDSA],
            ),
            (
                DWalletCurve::Ristretto,
                vec![DWalletSignatureAlgorithm::SchnorrkelSubstrate],
            ),
        ]
    }

    /// Returns the network encryption key ID used for checkpoint signing (the oldest by DKG epoch).
    fn checkpoint_signing_network_encryption_key_id(&self) -> Option<ObjectID> {
        self.network_keys
            .network_encryption_keys
            .iter()
            .min_by(|(_, a), (_, b)| a.dkg_at_epoch.cmp(&b.dkg_at_epoch))
            .map(|(id, _)| *id)
    }

    /// Instantiates internal presign sessions based on consensus-agreed network key IDs.
    /// Uses only keys that have reached quorum agreement via status update voting.
    pub(super) fn instantiate_internal_presign_sessions(
        &mut self,
        consensus_round: u64,
        number_of_consensus_rounds: u64,
        network_is_idle: bool,
    ) {
        // Check if we are ready to instantiate internal sessions, which depend on the consensus agreed (synced) network key data.
        let agreed_checkpoint_key_id = match self.checkpoint_signing_network_encryption_key_id() {
            Some(id) => id,
            None => return,
        };

        let checkpoint_curve = self.protocol_config.checkpoint_signing_curve();
        let checkpoint_algorithm = self.protocol_config.checkpoint_signing_algorithm();

        let agreed_key_ids: Vec<_> = self.agreed_network_key_data.keys().copied().collect();
        for key_id in agreed_key_ids {
            for (curve, signature_algorithms) in Self::get_supported_curve_to_signature_algorithm()
            {
                for signature_algorithm in signature_algorithms {
                    let is_checkpointing_presign = agreed_checkpoint_key_id == key_id
                        && curve == checkpoint_curve
                        && signature_algorithm == checkpoint_algorithm;

                    let (minimal_pool_size, consensus_round_delay, sessions_to_instantiate) =
                        if is_checkpointing_presign {
                            (
                                self.protocol_config.checkpoint_presign_pool_minimum_size(),
                                self.protocol_config
                                    .checkpoint_presign_consensus_round_delay(),
                                self.protocol_config
                                    .checkpoint_presign_sessions_to_instantiate(),
                            )
                        } else {
                            (
                                self.protocol_config.get_internal_presign_pool_minimum_size(
                                    curve,
                                    signature_algorithm,
                                ),
                                self.protocol_config
                                    .get_internal_presign_consensus_round_delay(
                                        curve,
                                        signature_algorithm,
                                    ),
                                self.protocol_config
                                    .get_internal_presign_sessions_to_instantiate(
                                        curve,
                                        signature_algorithm,
                                    ),
                            )
                        };

                    let current_pool_size =
                        self.internal_presign_pool_size(key_id, curve, signature_algorithm);

                    if (number_of_consensus_rounds.is_multiple_of(consensus_round_delay)
                        && current_pool_size < minimal_pool_size)
                        || network_is_idle
                    {
                        for _ in 1..=sessions_to_instantiate {
                            self.instantiate_internal_presign_session(
                                consensus_round,
                                key_id,
                                curve,
                                signature_algorithm,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Instantiates an internal presign sessions.
    fn instantiate_internal_presign_session(
        &mut self,
        consensus_round: u64,
        dwallet_network_encryption_key_id: ObjectID,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) {
        let network_dkg_output_bytes = match self
            .network_keys
            .get_network_encryption_key_public_data(&dwallet_network_encryption_key_id)
        {
            Ok(key_data) => key_data.network_dkg_output().as_bytes().to_vec(),
            Err(e) => {
                error!(
                    ?dwallet_network_encryption_key_id,
                    error = ?e,
                    "Failed to get network encryption key data for internal presign session"
                );
                return;
            }
        };

        let session_sequence_number = self.next_internal_presign_sequence_number;
        let request = DWalletSessionRequest::new_internal_presign(
            self.epoch_id,
            consensus_round,
            session_sequence_number,
            curve,
            signature_algorithm,
            dwallet_network_encryption_key_id,
            &network_dkg_output_bytes,
        );

        let session_identifier = request.session_identifier;
        let status = self.session_status_from_request(request, true);

        let session_computation_type = SessionComputationType::MPC {
            messages_by_consensus_round: HashMap::new(),
        };

        info!(
            status=?status,
            consensus_round,
            ?curve,
            ?signature_algorithm,
            ?session_sequence_number,
            ?session_identifier,
            "instantiating new internal presign session",
        );

        self.new_session(&session_identifier, status, session_computation_type);

        self.next_internal_presign_sequence_number += 1;
    }

    /// Instantiates an internal sign session for signing a checkpoint message.
    ///
    /// This is called when a checkpoint is created and needs to be signed using
    /// the internal checkpoint dWallet (with emulated centralized party).
    ///
    /// # Arguments
    /// * `checkpoint_sequence_number` - The sequence number of the checkpoint to sign
    /// * `checkpoint_message` - The serialized checkpoint message to sign
    ///
    /// The network encryption key ID and signature algorithm are determined internally,
    /// using the same approach as internal presign sessions.
    pub(super) fn instantiate_internal_sign_session_for_checkpoint(
        &mut self,
        checkpoint_sequence_number: u64,
        checkpoint_message: Vec<u8>,
    ) -> bool {
        // Use the consensus-agreed checkpoint key ID.
        let dwallet_network_encryption_key_id = match self
            .checkpoint_signing_network_encryption_key_id()
        {
            Some(key_id) => key_id,
            None => {
                warn!(
                    checkpoint_sequence_number,
                    "No consensus-agreed checkpoint key available for internal checkpoint signing"
                );
                return false;
            }
        };

        // Get the checkpoint signing algorithm and curve from protocol config
        let signature_algorithm = self.protocol_config.checkpoint_signing_algorithm();
        let curve = self.protocol_config.checkpoint_signing_curve();

        let hash_scheme = self.protocol_config.checkpoint_signing_hash_scheme().into();

        let network_dkg_output_bytes = match self
            .network_keys
            .get_network_encryption_key_public_data(&dwallet_network_encryption_key_id)
        {
            Ok(key_data) => key_data.network_dkg_output().as_bytes().to_vec(),
            Err(e) => {
                error!(
                    ?dwallet_network_encryption_key_id,
                    checkpoint_sequence_number,
                    error = ?e,
                    "Failed to get network encryption key data for internal sign session"
                );
                return false;
            }
        };

        // Try to get a presign from the internal presign pool
        let (presign_session_id, presign) = match self
            .epoch_store
            .pop_presign(signature_algorithm, dwallet_network_encryption_key_id)
        {
            Ok(Some((session_id, presign))) => (session_id, presign),
            Ok(None) => {
                warn!(
                    checkpoint_sequence_number,
                    ?signature_algorithm,
                    "No presign available in internal pool for checkpoint signing"
                );
                return false;
            }
            Err(e) => {
                error!(
                    checkpoint_sequence_number,
                    ?signature_algorithm,
                    error = ?e,
                    "Failed to get presign from internal pool for checkpoint signing"
                );
                return false;
            }
        };

        // Check if this presign has already been used (safety check)
        if self
            .epoch_store
            .is_presign_used(presign_session_id)
            .unwrap_or(false)
        {
            error!(
                checkpoint_sequence_number,
                ?presign_session_id,
                "Presign has already been used - this should not happen"
            );
            return false;
        }

        // Mark the presign as used to prevent double-spending
        if let Err(e) = self.epoch_store.mark_presign_as_used(presign_session_id) {
            error!(
                checkpoint_sequence_number,
                ?presign_session_id,
                error = ?e,
                "Failed to mark presign as used"
            );
            return false;
        }

        let request = DWalletSessionRequest::new_internal_sign(
            self.epoch_id,
            checkpoint_sequence_number,
            curve,
            signature_algorithm,
            hash_scheme,
            dwallet_network_encryption_key_id,
            &network_dkg_output_bytes,
            checkpoint_message.clone(),
            presign,
        );

        let session_identifier = request.session_identifier;
        let status = self.session_status_from_request(request, true);

        let session_computation_type = SessionComputationType::MPC {
            messages_by_consensus_round: HashMap::new(),
        };

        info!(
            checkpoint_sequence_number,
            ?curve,
            ?signature_algorithm,
            ?session_identifier,
            message_length = checkpoint_message.len(),
            "instantiating internal sign session for checkpoint",
        );

        self.new_session(&session_identifier, status, session_computation_type);
        true
    }

    fn internal_presign_pool_size(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
        _curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> u64 {
        self.epoch_store
            .presign_pool_size(signature_algorithm, dwallet_network_encryption_key_id)
            .unwrap_or_else(|e| {
                error!(error=?e, ?signature_algorithm, "Failed to get presign pool size");
                0
            })
    }

    /// Handles an external presign request by assigning a presign from the internal pool
    /// to the assigned pool. Returns the session identifier if successful.
    pub fn handle_external_presign_request(
        &mut self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
    ) -> Option<SessionIdentifier> {
        // Assign the presign from internal pool to assigned pool
        match self.epoch_store.assign_presign(
            signature_algorithm,
            dwallet_network_encryption_key_id,
            user_verification_key,
            dwallet_id,
            self.epoch_id,
        ) {
            Ok(Some(session_id)) => {
                info!(
                    ?session_id,
                    ?signature_algorithm,
                    ?dwallet_network_encryption_key_id,
                    "Successfully assigned presign to external request"
                );
                Some(session_id)
            }
            Ok(None) => {
                warn!(
                    ?signature_algorithm,
                    ?dwallet_network_encryption_key_id,
                    "No presign available in internal pool for external request"
                );
                None
            }
            Err(e) => {
                error!(
                    error=?e,
                    ?signature_algorithm,
                    ?dwallet_network_encryption_key_id,
                    "Failed to assign presign for external request"
                );
                None
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
    /// Returns the completed computation results, idle status, and presign session requests.
    pub(crate) async fn perform_cryptographic_computation(
        &mut self,
        last_read_consensus_round: u64,
    ) -> (
        HashMap<ComputationId, DwalletMPCResult<mpc::GuaranteedOutputDeliveryRoundResult>>,
        bool,
    ) {
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
                    SessionType::InternalSign => true,
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

        let number_of_ready_to_advance_sessions = ready_to_advance_sessions.len();

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

        let is_idle = self.compute_is_idle(number_of_ready_to_advance_sessions);

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
                return (completed_computation_results, is_idle);
            }
        }

        (completed_computation_results, is_idle)
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

    /// Instantiates agreed network keys from consensus-voted data.
    /// For each key in `agreed_network_key_data` that is not yet loaded locally,
    /// instantiates the key from the consensus-voted data.
    /// Returns the IDs of newly instantiated keys.
    pub(crate) async fn instantiate_agreed_keys_from_voted_data(&mut self) -> Vec<ObjectID> {
        let keys_to_instantiate: Vec<(ObjectID, DWalletNetworkEncryptionKeyData)> = self
            .agreed_network_key_data
            .iter()
            .filter(|(key_id, _)| {
                !self
                    .network_keys
                    .network_encryption_keys
                    .contains_key(key_id)
            })
            .map(|(key_id, key_data)| (*key_id, key_data.clone()))
            .collect();

        let mut new_key_ids = Vec::new();

        for (key_id, key_data) in keys_to_instantiate {
            info!(key_id=?key_id, "Instantiating agreed network key from consensus-voted data");

            let res =
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
                    key_data.current_epoch,
                    self.access_structure.clone(),
                    key_data,
                    self.protocol_config.checkpoint_signing_curve(),
                    self.protocol_config.checkpoint_signing_algorithm(),
                    self.party_id,
                )
                .await;

            match res {
                Ok(key) => {
                    if key.epoch() != self.epoch_id {
                        info!(
                            key_id=?key_id,
                            epoch=?key.epoch(),
                            "Consensus-voted network key epoch does not match current epoch, ignoring"
                        );
                        continue;
                    }
                    info!(key_id=?key_id, "Updating network key from consensus-voted data");
                    if let Err(e) = self
                        .network_keys
                        .update_network_key(key_id, &key, &self.access_structure)
                        .await
                    {
                        error!(error=?e, key_id=?key_id, "Failed to update network key from consensus-voted data");
                    } else {
                        new_key_ids.push(key_id);
                    }
                }
                Err(err) => {
                    error!(
                        error=?err,
                        key_id=?key_id,
                        "Failed to instantiate network key from consensus-voted data"
                    );
                }
            }
        }

        new_key_ids
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
                    self.handle_mpc_internal_output(session_identifier, output);
                }
                DWalletMPCOutputKind::External { .. } => {}
            }

            Some((malicious_authorities, majority_vote))
        } else {
            None
        }
    }

    fn handle_mpc_internal_output(
        &mut self,
        session_identifier: SessionIdentifier,
        output: DWalletInternalMPCOutputKind,
    ) {
        match output {
            DWalletInternalMPCOutputKind::InternalPresign {
                output,
                signature_algorithm,
                session_sequence_number,
                ..
            } => match signature_algorithm {
                DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                    self.record_internal_presign_output::<Secp256k1ECDSAProtocol>(
                        signature_algorithm,
                        session_sequence_number,
                        session_identifier,
                        output,
                    );
                }
                DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                    self.record_internal_presign_output::<Secp256r1ECDSAProtocol>(
                        signature_algorithm,
                        session_sequence_number,
                        session_identifier,
                        output,
                    );
                }
                DWalletSignatureAlgorithm::EdDSA => {
                    self.record_internal_presign_output::<Curve25519EdDSAProtocol>(
                        signature_algorithm,
                        session_sequence_number,
                        session_identifier,
                        output,
                    );
                }
                DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                    self.record_internal_presign_output::<RistrettoSchnorrkelSubstrateProtocol>(
                        signature_algorithm,
                        session_sequence_number,
                        session_identifier,
                        output,
                    );
                }
                DWalletSignatureAlgorithm::Taproot => {
                    self.record_internal_presign_output::<Secp256k1TaprootProtocol>(
                        signature_algorithm,
                        session_sequence_number,
                        session_identifier,
                        output,
                    );
                }
            },
            DWalletInternalMPCOutputKind::InternalSign {
                output,
                curve,
                signature_algorithm,
                hash_scheme: _,
                checkpoint_sequence_number,
            } => {
                // Store the MPC signature for this checkpoint
                if let Err(e) = self
                    .epoch_store
                    .store_mpc_checkpoint_signature(checkpoint_sequence_number, output.clone())
                {
                    error!(
                        checkpoint_sequence_number,
                        error = ?e,
                        "Failed to store MPC checkpoint signature"
                    );
                } else {
                    info!(
                        checkpoint_sequence_number,
                        curve = ?curve,
                        signature_algorithm = ?signature_algorithm,
                        signature_length = output.len(),
                        signature_hex = %hex::encode(&output),
                        "Internal checkpoint sign completed - MPC signature stored"
                    );
                }
            }
        }
    }

    fn record_internal_presign_output<P: twopc_mpc::presign::Protocol>(
        &mut self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        public_output: Vec<u8>,
    ) {
        let presigns = match bcs::from_bytes::<Vec<P::Presign>>(&public_output) {
            Ok(presigns) => presigns,
            Err(e) => {
                error!(
                    should_never_happen = true,
                    error = ?e,
                    "failed to deserialize an internal presign output"
                );
                return;
            }
        };

        let serialized_presigns = match presigns
            .into_iter()
            .map(|presign| bcs::to_bytes(&presign))
            .collect::<bcs::Result<Vec<_>>>()
        {
            Ok(presigns) => presigns,
            Err(e) => {
                error!(
                    should_never_happen = true,
                    error = ?e,
                    "failed to serialize an internal presign output"
                );
                return;
            }
        };

        let number_of_new_presigns = serialized_presigns.len();
        let presign_size = serialized_presigns.first().map(|x| x.len()).unwrap_or(0);

        if let Err(e) = self.epoch_store.insert_presigns(
            signature_algorithm,
            session_sequence_number,
            session_identifier,
            serialized_presigns,
        ) {
            error!(
                error = ?e,
                ?signature_algorithm,
                ?session_sequence_number,
                "failed to insert presigns into the epoch store"
            );
            return;
        }

        // TODO: no unwrap or?
        let pool_new_size = self
            .epoch_store
            .presign_pool_size(signature_algorithm)
            .unwrap_or(0);

        info!(
            ?number_of_new_presigns,
            ?pool_new_size,
            ?signature_algorithm,
            ?session_sequence_number,
            ?presign_size,
            "Added presigns to the internal presign pool"
        );
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

    /// Returns the number of cryptographic computations currently running.
    pub fn running_computation_count(&self) -> usize {
        self.cryptographic_computations_orchestrator
            .currently_running_cryptographic_computations
            .len()
    }

    /// Computes whether this validator is idle based on the number of ready-to-run
    /// sessions plus currently running computations, compared to the threshold.
    pub fn compute_is_idle(&self, number_of_ready_to_advance_sessions: usize) -> bool {
        let number_of_executing_sessions = self.running_computation_count();
        let total_session_count =
            number_of_ready_to_advance_sessions + number_of_executing_sessions;
        let threshold = self.protocol_config.idle_session_count_threshold();
        total_session_count < threshold as usize
    }
}
