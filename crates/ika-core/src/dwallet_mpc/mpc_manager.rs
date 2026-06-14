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
use crate::dwallet_mpc::network_dkg::spawn_network_encryption_key_public_data_instantiation;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, ValidatorPrivateDecryptionKeyData};
use crate::dwallet_mpc::{
    ValidatorMpcKeysByPartyId, authority_name_to_party_id_from_committee,
    generate_access_structure_from_committee, get_validator_mpc_keys_by_party_id,
    party_id_to_authority_name,
};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm, NetworkEncryptionKeyPublicData,
    VersionedPresignOutput,
};
use dwallet_mpc_types::mpc_protocol_configuration::supported_curve_to_signature_algorithms;
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use group::PartyID;
use hex;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::handoff::HandoffItemKey;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    ConsensusGlobalPresignRequest, ConsensusNOAObservation, Curve25519EdDSAProtocol,
    DWalletInternalMPCOutputKind, DWalletMPCMessage, DWalletMPCOutputKind, DWalletMPCOutputReport,
    DWalletNetworkEncryptionKeyData, GlobalPresignRequest, IdleStatusUpdate,
    RistrettoSchnorrkelProtocol, Secp256k1ECDSAProtocol, Secp256k1TaprootProtocol,
    Secp256r1ECDSAProtocol, SessionIdentifier, SessionType, SuiChainObservationUpdate,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sui_types::base_types::ObjectID;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

use ika_types::noa_checkpoint::{
    CounterpartyChain, NOACheckpointTxObservation, NOACheckpointTxRef, SuiChainContext,
    SuiChainObservation, SuiCounterpartyChain,
};

use crate::dwallet_mpc::NetworkOwnedAddressSignOutput;

/// Compute the agreed chain context for any `CounterpartyChain` implementation.
/// Updates `current_context` in place if a new context is agreed upon.
fn compute_chain_context<C: CounterpartyChain>(
    observations_by_party: &HashMap<PartyID, C::Observation>,
    current_context: &mut Option<C::Context>,
    access_structure: &WeightedThresholdAccessStructure,
    consensus_round: u64,
) {
    let observations: HashMap<u16, C::Observation> = observations_by_party
        .iter()
        .map(|(party_id, obs)| (*party_id, obs.clone()))
        .collect();

    if let Some(context) =
        C::context_from_observations(&observations, current_context.as_ref(), access_structure)
    {
        info!(
            consensus_round,
            chain = %C::KIND,
            "Chain context agreed upon"
        );
        *current_context = Some(context);
    }
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
    /// All four per-validator on-chain public-key payloads (class groups + 3
    /// PVSS HPKE) keyed by party id. Built once at MPC manager init from the
    /// committee's 4 sibling HashMaps; passed to `session_input_from_request`
    /// per session-input construction. See `ValidatorMpcKeysByPartyId`
    /// for the bundle's contents.
    pub(crate) validator_mpc_keys_by_party_id: ValidatorMpcKeysByPartyId,
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

    /// Network DKG / reconfig requests that arrived before the
    /// off-chain freeze gate was satisfied. Drained on every
    /// `handle_mpc_request_batch` by re-running each through
    /// `handle_mpc_request`; once the per-epoch freeze (and
    /// per-key DKG quorum, for DKG requests) is in place, they
    /// pass the gate and run normally.
    pub(crate) requests_pending_for_frozen_mpc_data: Vec<DWalletSessionRequest>,
    pub(crate) next_active_committee: Option<Committee>,
    pub(crate) dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,

    pub(crate) network_dkg_third_round_delay: u64,
    pub(crate) decryption_key_reconfiguration_third_round_delay: u64,
    pub(crate) schnorr_presign_second_round_delay: u64,
    sui_data_receivers: SuiDataReceivers,
    pub(crate) protocol_config: ProtocolConfig,

    /// Tracks the idle status of each party, overwritten on each status update.
    /// At the end of processing status updates for a consensus round, we majority vote
    /// to determine the network's idle status.
    pub(crate) idle_status_by_party: HashMap<PartyID, bool>,

    /// Tracks which parties have seen each presign request, keyed by sequence number.
    /// When a presign request reaches majority, it's moved to `completed_presign_sequence_numbers`.
    presign_request_votes: HashMap<u64, HashSet<PartyID>>,

    /// Sequence numbers of presign requests that have reached majority vote.
    /// Once completed, we don't record new votes for these requests.
    completed_presign_sequence_numbers: HashSet<u64>,

    /// Global presign requests collected from Sui events, to be broadcast in status updates.
    pub(crate) global_presign_requests: Vec<GlobalPresignRequest>,

    /// Sequence numbers of presign requests that have already been sent through consensus.
    /// When we receive our own status update back from consensus, we mark those requests as sent.
    /// This prevents sending the same request multiple times.
    sent_presign_sequence_numbers: HashSet<u64>,

    /// Sequence numbers whose lock-target deferral was already logged, so a
    /// request waiting for `last_session_to_complete_in_current_epoch` to
    /// cover it logs once instead of every consensus round.
    logged_lock_deferred_presigns: HashSet<u64>,

    /// Network-key data adopted by `adopt_cert_verified_keys` (gated by the
    /// prior epoch's handoff cert); the instantiation input set.
    pub(crate) adopted_network_key_data: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,

    /// The `(overlay, cert-present)` input pair of the last completed
    /// `adopt_cert_verified_keys` pass. The overlay watch publishes a
    /// fresh `Arc` on every change (never mutates in place) and the
    /// prior epoch's handoff cert is immutable once present, so an
    /// identical pair cannot produce new adoptions — the pass (which
    /// re-hashes multi-MB blobs) is skipped for that tick.
    last_adoption_input: Option<(
        Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>,
        bool,
    )>,

    /// Per-key snapshot of the `DWalletNetworkEncryptionKeyData`
    /// shape we last passed to `update_network_key`. Used by
    /// `instantiate_adopted_network_keys` to distinguish
    /// "agreed data hasn't changed since we last instantiated"
    /// from "agreed data was just overwritten by a fresh quorum
    /// (typically the reconfig output flipping)" — only the latter
    /// needs a re-instantiation pass.
    last_instantiated_network_key_data: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
    /// The last network-key data whose instantiation FAILED to decrypt
    /// this validator's share (e.g. the validator isn't in that output's
    /// committee yet — a joiner mid-fold-in, or a departing validator).
    /// The decryption is deterministic, so re-running it on identical
    /// bytes every service tick only burns class-groups crypto; this
    /// snapshot suppresses the retry until the bytes change (the output
    /// that carries this validator's share arrives).
    last_failed_network_key_data: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,

    /// Network-key instantiations currently running on the rayon pool,
    /// polled (non-blocking) every service tick. The instantiation is
    /// an expensive, long-running computation; awaiting it inline froze
    /// the whole MPC service loop — every session on the validator —
    /// for its full duration at each epoch boundary.
    pub(crate) pending_network_key_instantiations:
        HashMap<ObjectID, PendingNetworkKeyInstantiation>,

    /// Last time the handoff-cert read-error warn in
    /// `adopt_cert_verified_keys` was emitted. The adoption pass runs
    /// every 20ms service iteration, so a persistent store error would
    /// otherwise warn ~50x/second; warn at most every 10s (debug in
    /// between). The retry behavior itself is unthrottled.
    last_cert_read_warn: Option<Instant>,

    /// `(key_id, local output digest)` pairs whose contradiction with the
    /// prior epoch's handoff cert was already warned about. The adoption
    /// pass re-runs whenever the overlay `Arc` republishes (every ~5s
    /// during incomplete-overlay convergence), so an unchanged mismatch
    /// would re-warn per republish; warn once per distinct local digest,
    /// debug thereafter.
    warned_cert_digest_mismatches: HashSet<(ObjectID, [u8; 32])>,

    /// Sessions whose protocol-cryptographic-data generation already
    /// failed and was logged. The generation re-runs every 20ms service
    /// iteration, so a stuck session would otherwise emit ~50 identical
    /// errors/second; log once per session (the skip-and-retry behavior
    /// itself is unthrottled).
    warned_cryptographic_data_generation_failures: HashSet<SessionIdentifier>,

    // The sequence number of the next internal presign session.
    // Starts from 1 in every epoch, and increases as they are spawned.
    // Different epochs will see repeating values of this variable,
    // but that is safe as they are synced within an epoch and
    // the session identifier is derived from the epoch as well.
    next_internal_presign_sequence_number: u64,

    /// Monotonically increasing count of instantiated internal presign sessions
    /// per (curve, signature_algorithm). Incremented when a session is created.
    /// Used with `completed_internal_presign_sessions` to prevent instantiating
    /// new sessions while existing ones haven't completed — each session produces
    /// a variable number of presigns (1 to n-t), so overlapping batches cause
    /// pool overshoot.
    /// Consensus-safe: instantiation is consensus-agreed, so all honest parties
    /// maintain identical values.
    pub(crate) instantiated_internal_presign_sessions:
        HashMap<(DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// Monotonically increasing count of completed internal presign sessions
    /// per (curve, signature_algorithm). Incremented when a session's output
    /// reaches consensus majority. When this equals `instantiated_internal_presign_sessions`
    /// for a given pair, new sessions may be instantiated.
    pub(crate) completed_internal_presign_sessions:
        HashMap<(DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// The epoch store for persisting presign pools to disk.
    pub(crate) epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,

    /// Channel sender for completed network-owned-address sign session outputs.
    pub(crate) network_owned_address_sign_output_sender: Sender<NetworkOwnedAddressSignOutput>,

    /// Each validator's latest Sui chain observation, keyed by party ID.
    /// Updated every time a status update with an observation is received.
    sui_chain_observations_by_party: HashMap<PartyID, SuiChainObservation>,
    /// The most recently consensus-agreed Sui chain context (None at startup).
    agreed_sui_chain_context: Option<SuiChainContext>,

    /// NOA finalization observation votes: tx_ref → set of party IDs that observed finalization.
    noa_finalization_observations: HashMap<NOACheckpointTxRef, HashSet<PartyID>>,
    /// NOA failure observation votes: (tx_ref, retry_round) → set of party IDs.
    noa_failure_observations: HashMap<(NOACheckpointTxRef, u32), HashSet<PartyID>>,
    /// tx_refs that have already reached finalization quorum (prevents duplicate commands).
    finalized_tx_refs: HashSet<NOACheckpointTxRef>,
    /// (tx_ref, retry_round) pairs that have already reached failure quorum.
    failed_tx_ref_rounds: HashSet<(NOACheckpointTxRef, u32)>,
}

/// An in-flight network-key instantiation: the input bytes that were
/// attempted (retained for the failure record, which suppresses retries
/// on identical bytes) and the receiver its result arrives on.
pub(crate) struct PendingNetworkKeyInstantiation {
    attempted: DWalletNetworkEncryptionKeyData,
    receiver: oneshot::Receiver<DwalletMPCResult<NetworkEncryptionKeyPublicData>>,
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
        network_owned_address_sign_output_sender: Sender<NetworkOwnedAddressSignOutput>,
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
            network_owned_address_sign_output_sender,
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
        network_owned_address_sign_output_sender: Sender<NetworkOwnedAddressSignOutput>,
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
            validator_mpc_keys_by_party_id: get_validator_mpc_keys_by_party_id(&committee)?,
            cryptographic_computations_orchestrator: mpc_computations_orchestrator,
            malicious_actors: HashSet::new(),
            last_session_to_complete_in_current_epoch: 0,
            recognized_self_as_malicious: false,
            network_keys: Box::new(dwallet_network_keys),
            sui_data_receivers,
            requests_pending_for_next_active_committee: Vec::new(),
            requests_pending_for_network_key: HashMap::new(),
            requests_pending_for_frozen_mpc_data: Vec::new(),
            dwallet_mpc_metrics,
            next_active_committee: None,
            validator_name,
            committee,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            schnorr_presign_second_round_delay,
            protocol_config,
            idle_status_by_party: HashMap::new(),
            presign_request_votes: HashMap::new(),
            completed_presign_sequence_numbers: HashSet::new(),
            global_presign_requests: Vec::new(),
            sent_presign_sequence_numbers: HashSet::new(),
            logged_lock_deferred_presigns: HashSet::new(),
            adopted_network_key_data: HashMap::new(),
            last_adoption_input: None,
            last_instantiated_network_key_data: HashMap::new(),
            pending_network_key_instantiations: HashMap::new(),
            last_cert_read_warn: None,
            warned_cert_digest_mismatches: HashSet::new(),
            warned_cryptographic_data_generation_failures: HashSet::new(),
            last_failed_network_key_data: HashMap::new(),
            next_internal_presign_sequence_number: 1,
            instantiated_internal_presign_sessions: HashMap::new(),
            completed_internal_presign_sessions: HashMap::new(),
            epoch_store,
            network_owned_address_sign_output_sender,
            sui_chain_observations_by_party: HashMap::new(),
            agreed_sui_chain_context: None,
            noa_finalization_observations: HashMap::new(),
            noa_failure_observations: HashMap::new(),
            finalized_tx_refs: HashSet::new(),
            failed_tx_ref_rounds: HashSet::new(),
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
    /// Returns each agreed output paired with the session's chain (if any),
    /// plus the list of completed session identifiers.
    pub fn handle_consensus_round_outputs(
        &mut self,
        consensus_round: u64,
        outputs: Vec<DWalletMPCOutputReport>,
    ) -> (
        Vec<(DWalletMPCOutputKind, Option<CounterpartyChainKind>)>,
        Vec<SessionIdentifier>,
    ) {
        let mut agreed_outputs = vec![];
        let mut completed_sessions = vec![];
        for output in &outputs {
            let session_identifier = output.session_identifier();
            let is_internal = output.is_internal();

            let output_result = self.handle_output(consensus_round, output.clone());
            match output_result {
                Some((malicious_authorities, output_result)) => {
                    // Recovery net: cache quorum-agreed network-key outputs
                    // locally even when this validator didn't produce them
                    // (see `cache_network_key_output_from_quorum`).
                    self.cache_network_key_output_from_quorum(&output_result);
                    // Read counterparty_chain before completing (which removes session data).
                    let counterparty_chain = self
                        .sessions
                        .get(&session_identifier)
                        .and_then(|s| s.counterparty_chain);
                    self.complete_mpc_session(&session_identifier);
                    agreed_outputs.push((output_result, counterparty_chain));
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

    /// Recovery net for network-key outputs: caches the quorum-agreed DKG /
    /// reconfiguration output bytes locally even when this validator did not
    /// compute them itself.
    ///
    /// The producer-side cache (the `Finalize` arm in `dwallet_mpc_service`)
    /// runs only for sessions this validator computed locally to completion.
    /// A validator that restarted mid-session (replay marks the session
    /// completed from the quorum output and never re-runs the computation),
    /// or whose own computation finished after it processed the quorum round
    /// (the `Finalize` result is dropped for non-active sessions), would
    /// otherwise NEVER hold the output locally — leaving its off-chain
    /// overlay empty for the key, withholding its EndOfPublish vote
    /// (`snapshot_ready_for_signing` requires the local digest), and under
    /// v4 there is no chain fallback to heal it (observed live as a wedged
    /// genesis: one validator missing the DKG output blocked the epoch from
    /// ever closing).
    ///
    /// The bytes are the stake-quorum-agreed value from consensus — the same
    /// canonical output every peer holds — so caching them is safe. Chunked
    /// outputs (`slice_public_output_into_messages` splits large outputs
    /// across several message kinds, in order) are reassembled by
    /// concatenation. The cache is content-addressed, so on the validators
    /// that DID compute locally this is a no-op re-cache of identical bytes.
    /// Reconfiguration outputs are keyed by this manager's epoch — the
    /// reconfiguration session's own epoch, matching the producer side's
    /// `session_request.epoch` keying (system sessions are always
    /// current-epoch).
    fn cache_network_key_output_from_quorum(&self, output: &DWalletMPCOutputKind) {
        if !self.epoch_store.off_chain_validator_metadata_enabled() {
            return;
        }
        let DWalletMPCOutputKind::External { output: kinds } = output else {
            return;
        };
        let mut dkg_outputs: HashMap<ObjectID, Vec<u8>> = HashMap::new();
        let mut reconfiguration_outputs: HashMap<ObjectID, Vec<u8>> = HashMap::new();
        for kind in kinds {
            match kind {
                DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(chunk)
                    if !chunk.rejected =>
                {
                    if let Ok(key_id) =
                        ObjectID::from_bytes(&chunk.dwallet_network_encryption_key_id)
                    {
                        dkg_outputs
                            .entry(key_id)
                            .or_default()
                            .extend_from_slice(&chunk.public_output);
                    }
                }
                DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(
                    chunk,
                ) if !chunk.rejected => {
                    if let Ok(key_id) =
                        ObjectID::from_bytes(&chunk.dwallet_network_encryption_key_id)
                    {
                        reconfiguration_outputs
                            .entry(key_id)
                            .or_default()
                            .extend_from_slice(&chunk.public_output);
                    }
                }
                _ => {}
            }
        }
        for (key_id, bytes) in dkg_outputs {
            if bytes.is_empty() {
                continue;
            }
            if let Err(e) = self.epoch_store.cache_network_dkg_output(key_id, &bytes) {
                warn!(
                    error = ?e,
                    ?key_id,
                    "failed to cache quorum-agreed network DKG output"
                );
            }
        }
        for (key_id, bytes) in reconfiguration_outputs {
            if bytes.is_empty() {
                continue;
            }
            if let Err(e) =
                self.epoch_store
                    .cache_network_reconfiguration_output(key_id, self.epoch_id, &bytes)
            {
                warn!(
                    error = ?e,
                    ?key_id,
                    "failed to cache quorum-agreed network reconfiguration output"
                );
            }
        }
    }

    /// Handle idle status and chain observation updates for a consensus round.
    ///
    /// For each idle status update, override the sender's idle status in `idle_status_by_party`.
    /// For each chain observation update, store the sender's latest observation.
    ///
    /// Always runs majority vote on idle status (even with empty input).
    /// Returns `(is_idle, Option<SuiChainContext>)`.
    pub fn handle_idle_and_chain_updates(
        &mut self,
        consensus_round: u64,
        idle_updates: Vec<IdleStatusUpdate>,
        chain_observations: Vec<SuiChainObservationUpdate>,
    ) -> (bool, Option<SuiChainContext>) {
        for update in idle_updates {
            let Ok(sender_party_id) =
                authority_name_to_party_id_from_committee(&self.committee, &update.authority)
            else {
                error!(
                    sender_authority=?update.authority,
                    consensus_round,
                    should_never_happen = true,
                    "got an idle status update for an authority without party ID",
                );
                continue;
            };

            self.idle_status_by_party
                .insert(sender_party_id, update.is_idle);
        }

        for observation in chain_observations {
            let Ok(sender_party_id) =
                authority_name_to_party_id_from_committee(&self.committee, &observation.authority)
            else {
                error!(
                    sender_authority=?observation.authority,
                    consensus_round,
                    should_never_happen = true,
                    "got a chain observation update for an authority without party ID",
                );
                continue;
            };

            self.sui_chain_observations_by_party
                .insert(sender_party_id, observation.sui_chain_observation);
        }

        // Compute agreed chain context from accumulated observations.
        compute_chain_context::<SuiCounterpartyChain>(
            &self.sui_chain_observations_by_party,
            &mut self.agreed_sui_chain_context,
            &self.access_structure,
            consensus_round,
        );

        // Perform majority vote on idle status.
        let network_is_idle = self.compute_idle_status_majority_vote();

        (network_is_idle, self.agreed_sui_chain_context.clone())
    }

    /// Handle presign request messages. Performs quorum voting per sequence number.
    /// Marks own messages as sent when they return from consensus.
    /// Returns newly agreed presign requests.
    pub fn handle_presign_request_messages(
        &mut self,
        consensus_round: u64,
        messages: Vec<ConsensusGlobalPresignRequest>,
    ) -> Vec<GlobalPresignRequest> {
        let mut agreed_presign_requests = Vec::new();

        for msg in messages {
            let sender_authority = msg.authority;
            let request = msg.request;

            let Ok(sender_party_id) =
                authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
            else {
                error!(
                    sender_authority=?sender_authority,
                    consensus_round,
                    should_never_happen = true,
                    "got a presign request for an authority without party ID",
                );
                continue;
            };

            // When we receive our own presign request back from consensus,
            // mark it as sent to avoid re-sending.
            if sender_authority == self.validator_name {
                self.sent_presign_sequence_numbers
                    .insert(request.session_sequence_number);
            }

            let sequence_number = request.session_sequence_number;

            // Skip if this presign request has already reached majority.
            if self
                .completed_presign_sequence_numbers
                .contains(&sequence_number)
            {
                continue;
            }

            // Add this party's vote for this presign request.
            let parties = self
                .presign_request_votes
                .entry(sequence_number)
                .or_default();
            parties.insert(sender_party_id);

            // Check if the parties that voted form an authorized subset.
            if self.access_structure.is_authorized_subset(parties).is_ok() {
                self.completed_presign_sequence_numbers
                    .insert(sequence_number);
                agreed_presign_requests.push(request);
                debug!(
                    sequence_number,
                    consensus_round, "Presign request reached majority vote"
                );
            }
        }

        agreed_presign_requests
    }

    /// Adopt this validator's locally-observed network-key outputs into
    /// the instantiation set (`adopted_network_key_data`), gated by the
    /// prior epoch's handoff cert — the cross-epoch agreement on which
    /// outputs the current epoch inherits, replacing the now-removed consensus vote.
    ///
    /// - A **reconfigured** key (it carries a current-epoch
    ///   reconfiguration output) is adopted only when both its stable DKG
    ///   digest and its epoch-specific reconfiguration digest match the
    ///   prior cert. A stale/wrong local value (the lagging-snapshot
    ///   hazard the now-removed vote filtered via byte-identical-quorum) fails the
    ///   match and is skipped; so does any key when the cert isn't
    ///   available yet (the bootstrap anchor may still be fetching it).
    /// - A key still in its **initial-DKG state** (no reconfiguration has
    ///   run yet — the genesis network key, or one created this epoch) is
    ///   adopted from its local DKG output directly: the DKG output is a
    ///   one-time deterministic computation (byte-identical across the
    ///   committee), and no prior cert can pin a key produced after it.
    ///   THIS epoch's handoff then certifies it for peers joining at E+1.
    ///   If a cert does happen to pin the key's DKG digest, the match is
    ///   still required as a consistency check.
    pub fn adopt_cert_verified_keys(
        &mut self,
        overlay: &Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>,
    ) {
        // Once a pass ran with the cert present, the same overlay `Arc`
        // can't yield new adoptions — skip before even the cert DB read.
        if let Some((last_overlay, cert_was_present)) = &self.last_adoption_input
            && Arc::ptr_eq(last_overlay, overlay)
            && *cert_was_present
        {
            return;
        }
        // A cert READ ERROR must not be conflated with a genuinely-absent
        // cert: `cert == None` sends a reconfigured key down the unverified
        // v3->v4-boundary adoption path below, silently bypassing the
        // cert-digest gate. A transient store error therefore skips adoption
        // entirely for this tick (the service loop retries every iteration)
        // rather than degrading the security gate to blind adoption.
        let cert = match self.epoch_id.checked_sub(1) {
            Some(prior_epoch) => match self
                .epoch_store
                .get_certified_handoff_attestation(prior_epoch)
            {
                Ok(cert) => cert,
                Err(e) => {
                    // The adoption pass runs every 20ms service iteration
                    // and a read error returns before the early-out input
                    // snapshot updates, so a persistent store error would
                    // otherwise emit ~50 identical warns/second. Throttle
                    // the emission (not the retry) to one warn per 10s.
                    let should_warn = self
                        .last_cert_read_warn
                        .is_none_or(|last| last.elapsed() >= Duration::from_secs(10));
                    if should_warn {
                        self.last_cert_read_warn = Some(Instant::now());
                        warn!(
                            error = ?e,
                            prior_epoch,
                            "failed to read the handoff cert for instantiation — skipping \
                             network-key adoption this tick (retrying next iteration)"
                        );
                    } else {
                        debug!(
                            error = ?e,
                            prior_epoch,
                            "failed to read the handoff cert for instantiation — skipping \
                             network-key adoption this tick (retrying next iteration)"
                        );
                    }
                    return;
                }
            },
            None => None,
        };
        // Same overlay and the cert is still absent — identical inputs
        // to the last completed pass, nothing new to adopt.
        if let Some((last_overlay, cert_was_present)) = &self.last_adoption_input
            && Arc::ptr_eq(last_overlay, overlay)
            && *cert_was_present == cert.is_some()
        {
            return;
        }
        let mut dkg_digests: HashMap<ObjectID, [u8; 32]> = HashMap::new();
        let mut reconfiguration_digests: HashMap<ObjectID, [u8; 32]> = HashMap::new();
        if let Some(cert) = &cert {
            for (item, digest) in &cert.attestation.items {
                match item {
                    HandoffItemKey::NetworkDkgOutput { key_id } => {
                        dkg_digests.insert(*key_id, *digest);
                    }
                    HandoffItemKey::NetworkReconfigurationOutput { key_id } => {
                        reconfiguration_digests.insert(*key_id, *digest);
                    }
                    HandoffItemKey::ValidatorMpcData { .. } => {}
                }
            }
        }
        let off_chain_on = self.epoch_store.off_chain_validator_metadata_enabled();
        for (key_id, data) in overlay.iter() {
            if data.network_dkg_public_output.is_empty() {
                continue; // nothing computed/fetched locally yet
            }
            let local_dkg_digest = mpc_data_blob_hash(&data.network_dkg_public_output);
            if data.current_reconfiguration_public_output.is_empty() {
                // A cert that pins a reconfiguration digest for this key means
                // the committee agreed this epoch runs on parameters derived
                // from THAT reconfiguration output. An overlay entry whose
                // reconfiguration output is (transiently) empty must therefore
                // never be adopted through this initial-DKG branch: it would
                // instantiate DKG-derived parameters — a set the committee
                // never agreed to use this epoch — and every MPC output this
                // validator computes with them byte-diverges from its peers',
                // which the output-quorum byte-equality tally then convicts
                // as malicious. Skip and retry: the overlay re-merges every
                // sync tick and the prepare-then-start barrier installs the
                // cert-pinned blob by digest at the boundary, so the bytes
                // become locally resolvable. Warn once per cert digest
                // (deduped), debug on repeats — same pattern as the
                // mismatch skips below.
                if off_chain_on
                    && let Some(cert_reconfiguration_digest) = reconfiguration_digests.get(key_id)
                {
                    if self
                        .warned_cert_digest_mismatches
                        .insert((*key_id, *cert_reconfiguration_digest))
                    {
                        warn!(
                            ?key_id,
                            ?cert_reconfiguration_digest,
                            "prior epoch's handoff cert pins a reconfiguration output for \
                             this key but the overlay's reconfiguration output is empty — \
                             skipping adoption until the blob resolves locally (a DKG-only \
                             instantiation would diverge from the committee-agreed \
                             parameters)"
                        );
                    } else {
                        debug!(
                            ?key_id,
                            "overlay reconfiguration output still empty for a \
                             cert-reconfigured key — skipping adoption"
                        );
                    }
                    continue;
                }
                // Initial-DKG state: adopt the deterministic local DKG
                // output. Require the match only if a cert pins it.
                if let Some(cert_dkg) = dkg_digests.get(key_id)
                    && *cert_dkg != local_dkg_digest
                {
                    // A locally-held DKG output contradicting the
                    // quorum-certified cert is genuinely anomalous: the
                    // key is never adopted/instantiated and the validator
                    // silently stops signing with it. Warn (deduped per
                    // local digest, so overlay republishes don't re-warn).
                    if self
                        .warned_cert_digest_mismatches
                        .insert((*key_id, local_dkg_digest))
                    {
                        warn!(
                            ?key_id,
                            cert_dkg_digest = ?cert_dkg,
                            local_dkg_digest = ?local_dkg_digest,
                            "local network-key DKG output digest does not match the prior \
                             epoch's handoff cert — skipping adoption"
                        );
                    } else {
                        debug!(
                            ?key_id,
                            "local network-key DKG output still contradicts the handoff \
                             cert — skipping adoption"
                        );
                    }
                    continue;
                }
            } else if off_chain_on && cert.is_some() {
                // Reconfigured key, off-chain mode with a prior handoff cert:
                // the overlay carries locally-cached blobs, so anchor them
                // against the prior epoch's cert — both the stable DKG digest
                // and the epoch-specific reconfiguration digest must match.
                if dkg_digests.get(key_id) != Some(&local_dkg_digest) {
                    // Same anomaly as above for a reconfigured key's
                    // stable DKG digest.
                    if self
                        .warned_cert_digest_mismatches
                        .insert((*key_id, local_dkg_digest))
                    {
                        warn!(
                            ?key_id,
                            cert_dkg_digest = ?dkg_digests.get(key_id),
                            local_dkg_digest = ?local_dkg_digest,
                            "local network-key DKG output digest does not match the prior \
                             epoch's handoff cert — skipping adoption"
                        );
                    } else {
                        debug!(
                            ?key_id,
                            "local network-key DKG output still contradicts the handoff \
                             cert — skipping adoption"
                        );
                    }
                    continue;
                }
                let local_reconfiguration_digest =
                    mpc_data_blob_hash(&data.current_reconfiguration_public_output);
                if reconfiguration_digests.get(key_id) != Some(&local_reconfiguration_digest) {
                    // NOT contradiction-only: once THIS epoch's
                    // reconfiguration completes, the overlay carries the
                    // new epoch-keyed output which by design mismatches
                    // the PRIOR epoch's cert — that skip is the intended
                    // defer-to-next-epoch with the already-adopted prior
                    // value still installed (debug). Only when the skip
                    // actually leaves the key unadopted is it the
                    // security-relevant divergence worth a warn.
                    if !self.adopted_network_key_data.contains_key(key_id) {
                        if self
                            .warned_cert_digest_mismatches
                            .insert((*key_id, local_reconfiguration_digest))
                        {
                            warn!(
                                ?key_id,
                                cert_reconfiguration_digest = ?reconfiguration_digests.get(key_id),
                                local_reconfiguration_digest = ?local_reconfiguration_digest,
                                "local network-key reconfiguration output digest does not \
                                 match the prior epoch's handoff cert and the key has no \
                                 adopted value — skipping adoption, the key stays \
                                 uninstantiated"
                            );
                        } else {
                            debug!(
                                ?key_id,
                                "local network-key reconfiguration output still contradicts \
                                 the handoff cert (key unadopted) — skipping adoption"
                            );
                        }
                    } else {
                        debug!(
                            ?key_id,
                            "overlay reconfiguration output does not match the prior \
                             epoch's cert (expected once this epoch's reconfiguration \
                             completes) — keeping the adopted prior value"
                        );
                    }
                    continue;
                }
            }
            // Reconfigured key with NO prior handoff cert to anchor against —
            // either off-chain is disabled (protocol v3), or this is the first
            // off-chain epoch right after the v3→v4 upgrade (the prior epoch
            // ran v3 and produced no cert). In both cases the overlay IS the
            // authoritative chain copy (the chain reconfiguration output is
            // quorum-processed on-chain), so adopt it directly. A handoff cert
            // is built durably every off-chain epoch, so `cert.is_none()` here
            // means only the genuine v3→v4 boundary, never a steady-state race.
            // Requiring a cert match with no cert (`dkg_digests` empty) would
            // skip every reconfigured key forever and wedge epoch advance.
            //
            // TODO(v3->v4 migration): the cert-less adoption of a *reconfigured*
            // key is the v3→v4 boundary path (a v4-native reconfigured key always
            // has a prior cert and is anchored by the `else if` branch above).
            // Once the upgrade is complete and every key is in the off-chain
            // handoff plane, tighten this so a reconfigured key with no cert is
            // rejected rather than blindly adopted from chain.

            // TODO(v3->v4 migration): don't let a transiently-empty overlay
            // DOWNGRADE a reconfiguration output we already hold non-empty this
            // epoch. At the v3→v4 boundary the syncer imports the pre-v4
            // reconfiguration output from chain for the few ticks until this
            // key's DKG output lands in the off-chain handoff; once it does, the
            // syncer's fast path resumes and synthesizes an EMPTY reconfiguration
            // output (the off-chain plane has no v3-produced reconfiguration blob
            // to fill it with). Adopting that empty value would re-instantiate
            // the key from its DKG output and lose the validator's current
            // share — re-wedging the first v4 reconfiguration. Keep the last
            // non-empty reconfiguration output instead; the legitimate next one
            // (this epoch's v4 reconfiguration) arrives non-empty and overwrites
            // it normally. Removable with the syncer chain-import once all keys
            // are off-chain.
            if data.current_reconfiguration_public_output.is_empty()
                && self
                    .adopted_network_key_data
                    .get(key_id)
                    .is_some_and(|existing| {
                        !existing.current_reconfiguration_public_output.is_empty()
                    })
            {
                continue;
            }
            // Surface the one place the cert-digest security gate is
            // bypassed: adopting a RECONFIGURED key without a prior
            // handoff cert anchoring it. Under v3 (off-chain disabled)
            // this is the designed every-epoch path; under v4 it is
            // expected only at the genuine v3→v4 boundary — anywhere
            // else it indicates a missing cert in steady state. Gated
            // on the adopted value actually changing so overlay
            // republishes don't re-log.
            let reconfigured = !data.current_reconfiguration_public_output.is_empty();
            let cert_anchored = off_chain_on && cert.is_some();
            let cert_gate_bypassed = reconfigured && !cert_anchored;
            if cert_gate_bypassed && self.adopted_network_key_data.get(key_id) != Some(data) {
                if off_chain_on {
                    warn!(
                        ?key_id,
                        "adopting reconfigured network key without a prior handoff cert — \
                         expected only at the v3→v4 boundary; in steady-state v4 this \
                         indicates a missing handoff cert"
                    );
                } else {
                    info!(
                        ?key_id,
                        "adopting reconfigured network key from the chain copy (off-chain \
                         metadata disabled; no handoff cert exists)"
                    );
                }
            }
            self.adopted_network_key_data.insert(*key_id, data.clone());
        }
        self.last_adoption_input = Some((overlay.clone(), cert.is_some()));
    }

    /// Handle NOA observation messages. Resolves finalization and failure quorums.
    /// Returns `(newly_finalized_tx_refs, newly_failed_tx_refs)`.
    pub fn handle_noa_observation_messages(
        &mut self,
        consensus_round: u64,
        messages: Vec<ConsensusNOAObservation>,
    ) -> (Vec<NOACheckpointTxRef>, Vec<(NOACheckpointTxRef, u32)>) {
        let mut newly_finalized = Vec::new();
        let mut newly_failed = Vec::new();

        for msg in messages {
            let sender_authority = msg.authority;

            let Ok(sender_party_id) =
                authority_name_to_party_id_from_committee(&self.committee, &sender_authority)
            else {
                error!(
                    sender_authority=?sender_authority,
                    consensus_round,
                    should_never_happen = true,
                    "got an NOA observation for an authority without party ID",
                );
                continue;
            };

            match msg.observation {
                NOACheckpointTxObservation::Finalized(tx_ref) => {
                    if self.finalized_tx_refs.contains(&tx_ref) {
                        continue;
                    }
                    let parties = self
                        .noa_finalization_observations
                        .entry(tx_ref.clone())
                        .or_default();
                    parties.insert(sender_party_id);
                    if self.access_structure.is_authorized_subset(parties).is_ok() {
                        self.finalized_tx_refs.insert(tx_ref.clone());
                        newly_finalized.push(tx_ref);
                    }
                }
                NOACheckpointTxObservation::Failed(tx_ref, retry_round) => {
                    if self.finalized_tx_refs.contains(&tx_ref) {
                        continue;
                    }
                    let key = (tx_ref.clone(), retry_round);
                    if self.failed_tx_ref_rounds.contains(&key) {
                        continue;
                    }
                    let parties = self
                        .noa_failure_observations
                        .entry(key.clone())
                        .or_default();
                    parties.insert(sender_party_id);
                    if self.access_structure.is_authorized_subset(parties).is_ok() {
                        self.failed_tx_ref_rounds.insert(key);
                        newly_failed.push((tx_ref, retry_round));
                    }
                }
            }
        }

        // Finalization takes precedence: filter out failures for already-finalized tx_refs.
        let newly_failed: Vec<_> = newly_failed
            .into_iter()
            .filter(|(tx_ref, _)| !self.finalized_tx_refs.contains(tx_ref))
            .collect();

        (newly_finalized, newly_failed)
    }

    /// Compute majority vote for idle status using the accumulated `idle_status_by_party`.
    fn compute_idle_status_majority_vote(&self) -> bool {
        if self.idle_status_by_party.is_empty() {
            return false;
        }

        // Clone is required because `weighted_majority_vote` consumes `self`
        // (defined in the external `mpc` crate).
        match self
            .idle_status_by_party
            .clone()
            .weighted_majority_vote(&self.access_structure)
        {
            Ok((_, majority_vote)) => majority_vote,
            Err(e) if matches!(e.kind, mpc::ErrorKind::ThresholdNotReached) => false,
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
    ///
    /// Requests beyond `last_session_to_complete_in_current_epoch` are held
    /// back: an agreed request is served from the internal pool and completed
    /// on-chain with no further lock check, and the end-of-publish predicate
    /// is a strict equality (`completed_sessions_count ==` locked target), so
    /// completing a session beyond the locked target wedges the epoch
    /// permanently — the counter can never come back down. The on-chain
    /// target is monotone within an epoch and frozen by the epoch-close
    /// lock, so a majority vote implies an honest validator observed the
    /// target covering the request, making overshoot impossible. Held-back
    /// requests are retried here as the synced target advances, and re-pulled
    /// next epoch otherwise — exactly like lock-gated MPC user sessions.
    pub(crate) fn get_unsent_presign_requests(&mut self) -> Vec<GlobalPresignRequest> {
        let (covered, deferred): (Vec<&GlobalPresignRequest>, Vec<&GlobalPresignRequest>) = self
            .global_presign_requests
            .iter()
            .filter(|request| {
                !self
                    .sent_presign_sequence_numbers
                    .contains(&request.session_sequence_number)
            })
            .partition(|request| {
                request.session_sequence_number <= self.last_session_to_complete_in_current_epoch
            });
        for request in deferred {
            if self
                .logged_lock_deferred_presigns
                .insert(request.session_sequence_number)
            {
                info!(
                    session_sequence_number = request.session_sequence_number,
                    last_session_to_complete_in_current_epoch =
                        self.last_session_to_complete_in_current_epoch,
                    session_identifier = ?request.session_identifier,
                    "holding global presign vote until the epoch-close lock target covers it; retried as the target advances, re-pulled next epoch otherwise"
                );
            }
        }
        covered.into_iter().cloned().collect()
    }

    /// Handles a message by forwarding it to the relevant MPC session.
    #[tracing::instrument(level = "trace", skip_all, fields(session_identifier = ?message.session_identifier))]
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
        trace!(
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
                debug!(
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
                    None, // chain unknown until request arrives
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
            self.validator_mpc_keys_by_party_id.clone(),
            &self.protocol_config,
        ) {
            Ok((public_input, private_input)) => SessionStatus::Active {
                public_input,
                private_input,
                request,
            },
            Err(e) => {
                if is_internal {
                    error!(                        should_never_happen = true, error=?e, ?request, "create internal session input from dWallet request with error");
                } else {
                    error!(error=?e, ?request, "create session input from dWallet request with error");
                }
                SessionStatus::Failed
            }
        }
    }

    /// Returns the network encryption key ID used for network-owned-address signing (the oldest by DKG epoch).
    /// Used by internal presign session instantiation to determine internal-signing-specific pool params.
    fn network_owned_address_signing_network_encryption_key_id(&self) -> Option<ObjectID> {
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
        let agreed_network_owned_address_signing_key_id =
            match self.network_owned_address_signing_network_encryption_key_id() {
                Some(id) => id,
                None => return,
            };

        // Ordered (`BTreeSet`) on purpose: the loop below assigns internal presign
        // session sequence numbers from a single shared counter in iteration order,
        // and the sequence number is bound into the session identifier. Every
        // validator must iterate keys (and curves/algorithms — see
        // `SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES`) in the same
        // order, or they derive different session identifiers for the same work
        // and the sessions never reach quorum.
        let agreed_key_ids: BTreeSet<_> = self.adopted_network_key_data.keys().copied().collect();
        let mut pools_filled: Vec<String> = Vec::new();
        for key_id in agreed_key_ids {
            for (curve, signature_algorithms) in supported_curve_to_signature_algorithms() {
                for signature_algorithm in signature_algorithms {
                    let is_network_owned_address_signing_presign =
                        agreed_network_owned_address_signing_key_id == key_id;

                    let (
                        minimal_pool_size,
                        maximum_pool_size,
                        consensus_round_delay,
                        sessions_to_instantiate,
                    ) = if is_network_owned_address_signing_presign {
                        (
                            self.protocol_config
                                .get_network_owned_address_presign_pool_minimum_size(
                                    signature_algorithm,
                                ),
                            self.protocol_config
                                .get_network_owned_address_presign_pool_maximum_size(
                                    signature_algorithm,
                                ),
                            self.protocol_config
                                .get_network_owned_address_presign_consensus_round_delay(
                                    signature_algorithm,
                                ),
                            self.protocol_config
                                .get_network_owned_address_presign_sessions_to_instantiate(
                                    signature_algorithm,
                                ),
                        )
                    } else {
                        (
                            self.protocol_config
                                .get_internal_presign_pool_minimum_size(curve, signature_algorithm),
                            self.protocol_config
                                .get_internal_presign_pool_maximum_size(curve, signature_algorithm),
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

                    // Export the pool size BEFORE the in-flight skip below,
                    // so a pool wedged behind never-completing sessions is
                    // still observable. The key dimension is reduced to a
                    // bounded `key_role` label — see the metric's docs.
                    let current_pool_size =
                        self.internal_presign_pool_size(key_id, curve, signature_algorithm);
                    let key_role = if is_network_owned_address_signing_presign {
                        "network_owned_address_signing"
                    } else {
                        "other"
                    };
                    let curve_label = format!("{curve:?}");
                    let signature_algorithm_label = format!("{signature_algorithm:?}");
                    self.dwallet_mpc_metrics
                        .internal_presign_pool_size
                        .with_label_values(&[
                            curve_label.as_str(),
                            signature_algorithm_label.as_str(),
                            key_role,
                        ])
                        .set(current_pool_size as i64);

                    // Skip instantiation if previous sessions for this (curve, algorithm)
                    // haven't completed yet. Each session produces a variable number of
                    // presigns (1 to n-t), so overlapping batches cause pool overshoot.
                    let instantiated = self
                        .instantiated_internal_presign_sessions
                        .get(&(curve, signature_algorithm))
                        .copied()
                        .unwrap_or(0);
                    let completed = self
                        .completed_internal_presign_sessions
                        .get(&(curve, signature_algorithm))
                        .copied()
                        .unwrap_or(0);
                    if instantiated != completed {
                        continue;
                    }

                    if (number_of_consensus_rounds.is_multiple_of(consensus_round_delay)
                        && current_pool_size < minimal_pool_size)
                        || (network_is_idle && current_pool_size < maximum_pool_size)
                    {
                        for _ in 1..=sessions_to_instantiate {
                            self.instantiate_internal_presign_session(
                                consensus_round,
                                key_id,
                                curve,
                                signature_algorithm,
                            );
                            *self
                                .instantiated_internal_presign_sessions
                                .entry((curve, signature_algorithm))
                                .or_insert(0) += 1;
                        }
                        pools_filled.push(format!(
                            "{curve:?}/{signature_algorithm:?}={current_pool_size}(min{minimal_pool_size})+{sessions_to_instantiate}"
                        ));
                    }
                }
            }
        }
        if !pools_filled.is_empty() {
            info!(
                consensus_round,
                pools = ?pools_filled,
                "Topping up internal presign pools",
            );
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
        // `consensus_round` is logged below for traceability but is
        // deliberately NOT part of the request/session identifier:
        // validators reach this point at different rounds (the network
        // key installs asynchronously), and the identifier must come out
        // identical on every committee member.
        let request = DWalletSessionRequest::new_internal_presign(
            self.epoch_id,
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

        debug!(
            status=?status,
            consensus_round,
            ?curve,
            ?signature_algorithm,
            ?session_sequence_number,
            ?session_identifier,
            "instantiating new internal presign session",
        );

        self.new_session(&session_identifier, status, None, session_computation_type);

        self.next_internal_presign_sequence_number += 1;
    }

    /// Instantiates a generic network-owned-address sign session.
    ///
    /// Pops a presign from the internal pool, wraps it, and creates the sign session.
    /// Returns `true` if the session was successfully instantiated, `false` on error.
    pub(super) fn instantiate_network_owned_address_sign_session(
        &mut self,
        message: Vec<u8>,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
        hash_scheme: DWalletHashScheme,
    ) -> bool {
        // Derive config values from the request
        let Some(dwallet_network_encryption_key_id) =
            self.network_owned_address_signing_network_encryption_key_id()
        else {
            error!(
                should_never_happen = true,
                "No network-owned-address signing network key available — caller should check \
                 has_network_owned_address_signing_network_key() first"
            );
            return false;
        };
        let hash_scheme_group: group::HashScheme = hash_scheme.into();
        let network_dkg_output_bytes = match self
            .network_keys
            .get_network_encryption_key_public_data(&dwallet_network_encryption_key_id)
        {
            Ok(key_data) => key_data.network_dkg_output().as_bytes().to_vec(),
            Err(e) => {
                error!(
                    ?dwallet_network_encryption_key_id,
                    error = ?e,
                    should_never_happen = true,
                    "Failed to get network encryption key data for network-owned-address sign session"
                );
                return false;
            }
        };

        // Try to get a presign from the internal presign pool
        let (presign_session_id, presign_blending_index, presign) = match self
            .epoch_store
            .pop_presign(signature_algorithm, dwallet_network_encryption_key_id)
        {
            Ok(Some(triple)) => triple,
            Ok(None) => {
                error!(
                    ?signature_algorithm,
                    should_never_happen = true,
                    "No presign available in pool — caller should check \
                     has_network_owned_address_signing_presign_available() first"
                );
                return false;
            }
            Err(e) => {
                error!(
                    ?signature_algorithm,
                    error = ?e,
                    should_never_happen = true,
                    "Failed to get presign from internal pool for network-owned-address signing"
                );
                return false;
            }
        };

        // Check if this presign has already been used (safety check)
        if self
            .epoch_store
            .is_presign_used(presign_session_id, presign_blending_index)
            .unwrap_or(false)
        {
            error!(
                ?presign_session_id,
                ?presign_blending_index,
                should_never_happen = true,
                "Presign has already been used — this should not happen"
            );
            return false;
        }

        // Mark the presign as used to prevent double-spending
        if let Err(e) = self
            .epoch_store
            .mark_presign_as_used(presign_session_id, presign_blending_index)
        {
            error!(
                ?presign_session_id,
                ?presign_blending_index,
                error = ?e,
                should_never_happen = true,
                "Failed to mark presign as used"
            );
            return false;
        }

        // Wrap the raw presign bytes in VersionedPresignOutput::V2 for consistency
        // with the sign session input path, which expects this wrapping.
        let wrapped_presign = match bcs::to_bytes(&VersionedPresignOutput::V2(presign)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    error = ?e,
                    should_never_happen = true,
                    "Failed to wrap presign in VersionedPresignOutput for network-owned-address sign"
                );
                return false;
            }
        };

        let request = DWalletSessionRequest::new_network_owned_address_sign(
            self.epoch_id,
            curve,
            signature_algorithm,
            hash_scheme_group,
            dwallet_network_encryption_key_id,
            &network_dkg_output_bytes,
            message.clone(),
            wrapped_presign,
        );

        let session_identifier = request.session_identifier;

        let status = self.session_status_from_request(request, true);

        let session_computation_type = SessionComputationType::MPC {
            messages_by_consensus_round: HashMap::new(),
        };

        info!(
            ?curve,
            ?signature_algorithm,
            ?session_identifier,
            message_length = message.len(),
            "instantiating network-owned-address sign session",
        );

        self.new_session(&session_identifier, status, None, session_computation_type);
        true
    }

    /// Checks if this manager has an network-owned-address signing network key available
    pub(super) fn has_network_owned_address_signing_network_key(&self) -> bool {
        self.network_owned_address_signing_network_encryption_key_id()
            .is_some()
    }

    /// Checks if this manager has a presign available for network-owned-address signing
    /// for the given signature algorithm.
    pub(super) fn has_network_owned_address_signing_presign_available(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> bool {
        let Some(key_id) = self.network_owned_address_signing_network_encryption_key_id() else {
            return false;
        };

        self.epoch_store
            .presign_pool_size(signature_algorithm, key_id)
            .unwrap_or(0)
            > 0
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

    /// Whether this validator has every frozen-set member's
    /// mpc_data blob locally available and decode-validated.
    /// Returns `true` under v3 (off_chain disabled — no frozen set
    /// to check), under v4 when the frozen set is still empty
    /// (freeze hasn't fired — caller's gate is purely additive,
    /// other gates govern session start), or when every authority
    /// in the frozen set has a blob whose hash matches the frozen
    /// digest AND the blob structurally decodes.
    ///
    /// Used by `perform_cryptographic_computation` to hold back
    /// network DKG / reconfig session messages on a validator
    /// whose P2P fan-out hasn't fully converged yet. The remedy
    /// is "wait until the next tick"; the rest of the network
    /// proceeds via threshold.
    fn local_mpc_data_ready_for_frozen_set(&self) -> bool {
        if !self.epoch_store.off_chain_validator_metadata_enabled() {
            return true;
        }
        let Ok(frozen) = self.epoch_store.get_frozen_mpc_data_input_set_trait() else {
            return true;
        };
        if frozen.is_empty() {
            // Freeze gate hasn't fired yet. The on-chain
            // session-activation gate is the single source of
            // truth for session start while the freeze is
            // still pending; the local-readiness gate just
            // doesn't have an opinion until the frozen set
            // materializes.
            return true;
        }
        let Some(perpetual) = self.epoch_store.perpetual_tables_handle() else {
            // Bootstrap window — `install_perpetual_tables_for_handoff`
            // hasn't fired yet. Behave like the empty-frozen-set
            // branch above ("no opinion") rather than blocking
            // every session forever. Compare
            // `compute_locally_validated_peers`, which also treats
            // an absent perpetual handle as "not enough info to
            // veto."
            tracing::debug!(
                "local readiness: perpetual tables not installed yet, deferring opinion"
            );
            return true;
        };
        for expected_digest in frozen.values() {
            let Ok(Some(bytes)) = perpetual.get_mpc_artifact_blob(expected_digest) else {
                return false;
            };
            if !crate::validator_metadata::blob_decodes_to_valid_mpc_data(&bytes) {
                return false;
            }
        }
        true
    }

    /// Creates a new session with SID `session_identifier`,
    /// and insert it into the MPC session map `self.mpc_sessions`.
    #[tracing::instrument(level = "debug", skip_all, fields(session_identifier = ?session_identifier, session_sequence_number = ?status.session_sequence_number()))]
    pub(super) fn new_session(
        &mut self,
        session_identifier: &SessionIdentifier,
        status: SessionStatus,
        counterparty_chain: Option<CounterpartyChainKind>,
        session_computation_type: SessionComputationType,
    ) {
        debug!(
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
            counterparty_chain,
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
                        if request.session_sequence_number.is_none() {
                            error!(
                                should_never_happen = true,
                                session_identifier = ?request.session_identifier,
                                "User session missing session_sequence_number",
                            );
                        }
                        request
                            .session_sequence_number
                            .expect("User sessions always have a session sequence number")
                            <= self.last_session_to_complete_in_current_epoch
                    }
                    SessionType::System => true,
                    SessionType::InternalPresign => true,
                    SessionType::NetworkOwnedAddressSign => true,
                };

                if !should_advance {
                    return None;
                }

                // Local-readiness gate for network DKG / reconfig
                // sessions under v4 off_chain mode. These sessions
                // consume the frozen-set members' mpc_data blobs
                // (class-groups keys). If the freeze gate has fired
                // but P2P propagation hasn't delivered every
                // frozen-set blob to this validator yet, we hold off
                // emitting our first-round message — other validators
                // proceed via threshold; we catch up on the next tick
                // once the missing blob lands. Without this gate, we
                // would emit a round message computed against an
                // incomplete view of peer class-groups material and
                // cross-reject in MPC.
                if matches!(
                    &request.protocol_data,
                    crate::request_protocol_data::ProtocolData::NetworkEncryptionKeyDkg { .. }
                        | crate::request_protocol_data::ProtocolData::NetworkEncryptionKeyReconfiguration { .. }
                ) && !self.local_mpc_data_ready_for_frozen_set()
                {
                    return None;
                }

                Some((session, request))
            })
            .collect();

        ready_to_advance_sessions
            .sort_by(|(_, request), (_, other_request)| request.cmp(other_request));

        let number_of_ready_to_advance_sessions = ready_to_advance_sessions.len();

        // Collected inside the immutable-borrow iteration below, logged
        // (deduped per session) after it ends — a generation failure
        // recurs every 20ms service tick for a stuck session, and the
        // skip used to be silent, which blinded post-mortems.
        let mut failed_cryptographic_data_generations = Vec::new();

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
                        should_never_happen = true,
                        session_identifier=?session.session_identifier,
                        "session is not active, cannot perform cryptographic computation",
                    );

                    return None;
                };

                let protocol_cryptographic_data = match self.generate_protocol_cryptographic_data(
                    &session.computation_type,
                    &request.protocol_data,
                    last_read_consensus_round,
                    public_input.clone(),
                    &self.protocol_config,
                ) {
                    Ok(protocol_cryptographic_data) => protocol_cryptographic_data,
                    Err(e) => {
                        // The skip is correct (the session simply isn't
                        // advanceable this tick); the silence was the bug.
                        failed_cryptographic_data_generations.push((
                            session.session_identifier,
                            DWalletSessionRequestMetricData::from(&request.protocol_data),
                            e,
                        ));

                        return None;
                    }
                };

                protocol_cryptographic_data.map(|protocol_cryptographic_data| {
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

        for (session_identifier, protocol_data, error) in failed_cryptographic_data_generations {
            // Once per session: the failure recurs every tick while the
            // session is stuck, and the first occurrence carries all the
            // signal.
            if self
                .warned_cryptographic_data_generation_failures
                .insert(session_identifier)
            {
                error!(
                    ?session_identifier,
                    mpc_protocol = %protocol_data,
                    error = ?error,
                    "failed to generate protocol cryptographic data — session skipped \
                     this tick (will retry every service iteration)"
                );
            }
        }

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

    /// Polls the in-flight network-key instantiations (non-blocking):
    /// each runs on the rayon pool for up to minutes, and the service
    /// loop must keep processing sessions in the meantime. Called once
    /// per service ITERATION — not per consensus round — so a completed
    /// key installs even when no new consensus rounds arrived. Returns
    /// the IDs whose instantiation completed and installed this poll.
    pub(crate) async fn poll_pending_network_key_instantiations(&mut self) -> Vec<ObjectID> {
        let mut new_key_ids = Vec::new();
        let in_flight_key_ids: Vec<ObjectID> = self
            .pending_network_key_instantiations
            .keys()
            .copied()
            .collect();
        for key_id in in_flight_key_ids {
            let Some(mut pending) = self.pending_network_key_instantiations.remove(&key_id) else {
                continue;
            };
            let res = match pending.receiver.try_recv() {
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Still computing — put it back and check next tick.
                    self.pending_network_key_instantiations
                        .insert(key_id, pending);
                    continue;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    // The computation dropped its sender without a result
                    // (panicked on the rayon pool). Record the attempt so
                    // identical bytes aren't retried every tick.
                    warn!(
                        key_id=?key_id,
                        "network key instantiation dropped its result channel; \
                         recording the attempt as failed"
                    );
                    self.dwallet_mpc_metrics
                        .network_key_instantiation_failures_total
                        .with_label_values(&["channel_closed"])
                        .inc();
                    self.last_failed_network_key_data
                        .insert(key_id, pending.attempted);
                    continue;
                }
                Ok(res) => res,
            };
            let attempted = pending.attempted;
            match res {
                Ok(key) => {
                    if key.epoch() != self.epoch_id {
                        warn!(
                            key_id=?key_id,
                            key_epoch=?key.epoch(),
                            current_epoch=?self.epoch_id,
                            "Adopted network key epoch does not match current epoch, ignoring"
                        );
                        self.dwallet_mpc_metrics
                            .network_key_instantiation_failures_total
                            .with_label_values(&["epoch_mismatch"])
                            .inc();
                        continue;
                    }
                    info!(key_id=?key_id, "Updating network key");
                    if let Err(e) = self
                        .network_keys
                        .update_network_key(key_id, &key, &self.access_structure)
                        .await
                    {
                        // Expected during churn: this validator can't yet
                        // decrypt its share from this output (not in its
                        // committee yet — a joiner mid-fold-in, or a
                        // departing validator). Record the bytes so the
                        // deterministic decryption isn't re-run on them
                        // every tick; it retries when the bytes change.
                        warn!(error=?e, key_id=?key_id, "could not decrypt share for network key from this output yet; will retry when its bytes change");
                        self.dwallet_mpc_metrics
                            .network_key_instantiation_failures_total
                            .with_label_values(&["decrypt_failed"])
                            .inc();
                        self.last_failed_network_key_data.insert(key_id, attempted);
                    } else {
                        // Mirror the adopted **DKG** output bytes
                        // into the local digest caches so validators that
                        // didn't reach `Finalize` locally still hold the
                        // stable, one-time DKG digest and can build the
                        // `NetworkDkgOutput` handoff item.
                        //
                        // The reconfiguration output is deliberately NOT
                        // mirrored here. It is epoch-specific, and
                        // `adopted_network_key_data` can still carry the
                        // *prior* epoch's output (the adopted overlay can lag the local
                        // computation), so mirroring it would race the
                        // local current value and corrupt the handoff
                        // `NetworkReconfigurationOutput` digest — the
                        // stale-vs-current `AttestationMismatch`. The
                        // handoff sources the reconfiguration digest from
                        // the local-MPC write only, keyed by the
                        // reconfiguration session's own epoch
                        // (`get_network_reconfiguration_output_digests_for_epoch`);
                        // a validator that didn't compute this epoch's
                        // reconfiguration is excluded from that item by
                        // design (the computing validators are a quorum).
                        //
                        // TODO(v3->v4 migration): only mirror the DKG into the
                        // off-chain handoff once off-chain metadata is enabled
                        // (v4). The handoff itself is v4-only, so mirroring at v3
                        // is otherwise pointless — but it is load-bearing for the
                        // v3->v4 boundary: the syncer's temporary chain import
                        // gates on "DKG present in the off-chain handoff" to tell
                        // a not-yet-migrated pre-v4 key (DKG only on chain → keep
                        // importing the chain reconfiguration output) from a
                        // migrated one. If we mirrored the DKG during the v3
                        // epochs, that gate would read "present" at the first v4
                        // epoch and skip the import, leaving the pre-v4
                        // reconfiguration output undelivered and wedging the
                        // first v4 reconfiguration. Remove this guard (always
                        // mirror) once the migration chain import is gone.
                        let key_data = self.adopted_network_key_data.get(&key_id).cloned();
                        if let Some(key_data) = key_data {
                            if self.epoch_store.off_chain_validator_metadata_enabled()
                                && !key_data.network_dkg_public_output.is_empty()
                                && let Err(e) = self.epoch_store.cache_network_dkg_output(
                                    key_id,
                                    &key_data.network_dkg_public_output,
                                )
                            {
                                warn!(
                                    error = ?e,
                                    ?key_id,
                                    "failed to cache DKG output digest from adopted data"
                                );
                            }
                            // Snapshot the data we just instantiated so
                            // the next poll skips this key unless a
                            // newer quorum has overwritten
                            // `adopted_network_key_data` since.
                            self.last_instantiated_network_key_data
                                .insert(key_id, key_data);
                        }
                        // Succeeded — drop any prior failure record.
                        self.last_failed_network_key_data.remove(&key_id);
                        new_key_ids.push(key_id);
                    }
                }
                Err(err) => {
                    warn!(
                        error=?err,
                        key_id=?key_id,
                        "could not instantiate network key from this output yet; will retry when its bytes change"
                    );
                    self.dwallet_mpc_metrics
                        .network_key_instantiation_failures_total
                        .with_label_values(&["instantiate_failed"])
                        .inc();
                    self.last_failed_network_key_data.insert(key_id, attempted);
                }
            }
        }
        self.dwallet_mpc_metrics
            .network_key_instantiations_in_flight
            .set(self.pending_network_key_instantiations.len() as i64);

        new_key_ids
    }

    /// Instantiates network keys from the cert-verified outputs adopted into `adopted_network_key_data`.
    /// For each key in `adopted_network_key_data` either (a) not yet
    /// loaded locally, or (b) loaded but with a stale shape compared
    /// to the latest agreed bytes (typically the reconfig output
    /// flipping each epoch), SPAWNS the instantiation on the rayon
    /// pool — the instantiation is an expensive, long-running
    /// computation, and awaiting it inline froze every session on the
    /// validator for its full duration at each epoch boundary.
    /// Completions are collected
    /// by [`Self::poll_pending_network_key_instantiations`].
    ///
    /// The `last_instantiated_network_key_data` snapshot prevents
    /// re-running on every poll: re-instantiation costs a per-curve
    /// decrypt + key-share regenerate inside `update_network_key`,
    /// so we only do it when the agreed bytes actually changed.
    pub(crate) fn instantiate_adopted_network_keys(&mut self) {
        let keys_to_instantiate: Vec<(ObjectID, DWalletNetworkEncryptionKeyData)> = self
            .adopted_network_key_data
            .iter()
            .filter(|(key_id, key_data)| {
                // An instantiation for this key is already in flight —
                // don't spawn another; if the agreed bytes moved in the
                // meantime, the snapshot comparison below re-fires once
                // the in-flight one completes.
                if self.pending_network_key_instantiations.contains_key(key_id) {
                    return false;
                }
                // The adopted snapshot can carry a stale chain epoch — the
                // syncer fetched it before the chain rolled over (or after,
                // for a manager about to be torn down). The post-instantiation
                // poll already rejects such a key (`key.epoch() != self.epoch_id`),
                // but only after ~10s of parameter derivation burnt on the
                // rayon pool — and while that doomed instantiation is in
                // flight, the correct same-key data cannot spawn. Reject the
                // metadata mismatch before spawning instead; the syncer
                // re-fetches and the adoption pass delivers the current
                // epoch's data within a few ticks.
                if key_data.current_epoch != self.epoch_id {
                    debug!(
                        ?key_id,
                        key_data_epoch = key_data.current_epoch,
                        current_epoch = self.epoch_id,
                        "adopted network-key data carries a different epoch — not \
                         spawning instantiation; awaiting the current epoch's overlay"
                    );
                    return false;
                }
                // Filter to: first instantiation OR the *content*
                // (DKG output, reconfig output, state) has moved
                // since we last instantiated. Excludes the per-epoch
                // `current_epoch` field, which flips every epoch
                // boundary even when the underlying bytes are
                // unchanged and would otherwise force a wasteful
                // `update_network_key` pass that re-decrypts the key
                // shares.
                if !self
                    .network_keys
                    .network_encryption_keys
                    .contains_key(key_id)
                {
                    return true;
                }
                match self.last_instantiated_network_key_data.get(key_id) {
                    // Never instantiated this key. Attempt it — unless we
                    // already failed to decrypt these exact bytes. The
                    // decryption is deterministic, so identical bytes
                    // would fail identically; retry only once the bytes
                    // change (the output carrying our share arrives).
                    None => match self.last_failed_network_key_data.get(key_id) {
                        None => true,
                        Some(failed) => {
                            failed.network_dkg_public_output != key_data.network_dkg_public_output
                                || failed.current_reconfiguration_public_output
                                    != key_data.current_reconfiguration_public_output
                                || failed.state != key_data.state
                        }
                    },
                    Some(prev) => {
                        prev.network_dkg_public_output != key_data.network_dkg_public_output
                            || prev.current_reconfiguration_public_output
                                != key_data.current_reconfiguration_public_output
                            || prev.state != key_data.state
                    }
                }
            })
            .map(|(key_id, key_data)| (*key_id, key_data.clone()))
            .collect();

        for (key_id, key_data) in keys_to_instantiate {
            info!(key_id=?key_id, "Instantiating agreed network key");
            // Retained for the failure path (the bytes are moved into
            // instantiation below) so we can record what failed and skip
            // re-attempting identical bytes next tick.
            let attempted = key_data.clone();
            let receiver = spawn_network_encryption_key_public_data_instantiation(
                key_data.current_epoch,
                self.access_structure.clone(),
                key_data,
                self.dwallet_mpc_metrics.clone(),
            );
            self.pending_network_key_instantiations.insert(
                key_id,
                PendingNetworkKeyInstantiation {
                    attempted,
                    receiver,
                },
            );
        }
        self.dwallet_mpc_metrics
            .network_key_instantiations_in_flight
            .set(self.pending_network_key_instantiations.len() as i64);
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
                    None, // chain unknown until request arrives
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
                curve,
                signature_algorithm,
                session_sequence_number,
                dwallet_network_encryption_key_id,
            } => {
                match signature_algorithm {
                    DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                        self.record_internal_presign_output::<Secp256k1ECDSAProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                        self.record_internal_presign_output::<Secp256r1ECDSAProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::EdDSA => {
                        self.record_internal_presign_output::<Curve25519EdDSAProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::Schnorrkel => {
                        self.record_internal_presign_output::<RistrettoSchnorrkelProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::Taproot => {
                        self.record_internal_presign_output::<Secp256k1TaprootProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                }
                *self
                    .completed_internal_presign_sessions
                    .entry((curve, signature_algorithm))
                    .or_insert(0) += 1;
            }
            DWalletInternalMPCOutputKind::NetworkOwnedAddressSign {
                output,
                session_identifier,
                message,
                curve,
                signature_algorithm,
                hash_scheme,
            } => {
                info!(
                    ?session_identifier,
                    ?curve,
                    ?signature_algorithm,
                    signature_length = output.len(),
                    signature_hex = %hex::encode(&output),
                    "Network-owned-address sign completed"
                );
                let sign_output = NetworkOwnedAddressSignOutput {
                    session_identifier,
                    message,
                    signature: output,
                    curve,
                    signature_algorithm,
                    hash_scheme,
                };
                if let Err(e) = self
                    .network_owned_address_sign_output_sender
                    .try_send(sign_output)
                {
                    error!(
                        ?session_identifier,
                        error = ?e,
                        should_never_happen = true,
                        "Failed to send network-owned-address sign output to channel"
                    );
                }
            }
        }
    }

    fn record_internal_presign_output<P: twopc_mpc::presign::Protocol>(
        &mut self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
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
            dwallet_network_encryption_key_id,
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

        let pool_new_size = self
            .epoch_store
            .presign_pool_size(signature_algorithm, dwallet_network_encryption_key_id)
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
        outputs_by_consensus_round: BTreeMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
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
            Err(e) if matches!(e.kind, mpc::ErrorKind::ThresholdNotReached) => None,
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

    pub(crate) fn mark_global_presign_request_fulfilled(&mut self, session_sequence_number: u64) {
        self.completed_presign_sequence_numbers
            .insert(session_sequence_number);
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
                    None, // chain unknown until request arrives
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
