// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible for draining each consensus round's DWallet MPC messages
//! off the bounded channel the consensus fold feeds
//! (`authority::round_transport`), every [`READ_INTERVAL_MS`] milliseconds,
//! and forwarding them to the [`DWalletMPCManager`].
//!
//! Nothing on this path reads a per-round table: the rounds arrive in memory,
//! and a drain that falls behind blocks the fold rather than accumulating
//! rows behind it.

use crate::SuiDataReceivers;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStoreTrait, NoaPresignDemandResolution, PresignAssignmentOutcome,
    PresignDemand,
};
use crate::authority::round_transport::{ConsensusRoundPayload, RoundTransportReceiver};
use crate::authority::{AuthorityState, AuthorityStateTrait};
use crate::consensus_manager::ReplayWaiter;
use crate::dwallet_checkpoints::{
    DWalletCheckpointServiceNotify, PendingDWalletCheckpoint, PendingDWalletCheckpointInfo,
    PendingDWalletCheckpointV1,
};
use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::dwallet_mpc_metrics::{DWalletMPCMetrics, session_type_label};
use crate::dwallet_mpc::mpc_diagnostics::{
    MpcAnomalyContext, MpcAnomalyKind, dwallet_mpc_error_diagnostic, output_digest,
    raw_output_digest,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::{
    ComputationResultData, SessionComputationType, SessionStatus,
};
use crate::dwallet_mpc::park_drain_test_hook::park_mpc_drain_hook;
use crate::dwallet_mpc::party_ids_to_authority_names;
use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use crate::noa_checkpoints::NOACheckpointHandler;
use crate::request_protocol_data::ProtocolData;
use arc_swap::ArcSwap;
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ValidatorMPCSecrets;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use dwallet_mpc_types::dwallet_mpc::VersionedPresignOutput;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, MPCMessage};
#[cfg(any(test, feature = "test-utils"))]
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use fastcrypto::traits::KeyPair;
use ika_config::NodeConfig;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee, EpochId};
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaError;
use ika_types::message::{
    DWalletCheckpointMessageKind, DWalletDKGOutput, DWalletImportedKeyVerificationOutput,
    EncryptedUserShareOutput, MPCNetworkDKGOutput, MPCNetworkReconfigurationOutput,
    MakeDWalletUserSecretKeySharesPublicOutput, PartialSignatureVerificationOutput, PresignOutput,
    SignOutput,
};
use ika_types::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind};
use ika_types::messages_dwallet_mpc::{
    ConsensusNOAPresignDemand, DWalletInternalMPCOutputKind, DWalletMPCOutputKind,
    DWalletMPCOutputReport, GlobalPresignRequest, IdleStatusUpdate, SessionIdentifier, SessionType,
    SuiChainObservationUpdate, UserSecretKeyShareEventType,
};
use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
use ika_types::noa_checkpoint;
use ika_types::noa_checkpoint::{
    CounterpartyChainKind, NOACheckpointKindName, NOACheckpointTxObservation, SuiChainContext,
    SuiChainObservation,
};
use ika_types::sui::EpochStartSystem;
use ika_types::sui::{EpochStartSystemTrait, EpochStartValidatorInfoTrait};
use itertools::Itertools;
use mpc::GuaranteedOutputDeliveryRoundResult;
#[cfg(any(test, feature = "test-utils"))]
use prometheus::Registry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sui_types::base_types::ObjectID;
use sui_types::messages_consensus::Round;
use tokio::sync::mpsc::error::TryRecvError;
#[cfg(any(test, feature = "test-utils"))]
use tokio::sync::watch;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

const READ_INTERVAL_MS: u64 = 20;
const FIVE_KILO_BYTES: usize = 5 * 1024;

pub const NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY: usize = 1024;

/// How many consensus rounds a network-owned-address presign demand may stay
/// parked in the assignment drain before it is dropped.
///
/// A demand carries the network encryption key it was announced under, and the
/// presign pool is keyed by that id, so a demand naming a key this validator
/// holds no pool for cannot be assigned. It parks (kept in consensus-delivery
/// order, retried every round) rather than being rejected, because honest
/// validators do transiently hold different adopted key sets and a local
/// reject would turn that lag into a permanent drop — the reasoning is in
/// `dev-docs/specs/internal-presign-pool.md`. Without an upper bound, a demand
/// naming a key NO validator will ever adopt parks for the rest of the epoch
/// and blocks that epoch's NOA checkpoint finalization.
///
/// Rounds, not wall clock, so the drop decision is identical on every
/// validator (see `DWalletMPCService::drain_consensus_rounds`).
///
/// The value is ~1 hour of mainnet consensus at ~19.5 rounds/s (the rate the
/// catch-up gate is calibrated against — see `CATCH_UP_ENTER_GAP_ROUNDS`).
/// That sits far above every window in which an honest validator can still be
/// missing a key or its pool:
/// - the network-key syncer re-merges the overlay every 5s (~100 rounds);
/// - a restarting or joining validator recovers a stranded key by chain read
///   and then instantiates class groups for it — minutes, so at most low tens
///   of thousands of rounds;
/// - a freshly adopted key's presign pool is filled by internal-presign MPC,
///   again minutes.
///
/// And far below the epoch it has to fit inside: a 24h epoch is ~1.7M rounds,
/// so the bound spends ~4% of an epoch waiting before giving up on a demand.
///
/// A compile-time constant is safe only while demands cannot reach the wire:
/// announcements are gated on `noa_checkpoints()`, which is off on every live
/// network, so no committee can currently be split across two values of it.
/// Once that flag is on, changing this number is a consensus-affecting change
/// — validators running different values would drop different demands — and
/// it has to move into `ProtocolConfig`, where a change is version-gated
/// rather than binary-driven.
const NOA_PRESIGN_DEMAND_PARK_ROUNDS: u64 = 70_000;

/// A consensus-agreed NOA presign demand waiting in the assignment drain,
/// together with the consensus round that delivered it.
///
/// The delivery round is what the park bound measures from. It comes from the
/// consensus stream, so it holds the same value on every validator, and it
/// rebuilds identically when a restarted validator replays the epoch's rounds.
struct ParkedNOAPresignDemand {
    demand: ConsensusNOAPresignDemand,
    delivered_at_consensus_round: Round,
}

fn diagnostic_output_digest(message: &ConsensusTransaction) -> Option<[u8; 32]> {
    let report = match &message.kind {
        ConsensusTransactionKind::DWalletMPCOutput(output) => {
            DWalletMPCOutputReport::External(output.clone())
        }
        ConsensusTransactionKind::DWalletInternalMPCOutput(output) => {
            DWalletMPCOutputReport::Internal(output.clone())
        }
        _ => return None,
    };
    report.output().ok().as_ref().and_then(output_digest)
}

pub struct DWalletMPCService {
    last_read_consensus_round: Option<Round>,
    pub(crate) epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
    /// Where this service's per-round inputs arrive from: the bounded channel
    /// the consensus fold feeds. `None` on a process that folds commits but
    /// runs no drain.
    pub(crate) round_receiver: Option<RoundTransportReceiver>,
    dwallet_submit_to_consensus: Arc<dyn DWalletMPCSubmitToConsensus>,
    state: Arc<dyn AuthorityStateTrait>,
    dwallet_checkpoint_service: Option<Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>>,
    dwallet_mpc_manager: DWalletMPCManager,
    exit: Receiver<()>,
    end_of_publish: bool,
    dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    pub sui_data_requests: SuiDataReceivers,
    pub name: AuthorityName,
    pub epoch: EpochId,
    pub protocol_config: ProtocolConfig,
    pub committee: Arc<Committee>,
    /// Tracks the last sent idle status to avoid sending duplicate updates.
    last_sent_idle_status: Option<bool>,
    /// The number of consensus rounds since epoch started.
    /// Needed because the consensus rounds themselves might not be consecutive.
    number_of_consensus_rounds: u64,
    /// Whether the boot replay has released this drain, i.e. whether it is on
    /// the live path rather than inside [`Self::drain_while_replaying`].
    ///
    /// Only the test park hook reads it, and only so that the hook cannot park
    /// a drain the boot replay is still parked behind — see
    /// [`park_drain_test_hook`]. Production behaviour is identical either way.
    ///
    /// [`park_drain_test_hook`]: crate::dwallet_mpc::park_drain_test_hook
    drain_released_by_replay: bool,
    /// Rounds consumed since the boot replay released the drain. The park
    /// hook's threshold is measured in these, NOT in
    /// [`Self::number_of_consensus_rounds`], which counts the replay's rounds
    /// too and so cannot express "park once you are live" without knowing how
    /// deep the replay was.
    rounds_consumed_since_replay: u64,
    /// Is the network considered in an idle state?
    /// If so, we can process more internal presign sessions to make use of resources.
    network_is_idle: bool,
    agreed_global_presign_requests_queue: Vec<GlobalPresignRequest>,
    processed_global_presign_sequence_numbers: HashSet<u64>,
    /// Admission-rejected requests whose rejection output is held back until
    /// the epoch-close lock target covers their sequence number; retried each
    /// service loop iteration. A rejection that reaches quorum completes the
    /// session on-chain, and completing a user session beyond the locked
    /// target permanently wedges the epoch (the end-of-publish predicate is
    /// a strict equality).
    pending_rejected_sessions: Vec<DWalletSessionRequest>,
    /// Receiver for network-owned-address sign requests.
    network_owned_address_sign_requests_receiver:
        tokio::sync::mpsc::Receiver<NetworkOwnedAddressSignRequest>,
    /// Buffer for network-owned-address sign requests that couldn't be processed yet
    /// (e.g., key not yet agreed). Retried each service loop iteration.
    pending_network_owned_address_sign_requests: Vec<NetworkOwnedAddressSignRequest>,
    /// Last time the NOA-sign starvation warn fired. The service loop runs
    /// every 20ms, so the "requests waiting, pool empty / key unavailable"
    /// warn MUST be throttled (at most once per 30s).
    last_noa_starvation_log: Option<Instant>,
    /// Set of message hashes that have already been submitted for signing.
    /// Uses 32-byte Blake2b digests instead of full messages to bound memory.
    submitted_noa_sign_messages: HashSet<[u8; 32]>,
    /// Last sent Sui chain observation, to avoid sending duplicate updates.
    last_sent_sui_chain_observation: Option<SuiChainObservation>,
    /// Persistent context from the latest consensus-agreed Sui chain observation.
    /// `None` until the first quorum agreement on Sui chain context.
    current_agreed_sui_chain_context: Option<SuiChainContext>,
    /// Buffered dwallet checkpoint messages waiting for context agreement.
    buffered_noa_dwallet_messages: Vec<Vec<DWalletCheckpointMessageKind>>,
    /// Buffered system checkpoint messages waiting for context agreement.
    buffered_noa_system_messages: Vec<Vec<SystemCheckpointMessageKind>>,
    /// Buffered NOA checkpoint observations to include in the next status update.
    buffered_noa_observations: Vec<NOACheckpointTxObservation>,
    /// NOA sign presign demands announced this iteration, awaiting submission to
    /// consensus in the next status update.
    ///
    /// These three fields are per-epoch: they rebuild empty when the per-epoch
    /// service is reconstructed at an epoch boundary. The presign pool and the
    /// `noa_presign_demand_resolutions` table they feed are also per-epoch, so a
    /// rebuild simply re-announces any still-pending demand (consensus dedup and
    /// the idempotent resolution table absorb the duplicate) — while a demand
    /// the drain already resolved is not re-announced at all, because that
    /// resolution outlives the rebuild.
    buffered_noa_presign_demands: Vec<ConsensusNOAPresignDemand>,
    /// NOA sign presign demands agreed via consensus, drained in
    /// consensus-delivery order to assign each a presign (kept across rounds
    /// when the pool is momentarily empty, up to
    /// [`NOA_PRESIGN_DEMAND_PARK_ROUNDS`]).
    agreed_noa_presign_demands_queue: Vec<ParkedNOAPresignDemand>,
    /// Digests of demands this validator has already announced this epoch, so it
    /// announces each demand at most once.
    announced_noa_demand_digests: HashSet<[u8; 32]>,
    /// Consensus rounds a demand may stay parked before the drain drops it.
    /// [`NOA_PRESIGN_DEMAND_PARK_ROUNDS`] in production; only tests override
    /// it. The value is part of a consensus-uniform predicate, so every
    /// validator must run the same one — it is deliberately NOT node
    /// configuration.
    noa_presign_demand_park_rounds: u64,
    /// Receiver for sign outputs from MPC manager to route to NOA checkpoint handlers.
    network_owned_address_sign_output_receiver:
        tokio::sync::mpsc::Receiver<NetworkOwnedAddressSignOutput>,
    /// DWallet checkpoint handler, driven directly by the service.
    dwallet_checkpoint_handler: Option<NOACheckpointHandler<noa_checkpoint::SuiDWalletCheckpoint>>,
    /// System checkpoint handler, driven directly by the service.
    system_checkpoint_handler: Option<NOACheckpointHandler<noa_checkpoint::SuiSystemCheckpoint>>,
}

impl DWalletMPCService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
        round_receiver: RoundTransportReceiver,
        exit: Receiver<()>,
        consensus_adapter: Arc<dyn DWalletMPCSubmitToConsensus>,
        node_config: NodeConfig,
        dwallet_checkpoint_service: Option<Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>>,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        state: Arc<AuthorityState>,
        sui_data_receivers: SuiDataReceivers,
        validator_name: AuthorityName,
        epoch_id: sui_types::base_types::EpochId,
        committee: Arc<Committee>,
        protocol_config: ProtocolConfig,
        network_owned_address_sign_requests_receiver: tokio::sync::mpsc::Receiver<
            NetworkOwnedAddressSignRequest,
        >,
        network_owned_address_sign_output_sender: tokio::sync::mpsc::Sender<
            NetworkOwnedAddressSignOutput,
        >,
        network_owned_address_sign_output_receiver: tokio::sync::mpsc::Receiver<
            NetworkOwnedAddressSignOutput,
        >,
        dwallet_checkpoint_handler: Option<
            NOACheckpointHandler<noa_checkpoint::SuiDWalletCheckpoint>,
        >,
        system_checkpoint_handler: Option<
            NOACheckpointHandler<noa_checkpoint::SuiSystemCheckpoint>,
        >,
        // Shared set of restart-stranded network keys (created once at the
        // node seam, also handed to the sui-connector syncer). The manager
        // flags a stranded key at adoption and un-flags it on confirmed
        // instantiation; the syncer chain-reads flagged keys.
        stranded_network_keys: Arc<ArcSwap<HashSet<ObjectID>>>,
    ) -> Self {
        let network_dkg_third_round_delay = protocol_config.network_dkg_third_round_delay();

        let decryption_key_reconfiguration_third_round_delay =
            protocol_config.decryption_key_reconfiguration_third_round_delay();

        // None below protocol v4 — external Schnorr presigns at v3 must
        // advance exactly like 1.1.8 (no delay); 0 entries are omitted from
        // the delay map entirely.
        let schnorr_presign_second_round_delay = protocol_config
            .schnorr_presign_second_round_delay_as_option()
            .unwrap_or(0);

        let max_mpc_computation_cores = node_config.max_mpc_computation_cores;
        let root_seed = match node_config.root_seed_key_pair {
            None => {
                error!("root_seed is not set in the node config, cannot start DWallet MPC service");
                panic!("root_seed is not set in the node config, cannot start DWallet MPC service");
            }
            Some(root_seed) => root_seed.root_seed().clone(),
        };

        let mut dwallet_mpc_manager = DWalletMPCManager::new(
            validator_name,
            committee.clone(),
            epoch_id,
            root_seed,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            schnorr_presign_second_round_delay,
            dwallet_mpc_metrics.clone(),
            sui_data_receivers.clone(),
            protocol_config.clone(),
            epoch_store.clone(),
            network_owned_address_sign_output_sender,
            max_mpc_computation_cores,
            stranded_network_keys,
        );
        // Self-malicious diagnostic snapshots are mirrored to disk beside the
        // databases (NOT under `db_path()`/live, which is RocksDB-managed):
        // the convicted validator's service stops right after emitting them,
        // and its log stream — the only other copy — rotates out within hours
        // at validator log volumes (#1978).
        dwallet_mpc_manager.set_diagnostics_dir(node_config.db_path.join("mpc_diagnostics"));

        Self {
            last_read_consensus_round: None,
            epoch_store: epoch_store.clone(),
            round_receiver: Some(round_receiver),
            dwallet_submit_to_consensus: consensus_adapter,
            state,
            dwallet_checkpoint_service,
            dwallet_mpc_manager,
            exit,
            end_of_publish: false,
            dwallet_mpc_metrics,
            sui_data_requests: sui_data_receivers.clone(),
            name: validator_name,
            epoch: epoch_id,
            protocol_config,
            committee,
            last_sent_idle_status: None,
            number_of_consensus_rounds: 0,
            drain_released_by_replay: false,
            rounds_consumed_since_replay: 0,
            network_is_idle: false,
            agreed_global_presign_requests_queue: Vec::new(),
            processed_global_presign_sequence_numbers: HashSet::new(),
            pending_rejected_sessions: Vec::new(),
            network_owned_address_sign_requests_receiver,
            pending_network_owned_address_sign_requests: Vec::new(),
            last_noa_starvation_log: None,
            submitted_noa_sign_messages: HashSet::new(),
            last_sent_sui_chain_observation: None,
            current_agreed_sui_chain_context: None,
            buffered_noa_dwallet_messages: Vec::new(),
            buffered_noa_system_messages: Vec::new(),
            buffered_noa_observations: Vec::new(),
            buffered_noa_presign_demands: Vec::new(),
            agreed_noa_presign_demands_queue: Vec::new(),
            announced_noa_demand_digests: HashSet::new(),
            noa_presign_demand_park_rounds: NOA_PRESIGN_DEMAND_PARK_ROUNDS,
            network_owned_address_sign_output_receiver,
            dwallet_checkpoint_handler,
            system_checkpoint_handler,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn new_for_testing(
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
        round_receiver: RoundTransportReceiver,
        seed: RootSeed,
        dwallet_submit_to_consensus: Arc<dyn DWalletMPCSubmitToConsensus>,
        authority_state: Arc<dyn AuthorityStateTrait>,
        checkpoint_service: Option<Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>>,
        authority_name: AuthorityName,
        committee: Committee,
        sui_data_receivers: SuiDataReceivers,
    ) -> (
        Self,
        tokio::sync::mpsc::Sender<NetworkOwnedAddressSignRequest>,
        tokio::sync::mpsc::Receiver<NetworkOwnedAddressSignOutput>,
    ) {
        let (
            network_owned_address_sign_request_sender,
            network_owned_address_sign_request_receiver,
        ) = tokio::sync::mpsc::channel::<NetworkOwnedAddressSignRequest>(
            NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
        );

        let (network_owned_address_sign_output_sender, network_owned_address_sign_output_receiver) =
            tokio::sync::mpsc::channel::<NetworkOwnedAddressSignOutput>(
                NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
            );

        let service = DWalletMPCService {
            last_read_consensus_round: Some(0),
            epoch_store: epoch_store.clone(),
            // A REAL receiver, on the real channel the harness's stand-in fold
            // sends into. This used to be `None`, which made the drain a no-op
            // and left every integration test exercising nothing of the round
            // path at all.
            round_receiver: Some(round_receiver),
            dwallet_submit_to_consensus,
            state: authority_state,
            dwallet_checkpoint_service: checkpoint_service,
            dwallet_mpc_manager: DWalletMPCManager::new(
                authority_name,
                Arc::new(committee.clone()),
                1,
                seed,
                0,
                0,
                0,
                DWalletMPCMetrics::new(&Registry::new()),
                sui_data_receivers.clone(),
                ProtocolConfig::get_for_max_version_UNSAFE(),
                epoch_store,
                network_owned_address_sign_output_sender,
                None,
                Arc::new(ArcSwap::from_pointee(HashSet::new())),
            ),
            exit: watch::channel(()).1,
            end_of_publish: false,
            dwallet_mpc_metrics: DWalletMPCMetrics::new(&Registry::new()),
            sui_data_requests: sui_data_receivers,
            name: authority_name,
            epoch: 1,
            protocol_config: ProtocolConfig::get_for_max_version_UNSAFE(),
            committee: Arc::new(committee),
            last_sent_idle_status: None,
            number_of_consensus_rounds: 0,
            drain_released_by_replay: false,
            rounds_consumed_since_replay: 0,
            network_is_idle: false,
            processed_global_presign_sequence_numbers: HashSet::new(),
            agreed_global_presign_requests_queue: Vec::new(),
            pending_rejected_sessions: Vec::new(),
            network_owned_address_sign_requests_receiver:
                network_owned_address_sign_request_receiver,
            pending_network_owned_address_sign_requests: Vec::new(),
            last_noa_starvation_log: None,
            submitted_noa_sign_messages: HashSet::new(),
            last_sent_sui_chain_observation: None,
            current_agreed_sui_chain_context: None,
            buffered_noa_dwallet_messages: Vec::new(),
            buffered_noa_system_messages: Vec::new(),
            buffered_noa_observations: Vec::new(),
            buffered_noa_presign_demands: Vec::new(),
            agreed_noa_presign_demands_queue: Vec::new(),
            announced_noa_demand_digests: HashSet::new(),
            noa_presign_demand_park_rounds: NOA_PRESIGN_DEMAND_PARK_ROUNDS,
            network_owned_address_sign_output_receiver: tokio::sync::mpsc::channel(
                NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
            )
            .1,
            dwallet_checkpoint_handler: None,
            system_checkpoint_handler: None,
        };

        (
            service,
            network_owned_address_sign_request_sender,
            network_owned_address_sign_output_receiver,
        )
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn dwallet_mpc_manager(&self) -> &DWalletMPCManager {
        &self.dwallet_mpc_manager
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn dwallet_mpc_manager_mut(&mut self) -> &mut DWalletMPCManager {
        &mut self.dwallet_mpc_manager
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn number_of_consensus_rounds(&self) -> u64 {
        self.number_of_consensus_rounds
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn network_is_idle(&self) -> bool {
        self.network_is_idle
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn pending_network_owned_address_sign_request_count(&self) -> usize {
        self.pending_network_owned_address_sign_requests.len()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn last_read_consensus_round(&self) -> Option<Round> {
        self.last_read_consensus_round
    }

    /// Shrinks the demand park bound so a test can reach it in a handful of
    /// rounds instead of [`NOA_PRESIGN_DEMAND_PARK_ROUNDS`]. Never call this
    /// outside tests: validators that disagree on the bound disagree on which
    /// demands were dropped.
    #[cfg(test)]
    pub(crate) fn set_noa_presign_demand_park_rounds_for_testing(&mut self, rounds: u64) {
        self.noa_presign_demand_park_rounds = rounds;
    }

    #[cfg(test)]
    pub(crate) fn dwallet_mpc_metrics(&self) -> &Arc<DWalletMPCMetrics> {
        &self.dwallet_mpc_metrics
    }

    /// How many consensus-agreed demands are still parked in the assignment
    /// drain — what tells a demand still waiting for its presign pool apart
    /// from one the park bound already dropped.
    #[cfg(test)]
    pub(crate) fn parked_noa_presign_demand_count(&self) -> usize {
        self.agreed_noa_presign_demands_queue.len()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) async fn send_status_update_to_consensus_for_testing(&mut self, is_idle: bool) {
        self.send_status_update_to_consensus(is_idle).await
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn buffer_noa_observation_for_testing(
        &mut self,
        observation: NOACheckpointTxObservation,
    ) {
        self.buffered_noa_observations.push(observation);
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn buffered_noa_observations_for_testing(&self) -> &[NOACheckpointTxObservation] {
        &self.buffered_noa_observations
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn buffer_noa_presign_demand_for_testing(
        &mut self,
        demand: ConsensusNOAPresignDemand,
    ) {
        self.buffered_noa_presign_demands.push(demand);
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn buffered_noa_presign_demands_for_testing(&self) -> &[ConsensusNOAPresignDemand] {
        &self.buffered_noa_presign_demands
    }

    /// Wire up NOA checkpoint handlers for testing.
    ///
    /// `new_for_testing` creates a disconnected sign-output receiver (the connected one
    /// is returned externally). This method replaces *both* the manager's sender and the
    /// service's receiver with a fresh connected pair, then installs the handler(s).
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn setup_noa_checkpoint_handlers_for_testing(
        &mut self,
        dwallet_handler: NOACheckpointHandler<noa_checkpoint::SuiDWalletCheckpoint>,
        system_handler: Option<NOACheckpointHandler<noa_checkpoint::SuiSystemCheckpoint>>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel::<NetworkOwnedAddressSignOutput>(
            NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
        );
        self.dwallet_mpc_manager
            .network_owned_address_sign_output_sender = sender;
        self.network_owned_address_sign_output_receiver = receiver;
        self.dwallet_checkpoint_handler = Some(dwallet_handler);
        self.system_checkpoint_handler = system_handler;
    }

    /// Set the agreed Sui chain context for testing, bypassing the consensus
    /// observation agreement flow that isn't wired in `new_for_testing`.
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn set_agreed_sui_chain_context_for_testing(&mut self, context: SuiChainContext) {
        self.current_agreed_sui_chain_context = Some(context);
    }

    async fn sync_last_session_to_complete_in_current_epoch(&mut self) {
        let (ika_current_epoch_on_sui, last_session_to_complete_in_current_epoch) = *self
            .sui_data_requests
            .last_session_to_complete_in_current_epoch_receiver
            .borrow();
        if ika_current_epoch_on_sui == self.epoch {
            self.dwallet_mpc_manager
                .sync_last_session_to_complete_in_current_epoch(
                    last_session_to_complete_in_current_epoch,
                )
        }
    }

    /// Starts the DWallet MPC service.
    ///
    /// This service drains DWallet MPC messages off the consensus fold's round
    /// channel every [`READ_INTERVAL_MS`] milliseconds and forwards them to the
    /// [`DWalletMPCManager`] for processing.
    ///
    /// The service automatically terminates when an epoch switch occurs.
    pub async fn spawn(&mut self, replay_waiter: ReplayWaiter) {
        info!("Waiting for consensus commits to replay ...");
        self.drain_while_replaying(replay_waiter).await;
        info!("Consensus commits finished replaying");
        // From here on the drain is on the live path. Only the test park hook
        // reads this; see the field's docs.
        self.drain_released_by_replay = true;

        info!(
            validator=?self.name,
            "Spawning dWallet MPC Service"
        );

        loop {
            match self.exit.has_changed() {
                Ok(true) => {
                    warn!(
                        our_epoch_id=self.dwallet_mpc_manager.epoch_id,
                        authority=?self.name,
                        "DWalletMPCService exit signal received"
                    );
                    break;
                }
                Err(err) => {
                    warn!(
                        error=?err,
                        authority=?self.name,
                        our_epoch_id=self.dwallet_mpc_manager.epoch_id,
                        "DWalletMPCService exit channel was shutdown incorrectly"
                    );
                    break;
                }
                Ok(false) => (),
            };

            if self.dwallet_mpc_manager.recognized_self_as_malicious {
                self.dwallet_mpc_manager
                    .emit_self_malicious_service_exit_anomaly(self.last_read_consensus_round);
                error!(
                    authority=?self.name,
                    "the node has identified itself as malicious, breaking from MPC service loop"
                );

                // This signifies a bug, we can't proceed before we fix it.
                break;
            }

            self.run_service_loop_iteration().await;

            tokio::time::sleep(Duration::from_millis(READ_INTERVAL_MS)).await;
        }
    }

    /// Publishes the round transport's depth gauge and blocked counters until
    /// the epoch ends.
    ///
    /// A task of its own, and that is the entire point. These are the only
    /// place a WEDGED drain shows: the commit-liveness watchdog holds its
    /// clock while the fold is parked (correctly — a parked fold is not an
    /// isolated node), so nothing exits and nothing else alarms. Published
    /// from inside the drain's own loop, they would stop being written by
    /// precisely the failure they exist to report, freezing at their last
    /// healthy values while an operator reads a node that looks idle.
    ///
    /// Sampling rather than event-driven, at a period well under a scrape
    /// interval: a wedge is measured in minutes and the values are cheap
    /// atomic loads.
    ///
    /// The two blocked figures are published as DELTAS onto process-lifetime
    /// counters rather than set as absolute values. The transport is
    /// per-epoch, so its own totals restart at zero at every boundary; copying
    /// them across would drop the exported series to zero several times a day
    /// and make the "climbing versus flat" reading — the whole wedge signal —
    /// unreadable exactly when a boundary is in the alerting window. Both
    /// figures are monotonic within one transport, so the delta is always
    /// non-negative, and a fresh epoch's first sample is its own total.
    pub async fn publish_round_transport_metrics(
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        exit: Receiver<()>,
    ) {
        const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);
        let mut published_blocked_seconds = 0;
        let mut published_blocked_sends = 0;
        loop {
            if matches!(exit.has_changed(), Ok(true) | Err(_)) {
                return;
            }
            if let Some(transport) = epoch_store.round_transport_for_metrics() {
                dwallet_mpc_metrics
                    .round_channel_depth
                    .set(transport.queue_depth() as i64);

                // Clamp the high-water instead of assigning: a reader landing
                // inside `ParkGuard::drop` — between the park stamp's
                // `swap(0)` and the elapsed time's `fetch_add` — sees a
                // transient DIP (the completed total without the just-closed
                // park). Assigning the dipped value would rewind
                // `published_blocked_seconds`, and the next sample would
                // re-add the already-counted open interval — a one-time
                // overcount on the one signal that has no second opinion.
                // `saturating_sub` already zeroes the dipped delta; the max
                // keeps the baseline from rewinding.
                let blocked_seconds = transport.blocked_nanos() / 1_000_000_000;
                dwallet_mpc_metrics
                    .fold_blocked_seconds_total
                    .inc_by(blocked_seconds.saturating_sub(published_blocked_seconds));
                published_blocked_seconds = published_blocked_seconds.max(blocked_seconds);

                let blocked_sends = transport.blocked_sends();
                dwallet_mpc_metrics
                    .fold_blocked_sends_total
                    .inc_by(blocked_sends.saturating_sub(published_blocked_sends));
                published_blocked_sends = blocked_sends;
            }
            tokio::time::sleep(PUBLISH_INTERVAL).await;
        }
    }

    /// Consumes rounds while the boot replay is still folding them, and
    /// returns once the replay has finished.
    ///
    /// This exists to break a circular wait, and the cycle is worth stating
    /// exactly because the obvious simplification re-creates it:
    ///
    /// - the boot replay folds the epoch's commits, and every fold SENDS a
    ///   round into the bounded channel, blocking when it is full;
    /// - `ReplayWaiter` releases only after `ConsensusManager::start` has
    ///   published the consumer monitor, which happens after
    ///   `replay_epoch_commits` has returned;
    /// - so a service that waited for the replay before consuming would let
    ///   the channel fill, park the replay's send forever, and never reach the
    ///   release. Any epoch store holding more than
    ///   [`DEFAULT_ROUND_CHANNEL_CAPACITY`] finalized commits — about a minute
    ///   of mainnet — would hang on every boot, and hang SILENTLY: a parked
    ///   fold holds the commit-liveness watchdog, so nothing exits and the
    ///   node replays into the same wedge on restart.
    ///
    /// Only the drain runs here, deliberately. The rest of the service
    /// iteration submits to consensus, and consensus has not started yet — a
    /// submission would park on `UpdatableConsensusClient::get`, stop the
    /// drain, and rebuild the same cycle one layer up. The drain itself
    /// touches no submitting path: it feeds the manager, writes the epoch
    /// store and notifies the checkpoint builders (which are held behind this
    /// same waiter).
    ///
    /// [`DEFAULT_ROUND_CHANNEL_CAPACITY`]: crate::authority::round_transport::DEFAULT_ROUND_CHANNEL_CAPACITY
    async fn drain_while_replaying(&mut self, replay_waiter: ReplayWaiter) {
        let replay_complete = replay_waiter.wait_for_replay();
        tokio::pin!(replay_complete);
        loop {
            tokio::select! {
                // Biased so a finished replay is observed before another
                // sleep, rather than after a further interval of it.
                biased;
                () = &mut replay_complete => return,
                () = tokio::time::sleep(Duration::from_millis(READ_INTERVAL_MS)) => {
                    self.drain_consensus_rounds().await;
                }
            }
        }
    }

    pub(crate) async fn run_service_loop_iteration(&mut self) {
        debug!("Running DWalletMPCService loop");

        // Ingest the per-epoch off-chain validator MPC keys (3 PVSS + VSS HPKE)
        // FIRST, before any request handling builds an MPC session input this
        // iteration — those inputs read `validator_mpc_keys_by_party_id` /
        // `next_epoch_validator_mpc_keys`, so the keys must be in place before
        // the within-epoch network DKG / reconfiguration session is constructed.
        // The off-chain-only keys aren't on `Committee`; they're assembled
        // per-epoch and delivered on the current/next-epoch key channels (at
        // genesis the current-epoch set was never assembled as a prior epoch's
        // "next"). No-op once each set is complete.
        if let Err(e) = self.dwallet_mpc_manager.ingest_offchain_mpc_keys() {
            error!(error = ?e, "failed to ingest off-chain validator MPC keys");
        }

        // Retry internal presign requests parked on missing network key data —
        // per ITERATION, not per consensus round, because what they wait on
        // (the ingest above / an asynchronous key install) completes on
        // wall-clock time, and no new consensus round is guaranteed to follow.
        self.dwallet_mpc_manager
            .retry_internal_presign_requests_pending_for_network_key_data();

        self.sync_last_session_to_complete_in_current_epoch().await;

        // Process any pending network-owned-address sign requests.
        self.process_network_owned_address_sign_requests();

        // Receive **new** dWallet MPC events and save them in the local DB.
        let rejected_sessions = self.handle_new_requests().await.unwrap_or_else(|e| {
            error!(error=?e, "failed to handle new events from DWallet MPC service");
            vec![]
        });

        // Adopt locally-observed network-key outputs (cert-digest-gated)
        // and spawn instantiation for any not yet installed — once per
        // ITERATION, not per consensus round: the inputs (overlay watch,
        // persisted cert) don't depend on round content, and gating this
        // on fresh rounds deadlocks the key-arrives-after-request
        // bootstrap (nothing can emit a round WITHOUT the key, and no
        // round would mean no adoption). The adoption pass early-returns
        // in O(1) when neither the overlay Arc nor the cert changed.
        let overlay_snapshot = self
            .sui_data_requests
            .network_keys_receiver
            .borrow()
            .clone();
        self.dwallet_mpc_manager
            .adopt_cert_verified_keys(&overlay_snapshot);
        self.dwallet_mpc_manager.instantiate_adopted_network_keys();

        self.drain_consensus_rounds().await;
        // Network-key instantiations complete asynchronously on the rayon
        // pool; poll them once per ITERATION (not per consensus round) so
        // a completed key installs even when no new rounds arrived. Requests
        // parked on a key drain via the level-triggered check in
        // `handle_mpc_request_batch` on the next iteration — regardless of
        // whether the key materialized here or through the chain-copy
        // adoption path (issue #1834).
        self.dwallet_mpc_manager
            .poll_pending_network_key_instantiations()
            .await;

        self.process_cryptographic_computations().await;
        self.handle_noa_sign_outputs().await;
        self.poll_noa_chain_status().await;
        self.submit_rejections_covered_by_lock_target(rejected_sessions)
            .await;

        // Observability refresh runs once per tick, at iteration end, so every
        // gauge summarizes the same post-processing state. The per-tick
        // end_of_publish touch (not just the flip site) makes the series exist
        // at 0 before the flip, so dashboards can tell "not yet" from
        // "not scraped".
        self.dwallet_mpc_metrics
            .service_end_of_publish_local
            .set(self.end_of_publish as i64);
        self.dwallet_mpc_manager.refresh_observability_metrics();
    }

    /// Process network-owned-address sign requests received via the channel.
    /// Drains the channel into a pending buffer, then instantiates sessions
    /// for requests whose network key is already available.
    fn process_network_owned_address_sign_requests(&mut self) {
        // Drain the receiver into the shared pending buffer, deduplicating by
        // the demand IDENTITY rather than by the message: the same message
        // under two algorithms is two distinct legitimate demands (the
        // algorithm is part of the identity), and keying on the message alone
        // would drop the second at intake while a peer's announcement of it
        // still consumed a presign in the drain.
        while let Ok(request) = self.network_owned_address_sign_requests_receiver.try_recv() {
            let demand_digest = request.demand_id.digest();
            if self.submitted_noa_sign_messages.contains(&demand_digest) {
                ika_types::report_invariant_violation!(
                    "duplicate_noa_sign_request",
                    message_len = request.message.len(),
                    curve = ?request.curve,
                    algorithm = ?request.demand_id.expected_signature_algorithm(),
                    "Skipping duplicate network-owned-address sign request"
                );
                continue;
            }
            debug!(
                message_len = request.message.len(),
                curve = ?request.curve,
                algorithm = ?request.demand_id.expected_signature_algorithm(),
                "Received network-owned-address sign request"
            );
            self.pending_network_owned_address_sign_requests
                .push(request);
        }

        if self.pending_network_owned_address_sign_requests.is_empty() {
            return;
        }

        // Announce a presign demand for each pending request so every validator
        // assigns it a presign in the same consensus-delivery order (the drain
        // in `drain_consensus_rounds`). Gated on `noa_checkpoints()`
        // for wire safety — the `NOAPresignDemand` consensus kind must never
        // reach a peer that predates it — and on the signing network key being
        // known (the demand carries its id, and the presign pool is keyed by it;
        // announcing before adoption would let validators disagree on the key).
        // Announce each demand at most once; one the drain already resolved —
        // assigned a presign, or dropped at the park bound — needs no
        // (re-)announcement, and the resolution is durable, so this holds after
        // a restart too. Do NOT pop/instantiate here.
        if self.protocol_config.noa_checkpoints()
            && let Some(network_encryption_key_id) = self
                .dwallet_mpc_manager
                .network_owned_address_signing_network_encryption_key_id()
        {
            for request in &self.pending_network_owned_address_sign_requests {
                let digest = request.demand_id.digest();
                if self.announced_noa_demand_digests.contains(&digest) {
                    continue;
                }
                match self
                    .epoch_store
                    .has_noa_presign_demand_resolution(&request.demand_id)
                {
                    Ok(true) => {
                        // Already resolved — no (re-)announcement needed.
                        self.announced_noa_demand_digests.insert(digest);
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        // Rare DB read error on this per-iteration path. Log it
                        // (once per digest: on fall-through we mark it announced,
                        // so the `contains` guard above suppresses re-logs) and
                        // announce anyway — the consensus-ordered drain is
                        // idempotent, so a redundant announcement is harmless.
                        ika_types::report_invariant_violation!(
                            "noa_presign_demand_resolution_read",
                            error=?e,
                            "failed to read NOA presign-demand resolution during announcement; announcing anyway"
                        );
                    }
                }
                self.buffered_noa_presign_demands
                    .push(ConsensusNOAPresignDemand {
                        authority: self.name,
                        demand_id: request.demand_id.clone(),
                        network_encryption_key_id,
                    });
                self.announced_noa_demand_digests.insert(digest);
            }
        }

        let mut newly_submitted: Vec<[u8; 32]> = Vec::new();
        self.pending_network_owned_address_sign_requests
            .retain(|request| {
                let digest = request.demand_id.digest();
                // A request is driven entirely by its demand's DURABLE
                // resolution: instantiate on an assignment, release on a drop,
                // wait while there is neither. Reading the drop from the store
                // rather than from process memory is what keeps this working
                // across a restart, which is also where the resolution itself
                // has to be durable (see `NoaPresignDemandResolution`).
                //
                // Only the assignment path needs the signing network key
                // locally; a release must not wait on it, or a validator that
                // never adopts the key would hold the request forever.
                let resolution = match self
                    .epoch_store
                    .noa_presign_demand_resolution(&request.demand_id)
                {
                    Ok(resolution) => resolution,
                    Err(e) => {
                        error!(error = ?e, "failed to read NOA presign-demand resolution; keeping request pending");
                        return true;
                    }
                };
                match resolution {
                    // The demand was dropped at the park bound: no presign will
                    // ever be assigned to it this epoch, so keeping the request
                    // only feeds the starvation warn below forever. Recovery,
                    // where it exists at all, comes from a HIGHER layer minting
                    // a FRESH demand id — a checkpoint demand carries its retry
                    // round, so a retry is a different demand with a different
                    // consensus dedup key — and today that only happens after
                    // an on-chain failure quorum. A dropped checkpoint sign
                    // therefore stays unsigned for the rest of the epoch.
                    Some(NoaPresignDemandResolution::Evicted) => {
                        warn!(
                            demand_id = ?request.demand_id,
                            demand_id_digest = hex::encode(digest),
                            "releasing a pending network-owned-address sign request whose presign \
                             demand was dropped at the park bound; it will not be signed this epoch"
                        );
                        false
                    }
                    // Instantiate only once this demand's presign has been
                    // assigned in consensus order (written to
                    // `noa_presign_demand_resolutions` by the drain); never pop
                    // the pool here — that reintroduces the local-order pairing
                    // this fix removes. The raw presign and the network key it
                    // was popped from are both read from the assignment, so the
                    // sign instantiates under the SAME key the presign came from
                    // (never a locally re-resolved key that could have shifted
                    // since announce).
                    Some(NoaPresignDemandResolution::Assigned {
                        session_identifier,
                        blending_index,
                        presign,
                        network_encryption_key_id,
                    }) => {
                        if !self
                            .dwallet_mpc_manager
                            .has_network_owned_address_signing_network_key()
                        {
                            return true; // key not yet available, keep in buffer
                        }
                        let instantiated = self
                            .dwallet_mpc_manager
                            .instantiate_network_owned_address_sign_session(
                                request.message.clone(),
                                request.curve,
                                request.demand_id.expected_signature_algorithm(),
                                request.hash_scheme,
                                session_identifier,
                                blending_index,
                                presign,
                                network_encryption_key_id,
                            );
                        if instantiated {
                            newly_submitted.push(DefaultHash::digest(&request.message).into());
                        }
                        !instantiated // keep in buffer if instantiation failed
                    }
                    // Not yet resolved in consensus order — keep waiting.
                    None => true,
                }
            });
        // Starvation signal: requests are waiting and this pass made no
        // progress — the signing network key is unavailable, or the demand's
        // presign has not yet been assigned in consensus order (the pool is
        // momentarily empty, or the demand has not yet reached consensus).
        // Without this, a wedged pool looks identical to no demand. Throttled to
        // once per 30s (the loop runs every 20ms).
        let starvation_persists = newly_submitted.is_empty()
            && !self.pending_network_owned_address_sign_requests.is_empty();
        if starvation_persists
            && self
                .last_noa_starvation_log
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
        {
            self.last_noa_starvation_log = Some(Instant::now());
            warn!(
                pending_requests = self.pending_network_owned_address_sign_requests.len(),
                "network-owned-address sign requests waiting: presign not yet assigned \
                 in consensus order or signing key unavailable"
            );
        }
        self.submitted_noa_sign_messages.extend(newly_submitted);
    }

    /// Send status update and individual consensus messages for presign requests,
    /// network key data, and NOA observations.
    async fn send_status_update_to_consensus(&mut self, is_idle: bool) {
        let Some(consensus_round) = self.last_read_consensus_round else {
            return;
        };

        // Only include presign requests that haven't been sent yet.
        let unsent_presign_requests = self.dwallet_mpc_manager.get_unsent_presign_requests();

        // FIXME(noa-checkpoints): Without a real SuiChainObservation, the entire NOA
        // checkpoint flow is non-functional — messages buffer indefinitely because
        // `current_agreed_sui_chain_context` never becomes Some. Wire up SuiSyncer.
        let sui_chain_observation: Option<SuiChainObservation> = None;

        // Check if there's anything new to send.
        let has_unsent_requests = !unsent_presign_requests.is_empty();
        let idle_status_changed = self.last_sent_idle_status != Some(is_idle);
        let observation_changed = sui_chain_observation != self.last_sent_sui_chain_observation;
        let has_noa_observations = !self.buffered_noa_observations.is_empty();
        let has_noa_presign_demands = !self.buffered_noa_presign_demands.is_empty();

        if !has_unsent_requests
            && !idle_status_changed
            && !observation_changed
            && !has_noa_observations
            && !has_noa_presign_demands
        {
            return;
        }

        // Submit each transaction individually — the consensus adapter only accepts
        // single-transaction submissions (submit_batch enforces len == 1).

        // Idle status update when idle status changed.
        if idle_status_changed {
            let tx = ConsensusTransaction::new_idle_status_update(IdleStatusUpdate::new(
                self.name, is_idle,
            ));
            if let Err(e) = self
                .dwallet_submit_to_consensus
                .submit_to_consensus(&[tx])
                .await
            {
                error!(error = ?e, consensus_round, "Failed to submit idle status update");
            } else {
                self.last_sent_idle_status = Some(is_idle);
            }
        }

        // Sui chain observation update when the observation changed and is present.
        if observation_changed && let Some(ref observation) = sui_chain_observation {
            let tx = ConsensusTransaction::new_sui_chain_observation_update(
                SuiChainObservationUpdate::new(self.name, observation.clone()),
            );
            if let Err(e) = self
                .dwallet_submit_to_consensus
                .submit_to_consensus(&[tx])
                .await
            {
                error!(error = ?e, consensus_round, "Failed to submit chain observation update");
            } else {
                self.last_sent_sui_chain_observation = sui_chain_observation.clone();
            }
        }

        // One message per unsent presign request.
        for request in &unsent_presign_requests {
            let tx = ConsensusTransaction::new_global_presign_request(self.name, *request);
            if let Err(e) = self
                .dwallet_submit_to_consensus
                .submit_to_consensus(&[tx])
                .await
            {
                error!(error = ?e, consensus_round, "Failed to submit presign request");
            }
        }

        // One message per buffered NOA observation. On submit failure, re-buffer
        // the observation for the next status update: its producer is one-shot
        // (the checkpoint handler marks a tx confirmed-locally / voted-failed
        // BEFORE emitting the observation), so a dropped observation would never
        // be re-emitted and this validator's finalize/fail vote would be silently
        // lost. Retrying a submission that actually landed is harmless — the
        // observation tally is a per-authority set.
        let noa_observations = std::mem::take(&mut self.buffered_noa_observations);
        for obs in noa_observations {
            let tx = ConsensusTransaction::new_noa_observation(self.name, obs.clone());
            if let Err(e) = self
                .dwallet_submit_to_consensus
                .submit_to_consensus(&[tx])
                .await
            {
                error!(error = ?e, consensus_round, "Failed to submit NOA observation; re-buffering for retry");
                self.buffered_noa_observations.push(obs);
            }
        }

        // One message per buffered NOA presign demand. Gated on `noa_checkpoints()`
        // for wire safety — the `NOAPresignDemand` consensus kind must never reach
        // a peer that predates it. Consensus dedups cross-validator duplicates by
        // the demand-id digest key, and the assignment drain is idempotent.
        // On submit failure, re-buffer the demand for the next status update:
        // `announced_noa_demand_digests` marks a demand announced when it is
        // buffered, so a dropped demand would never be re-announced by this
        // validator.
        if self.protocol_config.noa_checkpoints() {
            let noa_presign_demands = std::mem::take(&mut self.buffered_noa_presign_demands);
            for demand in noa_presign_demands {
                let tx = ConsensusTransaction::new_noa_presign_demand(
                    demand.authority,
                    demand.demand_id.clone(),
                    demand.network_encryption_key_id,
                );
                if let Err(e) = self
                    .dwallet_submit_to_consensus
                    .submit_to_consensus(&[tx])
                    .await
                {
                    error!(error = ?e, consensus_round, "Failed to submit NOA presign demand; re-buffering for retry");
                    self.buffered_noa_presign_demands.push(demand);
                }
            }
        }
    }

    /// Route a single NOA checkpoint resolution to the appropriate handler.
    fn route_resolution(
        &mut self,
        resolution: ika_types::noa_checkpoint::NOACheckpointResolution<
            ika_types::noa_checkpoint::SuiCounterpartyChain,
        >,
        kind_name: NOACheckpointKindName,
    ) {
        match kind_name {
            NOACheckpointKindName::SuiDWallet => {
                if let Some(ref mut handler) = self.dwallet_checkpoint_handler {
                    let requests = handler.handle_resolution(resolution);
                    self.pending_network_owned_address_sign_requests
                        .extend(requests);
                }
            }
            NOACheckpointKindName::SuiSystem => {
                if let Some(ref mut handler) = self.system_checkpoint_handler {
                    let requests = handler.handle_resolution(resolution);
                    self.pending_network_owned_address_sign_requests
                        .extend(requests);
                }
            }
        }
    }

    /// Drain sign outputs from MPC manager and route to both NOA checkpoint handlers.
    /// Each handler's `add_signature` silently ignores outputs for tx bytes it doesn't
    /// own (returns `None`), so broadcasting is correct. The `debug!` log in `add_signature`
    /// is the only side-effect of sending to the wrong handler.
    async fn handle_noa_sign_outputs(&mut self) {
        while let Ok(output) = self.network_owned_address_sign_output_receiver.try_recv() {
            if let Some(ref mut handler) = self.dwallet_checkpoint_handler {
                handler.handle_sign_output(output.clone()).await;
            }
            if let Some(ref mut handler) = self.system_checkpoint_handler {
                handler.handle_sign_output(output).await;
            }
        }
    }

    /// Poll chain status for all NOA checkpoint handlers and collect observations.
    async fn poll_noa_chain_status(&mut self) {
        if let Some(ref mut handler) = self.dwallet_checkpoint_handler {
            let observations = handler.poll_chain_status().await;
            self.buffered_noa_observations.extend(observations);
            handler.update_finalized_flag();
        }
        if let Some(ref mut handler) = self.system_checkpoint_handler {
            let observations = handler.poll_chain_status().await;
            self.buffered_noa_observations.extend(observations);
            handler.update_finalized_flag();
        }
    }

    async fn process_cryptographic_computations(&mut self) {
        let Some(last_read_consensus_round) = self.last_read_consensus_round else {
            warn!("No last read consensus round, cannot perform cryptographic computation");
            return;
        };

        let (computation_results, is_idle) = self
            .dwallet_mpc_manager
            .perform_cryptographic_computation(last_read_consensus_round)
            .await;

        self.handle_computation_results_and_submit_to_consensus(computation_results)
            .await;

        // TODO: do this only if the status changed.
        // Send status update to consensus using the result from cryptographic computations
        self.send_status_update_to_consensus(is_idle).await;
    }

    async fn handle_new_requests(&mut self) -> DwalletMPCResult<Vec<DWalletSessionRequest>> {
        let uncompleted_requests = self.load_uncompleted_requests().await;
        let pulled_requests = match self.receive_new_sui_requests() {
            Ok(requests) => requests,
            Err(e) => {
                error!(
                    error=?e,
                    "failed to receive dWallet new dWallet requests");
                return Err(DwalletMPCError::TokioRecv);
            }
        };
        let requests = [uncompleted_requests, pulled_requests].concat();

        let requests_by_session_identifiers: HashMap<SessionIdentifier, &DWalletSessionRequest> =
            requests.iter().map(|e| (e.session_identifier, e)).collect();

        let requests_session_identifiers =
            requests_by_session_identifiers.keys().copied().collect();

        match self
            .state
            .get_dwallet_mpc_sessions_completed_status(requests_session_identifiers)
        {
            Ok(mpc_session_identifier_to_computation_completed) => {
                for (session_identifier, session_completed) in
                    mpc_session_identifier_to_computation_completed
                {
                    // Safe to unwrap, as we just inserted the session identifier into the map.
                    let request = requests_by_session_identifiers
                        .get(&session_identifier)
                        .unwrap();

                    if session_completed {
                        self.dwallet_mpc_manager
                            .complete_computation_mpc_session_and_create_if_not_exists(
                                &session_identifier,
                                SessionComputationType::from(&request.protocol_data),
                                request.session_sequence_number,
                                request.session_type,
                            );

                        debug!(
                            ?session_identifier,
                            "Got a request for a session that was previously computation completed, marking it as computation completed"
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    ?requests_by_session_identifiers,
                    error=?e,
                    "Could not read from the DB completed sessions, got error"
                );
            }
        }

        let rejected_sessions = self
            .dwallet_mpc_manager
            .handle_mpc_request_batch(requests)
            .await;

        Ok(rejected_sessions)
    }

    /// Consumes every round queued on the transport, then returns.
    ///
    /// **Nothing reachable from here may wait on consensus.** This runs during
    /// the boot replay ([`Self::drain_while_replaying`]), before consensus has
    /// started, and the replay's own folds are parked on the channel this
    /// drains — so a call that waited for consensus to come up would stop the
    /// drain, keep the channel full, park the replay forever, and leave
    /// consensus never starting: the wait would be on the thing the wait
    /// blocks.
    ///
    /// The invariant currently holds structurally, and cheaply enough to
    /// re-check by hand: the whole body has exactly one await point,
    /// `yield_now`. Everything else it touches — the manager, the epoch store,
    /// the checkpoint-service notification — is synchronous. Adding an
    /// `.await` here is the moment to re-read this comment; the submitting
    /// work belongs in `run_service_loop_iteration`, which runs only after the
    /// replay signal. `a_replay_longer_than_the_channel_still_finishes` fails
    /// if a submission does creep in.
    ///
    /// # The test park hook
    ///
    /// `IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND` makes this function return
    /// without consuming anything once the drain has taken that many rounds
    /// since the boot replay released it; `IKA_TEST_PARK_MPC_DRAIN_UNPARK_FILE`
    /// names a path whose appearance releases it, permanently. Both are off
    /// unless explicitly set, and a process that arms them WARNs on boot and
    /// again on the park. See [`park_drain_test_hook`] for the whole contract.
    ///
    /// It exists because "the drain is alive but stuck" is not reachable any
    /// other way from outside a real validator process, and the composition it
    /// produces — the channel fills, the fold parks, the commit-liveness
    /// watchdog holds, and the counters are the only evidence — had only ever
    /// been tested piecewise in-process (ika #2102).
    ///
    /// The park is deliberately at the TOP of the drain rather than inside the
    /// receive loop: everything downstream of consumption then stops together
    /// — the catch-up gate's observation included — which is what a wedged
    /// drain does. A half-running loop that kept feeding the gate would be a
    /// shape no real failure has.
    ///
    /// [`park_drain_test_hook`]: crate::dwallet_mpc::park_drain_test_hook
    async fn drain_consensus_rounds(&mut self) {
        // Rounds arrive over the bounded channel the commit boundary feeds;
        // there is no per-round table to poll, and no round-equality check to
        // make across ten streams, because a round is now one message.
        //
        // `try_recv`, not `recv`: this runs inside the service's 20ms
        // iteration, which has other per-iteration work to do (computation
        // spawning, chain polls, submissions). Blocking here would stall all
        // of it behind the fold. Drain what has arrived, then let the caller
        // continue — the fold blocks on US when we fall behind, which is the
        // backpressure this design is built on.
        if self.round_receiver.is_none() {
            // No transport installed: this process folds commits but runs no
            // drain. Nothing to do.
            return;
        }

        // Test-only wedge hook; off on every production validator. See the
        // "test park hook" section of this function's docs.
        if self.drain_released_by_replay
            && let Some(hook) = park_mpc_drain_hook()
            && hook.should_park(self.rounds_consumed_since_replay)
        {
            return;
        }

        // Feed the catch-up gate BEFORE draining, against the highest round
        // this node has OBSERVED rather than the highest it has folded. Under
        // a blocking transport the fold is never more than the channel's
        // capacity ahead of us, so a gap measured against the fold would be
        // pinned below the gate's entry threshold and the gate would never
        // engage. The observed head comes from the boot replay (which reads
        // the consensus store's head before folding anything) and from
        // commit arrival on the live path.
        let observed_head = self.epoch_store.observed_consensus_head_round();
        self.dwallet_mpc_manager
            .observe_consensus_round_gap(observed_head, self.last_read_consensus_round);

        // The transport's own depth and blocked figures are deliberately NOT
        // published here. They exist to report a drain that has stopped
        // consuming, and a publisher living inside that drain stops publishing
        // in exactly that case — the series would freeze at their last healthy
        // values and the wedge would look like a node with nothing to do. They
        // are published by `publish_round_transport_metrics`, which shares fate
        // with nothing but the runtime.

        loop {
            // Borrow the receiver only for the receive, so the rest of the
            // loop body can use `self` mutably.
            let payload = match self.round_receiver.as_mut() {
                Some(receiver) => match receiver.try_recv() {
                    Ok(payload) => payload,
                    // Nothing queued: we are caught up with the fold for now.
                    Err(TryRecvError::Empty) => return,
                    // The fold dropped its sender — the epoch is over.
                    Err(TryRecvError::Disconnected) => {
                        info!("the consensus fold closed the round channel; ending this iteration");
                        return;
                    }
                },
                None => return,
            };

            self.number_of_consensus_rounds += 1;
            if self.drain_released_by_replay {
                // Only the test park hook reads this; see the field's docs.
                self.rounds_consumed_since_replay += 1;
            }

            let ConsensusRoundPayload {
                round: consensus_round,
                mpc_messages,
                mpc_outputs: external_mpc_outputs,
                internal_mpc_outputs,
                verified_dwallet_checkpoint_messages,
                verified_system_checkpoint_messages,
                idle_status_updates,
                sui_chain_observation_updates,
                global_presign_requests: presign_request_messages,
                noa_observations: noa_observation_messages,
                noa_presign_demands: noa_presign_demand_messages,
            } = payload;

            if self.last_read_consensus_round >= Some(consensus_round) {
                ika_types::report_invariant_violation!(
                    "consensus_round_not_ascending",
                    consensus_round,
                    last_read_consensus_round=?self.last_read_consensus_round,
                    "consensus round must be in a ascending order"
                );

                panic!("consensus round must be in a ascending order");
            }

            // The NOA cluster stays gated on `noa_checkpoints()`, exactly as
            // it was when these arrived through per-round tables: that flag is
            // off on every live network, the old write path never persisted
            // these streams while it was off, and so the drain never acted on
            // them. Deleting the tables silently deleted that gate with them.
            //
            // The payload keeps carrying them — the fold is version-uniform
            // and the channel is in-process, so nothing on the wire moves —
            // but ACTING on them must not flip with the binary. The demand
            // queue pops the SHARED internal presign pool
            // (`assign_presign_for_demand`), so a node that processed demands
            // while the network's flag was off would drain a pool no peer is
            // drawing on and answer demands no peer answers: a
            // consensus-visible divergence decided by which binary a validator
            // runs rather than by the protocol version. That is the one class
            // of change this repo rules out outright, and during a rolling
            // upgrade it would be live on a mixed committee.
            let (
                sui_chain_observation_updates,
                noa_observation_messages,
                noa_presign_demand_messages,
                verified_system_checkpoint_messages,
            ) = if self.protocol_config.noa_checkpoints() {
                (
                    sui_chain_observation_updates,
                    noa_observation_messages,
                    noa_presign_demand_messages,
                    verified_system_checkpoint_messages,
                )
            } else {
                (Vec::new(), Vec::new(), Vec::new(), Vec::new())
            };

            // 1a. Handle idle status and chain observations.
            let (is_idle, agreed_sui_chain_context) =
                self.dwallet_mpc_manager.handle_idle_and_chain_updates(
                    consensus_round,
                    idle_status_updates,
                    sui_chain_observation_updates,
                );

            // 1b. Handle presign request messages.
            let agreed_presign_requests = self
                .dwallet_mpc_manager
                .handle_presign_request_messages(consensus_round, presign_request_messages);

            // 1d. Handle NOA observation messages.
            let (newly_finalized_tx_refs, newly_failed_tx_refs) = self
                .dwallet_mpc_manager
                .handle_noa_observation_messages(consensus_round, noa_observation_messages);

            // Update persistent context from consensus agreement.
            self.current_agreed_sui_chain_context = agreed_sui_chain_context;

            // Dispatch NOA checkpoint resolutions.
            for tx_ref in &newly_finalized_tx_refs {
                let resolution =
                    ika_types::noa_checkpoint::NOACheckpointResolution::Finalized(tx_ref.clone());
                self.route_resolution(resolution, tx_ref.kind_name);
            }
            for (tx_ref, _) in &newly_failed_tx_refs {
                if let Some(ctx) = &self.current_agreed_sui_chain_context {
                    let resolution =
                        ika_types::noa_checkpoint::NOACheckpointResolution::RetryWithContext {
                            tx_ref: tx_ref.clone(),
                            context: ctx.clone(),
                        };
                    self.route_resolution(resolution, tx_ref.kind_name);
                }
            }

            // Take only the requests we haven't agreed on yet, and haven't processed.
            {
                let new_global_presign_requests: Vec<_> = agreed_presign_requests
                    .into_iter()
                    .filter(|request| !self.agreed_global_presign_requests_queue.contains(request))
                    .filter(|request| {
                        !self
                            .processed_global_presign_sequence_numbers
                            .contains(&request.session_sequence_number)
                    })
                    .sorted_by_key(|r| r.session_sequence_number)
                    .collect();

                if self.network_is_idle != is_idle || !new_global_presign_requests.is_empty() {
                    debug!(
                        consensus_round,
                        is_idle,
                        number_of_new_global_presign_requests = new_global_presign_requests.len(),
                        "Agreed status changed"
                    );

                    self.network_is_idle = is_idle;
                    self.agreed_global_presign_requests_queue
                        .extend(new_global_presign_requests);
                }
            }

            // Network-key adoption + instantiation spawning deliberately do
            // NOT live in this per-round loop — see the per-ITERATION block
            // in `run_service_loop_iteration`: their inputs (overlay watch,
            // persisted cert) don't depend on round content, and gating them
            // on fresh consensus rounds deadlocks the key-arrives-after-
            // request bootstrap (no validator can emit a round WITHOUT the
            // key, and no round means no adoption).

            // 3. Instantiate internal presign sessions (now uses agreed values).
            self.dwallet_mpc_manager
                .instantiate_internal_presign_sessions(
                    consensus_round,
                    self.number_of_consensus_rounds,
                    self.network_is_idle,
                );

            // 4. Handle MPC messages.
            self.dwallet_mpc_manager
                .handle_consensus_round_messages(consensus_round, mpc_messages);

            // 5. Handle MPC outputs.
            let external_mpc_outputs = external_mpc_outputs
                .into_iter()
                .map(DWalletMPCOutputReport::External)
                .collect();
            let (agreed_external_mpc_outputs, completed_external_sessions) = self
                .dwallet_mpc_manager
                .handle_consensus_round_outputs(consensus_round, external_mpc_outputs);

            let internal_mpc_outputs = internal_mpc_outputs
                .into_iter()
                .map(DWalletMPCOutputReport::Internal)
                .collect();
            let (_, completed_internal_sessions) = self
                .dwallet_mpc_manager
                .handle_consensus_round_outputs(consensus_round, internal_mpc_outputs);

            let completed_sessions: Vec<_> = completed_external_sessions
                .into_iter()
                .chain(completed_internal_sessions)
                .collect();

            // Handle global presign requests
            let global_presign_checkpoint_messages = if !self
                .agreed_global_presign_requests_queue
                .is_empty()
            {
                let mut global_presign_checkpoint_messages = Vec::new();

                // Use retain to keep only unprocessed requests in the queue
                self.agreed_global_presign_requests_queue.retain(|request| {
                    if self
                            .processed_global_presign_sequence_numbers
                            .contains(&request.session_sequence_number) {
                        // Extra precaution: if we already assigned an external presign for this
                        // sequence number, don't assign another — remove from queue (return false).
                        return false;
                    }

                    // Atomic + idempotent (see `assign_presign_for_demand`): pops the
                    // pool head and records what it served in ONE committed
                    // batch, or returns the presign already served for this
                    // sequence number without popping. A bare pop
                    // here would re-pop when this loop replays the epoch's
                    // rounds after a restart — against a pool the replay never
                    // reset — and answer the request with a different presign
                    // than the never-crashed peers put in their checkpoint
                    // message for the same presign id.
                    match self.epoch_store.assign_presign_for_demand(
                        &PresignDemand::GlobalRequest {
                            session_sequence_number: request.session_sequence_number,
                        },
                        request.signature_algorithm,
                        request.dwallet_network_encryption_key_id,
                    ) {
                        Ok(PresignAssignmentOutcome::Assigned { presign, .. }) => {
                            match bcs::to_bytes(&VersionedPresignOutput::V2(presign)) {
                                Ok(presign) => {
                                    // Info on purpose: a pool-served presign
                                    // session completes without ever running
                                    // MPC, so this is the ONLY line tying its
                                    // session identifier and sequence number
                                    // to a completion — at debug, such
                                    // sessions are untraceable in production
                                    // logs (each held/served session's fate
                                    // was invisible in the issue #1736
                                    // forensics). Volume: once per served
                                    // presign.
                                    info!(
                                        request_session_id =? request.session_identifier,
                                        presign_id =? request.presign_id,
                                        session_sequence_number =? request.session_sequence_number,
                                        "popped presign from internal pool for global presign request"
                                    );

                                    let checkpoint_message =
                                        DWalletCheckpointMessageKind::RespondDWalletPresign(
                                            PresignOutput {
                                                presign,
                                                dwallet_id: None,
                                                presign_id: request.presign_id.to_vec(),
                                                rejected: false,
                                                session_sequence_number: request
                                                    .session_sequence_number,
                                            },
                                        );

                                    global_presign_checkpoint_messages.push(checkpoint_message);
                                    self.dwallet_mpc_metrics
                                        .global_presigns_served_total
                                        .with_label_values(&[&format!(
                                            "{:?}",
                                            request.signature_algorithm
                                        )])
                                        .inc();
                                    self.processed_global_presign_sequence_numbers
                                        .insert(request.session_sequence_number);
                                    // Mark this request as fulfilled in the manager to skip future voting
                                    self.dwallet_mpc_manager
                                        .mark_global_presign_request_fulfilled(request.session_sequence_number);

                                    // Successfully processed - remove from queue (return false)
                                    false
                                }
                                Err(e) => {
                                    // Serialization of a valid presign output should never fail.
                                    // If it does, the data is corrupted and retrying won't help.
                                    ika_types::report_invariant_violation!(
                                        "presign_output_serialize",
                                        error=?e,
                                        "failed to serialize presign output — data corruption"
                                    );
                                    panic!("failed to serialize presign output: {e:?}");
                                }
                            }
                        }
                        Ok(PresignAssignmentOutcome::PoolEmpty) => {
                            // No presign available in internal pool - keep in queue (return true)
                            true
                        }
                        Ok(PresignAssignmentOutcome::Evicted) => {
                            // Unreachable by construction: only a NOA demand can
                            // be dropped at the park bound, and only the NOA arm
                            // of the resolution table records such a drop. A
                            // global request reaching this arm means the two
                            // marker tables were crossed, so say so loudly and
                            // keep the request rather than answering it wrong.
                            ika_types::report_invariant_violation!(
                                "global_presign_request_evicted",
                                session_sequence_number = request.session_sequence_number,
                                "a global presign request resolved as dropped-at-the-park-bound, \
                                 which only a NOA demand can be — keeping it queued"
                            );
                            true
                        }
                        Err(e) => {
                            ika_types::report_invariant_violation!(
                                "internal_presign_pool_pop",
                                error=?e,
                                "failed to pop presign from internal pool"
                            );
                            // Keep in queue for retry (return true)
                            true
                        }
                    }
                });

                global_presign_checkpoint_messages
            } else {
                Vec::new()
            };
            // Set unconditionally (including the queue-empty branch above,
            // which skips the retain) so the gauge can't read stale-nonzero
            // after the queue drains or across the per-epoch service rebuild.
            self.dwallet_mpc_metrics
                .global_presign_requests_waiting
                .set(self.agreed_global_presign_requests_queue.len() as i64);

            // NOA sign presign demands: assign each a presign in consensus-
            // delivery order, so the sign session that later reads
            // `noa_presign_demand_resolutions` pairs the SAME presign with the
            // SAME demand on every validator. This is the determinism crux of
            // the fix:
            //   (a) every validator processes consensus rounds in identical order
            //       (this loop reads the per-round DB stream in ascending
            //       round order);
            //   (b) the demand queue is extended in that same order;
            //   (c) `Vec::retain` visits elements in their original (insertion)
            //       order, so demands drain in consensus order;
            //   (d) the presign pool is network-uniform (keyed by the
            //       consensus-assigned presign sequence), so popping in the same
            //       order yields the same presign per demand on every validator;
            //   (e) a demand that stays unassigned is dropped on a predicate
            //       built only from (a)-(d): its consensus delivery round, the
            //       consensus round being drained, and whether the pool of
            //       (a)-(d) could serve it. Nothing per-validator — not the
            //       locally adopted key set, not the network-key overlay, not
            //       wall clock — enters it, so every validator drops the same
            //       demand at the same round. A drop decided on local state
            //       would put back exactly the disagreement this queue exists
            //       to remove.
            // `assign_presign_for_demand` is atomic + idempotent: it pops and
            // records in one committed batch, and reports an already-resolved demand
            // without popping again (so re-delivery, and a re-drain after a
            // consensus-round replay, are both safe). Keeping a demand while the
            // pool is empty (`PoolEmpty` => keep) preserves ordering across
            // rounds until its presign is generated, up to
            // `noa_presign_demand_park_rounds`. Both the queue and the
            // resolution table it writes are per-epoch (the queue rebuilds
            // empty on the per-epoch service restart; the table is physically
            // dropped on epoch rotation), and so are the delivery rounds
            // recorded here — a replay of the epoch's rounds rebuilds them
            // identically. The RESOLUTION, however, must survive that replay
            // rather than be recomputed: the pool is not rewound with the
            // rounds, so a demand this validator dropped while its key had no
            // pool would be re-read against a pool that has since filled. Both
            // outcomes are therefore written to the same durable per-demand
            // table, and the replay reads them instead of deciding again.
            //
            // The assignment step reads ONLY the consensus-delivered demand
            // queue and the consensus-generated presign pool — there is no
            // wall-clock, channel-arrival-order, or local-instantiation-order
            // input in it. That is the whole point: the bug this replaces
            // popped presigns in local instantiation order, which diverged
            // across a staggered restart. The `network_encryption_key_id` is
            // carried IN the consensus-agreed demand (frozen at announce), and
            // the sign later instantiates under that same key (stored with the
            // assignment), so the key is fully consensus-uniform — it does not
            // rest on the announce-time and instantiate-time key resolutions
            // agreeing.
            self.agreed_noa_presign_demands_queue.extend(
                noa_presign_demand_messages
                    .into_iter()
                    .map(|demand| ParkedNOAPresignDemand {
                        demand,
                        delivered_at_consensus_round: consensus_round,
                    }),
            );
            if !self.agreed_noa_presign_demands_queue.is_empty() {
                let park_rounds = self.noa_presign_demand_park_rounds;
                self.agreed_noa_presign_demands_queue.retain(|parked| {
                    let ParkedNOAPresignDemand {
                        demand,
                        delivered_at_consensus_round,
                    } = parked;
                    // Atomic + idempotent (see `assign_presign_for_demand`): pops a
                    // presign and records the assignment (raw presign + the
                    // demand's network key id) in ONE committed batch, or
                    // returns the existing assignment without popping. The pop
                    // and the record MUST be one commit — a crash between a
                    // self-committed pop and a separate record would let a
                    // re-drain after a consensus-round replay pop a different
                    // presign than peers assigned. `Assigned` (just now, or by
                    // an earlier drain) and `Evicted` are both terminal — drop
                    // from the queue; `PoolEmpty` => keep, preserving order
                    // across rounds until the presign is generated or the park
                    // bound expires; `Err` => keep for retry.
                    // The algorithm comes from the demand IDENTITY, never from
                    // the announcement: the consensus dedup key is the
                    // demand-id digest alone, so the first announcement
                    // sequenced for a demand would otherwise supply that field
                    // for the whole network while the honest duplicates are
                    // dropped behind it. Carrying no second copy is stronger
                    // than comparing two: an announcer with a different
                    // algorithm produces a DIFFERENT identity — a demand no
                    // honest consumer looks up — and the pool popped here
                    // cannot disagree with the session instantiated from the
                    // same id.
                    //
                    // `network_encryption_key_id` is NOT derivable from the
                    // identity (it is frozen at announce time on purpose, so
                    // the assignment does not rest on the announce-time and
                    // instantiate-time key resolutions agreeing), so it stays
                    // announcer-supplied behind the same dedup key. It is
                    // deliberately NOT validated against the locally adopted
                    // key set: honest validators transiently hold different
                    // adopted sets (every epoch start has such a window), so a
                    // local reject would drop honest demands. A demand naming a
                    // key this validator has no pool for therefore parks, in
                    // order, and is retried every round — and is dropped only
                    // once it has been parked for `park_rounds` consensus
                    // rounds, which is what stops a demand naming a key nobody
                    // will ever adopt from parking for the whole epoch and
                    // blocking that epoch's NOA checkpoint finalization. The
                    // bound cannot tell that case apart from a key still on its
                    // way, because no consensus-uniform signal distinguishes
                    // them; it is sized so that no honest window comes near it
                    // (see `NOA_PRESIGN_DEMAND_PARK_ROUNDS`), and
                    // `dev-docs/specs/internal-presign-pool.md` records why
                    // parking-with-a-bound is the only safe shape here.
                    match self.epoch_store.assign_presign_for_demand(
                        &PresignDemand::Noa {
                            demand_id: demand.demand_id.clone(),
                        },
                        demand.demand_id.expected_signature_algorithm(),
                        demand.network_encryption_key_id,
                    ) {
                        Ok(PresignAssignmentOutcome::Assigned { .. }) => false,
                        // Dropped by an earlier round of this same stream and
                        // recorded durably, so this is a re-drain (a restart
                        // replaying the epoch's rounds). Terminal already: leave
                        // the store alone, and do not re-log or re-count what
                        // the original pass already reported.
                        Ok(PresignAssignmentOutcome::Evicted) => {
                            debug!(
                                demand_id = ?demand.demand_id,
                                demand_id_digest = hex::encode(demand.demand_id_digest()),
                                "replayed a NOA presign demand that was already dropped at the \
                                 park bound; leaving it dropped"
                            );
                            false
                        }
                        Ok(PresignAssignmentOutcome::PoolEmpty) => {
                            let parked_rounds =
                                consensus_round.saturating_sub(*delivered_at_consensus_round);
                            if parked_rounds < park_rounds {
                                return true;
                            }
                            // Record the drop DURABLY before dropping the demand
                            // from the queue. The pool is not rewound by a
                            // replay, so a drop kept only in memory would let a
                            // restart re-read this demand at its delivery round
                            // against a pool that filled after the drop and pop
                            // for a demand every peer abandoned. On a write
                            // error, keep the demand and retry next round —
                            // the same failure posture as an assignment error.
                            if let Err(e) =
                                self.epoch_store.evict_noa_presign_demand(&demand.demand_id)
                            {
                                error!(
                                    error = ?e,
                                    demand_id = ?demand.demand_id,
                                    "failed to record a NOA presign demand's drop — keeping it \
                                     parked for retry"
                                );
                                return true;
                            }
                            self.dwallet_mpc_metrics
                                .noa_presign_demands_evicted_total
                                .with_label_values(&[&format!(
                                    "{:?}",
                                    demand.demand_id.expected_signature_algorithm()
                                )])
                                .inc();
                            error!(
                                demand_id = ?demand.demand_id,
                                demand_id_digest = hex::encode(demand.demand_id_digest()),
                                network_encryption_key_id = ?demand.network_encryption_key_id,
                                announcing_authority = ?demand.authority,
                                delivered_at_consensus_round,
                                eviction_consensus_round = consensus_round,
                                parked_rounds,
                                "dropping a NOA presign demand that stayed unassigned for the \
                                 whole park bound: no presign pool exists for the network \
                                 encryption key its announcement named. This demand's sign will \
                                 NOT happen in this epoch — either the announcer named a key the \
                                 network never adopts, or that key took longer than the bound to \
                                 arrive"
                            );
                            false
                        }
                        Err(e) => {
                            ika_types::report_invariant_violation!(
                                "noa_presign_assignment",
                                error=?e,
                                "failed to assign presign for NOA demand — keeping for retry"
                            );
                            true
                        }
                    }
                });
            }

            // Group checkpoint messages by chain.
            let mut messages_by_chain: HashMap<
                CounterpartyChainKind,
                Vec<DWalletCheckpointMessageKind>,
            > = HashMap::new();

            for (output, counterparty_chain) in agreed_external_mpc_outputs {
                if let DWalletMPCOutputKind::External { output } = output {
                    let chain = counterparty_chain.unwrap_or(CounterpartyChainKind::Sui);
                    messages_by_chain.entry(chain).or_default().extend(output);
                }
            }

            // Global presign and verified messages are Sui for now.
            let sui_messages = messages_by_chain
                .entry(CounterpartyChainKind::Sui)
                .or_default();
            sui_messages.extend(global_presign_checkpoint_messages);
            sui_messages.extend(verified_dwallet_checkpoint_messages);

            // EndOfPublish detection — always on Sui messages.
            let sui_checkpoint_messages = messages_by_chain
                .get(&CounterpartyChainKind::Sui)
                .map(|m| m.as_slice())
                .unwrap_or(&[]);
            if !self.end_of_publish {
                let final_round = sui_checkpoint_messages
                    .last()
                    .is_some_and(|msg| matches!(msg, DWalletCheckpointMessageKind::EndOfPublish));
                if final_round {
                    self.end_of_publish = true;
                    self.dwallet_mpc_metrics.service_end_of_publish_local.set(1);

                    info!(
                        authority=?self.name,
                        epoch=?self.epoch,
                        consensus_round,
                        "End of publish reached, no more dwallet checkpoints will be processed for this epoch"
                    );
                }

                for (chain, checkpoint_messages) in &mut messages_by_chain {
                    if checkpoint_messages.is_empty() {
                        continue;
                    }

                    // BLS checkpoint path (Sui only for now).
                    if *chain == CounterpartyChainKind::Sui
                        && self.protocol_config.bls_checkpoints()
                    {
                        let pending_checkpoint =
                            PendingDWalletCheckpoint::V1(PendingDWalletCheckpointV1 {
                                messages: checkpoint_messages.clone(),
                                details: PendingDWalletCheckpointInfo {
                                    checkpoint_height: consensus_round,
                                },
                            });
                        if let Err(e) = self
                            .epoch_store
                            .insert_pending_dwallet_checkpoint(pending_checkpoint)
                        {
                            // `EpochEnded` here is the reconfiguration
                            // boundary, not a defect: this service is
                            // per-epoch and teardown does not join it, so the
                            // store's tables can be swapped out from under an
                            // iteration that is still running. Stop the
                            // iteration gracefully — the same semantics the
                            // per-round store reads used to get from
                            // `stop_on_epoch_end!`, which existed because
                            // panicking on this race crashed the node and
                            // stalled reconfiguration under churn.
                            if let IkaError::EpochEnded(ended_epoch) = e {
                                info!(
                                    ended_epoch,
                                    consensus_round,
                                    "epoch ended while writing a pending dWallet checkpoint; \
                                     stopping this service iteration gracefully"
                                );
                                return;
                            }
                            error!(
                                    error=?e,
                                    ?consensus_round,
                                    ?checkpoint_messages,
                                    "failed to insert pending checkpoint into the local DB"
                            );

                            panic!("failed to insert pending checkpoint into the local DB");
                        };

                        debug!(
                            ?consensus_round,
                            "Notifying checkpoint service about new pending checkpoint(s)",
                        );
                        if let Some(ref service) = self.dwallet_checkpoint_service
                            && let Err(e) = service.notify_checkpoint()
                        {
                            // Same boundary race as the write above.
                            if let IkaError::EpochEnded(ended_epoch) = e {
                                info!(
                                    ended_epoch,
                                    consensus_round,
                                    "epoch ended while notifying the checkpoint service; \
                                     stopping this service iteration gracefully"
                                );
                                return;
                            }
                            error!(
                                error=?e,
                                ?consensus_round,
                                "failed to notify checkpoint service about new pending checkpoint(s)"
                            );

                            panic!(
                                "failed to notify checkpoint service about new pending checkpoint(s)"
                            );
                        }
                    }

                    // NOA checkpoint routing by chain.
                    if let Some(ref ctx) = self.current_agreed_sui_chain_context {
                        match chain {
                            CounterpartyChainKind::Sui => {
                                if let Some(ref mut handler) = self.dwallet_checkpoint_handler {
                                    for buffered in self.buffered_noa_dwallet_messages.drain(..) {
                                        let requests =
                                            handler.handle_new_checkpoint(buffered, ctx.clone());
                                        self.pending_network_owned_address_sign_requests
                                            .extend(requests);
                                    }
                                    let requests = handler.handle_new_checkpoint(
                                        std::mem::take(checkpoint_messages),
                                        ctx.clone(),
                                    );
                                    self.pending_network_owned_address_sign_requests
                                        .extend(requests);
                                }
                            }
                        }
                    } else {
                        match chain {
                            CounterpartyChainKind::Sui => {
                                self.buffered_noa_dwallet_messages
                                    .push(std::mem::take(checkpoint_messages));
                            }
                        }
                    }
                }

                // System checkpoint messages — always Sui, independent of MPC session chains.
                if let Some(ref ctx) = self.current_agreed_sui_chain_context {
                    if let Some(ref mut handler) = self.system_checkpoint_handler {
                        for buffered in self.buffered_noa_system_messages.drain(..) {
                            let requests = handler.handle_new_checkpoint(buffered, ctx.clone());
                            self.pending_network_owned_address_sign_requests
                                .extend(requests);
                        }
                        if !verified_system_checkpoint_messages.is_empty() {
                            let requests = handler.handle_new_checkpoint(
                                verified_system_checkpoint_messages,
                                ctx.clone(),
                            );
                            self.pending_network_owned_address_sign_requests
                                .extend(requests);
                        }
                    }
                } else if !verified_system_checkpoint_messages.is_empty() {
                    self.buffered_noa_system_messages
                        .push(verified_system_checkpoint_messages);
                }

                if let Err(e) = self
                    .state
                    .insert_dwallet_mpc_computation_completed_sessions(&completed_sessions)
                {
                    error!(
                        error=?e,
                        ?consensus_round,
                        ?completed_sessions,
                        "failed to insert computation completed MPC sessions into the local (perpetual tables) DB"
                    );

                    panic!(
                        "failed to insert computation completed MPC sessions into the local (perpetual tables) DB"
                    );
                }
            }

            self.last_read_consensus_round = Some(consensus_round);

            self.dwallet_mpc_metrics
                .last_process_mpc_consensus_round
                .set(consensus_round as i64);
            // Publish progress for the consensus-path stall detector. It has to
            // live over there: every way this service stops also stops any
            // check placed inside it. The catch-up gate state travels with the
            // round because from the commit path a restart's replay backlog and
            // a service that never started look identical — and it travels on
            // EVERY consumed round because over there it is a lease, held only
            // while this loop keeps renewing it.
            self.epoch_store.record_mpc_consumed_consensus_round(
                consensus_round,
                self.dwallet_mpc_manager.is_catching_up(),
            );
            tokio::task::yield_now().await;
        }
    }

    pub(crate) async fn handle_computation_results_and_submit_to_consensus(
        &mut self,
        completed_computation_results: HashMap<
            ComputationId,
            DwalletMPCResult<GuaranteedOutputDeliveryRoundResult>,
        >,
    ) {
        let committee = self.committee.clone();
        let validator_name = self.name;

        for (computation_id, computation_result) in completed_computation_results {
            let session_identifier = computation_id.session_identifier;
            let mpc_round = computation_id.mpc_round;
            let consensus_adapter = self.dwallet_submit_to_consensus.clone();

            let computation_result_data = if let Some(mpc_round) = mpc_round {
                ComputationResultData::MPC { mpc_round }
            } else {
                ComputationResultData::Native
            };
            let (computation_result_name, computation_error) = match &computation_result {
                Ok(GuaranteedOutputDeliveryRoundResult::Advance { .. }) => ("advance", None),
                Ok(GuaranteedOutputDeliveryRoundResult::Finalize { .. }) => ("finalize", None),
                Err(error) => ("error", Some(dwallet_mpc_error_diagnostic(error))),
            };
            if let Some(session) = self
                .dwallet_mpc_manager
                .sessions
                .get_mut(&session_identifier)
            {
                session.record_computation_completed(
                    computation_id.consensus_round,
                    computation_id.mpc_round,
                    computation_id.attempt_number,
                    computation_result_name,
                    computation_error
                        .as_ref()
                        .map(|diagnostic| diagnostic.error_code),
                    computation_error
                        .as_ref()
                        .map_or_else(Vec::new, |diagnostic| diagnostic.party_ids.clone()),
                );
            }
            if let Some(diagnostic) = computation_error {
                self.dwallet_mpc_manager.emit_session_anomaly(
                    session_identifier,
                    MpcAnomalyKind::LocalComputationFailed,
                    MpcAnomalyContext {
                        current_consensus_round: self.last_read_consensus_round,
                        trigger_conditions: vec!["local_mpc_computation_returned_error"],
                        error_code: Some(diagnostic.error_code),
                        error_party_ids: diagnostic.party_ids,
                        error_backtrace: diagnostic.backtrace,
                        error_backtrace_truncated: diagnostic.backtrace_truncated,
                        ..Default::default()
                    },
                );
            }

            // Skip ONLY this result on a missing/non-active session —
            // never abandon the rest of the batch. A result for a session
            // that went non-active while its computation was in flight is
            // routine under load (e.g., it completed via the peers' output
            // quorum); a `return` here used to drop every other session's
            // round messages and outputs in the same batch, starving those
            // sessions below the message threshold network-wide and wedging
            // the epoch close (locked-set sessions could never complete).
            let Some(session) = self.dwallet_mpc_manager.sessions.get(&session_identifier) else {
                ika_types::report_invariant_violation!(
                    "computation_session_missing",
                    ?session_identifier,
                    validator=?validator_name,
                    ?computation_result_data,
                    "failed to retrieve session for which a computation update was received"
                );
                continue;
            };

            let SessionStatus::Active { request, .. } = session.status.clone() else {
                debug!(
                    ?session_identifier,
                    validator=?validator_name,
                    ?computation_result_data,
                    "received a computation update for a non-active session"
                );
                // An honest straggler: the session completed via the peers'
                // output quorum while this validator was still computing, so
                // this result is correctly discarded without submission.
                // Expected under load for any validator outside the fastest
                // two-thirds of a session — counted, never snapshotted, so
                // high session churn cannot flood the anomaly taxonomy.
                self.dwallet_mpc_manager
                    .dwallet_mpc_metrics
                    .completion_races_total
                    .with_label_values(&[
                        "local_computation_update_received_after_session_became_non_active",
                        session_type_label(session_identifier.session_type()),
                    ])
                    .inc();
                // For a network-key reconfiguration Finalize, digest the
                // discarded raw output bytes and compare them against the
                // quorum-agreed output recorded at quorum time — this is the
                // only remaining byte-level cross-version compatibility
                // evidence for this validator, so it does warrant a
                // diagnostic snapshot. Observability only: nothing is
                // submitted and the session stays non-active.
                let late_output_trigger = if let Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    public_output_value,
                    malicious_parties,
                    ..
                }) = &computation_result
                    && let Some(session) = self
                        .dwallet_mpc_manager
                        .sessions
                        .get_mut(&session_identifier)
                    && session.network_key_reconfiguration
                {
                    let late_output_digest = raw_output_digest(public_output_value);
                    let matches_quorum =
                        session.record_late_output(late_output_digest, malicious_parties.len());
                    let quorum_output_digest = session.quorum_raw_output_digest.map(hex::encode);
                    match matches_quorum {
                        Some(true) => {
                            info!(
                                ?session_identifier,
                                validator=?validator_name,
                                late_output_digest = %hex::encode(late_output_digest),
                                reported_malicious_count = malicious_parties.len(),
                                "late network-key reconfiguration output matches the quorum-agreed output; session already completed, output not submitted"
                            );
                            Some("late_network_key_output_matched_quorum")
                        }
                        Some(false) => {
                            error!(
                                ?session_identifier,
                                validator=?validator_name,
                                late_output_digest = %hex::encode(late_output_digest),
                                quorum_output_digest = ?quorum_output_digest,
                                reported_malicious_count = malicious_parties.len(),
                                "late network-key reconfiguration output DIVERGES from the quorum-agreed output"
                            );
                            Some("late_network_key_output_diverged_from_quorum")
                        }
                        None => {
                            warn!(
                                ?session_identifier,
                                validator=?validator_name,
                                late_output_digest = %hex::encode(late_output_digest),
                                reported_malicious_count = malicious_parties.len(),
                                "late network-key reconfiguration output recorded without a quorum digest to compare against"
                            );
                            Some("late_network_key_output_unverified")
                        }
                    }
                } else {
                    None
                };
                if let Some(late_output_trigger) = late_output_trigger {
                    self.dwallet_mpc_manager.emit_session_anomaly(
                        session_identifier,
                        MpcAnomalyKind::ComputationUpdateAfterSessionCompletion,
                        MpcAnomalyContext {
                            current_consensus_round: self.last_read_consensus_round,
                            trigger_conditions: vec![
                                "local_computation_update_received_after_session_became_non_active",
                                late_output_trigger,
                            ],
                            ..Default::default()
                        },
                    );
                }
                continue;
            };

            match computation_result {
                Ok(GuaranteedOutputDeliveryRoundResult::Advance { message }) => {
                    debug!(
                        ?session_identifier,
                        validator=?validator_name,
                        ?computation_result_data,
                        "Advanced session"
                    );

                    if let Some(session) = self
                        .dwallet_mpc_manager
                        .sessions
                        .get_mut(&session_identifier)
                    {
                        session.record_message_submission(
                            self.last_read_consensus_round,
                            computation_id.mpc_round,
                            computation_id.attempt_number,
                            message.len(),
                        );
                    }
                    let message = self.new_dwallet_mpc_message(session_identifier, message);

                    if let Err(err) = consensus_adapter.submit_to_consensus(&[message]).await {
                        error!(
                            ?session_identifier,
                            validator=?validator_name,
                            ?computation_result_data,
                            error=?err,
                            "failed to submit a message to consensus"
                        );
                        self.dwallet_mpc_manager.emit_session_anomaly(
                            session_identifier,
                            MpcAnomalyKind::ProtocolMessageSubmissionFailed,
                            MpcAnomalyContext {
                                current_consensus_round: self.last_read_consensus_round,
                                trigger_conditions: vec![
                                    "mpc_protocol_message_submission_to_consensus_failed",
                                ],
                                error_code: Some("consensus_submission"),
                                ..Default::default()
                            },
                        );
                    }
                }
                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    malicious_parties,
                    private_output,
                    public_output_value,
                }) => {
                    debug!(
                        ?session_identifier,
                        validator=?validator_name,
                        "Reached output for session"
                    );

                    // Fast Schnorr (VSS) presign: persist the private nonce-share
                    // output. The GOD layer produces a blended
                    // `bcs(Vec<PrivatePresignOutput>)`; split it into one serialized
                    // `PrivatePresignOutput` per blending index and persist each row
                    // keyed by `(presign session id, blending index)`, for the later
                    // sign to recover. All other protocols (AHE presign, DKG, reconfig,
                    // sign) have empty/irrelevant private outputs — skip.
                    if matches!(
                        request.protocol_data,
                        ProtocolData::Presign { .. } | ProtocolData::InternalPresign { .. }
                    ) && let Some(signature_algorithm) = request
                        .protocol_data
                        .signature_algorithm()
                        .filter(|algorithm| algorithm.is_vss())
                    {
                        let presign_session_id = CommitmentSizedNumber::from_le_slice(
                            session_identifier.to_vec().as_slice(),
                        );
                        match crate::dwallet_mpc::sign::split_vss_presign_private_outputs(
                            signature_algorithm,
                            &private_output,
                        ) {
                            Ok(entries) => {
                                entries
                                    .into_iter()
                                    .for_each(|(blending_index, entry_bytes)| {
                                        if let Err(err) =
                                            self.epoch_store.store_presign_private_output(
                                                presign_session_id,
                                                blending_index,
                                                entry_bytes,
                                            )
                                        {
                                            error!(
                                                ?session_identifier,
                                                validator=?validator_name,
                                                ?blending_index,
                                                error=?err,
                                                "failed to persist VSS presign private output"
                                            );
                                        }
                                    });
                            }
                            Err(err) => {
                                error!(
                                    ?session_identifier,
                                    validator=?validator_name,
                                    error=?err,
                                    "failed to split blended VSS presign private output"
                                );
                            }
                        }
                    }

                    let consensus_adapter = self.dwallet_submit_to_consensus.clone();
                    let malicious_authorities = if !malicious_parties.is_empty() {
                        let malicious_authorities =
                            party_ids_to_authority_names(&malicious_parties, &committee);

                        error!(
                            ?session_identifier,
                                validator=?validator_name,
                                ?malicious_parties,
                                ?malicious_authorities,
                            "malicious parties detected upon MPC session finalize",
                        );

                        malicious_authorities
                    } else {
                        vec![]
                    };

                    let rejected = false;

                    if let Some(consensus_message) = self.new_dwallet_mpc_output(
                        session_identifier,
                        &request,
                        public_output_value,
                        malicious_authorities,
                        rejected,
                    ) {
                        let output_digest = diagnostic_output_digest(&consensus_message);
                        if let Some(session) = self
                            .dwallet_mpc_manager
                            .sessions
                            .get_mut(&session_identifier)
                        {
                            session.record_local_output_produced(
                                Some(computation_id.consensus_round),
                                output_digest,
                                rejected,
                            );
                        }
                        if rejected {
                            self.dwallet_mpc_manager.emit_session_anomaly(
                                session_identifier,
                                MpcAnomalyKind::LocalRejectedOutput,
                                MpcAnomalyContext {
                                    current_consensus_round: self.last_read_consensus_round,
                                    trigger_conditions: vec![
                                        "local_validator_submitting_rejected_output",
                                    ],
                                    ..Default::default()
                                },
                            );
                        }
                        let submission_result = consensus_adapter
                            .submit_to_consensus(&[consensus_message])
                            .await;
                        if let Some(session) = self
                            .dwallet_mpc_manager
                            .sessions
                            .get_mut(&session_identifier)
                        {
                            session.record_local_output_submission(
                                self.last_read_consensus_round,
                                output_digest,
                                rejected,
                                submission_result.is_ok(),
                                submission_result
                                    .as_ref()
                                    .err()
                                    .map(|_| "consensus_submission"),
                            );
                        }
                        if let Err(err) = submission_result {
                            error!(
                                ?session_identifier,
                                validator=?validator_name,
                                error=?err,
                                "failed to submit an MPC output message to consensus",
                            );
                            self.dwallet_mpc_manager.emit_session_anomaly(
                                session_identifier,
                                MpcAnomalyKind::OutputSubmissionFailed,
                                MpcAnomalyContext {
                                    current_consensus_round: self.last_read_consensus_round,
                                    trigger_conditions: vec![
                                        "mpc_output_submission_to_consensus_failed",
                                    ],
                                    error_code: Some("consensus_submission"),
                                    ..Default::default()
                                },
                            );
                        }
                    }
                }
                Err(err) => match request.session_type {
                    SessionType::InternalPresign | SessionType::NetworkOwnedAddressSign => {
                        ika_types::report_invariant_violation!(
                            "internal_session_failed",
                            session_identifier=?session.session_identifier,
                            session_type=?request.session_type,
                            error=?err,
                            "internal session failed",
                        );
                    }
                    _ => {
                        self.submit_failed_session(session_identifier, &request, err)
                            .await;
                    }
                },
            }
        }
    }

    /// Submit rejection outputs for admission-failed requests, holding back
    /// user-session rejections beyond the epoch-close lock target: a
    /// rejection that reaches quorum completes the session on-chain
    /// (Rejected counts as completed), and completing a user session beyond
    /// the locked target permanently wedges the epoch — the end-of-publish
    /// predicate is a strict equality and the completed counter never goes
    /// back down. Held rejections retry each iteration as the synced target
    /// advances; past the epoch boundary the request is re-pulled and
    /// re-rejected under the next epoch's target. System and internal
    /// sessions are not lock-gated and submit immediately.
    async fn submit_rejections_covered_by_lock_target(
        &mut self,
        rejected_sessions: Vec<DWalletSessionRequest>,
    ) {
        let lock_target = self
            .dwallet_mpc_manager
            .last_session_to_complete_in_current_epoch;
        let covered_by_lock_target = |request: &DWalletSessionRequest| match request.session_type {
            SessionType::User => match request.session_sequence_number {
                Some(session_sequence_number) => session_sequence_number <= lock_target,
                // Should never happen (user sessions always carry a sequence
                // number); submit rather than buffer forever.
                None => true,
            },
            _ => true,
        };

        for request in &rejected_sessions {
            if !covered_by_lock_target(request) {
                info!(
                    session_identifier = ?request.session_identifier,
                    session_sequence_number = ?request.session_sequence_number,
                    last_session_to_complete_in_current_epoch = lock_target,
                    "holding session rejection until the epoch-close lock target covers it; retried as the target advances, re-pulled next epoch otherwise"
                );
            }
        }
        self.pending_rejected_sessions.extend(rejected_sessions);

        let (covered, deferred): (Vec<_>, Vec<_>) = self
            .pending_rejected_sessions
            .drain(..)
            .partition(covered_by_lock_target);
        self.pending_rejected_sessions = deferred;
        self.handle_failed_requests_and_submit_reject_to_consensus(covered)
            .await;
    }

    async fn handle_failed_requests_and_submit_reject_to_consensus(
        &mut self,
        rejected_sessions: Vec<DWalletSessionRequest>,
    ) {
        for request in rejected_sessions {
            let session_identifier = request.session_identifier;
            self.submit_failed_session(
                session_identifier,
                &request,
                DwalletMPCError::MPCSessionError {
                    session_identifier,
                    error: "failed to create session".to_string(),
                },
            )
            .await;
        }
    }

    async fn submit_failed_session(
        &mut self,
        session_identifier: SessionIdentifier,
        request: &DWalletSessionRequest,
        error: DwalletMPCError,
    ) {
        let validator_name = self.name.to_string();
        let party_id = self.dwallet_mpc_manager.party_id;
        let error_diagnostic = dwallet_mpc_error_diagnostic(&error);
        let protocol_metric_data = DWalletSessionRequestMetricData::from(&request.protocol_data);
        error!(
            ?session_identifier,
            validator=?validator_name,
            party_id,
            session_type=?request.session_type,
            session_sequence_number=?request.session_sequence_number,
            protocol_data=?protocol_metric_data.to_string(),
            error=?error,
            error_kind=%error_diagnostic.error_code,
            "rejecting session."
        );

        self.dwallet_mpc_metrics
            .sessions_rejected_total
            .with_label_values(&[protocol_metric_data.name(), error.kind()])
            .inc();

        let consensus_adapter = self.dwallet_submit_to_consensus.clone();
        let rejected = true;

        if let Some(consensus_message) =
            self.new_dwallet_mpc_output(session_identifier, request, vec![], vec![], rejected)
        {
            let output_digest = diagnostic_output_digest(&consensus_message);
            if let Some(session) = self
                .dwallet_mpc_manager
                .sessions
                .get_mut(&session_identifier)
            {
                session.record_local_output_produced(
                    self.last_read_consensus_round,
                    output_digest,
                    rejected,
                );
            }
            self.dwallet_mpc_manager.emit_session_anomaly(
                session_identifier,
                MpcAnomalyKind::LocalRejectedOutput,
                MpcAnomalyContext {
                    current_consensus_round: self.last_read_consensus_round,
                    trigger_conditions: vec!["local_validator_submitting_rejected_output"],
                    error_code: Some(error_diagnostic.error_code),
                    error_party_ids: error_diagnostic.party_ids,
                    error_backtrace: error_diagnostic.backtrace,
                    error_backtrace_truncated: error_diagnostic.backtrace_truncated,
                    ..Default::default()
                },
            );
            let submission_result = consensus_adapter
                .submit_to_consensus(&[consensus_message])
                .await;
            if let Some(session) = self
                .dwallet_mpc_manager
                .sessions
                .get_mut(&session_identifier)
            {
                session.record_local_output_submission(
                    self.last_read_consensus_round,
                    output_digest,
                    rejected,
                    submission_result.is_ok(),
                    submission_result
                        .as_ref()
                        .err()
                        .map(|_| "consensus_submission"),
                );
            }
            if let Err(err) = submission_result {
                error!(
                    ?session_identifier,
                    validator=?validator_name,
                    error=?err,
                    "failed to submit an MPC SessionFailed message to consensus"
                );
                self.dwallet_mpc_manager.emit_session_anomaly(
                    session_identifier,
                    MpcAnomalyKind::RejectedOutputSubmissionFailed,
                    MpcAnomalyContext {
                        current_consensus_round: self.last_read_consensus_round,
                        trigger_conditions: vec!["rejected_output_submission_to_consensus_failed"],
                        error_code: Some("consensus_submission"),
                        ..Default::default()
                    },
                );
            }
        }
    }

    /// Create a new consensus transaction with the message to be sent to the other MPC parties.
    /// Returns Error only if the epoch switched in the middle and was not available.
    fn new_dwallet_mpc_message(
        &self,
        session_identifier: SessionIdentifier,
        message: MPCMessage,
    ) -> ConsensusTransaction {
        ConsensusTransaction::new_dwallet_mpc_message(self.name, session_identifier, message)
    }

    /// Create a new consensus transaction with the flow result (output) to be
    /// sent to the other MPC parties.
    /// Errors if the epoch was switched in the middle and was not available.
    fn new_dwallet_mpc_output(
        &self,
        session_identifier: SessionIdentifier,
        session_request: &DWalletSessionRequest,
        output: Vec<u8>,
        malicious_authorities: Vec<AuthorityName>,
        rejected: bool,
    ) -> Option<ConsensusTransaction> {
        match session_request.session_type {
            SessionType::InternalPresign => match &session_request.protocol_data {
                ProtocolData::InternalPresign {
                    data,
                    dwallet_network_encryption_key_id,
                } => {
                    if session_request.session_sequence_number.is_none() {
                        ika_types::report_invariant_violation!(
                            "internal_presign_sequence_missing",
                            ?session_identifier,
                            "internal presign session missing session_sequence_number",
                        );
                    }
                    Some(ConsensusTransaction::new_dwallet_internal_mpc_output(
                        self.name,
                        session_identifier,
                        DWalletInternalMPCOutputKind::InternalPresign {
                            output,
                            curve: data.curve,
                            signature_algorithm: data.signature_algorithm,
                            session_sequence_number: session_request
                                .session_sequence_number
                                .expect("internal presign sessions always have a session sequence number"),
                            dwallet_network_encryption_key_id: *dwallet_network_encryption_key_id,
                        },
                        malicious_authorities,
                    ))
                }
                _ => {
                    ika_types::report_invariant_violation!(
                        "internal_presign_protocol_mismatch",
                        session_identifier=?session_identifier,
                        "mismatch between session type and protocol data during MPC output creation",
                    );

                    None
                }
            },
            SessionType::NetworkOwnedAddressSign => match &session_request.protocol_data {
                ProtocolData::NetworkOwnedAddressSign { data, message, .. } => {
                    Some(ConsensusTransaction::new_dwallet_internal_mpc_output(
                        self.name,
                        session_identifier,
                        DWalletInternalMPCOutputKind::NetworkOwnedAddressSign {
                            output,
                            session_identifier,
                            message: message.clone(),
                            curve: data.curve,
                            signature_algorithm: data.signature_algorithm,
                            hash_scheme: data.hash_scheme.into(),
                        },
                        malicious_authorities,
                    ))
                }
                _ => {
                    ika_types::report_invariant_violation!(
                        "noa_sign_protocol_mismatch",
                        session_identifier=?session_identifier,
                        "mismatch between session type and protocol data during MPC output creation",
                    );

                    None
                }
            },
            SessionType::User | SessionType::System => {
                // Cache canonical (non-rejected) network DKG /
                // reconfig output bytes locally before they get
                // moved into the message builder. The handoff
                // trigger reads these back at EndOfPublish.
                if !rejected {
                    match &session_request.protocol_data {
                        ProtocolData::NetworkEncryptionKeyDkg {
                            dwallet_network_encryption_key_id,
                            ..
                        } => {
                            if let Err(e) = self.epoch_store.cache_network_dkg_output(
                                *dwallet_network_encryption_key_id,
                                &output,
                            ) {
                                warn!(
                                    error = ?e,
                                    ?dwallet_network_encryption_key_id,
                                    "failed to cache network DKG output"
                                );
                            }
                        }
                        ProtocolData::NetworkEncryptionKeyReconfiguration {
                            dwallet_network_encryption_key_id,
                            ..
                        } => {
                            if let Err(e) = self.epoch_store.cache_network_reconfiguration_output(
                                *dwallet_network_encryption_key_id,
                                session_request.epoch,
                                &output,
                            ) {
                                warn!(
                                    error = ?e,
                                    ?dwallet_network_encryption_key_id,
                                    "failed to cache network reconfiguration output"
                                );
                            }
                        }
                        _ => {}
                    }
                }

                let output = Self::build_dwallet_checkpoint_message_kinds_from_output(
                    &session_identifier,
                    session_request,
                    output,
                    rejected,
                );
                Some(ConsensusTransaction::new_dwallet_mpc_output(
                    self.name,
                    session_identifier,
                    output,
                    malicious_authorities,
                ))
            }
        }
    }

    fn build_dwallet_checkpoint_message_kinds_from_output(
        session_identifier: &SessionIdentifier,
        session_request: &DWalletSessionRequest,
        output: Vec<u8>,
        rejected: bool,
    ) -> Vec<DWalletCheckpointMessageKind> {
        debug!(
            mpc_protocol=?DWalletSessionRequestMetricData::from(&session_request.protocol_data),
            session_identifier=?session_identifier,
            "Creating session output message for checkpoint"
        );
        match &session_request.protocol_data {
            ProtocolData::DWalletDKG {
                dwallet_id, data, ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletDKGOutput(DWalletDKGOutput {
                    output,
                    dwallet_id: dwallet_id.to_vec(),
                    encrypted_secret_share_id: match data.user_secret_key_share {
                        UserSecretKeyShareEventType::Encrypted {
                            encrypted_user_secret_key_share_id,
                            ..
                        } => Some(encrypted_user_secret_key_share_id.to_vec()),
                        UserSecretKeyShareEventType::Public { .. } => None,
                    },
                    sign_id: None,
                    signature: vec![],
                    rejected,
                    session_sequence_number: session_request.session_sequence_number.unwrap_or(0),
                });
                vec![tx]
            }
            ProtocolData::DWalletDKGAndSign {
                dwallet_id, data, ..
            } => {
                let tx = if rejected {
                    DWalletCheckpointMessageKind::RespondDWalletDKGOutput(DWalletDKGOutput {
                        output,
                        dwallet_id: dwallet_id.to_vec(),
                        encrypted_secret_share_id: match data.user_secret_key_share {
                            UserSecretKeyShareEventType::Encrypted {
                                encrypted_user_secret_key_share_id,
                                ..
                            } => Some(encrypted_user_secret_key_share_id.to_vec()),
                            UserSecretKeyShareEventType::Public { .. } => None,
                        },
                        sign_id: None,
                        signature: vec![],
                        rejected,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    })
                } else {
                    let (dwallet_dkg_output, signature): (Vec<u8>, Vec<u8>) =
                        match bcs::from_bytes(&output) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                ika_types::report_invariant_violation!(
                                    "dkg_and_sign_checkpoint_deserialize",
                                    error = ?e,
                                    "Failed to deserialize dwallet dkg + sign output"
                                );
                                return vec![];
                            }
                        };
                    DWalletCheckpointMessageKind::RespondDWalletDKGOutput(DWalletDKGOutput {
                        output: dwallet_dkg_output,
                        dwallet_id: dwallet_id.to_vec(),
                        encrypted_secret_share_id: match data.user_secret_key_share {
                            UserSecretKeyShareEventType::Encrypted {
                                encrypted_user_secret_key_share_id,
                                ..
                            } => Some(encrypted_user_secret_key_share_id.to_vec()),
                            UserSecretKeyShareEventType::Public { .. } => None,
                        },
                        sign_id: Some(data.sign_id.to_vec()),
                        signature,
                        rejected,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    })
                };
                vec![tx]
            }
            ProtocolData::InternalPresign { .. } => {
                ika_types::report_invariant_violation!(
                    "internal_presign_checkpoint",
                    "received an internal presign session for checkpointing"
                );
                vec![]
            }
            ProtocolData::Presign {
                dwallet_id,
                presign_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletPresign(PresignOutput {
                    presign: output,
                    dwallet_id: dwallet_id.map(|id| id.to_vec()),
                    presign_id: presign_id.to_vec(),
                    rejected,
                    session_sequence_number: session_request.session_sequence_number.unwrap_or(0),
                });

                vec![tx]
            }
            ProtocolData::NetworkOwnedAddressSign { .. } => {
                ika_types::report_invariant_violation!(
                    "noa_sign_checkpoint",
                    "received an network-owned-address sign session for checkpointing"
                );
                vec![]
            }
            ProtocolData::Sign {
                dwallet_id,
                sign_id,
                is_future_sign,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletSign(SignOutput {
                    signature: output,
                    dwallet_id: dwallet_id.to_vec(),
                    is_future_sign: *is_future_sign,
                    sign_id: sign_id.to_vec(),
                    rejected,
                    session_sequence_number: session_request.session_sequence_number.unwrap_or(0),
                });

                vec![tx]
            }
            ProtocolData::EncryptedShareVerification {
                dwallet_id,
                encrypted_user_secret_key_share_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(
                    EncryptedUserShareOutput {
                        dwallet_id: dwallet_id.to_vec(),
                        encrypted_user_secret_key_share_id: encrypted_user_secret_key_share_id
                            .to_vec(),
                        rejected,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    },
                );
                vec![tx]
            }
            ProtocolData::PartialSignatureVerification {
                dwallet_id,
                partial_centralized_signed_message_id,
                ..
            } => {
                let tx =
                    DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(
                        PartialSignatureVerificationOutput {
                            dwallet_id: dwallet_id.to_vec(),
                            partial_centralized_signed_message_id:
                                partial_centralized_signed_message_id.to_vec(),
                            rejected,
                            session_sequence_number: session_request
                                .session_sequence_number
                                .unwrap_or(0),
                        },
                    );
                vec![tx]
            }
            ProtocolData::NetworkEncryptionKeyDkg {
                dwallet_network_encryption_key_id,
                ..
            } => {
                let supported_curves = if output.is_empty() {
                    vec![DWalletCurve::Secp256k1 as u32]
                } else {
                    match bcs::from_bytes::<dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput>(
                        &output,
                    ) {
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput::V1(_)) => {
                            unreachable!("V1 network DKG outputs are no longer produced")
                        }
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput::V2(_))
                        | Ok(dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput::V3(_))
                        | Ok(dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput::V4(_)) => {
                            // V2 (bwd-compat), V3 (pre-aggregation) and V4 (aggregated)
                            // all support all curves.
                            vec![
                                DWalletCurve::Secp256k1 as u32,
                                DWalletCurve::Secp256r1 as u32,
                                DWalletCurve::Ristretto as u32,
                                DWalletCurve::Curve25519 as u32,
                            ]
                        }
                        Err(e) => {
                            error!(
                                error=?e,
                                session_identifier=?session_identifier,
                                "failed to deserialize network DKG output to determine version, defaulting to V1 curves"
                            );
                            // Default to V1 curves for safety
                            vec![DWalletCurve::Secp256k1 as u32]
                        }
                    }
                };

                let slices = if rejected {
                    vec![MPCNetworkDKGOutput {
                        dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                            .to_vec(),
                        public_output: vec![],
                        supported_curves: supported_curves.clone(),
                        is_last: true,
                        rejected: true,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    }]
                } else {
                    Self::slice_public_output_into_messages(
                        output,
                        |public_output_chunk, is_last| MPCNetworkDKGOutput {
                            dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                                .to_vec(),
                            public_output: public_output_chunk,
                            supported_curves: supported_curves.clone(),
                            is_last,
                            rejected: false,
                            session_sequence_number: session_request
                                .session_sequence_number
                                .unwrap_or(0),
                        },
                    )
                };

                let messages: Vec<_> = slices
                    .into_iter()
                    .map(DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput)
                    .collect();
                messages
            }
            ProtocolData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
                ..
            } => {
                let supported_curves = if output.is_empty() {
                    vec![DWalletCurve::Secp256k1 as u32]
                } else {
                    match bcs::from_bytes::<dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput>(&output) {
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput::V1(_)) => {
                            unreachable!("V1 reconfiguration outputs are no longer produced")
                        }
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput::V2(_))
                        | Ok(dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput::V3(_))
                        | Ok(dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput::V4(_)) => {
                            // V2 (bwd-compat), V3 (pre-aggregation) and V4 (aggregated)
                            // all support all curves.
                            vec![
                                DWalletCurve::Secp256k1 as u32,
                                DWalletCurve::Secp256r1 as u32,
                                DWalletCurve::Ristretto as u32,
                                DWalletCurve::Curve25519 as u32,
                            ]
                        }
                        Err(e) => {
                            error!(
                                error=?e,
                                session_identifier=?session_identifier,
                                "failed to deserialize network reconfiguration output to determine version, defaulting to V1 curves"
                            );
                            // Default to V1 curves for safety
                            vec![DWalletCurve::Secp256k1 as u32]
                        }
                    }
                };

                let slices = if rejected {
                    vec![MPCNetworkReconfigurationOutput {
                        dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                            .to_vec(),
                        public_output: vec![],
                        supported_curves: supported_curves.clone(),
                        is_last: true,
                        rejected: true,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    }]
                } else {
                    Self::slice_public_output_into_messages(
                        output,
                        |public_output_chunk, is_last| MPCNetworkReconfigurationOutput {
                            dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                                .clone()
                                .to_vec(),
                            public_output: public_output_chunk,
                            supported_curves: supported_curves.clone(),
                            is_last,
                            rejected: false,
                            session_sequence_number: session_request
                                .session_sequence_number
                                .unwrap_or(0),
                        },
                    )
                };

                let messages: Vec<_> = slices
                    .into_iter()
                    .map(
                        DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput,
                    )
                    .collect();
                messages
            }
            ProtocolData::MakeDWalletUserSecretKeySharesPublic {
                data, dwallet_id, ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(
                    MakeDWalletUserSecretKeySharesPublicOutput {
                        dwallet_id: dwallet_id.to_vec(),
                        public_user_secret_key_shares: data.public_user_secret_key_shares.clone(),
                        rejected,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    },
                );
                vec![tx]
            }
            ProtocolData::ImportedKeyVerification {
                dwallet_id,
                encrypted_user_secret_key_share_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(
                    DWalletImportedKeyVerificationOutput {
                        dwallet_id: dwallet_id.to_vec(),
                        public_output: output,
                        encrypted_user_secret_key_share_id: encrypted_user_secret_key_share_id
                            .to_vec(),
                        rejected,
                        session_sequence_number: session_request
                            .session_sequence_number
                            .unwrap_or(0),
                    },
                );
                vec![tx]
            }
        }
    }

    /// Break down the key to slices because of chain transaction size limits.
    /// Limit 16 KB per Tx `pure` argument.
    /// `pub(crate)` so compatibility tests build their fabricated output
    /// envelopes through the real chunker instead of a copy that could drift.
    pub(crate) fn slice_public_output_into_messages<T>(
        public_output: Vec<u8>,
        func: impl Fn(Vec<u8>, bool) -> T,
    ) -> Vec<T> {
        let mut slices = Vec::new();
        // We set a total of 5 KB since we need 6 KB buffer for other params.

        let public_chunks = public_output.chunks(FIVE_KILO_BYTES).collect_vec();
        let empty: &[u8] = &[];
        // Take the max of the two lengths to ensure we have enough slices.
        for i in 0..public_chunks.len() {
            // If the chunk is missing, use an empty slice, as the size of the slices can be different.
            let public_chunk = public_chunks.get(i).unwrap_or(&empty);
            slices.push(func(public_chunk.to_vec(), i == public_chunks.len() - 1));
        }
        slices
    }

    pub fn verify_validator_keys(
        epoch_start_system: &EpochStartSystem,
        config: &NodeConfig,
    ) -> DwalletMPCResult<()> {
        // Self-lookup in the raw validator records, whose
        // `EpochStartValidatorInfoTrait::authority_name` is the BLS protocol
        // key — a different name space from the committee identity, which is
        // the consensus key.
        let authority_name = config.protocol_public_key();
        let Some(onchain_validator) = epoch_start_system
            .get_ika_validators()
            .into_iter()
            .find(|v| v.protocol_pubkey_bytes() == authority_name)
        else {
            return Err(DwalletMPCError::MPCManagerError(format!(
                "Validator {authority_name} not found in the epoch start system state"
            )));
        };

        if *config.network_key_pair().public() != onchain_validator.get_network_pubkey() {
            return Err(DwalletMPCError::MPCManagerError(
                "Network key pair does not match on-chain validator".to_string(),
            ));
        }
        if *config.consensus_key_pair().public() != onchain_validator.get_consensus_pubkey() {
            return Err(DwalletMPCError::MPCManagerError(
                "Consensus key pair does not match on-chain validator".to_string(),
            ));
        }

        let root_seed = config
            .root_seed_key_pair
            .clone()
            .ok_or(DwalletMPCError::MissingRootSeed)?
            .root_seed()
            .clone();

        let (_validator_mpc_secrets, validator_encryption_keys_and_proofs) =
            ValidatorMPCSecrets::from_seed(&root_seed);

        // Verify that the validator's local class-groups key is the same as stored
        // in the system state object on-chain. This makes sure the seed we are using
        // is the same seed we used at setup to create the encryption key, and thus it
        // assures we will generate the same decryption key too.
        //
        // The on-chain `mpc_data_bytes` is always the bare
        // `ClassGroupsEncryptionKeyAndProof`; the full
        // `ValidatorEncryptionKeysAndProofs` bundle (class groups + per-curve
        // PVSS + the Fast Schnorr VSS HPKE key) travels off-chain via validator
        // P2P. Decode the bare shape and compare the class-groups component —
        // the part that identifies the seed. (PVSS / VSS keys are verified
        // off-chain on the assembly path in `assemble_committee_mpc_data_off_chain`.)
        let onchain_bytes = onchain_validator.get_mpc_data().unwrap().mpc_data_bytes();
        let Ok(onchain_class_groups) =
            bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(&onchain_bytes)
        else {
            return Err(DwalletMPCError::MPCManagerError(
                "could not decode the validator's class-groups key stored in the system state object".to_string(),
            ));
        };
        if onchain_class_groups != validator_encryption_keys_and_proofs.class_groups {
            return Err(DwalletMPCError::MPCManagerError(
                "validator's class-groups key does not match the one stored in the system state object".to_string(),
            ));
        }

        Ok(())
    }
}
