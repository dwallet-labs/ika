// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::SuiDataReceivers;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::authority::{AuthorityState, AuthorityStateTrait};
use crate::consensus_manager::ReplayWaiter;
use crate::dwallet_checkpoints::{
    DWalletCheckpointServiceNotify, PendingDWalletCheckpoint, PendingDWalletCheckpointInfo,
    PendingDWalletCheckpointV1,
};
use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::{
    ComputationResultData, SessionComputationType, SessionStatus,
};
use crate::dwallet_mpc::party_ids_to_authority_names;
use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use crate::noa_checkpoints::NOACheckpointHandler;
use crate::request_protocol_data::ProtocolData;
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use dwallet_mpc_types::dwallet_mpc::VersionedPresignOutput;
use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, MPCMessage};
#[cfg(any(test, feature = "test-utils"))]
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use fastcrypto::traits::KeyPair;
use ika_config::NodeConfig;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::message::{
    DWalletCheckpointMessageKind, DWalletDKGOutput, DWalletImportedKeyVerificationOutput,
    EncryptedUserShareOutput, MPCNetworkDKGOutput, MPCNetworkReconfigurationOutput,
    MakeDWalletUserSecretKeySharesPublicOutput, PartialSignatureVerificationOutput, PresignOutput,
    SignOutput,
};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::{
    DWalletInternalMPCOutputKind, DWalletMPCOutputKind, DWalletMPCOutputReport,
    DWalletNetworkEncryptionKeyState, GlobalPresignRequest, IdleStatusUpdate, SessionIdentifier,
    SessionType, SuiChainObservationUpdate, UserSecretKeyShareEventType,
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
use std::time::Duration;
use sui_types::base_types::ObjectID;
use sui_types::messages_consensus::Round;
#[cfg(any(test, feature = "test-utils"))]
use tokio::sync::watch;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

const DELAY_NO_ROUNDS_SEC: u64 = 2;
const READ_INTERVAL_MS: u64 = 20;
const FIVE_KILO_BYTES: usize = 5 * 1024;

pub const NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY: usize = 1024;

pub struct DWalletMPCService {
    last_read_consensus_round: Option<Round>,
    pub(crate) epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
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
    /// Is the network considered in an idle state?
    /// If so, we can process more internal presign sessions to make use of resources.
    network_is_idle: bool,
    agreed_global_presign_requests_queue: Vec<GlobalPresignRequest>,
    processed_global_presign_sequence_numbers: HashSet<u64>,
    /// Tracks which network key IDs have already been sent through consensus.
    sent_network_key_ids: HashSet<ObjectID>,
    /// Receiver for network-owned-address sign requests.
    network_owned_address_sign_requests_receiver:
        tokio::sync::mpsc::Receiver<NetworkOwnedAddressSignRequest>,
    /// Buffer for network-owned-address sign requests that couldn't be processed yet
    /// (e.g., key not yet agreed). Retried each service loop iteration.
    pending_network_owned_address_sign_requests: Vec<NetworkOwnedAddressSignRequest>,
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
    ) -> Self {
        let network_dkg_third_round_delay = protocol_config.network_dkg_third_round_delay();

        let decryption_key_reconfiguration_third_round_delay =
            protocol_config.decryption_key_reconfiguration_third_round_delay();

        let schnorr_presign_second_round_delay =
            protocol_config.schnorr_presign_second_round_delay();

        let root_seed = match node_config.root_seed_key_pair {
            None => {
                error!("root_seed is not set in the node config, cannot start DWallet MPC service");
                panic!("root_seed is not set in the node config, cannot start DWallet MPC service");
            }
            Some(root_seed) => root_seed.root_seed().clone(),
        };

        let dwallet_mpc_manager = DWalletMPCManager::new(
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
        );

        Self {
            last_read_consensus_round: None,
            epoch_store: epoch_store.clone(),
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
            network_is_idle: false,
            agreed_global_presign_requests_queue: Vec::new(),
            processed_global_presign_sequence_numbers: HashSet::new(),
            sent_network_key_ids: HashSet::new(),
            network_owned_address_sign_requests_receiver,
            pending_network_owned_address_sign_requests: Vec::new(),
            submitted_noa_sign_messages: HashSet::new(),
            last_sent_sui_chain_observation: None,
            current_agreed_sui_chain_context: None,
            buffered_noa_dwallet_messages: Vec::new(),
            buffered_noa_system_messages: Vec::new(),
            buffered_noa_observations: Vec::new(),
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
            network_is_idle: false,
            processed_global_presign_sequence_numbers: HashSet::new(),
            agreed_global_presign_requests_queue: Vec::new(),
            sent_network_key_ids: HashSet::new(),
            network_owned_address_sign_requests_receiver:
                network_owned_address_sign_request_receiver,
            pending_network_owned_address_sign_requests: Vec::new(),
            submitted_noa_sign_messages: HashSet::new(),
            last_sent_sui_chain_observation: None,
            current_agreed_sui_chain_context: None,
            buffered_noa_dwallet_messages: Vec::new(),
            buffered_noa_system_messages: Vec::new(),
            buffered_noa_observations: Vec::new(),
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
    /// This service periodically reads DWallet MPC messages from the local database
    /// at intervals defined by [`READ_INTERVAL_SECS`] seconds.
    /// The messages are then forwarded to the
    /// [`DWalletMPCManager`] for processing.
    ///
    /// The service automatically terminates when an epoch switch occurs.
    pub async fn spawn(&mut self, replay_waiter: ReplayWaiter) {
        info!("Waiting for consensus commits to replay ...");
        replay_waiter.wait_for_replay().await;
        info!("Consensus commits finished replaying");

        info!(
            validator=?self.name,
            "Spawning dWallet MPC Service"
        );

        let mut newly_instantiated_network_key_ids = vec![];
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
                error!(
                    authority=?self.name,
                    "the node has identified itself as malicious, breaking from MPC service loop"
                );

                // This signifies a bug, we can't proceed before we fix it.
                break;
            }

            newly_instantiated_network_key_ids = self
                .run_service_loop_iteration(newly_instantiated_network_key_ids)
                .await;

            tokio::time::sleep(Duration::from_millis(READ_INTERVAL_MS)).await;
        }
    }

    pub(crate) async fn run_service_loop_iteration(
        &mut self,
        newly_instantiated_network_key_ids: Vec<ObjectID>,
    ) -> Vec<ObjectID> {
        debug!("Running DWalletMPCService loop");
        self.sync_last_session_to_complete_in_current_epoch().await;

        // Process any pending network-owned-address sign requests.
        self.process_network_owned_address_sign_requests();

        // Receive **new** dWallet MPC events and save them in the local DB.
        let rejected_sessions = self
            .handle_new_requests(newly_instantiated_network_key_ids)
            .await
            .unwrap_or_else(|e| {
                error!(error=?e, "failed to handle new events from DWallet MPC service");
                vec![]
            });

        let newly_instantiated_network_key_ids = self.process_consensus_rounds_from_storage().await;

        self.process_cryptographic_computations().await;
        self.handle_noa_sign_outputs().await;
        self.poll_noa_chain_status().await;
        self.handle_failed_requests_and_submit_reject_to_consensus(rejected_sessions)
            .await;

        newly_instantiated_network_key_ids
    }

    /// Process network-owned-address sign requests received via the channel.
    /// Drains the channel into a pending buffer, then instantiates sessions
    /// for requests whose network key is already available.
    fn process_network_owned_address_sign_requests(&mut self) {
        // Drain the receiver into the shared pending buffer, deduplicating by message.
        while let Ok(request) = self.network_owned_address_sign_requests_receiver.try_recv() {
            let message_hash: [u8; 32] = DefaultHash::digest(&request.message).into();
            if self.submitted_noa_sign_messages.contains(&message_hash) {
                error!(
                    should_never_happen = true,
                    message_len = request.message.len(),
                    curve = ?request.curve,
                    algorithm = ?request.signature_algorithm,
                    "Skipping duplicate network-owned-address sign request"
                );
                continue;
            }
            info!(
                message_len = request.message.len(),
                curve = ?request.curve,
                algorithm = ?request.signature_algorithm,
                "Received network-owned-address sign request"
            );
            self.pending_network_owned_address_sign_requests
                .push(request);
        }

        if self.pending_network_owned_address_sign_requests.is_empty() {
            return;
        }

        let mut newly_submitted: Vec<[u8; 32]> = Vec::new();
        self.pending_network_owned_address_sign_requests
            .retain(|request| {
                if !self
                    .dwallet_mpc_manager
                    .has_network_owned_address_signing_network_key()
                {
                    return true; // key not yet available, keep in buffer
                }
                if !self
                    .dwallet_mpc_manager
                    .has_network_owned_address_signing_presign_available(
                        request.signature_algorithm,
                    )
                {
                    return true; // no presign yet for this algorithm, keep in buffer
                }

                let instantiated = self
                    .dwallet_mpc_manager
                    .instantiate_network_owned_address_sign_session(
                        request.message.clone(),
                        request.curve,
                        request.signature_algorithm,
                        request.hash_scheme,
                    );
                if instantiated {
                    newly_submitted.push(DefaultHash::digest(&request.message).into());
                }
                !instantiated // keep in buffer if instantiation failed
            });
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

        // Read raw key data from the Sui watch channel and filter to keys not yet sent
        // and only in completed states (with actual usable data).
        // Scoped to ensure the RwLockReadGuard is dropped before any `.await`.
        let new_key_data: Vec<_> = {
            let all_key_data = self.sui_data_requests.network_keys_receiver.borrow();
            all_key_data
                .values()
                .filter(|data| !self.sent_network_key_ids.contains(&data.id))
                .filter(|data| {
                    !matches!(
                        &data.state,
                        DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                    )
                })
                .cloned()
                .collect()
        };

        // FIXME(noa-checkpoints): Without a real SuiChainObservation, the entire NOA
        // checkpoint flow is non-functional — messages buffer indefinitely because
        // `current_agreed_sui_chain_context` never becomes Some. Wire up SuiSyncer.
        let sui_chain_observation: Option<SuiChainObservation> = None;

        // Check if there's anything new to send.
        let has_unsent_requests = !unsent_presign_requests.is_empty();
        let idle_status_changed = self.last_sent_idle_status != Some(is_idle);
        let has_new_key_data = !new_key_data.is_empty();
        let observation_changed = sui_chain_observation != self.last_sent_sui_chain_observation;
        let has_noa_observations = !self.buffered_noa_observations.is_empty();

        if !has_unsent_requests
            && !idle_status_changed
            && !has_new_key_data
            && !observation_changed
            && !has_noa_observations
        {
            return;
        }

        // Build a batch of consensus transactions.
        let mut transactions = Vec::new();

        // Idle status update when idle status changed.
        if idle_status_changed {
            transactions.push(ConsensusTransaction::new_idle_status_update(
                IdleStatusUpdate::new(self.name, is_idle),
            ));
        }

        // Sui chain observation update when the observation changed and is present.
        if observation_changed && let Some(ref observation) = sui_chain_observation {
            transactions.push(ConsensusTransaction::new_sui_chain_observation_update(
                SuiChainObservationUpdate::new(self.name, observation.clone()),
            ));
        }

        // One message per unsent presign request.
        for request in &unsent_presign_requests {
            transactions.push(ConsensusTransaction::new_global_presign_request(
                self.name, *request,
            ));
        }

        // One message per new network key.
        for key_data in &new_key_data {
            transactions.push(ConsensusTransaction::new_network_key_data(
                self.name,
                key_data.clone(),
            ));
        }

        // One message per buffered NOA observation.
        for obs in &self.buffered_noa_observations {
            transactions.push(ConsensusTransaction::new_noa_observation(
                self.name,
                obs.clone(),
            ));
        }

        if let Err(e) = self
            .dwallet_submit_to_consensus
            .submit_to_consensus(&transactions)
            .await
        {
            error!(
                error = ?e,
                consensus_round,
                "Failed to submit status update to consensus"
            );
        } else {
            // Update last sent values.
            self.last_sent_idle_status = Some(is_idle);
            for key_data in &new_key_data {
                self.sent_network_key_ids.insert(key_data.id);
            }
            self.last_sent_sui_chain_observation = sui_chain_observation;
            self.buffered_noa_observations.clear();
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

    async fn handle_new_requests(
        &mut self,
        newly_instantiated_network_key_ids: Vec<ObjectID>,
    ) -> DwalletMPCResult<Vec<DWalletSessionRequest>> {
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
                            );

                        info!(
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
            .handle_mpc_request_batch(requests, newly_instantiated_network_key_ids)
            .await;

        Ok(rejected_sessions)
    }

    async fn process_consensus_rounds_from_storage(&mut self) -> Vec<ObjectID> {
        // The last consensus round for MPC messages is also the last one for MPC outputs and verified dWallet checkpoint messages,
        // as they are all written in an atomic batch manner as part of committing the consensus commit outputs.
        let last_consensus_round = if let Ok(last_consensus_round) =
            self.epoch_store.last_dwallet_mpc_message_round()
        {
            if let Some(last_consensus_round) = last_consensus_round {
                last_consensus_round
            } else {
                info!("No consensus round from DB yet, retrying in {DELAY_NO_ROUNDS_SEC} seconds.");
                tokio::time::sleep(Duration::from_secs(DELAY_NO_ROUNDS_SEC)).await;
                return Vec::new();
            }
        } else {
            error!("failed to get last consensus round from DB");
            panic!("failed to get last consensus round from DB");
        };

        let mut accumulated_new_key_ids = Vec::new();

        while Some(last_consensus_round) > self.last_read_consensus_round {
            self.number_of_consensus_rounds += 1;

            let mpc_messages = self
                .epoch_store
                .next_dwallet_mpc_message(self.last_read_consensus_round);
            let (mpc_messages_consensus_round, mpc_messages) = match mpc_messages {
                Ok(mpc_messages) => {
                    if let Some(mpc_messages) = mpc_messages {
                        mpc_messages
                    } else {
                        error!("failed to get mpc messages, None value");
                        panic!("failed to get mpc messages, None value");
                    }
                }
                Err(e) => {
                    error!(
                        error=?e,
                        last_read_consensus_round=self.last_read_consensus_round,
                        "failed to load DWallet MPC messages from the local DB"
                    );

                    panic!("failed to load DWallet MPC messages from the local DB");
                }
            };

            let mpc_outputs = self
                .epoch_store
                .next_dwallet_mpc_output(self.last_read_consensus_round);

            let (external_mpc_outputs_consensus_round, external_mpc_outputs) = match mpc_outputs {
                Ok(mpc_outputs) => {
                    if let Some(mpc_outputs) = mpc_outputs {
                        mpc_outputs
                    } else {
                        error!("failed to get mpc outputs, None value");
                        panic!("failed to get mpc outputs, None value");
                    }
                }
                Err(e) => {
                    error!(
                        error=?e,
                        last_read_consensus_round=self.last_read_consensus_round,
                        "failed to load DWallet MPC outputs from the local DB"
                    );
                    panic!("failed to load DWallet MPC outputs from the local DB");
                }
            };

            let mpc_outputs = self
                .epoch_store
                .next_dwallet_internal_mpc_output(self.last_read_consensus_round);

            let internal_mpc_outputs = match mpc_outputs {
                Ok(Some((round, outputs))) => {
                    // Validate round matches
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?mpc_messages_consensus_round,
                            ?round,
                            "consensus round mismatch for internal MPC outputs"
                        );
                        panic!("consensus round mismatch for internal MPC outputs");
                    }
                    outputs
                }
                Ok(None) => {
                    // No internal MPC outputs for this round - use empty list.
                    // This can happen during initialization or when no internal outputs are generated.
                    Vec::new()
                }
                Err(e) => {
                    error!(
                        error=?e,
                        last_read_consensus_round=self.last_read_consensus_round,
                        "failed to load internal DWallet MPC outputs from the local DB"
                    );
                    panic!("failed to load DWallet MPC outputs from the local DB");
                }
            };

            let verified_dwallet_checkpoint_messages = self
                .epoch_store
                .next_verified_dwallet_checkpoint_message(self.last_read_consensus_round);
            let verified_dwallet_checkpoint_messages = match verified_dwallet_checkpoint_messages {
                Ok(Some((round, messages))) => {
                    // Validate round matches
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?mpc_messages_consensus_round,
                            ?round,
                            "consensus round mismatch for verified checkpoint messages"
                        );
                        panic!("consensus round mismatch for verified checkpoint messages");
                    }
                    messages
                }
                Ok(None) => {
                    // No verified checkpoint messages for this round - use empty list.
                    // This is expected during initialization or internal-only rounds, where no
                    // checkpoint messages need to be produced. The old code would panic in this case.
                    Vec::new()
                }
                Err(e) => {
                    error!(
                        error=?e,
                        last_read_consensus_round=self.last_read_consensus_round,
                        "failed to load verified dwallet checkpoint messages from the local DB"
                    );
                    panic!("failed to load verified dwallet checkpoint messages from the local DB");
                }
            };

            let verified_system_checkpoint_messages = self
                .epoch_store
                .next_verified_system_checkpoint_message(self.last_read_consensus_round);
            let verified_system_checkpoint_messages = match verified_system_checkpoint_messages {
                Ok(Some((round, messages))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?mpc_messages_consensus_round,
                            ?round,
                            "consensus round mismatch for verified system checkpoint messages"
                        );
                        panic!("consensus round mismatch for verified system checkpoint messages");
                    }
                    messages
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(
                        error=?e,
                        last_read_consensus_round=self.last_read_consensus_round,
                        "failed to load verified system checkpoint messages from the local DB"
                    );
                    panic!("failed to load verified system checkpoint messages from the local DB");
                }
            };

            let idle_status_updates = match self
                .epoch_store
                .next_idle_status_update(self.last_read_consensus_round)
            {
                Ok(Some((round, updates))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?round,
                            ?mpc_messages_consensus_round,
                            "idle status updates consensus round does not match MPC messages consensus round"
                        );
                        panic!(
                            "idle status updates consensus round does not match MPC messages consensus round"
                        );
                    }
                    updates
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(error=?e, "failed to load idle status updates from the local DB");
                    panic!("failed to load idle status updates from the local DB");
                }
            };

            let sui_chain_observation_updates = match self
                .epoch_store
                .next_sui_chain_observation_update(self.last_read_consensus_round)
            {
                Ok(Some((round, updates))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?round,
                            ?mpc_messages_consensus_round,
                            "sui chain observation updates consensus round does not match MPC messages consensus round"
                        );
                        panic!(
                            "sui chain observation updates consensus round does not match MPC messages consensus round"
                        );
                    }
                    updates
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(error=?e, "failed to load sui chain observation updates from the local DB");
                    panic!("failed to load sui chain observation updates from the local DB");
                }
            };

            let presign_request_messages = match self
                .epoch_store
                .next_global_presign_request(self.last_read_consensus_round)
            {
                Ok(Some((round, msgs))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?round,
                            ?mpc_messages_consensus_round,
                            "presign requests consensus round mismatch"
                        );
                        panic!("presign requests consensus round mismatch");
                    }
                    msgs
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(error=?e, "failed to load global presign requests from the local DB");
                    panic!("failed to load global presign requests from the local DB");
                }
            };

            let network_key_data_messages = match self
                .epoch_store
                .next_network_key_data(self.last_read_consensus_round)
            {
                Ok(Some((round, msgs))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?round,
                            ?mpc_messages_consensus_round,
                            "network key data consensus round mismatch"
                        );
                        panic!("network key data consensus round mismatch");
                    }
                    msgs
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(error=?e, "failed to load network key data from the local DB");
                    panic!("failed to load network key data from the local DB");
                }
            };

            let noa_observation_messages = match self
                .epoch_store
                .next_noa_observation(self.last_read_consensus_round)
            {
                Ok(Some((round, msgs))) => {
                    if round != mpc_messages_consensus_round {
                        error!(
                            ?round,
                            ?mpc_messages_consensus_round,
                            "NOA observations consensus round mismatch"
                        );
                        panic!("NOA observations consensus round mismatch");
                    }
                    msgs
                }
                Ok(None) => Vec::new(),
                Err(e) => {
                    error!(error=?e, "failed to load NOA observations from the local DB");
                    panic!("failed to load NOA observations from the local DB");
                }
            };

            if mpc_messages_consensus_round != external_mpc_outputs_consensus_round {
                error!(
                    ?mpc_messages_consensus_round,
                    ?external_mpc_outputs_consensus_round,
                    "the consensus rounds of MPC messages and external MPC outputs do not match"
                );

                panic!(
                    "the consensus rounds of MPC messages and external MPC outputs do not match"
                );
            }

            let consensus_round = mpc_messages_consensus_round;

            if self.last_read_consensus_round >= Some(consensus_round) {
                error!(
                    should_never_happen = true,
                    consensus_round,
                    last_read_consensus_round=?self.last_read_consensus_round,
                    "consensus round must be in a ascending order"
                );

                panic!("consensus round must be in a ascending order");
            }

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

            // 1c. Handle network key data messages.
            self.dwallet_mpc_manager
                .handle_network_key_data_messages(consensus_round, network_key_data_messages);

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
                    info!(
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

            // 2. Instantiate any agreed keys we don't have yet, from consensus-voted data.
            let new_key_ids = self
                .dwallet_mpc_manager
                .instantiate_agreed_keys_from_voted_data()
                .await;
            accumulated_new_key_ids.extend(new_key_ids);

            // 3. Instantiate internal presign sessions (now uses agreed values).
            if self.protocol_config.internal_presign_sessions_enabled() {
                self.dwallet_mpc_manager
                    .instantiate_internal_presign_sessions(
                        consensus_round,
                        self.number_of_consensus_rounds,
                        self.network_is_idle,
                    );
            }

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

                    match self.epoch_store.pop_presign(
                        request.signature_algorithm,
                        request.dwallet_network_encryption_key_id,
                    ) {
                        Ok(Some((_presign_session_id, presign))) => {
                            match bcs::to_bytes(&VersionedPresignOutput::V2(presign)) {
                                Ok(presign) => {
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
                                    error!(
                                        error=?e,
                                        should_never_happen = true,
                                        "failed to serialize presign output — data corruption"
                                    );
                                    panic!("failed to serialize presign output: {e:?}");
                                }
                            }
                        }
                        Ok(None) => {
                            // No presign available in internal pool - keep in queue (return true)
                            true
                        }
                        Err(e) => {
                            error!(
                                error=?e,
                                should_never_happen = true,
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
            tokio::task::yield_now().await;
        }

        accumulated_new_key_ids
    }

    async fn handle_computation_results_and_submit_to_consensus(
        &mut self,
        completed_computation_results: HashMap<
            ComputationId,
            DwalletMPCResult<GuaranteedOutputDeliveryRoundResult>,
        >,
    ) {
        let committee = self.committee.clone();
        let validator_name = &self.name;
        let party_id = self.dwallet_mpc_manager.party_id;

        for (computation_id, computation_result) in completed_computation_results {
            let session_identifier = computation_id.session_identifier;
            let mpc_round = computation_id.mpc_round;
            let consensus_adapter = self.dwallet_submit_to_consensus.clone();

            let computation_result_data = if let Some(mpc_round) = mpc_round {
                ComputationResultData::MPC { mpc_round }
            } else {
                ComputationResultData::Native
            };

            let Some(session) = self.dwallet_mpc_manager.sessions.get(&session_identifier) else {
                error!(
                    should_never_happen = true,
                    ?session_identifier,
                    validator=?validator_name,
                    ?computation_result_data,
                    "failed to retrieve session for which a computation update was received"
                );
                return;
            };

            let SessionStatus::Active { request, .. } = session.status.clone() else {
                warn!(
                    ?session_identifier,
                    validator=?validator_name,
                    ?computation_result_data,
                    "received a computation update for a non-active session"
                );
                return;
            };

            match computation_result {
                Ok(GuaranteedOutputDeliveryRoundResult::Advance { message }) => {
                    info!(
                        ?session_identifier,
                        validator=?validator_name,
                        ?computation_result_data,
                        "Advanced session"
                    );

                    let message = self.new_dwallet_mpc_message(session_identifier, message);

                    if let Err(err) = consensus_adapter.submit_to_consensus(&[message]).await {
                        error!(
                            ?session_identifier,
                            validator=?validator_name,
                            ?computation_result_data,
                            error=?err,
                            "failed to submit a message to consensus"
                        );
                    }
                }
                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    malicious_parties,
                    private_output: _,
                    public_output_value,
                }) => {
                    info!(
                        ?session_identifier,
                        validator=?validator_name,
                        "Reached output for session"
                    );
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
                    ) && let Err(err) = consensus_adapter
                        .submit_to_consensus(&[consensus_message])
                        .await
                    {
                        error!(
                            ?session_identifier,
                            validator=?validator_name,
                            error=?err,
                            "failed to submit an MPC output message to consensus",
                        );
                    }
                }
                Err(err) => match request.session_type {
                    SessionType::InternalPresign | SessionType::NetworkOwnedAddressSign => {
                        error!(
                            should_never_happen = true,
                            session_identifier=?session.session_identifier,
                            session_type=?request.session_type,
                            error=?err,
                            "internal session failed",
                        );
                    }
                    _ => {
                        self.submit_failed_session(
                            session_identifier,
                            &request,
                            &validator_name.to_string(),
                            party_id,
                            err,
                        )
                        .await;
                    }
                },
            }
        }
    }

    async fn handle_failed_requests_and_submit_reject_to_consensus(
        &mut self,
        rejected_sessions: Vec<DWalletSessionRequest>,
    ) {
        let validator_name = &self.name;
        let party_id = self.dwallet_mpc_manager.party_id;

        for request in rejected_sessions {
            let session_identifier = request.session_identifier;
            self.submit_failed_session(
                session_identifier,
                &request,
                &validator_name.to_string(),
                party_id,
                DwalletMPCError::MPCSessionError {
                    session_identifier,
                    error: "failed to create session".to_string(),
                },
            )
            .await;
        }
    }

    async fn submit_failed_session(
        &self,
        session_identifier: SessionIdentifier,
        request: &DWalletSessionRequest,
        validator_name: &str,
        party_id: u16,
        error: DwalletMPCError,
    ) {
        error!(
            ?session_identifier,
            validator=?validator_name,
            party_id,
            session_type=?request.session_type,
            protocol_data=?DWalletSessionRequestMetricData::from(&request.protocol_data).to_string(),
            error=?error,
            "rejecting session."
        );

        let consensus_adapter = self.dwallet_submit_to_consensus.clone();
        let rejected = true;

        if let Some(consensus_message) =
            self.new_dwallet_mpc_output(session_identifier, request, vec![], vec![], rejected)
            && let Err(err) = consensus_adapter
                .submit_to_consensus(&[consensus_message])
                .await
        {
            error!(
                ?session_identifier,
                validator=?validator_name,
                error=?err,
                "failed to submit an MPC SessionFailed message to consensus"
            );
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
                        error!(
                            should_never_happen = true,
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
                    error!(
                        should_never_happen = true,
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
                    error!(
                        should_never_happen = true,
                        session_identifier=?session_identifier,
                        "mismatch between session type and protocol data during MPC output creation",
                    );

                    None
                }
            },
            SessionType::User | SessionType::System => {
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
        info!(
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
                                error!(
                                    error = ?e,
                                    should_never_happen = true,
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
                error!(
                    should_never_happen = true,
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
                error!(
                    should_never_happen = true,
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
                            // V1 only supports Secp256k1
                            vec![DWalletCurve::Secp256k1 as u32]
                        }
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedNetworkDkgOutput::V2(_)) => {
                            // V2 supports all curves
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
                            // V1 only supports Secp256k1
                            vec![DWalletCurve::Secp256k1 as u32]
                        }
                        Ok(dwallet_mpc_types::dwallet_mpc::VersionedDecryptionKeyReconfigurationOutput::V2(_)) => {
                            // V2 supports all curves
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
    fn slice_public_output_into_messages<T>(
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
        let authority_name = config.protocol_public_key();
        let Some(onchain_validator) = epoch_start_system
            .get_ika_validators()
            .into_iter()
            .find(|v| v.authority_name() == authority_name)
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

        let class_groups_key_pair = ClassGroupsKeyPairAndProof::from_seed(&root_seed);

        // Verify that the validators local class-groups key is the
        // same as stored in the system state object onchain.
        // This makes sure the seed we are using is the same seed we used at setup
        // to create the encryption key, and thus it assures we will generate the same decryption key too.
        if onchain_validator
            .get_mpc_data()
            .unwrap()
            .class_groups_public_key_and_proof()
            != bcs::to_bytes(&class_groups_key_pair.encryption_key_and_proof())?
        {
            return Err(DwalletMPCError::MPCManagerError(
                "validator's class-groups key does not match the one stored in the system state object".to_string(),
            ));
        }

        Ok(())
    }
}
