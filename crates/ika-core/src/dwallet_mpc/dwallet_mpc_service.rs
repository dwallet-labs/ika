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
use crate::dwallet_mpc::mpc_session::MPCSessionStatus;
use crate::dwallet_mpc::party_ids_to_authority_names;
use crate::dwallet_mpc::session_request::{
    DWalletSessionRequest, ProtocolData, ProtocolSpecificData,
};
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use dwallet_mpc_types::dwallet_mpc::{DWalletMPCNetworkKeyScheme, MPCMessage};
use fastcrypto::traits::KeyPair;
use ika_config::NodeConfig;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::message::{
    DKGFirstRoundOutput, DKGSecondRoundOutput, DWalletCheckpointMessageKind,
    DWalletImportedKeyVerificationOutput, EncryptedUserShareOutput, MPCNetworkDKGOutput,
    MPCNetworkReconfigurationOutput, MakeDWalletUserSecretKeySharesPublicOutput,
    PartialSignatureVerificationOutput, PresignOutput, SignOutput,
};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use ika_types::sui::EpochStartSystem;
use ika_types::sui::{EpochStartSystemTrait, EpochStartValidatorInfoTrait};
use itertools::Itertools;
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sui_types::messages_consensus::Round;
use tokio::sync::watch::Receiver;
use tracing::{debug, error, info, warn};

const DELAY_NO_ROUNDS_SEC: u64 = 2;
const READ_INTERVAL_MS: u64 = 20;
const FIVE_KILO_BYTES: usize = 5 * 1024;

pub struct DWalletMPCService {
    last_read_consensus_round: Option<Round>,
    pub(crate) epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
    dwallet_submit_to_consensus: Arc<dyn DWalletMPCSubmitToConsensus>,
    state: Arc<dyn AuthorityStateTrait>,
    dwallet_checkpoint_service: Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>,
    dwallet_mpc_manager: DWalletMPCManager,
    exit: Receiver<()>,
    end_of_publish: bool,
    dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
    pub sui_data_requests: SuiDataReceivers,
    pub name: AuthorityName,
    pub epoch: EpochId,
    pub protocol_config: ProtocolConfig,
    pub committee: Arc<Committee>,
}

impl DWalletMPCService {
    pub fn new(
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
        exit: Receiver<()>,
        consensus_adapter: Arc<dyn DWalletMPCSubmitToConsensus>,
        node_config: NodeConfig,
        dwallet_checkpoint_service: Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        state: Arc<AuthorityState>,
        sui_data_receivers: SuiDataReceivers,
        validator_name: AuthorityName,
        epoch_id: sui_types::base_types::EpochId,
        committee: Arc<Committee>,
        protocol_config: ProtocolConfig,
    ) -> Self {
        let network_dkg_third_round_delay = protocol_config.network_dkg_third_round_delay();

        let decryption_key_reconfiguration_third_round_delay =
            protocol_config.decryption_key_reconfiguration_third_round_delay();

        let root_seed = match node_config.root_seed_key_pair {
            None => {
                error!(
                    "root_seed_key_pair is not set in the node config, cannot start DWallet MPC service"
                );
                panic!(
                    "root_seed_key_pair is not set in the node config, cannot start DWallet MPC service"
                );
            }
            Some(root_seed_keypair) => root_seed_keypair.root_seed().clone(),
        };

        let dwallet_mpc_manager = DWalletMPCManager::new(
            validator_name,
            committee.clone(),
            epoch_id,
            root_seed,
            network_dkg_third_round_delay,
            decryption_key_reconfiguration_third_round_delay,
            dwallet_mpc_metrics.clone(),
            sui_data_receivers.clone(),
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
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_testing(
        epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,
        seed: RootSeed,
        dwallet_submit_to_consensus: Arc<dyn DWalletMPCSubmitToConsensus>,
        authority_state: Arc<dyn AuthorityStateTrait>,
        checkpoint_service: Arc<dyn DWalletCheckpointServiceNotify + Send + Sync>,
        authority_name: AuthorityName,
        committee: Committee,
        sui_data_receivers: SuiDataReceivers,
    ) -> Self {
        DWalletMPCService {
            last_read_consensus_round: Some(0),
            epoch_store,
            dwallet_submit_to_consensus,
            state: authority_state,
            dwallet_checkpoint_service: checkpoint_service,
            dwallet_mpc_manager: DWalletMPCManager::new(
                authority_name.clone(),
                Arc::new(committee.clone()),
                1,
                seed,
                0,
                0,
                DWalletMPCMetrics::new(&Registry::new()),
                sui_data_receivers.clone(),
            ),
            exit: watch::channel(()).1,
            end_of_publish: false,
            dwallet_mpc_metrics: DWalletMPCMetrics::new(&Registry::new()),
            sui_data_requests: sui_data_receivers,
            name: authority_name,
            epoch: 1,
            protocol_config: ProtocolConfig::get_for_min_version(),
            committee: Arc::new(committee),
        }
    }

    #[cfg(test)]
    pub(crate) fn dwallet_mpc_manager(&self) -> &DWalletMPCManager {
        &self.dwallet_mpc_manager
    }

    async fn sync_last_session_to_complete_in_current_epoch(&mut self) {
        let (ika_current_epoch_on_sui, last_session_to_complete_in_current_epoch) = self
            .sui_data_requests
            .last_session_to_complete_in_current_epoch_receiver
            .borrow()
            .clone();
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

            self.run_service_loop_iteration().await;

            tokio::time::sleep(Duration::from_millis(READ_INTERVAL_MS)).await;
        }
    }

    pub(crate) async fn run_service_loop_iteration(&mut self) {
        debug!("Running DWalletMPCService loop");
        self.sync_last_session_to_complete_in_current_epoch().await;

        // Receive **new** dWallet MPC events and save them in the local DB.
        if let Err(err) = self.handle_new_requests().await {
            error!(?err, "failed to handle new events from DWallet MPC service")
        }

        self.process_consensus_rounds_from_storage().await;

        self.process_cryptographic_computations().await;
    }

    async fn process_cryptographic_computations(&mut self) {
        let Some(last_read_consensus_round) = self.last_read_consensus_round else {
            warn!("No last read consensus round, cannot perform cryptographic computation");
            return;
        };
        let completed_computation_results = self
            .dwallet_mpc_manager
            .perform_cryptographic_computation(last_read_consensus_round)
            .await;

        self.handle_computation_results_and_submit_to_consensus(completed_computation_results)
            .await;
    }

    async fn handle_new_requests(&mut self) -> DwalletMPCResult<()> {
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

        let requests_session_identifiers =
            requests.iter().map(|e| e.session_identifier).collect_vec();

        match self
            .state
            .get_dwallet_mpc_sessions_completed_status(requests_session_identifiers.clone())
        {
            Ok(mpc_session_identifier_to_computation_completed) => {
                for (session_identifier, session_completed) in
                    mpc_session_identifier_to_computation_completed
                {
                    if session_completed {
                        self.dwallet_mpc_manager
                            .complete_computation_mpc_session_and_create_if_not_exists(
                                &session_identifier,
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
                    ?requests_session_identifiers,
                    error=?e,
                    "Could not read from the DB completed sessions, got error"
                );
            }
        }

        self.dwallet_mpc_manager
            .handle_mpc_request_batch(requests)
            .await;
        Ok(())
    }

    async fn process_consensus_rounds_from_storage(&mut self) {
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
                return;
            }
        } else {
            error!("failed to get last consensus round from DB");
            panic!("failed to get last consensus round from DB");
        };

        while Some(last_consensus_round) > self.last_read_consensus_round {
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
            let (mpc_outputs_consensus_round, mpc_outputs) = match mpc_outputs {
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

            let verified_dwallet_checkpoint_messages = self
                .epoch_store
                .next_verified_dwallet_checkpoint_message(self.last_read_consensus_round);
            let (
                verified_dwallet_checkpoint_messages_consensus_round,
                verified_dwallet_checkpoint_messages,
            ) = match verified_dwallet_checkpoint_messages {
                Ok(verified_dwallet_checkpoint_messages) => {
                    if let Some(verified_dwallet_checkpoint_messages) =
                        verified_dwallet_checkpoint_messages
                    {
                        verified_dwallet_checkpoint_messages
                    } else {
                        error!("failed to get verified dwallet checkpoint messages, None value");
                        panic!("failed to get verified dwallet checkpoint messages, None value");
                    }
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

            if mpc_messages_consensus_round != mpc_outputs_consensus_round
                || mpc_messages_consensus_round
                    != verified_dwallet_checkpoint_messages_consensus_round
            {
                error!(
                    ?mpc_messages_consensus_round,
                    ?mpc_outputs_consensus_round,
                    ?verified_dwallet_checkpoint_messages_consensus_round,
                    "the consensus rounds of MPC messages, MPC outputs and checkpoint messages do not match"
                );

                panic!(
                    "the consensus rounds of MPC messages, MPC outputs and checkpoint messages do not match"
                );
            }

            let consensus_round = mpc_messages_consensus_round;

            if self.last_read_consensus_round >= Some(consensus_round) {
                error!(
                    should_never_happen=true,
                    consensus_round,
                    last_read_consensus_round=?self.last_read_consensus_round,
                    "consensus round must be in a ascending order"
                );

                panic!("consensus round must be in a ascending order");
            }

            // Let's start processing the MPC messages for the current round.
            self.dwallet_mpc_manager
                .handle_consensus_round_messages(consensus_round, mpc_messages);

            // Now we have the MPC messages for the current round, we can
            // process the MPC outputs for the current round.
            let (mut checkpoint_messages, completed_sessions) = self
                .dwallet_mpc_manager
                .handle_consensus_round_outputs(consensus_round, mpc_outputs);

            // Now we have the MPC outputs for the current round, we can
            // add messages from the consensus output such as EndOfPublish.
            checkpoint_messages.extend(verified_dwallet_checkpoint_messages);

            if !self.end_of_publish {
                let final_round = checkpoint_messages
                    .iter()
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
                if !checkpoint_messages.is_empty() {
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
                    // Only after batch is written, notify checkpoint service to start building any new
                    // pending checkpoints.
                    if let Err(e) = self.dwallet_checkpoint_service.notify_checkpoint() {
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

            if let Some(session) = self
                .dwallet_mpc_manager
                .mpc_sessions
                .get(&session_identifier)
            {
                if let MPCSessionStatus::Active { .. } = &session.status {
                    if let Some(session_request) = session.request_data.clone() {
                        match computation_result {
                            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message }) => {
                                info!(
                                    ?session_identifier,
                                    validator=?validator_name,
                                    ?mpc_round,
                                    "Advanced MPC session"
                                );

                                let message =
                                    self.new_dwallet_mpc_message(session_identifier, message);

                                if let Err(err) =
                                    consensus_adapter.submit_to_consensus(&[message]).await
                                {
                                    error!(
                                        ?session_identifier,
                                        validator=?validator_name,
                                        ?mpc_round,
                                        error=?err,
                                        "failed to submit an MPC message to consensus"
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
                                    let malicious_authorities = party_ids_to_authority_names(
                                        &malicious_parties,
                                        &committee,
                                    );

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

                                self.dwallet_mpc_manager
                                    .record_malicious_actors(&malicious_authorities);

                                let rejected = false;

                                let consensus_message = self.new_dwallet_mpc_output(
                                    session_identifier,
                                    &session_request,
                                    public_output_value,
                                    malicious_authorities,
                                    rejected,
                                );

                                if let Err(err) = consensus_adapter
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
                            Err(DwalletMPCError::MPCError(mpc::Error::ThresholdNotReached)) => {
                                error!(
                                    error=?DwalletMPCError::MPCError(mpc::Error::ThresholdNotReached),
                                        ?session_identifier,
                                    validator=?validator_name,
                                    mpc_round,
                                    party_id,
                                    "MPC session failed"
                                );

                                let consensus_round = computation_id.consensus_round.expect("consensus round must be set for the computation ID of a computation that got a threshold not reached error");
                                self.dwallet_mpc_manager.record_threshold_not_reached(
                                    consensus_round,
                                    computation_id.session_identifier,
                                )
                            }
                            Err(err) => {
                                error!(
                                    ?session_identifier,
                                    validator=?validator_name,
                                    ?mpc_round,
                                    party_id,
                                    error=?err,
                                    "failed to advance the MPC session, rejecting."
                                );

                                let consensus_adapter = self.dwallet_submit_to_consensus.clone();

                                let rejected = true;

                                let consensus_message = self.new_dwallet_mpc_output(
                                    session_identifier,
                                    &session_request,
                                    vec![],
                                    vec![],
                                    rejected,
                                );

                                if let Err(err) = consensus_adapter
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
                        }
                    } else {
                        error!(
                            should_never_happen =? true,
                            ?session_identifier,
                            validator=?validator_name,
                            ?mpc_round,
                            "no session_request for a session for which a computation update was received"
                        );
                    }
                } else {
                    warn!(
                        ?session_identifier,
                        validator=?validator_name,
                        ?mpc_round,
                        "received a computation update for an non-active MPC session"
                    );
                }
            } else {
                error!(
                    should_never_happen =? true,
                    ?session_identifier,
                    validator=?validator_name,
                    ?mpc_round,
                    "failed to retrieve MPC session for which a computation update was received"
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
    ) -> ConsensusTransaction {
        let output = Self::build_dwallet_checkpoint_message_kinds_from_output(
            &session_identifier,
            session_request,
            output,
            rejected,
        );
        ConsensusTransaction::new_dwallet_mpc_output(
            self.name,
            session_identifier,
            output,
            malicious_authorities,
        )
    }

    fn build_dwallet_checkpoint_message_kinds_from_output(
        session_identifier: &SessionIdentifier,
        session_request: &DWalletSessionRequest,
        output: Vec<u8>,
        rejected: bool,
    ) -> Vec<DWalletCheckpointMessageKind> {
        info!(
            mpc_protocol=? ProtocolData::from(&session_request.protocol_specific_data).to_string(),
            session_identifier=?session_identifier,
            "Creating session output message for checkpoint"
        );
        match &session_request.protocol_specific_data {
            ProtocolSpecificData::DKGFirst { dwallet_id, .. } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(
                    DKGFirstRoundOutput {
                        dwallet_id: dwallet_id.to_vec(),
                        output,
                        session_sequence_number: session_request.session_sequence_number,
                        rejected,
                    },
                );
                vec![tx]
            }
            ProtocolSpecificData::DKGSecond {
                dwallet_id,
                encrypted_secret_share_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(
                    DKGSecondRoundOutput {
                        output,
                        dwallet_id: dwallet_id.to_vec(),
                        encrypted_secret_share_id: encrypted_secret_share_id.to_vec(),
                        rejected,
                        session_sequence_number: session_request.session_sequence_number,
                    },
                );
                vec![tx]
            }
            ProtocolSpecificData::Presign {
                dwallet_id,
                presign_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletPresign(PresignOutput {
                    presign: output,
                    dwallet_id: dwallet_id.map(|id| id.to_vec()),
                    presign_id: presign_id.to_vec(),
                    rejected,
                    session_sequence_number: session_request.session_sequence_number,
                });
                vec![tx]
            }
            ProtocolSpecificData::Sign {
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
                    session_sequence_number: session_request.session_sequence_number,
                });
                vec![tx]
            }
            ProtocolSpecificData::EncryptedShareVerification {
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
                        session_sequence_number: session_request.session_sequence_number,
                    },
                );
                vec![tx]
            }
            ProtocolSpecificData::PartialSignatureVerification {
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
                            session_sequence_number: session_request.session_sequence_number,
                        },
                    );
                vec![tx]
            }
            ProtocolSpecificData::NetworkEncryptionKeyDkg {
                dwallet_network_encryption_key_id,
                ..
            } => {
                let slices = if rejected {
                    vec![MPCNetworkDKGOutput {
                        dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                            .to_vec(),
                        public_output: vec![],
                        supported_curves: vec![DWalletMPCNetworkKeyScheme::Secp256k1 as u32],
                        is_last: true,
                        rejected: true,
                        session_sequence_number: session_request.session_sequence_number,
                    }]
                } else {
                    Self::slice_public_output_into_messages(
                        output,
                        |public_output_chunk, is_last| MPCNetworkDKGOutput {
                            dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                                .to_vec(),
                            public_output: public_output_chunk,
                            supported_curves: vec![DWalletMPCNetworkKeyScheme::Secp256k1 as u32],
                            is_last,
                            rejected: false,
                            session_sequence_number: session_request.session_sequence_number,
                        },
                    )
                };

                let messages: Vec<_> = slices
                    .into_iter()
                    .map(DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput)
                    .collect();
                messages
            }
            ProtocolSpecificData::NetworkEncryptionKeyReconfiguration {
                dwallet_network_encryption_key_id,
            } => {
                let slices = if rejected {
                    vec![MPCNetworkReconfigurationOutput {
                        dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                            .to_vec(),
                        public_output: vec![],
                        supported_curves: vec![DWalletMPCNetworkKeyScheme::Secp256k1 as u32],
                        is_last: true,
                        rejected: true,
                        session_sequence_number: session_request.session_sequence_number,
                    }]
                } else {
                    Self::slice_public_output_into_messages(
                        output,
                        |public_output_chunk, is_last| MPCNetworkReconfigurationOutput {
                            dwallet_network_encryption_key_id: dwallet_network_encryption_key_id
                                .clone()
                                .to_vec(),
                            public_output: public_output_chunk,
                            supported_curves: vec![DWalletMPCNetworkKeyScheme::Secp256k1 as u32],
                            is_last,
                            rejected: false,
                            session_sequence_number: session_request.session_sequence_number,
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
            ProtocolSpecificData::MakeDWalletUserSecretKeySharesPublic {
                public_user_secret_key_shares,
                dwallet_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(
                    MakeDWalletUserSecretKeySharesPublicOutput {
                        dwallet_id: dwallet_id.to_vec(),
                        public_user_secret_key_shares: public_user_secret_key_shares.clone(),
                        rejected,
                        session_sequence_number: session_request.session_sequence_number,
                    },
                );
                vec![tx]
            }
            ProtocolSpecificData::ImportedKeyVerification {
                dwallet_id,
                encrypted_user_secret_key_share_id,
                ..
            } => {
                let tx = DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(
                    DWalletImportedKeyVerificationOutput {
                        dwallet_id: dwallet_id.to_vec().clone(),
                        public_output: output,
                        encrypted_user_secret_key_share_id: encrypted_user_secret_key_share_id
                            .to_vec(),
                        rejected,
                        session_sequence_number: session_request.session_sequence_number,
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
