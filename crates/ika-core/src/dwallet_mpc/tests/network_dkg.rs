// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the DWalletMPCService struct.
//! It is responsible to read DWallet MPC messages from the
//! local DB every [`READ_INTERVAL_MS`] seconds
//! and forward them to the [`DWalletMPCManager`].

use crate::SuiDataReceivers;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::authority::{AuthorityState, AuthorityStateTrait};
use crate::consensus_adapter::SubmitToConsensus;
use crate::consensus_manager::ReplayWaiter;
use crate::dwallet_checkpoints::{
    DWalletCheckpointServiceNotify, PendingDWalletCheckpoint, PendingDWalletCheckpointInfo,
    PendingDWalletCheckpointV1,
};
use crate::dwallet_mpc::crytographic_computation::ComputationId;
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::MPCEventData;
use crate::dwallet_mpc::party_ids_to_authority_names;
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use dwallet_mpc_types::dwallet_mpc::{DWalletMPCNetworkKeyScheme, MPCMessage, MPCSessionStatus};
use fastcrypto::traits::KeyPair;
use ika_config::NodeConfig;
use ika_config::node::RootSeedWithPath;
use ika_protocol_config::ProtocolConfig;
use ika_sui_client::SuiConnectorClient;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaResult;
use ika_types::message::{
    DKGFirstRoundOutput, DKGSecondRoundOutput, DWalletCheckpointMessageKind,
    DWalletImportedKeyVerificationOutput, EncryptedUserShareOutput, MPCNetworkDKGOutput,
    MPCNetworkReconfigurationOutput, MakeDWalletUserSecretKeySharesPublicOutput,
    PartialSignatureVerificationOutput, PresignOutput, SignOutput,
};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkEncryptionKeyData, IkaNetworkConfig, MPCRequestInput,
    SessionIdentifier,
};
use ika_types::sui::{DWalletCoordinatorInner, EpochStartSystem};
use ika_types::sui::{EpochStartSystemTrait, EpochStartValidatorInfoTrait};
use itertools::Itertools;
use mpc::GuaranteedOutputDeliveryRoundResult;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sui_json_rpc_types::SuiEvent;
use sui_types::base_types::ObjectID;
use sui_types::messages_consensus::Round;
use tokio::sync::watch::error::RecvError;
use tokio::sync::watch::{Receiver, Ref};
use tracing::{debug, error, info, warn};

use crate::SuiDataSenders;
use dwallet_rng::RootSeed;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::crypto::AuthorityKeyPair;
use ika_types::messages_consensus::ConsensusTransactionKind;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSignatureMessage;
use ika_types::messages_dwallet_mpc::{
    DWalletMPCMessage, DWalletMPCOutput, DWalletNetworkDKGEncryptionKeyRequestEvent,
    DWalletSessionEvent, DWalletSessionEventTrait, SessionType,
};
use prometheus::Registry;
use std::sync::Mutex;
use tokio::sync::watch;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;

struct TestingAuthorityPerEpochStore {
    pending_checkpoints: Arc<Mutex<Vec<PendingDWalletCheckpoint>>>,
    current_round: Arc<Mutex<Round>>,
    round_to_messages: Arc<Mutex<HashMap<Round, Vec<DWalletMPCMessage>>>>,
    round_to_outputs: Arc<Mutex<HashMap<Round, Vec<DWalletMPCOutput>>>>,
}

impl TestingAuthorityPerEpochStore {
    fn new() -> Self {
        Self {
            pending_checkpoints: Arc::new(Mutex::new(vec![])),
            current_round: Arc::new(Mutex::new(0)),
            round_to_messages: Arc::new(Mutex::new(Default::default())),
            round_to_outputs: Arc::new(Mutex::new(Default::default())),
        }
    }
}

impl AuthorityPerEpochStoreTrait for TestingAuthorityPerEpochStore {
    fn insert_pending_dwallet_checkpoint(
        &self,
        checkpoint: PendingDWalletCheckpoint,
    ) -> IkaResult<()> {
        self.pending_checkpoints.lock().unwrap().push(checkpoint);
        Ok(())
    }

    fn last_dwallet_mpc_message_round(&self) -> IkaResult<Option<Round>> {
        Ok(Some(*self.current_round.lock().unwrap()))
    }

    fn next_dwallet_mpc_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCMessage>)>> {
        let round_to_messages = self.round_to_messages.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_messages
                .get(&0)
                .and_then(|messages| return Some((0, messages.clone()))));
        }
        Ok(round_to_messages
            .get(&(last_consensus_round.unwrap() + 1))
            .and_then(|messages| {
                return Some((last_consensus_round.unwrap() + 1, messages.clone()));
            }))
    }

    fn next_dwallet_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCOutput>)>> {
        let round_to_outputs = self.round_to_outputs.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_outputs
                .get(&0)
                .and_then(|outputs| return Some((0, outputs.clone()))));
        }
        Ok(round_to_outputs
            .get(&(last_consensus_round.unwrap() + 1))
            .and_then(|outputs| {
                return Some((last_consensus_round.unwrap() + 1, outputs.clone()));
            }))
    }

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>> {
        Ok(None)
    }
}

#[derive(Clone)]
struct TestingSubmitToConsensus {
    submitted_messages: Arc<Mutex<Vec<ConsensusTransaction>>>,
}

impl TestingSubmitToConsensus {
    fn new() -> Self {
        Self {
            submitted_messages: Arc::new(Mutex::new(vec![])),
        }
    }
}

#[async_trait::async_trait]
impl DWalletMPCSubmitToConsensus for TestingSubmitToConsensus {
    async fn submit_to_consensus(&self, messages: &[ConsensusTransaction]) -> IkaResult<()> {
        self.submitted_messages
            .lock()
            .unwrap()
            .extend_from_slice(messages);
        Ok(())
    }
}

struct TestingAuthorityState {
    dwallet_mpc_computation_completed_sessions: Arc<Mutex<HashMap<SessionIdentifier, bool>>>,
}

impl TestingAuthorityState {
    fn new() -> Self {
        Self {
            dwallet_mpc_computation_completed_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AuthorityStateTrait for TestingAuthorityState {
    fn insert_dwallet_mpc_computation_completed_sessions(
        &self,
        newly_completed_session_ids: &[SessionIdentifier],
    ) -> IkaResult {
        self.dwallet_mpc_computation_completed_sessions
            .lock()
            .unwrap()
            .extend(
                newly_completed_session_ids
                    .iter()
                    .map(|id| (id.clone(), true)),
            );
        Ok(())
    }

    fn get_dwallet_mpc_sessions_completed_status(
        &self,
        session_identifiers: Vec<SessionIdentifier>,
    ) -> IkaResult<HashMap<SessionIdentifier, bool>> {
        let dwallet_mpc_computation_completed_sessions = self
            .dwallet_mpc_computation_completed_sessions
            .lock()
            .unwrap();
        Ok(session_identifiers
            .iter()
            .filter_map(|session_id| {
                dwallet_mpc_computation_completed_sessions
                    .get(session_id)
                    .and_then(|_| Some((*session_id, true)))
            })
            .collect())
    }
}

struct TestingDWalletCheckpointNotify {}
impl DWalletCheckpointServiceNotify for TestingDWalletCheckpointNotify {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &DWalletCheckpointSignatureMessage,
    ) -> IkaResult {
        todo!()
    }

    fn notify_checkpoint(&self) -> IkaResult {
        todo!()
    }
}

#[tokio::test]
async fn test_network_dkg_full_flow() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (committee, keypairs) = Committee::new_simple_test_committee();
    let committee_clone = committee.clone();
    let names: Vec<_> = committee_clone.names().collect();
    let ika_network_config = IkaNetworkConfig::new(
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
    );
    let (
        mut dwallet_mpc_services,
        sui_data_senders,
        mut sent_consensus_messages_collectors,
        mut epoch_stores,
    ) = create_dwallet_mpc_services();
    sui_data_senders.iter().for_each(|mut sui_data_sender| {
            let _ = sui_data_sender.uncompleted_events_sender.send((
                vec![DBSuiEvent {
                    type_: DWalletSessionEvent::<DWalletNetworkDKGEncryptionKeyRequestEvent>::type_(
                        &ika_network_config,
                    ),
                    contents: base64::decode("Z7MmXd0I4lvGWLDA969YOVo7wrZlXr21RMvixIFabCqAU3voWC2pRFG3QwPYD+ta0sX5poLEkq77ovCi3BBQDgEAAAAAAAAAgFN76FgtqURRt0MD2A/rWtLF+aaCxJKu+6LwotwQUA4BAQAAAAAAAAAggZwXRQsb/ha4mk5xZZfqItaokplduZGMnsuEQzdm7UTt2Z+ktotfGXHn2YVaxxqVhDM8UaafXejIDXnaPLxaMAA=").unwrap(),
                    pulled: true,
                }],
                1,
            ));
        });
    println!("Created dwallet_mpc_services");
    for i in 0..committee.voting_rights.len() {
        let mut dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
        let _ = dwallet_mpc_service.run_service_loop_iteration().await;
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();

        loop {
            if !consensus_messages_store.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = dwallet_mpc_service
                .run_service_loop_iteration()
                .await;
        }
        println!("Processed cryptographic computations for service {i}");
    }

    // send each parties messages to the other parties
    for i in 0..committee.voting_rights.len() {
        let dwallet_mpc_service = dwallet_mpc_services.get(i).unwrap();
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let messages = consensus_messages_store.lock().unwrap().clone();
        consensus_messages_store.lock().unwrap().clear();
        let messages: Vec<_> = messages
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCMessage(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        drop(dwallet_mpc_service);
        for j in 0..committee.voting_rights.len() {
            let other_epoch_store = epoch_stores.get(j).unwrap();
            other_epoch_store
                .round_to_messages
                .lock()
                .unwrap()
                .insert(1, messages.clone());
        }
    }
}

fn create_dwallet_mpc_services() -> (
    Vec<DWalletMPCService>,
    Vec<SuiDataSenders>,
    Vec<Arc<TestingSubmitToConsensus>>,
    Vec<Arc<TestingAuthorityPerEpochStore>>,
) {
    let mut seeds: HashMap<AuthorityName, RootSeed> = Default::default();
    let (mut committee, keypairs) = Committee::new_simple_test_committee();
    for (authority_name, _) in committee.voting_rights.iter() {
        let seed = RootSeed::random_seed();
        seeds.insert(authority_name.clone(), seed.clone());
        let class_groups_key_pair = ClassGroupsKeyPairAndProof::from_seed(&seed);
        committee.class_groups_public_keys_and_proofs.insert(
            authority_name.clone(),
            class_groups_key_pair.encryption_key_and_proof(),
        );
    }
    let committee_clone = committee.clone();
    let names: Vec<_> = committee_clone.names().collect();
    let ika_network_config = IkaNetworkConfig::new(
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
        ObjectID::from_single_byte(1),
    );
    let dwallet_mpc_services = committee
        .names()
        .map(|authority_name| {
            create_dwallet_mpc_service(
                authority_name,
                committee.clone(),
                ika_network_config.clone(),
                seeds.get(authority_name).unwrap().clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut services = Vec::new();
    let mut sui_data_senders = Vec::new();
    let mut consensus_stores = Vec::new();
    let mut epoch_stores = Vec::new();
    for (dwallet_mpc_service, sui_data_sender, dwallet_submit_to_consensus, epoch_store) in
        dwallet_mpc_services
    {
        services.push(dwallet_mpc_service);
        sui_data_senders.push(sui_data_sender);
        consensus_stores.push(dwallet_submit_to_consensus);
        epoch_stores.push(epoch_store);
    }
    (services, sui_data_senders, consensus_stores, epoch_stores)
}

fn create_dwallet_mpc_service(
    authority_name: &AuthorityName,
    committee: Committee,
    ika_network_config: IkaNetworkConfig,
    seed: RootSeed,
) -> (
    DWalletMPCService,
    SuiDataSenders,
    Arc<TestingSubmitToConsensus>,
    Arc<TestingAuthorityPerEpochStore>,
) {
    let (sui_data_receivers, sui_data_senders) = SuiDataReceivers::new_for_testing();
    let committee_clone = committee.clone();
    let dwallet_submit_to_consensus = Arc::new(TestingSubmitToConsensus::new());
    let epoch_store = Arc::new(TestingAuthorityPerEpochStore::new());
    (
        DWalletMPCService {
            last_read_consensus_round: Some(0),
            epoch_store: epoch_store.clone(),
            dwallet_submit_to_consensus: dwallet_submit_to_consensus.clone(),
            state: Arc::new(TestingAuthorityState::new()),
            dwallet_checkpoint_service: Arc::new(TestingDWalletCheckpointNotify {}),
            dwallet_mpc_manager: DWalletMPCManager::new(
                authority_name.clone(),
                Arc::new(committee.clone()),
                1,
                ika_network_config,
                seed,
                0,
                0,
                DWalletMPCMetrics::new(&Registry::new()),
                sui_data_receivers.clone(),
            ),
            exit: watch::channel(()).1,
            end_of_publish: false,
            dwallet_mpc_metrics: DWalletMPCMetrics::new(&Registry::new()),
            sui_data_receivers,
            name: Default::default(),
            epoch: 1,
            protocol_config: ProtocolConfig::get_for_min_version(),
            committee: Arc::new(committee),
        },
        sui_data_senders,
        dwallet_submit_to_consensus,
        epoch_store,
    )
}
