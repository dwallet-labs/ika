use crate::authority::AuthorityStateTrait;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::dwallet_checkpoints::{DWalletCheckpointServiceNotify, PendingDWalletCheckpoint};
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use crate::{SuiDataReceivers, SuiDataSenders};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_rng::RootSeed;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSignatureMessage;
use ika_types::messages_dwallet_mpc::{
    DWalletMPCMessage, DWalletMPCOutput, IkaNetworkConfig, SessionIdentifier,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sui_types::base_types::ObjectID;
use sui_types::messages_consensus::Round;

pub(crate) struct TestingAuthorityPerEpochStore {
    pub(crate) pending_checkpoints: Arc<Mutex<Vec<PendingDWalletCheckpoint>>>,
    pub(crate) round_to_messages: Arc<Mutex<HashMap<Round, Vec<DWalletMPCMessage>>>>,
    pub(crate) round_to_outputs: Arc<Mutex<HashMap<Round, Vec<DWalletMPCOutput>>>>,
    pub(crate) round_to_verified_checkpoint:
        Arc<Mutex<HashMap<Round, Vec<DWalletCheckpointMessageKind>>>>,
}

impl TestingAuthorityPerEpochStore {
    fn new() -> Self {
        Self {
            pending_checkpoints: Arc::new(Mutex::new(vec![])),
            // The DWalletMPCService expects at least on round of messages to be present before start functioning.
            round_to_messages: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            round_to_outputs: Arc::new(Mutex::new(Default::default())),
            round_to_verified_checkpoint: Arc::new(Mutex::new(Default::default())),
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
        Ok(Some(
            (self.round_to_messages.lock().unwrap().len() - 1) as u64,
        ))
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
        let round_to_verified_checkpoint = self.round_to_verified_checkpoint.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_verified_checkpoint
                .get(&0)
                .and_then(|messages| return Some((0, messages.clone()))));
        }
        Ok(round_to_verified_checkpoint
            .get(&(last_consensus_round.unwrap() + 1))
            .and_then(|messages| {
                return Some((last_consensus_round.unwrap() + 1, messages.clone()));
            }))
    }
}

#[derive(Clone)]
pub(crate) struct TestingSubmitToConsensus {
    pub(crate) submitted_messages: Arc<Mutex<Vec<ConsensusTransaction>>>,
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

pub(crate) struct TestingAuthorityState {
    pub(crate) dwallet_mpc_computation_completed_sessions:
        Arc<Mutex<HashMap<SessionIdentifier, bool>>>,
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

pub(crate) struct TestingDWalletCheckpointNotify {}

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

pub fn create_dwallet_mpc_services() -> (
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
    let dwallet_submit_to_consensus = Arc::new(TestingSubmitToConsensus::new());
    let epoch_store = Arc::new(TestingAuthorityPerEpochStore::new());
    (
        DWalletMPCService::new_for_testing(
            epoch_store.clone(),
            seed,
            dwallet_submit_to_consensus.clone(),
            Arc::new(TestingAuthorityState::new()),
            Arc::new(TestingDWalletCheckpointNotify {}),
            authority_name.clone(),
            committee.clone(),
            ika_network_config.clone(),
            sui_data_receivers.clone(),
        ),
        sui_data_senders,
        dwallet_submit_to_consensus,
        epoch_store,
    )
}
