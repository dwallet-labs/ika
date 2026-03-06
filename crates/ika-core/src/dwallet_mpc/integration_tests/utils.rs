use crate::authority::AuthorityStateTrait;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::dwallet_checkpoints::{DWalletCheckpointServiceNotify, PendingDWalletCheckpoint};
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use crate::{SuiDataReceivers, SuiDataSenders};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use dwallet_rng::RootSeed;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind};
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSignatureMessage;
use ika_types::messages_dwallet_mpc::{
    AssignedPresign, DWalletInternalMPCOutput, DWalletMPCMessage, DWalletMPCOutput,
    InternalSessionsStatusUpdate, SessionIdentifier, SessionType, UserSecretKeyShareEventType,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::messages_consensus::Round;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::info;

/// A testing implementation of the `AuthorityPerEpochStoreTrait`.
/// Records all received data for testing purposes.
pub(crate) struct TestingAuthorityPerEpochStore {
    pub(crate) pending_checkpoints: Arc<Mutex<Vec<PendingDWalletCheckpoint>>>,
    pub(crate) round_to_messages: Arc<Mutex<HashMap<Round, Vec<DWalletMPCMessage>>>>,
    pub(crate) round_to_outputs: Arc<Mutex<HashMap<Round, Vec<DWalletMPCOutput>>>>,
    pub(crate) round_to_internal_outputs: Arc<Mutex<HashMap<Round, Vec<DWalletInternalMPCOutput>>>>,
    pub(crate) round_to_verified_checkpoint:
        Arc<Mutex<HashMap<Round, Vec<DWalletCheckpointMessageKind>>>>,
    pub(crate) round_to_status_updates:
        Arc<Mutex<HashMap<Round, Vec<InternalSessionsStatusUpdate>>>>,
    /// Presign pool keyed by (signature algorithm, dwallet_network_encryption_key_id)
    /// Each entry contains a vector of (SessionIdentifier, presign_bytes)
    pub(crate) presign_pools: Arc<
        Mutex<HashMap<(DWalletSignatureAlgorithm, ObjectID), Vec<(SessionIdentifier, Vec<u8>)>>>,
    >,
    /// Tracks presign session usage counts.
    /// Maps session ID → (used_count, total_inserted_count).
    /// A presign is considered fully used only when all presigns from that session
    /// have been consumed (used_count >= total_count).
    pub(crate) used_presigns: Arc<Mutex<HashMap<SessionIdentifier, (u64, u64)>>>,
    /// Assigned presigns keyed by (signature_algorithm, session_identifier).
    pub(crate) assigned_presigns:
        Arc<Mutex<HashMap<(DWalletSignatureAlgorithm, SessionIdentifier), AssignedPresign>>>,
}

pub(crate) struct IntegrationTestState {
    pub(crate) dwallet_mpc_services: Vec<DWalletMPCService>,
    pub(crate) sent_consensus_messages_collectors: Vec<Arc<TestingSubmitToConsensus>>,
    pub(crate) epoch_stores: Vec<Arc<TestingAuthorityPerEpochStore>>,
    pub(crate) notify_services: Vec<Arc<TestingDWalletCheckpointNotify>>,
    pub(crate) crypto_round: usize,
    pub(crate) consensus_round: usize,
    pub(crate) committee: Committee,
    pub(crate) sui_data_senders: Vec<SuiDataSenders>,
    /// Per-algorithm senders for network-owned-address sign requests.
    pub(crate) network_owned_address_sign_request_senders:
        Vec<HashMap<DWalletSignatureAlgorithm, UnboundedSender<NetworkOwnedAddressSignRequest>>>,
    pub(crate) network_owned_address_sign_output_receivers:
        Vec<UnboundedReceiver<NetworkOwnedAddressSignOutput>>,
}

/// A testing implementation of the `DWalletMPCSubmitToConsensus` trait.
/// Records all submitted messages for testing purposes.
#[derive(Clone)]
pub(crate) struct TestingSubmitToConsensus {
    pub(crate) submitted_messages: Arc<Mutex<Vec<ConsensusTransaction>>>,
}

/// A testing implementation of the `AuthorityStateTrait`.
/// Records all completed sessions for testing purposes.
pub(crate) struct TestingAuthorityState {
    pub(crate) dwallet_mpc_computation_completed_sessions:
        Arc<Mutex<HashMap<SessionIdentifier, bool>>>,
}

pub(crate) struct TestingDWalletCheckpointNotify {
    pub(crate) checkpoints_notification_count: Arc<Mutex<usize>>,
}

impl TestingDWalletCheckpointNotify {
    pub(crate) fn new() -> Self {
        Self {
            checkpoints_notification_count: Arc::new(Mutex::new(0)),
        }
    }
}

impl TestingAuthorityPerEpochStore {
    fn new() -> Self {
        Self {
            pending_checkpoints: Arc::new(Mutex::new(vec![])),
            // The DWalletMPCService expects at least on round of messages to be present before start functioning.
            round_to_messages: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            round_to_outputs: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            round_to_internal_outputs: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            round_to_verified_checkpoint: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            round_to_status_updates: Arc::new(Mutex::new(HashMap::from([(0, vec![])]))),
            presign_pools: Arc::new(Mutex::new(Default::default())),
            used_presigns: Arc::new(Mutex::new(HashMap::new())),
            assigned_presigns: Arc::new(Mutex::new(HashMap::new())),
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
        Ok(self.round_to_messages.lock().unwrap().keys().max().copied())
    }

    fn next_dwallet_mpc_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCMessage>)>> {
        let round_to_messages = self.round_to_messages.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_messages
                .get(&0)
                .map(|messages| (0, messages.clone())));
        }
        Ok(round_to_messages
            .get(&(last_consensus_round.unwrap() + 1))
            .map(|messages| (last_consensus_round.unwrap() + 1, messages.clone())))
    }

    fn next_dwallet_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCOutput>)>> {
        let round_to_outputs = self.round_to_outputs.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_outputs.get(&0).map(|outputs| (0, outputs.clone())));
        }
        Ok(round_to_outputs
            .get(&(last_consensus_round.unwrap() + 1))
            .map(|outputs| (last_consensus_round.unwrap() + 1, outputs.clone())))
    }

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>> {
        let round_to_verified_checkpoint = self.round_to_verified_checkpoint.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_verified_checkpoint
                .get(&0)
                .map(|messages| (0, messages.clone())));
        }
        Ok(round_to_verified_checkpoint
            .get(&(last_consensus_round.unwrap() + 1))
            .map(|messages| (last_consensus_round.unwrap() + 1, messages.clone())))
    }

    fn next_dwallet_internal_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletInternalMPCOutput>)>> {
        let round_to_internal_outputs = self.round_to_internal_outputs.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_internal_outputs
                .get(&0)
                .map(|outputs| (0, outputs.clone())));
        }
        Ok(round_to_internal_outputs
            .get(&(last_consensus_round.unwrap() + 1))
            .map(|outputs| (last_consensus_round.unwrap() + 1, outputs.clone())))
    }

    fn insert_presigns(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        _session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()> {
        let mut pools = self.presign_pools.lock().unwrap();
        let key = (signature_algorithm, dwallet_network_encryption_key_id);
        let pool = pools.entry(key).or_insert_with(Vec::new);

        // Deduplicate by session_identifier: production code overwrites on the same
        // (key_id, session_sequence_number) key, so only one copy of each session's
        // presigns should exist in the pool. Skip if already present.
        let already_exists = pool.iter().any(|(sid, _)| *sid == session_identifier);
        if already_exists {
            return Ok(());
        }

        let count = presigns.len() as u64;
        for presign in presigns {
            pool.push((session_identifier, presign));
        }

        // Track inserted count for is_presign_used checks.
        let mut used = self.used_presigns.lock().unwrap();
        let entry = used.entry(session_identifier).or_insert((0, 0));
        entry.1 += count;

        Ok(())
    }

    fn presign_pool_size(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<u64> {
        let pools = self.presign_pools.lock().unwrap();
        let key = (signature_algorithm, dwallet_network_encryption_key_id);
        Ok(pools.get(&key).map_or(0, |pool| pool.len() as u64))
    }

    fn pop_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, Vec<u8>)>> {
        let mut pools = self.presign_pools.lock().unwrap();
        let key = (signature_algorithm, dwallet_network_encryption_key_id);
        Ok(pools.get_mut(&key).and_then(|pool| pool.pop()))
    }

    fn mark_presign_as_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<()> {
        let mut used = self.used_presigns.lock().unwrap();
        let entry = used.entry(presign_session_id).or_insert((0, 0));
        entry.0 += 1;
        Ok(())
    }

    fn is_presign_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<bool> {
        let used = self.used_presigns.lock().unwrap();
        match used.get(&presign_session_id) {
            // A session is "used" if:
            // - It was marked without prior insert (total=0, used>0): external use
            // - All batch presigns have been consumed (used >= total, total > 0)
            Some((used_count, total_count)) => Ok(*used_count > 0 && *used_count >= *total_count),
            None => Ok(false),
        }
    }

    fn next_internal_sessions_status_update(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<InternalSessionsStatusUpdate>)>> {
        let round_to_status_updates = self.round_to_status_updates.lock().unwrap();
        if last_consensus_round.is_none() {
            return Ok(round_to_status_updates
                .get(&0)
                .map(|updates| (0, updates.clone())));
        }
        Ok(round_to_status_updates
            .get(&(last_consensus_round.unwrap() + 1))
            .map(|updates| (last_consensus_round.unwrap() + 1, updates.clone())))
    }

    fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<SessionIdentifier>> {
        let popped = self.pop_presign(signature_algorithm, dwallet_network_encryption_key_id)?;
        match popped {
            Some((session_id, presign_bytes)) => {
                let assigned = AssignedPresign {
                    session_identifier: session_id,
                    presign: presign_bytes,
                    user_verification_key,
                    dwallet_id,
                    assigned_epoch: current_epoch,
                };
                self.assigned_presigns
                    .lock()
                    .unwrap()
                    .insert((signature_algorithm, session_id), assigned);
                Ok(Some(session_id))
            }
            None => Ok(None),
        }
    }

    fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        Ok(self
            .assigned_presigns
            .lock()
            .unwrap()
            .get(&(signature_algorithm, session_identifier))
            .cloned())
    }

    fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        Ok(self
            .assigned_presigns
            .lock()
            .unwrap()
            .remove(&(signature_algorithm, session_identifier)))
    }
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
            .extend(newly_completed_session_ids.iter().map(|id| (*id, true)));
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
                    .map(|_| (*session_id, true))
            })
            .collect())
    }
}

impl DWalletCheckpointServiceNotify for TestingDWalletCheckpointNotify {
    fn notify_checkpoint_signature(
        &self,
        _epoch_store: &AuthorityPerEpochStore,
        _info: &DWalletCheckpointSignatureMessage,
    ) -> IkaResult {
        Ok(())
    }

    fn notify_checkpoint(&self) -> IkaResult {
        *self.checkpoints_notification_count.lock().unwrap() += 1;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn create_dwallet_mpc_services(
    size: usize,
) -> (
    Vec<DWalletMPCService>,
    Vec<SuiDataSenders>,
    Vec<Arc<TestingSubmitToConsensus>>,
    Vec<Arc<TestingAuthorityPerEpochStore>>,
    Vec<Arc<TestingDWalletCheckpointNotify>>,
    Vec<HashMap<DWalletSignatureAlgorithm, UnboundedSender<NetworkOwnedAddressSignRequest>>>,
    Vec<UnboundedReceiver<NetworkOwnedAddressSignOutput>>,
) {
    let mut seeds: HashMap<AuthorityName, RootSeed> = Default::default();
    let (mut committee, _) = Committee::new_simple_test_committee_of_size(size);
    for (authority_name, _) in committee.voting_rights.iter() {
        let seed = RootSeed::random_seed();
        seeds.insert(*authority_name, seed.clone());
        let class_groups_key_pair = ClassGroupsKeyPairAndProof::from_seed(&seed);
        committee.class_groups_public_keys_and_proofs.insert(
            *authority_name,
            class_groups_key_pair.encryption_key_and_proof(),
        );
    }
    let dwallet_mpc_services = committee
        .names()
        .map(|authority_name| {
            create_dwallet_mpc_service(
                authority_name,
                committee.clone(),
                seeds.get(authority_name).unwrap().clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut services = Vec::new();
    let mut sui_data_senders = Vec::new();
    let mut consensus_stores = Vec::new();
    let mut epoch_stores = Vec::new();
    let mut notify_services = Vec::new();
    let mut sign_request_senders = Vec::new();
    let mut sign_output_receivers = Vec::new();
    for (
        dwallet_mpc_service,
        sui_data_sender,
        dwallet_submit_to_consensus,
        epoch_store,
        notify_service,
        sign_request_sender_map,
        sign_output_receiver,
    ) in dwallet_mpc_services
    {
        services.push(dwallet_mpc_service);
        sui_data_senders.push(sui_data_sender);
        consensus_stores.push(dwallet_submit_to_consensus);
        epoch_stores.push(epoch_store);
        notify_services.push(notify_service);
        sign_request_senders.push(sign_request_sender_map);
        sign_output_receivers.push(sign_output_receiver);
    }
    (
        services,
        sui_data_senders,
        consensus_stores,
        epoch_stores,
        notify_services,
        sign_request_senders,
        sign_output_receivers,
    )
}

#[allow(clippy::type_complexity)]
fn create_dwallet_mpc_service(
    authority_name: &AuthorityName,
    committee: Committee,
    seed: RootSeed,
) -> (
    DWalletMPCService,
    SuiDataSenders,
    Arc<TestingSubmitToConsensus>,
    Arc<TestingAuthorityPerEpochStore>,
    Arc<TestingDWalletCheckpointNotify>,
    HashMap<DWalletSignatureAlgorithm, UnboundedSender<NetworkOwnedAddressSignRequest>>,
    UnboundedReceiver<NetworkOwnedAddressSignOutput>,
) {
    let (sui_data_receivers, sui_data_senders) = SuiDataReceivers::new_for_testing();
    let dwallet_submit_to_consensus = Arc::new(TestingSubmitToConsensus::new());
    let epoch_store = Arc::new(TestingAuthorityPerEpochStore::new());
    let checkpoint_notify = Arc::new(TestingDWalletCheckpointNotify::new());
    let (service, sign_request_sender_map, sign_output_receiver) =
        DWalletMPCService::new_for_testing(
            epoch_store.clone(),
            seed,
            dwallet_submit_to_consensus.clone(),
            Arc::new(TestingAuthorityState::new()),
            checkpoint_notify.clone(),
            *authority_name,
            committee.clone(),
            sui_data_receivers.clone(),
        );
    (
        service,
        sui_data_senders,
        dwallet_submit_to_consensus,
        epoch_store,
        checkpoint_notify,
        sign_request_sender_map,
        sign_output_receiver,
    )
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn send_advance_results_between_parties(
    committee: &Committee,
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
    epoch_stores: &mut [Arc<TestingAuthorityPerEpochStore>],
    new_data_consensus_round: Round,
) {
    for i in 0..committee.voting_rights.len() {
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let consensus_messages = consensus_messages_store.lock().unwrap().clone();
        consensus_messages_store.lock().unwrap().clear();
        let dwallet_messages: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCMessage(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        let dwallet_outputs: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCOutput(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        let internal_outputs: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletInternalMPCOutput(output) = message.kind {
                    Some(output)
                } else {
                    None
                }
            })
            .collect();
        let status_updates: Vec<_> = consensus_messages
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update) =
                    message.kind
                {
                    Some(status_update)
                } else {
                    None
                }
            })
            .collect();
        for j in 0..committee.voting_rights.len() {
            let other_epoch_store = epoch_stores.get(j).unwrap();
            other_epoch_store
                .round_to_messages
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(dwallet_messages.clone());
            other_epoch_store
                .round_to_outputs
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(dwallet_outputs.clone());

            // The DWalletMPCService every round will have entries in all the round-specific DB tables.
            other_epoch_store
                .round_to_verified_checkpoint
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default();

            // Distribute internal MPC outputs (e.g. completed internal presign sessions) to all parties
            other_epoch_store
                .round_to_internal_outputs
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(internal_outputs.clone());
            // Distribute status updates to all parties
            other_epoch_store
                .round_to_status_updates
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(status_updates.clone());
        }
    }
}

/// Like [`send_advance_results_between_parties`], but skips distributing messages
/// TO the excluded receivers (simulating them being offline / not receiving consensus).
/// Messages FROM excluded senders are still collected and distributed to online receivers.
#[allow(clippy::needless_range_loop)]
pub(crate) fn send_advance_results_between_parties_excluding(
    committee: &Committee,
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
    epoch_stores: &mut [Arc<TestingAuthorityPerEpochStore>],
    new_data_consensus_round: Round,
    excluded_receivers: &HashSet<usize>,
) {
    for i in 0..committee.voting_rights.len() {
        let consensus_messages_store = sent_consensus_messages_collectors[i]
            .submitted_messages
            .clone();
        let consensus_messages = consensus_messages_store.lock().unwrap().clone();
        consensus_messages_store.lock().unwrap().clear();
        let dwallet_messages: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCMessage(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        let dwallet_outputs: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletMPCOutput(message) = message.kind {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        let internal_outputs: Vec<_> = consensus_messages
            .clone()
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::DWalletInternalMPCOutput(output) = message.kind {
                    Some(output)
                } else {
                    None
                }
            })
            .collect();
        let status_updates: Vec<_> = consensus_messages
            .into_iter()
            .filter_map(|message| {
                if let ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update) =
                    message.kind
                {
                    Some(status_update)
                } else {
                    None
                }
            })
            .collect();
        for j in 0..committee.voting_rights.len() {
            if excluded_receivers.contains(&j) {
                continue;
            }
            let other_epoch_store = epoch_stores.get(j).unwrap();
            other_epoch_store
                .round_to_messages
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(dwallet_messages.clone());
            other_epoch_store
                .round_to_outputs
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(dwallet_outputs.clone());
            other_epoch_store
                .round_to_verified_checkpoint
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default();
            other_epoch_store
                .round_to_internal_outputs
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(internal_outputs.clone());
            other_epoch_store
                .round_to_status_updates
                .lock()
                .unwrap()
                .entry(new_data_consensus_round)
                .or_default()
                .extend(status_updates.clone());
        }
    }
}

/// Maximum iterations when waiting for rayon computations to complete.
/// At 100ms per iteration, this gives ~180 seconds before failing.
/// The generous limit accounts for rayon thread pool contention when
/// the full integration test suite runs in a single process.
const MAX_COMPUTATION_WAIT_ITERATIONS: usize = 1800;

/// Wait for all parties' in-flight rayon computations to complete.
///
/// Runs the service loop repeatedly (with 100ms sleeps to let the tokio
/// runtime poll rayon-spawned channel sends) until every party's
/// `currently_running_cryptographic_computations` set is empty.
///
/// This is essential for tests that assert on session completion or pool
/// sizes, because the cryptographic computations run on rayon and need
/// real wall-clock time plus tokio runtime polls to deliver their results
/// through the completion channel.
pub(crate) async fn wait_for_computations(test_state: &mut IntegrationTestState) {
    for iteration in 0..MAX_COMPUTATION_WAIT_ITERATIONS {
        let all_idle = test_state.dwallet_mpc_services.iter().all(|s| {
            s.dwallet_mpc_manager()
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .is_empty()
        });
        if all_idle {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Run service loop to collect completed rayon results from the
        // channel and submit them to consensus.  Without new consensus
        // rounds in the epoch store, `process_consensus_rounds_from_storage`
        // is a no-op, so only `process_cryptographic_computations` does work.
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
        if iteration > 0 && iteration % 100 == 0 {
            info!(
                iteration,
                "wait_for_computations: still waiting for rayon computations"
            );
        }
    }
    panic!(
        "Rayon computations did not complete within {} seconds",
        MAX_COMPUTATION_WAIT_ITERATIONS / 10
    );
}

pub(crate) async fn advance_all_parties_and_wait_for_completions(
    committee: &Committee,
    dwallet_mpc_services: &mut [DWalletMPCService],
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
    testing_epoch_stores: &[Arc<TestingAuthorityPerEpochStore>],
    notify_services: &[Arc<TestingDWalletCheckpointNotify>],
) -> Option<PendingDWalletCheckpoint> {
    advance_some_parties_and_wait_for_completions(
        committee,
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        testing_epoch_stores,
        notify_services,
        &(0..committee.voting_rights.len()).collect::<Vec<_>>(),
    )
    .await
}

/// Maximum iterations for the inner party advancement loop.
/// At 100ms per iteration, this gives ~60 seconds before failing.
/// This needs to be long enough to complete internal presign sessions
/// which run in parallel and can be CPU-intensive.
const MAX_PARTY_ITERATIONS: usize = 600;

pub(crate) async fn advance_some_parties_and_wait_for_completions(
    committee: &Committee,
    dwallet_mpc_services: &mut [DWalletMPCService],
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
    testing_epoch_stores: &[Arc<TestingAuthorityPerEpochStore>],
    notify_services: &[Arc<TestingDWalletCheckpointNotify>],
    parties_to_advance: &[usize],
) -> Option<PendingDWalletCheckpoint> {
    let mut pending_checkpoints = vec![];
    let mut completed_parties = vec![];
    let mut iterations = 0usize;
    // Track per-party newly-instantiated network key IDs so that sessions waiting
    // for a key (in `requests_pending_for_network_key`) are activated as soon as the
    // key is voted-in through a consensus round, without requiring a second outer-loop
    // iteration.
    let mut party_newly_instantiated_network_key_ids: Vec<Vec<ObjectID>> =
        vec![vec![]; committee.voting_rights.len()];
    while completed_parties.len() < parties_to_advance.len() {
        iterations += 1;
        if iterations >= MAX_PARTY_ITERATIONS {
            panic!(
                "Party advancement did not complete after {} iterations (~{} seconds). \
                Completed {}/{} parties. Completed: {:?}, Expected: {:?}. \
                This likely indicates a bug in the test or the MPC flow.",
                MAX_PARTY_ITERATIONS,
                MAX_PARTY_ITERATIONS / 10,
                completed_parties.len(),
                parties_to_advance.len(),
                completed_parties,
                parties_to_advance
            );
        }
        for i in 0..committee.voting_rights.len() {
            if !parties_to_advance.contains(&i) || completed_parties.contains(&i) {
                continue;
            }
            let dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
            let consensus_messages_store = sent_consensus_messages_collectors[i]
                .submitted_messages
                .clone();
            let pending_checkpoints_store = testing_epoch_stores[i].pending_checkpoints.clone();
            let notify_service = notify_services[i].clone();

            // Helper to check for MPC activity (excluding InternalPresign sessions)
            let check_mpc_activity = |store: &Arc<Mutex<Vec<ConsensusTransaction>>>| {
                store.lock().unwrap().iter().any(|msg| match &msg.kind {
                    ConsensusTransactionKind::DWalletMPCMessage(mpc_msg) => {
                        mpc_msg.session_identifier.session_type() != SessionType::InternalPresign
                    }
                    ConsensusTransactionKind::DWalletMPCOutput(mpc_output) => {
                        mpc_output.session_identifier.session_type() != SessionType::InternalPresign
                    }
                    _ => false,
                })
            };

            // When `currently_running == 0` and the party has an
            // `InternalSessionsStatusUpdate` containing new network key data (e.g. key
            // data broadcast after DKG completes), treat it as a round boundary so the
            // outer loop can call `send_advance_results_between_parties` and activate
            // sessions waiting on the key.
            // Also trigger when the update contains global presign requests, so that the
            // outer loop distributes them to all parties (regardless of running computations).
            // This check must happen BEFORE clearing so the status update is not lost.
            // We only trigger on updates with actual `network_key_data` or `global_presign_requests`
            // to avoid false positives from idle-status-only updates (emitted on first run due to
            // `last_sent_idle_status = None`), which would waste outer-loop rounds.
            let currently_running_len = dwallet_mpc_service
                .dwallet_mpc_manager()
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .len();
            let check_status_update_with_data = |store: &Arc<Mutex<Vec<ConsensusTransaction>>>| {
                store.lock().unwrap().iter().any(|msg| {
                    if let ConsensusTransactionKind::InternalSessionsStatusUpdate(update) =
                        &msg.kind
                    {
                        !update.global_presign_requests.is_empty()
                            || (currently_running_len == 0 && !update.network_key_data.is_empty())
                    } else {
                        false
                    }
                })
            };

            // Check for MPC activity BEFORE clearing - this handles messages produced
            // during setup phases (e.g., rejected sessions when network key is already available)
            // Also exit early if there's a pending-for-key/presign status update to distribute.
            if check_mpc_activity(&consensus_messages_store)
                || check_status_update_with_data(&consensus_messages_store)
            {
                info!(
                    party_id=?i+1,
                    "Received MPC messages/outputs for party (from previous phase)",
                );
                completed_parties.push(i);
                continue;
            }

            // Clear non-InternalPresign messages BEFORE running the service loop
            // so we only track messages produced by THIS iteration.
            // InternalPresign messages must be preserved because they run concurrently
            // with the main flow — clearing them destroys round-advancement messages
            // that the sessions need to progress through consensus.
            {
                let mut messages = sent_consensus_messages_collectors[i]
                    .submitted_messages
                    .lock()
                    .unwrap();
                messages.retain(|msg| match &msg.kind {
                    ConsensusTransactionKind::DWalletMPCMessage(mpc_msg) => {
                        mpc_msg.session_identifier.session_type() == SessionType::InternalPresign
                    }
                    ConsensusTransactionKind::DWalletMPCOutput(mpc_output) => {
                        mpc_output.session_identifier.session_type() == SessionType::InternalPresign
                    }
                    ConsensusTransactionKind::DWalletInternalMPCOutput(_) => true,
                    ConsensusTransactionKind::InternalSessionsStatusUpdate(_) => true,
                    _ => false,
                });
            }
            let key_ids = std::mem::take(&mut party_newly_instantiated_network_key_ids[i]);
            let new_key_ids = dwallet_mpc_service
                .run_service_loop_iteration(key_ids)
                .await;
            party_newly_instantiated_network_key_ids[i] = new_key_ids;

            // Check if the party has produced MPC messages or outputs in THIS iteration.
            // We filter for DWalletMPCMessage and DWalletMPCOutput because InternalSessionsStatusUpdate
            // can be produced when processing old sessions, not new ones.
            // IMPORTANT: We also filter OUT messages for InternalPresign sessions, as these are
            // background tasks that run asynchronously and should not count as "completion" for
            // the test harness. Otherwise, one party starting internal presigns before others
            // would cause the test to progress before all parties have processed the same events.
            if check_mpc_activity(&consensus_messages_store)
                || check_status_update_with_data(&consensus_messages_store)
            {
                info!(
                    party_id=?i+1,
                    "Received MPC messages/outputs for party",
                );
                completed_parties.push(i);
                continue;
            }
            if *notify_service
                .checkpoints_notification_count
                .lock()
                .unwrap()
                > 0
            {
                *notify_service
                    .checkpoints_notification_count
                    .lock()
                    .unwrap() = 0;
                let pending_checkpoint = pending_checkpoints_store.lock().unwrap().pop();
                assert!(
                    pending_checkpoint.is_some(),
                    "received a checkpoint notification, but no pending checkpoint was found"
                );
                let pending_dwallet_checkpoint = pending_checkpoint.unwrap();
                info!(?pending_dwallet_checkpoint, party_id=?i+1, "Pending checkpoint found");
                pending_checkpoints.push(pending_dwallet_checkpoint);
                completed_parties.push(i);
                continue;
            }
            // Note: We don't assert that exactly 1 computation is running here.
            // The computation might have already completed if it was fast, which is fine.
            // The assertion at the end of the function will verify cleanup.
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Process any pending completion updates to clean up `currently_running_cryptographic_computations`.
    // We need to poll multiple times because:
    // 1. The rayon thread spawns a tokio task to send the completion message
    // 2. That tokio task needs to be polled to actually send the message
    // 3. Then receive_completed_computations needs to be called to process it
    // We run the service loop iteration which will call receive_completed_computations internally.
    // Using actual sleep (not just yield) to give rayon tasks time to complete.
    for _ in 0..100 {
        let mut all_done = true;
        for i in 0..committee.voting_rights.len() {
            if !parties_to_advance.contains(&i) {
                continue;
            }
            let dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
            // Run the service loop to allow tokio tasks spawned by rayon to complete
            // and to call receive_completed_computations internally.
            let _ = dwallet_mpc_service.run_service_loop_iteration(vec![]).await;
            if dwallet_mpc_service
                .dwallet_mpc_manager()
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .len()
                > 0
            {
                all_done = false;
            }
        }
        if all_done {
            break;
        }
        // Sleep to give rayon tasks actual time to complete and send results
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Note: We no longer assert that all computations have completed because
    // internal presign sessions run continuously in the background and may always
    // have ongoing computations. The cleanup loop above gives sufficient time
    // for the specific flow being tested to complete.

    if pending_checkpoints.len() == parties_to_advance.len()
        && pending_checkpoints
            .iter()
            .all(|x| x.clone() == pending_checkpoints[0].clone())
    {
        return Some(pending_checkpoints[0].clone());
    }
    assert!(
        pending_checkpoints.is_empty(),
        "Pending checkpoints are not equal across all parties: {:?}",
        pending_checkpoints
    );

    None
}

/// Overrides the legitimate messages of malicious parties with false messages for the given crypto round and
/// malicious parties. When other validators receive these messages, they will mark the malicious parties as malicious.
// TODO: itay
#[allow(dead_code)]
pub(crate) fn override_legit_messages_with_false_messages(
    malicious_parties: &[usize],
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
    crypto_round: u64,
) {
    for malicious_party_index in malicious_parties {
        // Create a malicious message for round 1, and set it as the patty's message.
        let original_message = sent_consensus_messages_collectors[*malicious_party_index]
            .submitted_messages
            .lock()
            .unwrap()
            .pop();
        if let Some(mut original_message) = original_message {
            let ConsensusTransactionKind::DWalletMPCMessage(ref mut msg) = original_message.kind
            else {
                panic!("Only DWalletMPCMessage messages can be overridden with false messages");
            };
            let mut new_message: Vec<u8> = vec![0];
            new_message.extend(bcs::to_bytes::<u64>(&crypto_round).unwrap());
            new_message.extend([3; 48]);
            msg.message = new_message;
            sent_consensus_messages_collectors[*malicious_party_index]
                .submitted_messages
                .lock()
                .unwrap()
                .push(original_message);
        };
    }
}
use crate::dwallet_mpc::mpc_session::SessionStatus;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{DWalletDKGData, NetworkEncryptionKeyDkgData, ProtocolData};
use ika_protocol_config::OverrideGuard;

/// Test-friendly protocol config values.
/// These are small to keep integration tests fast and assertions exact.
pub(crate) const TEST_IDLE_SESSION_COUNT_THRESHOLD: u64 = 5;
pub(crate) const TEST_PRESIGN_POOL_MINIMUM_SIZE: u64 = 4;
pub(crate) const TEST_PRESIGN_POOL_MAXIMUM_SIZE: u64 = 12;
pub(crate) const TEST_PRESIGN_CONSENSUS_ROUND_DELAY: u64 = 2;
pub(crate) const TEST_PRESIGN_SESSIONS_TO_INSTANTIATE: u64 = 1;
pub(crate) const TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE: u64 = 2;

/// Creates a protocol config override guard with small, test-friendly values.
///
/// Must be called BEFORE creating services (since `get_for_max_version_UNSAFE` caches).
/// Hold the returned guard for the duration of the test.
#[cfg(test)]
pub(crate) fn create_test_protocol_config_guard() -> OverrideGuard {
    ProtocolConfig::apply_overrides_for_testing(|_version, mut config| {
        config.set_idle_session_count_threshold_for_testing(TEST_IDLE_SESSION_COUNT_THRESHOLD);

        // Per-algorithm presign pool settings
        config.set_internal_secp256k1_ecdsa_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_internal_secp256k1_ecdsa_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_internal_secp256k1_ecdsa_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_internal_secp256k1_ecdsa_presign_sessions_to_instantiate_for_testing(
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_internal_secp256r1_ecdsa_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_internal_secp256r1_ecdsa_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_internal_secp256r1_ecdsa_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_internal_secp256r1_ecdsa_presign_sessions_to_instantiate_for_testing(
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_internal_eddsa_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_internal_eddsa_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_internal_eddsa_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_internal_eddsa_presign_sessions_to_instantiate_for_testing(
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_internal_schnorrkel_substrate_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_internal_schnorrkel_substrate_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_internal_schnorrkel_substrate_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_internal_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_internal_taproot_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_internal_taproot_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_internal_taproot_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_internal_taproot_presign_sessions_to_instantiate_for_testing(
            TEST_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        // Network-owned-address sign presign pools (per algorithm)
        config
            .set_network_owned_address_sign_ecdsa_secp256k1_presign_pool_minimum_size_for_testing(
                TEST_PRESIGN_POOL_MINIMUM_SIZE,
            );
        config
            .set_network_owned_address_sign_ecdsa_secp256k1_presign_pool_maximum_size_for_testing(
                TEST_PRESIGN_POOL_MAXIMUM_SIZE,
            );
        config.set_network_owned_address_sign_ecdsa_secp256k1_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_network_owned_address_sign_ecdsa_secp256k1_presign_sessions_to_instantiate_for_testing(
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config
            .set_network_owned_address_sign_ecdsa_secp256r1_presign_pool_minimum_size_for_testing(
                TEST_PRESIGN_POOL_MINIMUM_SIZE,
            );
        config
            .set_network_owned_address_sign_ecdsa_secp256r1_presign_pool_maximum_size_for_testing(
                TEST_PRESIGN_POOL_MAXIMUM_SIZE,
            );
        config.set_network_owned_address_sign_ecdsa_secp256r1_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_network_owned_address_sign_ecdsa_secp256r1_presign_sessions_to_instantiate_for_testing(
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_network_owned_address_sign_eddsa_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_network_owned_address_sign_eddsa_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_network_owned_address_sign_eddsa_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_network_owned_address_sign_eddsa_presign_sessions_to_instantiate_for_testing(
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_network_owned_address_sign_schnorrkel_substrate_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_network_owned_address_sign_schnorrkel_substrate_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_network_owned_address_sign_schnorrkel_substrate_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_network_owned_address_sign_schnorrkel_substrate_presign_sessions_to_instantiate_for_testing(
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config.set_network_owned_address_sign_taproot_presign_pool_minimum_size_for_testing(
            TEST_PRESIGN_POOL_MINIMUM_SIZE,
        );
        config.set_network_owned_address_sign_taproot_presign_pool_maximum_size_for_testing(
            TEST_PRESIGN_POOL_MAXIMUM_SIZE,
        );
        config.set_network_owned_address_sign_taproot_presign_consensus_round_delay_for_testing(
            TEST_PRESIGN_CONSENSUS_ROUND_DELAY,
        );
        config.set_network_owned_address_sign_taproot_presign_sessions_to_instantiate_for_testing(
            TEST_NETWORK_OWNED_ADDRESS_SIGN_PRESIGN_SESSIONS_TO_INSTANTIATE,
        );

        config
    })
}

/// Counts sessions of a given type in validator 0's manager.
///
/// Using validator 0 as a proxy is sufficient because all validators run the same
/// service-loop logic and receive the same consensus output; their session sets are
/// structurally identical at any given round boundary.
#[cfg(test)]
pub(crate) fn count_sessions_by_type(
    test_state: &IntegrationTestState,
    session_type: SessionType,
) -> usize {
    test_state.dwallet_mpc_services[0]
        .dwallet_mpc_manager()
        .sessions
        .iter()
        .filter(|(id, _)| id.session_type() == session_type)
        .count()
}

/// Creates an `IntegrationTestState` from the output of `create_dwallet_mpc_services`.
#[cfg(test)]
pub(crate) fn build_test_state(size: usize) -> IntegrationTestState {
    let (committee, _) = Committee::new_simple_test_committee_of_size(size);
    let (
        dwallet_mpc_services,
        sui_data_senders,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    ) = create_dwallet_mpc_services(size);
    IntegrationTestState {
        dwallet_mpc_services,
        sent_consensus_messages_collectors,
        epoch_stores,
        notify_services,
        crypto_round: 1,
        consensus_round: 1,
        committee,
        sui_data_senders,
        network_owned_address_sign_request_senders,
        network_owned_address_sign_output_receivers,
    }
}

pub(crate) async fn send_start_network_dkg_event_to_all_parties(
    epoch_id: EpochId,
    test_state: &mut IntegrationTestState,
) {
    let key_id = ObjectID::random();
    let all_parties = &(0..test_state.sui_data_senders.len()).collect::<Vec<_>>();
    send_configurable_start_network_dkg_event(
        epoch_id,
        &mut test_state.sui_data_senders,
        [1u8; 32],
        1,
        all_parties,
        key_id,
    );
    for dwallet_mpc_service in test_state.dwallet_mpc_services.iter_mut() {
        dwallet_mpc_service.run_service_loop_iteration(vec![]).await;
        assert_eq!(dwallet_mpc_service.dwallet_mpc_manager().sessions.len(), 1);
        let session = dwallet_mpc_service
            .dwallet_mpc_manager()
            .sessions
            .values()
            .next()
            .unwrap();
        assert!(
            matches!(session.status, SessionStatus::Active { .. }),
            "Session should be active"
        );
    }
}

pub(crate) fn send_start_network_dkg_event_to_some_parties(
    epoch_id: EpochId,
    sui_data_senders: &mut [SuiDataSenders],
    parties: &[usize],
    key_id: ObjectID,
) {
    send_configurable_start_network_dkg_event(
        epoch_id,
        sui_data_senders,
        [1u8; 32],
        1,
        parties,
        key_id,
    );
}

pub(crate) fn send_configurable_start_network_dkg_event(
    epoch_id: EpochId,
    sui_data_senders: &mut [SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    parties: &[usize],
    key_id: ObjectID,
) {
    sui_data_senders
        .iter()
        .enumerate()
        .filter(|(i, _)| parties.contains(i))
        .for_each(|(_, sui_data_sender)| {
            let _ = sui_data_sender.uncompleted_events_sender.send((
                vec![DWalletSessionRequest {
                    session_type: SessionType::System,
                    session_identifier: SessionIdentifier::new(
                        SessionType::System,
                        session_identifier_preimage,
                    ),
                    session_sequence_number,
                    protocol_data: ProtocolData::NetworkEncryptionKeyDkg {
                        data: NetworkEncryptionKeyDkgData {},
                        dwallet_network_encryption_key_id: key_id,
                    },
                    epoch: 1,
                    requires_network_key_data: false,
                    requires_next_active_committee: false,
                    pulled: false,
                }],
                epoch_id,
            ));
        });
}

pub(crate) fn send_start_dwallet_dkg_first_round_event(
    epoch_id: EpochId,
    sui_data_senders: &mut [SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
) {
    let dwallet_id = ObjectID::random();
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number,
                protocol_data: ProtocolData::DWalletDKG {
                    data: DWalletDKGData {
                        curve: DWalletCurve::Secp256k1,
                        centralized_public_key_share_and_proof: vec![],
                        user_secret_key_share: UserSecretKeyShareEventType::Public {
                            public_user_secret_key_share: vec![],
                        },
                    },
                    dwallet_id,
                    dwallet_network_encryption_key_id,
                },
                epoch: 1,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

pub(crate) fn send_start_dwallet_dkg_event(
    epoch_id: EpochId,
    sui_data_senders: &[SuiDataSenders],
    session_identifier_preimage: [u8; 32],
    session_sequence_number: u64,
    dwallet_network_encryption_key_id: ObjectID,
    dwallet_id: ObjectID,
    centralized_public_key_share_and_proof: Vec<u8>,
    user_secret_key_share: UserSecretKeyShareEventType,
    curve: DWalletCurve,
) {
    sui_data_senders.iter().for_each(|sui_data_sender| {
        let _ = sui_data_sender.uncompleted_events_sender.send((
            vec![DWalletSessionRequest {
                session_type: SessionType::User,
                session_identifier: SessionIdentifier::new(
                    SessionType::User,
                    session_identifier_preimage,
                ),
                session_sequence_number,
                protocol_data: ProtocolData::DWalletDKG {
                    data: DWalletDKGData {
                        curve,
                        centralized_public_key_share_and_proof:
                            centralized_public_key_share_and_proof.clone(),
                        user_secret_key_share: user_secret_key_share.clone(),
                    },
                    dwallet_id,
                    dwallet_network_encryption_key_id,
                },
                epoch: 1,
                requires_network_key_data: true,
                requires_next_active_committee: false,
                pulled: false,
            }],
            epoch_id,
        ));
    });
}

/// Advances consensus rounds until the internal presign pool for the given algorithm and
/// network key has at least one presign available. Returns the new consensus round.
///
/// This is useful when tests need real presigns from the internal pool (e.g. for sign tests),
/// and need to wait for the background internal presign sessions to complete.
pub(crate) async fn advance_rounds_while_presign_pool_empty(
    test_state: &mut IntegrationTestState,
    signature_algorithm: DWalletSignatureAlgorithm,
    network_key_id: ObjectID,
    start_consensus_round: Round,
) -> Round {
    const MAX_WAIT_ROUNDS: usize = 300;
    /// Polling iterations per consensus round.  Each iteration sleeps 100ms
    /// and runs the service loop so completed rayon tasks are collected.
    /// We do NOT use `wait_for_computations` here because callers may have
    /// in-flight multi-round sessions (e.g. ECDSA presigns started during DKG)
    /// that cannot finish without future consensus rounds — blocking until ALL
    /// computations are idle would deadlock.
    const POLLS_PER_ROUND: usize = 20;
    let mut consensus_round = start_consensus_round;
    for round_idx in 0..MAX_WAIT_ROUNDS {
        send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
        for service in test_state.dwallet_mpc_services.iter_mut() {
            service.run_service_loop_iteration(vec![]).await;
        }
        // Poll the service loop to collect rayon results, giving up to
        // POLLS_PER_ROUND × 100ms for single-round computations to finish.
        for _ in 0..POLLS_PER_ROUND {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for service in test_state.dwallet_mpc_services.iter_mut() {
                service.run_service_loop_iteration(vec![]).await;
            }
        }
        let pool_size = test_state
            .epoch_stores
            .first()
            .expect("at least one epoch store should exist")
            .presign_pool_size(signature_algorithm, network_key_id)
            .unwrap_or(0);
        if round_idx < 10 || round_idx % 20 == 0 {
            let svc = &test_state.dwallet_mpc_services[0];
            let mgr = svc.dwallet_mpc_manager();
            let network_keys = mgr.network_keys.network_encryption_keys.len();
            let running = mgr
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .len();
            let instantiated = mgr.instantiated_internal_presign_sessions.clone();
            let completed = mgr.completed_internal_presign_sessions.clone();
            info!(
                round_idx,
                consensus_round,
                pool_size,
                network_keys,
                running,
                ?instantiated,
                ?completed,
                number_of_consensus_rounds = svc.number_of_consensus_rounds(),
                last_read = ?svc.last_read_consensus_round(),
                "advance_rounds_while_presign_pool_empty: status"
            );
        }
        if pool_size > 0 {
            return consensus_round;
        }
    }
    panic!(
        "Presign pool for {:?} did not fill after {} rounds",
        signature_algorithm, MAX_WAIT_ROUNDS,
    );
}

/// Maximum number of consensus rounds to wait before failing the test.
/// This prevents infinite loops in case of bugs.
const MAX_CONSENSUS_ROUNDS: u64 = 100;

pub(crate) async fn advance_mpc_flow_until_completion(
    test_state: &mut IntegrationTestState,
    start_consensus_round: Round,
) -> (Round, PendingDWalletCheckpoint) {
    let mut consensus_round = start_consensus_round;
    let mut rounds_waited = 0u64;
    loop {
        if rounds_waited >= MAX_CONSENSUS_ROUNDS {
            panic!(
                "MPC flow did not complete after {} consensus rounds. \
                Started at round {}, currently at round {}. \
                This likely indicates a bug in the test or the MPC flow.",
                MAX_CONSENSUS_ROUNDS, start_consensus_round, consensus_round
            );
        }

        if let Some(pending_checkpoint) = advance_all_parties_and_wait_for_completions(
            &test_state.committee,
            &mut test_state.dwallet_mpc_services,
            &mut test_state.sent_consensus_messages_collectors,
            &test_state.epoch_stores,
            &test_state.notify_services,
        )
        .await
        {
            info!(?pending_checkpoint, "MPC flow completed successfully");
            send_advance_results_between_parties(
                &test_state.committee,
                &mut test_state.sent_consensus_messages_collectors,
                &mut test_state.epoch_stores,
                consensus_round,
            );
            return (consensus_round, pending_checkpoint);
        }

        send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
        rounds_waited += 1;
    }
}

pub(crate) fn replace_party_message_with_other_party_message(
    party_to_replace: usize,
    other_party: usize,
    crypto_round: u64,
    sent_consensus_messages_collectors: &mut [Arc<TestingSubmitToConsensus>],
) {
    info!(
        "Replacing party {} message with party {} message for crypto round {}",
        party_to_replace, other_party, crypto_round
    );
    let original_message = sent_consensus_messages_collectors[party_to_replace]
        .submitted_messages
        .lock()
        .unwrap()
        .pop()
        .unwrap();

    let mut other_party_message = sent_consensus_messages_collectors[other_party]
        .submitted_messages
        .lock()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let ConsensusTransactionKind::DWalletMPCMessage(ref mut other_party_message_content) =
        other_party_message.kind
    else {
        panic!("Only DWalletMPCMessage messages can be replaced with other party messages");
    };
    let ConsensusTransactionKind::DWalletMPCMessage(original_message) = original_message.kind
    else {
        panic!("Only DWalletMPCMessage messages can be replaced with other party messages");
    };
    other_party_message_content.authority = original_message.authority;
    sent_consensus_messages_collectors[party_to_replace]
        .submitted_messages
        .lock()
        .unwrap()
        .push(other_party_message)
}
