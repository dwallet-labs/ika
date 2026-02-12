use crate::authority::AuthorityStateTrait;
use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait,
};
use crate::dwallet_checkpoints::{DWalletCheckpointServiceNotify, PendingDWalletCheckpoint};
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::epoch::submit_to_consensus::DWalletMPCSubmitToConsensus;
use crate::{SuiDataReceivers, SuiDataSenders};
use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::DWalletCurve;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use dwallet_rng::RootSeed;
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::{ConsensusTransaction, ConsensusTransactionKind};
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSignatureMessage;
use ika_types::messages_dwallet_mpc::{
    DWalletInternalMPCOutput, DWalletMPCMessage, DWalletMPCOutput, InternalSessionsStatusUpdate,
    SessionIdentifier, SessionType, UserSecretKeyShareEventType,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::messages_consensus::Round;
use tracing::info;

/// A testing implementation of the `AuthorityPerEpochStoreTrait`.
/// Records all received data for testing purposes.
pub(crate) struct TestingAuthorityPerEpochStore {
    pub(crate) pending_checkpoints: Arc<Mutex<Vec<PendingDWalletCheckpoint>>>,
    pub(crate) round_to_messages: Arc<Mutex<HashMap<Round, Vec<DWalletMPCMessage>>>>,
    pub(crate) round_to_outputs: Arc<Mutex<HashMap<Round, Vec<DWalletMPCOutput>>>>,
    pub(crate) round_to_verified_checkpoint:
        Arc<Mutex<HashMap<Round, Vec<DWalletCheckpointMessageKind>>>>,
    pub(crate) round_to_status_updates:
        Arc<Mutex<HashMap<Round, Vec<InternalSessionsStatusUpdate>>>>,
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
            round_to_outputs: Arc::new(Mutex::new(Default::default())),
            round_to_verified_checkpoint: Arc::new(Mutex::new(Default::default())),
            round_to_status_updates: Arc::new(Mutex::new(Default::default())),
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
        _last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletInternalMPCOutput>)>> {
        Ok(None)
    }

    fn insert_presigns(
        &self,
        _signature_algorithm: DWalletSignatureAlgorithm,
        _dwallet_network_encryption_key_id: ObjectID,
        _session_sequence_number: u64,
        _session_identifier: SessionIdentifier,
        _presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()> {
        Ok(())
    }

    fn presign_pool_size(
        &self,
        _signature_algorithm: DWalletSignatureAlgorithm,
        _dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<u64> {
        Ok(0)
    }

    fn pop_presign(
        &self,
        _signature_algorithm: DWalletSignatureAlgorithm,
        _dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, Vec<u8>)>> {
        Ok(None)
    }

    fn mark_presign_as_used(&self, _presign_session_id: SessionIdentifier) -> IkaResult<()> {
        Ok(())
    }

    fn is_presign_used(&self, _presign_session_id: SessionIdentifier) -> IkaResult<bool> {
        Ok(false)
    }

    fn next_internal_sessions_status_update(
        &self,
        _last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<InternalSessionsStatusUpdate>)>> {
        Ok(None)
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
    for (
        dwallet_mpc_service,
        sui_data_sender,
        dwallet_submit_to_consensus,
        epoch_store,
        notify_service,
    ) in dwallet_mpc_services
    {
        services.push(dwallet_mpc_service);
        sui_data_senders.push(sui_data_sender);
        consensus_stores.push(dwallet_submit_to_consensus);
        epoch_stores.push(epoch_store);
        notify_services.push(notify_service);
    }
    (
        services,
        sui_data_senders,
        consensus_stores,
        epoch_stores,
        notify_services,
    )
}

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
) {
    let (sui_data_receivers, sui_data_senders) = SuiDataReceivers::new_for_testing();
    let dwallet_submit_to_consensus = Arc::new(TestingSubmitToConsensus::new());
    let epoch_store = Arc::new(TestingAuthorityPerEpochStore::new());
    let checkpoint_notify = Arc::new(TestingDWalletCheckpointNotify::new());
    (
        DWalletMPCService::new_for_testing(
            epoch_store.clone(),
            seed,
            dwallet_submit_to_consensus.clone(),
            Arc::new(TestingAuthorityState::new()),
            checkpoint_notify.clone(),
            *authority_name,
            committee.clone(),
            sui_data_receivers.clone(),
        ),
        sui_data_senders,
        dwallet_submit_to_consensus,
        epoch_store,
        checkpoint_notify,
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
                .insert(new_data_consensus_round, vec![]);

            // Distribute status updates to all parties.
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
    while completed_parties.len() < parties_to_advance.len() {
        for i in 0..committee.voting_rights.len() {
            if !parties_to_advance.contains(&i) || completed_parties.contains(&i) {
                continue;
            }
            let dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
            let _ = dwallet_mpc_service.run_service_loop_iteration().await;
            let consensus_messages_store = sent_consensus_messages_collectors[i]
                .submitted_messages
                .clone();
            let pending_checkpoints_store = testing_epoch_stores[i].pending_checkpoints.clone();
            let notify_service = notify_services[i].clone();
            if !consensus_messages_store.lock().unwrap().is_empty() {
                info!(
                    party_id=?i+1,
                    "Received messages for party",
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
            assert_eq!(
                dwallet_mpc_service
                    .dwallet_mpc_manager()
                    .cryptographic_computations_orchestrator
                    .currently_running_cryptographic_computations
                    .len(),
                1,
                "Pending for a non existent computation for party id: {}",
                i + 1,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

    for i in 0..committee.voting_rights.len() {
        if !parties_to_advance.contains(&i) {
            continue;
        }
        let dwallet_mpc_service = dwallet_mpc_services.get_mut(i).unwrap();
        assert_eq!(
            dwallet_mpc_service
                .dwallet_mpc_manager()
                .cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .len(),
            0
        );
    }

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
        dwallet_mpc_service.run_service_loop_iteration().await;
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
    encrypted_user_secret_key_share_id: ObjectID,
    dwallet_id: ObjectID,
    centralized_public_key_share_and_proof: Vec<u8>,
    encrypted_centralized_secret_share_and_proof: Vec<u8>,
    encryption_key: Vec<u8>,
    encryption_key_id: ObjectID,
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
                        curve: DWalletCurve::Secp256k1,
                        centralized_public_key_share_and_proof:
                            centralized_public_key_share_and_proof.clone(),
                        user_secret_key_share: UserSecretKeyShareEventType::Encrypted {
                            encrypted_user_secret_key_share_id,
                            encrypted_centralized_secret_share_and_proof:
                                encrypted_centralized_secret_share_and_proof.clone(),
                            encryption_key: encryption_key.clone(),
                            encryption_key_id,
                            encryption_key_address: Default::default(),
                            signer_public_key: vec![],
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

pub(crate) async fn advance_mpc_flow_until_completion(
    test_state: &mut IntegrationTestState,
    start_consensus_round: Round,
) -> (Round, PendingDWalletCheckpoint) {
    let mut consensus_round = start_consensus_round;
    loop {
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
            return (consensus_round, pending_checkpoint);
        }

        send_advance_results_between_parties(
            &test_state.committee,
            &mut test_state.sent_consensus_messages_collectors,
            &mut test_state.epoch_stores,
            consensus_round,
        );
        consensus_round += 1;
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
