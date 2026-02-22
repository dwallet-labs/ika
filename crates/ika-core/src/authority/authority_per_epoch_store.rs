// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use arc_swap::ArcSwapOption;
use enum_dispatch::enum_dispatch;
use futures::FutureExt;
use futures::future::{Either, join_all, select};
use ika_types::committee::Committee;
use ika_types::committee::CommitteeTrait;
use ika_types::crypto::AuthorityName;
use ika_types::digests::ChainIdentifier;
use ika_types::error::{IkaError, IkaResult};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sui_types::base_types::{EpochId, ObjectID};
use tracing::{debug, info, instrument, trace, warn};
use typed_store::rocks::{DBBatch, DBMap, DBOptions, MetricConf, default_db_options};
use typed_store::rocksdb::Options;

use super::epoch_start_configuration::EpochStartConfigTrait;

use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::authority::{AuthorityCapabilitiesVotingResults, AuthorityMetrics, AuthorityState};
use crate::dwallet_checkpoints::{
    BuilderDWalletCheckpointMessage, DWalletCheckpointHeight, DWalletCheckpointServiceNotify,
    PendingDWalletCheckpoint,
};

use crate::consensus_handler::{
    ConsensusCommitInfo, SequencedConsensusTransaction, SequencedConsensusTransactionKey,
    SequencedConsensusTransactionKind, VerifiedSequencedConsensusTransaction,
};

use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
};
use crate::epoch::epoch_metrics::EpochMetrics;
use crate::stake_aggregator::StakeAggregator;
use crate::system_checkpoints::{
    BuilderSystemCheckpoint, PendingSystemCheckpoint, PendingSystemCheckpointInfo,
    PendingSystemCheckpointV1, SystemCheckpointHeight, SystemCheckpointService,
    SystemCheckpointServiceNotify,
};
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use group::PartyID;
use ika_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use ika_types::digests::MessageDigest;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_consensus::Round;
use ika_types::messages_consensus::{
    AuthorityCapabilitiesV1, ConsensusTransaction, ConsensusTransactionKey,
    ConsensusTransactionKind,
};
use ika_types::messages_dwallet_checkpoint::{
    DWalletCheckpointMessage, DWalletCheckpointSequenceNumber, DWalletCheckpointSignatureMessage,
};
use ika_types::messages_dwallet_mpc::{
    AssignedPresign, DWalletInternalMPCOutput, DWalletMPCMessage, DWalletMPCOutput,
    IkaNetworkConfig, InternalSessionsStatusUpdate, SessionIdentifier,
};
use ika_types::messages_system_checkpoints::{
    SystemCheckpointMessage, SystemCheckpointMessageKind, SystemCheckpointSequenceNumber,
    SystemCheckpointSignatureMessage,
};
use ika_types::sui::epoch_start_system::{EpochStartSystem, EpochStartSystemTrait};
use mpc::WeightedThresholdAccessStructure;
use mysten_common::sync::notify_once::NotifyOnce;
use mysten_common::sync::notify_read::NotifyRead;
use mysten_metrics::monitored_scope;
use prometheus::IntCounter;
use tap::TapOptional;
use tokio::time::Instant;
use typed_store::DBMapUtils;
use typed_store::Map;

/// The key where the latest consensus index is stored in the database.
// TODO: Make a single table (e.g., called `variables`) storing all our lonely variables in one place.
const LAST_CONSENSUS_STATS_ADDR: u64 = 0;
const OVERRIDE_PROTOCOL_UPGRADE_BUFFER_STAKE_INDEX: u64 = 0;
pub const EPOCH_DB_PREFIX: &str = "epoch_";

pub enum CancelConsensusCertificateReason {
    CongestionOnObjects(Vec<ObjectID>),
    DkgFailed,
}

pub enum ConsensusCertificateResult {
    /// The last checkpoint message of the epoch.
    /// After the Sui smart contract receives this message, it knows that no more system checkpoints will get created
    /// in this epoch, and it allows external calls to advance the epoch.
    ///
    /// This is a certificate result, so both the system & dwallet checkpointing mechanisms will create
    /// separate checkpoint messages, to update both the DWallet Coordinator & Ika System Sui objects.
    EndOfPublish,
    /// The consensus message was ignored (e.g. because it has already been processed).
    Ignored,
    /// Everything else, e.g. AuthorityCapabilities, CheckpointSignatures, etc.
    ConsensusMessage,
    /// A system message in consensus was ignored (e.g. because of end of epoch).
    IgnoredSystem,

    SystemTransaction(Vec<SystemCheckpointMessageKind>),
    // /// A will-be-cancelled transaction. It'll still go through execution engine (but not be executed),
    // /// unlock any owned objects, and return corresponding cancellation error according to
    // /// `CancelConsensusCertificateReason`.
    // Cancelled(
    //     (
    //         VerifiedExecutableTransaction,
    //         CancelConsensusCertificateReason,
    //     ),
    // ),
}

/// ConsensusStats is versioned because we may iterate on the struct, and it is
/// stored on disk.
#[enum_dispatch]
pub trait ConsensusStatsAPI {
    fn is_initialized(&self) -> bool;

    fn get_num_messages(&self, authority: usize) -> u64;
    fn inc_num_messages(&mut self, authority: usize) -> u64;

    fn get_num_user_transactions(&self, authority: usize) -> u64;
    fn inc_num_user_transactions(&mut self, authority: usize) -> u64;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[enum_dispatch(ConsensusStatsAPI)]
pub enum ConsensusStats {
    V1(ConsensusStatsV1),
}

impl ConsensusStats {
    pub fn new(size: usize) -> Self {
        Self::V1(ConsensusStatsV1 {
            num_messages: vec![0; size],
            num_user_transactions: vec![0; size],
        })
    }
}

impl Default for ConsensusStats {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConsensusStatsV1 {
    pub num_messages: Vec<u64>,
    pub num_user_transactions: Vec<u64>,
}

impl ConsensusStatsAPI for ConsensusStatsV1 {
    fn is_initialized(&self) -> bool {
        !self.num_messages.is_empty()
    }

    fn get_num_messages(&self, authority: usize) -> u64 {
        self.num_messages[authority]
    }

    fn inc_num_messages(&mut self, authority: usize) -> u64 {
        self.num_messages[authority] += 1;
        self.num_messages[authority]
    }

    fn get_num_user_transactions(&self, authority: usize) -> u64 {
        self.num_user_transactions[authority]
    }

    fn inc_num_user_transactions(&mut self, authority: usize) -> u64 {
        self.num_user_transactions[authority] += 1;
        self.num_user_transactions[authority]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Copy)]
pub struct ExecutionIndices {
    /// The round number of the last committed leader.
    pub last_committed_round: u64,
    /// The index of the last sub-DAG that was executed (either fully or partially).
    pub sub_dag_index: u64,
    /// The index of the last transaction was executed (used for crash-recovery).
    pub transaction_index: u64,
}

impl Ord for ExecutionIndices {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.last_committed_round,
            self.sub_dag_index,
            self.transaction_index,
        )
            .cmp(&(
                other.last_committed_round,
                other.sub_dag_index,
                other.transaction_index,
            ))
    }
}

impl PartialOrd for ExecutionIndices {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionIndicesWithStats {
    pub index: ExecutionIndices,
    // Hash is always 0 and kept for compatibility only.
    pub hash: u64,
    pub stats: ConsensusStats,
}

/// Trait for the AuthorityPerEpochStore, which gets recreated at the beginning of each epoch.
pub trait AuthorityPerEpochStoreTrait: Sync + Send + 'static {
    fn insert_pending_dwallet_checkpoint(
        &self,
        checkpoint: PendingDWalletCheckpoint,
    ) -> IkaResult<()>;

    fn last_dwallet_mpc_message_round(&self) -> IkaResult<Option<Round>>;

    fn next_dwallet_mpc_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCMessage>)>>;

    fn next_dwallet_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCOutput>)>>;

    fn next_dwallet_internal_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletInternalMPCOutput>)>>;

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>>;

    /// Inserts presigns into the pool for the given signature algorithm and network encryption key.
    fn insert_presigns(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()>;

    /// Returns the total number of presigns in the pool for the given signature algorithm
    /// and network encryption key.
    fn presign_pool_size(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<u64>;

    /// Pops a single presign from the pool for the given signature algorithm and network
    /// encryption key. Returns the session identifier and presign bytes, or None if the pool
    /// is empty.
    fn pop_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, Vec<u8>)>>;

    /// Returns the next internal sessions status update after the given consensus round.
    fn next_internal_sessions_status_update(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<InternalSessionsStatusUpdate>)>>;

    /// Marks a presign as used so it cannot be reused.
    fn mark_presign_as_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<()>;

    /// Checks if a presign has already been used.
    fn is_presign_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<bool>;

    /// Assigns a presign to a user by moving it from the internal pool to the assigned pool.
    /// This is used for external presign requests.
    fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<SessionIdentifier>>;

    /// Retrieves an assigned presign by session identifier and signature algorithm.
    fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>>;

    /// Pops an assigned presign from the pool. Used when the presign is consumed for signing.
    fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>>;

    /// Stores an MPC signature for a checkpoint.
    fn store_mpc_checkpoint_signature(
        &self,
        checkpoint_sequence_number: DWalletCheckpointSequenceNumber,
        signature: Vec<u8>,
    ) -> IkaResult<()>;

    /// Retrieves the MPC signature for a checkpoint, if it exists.
    fn get_mpc_checkpoint_signature(
        &self,
        checkpoint_sequence_number: DWalletCheckpointSequenceNumber,
    ) -> IkaResult<Option<Vec<u8>>>;
}

impl AuthorityPerEpochStoreTrait for AuthorityPerEpochStore {
    fn insert_pending_dwallet_checkpoint(
        &self,
        checkpoint: PendingDWalletCheckpoint,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        Ok(tables
            .pending_dwallet_checkpoints
            .insert(&checkpoint.height(), &checkpoint)?)
    }

    fn last_dwallet_mpc_message_round(&self) -> IkaResult<Option<Round>> {
        let tables = self.tables()?;
        Ok(tables
            .dwallet_mpc_messages
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(r, _)| r))
    }

    fn next_dwallet_mpc_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCMessage>)>> {
        let tables = self.tables()?;
        let mut iter = tables
            .dwallet_mpc_messages
            .safe_iter_with_bounds(last_consensus_round, None);
        if last_consensus_round.is_none() {
            Ok(iter.next().transpose()?)
        } else {
            Ok(iter.nth(1).transpose()?)
        }
    }

    fn next_dwallet_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletMPCOutput>)>> {
        let tables = self.tables()?;
        let mut iter = tables
            .dwallet_mpc_outputs
            .safe_iter_with_bounds(last_consensus_round, None);
        if last_consensus_round.is_none() {
            Ok(iter.next().transpose()?)
        } else {
            Ok(iter.nth(1).transpose()?)
        }
    }

    fn next_dwallet_internal_mpc_output(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletInternalMPCOutput>)>> {
        let tables = self.tables()?;
        let mut iter = tables
            .dwallet_internal_mpc_outputs
            .safe_iter_with_bounds(last_consensus_round, None);
        if last_consensus_round.is_none() {
            Ok(iter.next().transpose()?)
        } else {
            Ok(iter.nth(1).transpose()?)
        }
    }

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>> {
        let tables = self.tables()?;
        let mut iter = tables
            .verified_dwallet_checkpoint_messages
            .safe_iter_with_bounds(last_consensus_round, None);
        if last_consensus_round.is_none() {
            Ok(iter.next().transpose()?)
        } else {
            Ok(iter.nth(1).transpose()?)
        }
    }

    fn insert_presigns(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        tables.insert_presigns(
            signature_algorithm,
            dwallet_network_encryption_key_id,
            session_sequence_number,
            session_identifier,
            presigns,
        )
    }

    fn presign_pool_size(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<u64> {
        let tables = self.tables()?;
        tables.presign_pool_size(signature_algorithm, dwallet_network_encryption_key_id)
    }

    fn pop_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, Vec<u8>)>> {
        let tables = self.tables()?;
        tables.pop_presign(signature_algorithm, dwallet_network_encryption_key_id)
    }

    fn next_internal_sessions_status_update(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<InternalSessionsStatusUpdate>)>> {
        let tables = self.tables()?;
        let mut iter = tables
            .internal_sessions_status_updates
            .safe_iter_with_bounds(last_consensus_round, None);
        if last_consensus_round.is_none() {
            Ok(iter.next().transpose()?)
        } else {
            Ok(iter.nth(1).transpose()?)
        }
    }

    fn mark_presign_as_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<()> {
        let tables = self.tables()?;
        tables.mark_presign_as_used(presign_session_id)
    }

    fn is_presign_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<bool> {
        let tables = self.tables()?;
        tables.is_presign_used(presign_session_id)
    }

    fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<SessionIdentifier>> {
        let tables = self.tables()?;
        tables.assign_presign(
            signature_algorithm,
            dwallet_network_encryption_key_id,
            user_verification_key,
            dwallet_id,
            current_epoch,
        )
    }

    fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        let tables = self.tables()?;
        tables.get_assigned_presign(signature_algorithm, session_identifier)
    }

    fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        let tables = self.tables()?;
        tables.pop_assigned_presign(signature_algorithm, session_identifier)
    }

    fn store_mpc_checkpoint_signature(
        &self,
        checkpoint_sequence_number: DWalletCheckpointSequenceNumber,
        signature: Vec<u8>,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        Ok(tables
            .mpc_checkpoint_signatures
            .insert(&checkpoint_sequence_number, &signature)?)
    }

    fn get_mpc_checkpoint_signature(
        &self,
        checkpoint_sequence_number: DWalletCheckpointSequenceNumber,
    ) -> IkaResult<Option<Vec<u8>>> {
        let tables = self.tables()?;
        Ok(tables
            .mpc_checkpoint_signatures
            .get(&checkpoint_sequence_number)?)
    }
}

pub struct AuthorityPerEpochStore {
    /// The name of this authority.
    pub name: AuthorityName,

    /// Committee of validators for the current epoch.
    committee: Arc<Committee>,

    /// Holds the underlying per-epoch typed store tables.
    /// This is an ArcSwapOption because it needs to be used concurrently,
    /// and it needs to be cleared at the end of the epoch.
    tables: ArcSwapOption<AuthorityEpochTables>,

    protocol_config: ProtocolConfig,

    // needed for re-opening epoch db.
    parent_path: PathBuf,
    db_options: Option<Options>,

    consensus_notify_read: NotifyRead<SequencedConsensusTransactionKey, ()>,

    /// This is used to notify all epoch specific tasks that epoch has ended.
    epoch_alive_notify: NotifyOnce,

    /// Used to notify all epoch specific tasks that user certs are closed.
    user_certs_closed_notify: NotifyOnce,

    /// This lock acts as a barrier for tasks that should not be executed in parallel with reconfiguration
    /// See comments in AuthorityPerEpochStore::epoch_terminated() on how this is used
    /// Crash recovery note: we write next epoch in the database first, and then use this lock to
    /// wait for in-memory tasks for the epoch to finish. If node crashes at this stage validator
    /// will start with the new epoch(and will open instance of per-epoch store for a new epoch).
    epoch_alive: tokio::sync::RwLock<bool>,

    /// The moment when the current epoch started locally on this validator. Note that this
    /// value could be skewed if the node crashed and restarted in the middle of the epoch. That's
    /// ok because this is used for metric purposes and we could tolerate some skews occasionally.
    pub(crate) epoch_open_time: Instant,

    /// The moment when epoch is closed. We don't care much about crash recovery because it's
    /// a metric that doesn't have to be available for each epoch, and it's only used during
    /// the last few seconds of an epoch.
    epoch_close_time: RwLock<Option<Instant>>,
    pub(crate) metrics: Arc<EpochMetrics>,
    epoch_start_configuration: Arc<EpochStartConfiguration>,

    /// Chain identifier
    chain_identifier: ChainIdentifier,

    pub packages_config: IkaNetworkConfig,
    reconfig_state: RwLock<ReconfigState>,
    end_of_publish: Mutex<StakeAggregator<(), true>>,
}

/// The reconfiguration state of the authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconfigState {
    status: ReconfigCertStatus,
}

/// The possible reconfiguration states of the authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReconfigCertStatus {
    AcceptAllCerts,
    RejectAllTx,
}

/// AuthorityEpochTables contains tables that contain data that is only valid within an epoch.
#[derive(DBMapUtils)]
pub struct AuthorityEpochTables {
    /// Track which transactions have been processed in handle_consensus_transaction. We must be
    /// sure to advance next_shared_object_versions exactly once for each transaction we receive from
    /// consensus. But, we may also be processing transactions from checkpoints, so we need to
    /// track this state separately.
    ///
    /// Entries in this table can be garbage collected whenever we can prove that we won't receive
    /// another handle_consensus_transaction call for the given digest. This probably means at
    /// epoch change.
    consensus_message_processed: DBMap<SequencedConsensusTransactionKey, bool>,

    /// Map stores pending transactions that this authority submitted to consensus
    #[default_options_override_fn = "pending_consensus_transactions_table_default_config"]
    pending_consensus_transactions: DBMap<ConsensusTransactionKey, ConsensusTransaction>,

    /// The following table is used to store a single value (the corresponding key is a constant). The value
    /// represents the index of the latest consensus message this authority processed, running hash of
    /// transactions, and accumulated stats of consensus output.
    /// This field is written by a single process (consensus handler).
    last_consensus_stats: DBMap<u64, ExecutionIndicesWithStats>,

    /// This table has information for the checkpoints for which we constructed all the data
    /// from consensus, but not yet constructed actual checkpoint.
    ///
    /// Key in this table is the consensus commit height and not a checkpoint sequence number.
    ///
    /// Non-empty list of transactions here might result in empty list when we are forming checkpoint.
    /// Because we don't want to create checkpoints with empty content(see CheckpointBuilder::write_checkpoint),
    /// the sequence number of checkpoint does not match height here.
    #[default_options_override_fn = "pending_checkpoints_table_default_config"]
    pending_dwallet_checkpoints: DBMap<DWalletCheckpointHeight, PendingDWalletCheckpoint>,

    #[default_options_override_fn = "verified_dwallet_checkpoint_messages_table_default_config"]
    verified_dwallet_checkpoint_messages:
        DBMap<DWalletCheckpointHeight, Vec<DWalletCheckpointMessageKind>>,

    /// Stores pending signatures
    /// The key in this table is checkpoint sequence number and an arbitrary integer
    pub(crate) pending_dwallet_checkpoint_signatures:
        DBMap<(DWalletCheckpointSequenceNumber, u64), DWalletCheckpointSignatureMessage>,

    /// Maps sequence number to checkpoint summary, used by CheckpointBuilder to build checkpoint within epoch
    pub(crate) builder_dwallet_checkpoint_message_v1:
        DBMap<DWalletCheckpointSequenceNumber, BuilderDWalletCheckpointMessage>,

    #[default_options_override_fn = "pending_checkpoints_table_default_config"]
    pending_system_checkpoints: DBMap<SystemCheckpointHeight, PendingSystemCheckpoint>,

    /// Stores pending signatures
    /// The key in this table is ika system checkpoint sequence number and an arbitrary integer
    pub(crate) pending_system_checkpoint_signatures:
        DBMap<(DWalletCheckpointSequenceNumber, u64), SystemCheckpointSignatureMessage>,

    /// Maps sequence number to ika system checkpoint summary, used by SystemCheckpointBuilder to build checkpoint within epoch
    builder_system_checkpoint_v1: DBMap<DWalletCheckpointSequenceNumber, BuilderSystemCheckpoint>,

    /// Record of the capabilities advertised by each authority.
    authority_capabilities_v1: DBMap<AuthorityName, AuthorityCapabilitiesV1>,

    /// Validators that sent a EndOfPublish message in this epoch.
    end_of_publish: DBMap<AuthorityName, ()>,

    /// Contains a single key, which overrides the value of
    /// ProtocolConfig::buffer_stake_for_protocol_upgrade_bps
    override_protocol_upgrade_buffer_stake: DBMap<u64, u64>,

    /// Holds all the DWallet MPC related messages that have been
    /// received since the beginning of the epoch.
    /// The key is the consensus round number,
    /// the value is the dWallet-mpc messages that have been received in that
    /// round.
    #[default_options_override_fn = "dwallet_mpc_messages_table_default_config"]
    dwallet_mpc_messages: DBMap<Round, Vec<DWalletMPCMessage>>,
    /// Consensus round -> Output.
    #[default_options_override_fn = "dwallet_mpc_outputs_table_default_config"]
    dwallet_mpc_outputs: DBMap<Round, Vec<DWalletMPCOutput>>,
    /// Consensus round -> Output.
    #[default_options_override_fn = "dwallet_internal_mpc_outputs_table_default_config"]
    dwallet_internal_mpc_outputs: DBMap<Round, Vec<DWalletInternalMPCOutput>>,

    /// Internal presign pools, keyed by (network_encryption_key_id, session_sequence_number).
    /// Each entry contains presigns generated by that session, along with the session identifier.
    /// Presigns are consumed in order (lowest session sequence number first) within a given key ID.
    /// Value is (SessionIdentifier, Vec<presign_bytes>) - the session ID and list of presigns.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_ecdsa_secp256k1:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)>,
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_ecdsa_secp256r1:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)>,
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_eddsa: DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)>,
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_taproot: DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)>,
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_schnorrkel_substrate:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)>,

    /// Tracks the total count of presigns in each pool by (signature algorithm, network encryption key ID).
    /// Value is the count.
    internal_presign_pool_sizes: DBMap<(DWalletSignatureAlgorithm, ObjectID), u64>,

    /// Internal sessions status updates by consensus round.
    #[default_options_override_fn = "internal_sessions_status_updates_table_default_config"]
    internal_sessions_status_updates: DBMap<Round, Vec<InternalSessionsStatusUpdate>>,

    /// Tracks presigns that have been consumed for signing.
    /// Key: SessionIdentifier - the session ID of the presign session that created the presign
    /// Value: () - just marks it as used
    /// Once a presign is used, it should never be used again.
    used_presigns: DBMap<SessionIdentifier, ()>,

    /// Assigned presigns pools for external presigns.
    /// Key: SessionIdentifier - the session ID that uniquely identifies this assigned presign
    /// Value: AssignedPresign - contains presign data, user verification key, dwallet_id (for non-global), and epoch
    /// These expire at the end of the epoch and are used for external sign requests.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_ecdsa_secp256k1: DBMap<SessionIdentifier, AssignedPresign>,
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_ecdsa_secp256r1: DBMap<SessionIdentifier, AssignedPresign>,
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_eddsa: DBMap<SessionIdentifier, AssignedPresign>,
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_taproot: DBMap<SessionIdentifier, AssignedPresign>,
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_schnorrkel_substrate: DBMap<SessionIdentifier, AssignedPresign>,

    /// MPC signatures for checkpoints. Key is checkpoint sequence number, value is the MPC signature bytes.
    /// This table is populated when InternalSign MPC sessions complete and is read when relaying checkpoints.
    mpc_checkpoint_signatures: DBMap<DWalletCheckpointSequenceNumber, Vec<u8>>,
}

fn pending_consensus_transactions_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn verified_dwallet_checkpoint_messages_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn pending_checkpoints_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn dwallet_mpc_messages_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn dwallet_mpc_outputs_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn dwallet_internal_mpc_outputs_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn internal_presign_pool_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn internal_sessions_status_updates_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn assigned_presign_pool_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

impl AuthorityEpochTables {
    pub fn open(epoch: EpochId, parent_path: &Path, db_options: Option<Options>) -> Self {
        Self::open_tables_read_write(
            Self::path(epoch, parent_path),
            MetricConf::new("epoch"),
            db_options,
            None,
        )
    }

    pub fn open_readonly(epoch: EpochId, parent_path: &Path) -> AuthorityEpochTablesReadOnly {
        Self::get_read_only_handle(
            Self::path(epoch, parent_path),
            None,
            None,
            MetricConf::new("epoch_readonly"),
        )
    }

    pub fn path(epoch: EpochId, parent_path: &Path) -> PathBuf {
        parent_path.join(format!("{EPOCH_DB_PREFIX}{epoch}"))
    }

    pub fn get_all_pending_consensus_transactions(&self) -> IkaResult<Vec<ConsensusTransaction>> {
        Ok(self
            .pending_consensus_transactions
            .safe_iter()
            .map(|item| item.map(|(_k, v)| v))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_last_consensus_index(&self) -> IkaResult<Option<ExecutionIndices>> {
        Ok(self
            .last_consensus_stats
            .get(&LAST_CONSENSUS_STATS_ADDR)?
            .map(|s| s.index))
    }

    pub fn get_last_consensus_stats(&self) -> IkaResult<Option<ExecutionIndicesWithStats>> {
        Ok(self.last_consensus_stats.get(&LAST_CONSENSUS_STATS_ADDR)?)
    }

    /// Returns a reference to the presign pool table for the given signature algorithm.
    fn presign_pool_table(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> &DBMap<(ObjectID, u64), (SessionIdentifier, Vec<Vec<u8>>)> {
        match signature_algorithm {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                &self.internal_presign_pool_ecdsa_secp256k1
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                &self.internal_presign_pool_ecdsa_secp256r1
            }
            DWalletSignatureAlgorithm::EdDSA => &self.internal_presign_pool_eddsa,
            DWalletSignatureAlgorithm::Taproot => &self.internal_presign_pool_taproot,
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                &self.internal_presign_pool_schnorrkel_substrate
            }
        }
    }

    /// Inserts presigns into the pool for the given signature algorithm and network encryption key.
    /// The presigns are keyed by (network_encryption_key_id, session_sequence_number).
    pub fn insert_presigns(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()> {
        let num_presigns = presigns.len() as u64;
        let table = self.presign_pool_table(signature_algorithm);
        let key = (dwallet_network_encryption_key_id, session_sequence_number);
        table.insert(&key, &(session_identifier, presigns))?;

        // Update the size counter
        let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
        let current_size = self
            .internal_presign_pool_sizes
            .get(&size_key)?
            .unwrap_or(0);
        self.internal_presign_pool_sizes
            .insert(&size_key, &(current_size + num_presigns))?;

        Ok(())
    }

    /// Returns the total number of presigns in the pool for the given signature algorithm
    /// and network encryption key.
    pub fn presign_pool_size(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<u64> {
        let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
        Ok(self
            .internal_presign_pool_sizes
            .get(&size_key)?
            .unwrap_or(0))
    }

    /// Pops a single presign from the pool for the given signature algorithm and network
    /// encryption key. Returns the session identifier and presign bytes, or None if the pool
    /// is empty. Presigns are consumed in order of session sequence number (lowest first).
    pub fn pop_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, Vec<u8>)>> {
        let table = self.presign_pool_table(signature_algorithm);

        // Get the first entry for this network encryption key ID.
        // Use an inclusive range to constrain iteration to only entries for this key_id.
        let first_entry = table
            .safe_range_iter(
                (dwallet_network_encryption_key_id, 0u64)
                    ..=(dwallet_network_encryption_key_id, u64::MAX),
            )
            .next();

        let Some(entry_result) = first_entry else {
            return Ok(None);
        };

        let (key, (session_identifier, mut presigns)) = entry_result?;

        if presigns.is_empty() {
            // This shouldn't happen, but handle it gracefully
            table.remove(&key)?;
            return Ok(None);
        }

        // Remove the first presign from the vec
        let presign = presigns.remove(0);

        if presigns.is_empty() {
            // No more presigns for this session, remove the entry
            table.remove(&key)?;
        } else {
            // Update the entry with remaining presigns
            table.insert(&key, &(session_identifier, presigns))?;
        }

        // Decrement the size counter
        let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
        let current_size = self
            .internal_presign_pool_sizes
            .get(&size_key)?
            .unwrap_or(1);
        self.internal_presign_pool_sizes
            .insert(&size_key, &(current_size.saturating_sub(1)))?;

        Ok(Some((session_identifier, presign)))
    }

    /// Marks a presign as used so it cannot be reused.
    pub fn mark_presign_as_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<()> {
        self.used_presigns.insert(&presign_session_id, &())?;
        Ok(())
    }

    /// Checks if a presign has already been used.
    pub fn is_presign_used(&self, presign_session_id: SessionIdentifier) -> IkaResult<bool> {
        Ok(self.used_presigns.contains_key(&presign_session_id)?)
    }

    /// Returns a reference to the assigned presign pool table for the given signature algorithm.
    fn assigned_presign_pool_table(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> &DBMap<SessionIdentifier, AssignedPresign> {
        match signature_algorithm {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => &self.assigned_presigns_ecdsa_secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256r1 => &self.assigned_presigns_ecdsa_secp256r1,
            DWalletSignatureAlgorithm::EdDSA => &self.assigned_presigns_eddsa,
            DWalletSignatureAlgorithm::Taproot => &self.assigned_presigns_taproot,
            DWalletSignatureAlgorithm::SchnorrkelSubstrate => {
                &self.assigned_presigns_schnorrkel_substrate
            }
        }
    }

    /// Assigns a presign to a user by moving it from the internal pool to the assigned pool.
    /// This is used for external presign requests.
    pub fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<SessionIdentifier>> {
        // Pop a presign from the internal pool
        let Some((session_identifier, presign)) =
            self.pop_presign(signature_algorithm, dwallet_network_encryption_key_id)?
        else {
            return Ok(None);
        };

        // Create the assigned presign
        let assigned_presign = AssignedPresign {
            session_identifier,
            presign,
            user_verification_key,
            dwallet_id,
            assigned_epoch: current_epoch,
        };

        // Store it in the assigned pool
        let table = self.assigned_presign_pool_table(signature_algorithm);
        table.insert(&session_identifier, &assigned_presign)?;

        Ok(Some(session_identifier))
    }

    /// Retrieves an assigned presign by session identifier and signature algorithm.
    pub fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        let table = self.assigned_presign_pool_table(signature_algorithm);
        Ok(table.get(&session_identifier)?)
    }

    /// Pops an assigned presign from the pool. Used when the presign is consumed for signing.
    pub fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<AssignedPresign>> {
        let table = self.assigned_presign_pool_table(signature_algorithm);
        let assigned_presign = table.get(&session_identifier)?;
        if assigned_presign.is_some() {
            table.remove(&session_identifier)?;
        }
        Ok(assigned_presign)
    }
}

impl AuthorityPerEpochStore {
    fn should_accept_tx(&self) -> bool {
        let reconfig_state = self.reconfig_state.read();
        !matches!(&reconfig_state.status, &ReconfigCertStatus::RejectAllTx)
    }

    #[instrument(name = "AuthorityPerEpochStore::new", level = "error", skip_all, fields(epoch = committee.epoch))]
    pub fn new(
        name: AuthorityName,
        committee: Arc<Committee>,
        parent_path: &Path,
        db_options: Option<Options>,
        metrics: Arc<EpochMetrics>,
        epoch_start_configuration: EpochStartConfiguration,
        chain_identifier: ChainIdentifier,
        packages_config: IkaNetworkConfig,
    ) -> IkaResult<Arc<Self>> {
        let current_time = Instant::now();
        let epoch_id = committee.epoch;

        let tables = AuthorityEpochTables::open(epoch_id, parent_path, db_options.clone());

        let epoch_alive_notify = NotifyOnce::new();
        assert_eq!(
            epoch_start_configuration.epoch_start_state().epoch(),
            epoch_id
        );
        let epoch_start_configuration = Arc::new(epoch_start_configuration);
        metrics.current_epoch.set(epoch_id as i64);
        metrics
            .current_voting_right
            .set(committee.weight(&name) as i64);
        let protocol_version = epoch_start_configuration
            .epoch_start_state()
            .protocol_version();
        let protocol_config =
            ProtocolConfig::get_for_version(protocol_version, chain_identifier.chain());
        let end_of_publish =
            StakeAggregator::from_iter(committee.clone(), tables.end_of_publish.safe_iter())?;
        let s = Arc::new(Self {
            name,
            committee: committee.clone(),
            protocol_config,
            tables: ArcSwapOption::new(Some(Arc::new(tables))),
            parent_path: parent_path.to_path_buf(),
            db_options,
            epoch_alive_notify,
            user_certs_closed_notify: NotifyOnce::new(),
            epoch_alive: tokio::sync::RwLock::new(true),
            consensus_notify_read: NotifyRead::new(),
            epoch_open_time: current_time,
            epoch_close_time: Default::default(),
            metrics,
            epoch_start_configuration,
            chain_identifier,
            packages_config,
            reconfig_state: RwLock::new(ReconfigState {
                status: ReconfigCertStatus::AcceptAllCerts,
            }),
            end_of_publish: Mutex::new(end_of_publish),
        });

        s.update_buffer_stake_metric();
        Ok(s)
    }

    /// Convert a given authority name (address) to it's corresponding [`PartyID`].
    /// The [`PartyID`] is the index of the authority in the committee.
    pub fn authority_name_to_party_id(
        &self,
        authority_name: &AuthorityName,
    ) -> DwalletMPCResult<PartyID> {
        authority_name_to_party_id_from_committee(self.committee().as_ref(), authority_name)
    }

    pub fn get_weighted_threshold_access_structure(
        &self,
    ) -> DwalletMPCResult<WeightedThresholdAccessStructure> {
        generate_access_structure_from_committee(self.committee().as_ref())
    }

    pub fn tables(&self) -> IkaResult<Arc<AuthorityEpochTables>> {
        match self.tables.load_full() {
            Some(tables) => Ok(tables),
            None => Err(IkaError::EpochEnded(self.epoch())),
        }
    }

    // Ideally the epoch tables handle should have the same lifetime as the outer AuthorityPerEpochStore,
    // and this function should be unnecessary. But unfortunately, Arc<AuthorityPerEpochStore> outlives the
    // epoch significantly right now, so we need to manually release the tables to release its memory usage.
    pub fn release_db_handles(&self) {
        // When the logic to release DB handles becomes obsolete, it may still be useful
        // to make sure AuthorityEpochTables is not used after the next epoch starts.
        self.tables.store(None);
    }

    pub fn get_parent_path(&self) -> PathBuf {
        self.parent_path.clone()
    }

    /// Returns `&Arc<EpochStartConfiguration>`
    /// User can treat this `Arc` as `&EpochStartConfiguration`, or clone the Arc to pass as owned object
    pub fn epoch_start_config(&self) -> &Arc<EpochStartConfiguration> {
        &self.epoch_start_configuration
    }

    pub fn epoch_start_state(&self) -> &EpochStartSystem {
        self.epoch_start_configuration.epoch_start_state()
    }

    pub fn get_chain_identifier(&self) -> ChainIdentifier {
        self.chain_identifier
    }

    pub fn new_at_next_epoch(
        &self,
        name: AuthorityName,
        new_committee: Committee,
        epoch_start_configuration: EpochStartConfiguration,
        chain_identifier: ChainIdentifier,
    ) -> IkaResult<Arc<Self>> {
        assert_eq!(self.epoch() + 1, new_committee.epoch);
        self.record_reconfig_halt_duration_metric();
        self.record_epoch_total_duration_metric();
        Self::new(
            name,
            Arc::new(new_committee),
            &self.parent_path,
            self.db_options.clone(),
            self.metrics.clone(),
            epoch_start_configuration,
            chain_identifier,
            self.packages_config.clone(),
        )
    }

    pub fn new_at_next_epoch_for_testing(&self) -> IkaResult<Arc<Self>> {
        let next_epoch = self.epoch() + 1;
        let next_committee = Committee::new(
            next_epoch,
            self.committee.voting_rights.to_vec(),
            self.committee.class_groups_public_keys_and_proofs.clone(),
            self.committee.quorum_threshold,
            self.committee.validity_threshold,
        );
        self.new_at_next_epoch(
            self.name,
            next_committee,
            self.epoch_start_configuration
                .new_at_next_epoch_for_testing(),
            self.chain_identifier,
        )
    }

    pub fn committee(&self) -> &Arc<Committee> {
        &self.committee
    }

    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    pub fn epoch(&self) -> EpochId {
        self.committee.epoch
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.epoch_start_state().protocol_version()
    }

    pub fn get_last_consensus_stats(&self) -> IkaResult<ExecutionIndicesWithStats> {
        match self.tables()?.get_last_consensus_stats()? {
            Some(stats) => Ok(stats),
            None => {
                let indices = self
                    .tables()?
                    .get_last_consensus_index()
                    .map(|x| x.unwrap_or_default())?;
                Ok(ExecutionIndicesWithStats {
                    index: indices,
                    hash: 0, // unused
                    stats: ConsensusStats::default(),
                })
            }
        }
    }

    pub fn get_all_pending_consensus_transactions(&self) -> Vec<ConsensusTransaction> {
        // The except() here is on purpose, because the epoch can't run without it.
        self.tables()
            .expect("recovery should not cross epoch boundary")
            .get_all_pending_consensus_transactions()
            .expect("failed to get pending consensus transactions")
    }

    /// Returns true if all messages with the given keys were processed by consensus.
    pub fn all_external_consensus_messages_processed(
        &self,
        keys: impl Iterator<Item = ConsensusTransactionKey>,
    ) -> IkaResult<bool> {
        let keys = keys.map(SequencedConsensusTransactionKey::External);
        Ok(self
            .check_consensus_messages_processed(keys)?
            .into_iter()
            .all(|processed| processed))
    }

    pub fn is_consensus_message_processed(
        &self,
        key: &SequencedConsensusTransactionKey,
    ) -> IkaResult<bool> {
        Ok(self
            .tables()?
            .consensus_message_processed
            .contains_key(key)?)
    }

    pub fn check_consensus_messages_processed(
        &self,
        keys: impl Iterator<Item = SequencedConsensusTransactionKey>,
    ) -> IkaResult<Vec<bool>> {
        Ok(self
            .tables()?
            .consensus_message_processed
            .multi_contains_keys(keys)?)
    }

    pub async fn consensus_messages_processed_notify(
        &self,
        keys: Vec<SequencedConsensusTransactionKey>,
    ) -> Result<(), IkaError> {
        let registrations = self.consensus_notify_read.register_all(&keys);

        let unprocessed_keys_registrations = registrations
            .into_iter()
            .zip(self.check_consensus_messages_processed(keys.into_iter())?)
            .filter(|(_, processed)| !processed)
            .map(|(registration, _)| registration);

        join_all(unprocessed_keys_registrations).await;
        Ok(())
    }

    pub fn clear_override_protocol_upgrade_buffer_stake(&self) -> IkaResult {
        warn!(
            epoch = ?self.epoch(),
            "clearing buffer_stake_for_protocol_upgrade_bps override"
        );
        self.tables()?
            .override_protocol_upgrade_buffer_stake
            .remove(&OVERRIDE_PROTOCOL_UPGRADE_BUFFER_STAKE_INDEX)?;
        self.update_buffer_stake_metric();
        Ok(())
    }

    pub fn set_override_protocol_upgrade_buffer_stake(&self, new_stake_bps: u64) -> IkaResult {
        warn!(
            ?new_stake_bps,
            epoch = ?self.epoch(),
            "storing buffer_stake_for_protocol_upgrade_bps override"
        );
        self.tables()?
            .override_protocol_upgrade_buffer_stake
            .insert(
                &OVERRIDE_PROTOCOL_UPGRADE_BUFFER_STAKE_INDEX,
                &new_stake_bps,
            )?;
        self.update_buffer_stake_metric();
        Ok(())
    }

    fn update_buffer_stake_metric(&self) {
        self.metrics
            .effective_buffer_stake
            .set(self.get_effective_buffer_stake_bps() as i64);
    }

    pub fn get_effective_buffer_stake_bps(&self) -> u64 {
        self.tables()
            .expect("epoch initialization should have finished")
            .override_protocol_upgrade_buffer_stake
            .get(&OVERRIDE_PROTOCOL_UPGRADE_BUFFER_STAKE_INDEX)
            .expect("force_protocol_upgrade read cannot fail")
            .tap_some(|b| warn!("using overridden buffer stake value of {}", b))
            .unwrap_or_else(|| {
                self.protocol_config()
                    .buffer_stake_for_protocol_upgrade_bps()
            })
    }

    /// Record most recently advertised capabilities of all authorities
    pub fn record_capabilities_v1(&self, capabilities: &AuthorityCapabilitiesV1) -> IkaResult {
        info!(capabilities=?capabilities, "received capabilities v1");
        let authority = &capabilities.authority;
        let tables = self.tables()?;

        // Read-compare-write pattern assumes we are only called from the consensus handler task.
        if let Some(cap) = tables.authority_capabilities_v1.get(authority)?
            && cap.generation >= capabilities.generation
        {
            debug!(
                "ignoring new capabilities {:?} in favor of previous capabilities {:?}",
                capabilities, cap
            );
            return Ok(());
        }
        tables
            .authority_capabilities_v1
            .insert(authority, capabilities)?;
        Ok(())
    }

    pub fn get_capabilities_v1(&self) -> IkaResult<Vec<AuthorityCapabilitiesV1>> {
        Ok(self
            .tables()?
            .authority_capabilities_v1
            .safe_iter()
            .map(|item| item.map(|(_, v)| v))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn record_end_of_publish_vote(&self, origin_authority: &AuthorityName) -> IkaResult {
        self.tables()?
            .end_of_publish
            .insert(origin_authority, &())?;
        Ok(())
    }

    pub async fn user_certs_closed_notify(&self) {
        self.user_certs_closed_notify.wait().await
    }

    /// Notify epoch is terminated, can only be called once on epoch store
    pub async fn epoch_terminated(&self) {
        // Notify interested tasks that epoch has ended
        self.epoch_alive_notify
            .notify()
            .expect("epoch_terminated called twice on same epoch store");
        // This `write` acts as a barrier - it waits for futures executing in
        // `within_alive_epoch` to terminate before we can continue here
        debug!("Epoch terminated - waiting for pending tasks to complete");
        *self.epoch_alive.write().await = false;
        debug!("All pending epoch tasks completed");
    }

    /// Waits for the notification about epoch termination
    pub async fn wait_epoch_terminated(&self) {
        self.epoch_alive_notify.wait().await
    }

    /// This function executes given future until epoch_terminated is called
    /// If future finishes before epoch_terminated is called, future result is returned
    /// If epoch_terminated is called before future is resolved, error is returned
    ///
    /// In addition to the early termination guarantee, this function also prevents epoch_terminated()
    /// if future is being executed.
    #[allow(clippy::result_unit_err)]
    pub async fn within_alive_epoch<F: Future + Send>(&self, f: F) -> Result<F::Output, ()> {
        // This guard is kept in the future until it resolves, preventing `epoch_terminated` to
        // acquire a write lock
        let guard = self.epoch_alive.read().await;
        if !*guard {
            return Err(());
        }
        let terminated = self.wait_epoch_terminated().boxed();
        let f = f.boxed();
        match select(terminated, f).await {
            Either::Left((_, _f)) => Err(()),
            Either::Right((result, _)) => Ok(result),
        }
    }

    /// Verifies transaction signatures and other data
    /// Important: This function can potentially be called in parallel and you can not rely on order of transactions to perform verification
    /// If this function return an error, transaction is skipped and is not passed to handle_consensus_transaction
    /// This function returns unit error and is responsible for emitting log messages for internal errors
    fn verify_consensus_transaction(
        &self,
        transaction: SequencedConsensusTransaction,
        skipped_consensus_txns: &IntCounter,
    ) -> Option<VerifiedSequencedConsensusTransaction> {
        let _scope = monitored_scope("VerifyConsensusTransaction");
        if self
            .is_consensus_message_processed(&transaction.transaction.key())
            .expect("Storage error")
        {
            debug!(
                consensus_index=?transaction.consensus_index.transaction_index,
                tracking_id=?transaction.transaction.get_tracking_id(),
                "handle_consensus_transaction UserTransaction [skip]",
            );
            skipped_consensus_txns.inc();
            return None;
        }
        // Signatures are verified as part of the consensus payload verification in IkaTxValidator
        match &transaction.transaction {
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletMPCOutput(output),
                ..
            }) => {
                // When sending an MPC output, the validator also includes its public key.
                // Here, we verify that the public key used to sign this transaction matches
                // the provided public key.
                // This public key is later used to identify the authority that sent the MPC message.
                if transaction.sender_authority() != output.authority {
                    warn!(
                        "DWalletMPCOutput authority {} does not match its author from consensus {}",
                        output.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletInternalMPCOutput(output),
                ..
            }) => {
                // When sending an MPC output, the validator also includes its public key.
                // Here, we verify that the public key used to sign this transaction matches
                // the provided public key.
                // This public key is later used to identify the authority that sent the MPC message.
                if transaction.sender_authority() != output.authority {
                    warn!(
                        "DWalletInternalMPCOutput authority {} does not match its author from consensus {}",
                        output.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletMPCMessage(message),
                ..
            }) => {
                // When sending an MPC message, the validator also includes its public key.
                // Here, we verify that the public key used to sign this transaction matches
                // the provided public key.
                // This public key is later used
                // to identify the authority that sent the MPC message.
                if transaction.sender_authority() != message.authority {
                    warn!(
                        "DWalletMPCMessage authority {} does not match its author from consensus {}",
                        message.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update),
                ..
            }) => {
                if transaction.sender_authority() != status_update.authority {
                    warn!(
                        "InternalSessionsStatusUpdate authority {} does not match its author from consensus {}",
                        status_update.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletCheckpointSignature(data),
                ..
            }) => {
                if transaction.sender_authority() != data.checkpoint_message.auth_sig().authority {
                    warn!(
                        "CheckpointSignature authority {} does not match its author from consensus {}",
                        data.checkpoint_message.auth_sig().authority,
                        transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind:
                    ConsensusTransactionKind::CapabilityNotificationV1(AuthorityCapabilitiesV1 {
                        authority,
                        ..
                    }),
                ..
            }) => {
                if transaction.sender_authority() != *authority {
                    warn!(
                        "CapabilityNotification authority {} does not match its author from consensus {}",
                        authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::SystemCheckpointSignature(data),
                ..
            }) => {
                if transaction.sender_authority() != data.checkpoint_message.auth_sig().authority {
                    warn!(
                        "SystemCheckpoint authority {} does not match its author from consensus {}",
                        data.checkpoint_message.auth_sig().authority,
                        transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::EndOfPublish(authority),
                ..
            }) => {
                if &transaction.sender_authority() != authority {
                    warn!(
                        "EndOfPublish authority {} does not match its author from consensus {}",
                        authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
        }
        Some(VerifiedSequencedConsensusTransaction(transaction))
    }

    fn db_batch(&self) -> IkaResult<DBBatch> {
        Ok(self.tables()?.last_consensus_stats.batch())
    }

    #[cfg(test)]
    pub fn db_batch_for_test(&self) -> DBBatch {
        self.db_batch()
            .expect("test should not be write past end of epoch")
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn process_consensus_transactions_and_commit_boundary<
        'a,
        C: DWalletCheckpointServiceNotify,
    >(
        &self,
        transactions: Vec<SequencedConsensusTransaction>,
        consensus_stats: &ExecutionIndicesWithStats,
        checkpoint_service: &Arc<C>,
        system_checkpoint_service: &Arc<SystemCheckpointService>,
        consensus_commit_info: &ConsensusCommitInfo,
        authority_metrics: &Arc<AuthorityMetrics>,
    ) -> IkaResult<(
        Vec<DWalletCheckpointMessageKind>,
        Vec<SystemCheckpointMessageKind>,
    )> {
        let verified_transactions: Vec<_> = transactions
            .into_iter()
            .filter_map(|transaction| {
                self.verify_consensus_transaction(
                    transaction,
                    &authority_metrics.skipped_consensus_txns,
                )
            })
            .collect();

        let mut output = ConsensusCommitOutput::new(consensus_commit_info.round);

        let (
            verified_dwallet_checkpoint_messages,
            verified_system_checkpoint_messages,
            notifications,
        ) = self
            .process_consensus_transactions(
                &mut output,
                &verified_transactions,
                checkpoint_service,
                system_checkpoint_service,
                consensus_commit_info,
                //&mut roots,
                authority_metrics,
            )
            .await?;
        //self.finish_consensus_certificate_process_with_batch(&mut output, &verified_transactions)?;
        output.record_verified_dwallet_checkpoint_messages(
            verified_dwallet_checkpoint_messages.clone(),
        );
        output.record_consensus_commit_stats(consensus_stats.clone());
        // Create pending checkpoints if we are still accepting tx.
        let should_accept_tx = self.should_accept_tx();
        let final_round = verified_system_checkpoint_messages
            .iter()
            .last()
            .is_some_and(|msg| matches!(msg, SystemCheckpointMessageKind::EndOfPublish));
        let make_checkpoint = should_accept_tx || final_round;
        if make_checkpoint && !verified_system_checkpoint_messages.is_empty() {
            let checkpoint_height = consensus_commit_info.round;

            let pending_system_checkpoint =
                PendingSystemCheckpoint::V1(PendingSystemCheckpointV1 {
                    messages: verified_system_checkpoint_messages.clone(),
                    details: PendingSystemCheckpointInfo { checkpoint_height },
                });
            self.write_pending_system_checkpoint(&mut output, &pending_system_checkpoint)?;
        }

        let mut batch = self.db_batch()?;
        output.write_to_batch(self, &mut batch)?;
        batch.write()?;

        // Only after batch is written, notify checkpoint service to start building any new
        // pending checkpoints.
        if make_checkpoint && !verified_system_checkpoint_messages.is_empty() {
            debug!(
                ?consensus_commit_info.round,
                "Notifying system_checkpoint service about new pending checkpoint(s)",
            );
            system_checkpoint_service.notify_checkpoint()?;
        }

        self.process_notifications(&notifications);

        Ok((
            verified_dwallet_checkpoint_messages,
            verified_system_checkpoint_messages,
        ))
    }

    fn process_notifications(&self, notifications: &[SequencedConsensusTransactionKey]) {
        for key in notifications {
            self.consensus_notify_read.notify(key, &());
        }
    }

    /// Depending on the type of the VerifiedSequencedConsensusTransaction wrappers,
    /// - Verify and initialize the state to execute the certificates.
    ///   Return VerifiedCertificates for each executable certificate
    /// - Or update the state for checkpoint or epoch change protocol.
    #[instrument(level = "debug", skip_all)]
    #[allow(clippy::type_complexity)]
    pub(crate) async fn process_consensus_transactions<C: DWalletCheckpointServiceNotify>(
        &self,
        output: &mut ConsensusCommitOutput,
        transactions: &[VerifiedSequencedConsensusTransaction],
        checkpoint_service: &Arc<C>,
        system_checkpoint_service: &Arc<SystemCheckpointService>,
        consensus_commit_info: &ConsensusCommitInfo,
        //roots: &mut BTreeSet<MessageDigest>,
        authority_metrics: &Arc<AuthorityMetrics>,
    ) -> IkaResult<(
        Vec<DWalletCheckpointMessageKind>, // transactions to schedule
        Vec<SystemCheckpointMessageKind>,
        Vec<SequencedConsensusTransactionKey>, // keys to notify as complete
    )> {
        let _scope = monitored_scope("ConsensusCommitHandler::process_consensus_transactions");

        let mut verified_dwallet_checkpoint_certificates =
            VecDeque::with_capacity(transactions.len() + 1);
        let mut verified_system_checkpoint_certificates =
            VecDeque::with_capacity(transactions.len() + 1);
        let mut notifications = Vec::with_capacity(transactions.len());

        let cancelled_txns: BTreeMap<MessageDigest, CancelConsensusCertificateReason> =
            BTreeMap::new();

        for tx in transactions {
            let key = tx.0.transaction.key();
            let mut ignored = false;
            // let mut filter_roots = false;
            match self
                .process_consensus_transaction(
                    output,
                    tx,
                    checkpoint_service,
                    system_checkpoint_service,
                    consensus_commit_info.round,
                    authority_metrics,
                )
                .await?
            {
                ConsensusCertificateResult::SystemTransaction(certs) => {
                    notifications.push(key.clone());
                    verified_system_checkpoint_certificates.extend(certs);
                }
                // ConsensusCertificateResult::Cancelled((cert, reason)) => {
                //     notifications.push(key.clone());
                //     assert!(cancelled_txns.insert(*cert.digest(), reason).is_none());
                //     verified_certificates.push_back(cert);
                // }
                ConsensusCertificateResult::ConsensusMessage => notifications.push(key.clone()),
                ConsensusCertificateResult::IgnoredSystem => {
                    // filter_roots = true;
                }
                // Note: ignored external transactions must not be recorded as processed. Otherwise
                // they may not get reverted after restart during epoch change.
                ConsensusCertificateResult::Ignored => {
                    ignored = true;
                    // filter_roots = true;
                }
                ConsensusCertificateResult::EndOfPublish => {
                    let capabilities = self.get_capabilities_v1()?;
                    let AuthorityCapabilitiesVotingResults {
                        protocol_version: new_version,
                        move_contracts_to_upgrade
                    } = AuthorityState::choose_highest_protocol_version_and_move_contracts_upgrades_v1(
                        self.protocol_version(),
                        self.committee(),
                        capabilities.clone(),
                        self.get_effective_buffer_stake_bps(),
                    );

                    let mut system_transactions: Vec<SystemCheckpointMessageKind> = Vec::new();
                    let current_protocol_version = self.protocol_version();
                    if self.protocol_version() != new_version {
                        info!(
                            validator=?self.name,
                            ?current_protocol_version,
                            new_protocol_version=?new_version,
                            "New protocol version reached quorum from capabilities v1",
                        );
                        system_transactions.push(
                            SystemCheckpointMessageKind::SetNextConfigVersion(new_version),
                        );
                        if new_version.as_u64() == 2
                            && self.chain_identifier.chain() == Chain::Testnet
                        {
                            system_transactions.push(
                                SystemCheckpointMessageKind::SetMinValidatorJoiningStake(
                                    40_000_000 * 1_000_000_000,
                                ),
                            );
                            system_transactions
                                .push(SystemCheckpointMessageKind::SetStakeSubsidyRate(200));
                        }
                    }

                    if !move_contracts_to_upgrade.is_empty() {
                        info!(
                            validator=?self.name,
                            ?current_protocol_version,
                            ?move_contracts_to_upgrade,
                            "New move contracts upgrade reached quorum from capabilities v1",
                        );
                        for (package_id, digest) in move_contracts_to_upgrade.iter() {
                            system_transactions.push(
                                SystemCheckpointMessageKind::SetApprovedUpgrade {
                                    package_id: package_id.to_vec(),
                                    digest: Some(digest.to_vec()),
                                },
                            );
                        }
                    }
                    verified_system_checkpoint_certificates.extend(system_transactions);
                    verified_dwallet_checkpoint_certificates
                        .push_back(DWalletCheckpointMessageKind::EndOfPublish);
                    verified_system_checkpoint_certificates
                        .push_back(SystemCheckpointMessageKind::EndOfPublish);
                    let mut reconfig_state = self.reconfig_state.write();
                    reconfig_state.status = ReconfigCertStatus::RejectAllTx;
                    break;
                }
            }
            if !ignored {
                output.record_consensus_message_processed(key.clone());
            }
        }
        // Save all the dWallet-MPC related DB data to the consensus commit output to
        // write it to the local DB. After saving the data, clear the data from the epoch store.
        let new_dwallet_mpc_round_messages = Self::filter_dwallet_mpc_messages(transactions);
        output.set_dwallet_mpc_round_messages(new_dwallet_mpc_round_messages);
        output.set_dwallet_mpc_round_outputs(Self::filter_dwallet_mpc_outputs(transactions));
        output.set_dwallet_internal_mpc_round_outputs(Self::filter_dwallet_internal_mpc_outputs(
            transactions,
        ));
        output.set_internal_sessions_status_updates(Self::filter_internal_sessions_status_updates(
            transactions,
        ));

        authority_metrics
            .consensus_handler_cancelled_transactions
            .inc_by(cancelled_txns.len() as u64);

        let verified_certificates: Vec<_> = verified_dwallet_checkpoint_certificates.into();

        Ok((
            verified_certificates,
            verified_system_checkpoint_certificates.into(),
            notifications,
        ))
    }

    /// Filter DWalletMPCMessages from the consensus output.
    /// Those messages will get processed when the dWallet MPC service reads
    /// them from the DB.
    fn filter_dwallet_mpc_messages(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<DWalletMPCMessage> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::DWalletMPCMessage(message),
                        ..
                    }) => Some(message.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    /// Filter DWalletMPCMessages from the consensus output.
    /// Those messages will get processed when the dWallet MPC service reads
    /// them from the DB.
    fn filter_dwallet_mpc_outputs(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<DWalletMPCOutput> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::DWalletMPCOutput(output),
                        ..
                    }) => Some(output.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    /// Filter DWalletMPCMessages from the consensus output.
    /// Those messages will get processed when the dWallet MPC service reads
    /// them from the DB.
    fn filter_dwallet_internal_mpc_outputs(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<DWalletInternalMPCOutput> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::DWalletInternalMPCOutput(output),
                        ..
                    }) => Some(output.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    fn filter_internal_sessions_status_updates(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<InternalSessionsStatusUpdate> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::InternalSessionsStatusUpdate(status_update),
                        ..
                    }) => Some(status_update.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    #[instrument(level = "trace", skip_all)]
    async fn process_consensus_transaction<C: DWalletCheckpointServiceNotify>(
        &self,
        _output: &mut ConsensusCommitOutput,
        transaction: &VerifiedSequencedConsensusTransaction,
        checkpoint_service: &Arc<C>,
        system_checkpoint_service: &Arc<SystemCheckpointService>, // should i do this generic as the checkpoint service?
        _commit_round: Round,
        _authority_metrics: &Arc<AuthorityMetrics>,
    ) -> IkaResult<ConsensusCertificateResult> {
        let _scope = monitored_scope("ConsensusCommitHandler::process_consensus_transaction");

        let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
            certificate_author_index: _,
            certificate_author: _certificate_author,
            consensus_index: _consensus_index,
            transaction,
        }) = transaction;
        let _tracking_id = transaction.get_tracking_id();

        match &transaction {
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletMPCOutput(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletInternalMPCOutput(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletMPCMessage(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::InternalSessionsStatusUpdate(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletCheckpointSignature(info),
                ..
            }) => {
                // We usually call notify_checkpoint_signature in IkaTxValidator, but that step can
                // be skipped when a batch is already part of a certificate, so we must also
                // notify here.
                checkpoint_service.notify_checkpoint_signature(self, info)?;
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::CapabilityNotificationV1(authority_capabilities),
                ..
            }) => {
                let authority = authority_capabilities.authority;
                debug!(
                    from_authority=?authority,
                    "Received CapabilityNotificationV1",
                );
                self.record_capabilities_v1(authority_capabilities)?;

                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::SystemCheckpointSignature(data),
                ..
            }) => {
                system_checkpoint_service.notify_checkpoint_signature(self, data)?;
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::EndOfPublish(authority),
                ..
            }) => {
                self.record_end_of_publish_vote(authority)?;
                let mut end_of_publish = self.end_of_publish.lock();
                // Note that we don't check here that the sender didn't already vote,
                // but that would be OK for two reasons:
                // The first, its transaction would be denied because its key is the same
                // (so the second wouldn't reach this flow).
                // The second, the stake aggregator is implemented by a HashMap,
                // and duplicate votes cannot be registered.
                if !end_of_publish.has_quorum()
                    && end_of_publish
                        .insert_generic(*authority, ())
                        .is_quorum_reached()
                {
                    return Ok(ConsensusCertificateResult::EndOfPublish);
                }
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
        }
    }

    pub fn get_pending_dwallet_checkpoints(
        &self,
        last: Option<DWalletCheckpointHeight>,
    ) -> IkaResult<Vec<(DWalletCheckpointHeight, PendingDWalletCheckpoint)>> {
        let tables = self.tables()?;
        let db_iter = tables
            .pending_dwallet_checkpoints
            .safe_iter_with_bounds(last.map(|height| height + 1), None);
        Ok(db_iter.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_pending_checkpoint(
        &self,
        index: &DWalletCheckpointHeight,
    ) -> IkaResult<Option<PendingDWalletCheckpoint>> {
        Ok(self.tables()?.pending_dwallet_checkpoints.get(index)?)
    }

    pub fn process_pending_dwallet_checkpoint(
        &self,
        commit_height: DWalletCheckpointHeight,
        checkpoint_messages: Vec<DWalletCheckpointMessage>,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        // All created checkpoints are inserted in builder_checkpoint_summary in a single batch.
        // This means that upon restart we can use BuilderCheckpointSummary::commit_height
        // from the last built summary to resume building checkpoints.
        let mut batch = tables.pending_dwallet_checkpoints.batch();
        for (position_in_commit, summary) in checkpoint_messages.into_iter().enumerate() {
            let sequence_number = summary.sequence_number;
            let summary = BuilderDWalletCheckpointMessage {
                checkpoint_message: summary,
                checkpoint_height: Some(commit_height),
                position_in_commit,
            };
            batch.insert_batch(
                &tables.builder_dwallet_checkpoint_message_v1,
                [(&sequence_number, summary)],
            )?;
        }

        // find all pending checkpoints <= commit_height and remove them
        let iter = tables
            .pending_dwallet_checkpoints
            .safe_range_iter(0..=commit_height);
        let keys = iter
            .map(|c| c.map(|(h, _)| h))
            .collect::<Result<Vec<_>, _>>()?;

        batch.delete_batch(&tables.pending_dwallet_checkpoints, &keys)?;

        Ok(batch.write()?)
    }

    pub fn last_built_dwallet_checkpoint_message_builder(
        &self,
    ) -> IkaResult<Option<BuilderDWalletCheckpointMessage>> {
        Ok(self
            .tables()?
            .builder_dwallet_checkpoint_message_v1
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, s)| s))
    }

    pub fn last_built_dwallet_checkpoint_message(
        &self,
    ) -> IkaResult<Option<(DWalletCheckpointSequenceNumber, DWalletCheckpointMessage)>> {
        Ok(self
            .tables()?
            .builder_dwallet_checkpoint_message_v1
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(seq, s)| (seq, s.checkpoint_message)))
    }

    pub fn get_built_dwallet_checkpoint_message(
        &self,
        sequence: DWalletCheckpointSequenceNumber,
    ) -> IkaResult<Option<DWalletCheckpointMessage>> {
        Ok(self
            .tables()?
            .builder_dwallet_checkpoint_message_v1
            .get(&sequence)?
            .map(|s| s.checkpoint_message))
    }

    pub fn get_last_dwallet_checkpoint_signature_index(&self) -> IkaResult<u64> {
        Ok(self
            .tables()?
            .pending_dwallet_checkpoint_signatures
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|((_, index), _)| index)
            .unwrap_or(1))
    }

    pub fn insert_checkpoint_signature(
        &self,
        checkpoint_seq: DWalletCheckpointSequenceNumber,
        index: u64,
        info: &DWalletCheckpointSignatureMessage,
    ) -> IkaResult<()> {
        Ok(self
            .tables()?
            .pending_dwallet_checkpoint_signatures
            .insert(&(checkpoint_seq, index), info)?)
    }

    pub(crate) fn write_pending_system_checkpoint(
        &self,
        output: &mut ConsensusCommitOutput,
        system_checkpoint: &PendingSystemCheckpoint,
    ) -> IkaResult {
        assert!(
            self.get_pending_system_checkpoint(&system_checkpoint.height())?
                .is_none(),
            "Duplicate pending system_checkpoint notification at height {:?}",
            system_checkpoint.height()
        );

        debug!(
            system_checkpoint_commit_height = system_checkpoint.height(),
            "Pending system_checkpoint has {} messages",
            system_checkpoint.messages().len(),
        );
        trace!(
            system_checkpoint_commit_height = system_checkpoint.height(),
            "Messages for pending system_checkpoint: {:?}",
            system_checkpoint.messages()
        );

        output.insert_pending_system_checkpoint(system_checkpoint.clone());

        Ok(())
    }

    pub fn get_pending_system_checkpoints(
        &self,
        last: Option<SystemCheckpointHeight>,
    ) -> IkaResult<Vec<(SystemCheckpointHeight, PendingSystemCheckpoint)>> {
        let tables = self.tables()?;
        let db_iter = tables
            .pending_system_checkpoints
            .safe_iter_with_bounds(last.map(|height| height + 1), None);
        Ok(db_iter.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_pending_system_checkpoint(
        &self,
        index: &SystemCheckpointHeight,
    ) -> IkaResult<Option<PendingSystemCheckpoint>> {
        Ok(self.tables()?.pending_system_checkpoints.get(index)?)
    }

    pub fn process_pending_system_checkpoint(
        &self,
        commit_height: SystemCheckpointHeight,
        system_checkpoint_messages: Vec<SystemCheckpointMessage>,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        // All created system_checkpoints are inserted in builder_system_checkpoint_summary in a single batch.
        // This means that upon restart we can use BuilderSystemCheckpointSummary::commit_height
        // from the last built summary to resume building system_checkpoints.
        let mut batch = tables.pending_system_checkpoints.batch();
        for (position_in_commit, summary) in system_checkpoint_messages.into_iter().enumerate() {
            let sequence_number = summary.sequence_number;
            let summary = BuilderSystemCheckpoint {
                checkpoint_message: summary,
                checkpoint_height: Some(commit_height),
                position_in_commit,
            };
            batch.insert_batch(
                &tables.builder_system_checkpoint_v1,
                [(&sequence_number, summary)],
            )?;
        }

        // find all pending system_checkpoints <= commit_height and remove them
        let iter = tables
            .pending_system_checkpoints
            .safe_range_iter(0..=commit_height);
        let keys = iter
            .map(|c| c.map(|(h, _)| h))
            .collect::<Result<Vec<_>, _>>()?;

        batch.delete_batch(&tables.pending_system_checkpoints, &keys)?;

        Ok(batch.write()?)
    }

    pub fn last_built_system_checkpoint_message_builder(
        &self,
    ) -> IkaResult<Option<BuilderSystemCheckpoint>> {
        Ok(self
            .tables()?
            .builder_system_checkpoint_v1
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, s)| s))
    }

    pub fn last_built_system_checkpoint_message(
        &self,
    ) -> IkaResult<Option<(SystemCheckpointSequenceNumber, SystemCheckpointMessage)>> {
        Ok(self
            .tables()?
            .builder_system_checkpoint_v1
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(seq, s)| (seq, s.checkpoint_message)))
    }

    pub fn get_built_system_checkpoint_message(
        &self,
        sequence: SystemCheckpointSequenceNumber,
    ) -> IkaResult<Option<SystemCheckpointMessage>> {
        Ok(self
            .tables()?
            .builder_system_checkpoint_v1
            .get(&sequence)?
            .map(|s| s.checkpoint_message))
    }

    pub fn get_last_system_checkpoint_signature_index(&self) -> IkaResult<u64> {
        Ok(self
            .tables()?
            .pending_system_checkpoint_signatures
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|((_, index), _)| index)
            .unwrap_or(1))
    }

    pub fn insert_system_checkpoint_signature(
        &self,
        system_checkpoint_seq: SystemCheckpointSequenceNumber,
        index: u64,
        info: &SystemCheckpointSignatureMessage,
    ) -> IkaResult<()> {
        Ok(self
            .tables()?
            .pending_system_checkpoint_signatures
            .insert(&(system_checkpoint_seq, index), info)?)
    }

    pub fn record_epoch_reconfig_start_time_metric(&self) {
        if let Some(epoch_close_time) = *self.epoch_close_time.read() {
            self.metrics
                .epoch_reconfig_start_time_since_epoch_close_ms
                .set(epoch_close_time.elapsed().as_millis() as i64);
        }
    }

    fn record_reconfig_halt_duration_metric(&self) {
        if let Some(epoch_close_time) = *self.epoch_close_time.read() {
            self.metrics
                .epoch_validator_halt_duration_ms
                .set(epoch_close_time.elapsed().as_millis() as i64);
        }
    }

    pub(crate) fn record_epoch_first_checkpoint_creation_time_metric(&self) {
        self.metrics
            .epoch_first_checkpoint_created_time_since_epoch_begin_ms
            .set(self.epoch_open_time.elapsed().as_millis() as i64);
    }

    pub(crate) fn record_epoch_first_system_checkpoint_creation_time_metric(&self) {
        self.metrics
            .epoch_first_system_checkpoint_created_time_since_epoch_begin_ms
            .set(self.epoch_open_time.elapsed().as_millis() as i64);
    }

    fn record_epoch_total_duration_metric(&self) {
        self.metrics.current_epoch.set(self.epoch() as i64);
        self.metrics
            .epoch_total_duration
            .set(self.epoch_open_time.elapsed().as_millis() as i64);
    }
}

#[derive(Default)]
pub(crate) struct ConsensusCommitOutput {
    // Consensus and reconfig state
    consensus_round: Round,
    consensus_messages_processed: BTreeSet<SequencedConsensusTransactionKey>,
    consensus_commit_stats: Option<ExecutionIndicesWithStats>,

    pending_system_checkpoints: Vec<PendingSystemCheckpoint>,

    /// All the dWallet-MPC related TXs that have been received in this round.
    dwallet_mpc_round_messages: Vec<DWalletMPCMessage>,
    dwallet_mpc_round_outputs: Vec<DWalletMPCOutput>,
    dwallet_internal_mpc_round_outputs: Vec<DWalletInternalMPCOutput>,
    internal_sessions_status_updates: Vec<InternalSessionsStatusUpdate>,

    verified_dwallet_checkpoint_messages: Vec<DWalletCheckpointMessageKind>,
}

impl ConsensusCommitOutput {
    pub fn new(consensus_round: Round) -> Self {
        Self {
            consensus_round,
            ..Default::default()
        }
    }

    pub(crate) fn set_dwallet_mpc_round_messages(&mut self, new_value: Vec<DWalletMPCMessage>) {
        self.dwallet_mpc_round_messages = new_value;
    }

    pub(crate) fn set_dwallet_mpc_round_outputs(&mut self, new_value: Vec<DWalletMPCOutput>) {
        self.dwallet_mpc_round_outputs = new_value;
    }

    pub(crate) fn set_dwallet_internal_mpc_round_outputs(
        &mut self,
        new_value: Vec<DWalletInternalMPCOutput>,
    ) {
        self.dwallet_internal_mpc_round_outputs = new_value;
    }

    pub(crate) fn set_internal_sessions_status_updates(
        &mut self,
        new_value: Vec<InternalSessionsStatusUpdate>,
    ) {
        self.internal_sessions_status_updates = new_value;
    }

    fn record_verified_dwallet_checkpoint_messages(
        &mut self,
        verified_dwallet_checkpoint_messages: Vec<DWalletCheckpointMessageKind>,
    ) {
        self.verified_dwallet_checkpoint_messages = verified_dwallet_checkpoint_messages;
    }

    fn record_consensus_commit_stats(&mut self, stats: ExecutionIndicesWithStats) {
        self.consensus_commit_stats = Some(stats);
    }

    fn record_consensus_message_processed(&mut self, key: SequencedConsensusTransactionKey) {
        self.consensus_messages_processed.insert(key);
    }

    fn insert_pending_system_checkpoint(&mut self, checkpoint: PendingSystemCheckpoint) {
        self.pending_system_checkpoints.push(checkpoint);
    }

    /// This function writes a batch of consensus commit outputs,
    /// which includes the MPC messages, outputs and verified checkpoint messages.
    ///
    /// We depend upon this batch writing logic, in `last_dwallet_mpc_message_round()` which should be the same for the outputs and verified checkpoint messages as well.
    pub fn write_to_batch(
        self,
        epoch_store: &AuthorityPerEpochStore,
        batch: &mut DBBatch,
    ) -> IkaResult {
        let tables = epoch_store.tables()?;

        // Write all the dWallet MPC related messages from this consensus round to the local DB.
        // The [`DWalletMPCService`] constantly reads and process those messages.
        batch.insert_batch(
            &tables.dwallet_mpc_messages,
            [(self.consensus_round, self.dwallet_mpc_round_messages)],
        )?;
        batch.insert_batch(
            &tables.dwallet_mpc_outputs,
            [(self.consensus_round, self.dwallet_mpc_round_outputs)],
        )?;
        batch.insert_batch(
            &tables.dwallet_internal_mpc_outputs,
            [(
                self.consensus_round,
                self.dwallet_internal_mpc_round_outputs,
            )],
        )?;
        batch.insert_batch(
            &tables.internal_sessions_status_updates,
            [(self.consensus_round, self.internal_sessions_status_updates)],
        )?;
        batch.insert_batch(
            &tables.verified_dwallet_checkpoint_messages,
            [(
                self.consensus_round,
                self.verified_dwallet_checkpoint_messages,
            )],
        )?;

        batch.insert_batch(
            &tables.consensus_message_processed,
            self.consensus_messages_processed
                .iter()
                .map(|key| (key, true)),
        )?;

        if let Some(consensus_commit_stats) = &self.consensus_commit_stats {
            batch.insert_batch(
                &tables.last_consensus_stats,
                [(LAST_CONSENSUS_STATS_ADDR, consensus_commit_stats)],
            )?;
        }

        batch.insert_batch(
            &tables.pending_system_checkpoints,
            self.pending_system_checkpoints
                .into_iter()
                .map(|cp| (cp.height(), cp)),
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockDetailsWrapper {
    V1(MessageDigest),
}

impl LockDetailsWrapper {
    pub fn migrate(self) -> Self {
        // TODO: when there are multiple versions, we must iteratively migrate from version N to
        // N+1 until we arrive at the latest version
        self
    }

    // Always returns the most recent version. Older versions are migrated to the latest version at
    // read time, so there is never a need to access older versions.
    pub fn inner(&self) -> &LockDetails {
        match self {
            Self::V1(v1) => v1,

            // can remove #[allow] when there are multiple versions
            #[allow(unreachable_patterns)]
            _ => panic!("lock details should have been migrated to latest version at read time"),
        }
    }
    pub fn into_inner(self) -> LockDetails {
        match self {
            Self::V1(v1) => v1,

            // can remove #[allow] when there are multiple versions
            #[allow(unreachable_patterns)]
            _ => panic!("lock details should have been migrated to latest version at read time"),
        }
    }
}

pub type LockDetails = MessageDigest;

impl From<LockDetails> for LockDetailsWrapper {
    fn from(details: LockDetails) -> Self {
        // always use latest version.
        LockDetailsWrapper::V1(details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
    use sui_types::base_types::ObjectID;

    fn create_tables() -> AuthorityEpochTables {
        let dir = tempfile::tempdir().unwrap();
        AuthorityEpochTables::open(0, dir.path(), None)
    }

    fn make_session_id(preimage: [u8; 32]) -> SessionIdentifier {
        SessionIdentifier::new(SessionType::InternalPresign, preimage)
    }

    #[test]
    fn test_insert_and_pop_presign() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let session_id = make_session_id([1; 32]);
        let presigns = vec![vec![1u8, 2, 3], vec![4, 5, 6]];

        tables
            .insert_presigns(algorithm, key_id, 0, session_id, presigns)
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 2);

        let (popped_session, first_presign) =
            tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(popped_session, session_id);
        assert_eq!(first_presign, vec![1u8, 2, 3]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 1);

        let (_, second_presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(second_presign, vec![4u8, 5, 6]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);

        assert!(tables.pop_presign(algorithm, key_id).unwrap().is_none());
    }

    #[test]
    fn test_presign_pool_isolation_across_key_ids() {
        let tables = create_tables();
        let key_id_a = ObjectID::random();
        let key_id_b = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let session_id_a = make_session_id([10; 32]);
        let session_id_b = make_session_id([20; 32]);
        let presigns_a = vec![vec![10u8], vec![11]];
        let presigns_b = vec![vec![20u8], vec![21], vec![22]];

        tables
            .insert_presigns(algorithm, key_id_a, 0, session_id_a, presigns_a)
            .unwrap();
        tables
            .insert_presigns(algorithm, key_id_b, 0, session_id_b, presigns_b)
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id_a).unwrap(), 2);
        assert_eq!(tables.presign_pool_size(algorithm, key_id_b).unwrap(), 3);

        let (popped_session, presign) = tables.pop_presign(algorithm, key_id_a).unwrap().unwrap();
        assert_eq!(popped_session, session_id_a);
        assert_eq!(presign, vec![10u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id_a).unwrap(), 1);
        assert_eq!(tables.presign_pool_size(algorithm, key_id_b).unwrap(), 3);

        let (popped_session, presign) = tables.pop_presign(algorithm, key_id_b).unwrap().unwrap();
        assert_eq!(popped_session, session_id_b);
        assert_eq!(presign, vec![20u8]);

        // Exhaust key_id_a
        tables.pop_presign(algorithm, key_id_a).unwrap().unwrap();
        assert!(tables.pop_presign(algorithm, key_id_a).unwrap().is_none());
        assert_eq!(tables.presign_pool_size(algorithm, key_id_a).unwrap(), 0);

        // key_id_b still has presigns
        assert_eq!(tables.presign_pool_size(algorithm, key_id_b).unwrap(), 2);
        let (_, presign) = tables.pop_presign(algorithm, key_id_b).unwrap().unwrap();
        assert_eq!(presign, vec![21u8]);
    }

    #[test]
    fn test_pop_presign_ordering_across_sessions() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;

        // Insert out of order by session_sequence_number
        tables
            .insert_presigns(
                algorithm,
                key_id,
                10,
                make_session_id([10; 32]),
                vec![vec![10u8]],
            )
            .unwrap();
        tables
            .insert_presigns(
                algorithm,
                key_id,
                5,
                make_session_id([5; 32]),
                vec![vec![5u8]],
            )
            .unwrap();
        tables
            .insert_presigns(
                algorithm,
                key_id,
                20,
                make_session_id([20; 32]),
                vec![vec![20u8]],
            )
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 3);

        // Should pop in ascending session_sequence_number order
        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![5u8]);

        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![10u8]);

        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![20u8]);

        assert!(tables.pop_presign(algorithm, key_id).unwrap().is_none());
    }

    #[test]
    fn test_pop_from_empty_pool() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;

        assert!(tables.pop_presign(algorithm, key_id).unwrap().is_none());
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);
    }

    #[test]
    fn test_multiple_presigns_per_session() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let session_id = make_session_id([42; 32]);
        let presigns = vec![vec![1u8], vec![2], vec![3]];

        tables
            .insert_presigns(algorithm, key_id, 0, session_id, presigns)
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 3);

        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![1u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 2);

        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![2u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 1);

        let (_, presign) = tables.pop_presign(algorithm, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![3u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);

        assert!(tables.pop_presign(algorithm, key_id).unwrap().is_none());
    }

    #[test]
    fn test_presign_pool_isolation_across_algorithms() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let ecdsa = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let eddsa = DWalletSignatureAlgorithm::EdDSA;
        let session_ecdsa = make_session_id([1; 32]);
        let session_eddsa = make_session_id([2; 32]);

        tables
            .insert_presigns(ecdsa, key_id, 0, session_ecdsa, vec![vec![100u8]])
            .unwrap();
        tables
            .insert_presigns(eddsa, key_id, 0, session_eddsa, vec![vec![200u8]])
            .unwrap();

        assert_eq!(tables.presign_pool_size(ecdsa, key_id).unwrap(), 1);
        assert_eq!(tables.presign_pool_size(eddsa, key_id).unwrap(), 1);

        let (_, presign) = tables.pop_presign(ecdsa, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![100u8]);
        assert_eq!(tables.presign_pool_size(ecdsa, key_id).unwrap(), 0);

        // EdDSA pool unaffected
        assert_eq!(tables.presign_pool_size(eddsa, key_id).unwrap(), 1);
        let (_, presign) = tables.pop_presign(eddsa, key_id).unwrap().unwrap();
        assert_eq!(presign, vec![200u8]);
    }
}
