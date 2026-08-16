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
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use sui_types::base_types::{EpochId, ObjectID};
use tracing::{debug, error, info, instrument, trace, warn};
use typed_store::rocks::{DBBatch, DBMap, DBOptions, MetricConf, default_db_options};
use typed_store::rocksdb::Options;

use super::epoch_start_configuration::EpochStartConfigTrait;

use crate::authority::derived_epoch_state::{
    EpochStateClass, EpochStateEntry, epoch_state_registry,
};
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::authority::round_transport::{ConsensusRoundPayload, RoundTransportSender};
use crate::authority::{AuthorityCapabilitiesVotingResults, AuthorityMetrics, AuthorityState};
use crate::dwallet_checkpoints::{
    BuilderDWalletCheckpointMessage, DWalletCheckpointHeight, DWalletCheckpointServiceNotify,
    PendingDWalletCheckpoint,
};
use crate::validator_metadata::{
    HandoffAggregator, HandoffSignatureRecordOutcome, HandoffSignatureVerdict,
    JoinerAnnouncementVerdict, JoinerPubkeyProvider, MAX_PENDING_RELAYED_JOINER_ANNOUNCEMENTS,
    NetworkKeyBlobSource, PENDING_RELAYED_JOINER_ANNOUNCEMENT_TTL,
    PendingRelayedJoinerAnnouncement, build_handoff_attestation, hash_next_committee_pubkey_set,
    process_handoff_signature, push_buffered_joiner_announcement,
    reevaluate_buffered_joiner_announcements, sign_handoff_attestation, verify_handoff_signature,
    verify_joiner_announcement,
};

use crate::consensus_handler::{
    ConsensusCommitInfo, SequencedConsensusTransaction, SequencedConsensusTransactionKey,
    SequencedConsensusTransactionKind, VerifiedSequencedConsensusTransaction,
};

use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
};
use crate::epoch::epoch_metrics::EpochMetrics;
use crate::epoch_tasks::mpc_data_announcement_sender::ready_signal_deadline_ms;
use crate::stake_aggregator::StakeAggregator;
use crate::system_checkpoints::{
    BuilderSystemCheckpoint, PendingSystemCheckpoint, PendingSystemCheckpointInfo,
    PendingSystemCheckpointV1, SystemCheckpointHeight, SystemCheckpointService,
    SystemCheckpointServiceNotify,
};
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
use fastcrypto::ed25519::Ed25519Signature;
use group::PartyID;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
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
    AssignedPresign, ConsensusGlobalPresignRequest, ConsensusNOAObservation,
    ConsensusNOAPresignDemand, DWalletInternalMPCOutput, DWalletMPCMessage, DWalletMPCOutput,
    IdleStatusUpdate, IkaNetworkConfig, SessionIdentifier, SuiChainObservationUpdate,
};
use ika_types::messages_system_checkpoints::{
    SystemCheckpointMessage, SystemCheckpointMessageKind, SystemCheckpointSequenceNumber,
    SystemCheckpointSignatureMessage,
};
use ika_types::noa_checkpoint::NOAPresignDemandId;
use ika_types::sui::epoch_start_system::{EpochStartSystem, EpochStartSystemTrait};
use ika_types::validator_metadata::{
    SignedValidatorMpcDataAnnouncement, ValidatorMpcDataAnnouncement,
};
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

/// Consensus rounds the MPC service may trail the commit path by before the
/// node reports itself as no longer contributing.
///
/// Sized to be unmistakable rather than sensitive. Observed testnet round
/// production is ~46k rounds/hour, so this is roughly an hour of falling
/// behind — comfortably past any restart catch-up, and far below the gaps the
/// two production incidents this exists for reached (ika #1978 sat ~247k rounds
/// behind after 3.5h and kept going; #1980 passed 335k). A validator legitimately
/// catching up closes the gap; a stopped one only grows it.
const MPC_LAG_ALARM_ROUNDS: u64 = 50_000;

/// How recent an MPC progress report must be for its catch-up flag to hold the
/// stopped-contributing alarm.
///
/// The hold is a LEASE the MPC service renews, never a flag it can leave set:
/// the service publishes a report for every consensus round it consumes, so a
/// service genuinely draining a backlog renews this hundreds to thousands of
/// times a second, and one that stopped renews never. An expiry-free flag would
/// hand the stall its perfect hiding place — the deliberate service-loop
/// `break` on self-recognised maliciousness is reachable during the
/// post-restart replay window, and would otherwise latch the suppression for
/// the life of the process.
///
/// A minute is ~3,000 service-loop iterations (the loop sleeps 20ms between
/// them) and orders of magnitude beyond the per-round drain interval a
/// catching-up validator sustains (~1-2k rounds a second in production), so
/// nothing short of the service actually stopping expires it — the bound is
/// generous in the direction where being wrong reintroduces the false alarm
/// this exists to remove. It is still 1/60th of the time scale
/// `MPC_LAG_ALARM_ROUNDS` encodes (~an hour of round production), so a service
/// that dies mid-catch-up is reported within a minute rather than never.
const MPC_CATCH_UP_REPORT_FRESHNESS: Duration = Duration::from_secs(60);

/// How long a reported catch-up may run without its lag reaching a new low
/// before the drain is called stuck.
///
/// While the service keeps reporting a catch-up the stopped-contributing alarm
/// is held, so this is the only line left that can say the validator is not on
/// its way back. The bound is generous on purpose: the largest backlog seen in
/// production (~640k rounds, a mid-epoch restart replaying the epoch) drained
/// COMPLETELY in five to ten minutes — with computation withheld the drain runs
/// at ~1-2k rounds/s against a ~19.5 rounds/s tip. A drain running at a
/// hundredth of that still reaches a new low every few commits, so a quarter
/// hour without one is not a slow drain — it is a drain that stopped.
const MPC_CATCH_UP_STUCK_DRAIN: Duration = Duration::from_secs(15 * 60);

/// What the MPC service publishes for the consensus-path stall detector: the
/// round it has finished consuming, whether its catch-up gate was engaged when
/// it finished, and when it said so.
///
/// One immutable value behind a single `ArcSwapOption` rather than three
/// separate atomics, so the consensus path always weighs a round against the
/// gate state and the timestamp that were true *together*. Torn across atomics
/// these would pair a fresh timestamp with a stale gate flag, which is the
/// exact combination that decides whether the alarm is held.
#[derive(Debug, Clone, Copy)]
struct MpcServiceProgress {
    consumed_round: Round,
    catching_up: bool,
    observed_at: Instant,
}

/// Consensus-side view of the catch-up currently being reported: the smallest
/// lag seen since it started and when that low was reached.
///
/// The MINIMUM rather than the previous sample, because the tip keeps advancing
/// while the cursor chases it: a drain closing the gap fast still produces
/// individual samples that tick upwards, and comparing consecutive samples
/// would read those as a stall.
#[derive(Debug, Clone, Copy)]
struct CatchUpDrainProgress {
    lowest_lag_rounds: u64,
    lowest_lag_at: Instant,
}

/// What a single MPC-lag sample changed, so the loud log fires on transition
/// rather than on every consensus commit. Returned rather than kept private so
/// the latching is directly testable — the state flag alone cannot distinguish
/// "logged once" from "logged every commit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MpcLagTransition {
    Raised,
    Cleared,
    Unchanged,
}

/// What one MPC-lag sample changed, per alarm: `stopped_contributing` is an MPC
/// service that is no longer consuming rounds at all, `stuck_drain` a reported
/// catch-up that has stopped closing its gap. Two alarms rather than one
/// because the first is deliberately held in exactly the situation that makes
/// the second the only remaining signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MpcLagReport {
    stopped_contributing: MpcLagTransition,
    stuck_drain: MpcLagTransition,
}

impl MpcLagReport {
    const UNCHANGED: Self = Self {
        stopped_contributing: MpcLagTransition::Unchanged,
        stuck_drain: MpcLagTransition::Unchanged,
    };
}

pub enum CancelConsensusCertificateReason {
    CongestionOnObjects(Vec<ObjectID>),
    DkgFailed,
}

/// Whether a relayed joiner announcement was kept or discarded.
///
/// The distinction decides whether its consensus key is recorded as
/// processed. The key is `(joiner, epoch, timestamp)` — the joiner's identity,
/// not the relayer's — so recording it consumes that identity's one slot for
/// the epoch. Only a copy we actually kept has earned that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayedAnnouncementDisposition {
    /// Accepted, or buffered for re-evaluation when a provider installs.
    Retained,
    /// Rejected on a verdict that re-evaluation cannot change.
    Discarded,
}

pub enum ConsensusCertificateResult {
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

/// The terminal resolution of a NOA sign demand: exactly one per demand
/// digest, per epoch, written by the consensus-order drain.
///
/// Both arms are terminal, and recording BOTH durably is what keeps a
/// restarted validator consistent with its peers. The drain replays the
/// epoch's consensus rounds after a restart while the presign pool — durable
/// per-epoch state — is not rewound with them, so a demand the park bound
/// dropped would otherwise be re-read at its delivery round against a pool
/// that filled after the drop, and the replayed drain would pop for a demand
/// every peer had already given up on.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum NoaPresignDemandResolution {
    /// A presign was popped for this demand and is bound to it.
    Assigned {
        session_identifier: SessionIdentifier,
        blending_index: u16,
        presign: Vec<u8>,
        network_encryption_key_id: ObjectID,
    },
    /// The demand stayed unassigned for the whole park bound and was dropped;
    /// it must never be assigned a presign in this epoch.
    Evicted,
}

/// What one drain attempt at a demand resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresignAssignmentOutcome {
    /// A presign is bound to the demand — popped by this call, or already
    /// recorded by an earlier drain of the same rounds.
    Assigned {
        session_identifier: SessionIdentifier,
        blending_index: u16,
        presign: Vec<u8>,
    },
    /// The demand was dropped at the park bound in an earlier round, and must
    /// never be assigned a presign in this epoch. Reachable only for
    /// [`PresignDemand::Noa`] — a global presign request has no park bound.
    Evicted,
    /// No presign exists for the demand's network encryption key yet.
    PoolEmpty,
}

/// What a presign is being assigned TO — and, because assignment is keyed by
/// it, the idempotency key.
///
/// Every consumer's demand stream is replayed from a per-epoch table after a
/// restart, so a bare pool pop on replay binds a DIFFERENT presign than the
/// never-crashed peers bound (fills complete out of sequence order, so the
/// pool head moves between the original pop and the replayed one). That is a
/// byte-divergent checkpoint or attestation from an honest validator. Routing
/// every assignment through a demand identity makes the replay a no-op
/// instead: a re-seen demand returns what it was already given, without
/// popping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresignDemand {
    /// A global presign request, identified by its consensus sequence number.
    GlobalRequest { session_sequence_number: u64 },
    /// A network-owned-address sign demand, identified by its demand id.
    ///
    /// Carries the identity TYPE, not a bare digest: the assignment table is
    /// keyed by `NOAPresignDemandId::digest()`, and any other 32-byte value
    /// would type-check at a call site while keying the assignment wrong.
    Noa { demand_id: NOAPresignDemandId },
}

/// Trait for the AuthorityPerEpochStore, which gets recreated at the beginning of each epoch.
pub trait AuthorityPerEpochStoreTrait: Sync + Send + 'static {
    fn insert_pending_dwallet_checkpoint(
        &self,
        checkpoint: PendingDWalletCheckpoint,
    ) -> IkaResult<()>;

    /// Publishes the consensus round the MPC service has finished consuming,
    /// and whether its catch-up gate was engaged when it finished.
    ///
    /// The MPC service cannot report its own stall: every path that stops it
    /// also stops the code that would notice — most starkly the deliberate
    /// `break` on self-recognised maliciousness, which ends the service loop
    /// for the life of the process while consensus keeps running normally.
    /// So the MPC side only publishes its progress here, and the CONSENSUS
    /// commit path — which is still alive in exactly the cases that matter —
    /// does the comparing.
    ///
    /// The gate state rides along because the consensus path cannot otherwise
    /// tell a stopped service from one deliberately draining a replay backlog:
    /// consensus rounds restart at zero each epoch and a restart's fresh epoch
    /// store starts its cursor there too, so from the commit path a mid-epoch
    /// restart looks exactly like a service that never started. `catching_up`
    /// must be sampled from the gate itself, not from the gate's metric — a
    /// gauge published by the service loop latches at its last value when that
    /// loop dies, which is the one case the detector exists for.
    fn record_mpc_consumed_consensus_round(&self, round: Round, catching_up: bool);

    /// The highest consensus round this node has OBSERVED — the catch-up
    /// gate's "how far is there to go". Not the highest folded: under the
    /// blocking round transport the fold cannot run more than the channel's
    /// capacity ahead of the drain, so its position would understate the gap
    /// by orders of magnitude.
    fn observed_consensus_head_round(&self) -> Round;

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>>;

    fn next_verified_system_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<SystemCheckpointMessageKind>)>>;

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

    /// The highest internal-presign session sequence number that has ever
    /// filled a pool slot for `(signature_algorithm, key)` this epoch, or
    /// `None` if no fill landed yet. This is the persisted high-water mark of
    /// the pool's ordinal stream: a process that restarts mid-epoch must seed
    /// its in-memory `next_internal_presign_sequence_number` from it (#1952) —
    /// seeding from 1 re-mints ordinals the committee already completed, and
    /// the top-up loop then trails the live ordinal window by a constant
    /// offset for the rest of the epoch (each dead mint is "released" only by
    /// a live peer completion, so the gap never closes).
    fn max_filled_presign_pool_slot(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<u64>>;

    /// Assign a presign to a demand — atomically, and idempotently in the
    /// demand's identity, so the per-epoch replay every consumer performs
    /// after a restart re-reads the same assignment instead of popping a
    /// second, different presign. See
    /// [`AuthorityEpochTables::assign_presign_for_demand`].
    fn assign_presign_for_demand(
        &self,
        demand: &PresignDemand,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<PresignAssignmentOutcome>;

    /// Reads a NOA sign demand's terminal resolution, if it has one.
    ///
    /// Keyed by the identity, never a bare digest — the same reason
    /// [`PresignDemand::Noa`] carries one.
    fn noa_presign_demand_resolution(
        &self,
        demand_id: &NOAPresignDemandId,
    ) -> IkaResult<Option<NoaPresignDemandResolution>>;

    /// Durably records that a demand was dropped at the park bound, so a
    /// replay of the epoch's rounds cannot assign it a presign the rest of the
    /// committee never assigned. Idempotent, and never overwrites an existing
    /// resolution.
    ///
    /// NOA-only: a global presign request has no bound to outlive, and its
    /// marker table holds served presigns alone.
    fn evict_noa_presign_demand(&self, demand_id: &NOAPresignDemandId) -> IkaResult<()>;

    /// Whether a NOA sign demand already has a terminal resolution — assigned
    /// OR dropped at the park bound. Both end the demand, so neither needs a
    /// (re-)announcement.
    fn has_noa_presign_demand_resolution(&self, demand_id: &NOAPresignDemandId) -> IkaResult<bool>;

    /// Marks a presign as used so it cannot be reused.
    fn mark_presign_as_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<()>;

    /// Checks if a presign has already been used.
    fn is_presign_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<bool>;

    /// Persists a single Fast Schnorr (VSS) presign's private output
    /// (`bcs(PrivatePresignOutput)`) keyed by `(presign session id, blending index)`,
    /// so the later sign can recover the nonce shares for that exact blended presign.
    /// Self-prunes at epoch rotation. VSS sessions only.
    fn store_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
        private_output: Vec<u8>,
    ) -> IkaResult<()>;

    /// Loads a persisted VSS presign private output by `(session id, blending index)`,
    /// if present. Absent on a non-VSS presign, after epoch rotation, or on disk loss
    /// — the sign treats `None` as a soft-fail (this validator drops out of the quorum).
    fn get_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
    ) -> IkaResult<Option<Vec<u8>>>;

    /// Assigns a presign to a USER by moving it from the internal pool to the
    /// assigned pool. NOT idempotent — see
    /// [`Self::assign_presign_for_demand`] for the demand-keyed form every
    /// replayed consumer must use.
    fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<(SessionIdentifier, u16)>>;

    /// Retrieves an assigned presign by session identifier, blending index, and signature algorithm.
    fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>>;

    /// Pops an assigned presign from the pool. Used when the presign is consumed for signing.
    fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>>;

    /// Caches the canonical output bytes of a network DKG session
    /// locally so the handoff trigger can pin its digest at
    /// EndOfPublish. Called by the MPC producer at the same point
    /// it builds the output `ConsensusTransaction`. The implementer
    /// is expected to be idempotent on identical bytes — protocols
    /// can re-finalize the same output without changing the cached
    /// digest.
    fn cache_network_dkg_output(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
        output_bytes: &[u8],
    ) -> IkaResult<()>;

    /// Same as `cache_network_dkg_output`, but for reconfiguration
    /// outputs (per-epoch, per-key). `reconfiguration_epoch` is the
    /// reconfiguration session's own epoch (the on-chain request
    /// event's epoch), used to key the epoch-deterministic handoff
    /// digest — pass `session_request.epoch`, never the wall-clock
    /// current epoch.
    fn cache_network_reconfiguration_output(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
        reconfiguration_epoch: EpochId,
        output_bytes: &[u8],
    ) -> IkaResult<()>;

    /// Returns the certified handoff attestation for `epoch` if this
    /// node holds it (crossed quorum locally, or the bootstrap anchor
    /// fetched + persisted it). The network-key instantiation path reads
    /// the prior epoch's cert as the cross-epoch agreement on the output
    /// digests it inherits.
    fn get_certified_handoff_attestation(
        &self,
        epoch: EpochId,
    ) -> IkaResult<Option<ika_types::handoff::CertifiedHandoffAttestation>>;

    /// Returns whether the epoch-wide `mpc_data` input set has been
    /// frozen. Network DKG and reconfiguration session kickoff defers
    /// until this is `true`. The freeze itself is decided at the consensus
    /// commit boundary (see
    /// `process_consensus_transactions_and_commit_boundary`), so the frozen
    /// set is a deterministic function of the consensus sequence.
    fn is_mpc_data_frozen(&self) -> IkaResult<bool>;

    /// Returns the freeze-time `validator -> blob_hash` snapshot
    /// for this epoch (post-attestation-tally working set), or an
    /// empty map if the freeze hasn't fired yet. Surfaced on the
    /// trait so the MPC manager's per-validator local-readiness
    /// gate can mockable-test the "I have the frozen-set blobs"
    /// branch without needing a real epoch store.
    fn get_frozen_mpc_data_input_set_trait(&self) -> IkaResult<HashMap<AuthorityName, [u8; 32]>>;

    /// Returns the perpetual-tables handle, or `None` if it isn't
    /// installed yet. Returning `Option<Arc<…>>` keeps the trait
    /// dyn-safe — `AuthorityPerpetualTables` itself doesn't need
    /// to be on this trait because the local-readiness gate only
    /// needs `get_mpc_artifact_blob`.
    fn perpetual_tables_handle(
        &self,
    ) -> Option<Arc<super::authority_perpetual_tables::AuthorityPerpetualTables>>;
}

/// The first per-round row STRICTLY after `last_consensus_round` — or the
/// first row at all on a fresh start (`None`).
///
/// Deliberately an exclusive lower bound rather than the previous pattern of
/// positioning the iterator AT the anchor row and skipping one (`nth(1)`):
/// the skip variant is only correct while the row at exactly
/// `last_consensus_round` exists in the table. If that anchor row is ever
/// absent — a pruned table, a partially rebuilt epoch store — `nth(1)`
/// consumes the first UNREAD row as if it were the anchor, and because every
/// per-round stream skips the same round in lockstep, the downstream
/// dense-stream alignment checks cannot catch it: a consensus round's MPC
/// messages would silently never be processed. With the exclusive bound a
/// missing anchor degrades to reading the next live row, which is the
/// intended semantics ("everything after what I processed").
fn next_round_row<V>(
    table: &DBMap<Round, V>,
    last_consensus_round: Option<Round>,
) -> IkaResult<Option<(Round, V)>>
where
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    Ok(table
        .safe_iter_with_bounds(
            last_consensus_round.map(|round| round.saturating_add(1)),
            None,
        )
        .next()
        .transpose()?)
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

    fn record_mpc_consumed_consensus_round(&self, round: Round, catching_up: bool) {
        self.mpc_service_progress
            .store(Some(Arc::new(MpcServiceProgress {
                consumed_round: round,
                catching_up,
                observed_at: Instant::now(),
            })));
    }

    fn observed_consensus_head_round(&self) -> Round {
        self.observed_consensus_head_round.load(Ordering::Acquire)
    }

    fn next_verified_dwallet_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<DWalletCheckpointMessageKind>)>> {
        let tables = self.tables()?;
        next_round_row(
            &tables.verified_dwallet_checkpoint_messages,
            last_consensus_round,
        )
    }

    fn next_verified_system_checkpoint_message(
        &self,
        last_consensus_round: Option<Round>,
    ) -> IkaResult<Option<(Round, Vec<SystemCheckpointMessageKind>)>> {
        let tables = self.tables()?;
        next_round_row(
            &tables.verified_system_checkpoint_messages,
            last_consensus_round,
        )
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

    fn max_filled_presign_pool_slot(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<u64>> {
        let tables = self.tables()?;
        tables.max_filled_presign_pool_slot(signature_algorithm, dwallet_network_encryption_key_id)
    }

    fn noa_presign_demand_resolution(
        &self,
        demand_id: &NOAPresignDemandId,
    ) -> IkaResult<Option<NoaPresignDemandResolution>> {
        Ok(self
            .tables()?
            .noa_presign_demand_resolutions
            .get(&demand_id.digest())?)
    }

    fn assign_presign_for_demand(
        &self,
        demand: &PresignDemand,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<PresignAssignmentOutcome> {
        self.tables()?.assign_presign_for_demand(
            demand,
            signature_algorithm,
            dwallet_network_encryption_key_id,
        )
    }

    fn evict_noa_presign_demand(&self, demand_id: &NOAPresignDemandId) -> IkaResult<()> {
        self.tables()?.evict_noa_presign_demand(demand_id)
    }

    fn has_noa_presign_demand_resolution(&self, demand_id: &NOAPresignDemandId) -> IkaResult<bool> {
        Ok(self
            .tables()?
            .noa_presign_demand_resolutions
            .contains_key(&demand_id.digest())?)
    }

    fn mark_presign_as_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        tables.mark_presign_as_used(presign_session_id, presign_blending_index)
    }

    fn is_presign_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<bool> {
        let tables = self.tables()?;
        tables.is_presign_used(presign_session_id, presign_blending_index)
    }

    fn store_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
        private_output: Vec<u8>,
    ) -> IkaResult<()> {
        let tables = self.tables()?;
        tables.store_presign_private_output(
            presign_session_id,
            presign_blending_index,
            private_output,
        )
    }

    fn get_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
    ) -> IkaResult<Option<Vec<u8>>> {
        let tables = self.tables()?;
        tables.get_presign_private_output(presign_session_id, presign_blending_index)
    }

    fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<(SessionIdentifier, u16)>> {
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
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>> {
        let tables = self.tables()?;
        tables.get_assigned_presign(signature_algorithm, session_identifier, blending_index)
    }

    fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>> {
        let tables = self.tables()?;
        tables.pop_assigned_presign(signature_algorithm, session_identifier, blending_index)
    }

    fn cache_network_dkg_output(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
        output_bytes: &[u8],
    ) -> IkaResult<()> {
        self.cache_protocol_output(
            ProtocolOutputKind::Dkg,
            dwallet_network_encryption_key_id,
            output_bytes,
        )
    }

    fn cache_network_reconfiguration_output(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
        reconfiguration_epoch: EpochId,
        output_bytes: &[u8],
    ) -> IkaResult<()> {
        // Per-epoch table + perpetual blob/by-key mirror (feeds the
        // off-chain overlay's by-key lookup). Unchanged.
        self.cache_protocol_output(
            ProtocolOutputKind::Reconfiguration,
            dwallet_network_encryption_key_id,
            output_bytes,
        )?;
        // Epoch-keyed digest for the handoff attestation, keyed by the
        // reconfiguration session's own epoch (deterministic across
        // validators) rather than the wall-clock epoch the per-epoch
        // table above is implicitly bound to. This is the slice the
        // handoff items builder reads, so a late-finalized output that
        // crosses the epoch boundary still certifies under the correct
        // epoch on every validator.
        if let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() {
            let digest = mpc_data_blob_hash(output_bytes);
            if let Err(e) = perpetual.insert_network_reconfiguration_output_digest_for_epoch(
                reconfiguration_epoch,
                dwallet_network_encryption_key_id,
                digest,
            ) {
                warn!(
                    error = ?e,
                    ?dwallet_network_encryption_key_id,
                    reconfiguration_epoch,
                    "failed to persist epoch-keyed reconfiguration output digest — handoff attestation may omit this key for the epoch"
                );
            }
        }
        Ok(())
    }

    fn get_certified_handoff_attestation(
        &self,
        epoch: EpochId,
    ) -> IkaResult<Option<ika_types::handoff::CertifiedHandoffAttestation>> {
        match self.perpetual_tables_for_handoff_load_full() {
            Some(perpetual) => perpetual.get_certified_handoff_attestation(epoch),
            None => Ok(None),
        }
    }

    fn is_mpc_data_frozen(&self) -> IkaResult<bool> {
        let tables = self.tables()?;
        Ok(!tables.frozen_validator_mpc_data_input_set.is_empty())
    }

    fn get_frozen_mpc_data_input_set_trait(&self) -> IkaResult<HashMap<AuthorityName, [u8; 32]>> {
        self.get_frozen_validator_mpc_data_input_set()
    }

    fn perpetual_tables_handle(
        &self,
    ) -> Option<Arc<super::authority_perpetual_tables::AuthorityPerpetualTables>> {
        self.perpetual_tables_for_handoff_load_full()
    }
}

/// Discriminator for the two protocol output caches that share an
/// implementation in [`AuthorityPerEpochStore::cache_protocol_output`].
#[derive(Copy, Clone)]
enum ProtocolOutputKind {
    Dkg,
    Reconfiguration,
}

/// Read-only adapter so `validator_metadata::NetworkKeyBlobSource`
/// can serve protocol output blobs straight out of this validator's
/// own caches (`network_dkg_output_digests` /
/// `network_reconfiguration_output_digests` + perpetual
/// `mpc_artifact_blobs`). Returning `None` causes the caller's
/// fallback chain-read path to kick in.
impl NetworkKeyBlobSource for AuthorityPerEpochStore {
    fn network_dkg_output_blob(&self, network_key_id: &ObjectID) -> Option<Vec<u8>> {
        self.lookup_protocol_output_blob(ProtocolOutputKind::Dkg, network_key_id)
    }

    fn network_reconfiguration_output_blob(&self, network_key_id: &ObjectID) -> Option<Vec<u8>> {
        self.lookup_protocol_output_blob(ProtocolOutputKind::Reconfiguration, network_key_id)
    }
}

/// The identity and configuration an epoch store is opened with.
///
/// Grouped so the constructors take two arguments rather than nine, and so
/// what varies between them — whether the derived tables are wiped — is not
/// buried among eight values that never vary. Instantiated directly; every
/// field is public and none is derived from another.
pub struct EpochStoreParams {
    pub name: AuthorityName,
    pub committee: Arc<Committee>,
    /// The `store` directory the per-epoch databases live under, NOT the
    /// epoch's own directory — `AuthorityEpochTables::path` appends that.
    pub parent_path: PathBuf,
    pub db_options: Option<Options>,
    pub metrics: Arc<EpochMetrics>,
    pub epoch_start_configuration: EpochStartConfiguration,
    pub chain_identifier: ChainIdentifier,
    pub packages_config: IkaNetworkConfig,
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

    /// The commit boundary hands each round's inputs to the MPC drain over
    /// this bounded channel, BLOCKING when it is full. Absent on a node that
    /// runs no drain (a fullnode or notifier), where the payload is dropped —
    /// nothing downstream of the drain exists there to want it.
    round_transport: ArcSwapOption<RoundTransportSender>,

    /// The highest consensus round this node has OBSERVED, which is not the
    /// same as the highest it has folded.
    ///
    /// The catch-up gate needs "how far behind is the drain", and under a
    /// blocking transport the fold's own position cannot answer that: the
    /// fold is never more than the channel's capacity ahead of the drain, so
    /// a gap measured against it is pinned far below the gate's entry
    /// threshold and the gate would silently never engage. This is fed from
    /// the two places that see further than the fold — the boot replay
    /// publishes the consensus store's head before it starts folding, and the
    /// live path reports each commit on arrival, before the fold can block on
    /// it.
    observed_consensus_head_round: AtomicU64,

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

    /// Source of truth for which authorities are registered as
    /// next-epoch joiners (members of `PendingActiveSet` whose next-
    /// epoch pubkey is known). Populated by the `sui_syncer` task;
    /// `None` while the syncer hasn't produced a snapshot yet, in
    /// which case every next-epoch joiner announcement is dropped.
    /// Current-epoch announcements are unaffected.
    joiner_pubkey_provider: ArcSwapOption<Box<dyn JoinerPubkeyProvider>>,

    /// This validator's locally-computed handoff attestation for the
    /// epoch — the value every honest validator must arrive at by
    /// the time EndOfPublish fires. Installed by the producer side
    /// when it has the frozen mpc-data input set plus the DKG /
    /// reconfig output digests. Until installed, incoming handoff
    /// signatures land in `pending_handoff_signatures` and are
    /// replayed against the aggregator at install time.
    expected_handoff_attestation: ArcSwapOption<ika_types::handoff::HandoffAttestation>,

    /// Buffer of `HandoffSignatureMessage`s received via
    /// `EndOfPublishV2` before this validator installed its own
    /// local expected attestation. Without this buffer, peer V2
    /// signatures that race ahead of our local install would be
    /// silently dropped — a validator that's slow to finish its own
    /// DKG / reconfig snapshot would lose every peer's vote that
    /// arrived first, leaving the aggregator under quorum for
    /// epochs at a time. Drained inside
    /// `install_expected_handoff_attestation` after the aggregator
    /// is constructed. Bounded by the committee size in practice
    /// (each validator emits one V2 per epoch).
    pending_handoff_signatures:
        parking_lot::Mutex<Vec<ika_types::handoff::HandoffSignatureMessage>>,

    /// Latest progress report from the MPC service — the round it finished
    /// consuming, its catch-up gate state, and when it published them.
    /// Compared against the commit round on the consensus path to detect an MPC
    /// subsystem that has stopped while consensus keeps running — see
    /// `record_mpc_consumed_consensus_round`. `None` until the service reports
    /// for the first time.
    mpc_service_progress: ArcSwapOption<MpcServiceProgress>,

    /// Whether the MPC-lag alarm is currently raised, so the loud log fires on
    /// transition instead of on every consensus commit.
    mpc_lag_alarm_active: std::sync::atomic::AtomicBool,

    /// Drain progress of the catch-up the MPC service is currently reporting,
    /// or `None` when it is reporting none. Cleared when the reported catch-up
    /// ends, so every catch-up is judged on its own drain rather than on the
    /// low-water mark of an earlier one.
    mpc_catch_up_drain: Mutex<Option<CatchUpDrainProgress>>,

    /// Whether the stuck-drain alarm is currently raised; latched for the same
    /// reason as `mpc_lag_alarm_active`.
    mpc_catch_up_stuck_alarm_active: AtomicBool,

    /// Pending `handoff_signatures` row mutations, waiting to be folded into
    /// the next `ConsensusCommitOutput`. `Some(signature)` is an upsert,
    /// `None` a delete. Every writer of that table stages here instead of
    /// writing it, so each row lands in exactly one commit's batch and the
    /// durable table can never run ahead of the last committed commit —
    /// which is what makes the close gate's read of it commit-attributable
    /// (#1927). Keyed by signer with last-op-wins, so it stays bounded by
    /// the committee size no matter how often a peer re-broadcasts.
    staged_handoff_signature_rows:
        parking_lot::Mutex<BTreeMap<AuthorityName, Option<Ed25519Signature>>>,

    /// Buffer of relayed next-epoch joiner announcements received via
    /// consensus while this validator's `JoinerPubkeyProvider` was
    /// absent or lagged the next-epoch committee (so the joiner's
    /// signature couldn't be verified yet). Consensus dedup never
    /// redelivers a dropped relay, so without this buffer a joiner
    /// whose announcement raced ahead of our provider install would be
    /// missing from our next-committee assembly. Re-evaluated against
    /// the provider in `install_joiner_pubkey_provider`. The next-epoch
    /// committee isn't known here, so it can't be bounded by membership
    /// the way `pending_handoff_signatures` is — bounded instead by a
    /// hard cap + TTL with last-write-wins per joiner; the per-epoch
    /// store lifecycle drops it at epoch end.
    pending_relayed_joiner_announcements: parking_lot::Mutex<Vec<PendingRelayedJoinerAnnouncement>>,

    /// In-memory stake-weighted accumulator over verified handoff
    /// signatures. Rebuilt from `handoff_signatures` + the installed
    /// expected attestation on first use after install; recreated
    /// when the installed attestation changes. Yields a
    /// `CertifiedHandoffAttestation` once stake crosses quorum and
    /// keeps enriching it with each later signer (slack for departed
    /// signers); a replayed signature is a no-op.
    handoff_aggregator: parking_lot::Mutex<Option<HandoffAggregator>>,

    /// Perpetual storage handle used to persist a fresh
    /// `CertifiedHandoffAttestation` the moment the aggregator
    /// crosses quorum. The handle is installed once at node startup
    /// (after the perpetual DB is open). `None` here means the cert
    /// is produced but not yet persisted; safe in this commit
    /// because no consumer (joiner bootstrap) is wired up yet.
    perpetual_tables_for_handoff:
        ArcSwapOption<super::authority_perpetual_tables::AuthorityPerpetualTables>,

    /// Once-per-epoch latch for the operator-actionable "own mpc_data
    /// blob missing/invalid in perpetual storage" warn emitted by
    /// `compute_locally_validated_peers` — the condition has no in-epoch
    /// self-heal, and the function runs every ~2s announcement-sender
    /// tick, so without the latch the identical warn floods for hours.
    /// The `own_mpc_data_blob_unhealthy` gauge carries the ongoing state.
    self_blob_unhealthy_warned: AtomicBool,

    /// Running max of `commit_timestamp_ms` over every consensus commit
    /// this validator has processed this epoch — the epoch's consensus
    /// clock. In-memory only: it starts at 0 on (re)open and restores
    /// itself on the next processed commit (replayed or fresh), and its
    /// only consumer — the mpc_data ready-signal emit gate — treats 0 as
    /// "consensus time unknown", which merely defers a wall-clock-free
    /// deadline that could not have any effect while no commits flow
    /// anyway (nothing can be sequenced). Leader-proposed timestamps are
    /// only manipulable at seconds scale against the hours-scale
    /// deadlines built on this; the max makes it monotone locally
    /// regardless.
    max_processed_commit_timestamp_ms: AtomicU64,
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

/// Presign pool DB table type.
/// Key: (network_encryption_key_id, session_sequence_number).
/// Value: (session_identifier, list of (blending_index, serialized presign bytes)).
/// The blending index is the presign's position in the originally-inserted vector;
/// together with the session identifier it uniquely identifies a single presign.
type PresignPoolTable = DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>;

/// An uncommitted presign pop: the pending write batch plus the popped
/// presign's session identifier, blending index, and serialized value.
type PreparedPresignPop = (DBBatch, SessionIdentifier, u16, Vec<u8>);

/// AuthorityEpochTables contains tables that contain data that is only valid within an epoch.
///
/// WRITE DISCIPLINE — read before adding a table, a write site, or a
/// consumer. This store deliberately holds two persistence patterns, and
/// confusing them has produced real divergence bugs (#1829, #1917/#1920).
/// Every field below therefore ends its doc comment with one
/// `write-discipline:` line, in one of these forms:
///
/// - `write-discipline: commit-batched` — the only writer is
///   `ConsensusCommitOutput::write_to_batch`, so the row lands in the same
///   atomic batch as the processed-markers of the commit that produced it.
///   A crash before that batch replays the whole commit and re-derives the
///   row. This is the required discipline for anything a consensus-visible
///   decision (close round, freeze partition, checkpoint content) reads.
/// - `write-discipline: direct — safe because <reason>: <consumer>` — the
///   row is written outside the commit batch, followed by the argument that
///   makes the table's consumers survive that. Fixed vocabulary:
///   `pure-function-of-table` (every consumer folds the WHOLE table, with no
///   arrival-order or size cap), `idempotent-replay` (re-running the
///   producing work rewrites the same key with the same value),
///   `local-only` (nothing consensus-visible reads it — only this node's own
///   scheduling, secrets, or operator overrides), `content-addressed` (the
///   key is a hash of the value).
/// - `write-discipline: direct — UNPROVEN (#NNNN)` — a direct write whose
///   safety argument does not currently close. Tracked, not blessed.
///
/// The reason must name the consumer it protects, because this class of bug
/// is born on the READER side: #1917 was a direct write that was fine until
/// `all_voted` folded an arrival-order-capped view of an uncapped table.
/// So a new consumer of a direct-written table is as much a change to this
/// contract as a new write site. Full rule (including what to do when the
/// reason no longer holds):
/// `dev-docs/conventions/epoch-table-write-discipline.md`, enforced by
/// `scripts/check-epoch-table-write-discipline.sh` in CI.
#[derive(DBMapUtils)]
#[allow(clippy::type_complexity)]
pub struct AuthorityEpochTables {
    /// Track which transactions have been processed in handle_consensus_transaction. We must be
    /// sure to advance next_shared_object_versions exactly once for each transaction we receive from
    /// consensus. But, we may also be processing transactions from checkpoints, so we need to
    /// track this state separately.
    ///
    /// Entries in this table can be garbage collected whenever we can prove that we won't receive
    /// another handle_consensus_transaction call for the given digest. This probably means at
    /// epoch change.
    ///
    /// write-discipline: commit-batched — this IS the marker the other
    /// commit-batched tables are made atomic with; a marker durable ahead of
    /// its commit's effects would let `is_consensus_message_processed` skip a
    /// transaction whose effects were lost.
    consensus_message_processed: DBMap<SequencedConsensusTransactionKey, bool>,

    /// The following table is used to store a single value (the corresponding key is a constant). The value
    /// represents the index of the latest consensus message this authority processed, running hash of
    /// transactions, and accumulated stats of consensus output.
    /// This field is written by a single process (consensus handler).
    ///
    /// write-discipline: commit-batched — the running per-author tallies must
    /// land with the commit that produced them, or a validator's checkpoint
    /// content would depend on where its last write happened to stop. This is
    /// no longer a startup cursor: it is wiped and re-accumulated from the
    /// first commit of the epoch on every boot, so `get_last_consensus_stats`
    /// reads empty there and the handler starts at the epoch's beginning.
    last_consensus_stats: DBMap<u64, ExecutionIndicesWithStats>,

    /// This table has information for the checkpoints for which we constructed all the data
    /// from consensus, but not yet constructed actual checkpoint.
    ///
    /// Key in this table is the consensus commit height and not a checkpoint sequence number.
    ///
    /// Non-empty list of transactions here might result in empty list when we are forming checkpoint.
    /// Because we don't want to create checkpoints with empty content(see CheckpointBuilder::write_checkpoint),
    /// the sequence number of checkpoint does not match height here.
    ///
    /// write-discipline: direct — safe because idempotent-replay: written by
    /// the `DWalletMPCService` round loop, keyed by the consensus round it
    /// derived the messages from, out of commit-batched inputs
    /// (`dwallet_mpc_messages` / `dwallet_mpc_outputs` /
    /// `verified_dwallet_checkpoint_messages`). A crash before the service's
    /// cursor advances re-derives the same height with the same content. Its
    /// only consumer is this node's checkpoint builder
    /// (`process_pending_dwallet_checkpoint`).
    #[default_options_override_fn = "pending_checkpoints_table_default_config"]
    pending_dwallet_checkpoints: DBMap<DWalletCheckpointHeight, PendingDWalletCheckpoint>,

    /// write-discipline: commit-batched — the `DWalletMPCService` replay walks
    /// this table in lockstep with `dwallet_mpc_messages` and requires it to be
    /// dense and round-aligned with the commits that produced it.
    #[default_options_override_fn = "verified_dwallet_checkpoint_messages_table_default_config"]
    verified_dwallet_checkpoint_messages:
        DBMap<DWalletCheckpointHeight, Vec<DWalletCheckpointMessageKind>>,

    /// write-discipline: commit-batched — same round-alignment requirement as
    /// `verified_dwallet_checkpoint_messages`, on the system-checkpoint stream.
    #[default_options_override_fn = "verified_system_checkpoint_messages_table_default_config"]
    verified_system_checkpoint_messages: DBMap<Round, Vec<SystemCheckpointMessageKind>>,

    /// Stores pending signatures
    /// The key in this table is checkpoint sequence number and an arbitrary integer
    ///
    /// write-discipline: direct — safe because local-only: the only consumer is
    /// this node's signature aggregator (`dwallet_checkpoints`), whose output is
    /// a stake-quorum certificate submitted to Sui. Which quorum subset it
    /// aggregates, and when a peer's row lands, is not observable to peers and
    /// feeds no consensus-visible decision.
    pub(crate) pending_dwallet_checkpoint_signatures:
        DBMap<(DWalletCheckpointSequenceNumber, u64), DWalletCheckpointSignatureMessage>,

    /// Maps sequence number to checkpoint summary, used by CheckpointBuilder to build checkpoint within epoch
    ///
    /// write-discipline: direct — safe because idempotent-replay: written in the
    /// same batch that deletes the `pending_dwallet_checkpoints` entries it
    /// consumed, so a crash before that batch rebuilds the identical summary
    /// from the unchanged pending queue. Consumers
    /// (`last_built_dwallet_checkpoint_message*`) read only this node's own
    /// build progress.
    pub(crate) builder_dwallet_checkpoint_message_v1:
        DBMap<DWalletCheckpointSequenceNumber, BuilderDWalletCheckpointMessage>,

    /// write-discipline: commit-batched for inserts (`write_to_batch`), so the
    /// system-checkpoint builder never sees a pending entry for a commit whose
    /// effects were lost. The build-time delete of the consumed prefix is
    /// direct and local-only — it rides the same batch as the
    /// `builder_system_checkpoint_v1` rows that replace it.
    #[default_options_override_fn = "pending_checkpoints_table_default_config"]
    pending_system_checkpoints: DBMap<SystemCheckpointHeight, PendingSystemCheckpoint>,

    /// Stores pending signatures
    /// The key in this table is ika system checkpoint sequence number and an arbitrary integer
    ///
    /// write-discipline: direct — safe because local-only: mirrors
    /// `pending_dwallet_checkpoint_signatures` on the system-checkpoint
    /// aggregator.
    pub(crate) pending_system_checkpoint_signatures:
        DBMap<(DWalletCheckpointSequenceNumber, u64), SystemCheckpointSignatureMessage>,

    /// Maps sequence number to ika system checkpoint summary, used by SystemCheckpointBuilder to build checkpoint within epoch
    ///
    /// write-discipline: direct — safe because idempotent-replay: mirrors
    /// `builder_dwallet_checkpoint_message_v1` (written in the same batch that
    /// deletes the pending entries it consumed).
    builder_system_checkpoint_v1: DBMap<DWalletCheckpointSequenceNumber, BuilderSystemCheckpoint>,

    /// Record of the capabilities advertised by each authority.
    ///
    /// write-discipline: direct — safe because pure-function-of-table:
    /// `get_capabilities_v1` folds the WHOLE table into the protocol-upgrade
    /// vote tally, with no arrival-order or size cap, and the
    /// `generation >=` guard in `record_capabilities_v1` makes a replayed
    /// receipt a no-op.
    authority_capabilities_v1: DBMap<AuthorityName, AuthorityCapabilitiesV1>,

    /// Validators that sent a EndOfPublish message in this epoch.
    ///
    /// write-discipline: commit-batched — the vote set must never run ahead of
    /// the commit that sequenced it, or the aggregator rehydrates on restart
    /// with votes the replayed commit has not re-counted and the close gate
    /// fires at a different round than peers (#1917/#1920).
    end_of_publish: DBMap<AuthorityName, ()>,

    /// Single-entry (key `0`) record of the consensus leader round at which
    /// a stake-quorum of EndOfPublish votes was first observed this epoch.
    /// Anchors the `end_of_publish_grace_rounds` (protocol config) close grace; persisted so a
    /// validator restarting mid-grace closes the epoch at the same round as
    /// its peers (the close — and the final checkpoint it builds — must be
    /// consensus-deterministic).
    ///
    /// write-discipline: commit-batched — must commit atomically with the
    /// commit that observed the quorum; the close-grace consumer
    /// (`should_close_epoch`) would otherwise anchor on a round no commit
    /// re-derives.
    end_of_publish_quorum_round: DBMap<u64, u64>,

    /// Single-entry (key `0`) record of how many authorities were in the
    /// in-memory `end_of_publish` aggregator at the commit that first
    /// observed quorum — the input to the close's `all_voted` fast path.
    ///
    /// Persisted for the same reason as `end_of_publish_quorum_round`, and it
    /// is NOT derivable from `end_of_publish` above. That table records every
    /// vote, but the live aggregator stops accepting inserts the moment
    /// quorum is reached, so its membership is a prefix of the CONSENSUS
    /// ARRIVAL ORDER — which the table does not store (its value is `()`, and
    /// iteration is by `AuthorityName`). Rebuilding the aggregator from a
    /// SURVIVING table therefore yields the FULL vote set, a larger count than
    /// a never-restarted peer holds; without this record a restarted validator
    /// could satisfy `all_voted`, skip the grace, and close the epoch at a
    /// different round than the rest of the committee. See #1917.
    ///
    /// Wiping both this and `end_of_publish` on boot removes that skew at its
    /// root rather than compensating for it: the aggregator is refilled from
    /// the replayed commits in the same consensus order, so it caps at the same
    /// member and re-pins the same count at the same commit. The record is
    /// still written, and still read back once pinned, because within a single
    /// boot the aggregator and the table diverge exactly as described above.
    ///
    /// write-discipline: commit-batched — written in the same batch as
    /// `end_of_publish_quorum_round` so the anchor and the pinned count can
    /// never disagree. This field is the canonical example of why the
    /// discipline must name its reader: the value exists ONLY because the
    /// `all_voted` consumer folds an arrival-order-capped view of the
    /// uncapped `end_of_publish` table.
    end_of_publish_quorum_voted_count: DBMap<u64, u64>,

    /// Single-entry (key `0`) marker set when the deferred epoch-close
    /// message set was emitted. Written atomically with that commit's batch.
    /// A restarting validator must not re-emit the close at a LATER commit
    /// than the one it originally decided at (which would fork its checkpoint
    /// stream from peers); the boot replay re-decides the close at that same
    /// commit and re-sets this marker there, and the epoch-store-open restore
    /// of `reconfig_state` covers a store opened without a replay behind it.
    ///
    /// write-discipline: commit-batched — the marker and the close messages it
    /// records must land or die together; the consumer is the epoch-store-open
    /// `reconfig_state` restore.
    epoch_close_emitted: DBMap<u64, ()>,

    /// Single-entry (key `0`) record of the consensus leader round at which
    /// a stake-quorum of `EpochMpcDataReadySignal`s was first observed this
    /// epoch. Anchors the `mpc_data_freeze_grace_rounds` (protocol config)
    /// freeze grace; written atomically with the observing commit's batch so
    /// every validator (including one restarting mid-grace) freezes at the
    /// same round on the same signal set.
    ///
    /// write-discipline: commit-batched — same atomicity requirement as
    /// `end_of_publish_quorum_round`; the freeze-grace consumer
    /// (`freeze_mpc_data_if_first`'s caller) must anchor on a round every
    /// validator re-derives from the same commit.
    mpc_data_ready_quorum_round: DBMap<u64, u64>,

    /// Single-entry (key `0`) record of the consensus leader round at which
    /// this epoch's mpc_data input set was frozen. Written atomically with
    /// the freeze commit's batch (alongside
    /// `frozen_validator_mpc_data_input_set`). Observability-only: nothing
    /// in the protocol reads it back — it re-seeds the
    /// `ika_dwallet_mpc_data_freeze_round` gauge after a restart, so the
    /// gauge never invents a freeze round from the current round. Absent
    /// when the freeze hasn't fired (or fired under a binary predating this
    /// table, in which case the gauge stays at its `-1` sentinel).
    ///
    /// write-discipline: commit-batched — written with the freeze partition it
    /// timestamps. Its only consumer is the gauge re-seed, but batching costs
    /// nothing here and keeps the observability claim ("this is the round the
    /// frozen set was decided at") true by construction.
    mpc_data_freeze_round: DBMap<u64, u64>,

    /// Single-key (0) table holding the `commit_timestamp_ms` of the FIRST
    /// consensus commit this validator processed this epoch — the
    /// consensus-clock anchor of the mpc_data ready-signal 3/4-epoch
    /// backstop deadline (`ready_signal_deadline_ms`). Written atomically
    /// with the first commit's batch, and re-derived on every boot because
    /// the replay starts at that same first commit — the row exists so the
    /// anchor is attributable to a commit, not because it would otherwise be
    /// unrecoverable. Identical across honest validators up to consensus
    /// determinism; consumed only for emit timing, never for signal content.
    ///
    /// write-discipline: commit-batched — the anchor must be the timestamp of a
    /// commit that actually persisted, so the ready-signal backstop deadline
    /// consumer computes the same deadline before and after a restart.
    epoch_first_commit_timestamp_ms: DBMap<u64, u64>,

    /// Contains a single key, which overrides the value of
    /// ProtocolConfig::buffer_stake_for_protocol_upgrade_bps
    ///
    /// write-discipline: direct — safe because local-only: set and cleared by
    /// this node's operator over the admin interface
    /// (`AuthorityState::set_override_protocol_upgrade_buffer_stake`). It is a
    /// deliberately per-node knob — the consumer,
    /// `get_effective_buffer_stake_bps`, only shifts when THIS validator votes
    /// to upgrade, and the protocol tolerates validators disagreeing on it.
    override_protocol_upgrade_buffer_stake: DBMap<u64, u64>,

    /// Internal presign pools, keyed by (network_encryption_key_id, session_sequence_number).
    /// Each entry contains presigns generated by that session, along with the session identifier.
    /// Presigns are consumed in order (lowest session sequence number first) within a given key ID.
    /// Value is (SessionIdentifier, Vec<(blending_index, presign_bytes)>) - the session ID and
    /// list of presigns, each tagged with its blending index (position in the inserted vector).
    ///
    /// write-discipline: direct — UNPROVEN (#1928). `prepare_pop_presign` and
    /// `insert_presigns` mutate the pool (and `internal_presign_pool_sizes`) in
    /// their OWN batch, committed independently of the consensus commit that
    /// consumed the presign. A crash between the pool batch and the commit
    /// batch lets replay re-pop and hand the sign session a DIFFERENT presign
    /// than peers bound to it — the false-malicious class — for any consumer
    /// that requires pool-head determinism. The NOA path closed this by
    /// batching the pop with an idempotent assignment record (see
    /// `noa_presign_demand_resolutions` / `assign_presign_for_demand`); the external
    /// `assign_presign` path has not been audited to the same standard.
    /// Do not add a consumer that assumes cross-validator pop identity until
    /// #1928 lands.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_ecdsa_secp256k1:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_ecdsa_secp256r1:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_eddsa: DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_taproot: DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_schnorrkel_substrate:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// Fast Schnorr (VSS) internal presign pools. Same structure as the AHE pools
    /// above: keyed by `(network_encryption_key_id: ObjectID, session_sequence_number:
    /// u64)`, value `(SessionIdentifier, Vec<(blending_index, presign_bytes)>)` — the
    /// session that produced the presigns plus its blending-index-tagged serialized
    /// presigns, consumed lowest-sequence-number-first within a given key ID. Kept
    /// separate from their AHE siblings because VSS presign bytes are a different
    /// format (a VSS sign must never pop an AHE presign, or vice versa).
    ///
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_taproot_vss:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_eddsa_vss:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `internal_presign_pool_ecdsa_secp256k1`.
    #[default_options_override_fn = "internal_presign_pool_table_default_config"]
    internal_presign_pool_schnorrkel_substrate_vss:
        DBMap<(ObjectID, u64), (SessionIdentifier, Vec<(u16, Vec<u8>)>)>,

    /// Tracks the total count of presigns in each pool by (signature algorithm, network encryption key ID).
    /// Value is the count.
    ///
    /// write-discipline: direct — UNPROVEN (#1928): always written in the same
    /// batch as the pool mutation it counts (so the counter cannot drift from
    /// the pool), but that batch is the pool's own, not the commit's — so this
    /// counter inherits the pool's re-pop exposure. `presign_pool_size` is a
    /// local scheduling input, but the divergent-pool state it reports is the
    /// suspected substrate of #1830.
    internal_presign_pool_sizes: DBMap<(DWalletSignatureAlgorithm, ObjectID), u64>,

    /// Pool slots already filled from an internal-presign output, keyed exactly
    /// like the pool entry the fill creates: `(signature algorithm, network
    /// encryption key ID, session sequence number)`. Written in the SAME batch
    /// as the fill it records.
    ///
    /// The DWallet MPC service replays every consensus round of the epoch after
    /// a restart (its round cursor is in-memory and starts unset), so the same
    /// internal-presign output reaches quorum again and would be absorbed a
    /// second time — on top of a pool that was NOT reset. Absorbing twice both
    /// double-counts `internal_presign_pool_sizes` (an inflated count reads as a
    /// full pool and suppresses top-ups until the pool physically starves) and
    /// resurrects presigns that were already served, which would hand the same
    /// presign to a second on-chain presign id.
    ///
    /// write-discipline: direct — safe because idempotent-replay: this marker
    /// is what MAKES `insert_presigns` idempotent — written in the fill's own
    /// batch and consulted before absorbing, so a replayed fill is a no-op;
    /// protects `internal_presign_pool_sizes` and the top-up decision (#1934).
    filled_presign_pool_slots: DBMap<(DWalletSignatureAlgorithm, ObjectID, u64), ()>,

    /// Presign served to each global presign request, keyed by the request's
    /// consensus-assigned session sequence number. Written in the SAME batch as
    /// the pop that produced it, and read back instead of popping when the
    /// request is seen again.
    ///
    /// The pop cannot stand alone: the replayed pool is not the pool the
    /// original run popped from (surviving entries whose sequence number is
    /// lower than the head at that round win the pop, and internal presign
    /// sessions in one batch complete in consensus order, not sequence order),
    /// so a bare re-pop serves a DIFFERENT presign than the never-crashed peers
    /// put in their checkpoint message for the same presign id. Per-epoch, like
    /// `noa_presign_demand_resolutions`, whose idempotency this mirrors.
    ///
    /// write-discipline: direct — safe because idempotent-replay: written in
    /// the pop's own batch and read back on a re-served sequence number, so a
    /// replayed request returns the identical presign; protects the
    /// checkpoint-message bytes that must match across the committee (#1934).
    served_global_presigns: DBMap<u64, (SessionIdentifier, u16, Vec<u8>)>,

    /// Terminal resolution of each NOA sign demand, keyed by the demand's
    /// `demand_id` digest: the presign assigned to it, or a marker that the
    /// park bound dropped it. Written by the consensus-order drain and read by
    /// the sign-session instantiation, so all validators pair the same presign
    /// with the same demand — and give up on the same demands. Value is a
    /// [`NoaPresignDemandResolution`]. Per-epoch (physically dropped on
    /// rotation) like `used_presigns`; the demand queue that feeds it is
    /// rebuilt empty when the per-epoch service restarts, and idempotency here
    /// makes re-drains safe.
    ///
    /// write-discipline: direct — safe because idempotent-replay: keyed by the
    /// demand digest and written in the SAME batch as the pool pop and the
    /// `used_presigns` marker (`assign_presign_for_demand`), so a re-drain after a
    /// crash returns the recorded assignment instead of popping again. This is
    /// the shape the raw pool tables lack (#1928): the consumer that needs
    /// cross-validator identity — sign-session instantiation — reads THIS
    /// table, never the pool head. The drop marker needs the same durability
    /// for the same reason: the pool is not rewound by the replay, so a drop
    /// held only in memory would let the replayed drain pop for a demand the
    /// committee had already abandoned.
    noa_presign_demand_resolutions: DBMap<[u8; 32], NoaPresignDemandResolution>,

    /// Tracks presigns that have been consumed for signing.
    /// Key: (SessionIdentifier, blending_index) - uniquely identifies a single presign within
    /// the blended vector produced by the presign session that created it.
    /// Value: () - just marks it as used
    /// Once a presign is used, it should never be used again.
    ///
    /// write-discipline: direct — safe because idempotent-replay: a monotone
    /// marker keyed by the presign it retires, written either inside
    /// `assign_presign_for_demand`'s pop batch or standalone by
    /// `mark_presign_as_used`. Re-writing it is a no-op, and the consumer
    /// (`is_presign_used`) only ever gates THIS node's reuse of a presign it
    /// already consumed.
    used_presigns: DBMap<(SessionIdentifier, u16), ()>,

    /// Assigned presigns pools for external presigns.
    /// Key: (SessionIdentifier, blending_index) - uniquely identifies this assigned presign
    /// Value: AssignedPresign - contains presign data, user verification key, dwallet_id (for non-global), and epoch
    /// These expire at the end of the epoch and are used for external sign requests.
    ///
    /// write-discipline: direct — UNPROVEN (#1928): the insert rides
    /// `assign_presign`'s pop batch (so an assignment can never exist without
    /// its pool removal), but that batch is the pool's own, not the consuming
    /// commit's — so WHICH presign a replayed assignment binds inherits the
    /// pool's re-pop exposure. Unlike `noa_presign_demand_resolutions` the key is the
    /// popped presign, not the request, so a re-pop yields a new row rather
    /// than hitting an idempotence guard.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_ecdsa_secp256k1: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_ecdsa_secp256r1: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_eddsa: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_taproot: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_schnorrkel_substrate: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// Fast Schnorr (VSS) assigned-presign pools (separate from AHE siblings).
    ///
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_taproot_vss: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_eddsa_vss: DBMap<(SessionIdentifier, u16), AssignedPresign>,
    /// write-discipline: direct — UNPROVEN (#1928), see
    /// `assigned_presigns_ecdsa_secp256k1`.
    #[default_options_override_fn = "assigned_presign_pool_table_default_config"]
    assigned_presigns_schnorrkel_substrate_vss: DBMap<(SessionIdentifier, u16), AssignedPresign>,

    /// Per-validator secret nonce shares from Fast Schnorr (VSS) presign sessions,
    /// persisted between presign-finalize and sign so the sign party can rebuild its
    /// `PrivateInput`. AHE Schnorr has no such secret presign output (its nonce lives
    /// encrypted inside the on-chain presign), so only VSS sessions write here.
    ///
    /// Key: `(presign session_id, blending_index)` — uniquely identifies a single
    ///      blended presign, matching the pool/`used_presigns` keying. Carried from
    ///      the presign pop, so the sign no longer re-parses it from the public presign.
    /// Value: `bcs(PrivatePresignOutput)` — the single output for that blending index.
    ///
    /// Self-prunes on epoch rotation (per-epoch physical DB drop). A missing row at
    /// sign time is a soft-fail that excludes this validator's contribution, not a
    /// hard error — the 2f+1 quorum absorbs it.
    ///
    /// write-discipline: direct — safe because local-only: this validator's own
    /// secret share, never compared across validators. The consumer
    /// (`get_presign_private_output`, at sign-party build) soft-fails on a
    /// missing row, so a write lost to a crash costs one contribution, not
    /// divergence.
    presign_private_outputs: DBMap<(CommitmentSizedNumber, u16), Vec<u8>>,

    /// Latest `ValidatorMpcDataAnnouncement` observed for each
    /// current-committee validator this epoch, signed with their
    /// authority BLS key. The consensus handler verifies the
    /// signature against `self.committee()` before insert, and only
    /// the strictly-newer-timestamp entry per validator wins (replays
    /// and duplicates are dropped). Off-chain consumers (later steps)
    /// freeze a snapshot of this table when 2f+1 ready signals land.
    ///
    /// write-discipline: direct — safe because local-only + idempotent-replay:
    /// the strict-newer-timestamp guard in `insert_validator_mpc_data_announcement`
    /// makes a replayed announcement a no-op, and no consensus-visible decision
    /// reads it — `freeze_mpc_data_if_first` deliberately tallies the ready
    /// signals ONLY (reading this table there would let a locally-dropped
    /// relayed announcement shrink one validator's frozen set). Its consumers
    /// are this node's blob fetcher and its own emitted `validated_peers`.
    pub(crate) validator_mpc_data_announcements: DBMap<AuthorityName, ValidatorMpcDataAnnouncement>,

    /// Map signer -> `EpochMpcDataReadySignal` for this epoch.
    /// We keep the full signal (not just the unit value) so the
    /// freeze gate can read each signer's `validated_peers` set
    /// when tallying per-announcer attestations. Re-broadcasts
    /// from the same signer are last-write-wins; in practice an
    /// honest validator only emits once per epoch.
    ///
    /// write-discipline: direct — safe because pure-function-of-table: every
    /// consensus-visible consumer (`freeze_mpc_data_if_first`'s tally, the
    /// ready-quorum anchor) folds the WHOLE table with no arrival-order or
    /// size cap, so a crash can only leave it holding the replayed commit's
    /// own signals — which the original run also counted before deciding.
    /// Adding a consumer that snapshots or caps this table reintroduces the
    /// #1917 shape; the decision it feeds must then be pinned through
    /// `ConsensusCommitOutput` instead. One single-row consumer is exempt
    /// from the fold-the-whole-table reason because it is local-only:
    /// `MpcDataAnnouncementSender::new` reads this signer's OWN row to seed
    /// its re-emit pacing after a restart (issue #1942) — nothing
    /// consensus-visible reads that seed, and reading a stale row only
    /// delays this node's own re-emit.
    pub(crate) epoch_mpc_data_ready_signals:
        DBMap<AuthorityName, ika_types::validator_metadata::EpochMpcDataReadySignal>,

    /// Frozen `validator -> blob_hash` snapshot taken at the
    /// consensus position where the first quorum of
    /// `EpochMpcDataReadySignal`s landed this epoch. Membership is
    /// per-announcer attestation-gated: a validator V appears in
    /// this map iff a stake-quorum of signers attested via
    /// `validated_peers` to having V's blob locally + decode-
    /// validated. Announcers that don't reach that threshold are
    /// recorded in `epoch_excluded_validators` instead.
    /// Empty until quorum; populated once and never modified within
    /// the epoch (`freeze_mpc_data_if_first` is idempotent on a
    /// non-empty table). Written through the freeze commit's
    /// `ConsensusCommitOutput` batch — never per-row — so the whole
    /// partition lands atomically with the commit's processed-markers
    /// (issue #1829: a partial write latched a shrunken, divergent
    /// frozen set forever).
    ///
    /// write-discipline: commit-batched — see above; the freeze is
    /// once-per-epoch and never revisited, so a partial write is permanent.
    pub(crate) frozen_validator_mpc_data_input_set: DBMap<AuthorityName, [u8; 32]>,

    /// Announcers that crossed the freeze gate's "announcement
    /// present" test but didn't have a quorum of signers attest to
    /// having a valid blob for them. Written at the same logical
    /// point as `frozen_validator_mpc_data_input_set`. The set is
    /// consensus-deterministic (every honest validator computes
    /// the same tally from the same consensus-ordered signals);
    /// downstream MPC / handoff consumers treat membership here
    /// as "this validator is excluded from the working set for
    /// this epoch — same semantics as today's `bad chain mpc_data
    /// → ignore that validator`."
    ///
    /// write-discipline: commit-batched — the other half of the freeze
    /// partition; must land in the same batch as
    /// `frozen_validator_mpc_data_input_set` or the two disagree about who is
    /// in the epoch's working set.
    pub(crate) epoch_excluded_validators: DBMap<AuthorityName, ()>,

    /// Per-signer Ed25519 signatures over this epoch's handoff
    /// attestation, captured from consensus order. Verified against
    /// the validator's locally-computed expected attestation +
    /// `ConsensusPubkeyProvider` before insert; replays are no-ops.
    /// On quorum, the in-memory `HandoffAggregator` produces a
    /// `CertifiedHandoffAttestation` which is persisted forever in
    /// `AuthorityPerpetualTables` (perpetual persist lands in step
    /// 7c).
    ///
    /// write-discipline: commit-batched (#1927). Every writer — the consensus
    /// `EndOfPublishV2` arm, the buffered drain in
    /// `install_expected_handoff_attestation`, and that same function's
    /// stale-row cleanup — stages into `staged_handoff_signature_rows`, which
    /// the next commit folds into its `ConsensusCommitOutput`. So a row is
    /// durable exactly when the commit it was staged under is, and the close
    /// gate that sums this table (`handoff_signatures_meet_quorum`) reads a
    /// state attributable to a commit rather than to whatever had reached
    /// RocksDB by the instant it looked.
    ///
    /// This does NOT make the gate a pure function of the sequence: WHICH
    /// commit a drained row lands under still follows this validator's local
    /// attestation install, so peers can still cross quorum at different
    /// commits. Retiring that residue is the sequence-pure tally in
    /// dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md (item 3),
    /// which has its own prerequisites; see the NOTE at the gate's call site
    /// for what holds close-safety in the meantime.
    pub(crate) handoff_signatures: DBMap<AuthorityName, Ed25519Signature>,

    /// Local cache of network DKG output digests for this epoch,
    /// keyed by `dwallet_network_encryption_key_id`. Populated by
    /// the MPC producer when it builds an output for consensus;
    /// consumed by the handoff trigger when assembling the
    /// attestation items list. Blob bytes go into the perpetual
    /// `mpc_artifact_blobs` table so peers can fetch them by digest.
    ///
    /// write-discipline: direct — safe because content-addressed: the value is
    /// the Blake2b256 digest of the output bytes, so any rewrite of the same
    /// logical output stores the same bytes and a replay is a no-op. The
    /// cross-validator agreement the handoff-attestation consumer needs comes
    /// from the canonical encoding of the output (see the DETERMINISM note on
    /// `cache_protocol_output`), never from when the row landed.
    pub(crate) network_dkg_output_digests: DBMap<ObjectID, [u8; 32]>,

    /// Local cache of network reconfiguration output digests for
    /// this epoch — same shape and lifecycle as
    /// `network_dkg_output_digests`. Per-epoch (not perpetual)
    /// because a key's reconfig output is by definition per-epoch.
    ///
    /// write-discipline: direct — safe because content-addressed, exactly as
    /// `network_dkg_output_digests`.
    pub(crate) network_reconfiguration_output_digests: DBMap<ObjectID, [u8; 32]>,
}

epoch_state_registry! {
    Derived consensus_message_processed:
        "the marker set is written by the fold itself, one row per transaction the \
         replayed commit re-processes; keeping it would make the replay see every \
         transaction as already handled and produce an empty epoch",
    Derived last_consensus_stats:
        "the fold's own cursor and per-author message tallies — a pure running \
         aggregate of the commits replayed so far",
    Derived pending_dwallet_checkpoints:
        "the MPC service builds these from the per-round streams it re-derives; \
         keyed by consensus round, so a rebuild lands the identical heights",
    Derived verified_dwallet_checkpoint_messages:
        "the fold's own output for the commit (session results promoted to \
         checkpoint messages), not an input to it",
    Derived verified_system_checkpoint_messages:
        "same as the dWallet stream, on the system-checkpoint side",
    Derived pending_dwallet_checkpoint_signatures:
        "peers' checkpoint signatures arrive as sequenced \
         `DWalletCheckpointSignature` transactions, so the replay re-collects the \
         same set",
    Derived builder_dwallet_checkpoint_message_v1:
        "the builder's output over the rebuilt pending queue; deterministic in the \
         queue, so it rebuilds byte-identically",
    Derived pending_system_checkpoints:
        "written through the commit batch by the fold",
    Derived pending_system_checkpoint_signatures:
        "mirrors `pending_dwallet_checkpoint_signatures` on the system-checkpoint \
         aggregator",
    Derived builder_system_checkpoint_v1:
        "mirrors `builder_dwallet_checkpoint_message_v1`",
    Derived authority_capabilities_v1:
        "every row comes from a sequenced `CapabilityNotificationV1`",
    Derived end_of_publish:
        "the vote set is exactly the sequenced `EndOfPublish*` senders",
    Derived end_of_publish_quorum_round:
        "the close-grace anchor is the round of the commit that first observed \
         quorum, which the replay re-observes at the same commit",
    Derived end_of_publish_quorum_voted_count:
        "pinned at the quorum-observing commit from an arrival-order-capped \
         aggregator; wiping is what makes the re-derivation exact, because the \
         aggregator is refilled in the same consensus order and stops at the same \
         member (this is the #1917 divergence removed at the root rather than \
         patched)",
    Derived epoch_close_emitted:
        "set by the fold in the closing commit's batch; the replay re-decides the \
         close at the same commit",
    Derived mpc_data_ready_quorum_round:
        "the freeze-grace anchor, re-observed at the same commit",
    Derived mpc_data_freeze_round:
        "observability re-seed of the freeze round, re-derived with the freeze",
    Derived epoch_first_commit_timestamp_ms:
        "the replay starts at the epoch's first commit, so the anchor it recorded \
         is directly re-observable — the reason this table was persisted at all \
         (replay used to resume mid-epoch) no longer applies",
    Preserved override_protocol_upgrade_buffer_stake:
        "an operator-set per-node knob written over the admin interface; no commit \
         carries it",
    Preserved internal_presign_pool_ecdsa_secp256k1:
        "presign material this node computed; the replay does not re-run the \
         cryptography (the catch-up gate suppresses it), and the pops that consume \
         the pool are not all consensus-ordered, so a rebuilt pool would serve \
         different presigns than never-crashed peers (#1928)",
    Preserved internal_presign_pool_ecdsa_secp256r1:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_eddsa:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_taproot:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_schnorrkel_substrate:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_taproot_vss:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_eddsa_vss:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_schnorrkel_substrate_vss:
        "see `internal_presign_pool_ecdsa_secp256k1`",
    Preserved internal_presign_pool_sizes:
        "counts the preserved pools and is written in their batches; wiping it \
         while the pools survive would report empty pools and trigger endless \
         top-ups",
    Preserved filled_presign_pool_slots:
        "the marker that makes a replayed internal-presign fill a no-op against \
         the preserved pool; wiping it is the double-accumulation failure this \
         classification exists to prevent (#1934)",
    Preserved served_global_presigns:
        "records which presign was served for a request so a re-served sequence \
         number returns the identical bytes; without it the replay re-pops a \
         different presign and this node's checkpoint message stops matching the \
         committee's (#1934)",
    Preserved noa_presign_demand_resolutions:
        "binds a demand to a presign popped from the preserved pool, and records \
         the demands the park bound abandoned; a wipe would re-pop for demands the \
         committee already resolved",
    Preserved used_presigns:
        "the monotone retirement marker over the preserved pool; losing it lets \
         the same presign be consumed twice",
    Preserved assigned_presigns_ecdsa_secp256k1:
        "an assignment carved out of the preserved pool — the pool row is already \
         gone, so the assignment is the only remaining copy",
    Preserved assigned_presigns_ecdsa_secp256r1:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_eddsa:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_taproot:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_schnorrkel_substrate:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_taproot_vss:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_eddsa_vss:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved assigned_presigns_schnorrkel_substrate_vss:
        "see `assigned_presigns_ecdsa_secp256k1`",
    Preserved presign_private_outputs:
        "this validator's own secret nonce shares from VSS presign sessions — \
         never published, so no commit can reproduce them",
    Derived validator_mpc_data_announcements:
        "every row comes from a sequenced (or sequenced-relayed) announcement",
    Derived epoch_mpc_data_ready_signals:
        "every row comes from a sequenced `EpochMpcDataReadySignal`",
    Derived frozen_validator_mpc_data_input_set:
        "the freeze partition is decided at a commit boundary from the ready \
         signals; the replay re-decides it at the same commit",
    Derived epoch_excluded_validators:
        "the other half of the freeze partition",
    Derived handoff_signatures:
        "rows come from sequenced `EndOfPublishV2` bundles. Preserving them would \
         let the epoch-close gate read signatures the replayed commits have not \
         re-counted, which is the shape #1917 was; the buffered-drain path \
         re-stages every bundle once this node's expected attestation installs",
    Preserved network_dkg_output_digests:
        "a content-addressed cache of protocol outputs this node computed or read \
         from Sui/peers; the replay does not re-run the cryptography, and the \
         handoff attestation reads it",
    Preserved network_reconfiguration_output_digests:
        "see `network_dkg_output_digests`",
}

/// Deletes every row of `table`, in bounded chunks, and returns how many were
/// removed.
///
/// Point deletes rather than a range delete: `Map::schedule_delete_all` issues
/// a RocksDB range delete over `[first_key, last_key)` and so leaves the last
/// row in place. Chunking keeps the wipe's memory flat on the dense per-round
/// tables, which hold one row per consensus round of the epoch.
fn wipe_table<K, V>(table: &DBMap<K, V>) -> IkaResult<u64>
where
    K: Serialize + serde::de::DeserializeOwned,
    V: Serialize + serde::de::DeserializeOwned,
{
    const WIPE_CHUNK_ROWS: usize = 10_000;

    let mut removed = 0_u64;
    loop {
        let keys = table
            .safe_iter()
            .take(WIPE_CHUNK_ROWS)
            .map(|row| row.map(|(key, _)| key))
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Ok(removed);
        }
        removed += keys.len() as u64;
        let mut batch = table.batch();
        batch.delete_batch(table, keys)?;
        batch.write()?;
    }
}

fn verified_dwallet_checkpoint_messages_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn verified_system_checkpoint_messages_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn pending_checkpoints_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_large_values_no_scan(1 << 10)
}

fn internal_presign_pool_table_default_config() -> DBOptions {
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
    ) -> &PresignPoolTable {
        match signature_algorithm {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => {
                &self.internal_presign_pool_ecdsa_secp256k1
            }
            DWalletSignatureAlgorithm::ECDSASecp256r1 => {
                &self.internal_presign_pool_ecdsa_secp256r1
            }
            DWalletSignatureAlgorithm::EdDSA => &self.internal_presign_pool_eddsa,
            DWalletSignatureAlgorithm::Taproot => &self.internal_presign_pool_taproot,
            DWalletSignatureAlgorithm::Schnorrkel => {
                &self.internal_presign_pool_schnorrkel_substrate
            }
            DWalletSignatureAlgorithm::TaprootVSS => &self.internal_presign_pool_taproot_vss,
            DWalletSignatureAlgorithm::EdDSAVSS => &self.internal_presign_pool_eddsa_vss,
            DWalletSignatureAlgorithm::SchnorrkelVSS => {
                &self.internal_presign_pool_schnorrkel_substrate_vss
            }
        }
    }

    /// Inserts presigns into the pool for the given signature algorithm and network encryption key.
    /// The presigns are keyed by (network_encryption_key_id, session_sequence_number).
    ///
    /// Idempotent per pool slot: the second and later calls for a given
    /// `(signature_algorithm, dwallet_network_encryption_key_id,
    /// session_sequence_number)` are no-ops. This is load-bearing, not
    /// defensive — the DWallet MPC service replays the whole epoch's consensus
    /// rounds after a restart, so every internal-presign output that already
    /// filled a slot reaches quorum a second time against a pool that was not
    /// reset. See `filled_presign_pool_slots`.
    pub fn insert_presigns(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        session_sequence_number: u64,
        session_identifier: SessionIdentifier,
        presigns: Vec<Vec<u8>>,
    ) -> IkaResult<()> {
        let slot_key = (
            signature_algorithm,
            dwallet_network_encryption_key_id,
            session_sequence_number,
        );
        if self.filled_presign_pool_slots.contains_key(&slot_key)? {
            debug!(
                ?signature_algorithm,
                ?dwallet_network_encryption_key_id,
                session_sequence_number,
                ?session_identifier,
                "internal presign output re-absorbed after a replay; pool slot already filled"
            );
            return Ok(());
        }

        let num_presigns = presigns.len() as u64;
        let table = self.presign_pool_table(signature_algorithm);
        let key = (dwallet_network_encryption_key_id, session_sequence_number);

        // Tag each presign with its blending index (its position in the inserted vector).
        let blended_presigns: Vec<(u16, Vec<u8>)> = presigns
            .into_iter()
            .enumerate()
            .map(|(blending_index, presign)| (blending_index as u16, presign))
            .collect();

        let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
        let current_size = self
            .internal_presign_pool_sizes
            .get(&size_key)?
            .unwrap_or(0);

        // Batch all three writes atomically: a fill that landed without its
        // slot marker would be re-absorbed on the next replay, and a marker
        // that landed without its fill would lose the presigns entirely.
        let mut batch = table.batch();
        batch.insert_batch(table, [(&key, &(session_identifier, blended_presigns))])?;
        batch.insert_batch(
            &self.internal_presign_pool_sizes,
            [(&size_key, &(current_size + num_presigns))],
        )?;
        batch.insert_batch(&self.filled_presign_pool_slots, [(&slot_key, &())])?;
        batch.write()?;

        Ok(())
    }

    /// Highest `session_sequence_number` ever recorded in
    /// `filled_presign_pool_slots` for `(signature_algorithm, key)`, or `None`
    /// when the pool has no fill yet this epoch. One reverse seek over the
    /// pool's slot-key range — the slot markers are written on every fill (and
    /// re-confirmed by the post-restart consensus replay), so this is the
    /// durable high-water mark of the pool's ordinal stream (#1952).
    pub fn max_filled_presign_pool_slot(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<u64>> {
        let lower = (
            signature_algorithm,
            dwallet_network_encryption_key_id,
            u64::MIN,
        );
        let upper = (
            signature_algorithm,
            dwallet_network_encryption_key_id,
            u64::MAX,
        );
        Ok(self
            .filled_presign_pool_slots
            .reversed_safe_iter_with_bounds(Some(lower), Some(upper))?
            .next()
            .transpose()?
            .map(|((_, _, session_sequence_number), ())| session_sequence_number))
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

    /// Test-only raw pool pop, for tests that inspect pool contents directly.
    ///
    /// No REPLAYED path pops bare: every consumer whose demand stream is
    /// replayed after a restart assigns through an idempotent
    /// [`PresignDemand`], because a bare pop on replay binds a different
    /// presign than peers bound. ([`Self::assign_presign`] does still pop
    /// unconditionally, but it has no consumer; a future one must gain a
    /// demand identity before it can be replay-safe.)
    #[cfg(test)]
    pub fn pop_presign_for_testing(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<(SessionIdentifier, u16, Vec<u8>)>> {
        let Some((batch, session_identifier, blending_index, presign)) =
            self.prepare_pop_presign(signature_algorithm, dwallet_network_encryption_key_id)?
        else {
            return Ok(None);
        };
        batch.write()?;
        Ok(Some((session_identifier, blending_index, presign)))
    }

    /// Assign a presign to a demand — atomically, and idempotently in the
    /// demand's identity.
    ///
    /// A re-seen demand returns the presign it was already given WITHOUT
    /// popping. That is what makes the per-epoch replay every consumer
    /// performs after a restart safe: a bare re-pop would bind a different
    /// presign than the never-crashed peers bound (fills complete out of
    /// sequence order, so the pool head moves), and the checkpoint or
    /// attestation built from it would be byte-divergent from an honest
    /// validator.
    ///
    /// The pop and the record land in ONE committed batch, which is why
    /// [`Self::prepare_pop_presign`] hands back an UNCOMMITTED batch for this
    /// method to extend. Committing them separately would open a crash window
    /// between the two writes: the pool would be advanced with no record of
    /// where the presign went, so the replay would pop again — the very
    /// divergence the identity key exists to prevent.
    /// A NOA demand carries a second terminal outcome the global arm has no
    /// equivalent of: the park bound can DROP it (see
    /// [`NoaPresignDemandResolution`]). That drop is recorded in the same
    /// per-demand table as its assignment, so this method reports it rather
    /// than popping — which is what stops a restart's replay from assigning a
    /// presign for a demand the whole committee already gave up on.
    pub fn assign_presign_for_demand(
        &self,
        demand: &PresignDemand,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<PresignAssignmentOutcome> {
        // Already resolved? Report it; never pop again.
        match demand {
            PresignDemand::GlobalRequest {
                session_sequence_number,
            } => {
                if let Some((session_identifier, blending_index, presign)) =
                    self.served_global_presigns.get(session_sequence_number)?
                {
                    return Ok(PresignAssignmentOutcome::Assigned {
                        session_identifier,
                        blending_index,
                        presign,
                    });
                }
            }
            PresignDemand::Noa { demand_id } => {
                match self
                    .noa_presign_demand_resolutions
                    .get(&demand_id.digest())?
                {
                    Some(NoaPresignDemandResolution::Assigned {
                        session_identifier,
                        blending_index,
                        presign,
                        ..
                    }) => {
                        return Ok(PresignAssignmentOutcome::Assigned {
                            session_identifier,
                            blending_index,
                            presign,
                        });
                    }
                    Some(NoaPresignDemandResolution::Evicted) => {
                        return Ok(PresignAssignmentOutcome::Evicted);
                    }
                    None => {}
                }
            }
        }

        let Some((mut batch, session_identifier, blending_index, presign)) =
            self.prepare_pop_presign(signature_algorithm, dwallet_network_encryption_key_id)?
        else {
            return Ok(PresignAssignmentOutcome::PoolEmpty);
        };

        match demand {
            PresignDemand::GlobalRequest {
                session_sequence_number,
            } => {
                batch.insert_batch(
                    &self.served_global_presigns,
                    [(
                        session_sequence_number,
                        &(session_identifier, blending_index, presign.clone()),
                    )],
                )?;
            }
            PresignDemand::Noa { demand_id } => {
                batch.insert_batch(
                    &self.noa_presign_demand_resolutions,
                    [(
                        &demand_id.digest(),
                        &NoaPresignDemandResolution::Assigned {
                            session_identifier,
                            blending_index,
                            presign: presign.clone(),
                            network_encryption_key_id: dwallet_network_encryption_key_id,
                        },
                    )],
                )?;
                // Mark the popped presign used, in the SAME batch as the
                // assignment. This is the point of actual consumption (the pool
                // pop happens in `prepare_pop_presign` above); the sign session
                // later reads the presign from the assignment table and never
                // pops again, so this is the only place the consumption is
                // recorded.
                batch.insert_batch(
                    &self.used_presigns,
                    [(&(session_identifier, blending_index), &())],
                )?;
            }
        }
        batch.write()?;
        Ok(PresignAssignmentOutcome::Assigned {
            session_identifier,
            blending_index,
            presign,
        })
    }

    /// Prepares a presign pop without committing, returning the uncommitted batch.
    /// Callers can extend the batch with additional operations before committing,
    /// ensuring atomicity across the pop and any follow-up writes (e.g. `assign_presign`).
    fn prepare_pop_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> IkaResult<Option<PreparedPresignPop>> {
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
            // This shouldn't happen, but handle it gracefully: remove the
            // corrupted entry and decrement the size counter atomically.
            ika_types::report_invariant_violation!(
                "presign_pool_empty_entry",
                ?signature_algorithm,
                ?dwallet_network_encryption_key_id,
                "prepare_pop_presign: found entry with empty presigns vec, removing"
            );
            let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
            let current_size = self
                .internal_presign_pool_sizes
                .get(&size_key)?
                .unwrap_or(0);
            let mut batch = table.batch();
            batch.delete_batch(table, [&key])?;
            if current_size > 0 {
                batch.insert_batch(
                    &self.internal_presign_pool_sizes,
                    [(&size_key, &(current_size - 1))],
                )?;
            }
            batch.write()?;
            return Ok(None);
        }

        // Remove the first presign from the vec, along with its blending index.
        let (blending_index, presign) = presigns.remove(0);

        // Read size counter before batch
        let size_key = (signature_algorithm, dwallet_network_encryption_key_id);
        let current_size = self
            .internal_presign_pool_sizes
            .get(&size_key)?
            .unwrap_or(0);
        if current_size == 0 {
            warn!(
                ?signature_algorithm,
                ?dwallet_network_encryption_key_id,
                "pop_presign: size counter missing or zero but presign existed in pool"
            );
        }

        // Batch all writes: pool update/remove + size counter decrement.
        // The batch is NOT committed here — the caller decides when to write.
        let mut batch = table.batch();
        if presigns.is_empty() {
            batch.delete_batch(table, [&key])?;
        } else {
            batch.insert_batch(table, [(&key, &(session_identifier, presigns))])?;
        }
        batch.insert_batch(
            &self.internal_presign_pool_sizes,
            [(&size_key, &(current_size.saturating_sub(1)))],
        )?;

        Ok(Some((batch, session_identifier, blending_index, presign)))
    }

    /// Marks a presign as used so it cannot be reused.
    pub fn mark_presign_as_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<()> {
        self.used_presigns
            .insert(&(presign_session_id, presign_blending_index), &())?;
        Ok(())
    }

    /// Checks if a presign has already been used.
    pub fn is_presign_used(
        &self,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
    ) -> IkaResult<bool> {
        Ok(self
            .used_presigns
            .contains_key(&(presign_session_id, presign_blending_index))?)
    }

    pub fn store_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
        private_output: Vec<u8>,
    ) -> IkaResult<()> {
        self.presign_private_outputs.insert(
            &(presign_session_id, presign_blending_index),
            &private_output,
        )?;
        Ok(())
    }

    pub fn get_presign_private_output(
        &self,
        presign_session_id: CommitmentSizedNumber,
        presign_blending_index: u16,
    ) -> IkaResult<Option<Vec<u8>>> {
        Ok(self
            .presign_private_outputs
            .get(&(presign_session_id, presign_blending_index))?)
    }

    /// Returns a reference to the assigned presign pool table for the given signature algorithm.
    fn assigned_presign_pool_table(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> &DBMap<(SessionIdentifier, u16), AssignedPresign> {
        match signature_algorithm {
            DWalletSignatureAlgorithm::ECDSASecp256k1 => &self.assigned_presigns_ecdsa_secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256r1 => &self.assigned_presigns_ecdsa_secp256r1,
            DWalletSignatureAlgorithm::EdDSA => &self.assigned_presigns_eddsa,
            DWalletSignatureAlgorithm::Taproot => &self.assigned_presigns_taproot,
            DWalletSignatureAlgorithm::Schnorrkel => &self.assigned_presigns_schnorrkel_substrate,
            DWalletSignatureAlgorithm::TaprootVSS => &self.assigned_presigns_taproot_vss,
            DWalletSignatureAlgorithm::EdDSAVSS => &self.assigned_presigns_eddsa_vss,
            DWalletSignatureAlgorithm::SchnorrkelVSS => {
                &self.assigned_presigns_schnorrkel_substrate_vss
            }
        }
    }

    /// Assigns a presign to a user by atomically moving it from the internal pool to the
    /// assigned pool. Uses a single batch write to ensure the presign is never lost.
    pub fn assign_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        user_verification_key: Option<Vec<u8>>,
        dwallet_id: Option<ObjectID>,
        current_epoch: u64,
    ) -> IkaResult<Option<(SessionIdentifier, u16)>> {
        let Some((mut batch, session_identifier, blending_index, presign)) =
            self.prepare_pop_presign(signature_algorithm, dwallet_network_encryption_key_id)?
        else {
            return Ok(None);
        };

        let assigned_presign = AssignedPresign {
            session_identifier,
            blending_index,
            presign,
            user_verification_key,
            dwallet_id,
            assigned_epoch: current_epoch,
        };

        // Extend the pop batch with the assigned pool insert, then commit atomically.
        let assigned_table = self.assigned_presign_pool_table(signature_algorithm);
        batch.insert_batch(
            assigned_table,
            [(&(session_identifier, blending_index), &assigned_presign)],
        )?;
        batch.write()?;

        Ok(Some((session_identifier, blending_index)))
    }

    /// Durably record that the park bound dropped a NOA sign demand.
    ///
    /// Idempotent, and never replaces an existing resolution: an assignment
    /// already recorded for this demand is the truth the whole committee holds,
    /// and a second drop marker is the same fact written twice. The read and
    /// the write need not be one batch — the drain is the single writer of this
    /// table, and it only calls this after the same round's
    /// `assign_presign_for_demand` reported an empty pool.
    pub fn evict_noa_presign_demand(&self, demand_id: &NOAPresignDemandId) -> IkaResult<()> {
        let digest = demand_id.digest();
        if self.noa_presign_demand_resolutions.contains_key(&digest)? {
            return Ok(());
        }
        Ok(self
            .noa_presign_demand_resolutions
            .insert(&digest, &NoaPresignDemandResolution::Evicted)?)
    }

    /// Retrieves an assigned presign by session identifier, blending index, and signature algorithm.
    pub fn get_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>> {
        let table = self.assigned_presign_pool_table(signature_algorithm);
        Ok(table.get(&(session_identifier, blending_index))?)
    }

    /// Pops an assigned presign from the pool. Used when the presign is consumed for signing.
    pub fn pop_assigned_presign(
        &self,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_identifier: SessionIdentifier,
        blending_index: u16,
    ) -> IkaResult<Option<AssignedPresign>> {
        let table = self.assigned_presign_pool_table(signature_algorithm);
        let assigned_presign = table.get(&(session_identifier, blending_index))?;
        if assigned_presign.is_some() {
            table.remove(&(session_identifier, blending_index))?;
        }
        Ok(assigned_presign)
    }
}

impl AuthorityPerEpochStore {
    fn should_accept_tx(&self) -> bool {
        let reconfig_state = self.reconfig_state.read();
        !matches!(&reconfig_state.status, &ReconfigCertStatus::RejectAllTx)
    }

    /// Opens the epoch's store, deleting every derived table on the way in.
    ///
    /// Takes its inputs as a struct so the one DECISION at this call site —
    /// whether the derived tables are wiped — is the thing a reader sees,
    /// rather than the ninth positional argument behind eight pieces of
    /// identity and configuration.
    ///
    /// The wipe is unconditional because there is no node on which it is
    /// anything but a no-op or the right thing. Every writer of a derived
    /// table — the consensus fold, the MPC drain, the checkpoint builders, and
    /// `IkaTxValidator`'s checkpoint-signature notify — lives inside the
    /// validator components, which only start for a committee member running
    /// in validator mode; on any other node those tables are empty. State sync
    /// writes no epoch-store table at all (its certificates and watermarks are
    /// in `DWalletCheckpointStore`, a separate database), which is why the
    /// preserved-class state-sync artifacts are not affected either.
    #[instrument(name = "AuthorityPerEpochStore::new", level = "error", skip_all, fields(epoch = params.committee.epoch))]
    pub fn new(params: EpochStoreParams) -> IkaResult<Arc<Self>> {
        Self::open(params, /* wipe_derived_state */ true)
    }

    /// Opens the store WITHOUT deleting its derived tables.
    ///
    /// Test-only, and only for tests whose subject is the durable write
    /// discipline itself — that a row written through
    /// `ConsensusCommitOutput`'s batch survives a crash at any point, and that
    /// reopening rehydrates the in-memory state built from it
    /// (`dev-docs/conventions/epoch-table-write-discipline.md`). That property
    /// still holds and is still load-bearing within one boot; it is simply not
    /// what a production reopen exercises any more, because production reopens
    /// wipe and replay. Using this outside such a test would assert against a
    /// state no validator ever reaches.
    #[cfg(test)]
    pub(crate) fn new_retaining_derived_state_for_testing(
        params: EpochStoreParams,
    ) -> IkaResult<Arc<Self>> {
        Self::open(params, /* wipe_derived_state */ false)
    }

    fn open(params: EpochStoreParams, wipe_derived_state: bool) -> IkaResult<Arc<Self>> {
        let EpochStoreParams {
            name,
            committee,
            parent_path,
            db_options,
            metrics,
            epoch_start_configuration,
            chain_identifier,
            packages_config,
        } = params;
        let current_time = Instant::now();
        let epoch_id = committee.epoch;

        let tables = AuthorityEpochTables::open(epoch_id, &parent_path, db_options.clone());

        // Everything below this point re-seeds in-memory state (the
        // EndOfPublish aggregator, the reconfiguration status, the freeze and
        // deadline gauges) from the tables, so the wipe has to happen FIRST or
        // that state would be rehydrated from rows the replay is about to
        // re-derive — the "replay against non-rewound durable state" hazard
        // this design exists to remove.
        if wipe_derived_state {
            let wiped = tables.wipe_derived_state()?;
            let remaining = tables.non_empty_derived_tables();
            assert!(
                remaining.is_empty(),
                "derived per-epoch tables still hold rows after the wipe: {remaining:?} — the \
                 replay would fold onto surviving state",
            );
            let wiped_rows: u64 = wiped.iter().map(|(_, rows)| rows).sum();
            let derived_tables = EPOCH_STATE_REGISTRY
                .iter()
                .filter(|entry| entry.class == EpochStateClass::Derived)
                .count();
            info!(
                epoch = epoch_id,
                wiped_rows,
                wiped_tables = wiped.len(),
                derived_tables,
                preserved_tables = EPOCH_STATE_REGISTRY.len() - derived_tables,
                ?wiped,
                "wiped derived per-epoch state; rebuilding it by replaying the epoch's \
                 consensus commits",
            );
        }

        let epoch_alive_notify = NotifyOnce::new();
        assert_eq!(
            epoch_start_configuration.epoch_start_state().epoch(),
            epoch_id
        );
        let epoch_start_configuration = Arc::new(epoch_start_configuration);
        metrics.current_epoch.set(epoch_id as i64);
        metrics
            .committee_quorum_threshold
            .set(committee.quorum_threshold() as i64);
        metrics
            .committee_validity_threshold
            .set(committee.validity_threshold() as i64);
        metrics
            .committee_total_stake
            .set(committee.total_votes() as i64);
        metrics
            .current_voting_right
            .set(committee.weight(&name) as i64);
        // EpochMetrics is node-lifetime (shared across epoch stores), so the
        // per-epoch off-chain-metadata gauges must be reset here — and
        // re-seeded from the per-epoch tables where state survives a
        // mid-epoch restart, so a restart doesn't false-alarm (e.g. a
        // freeze-epoch gauge stuck at 0 after the freeze already fired).
        let recorded_ready_signals = tables
            .epoch_mpc_data_ready_signals
            .safe_iter()
            .filter_map(Result::ok)
            .count();
        metrics
            .dwallet_mpc_data_ready_signals
            .set(recorded_ready_signals as i64);
        metrics.dwallet_mpc_data_ready_signal_stake.set(0);
        metrics.dwallet_mpc_data_locally_validated_peers.set(0);
        let recorded_announcements = tables
            .validator_mpc_data_announcements
            .safe_iter()
            .filter_map(Result::ok)
            .count();
        metrics
            .dwallet_mpc_data_announcements_received
            .set(recorded_announcements as i64);
        let frozen_set_present = !tables.frozen_validator_mpc_data_input_set.is_empty();
        if frozen_set_present {
            metrics.dwallet_mpc_data_freeze_epoch.set(epoch_id as i64);
        }
        let excluded_validators = tables
            .epoch_excluded_validators
            .safe_iter()
            .filter_map(Result::ok)
            .count();
        metrics
            .dwallet_mpc_data_excluded_validators
            .set(excluded_validators as i64);
        let persisted_handoff_signers: Vec<AuthorityName> = tables
            .handoff_signatures
            .safe_iter()
            .filter_map(Result::ok)
            .map(|(signer, _)| signer)
            .collect();
        let persisted_handoff_stake: u64 = persisted_handoff_signers
            .iter()
            .map(|signer| committee.weight(signer))
            .sum();
        metrics
            .dwallet_handoff_signatures_collected
            .set(persisted_handoff_signers.len() as i64);
        metrics
            .dwallet_handoff_signatures_stake
            .set(persisted_handoff_stake as i64);
        metrics.dwallet_handoff_signatures_buffered.set(0);
        metrics.own_mpc_data_blob_unhealthy.set(0);
        let protocol_version = epoch_start_configuration
            .epoch_start_state()
            .protocol_version();
        let protocol_config =
            ProtocolConfig::get_for_version(protocol_version, chain_identifier.chain());
        // Freeze-progress gauges. `-1` is the "not reached / not available"
        // sentinel throughout — epoch 0 and round 0 are valid values, so a
        // zero default would read as a plausible-but-wrong anchor. Round
        // anchors are re-seeded from the per-epoch tables so a mid-epoch
        // restart restores the true countdown state instead of resetting it.
        metrics.dwallet_mpc_data_ready_quorum_round.set(
            tables
                .mpc_data_ready_quorum_round
                .get(&0)?
                .map_or(-1, |round| round as i64),
        );
        metrics.dwallet_mpc_data_freeze_round.set(
            tables
                .mpc_data_freeze_round
                .get(&0)?
                .map_or(-1, |round| round as i64),
        );
        metrics.dwallet_mpc_data_freeze_grace_rounds.set(
            protocol_config
                .mpc_data_freeze_grace_rounds_as_option()
                .map_or(-1, |grace| grace as i64),
        );
        let last_committed_leader_round = tables
            .get_last_consensus_stats()?
            .map(|stats| stats.index.last_committed_round);
        metrics
            .last_committed_leader_consensus_round
            .set(last_committed_leader_round.map_or(-1, |round| round as i64));
        // Ready-signal deadline: restore the persisted 3/4-epoch backstop
        // anchor. The publication-grace term is deliberately absent here —
        // its anchor is local in-memory sender state that resets on restart,
        // and the sender re-tightens the gauge once it re-observes the
        // next-epoch committee (matching the emit gate's actual post-restart
        // behavior). Consensus-clock seconds, not local wall clock.
        let ready_signal_deadline_seconds = tables
            .epoch_first_commit_timestamp_ms
            .get(&0)?
            .and_then(|first_commit_ts_ms| {
                ready_signal_deadline_ms(
                    Some(first_commit_ts_ms),
                    epoch_start_configuration
                        .epoch_start_state()
                        .epoch_duration_ms(),
                    None,
                )
            })
            .map_or(-1, |deadline_ms| (deadline_ms / 1000) as i64);
        metrics
            .dwallet_mpc_data_ready_signal_deadline_timestamp_seconds
            .set(ready_signal_deadline_seconds);
        let end_of_publish =
            StakeAggregator::from_iter(committee.clone(), tables.end_of_publish.safe_iter())?;
        // Restore the closed state from `epoch_close_emitted`, which the
        // deferred close persists atomically with the closing commit. Under
        // `RebuildFromConsensus` the marker was just wiped, so this reads
        // `AcceptAllCerts` and the replay re-decides the close at the same
        // commit the original run did — the close set lands at the same round,
        // not a later one. Under `Retain` (a store opened without a replay
        // behind it) this is the only thing standing between a reopened store
        // and re-emitting the close at a later commit, which would fork this
        // validator's checkpoint stream from its peers.
        let initial_reconfig_status = if tables.epoch_close_emitted.get(&0)?.is_some() {
            ReconfigCertStatus::RejectAllTx
        } else {
            ReconfigCertStatus::AcceptAllCerts
        };
        let s = Arc::new(Self {
            name,
            committee: committee.clone(),
            protocol_config,
            tables: ArcSwapOption::new(Some(Arc::new(tables))),
            parent_path,
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
                status: initial_reconfig_status,
            }),
            end_of_publish: Mutex::new(end_of_publish),
            joiner_pubkey_provider: ArcSwapOption::empty(),
            expected_handoff_attestation: ArcSwapOption::empty(),
            mpc_service_progress: ArcSwapOption::empty(),
            mpc_lag_alarm_active: std::sync::atomic::AtomicBool::new(false),
            mpc_catch_up_drain: Mutex::new(None),
            mpc_catch_up_stuck_alarm_active: AtomicBool::new(false),
            pending_handoff_signatures: parking_lot::Mutex::new(Vec::new()),
            staged_handoff_signature_rows: parking_lot::Mutex::new(BTreeMap::new()),
            pending_relayed_joiner_announcements: parking_lot::Mutex::new(Vec::new()),
            handoff_aggregator: parking_lot::Mutex::new(None),
            perpetual_tables_for_handoff: ArcSwapOption::empty(),
            self_blob_unhealthy_warned: AtomicBool::new(false),
            max_processed_commit_timestamp_ms: AtomicU64::new(0),
            round_transport: ArcSwapOption::empty(),
            observed_consensus_head_round: AtomicU64::new(0),
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

    /// Installs the bounded round transport. Must happen before the first
    /// commit is folded, or the drain misses every round folded before it.
    pub fn install_round_transport(&self, sender: Arc<RoundTransportSender>) {
        self.round_transport.store(Some(sender));
    }

    /// The installed round transport, if this node runs an MPC drain.
    pub fn round_transport(&self) -> Option<Arc<RoundTransportSender>> {
        self.round_transport.load_full()
    }

    /// Records a consensus round this node has observed. Monotone, so an
    /// out-of-order report cannot walk the head backwards.
    pub fn record_observed_consensus_head_round(&self, round: Round) {
        self.observed_consensus_head_round
            .fetch_max(round, Ordering::AcqRel);
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
        Self::new(EpochStoreParams {
            name,
            committee: Arc::new(new_committee),
            parent_path: self.parent_path.clone(),
            db_options: self.db_options.clone(),
            metrics: self.metrics.clone(),
            epoch_start_configuration,
            chain_identifier,
            packages_config: self.packages_config.clone(),
        })
    }

    pub fn new_at_next_epoch_for_testing(&self) -> IkaResult<Arc<Self>> {
        let next_epoch = self.epoch() + 1;
        // Carry the committee's consensus keys forward so the fabricated
        // next committee can still verify consensus-key-signed messages.
        let consensus_keys = self
            .committee
            .names()
            .filter_map(|name| {
                self.committee
                    .consensus_key(name)
                    .map(|key| (*name, key.clone()))
            })
            .collect();
        let next_committee = Committee::new(
            next_epoch,
            self.committee.voting_rights.to_vec(),
            self.committee.class_groups_public_keys_and_proofs.clone(),
            consensus_keys,
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
        self.update_protocol_upgrade_metrics();
    }

    /// Export the protocol-upgrade activation line and the current support
    /// tally, computed by the SAME shared functions the activation decision
    /// uses (`AuthorityState::protocol_upgrade_effective_threshold` /
    /// `tally_protocol_upgrade_votes`) - no duplicated formula to drift.
    /// Supporting stake is the strongest same-(digest, contracts) vote group
    /// for the next protocol version, exactly the quantity the decision
    /// compares against the threshold. Called at epoch-store open, on
    /// buffer-override changes, and on every capability receipt - cheap
    /// (committee-sized scan of a per-epoch table).
    fn update_protocol_upgrade_metrics(&self) {
        let committee = self.committee();
        let effective_threshold =
            crate::authority::AuthorityState::protocol_upgrade_effective_threshold(
                committee,
                self.get_effective_buffer_stake_bps(),
            );
        self.metrics
            .protocol_upgrade_effective_threshold
            .set(effective_threshold as i64);
        let Ok(capabilities) = self.get_capabilities_v1() else {
            return;
        };
        let supporting = crate::authority::AuthorityState::tally_protocol_upgrade_votes(
            self.protocol_version() + 1,
            committee,
            &capabilities,
        )
        .map(|groups| {
            groups
                .into_iter()
                .map(|(_, _, stake)| stake)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);
        self.metrics
            .protocol_upgrade_supporting_stake
            .set(supporting as i64);
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
        self.update_protocol_upgrade_metrics();
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

    /// Whether `authority`'s EndOfPublish vote has been sequenced and
    /// recorded in this epoch's durable table. The handoff signature
    /// sender uses this to confirm its own `EndOfPublishV2` actually
    /// landed before it stops re-submitting: a successful
    /// `submit_to_consensus` only means the tx was handed to the
    /// background submitter, which can still fail to sequence at the
    /// epoch boundary (exactly when `EndOfPublishV2` fires) or on crash.
    /// Restart-safe — the table is reloaded into the in-memory
    /// aggregator at epoch-store construction.
    ///
    /// Votes become visible here at the batch write of the commit that
    /// sequenced them, not the instant they are processed (they ride
    /// `ConsensusCommitOutput`), so a `true` here means the vote is durable —
    /// which is precisely what this check is asking.
    pub fn has_recorded_end_of_publish_vote(&self, authority: &AuthorityName) -> IkaResult<bool> {
        Ok(self.tables()?.end_of_publish.get(authority)?.is_some())
    }

    /// Record a current-committee validator's self-submitted
    /// announcement. The consensus block author was already verified
    /// to equal `announcement.validator` in
    /// `verify_consensus_transaction`, so there's no payload
    /// signature to check here — only that the announcement is for
    /// the current epoch. Latest-by-timestamp: a stored entry is
    /// replaced only by a strictly newer `timestamp_ms` (see
    /// `insert_validator_mpc_data_announcement`); replays and stale
    /// duplicates drop silently. Next-epoch joiner announcements take
    /// the separate `record_relayed_validator_mpc_data_announcement`
    /// path, which verifies the joiner's Ed25519 signature.
    pub fn record_validator_mpc_data_announcement(
        &self,
        announcement: &ValidatorMpcDataAnnouncement,
        blob: &[u8],
    ) -> IkaResult {
        let current_epoch = self.epoch();
        if announcement.epoch != current_epoch {
            warn!(
                announcement_epoch = announcement.epoch,
                current_epoch, "self validator mpc data announcement epoch mismatch — dropping"
            );
            return Ok(());
        }
        // The blob rides consensus in-band, so every node persists it
        // here (hash-verified) instead of fetching it peer-to-peer.
        self.store_announced_mpc_data_blob(announcement.blob_hash, blob);
        self.insert_validator_mpc_data_announcement(announcement)
    }

    /// Persist an mpc_data blob delivered in-band over consensus into
    /// perpetual `mpc_artifact_blobs`, where the off-chain assembler
    /// resolves blobs by digest. The bytes are hash- and decode-
    /// verified against the announced digest first; a bad blob is
    /// dropped (the separately-recorded announcement just won't be
    /// locally validated without good bytes). Storage is content-
    /// addressed, so a blob from an as-yet-unverified relayed
    /// announcement is inert unless and until a frozen digest matches.
    fn store_announced_mpc_data_blob(&self, digest: [u8; 32], blob: &[u8]) {
        // Blobs ride consensus with no size cap yet; record the real
        // distribution so the eventual cap is measured, not guessed.
        self.metrics
            .mpc_data_announcement_blob_bytes
            .observe(blob.len() as f64);
        info!(
            blob_bytes = blob.len(),
            digest = ?digest,
            "storing in-band mpc_data announcement blob"
        );
        match crate::validator_metadata::verify_peer_blob_for_relay(blob, &digest) {
            crate::validator_metadata::PeerBlobVerdict::Accept => {}
            verdict => {
                warn!(
                    ?verdict,
                    digest = ?digest,
                    "in-band mpc_data blob failed verification — not persisting"
                );
                return;
            }
        }
        let Some(perpetual) = self.perpetual_tables_for_handoff_load_full() else {
            warn!(
                digest = ?digest,
                "perpetual tables not installed — in-band mpc_data blob not persisted"
            );
            return;
        };
        if let Err(e) = perpetual.insert_mpc_artifact_blob(digest, blob) {
            warn!(error = ?e, digest = ?digest, "failed to persist in-band mpc_data blob");
        }
    }

    /// Record a next-epoch joiner's announcement relayed by a
    /// current-committee validator. The relayer is unauthenticated
    /// for the payload, so the joiner's Ed25519 consensus-key
    /// signature is verified against its next-epoch consensus pubkey
    /// (via the installed `JoinerPubkeyProvider`) before storing.
    pub(crate) fn record_relayed_validator_mpc_data_announcement(
        &self,
        signed: &SignedValidatorMpcDataAnnouncement,
        blob: &[u8],
    ) -> IkaResult<RelayedAnnouncementDisposition> {
        // The blob is stored on every path that RETAINS the announcement —
        // accepted, or buffered for re-evaluation — because those paths need
        // the bytes later and consensus won't redeliver them. It is
        // deliberately NOT stored on the drop path below: that verdict is
        // final, and `mpc_artifact_blobs` is perpetual with no pruning, so
        // persisting there left permanent bytes behind an announcement we had
        // just decided to discard. Storage is still hash-verified and
        // content-addressed, so ordering it after the verdict costs nothing.
        let next_epoch = self.epoch().saturating_add(1);
        let Some(provider) = self.joiner_pubkey_provider.load_full() else {
            // Provider not installed yet — buffer and re-evaluate on
            // install, rather than drop a relay consensus won't
            // redeliver.
            self.store_announced_mpc_data_blob(signed.announcement.blob_hash, blob);
            self.buffer_relayed_joiner_announcement(signed);
            return Ok(RelayedAnnouncementDisposition::Retained);
        };
        match verify_joiner_announcement(signed, provider.as_ref().as_ref(), next_epoch) {
            JoinerAnnouncementVerdict::Accept => {
                self.store_announced_mpc_data_blob(signed.announcement.blob_hash, blob);
            }
            JoinerAnnouncementVerdict::UnregisteredJoiner => {
                // The installed provider predates this joiner's
                // registration (a next-epoch committee snapshot that
                // hasn't caught up). Buffer; the next provider install
                // re-evaluates it.
                self.store_announced_mpc_data_blob(signed.announcement.blob_hash, blob);
                self.buffer_relayed_joiner_announcement(signed);
                return Ok(RelayedAnnouncementDisposition::Retained);
            }
            verdict @ (JoinerAnnouncementVerdict::InvalidSignature
            | JoinerAnnouncementVerdict::InconsistentEnvelope) => {
                // Genuinely bad (bad signature / wrong epoch) —
                // re-evaluation can't rescue these, so drop.
                warn!(
                    ?verdict,
                    authority = ?signed.announcement.validator,
                    "joiner mpc data announcement rejected — dropping without \
                     persisting its blob or consuming its consensus key"
                );
                return Ok(RelayedAnnouncementDisposition::Discarded);
            }
        }
        self.insert_validator_mpc_data_announcement(&signed.announcement)?;
        Ok(RelayedAnnouncementDisposition::Retained)
    }

    /// Buffers a relayed joiner announcement whose signature can't be
    /// verified yet (provider absent or lagging the next-epoch
    /// committee), to be re-evaluated when a provider installs.
    fn buffer_relayed_joiner_announcement(&self, signed: &SignedValidatorMpcDataAnnouncement) {
        let mut buffer = self.pending_relayed_joiner_announcements.lock();
        push_buffered_joiner_announcement(
            &mut buffer,
            signed,
            Instant::now(),
            PENDING_RELAYED_JOINER_ANNOUNCEMENT_TTL,
            MAX_PENDING_RELAYED_JOINER_ANNOUNCEMENTS,
        );
        debug!(
            validator = ?signed.announcement.validator,
            pending_len = buffer.len(),
            "buffered relayed joiner announcement (provider absent or lagging); \
             will re-evaluate on provider install"
        );
    }

    /// Shared tail of both record paths: reject the sentinel
    /// timestamp, apply the latest-by-timestamp dedup, and store the
    /// bare announcement. The signature (if any) has already been
    /// verified by the caller and isn't needed by downstream
    /// consumers, which read only the announcement body.
    fn insert_validator_mpc_data_announcement(
        &self,
        announcement: &ValidatorMpcDataAnnouncement,
    ) -> IkaResult {
        // Reject the reserved sentinel timestamp. `sign_validator_mpc_data_announcement`
        // refuses to produce one, so reaching here means a byzantine peer
        // crafted one to wedge the strict-monotonic gate below.
        if announcement.timestamp_ms == 0 {
            warn!(
                validator = ?announcement.validator,
                "validator mpc data announcement with reserved sentinel timestamp_ms=0 — dropping"
            );
            return Ok(());
        }
        let tables = self.tables()?;
        if let Some(existing) = tables
            .validator_mpc_data_announcements
            .get(&announcement.validator)?
            && existing.timestamp_ms >= announcement.timestamp_ms
        {
            // Strict `>=`: an incoming announcement with timestamp
            // equal to the stored one is also dropped. Equal
            // timestamps from the same validator can only happen if
            // the sender re-uses a stale payload (replay) — the
            // honest producer-side clock is millisecond-resolution
            // and the producer rate is one announcement per epoch.
            debug!(
                validator = ?announcement.validator,
                incoming_ts = announcement.timestamp_ms,
                stored_ts = existing.timestamp_ms,
                "older or equal-timestamp validator mpc data announcement — dropping"
            );
            return Ok(());
        }
        tables
            .validator_mpc_data_announcements
            .insert(&announcement.validator, announcement)?;
        // Once per validator per epoch (re-announces are rare and strictly
        // newer-timestamped). Covers all three entry points — self, relayed
        // joiner, and buffered replay — and answers "did this node record
        // V's announcement" when the frozen set later excludes V.
        let recorded_announcements = tables
            .validator_mpc_data_announcements
            .safe_iter()
            .filter_map(Result::ok)
            .count();
        self.metrics
            .dwallet_mpc_data_announcements_received
            .set(recorded_announcements as i64);
        info!(
            validator = ?announcement.validator,
            epoch = announcement.epoch,
            blob_hash = ?announcement.blob_hash,
            timestamp_ms = announcement.timestamp_ms,
            "recorded validator mpc_data announcement"
        );
        Ok(())
    }

    /// Install the source of truth for next-epoch joiner registration.
    /// Repeated calls swap the active provider atomically; the
    /// previous provider is dropped. Until a provider is installed the
    /// store defaults to dropping joiner announcements.
    pub fn install_joiner_pubkey_provider(&self, provider: Box<dyn JoinerPubkeyProvider>) {
        let provider = Arc::new(provider);
        self.joiner_pubkey_provider.store(Some(provider.clone()));
        // A freshly-installed provider may now resolve joiners whose
        // relayed announcements we buffered while it was absent or
        // lagging — re-evaluate and apply the ones that now verify.
        let next_epoch = self.epoch().saturating_add(1);
        let to_apply = {
            let mut buffer = self.pending_relayed_joiner_announcements.lock();
            reevaluate_buffered_joiner_announcements(
                &mut buffer,
                provider.as_ref().as_ref(),
                next_epoch,
                Instant::now(),
                PENDING_RELAYED_JOINER_ANNOUNCEMENT_TTL,
            )
        };
        for announcement in &to_apply {
            if let Err(e) = self.insert_validator_mpc_data_announcement(announcement) {
                warn!(
                    error = ?e,
                    validator = ?announcement.validator,
                    "failed to apply buffered relayed joiner announcement on provider install"
                );
            }
        }
        if !to_apply.is_empty() {
            debug!(
                applied = to_apply.len(),
                "applied buffered relayed joiner announcements on provider install"
            );
        }
    }

    /// Currently-installed joiner pubkey provider, or `None` if
    /// none is installed. Used by the joiner-relay path to verify
    /// incoming announcements before forwarding them to consensus.
    pub fn joiner_pubkey_provider(&self) -> Option<Arc<Box<dyn JoinerPubkeyProvider>>> {
        self.joiner_pubkey_provider.load_full()
    }

    /// Install the locally-computed expected handoff attestation
    /// for the epoch. Rebuilds the in-memory `HandoffAggregator`
    /// from any signatures already persisted in
    /// `handoff_signatures`, so prior consensus-ordered signatures
    /// (e.g. ones drained from RocksDB at restart) get folded in
    /// correctly. Re-installing with a different attestation
    /// discards the old aggregator state.
    /// Whether the handoff aggregator has been built (an expected
    /// attestation was installed at least once this epoch). Used by the
    /// signature sender's steady-state early-out: once the own vote is
    /// durably recorded AND this is true, the per-tick
    /// hydrate+build+install pass has nothing left to do.
    pub fn handoff_aggregator_installed(&self) -> bool {
        self.handoff_aggregator.lock().is_some()
    }

    pub fn install_expected_handoff_attestation(
        &self,
        attestation: ika_types::handoff::HandoffAttestation,
    ) -> IkaResult {
        let attestation_arc = Arc::new(attestation.clone());
        let previous = self
            .expected_handoff_attestation
            .swap(Some(attestation_arc.clone()));
        let attestation_unchanged = previous
            .as_ref()
            .map(|p| p.as_ref() == attestation_arc.as_ref())
            .unwrap_or(false);
        let mut guard = self.handoff_aggregator.lock();
        if attestation_unchanged && guard.is_some() {
            return Ok(());
        }
        let mut aggregator = HandoffAggregator::new(self.committee.clone(), attestation.clone());
        // Replay persisted signatures into the fresh aggregator,
        // re-verifying each against the attestation being installed.
        // The persisted `(signer, signature)` rows were verified
        // against whatever was `expected` when they landed; if this
        // install carries a DIFFERENT attestation (the function
        // supports re-installing — e.g. a fresh hydration changed the
        // items), those rows endorse the old bytes and must not count
        // toward the new cert. Re-verification keeps the restart path
        // correct (same attestation ⇒ rows re-verify and are kept)
        // while dropping stale rows on a mid-epoch change. The committee
        // carries every member's consensus key, so verification is always
        // possible (no early-startup fallback needed). Order doesn't
        // matter — the aggregator is stake-weighted.
        let committee = self.committee();
        let mut replayed_signatures: usize = 0;
        // Rows that endorse a superseded attestation are dropped from the
        // aggregator AND deleted from the table below. The close-gate quorum
        // sum (`handoff_signatures_meet_quorum`) reads the TABLE, not the
        // aggregator, so leaving stale rows behind would let a re-install
        // that changed the attestation still count the old endorsements.
        let mut stale_signers: Vec<AuthorityName> = Vec::new();
        // Rows already staged for the next commit count here even though they
        // are not durable yet. They were verified against an attestation and
        // consensus will not redeliver them, so an install that read only the
        // committed table would drop every signature recorded since the last
        // commit out of the rebuilt aggregator — permanently, since the
        // aggregator is only ever rebuilt from this read.
        let staged = self.staged_handoff_signature_rows.lock().clone();
        for (signer, signature) in self.handoff_signature_rows_with(&staged)? {
            let msg = ika_types::handoff::HandoffSignatureMessage {
                attestation: attestation.clone(),
                signer,
                signature: signature.clone(),
            };
            if verify_handoff_signature(&msg, &attestation, committee.as_ref())
                != HandoffSignatureVerdict::Accept
            {
                warn!(
                    signer = ?signer,
                    epoch = attestation.epoch,
                    "persisted handoff signature no longer verifies against the \
                     installed attestation — dropping on replay"
                );
                stale_signers.push(signer);
                continue;
            }
            aggregator.insert_verified(signer, signature);
            replayed_signatures += 1;
        }
        // Stage the superseded rows for deletion so the table matches the
        // installed attestation. Staged rather than deleted on sight for the
        // same reason the inserts are: this moves the close gate DOWN, so the
        // commit it moves down at has to be a commit, not the wall-clock
        // instant this install happened to run. Idempotent — a crash before
        // the batch leaves the rows to be re-identified on the next install.
        //
        // NOT a writer this sweep can catch, and not a regression: a
        // consensus-arm row verifying against the OUTGOING attestation can be
        // staged after the snapshot above was cloned, so it survives into the
        // table under the incoming one. The pre-#1927 code had the identical
        // window (an insert landing after the sweep had iterated the table),
        // because both versions decide what is stale from a snapshot the
        // consensus thread can outrun. Closing it needs the gate to stop
        // depending on which attestation a row endorses at all — the
        // sequence-pure tally keyed by attestation digest, not a wider lock
        // here, which would only move the race to the arm.
        if !stale_signers.is_empty() {
            self.stage_handoff_signature_rows(stale_signers.iter().map(|signer| (*signer, None)));
            info!(
                epoch = attestation.epoch,
                dropped = stale_signers.len(),
                "staged superseded handoff signature rows for deletion on attestation re-install"
            );
        }
        let aggregator_signer_count = aggregator.signer_count();
        let aggregator_stake = aggregator.accumulated_stake();
        // Capture the full cert (not just the epoch) BEFORE the aggregator
        // moves into the guard, so a cert re-minted during replay can be
        // persisted below — it did not go through `record_handoff_signature`'s
        // `Certified` arm, which is otherwise the only persist path.
        let replay_cert = aggregator.certified().cloned();
        *guard = Some(aggregator);
        drop(guard);
        // Positive baseline record of what this validator attested to —
        // needed to interpret later AttestationMismatch warns and
        // buffered-quorum adoptions. The `attestation_unchanged`
        // early-return above bounds this to once per distinct
        // attestation install (once or twice per epoch).
        info!(
            epoch = attestation.epoch,
            items = attestation.items.len(),
            next_committee_hash = ?attestation.next_committee_pubkey_set_hash,
            replayed_signatures,
            "installed expected handoff attestation — aggregating peer signatures against it"
        );
        self.metrics
            .dwallet_handoff_signatures_collected
            .set(aggregator_signer_count as i64);
        self.metrics
            .dwallet_handoff_signatures_stake
            .set(aggregator_stake as i64);
        // A restart (or buffered-quorum) past quorum re-mints the cert in
        // memory during the replay above without going through
        // `record_handoff_signature`'s `Certified` arm. Re-seed the gauge so a
        // restart doesn't false-fire the cert-lag alert AND persist the cert: it
        // was minted here, not via the only other persist path, so without this
        // a validator that crossed quorum via replay holds the cert in memory
        // only, and a later restart or joiner-bootstrap read misses it (#1736:
        // persist on every mint path).
        if let Some(cert) = &replay_cert {
            self.metrics
                .dwallet_handoff_cert_epoch
                .set(cert.attestation.epoch as i64);
            if let Some(perpetual) = self.perpetual_tables_for_handoff.load_full()
                && let Err(e) =
                    perpetual.insert_certified_handoff_attestation(cert.attestation.epoch, cert)
            {
                warn!(
                    error = ?e,
                    epoch = cert.attestation.epoch,
                    "failed to persist replay-minted handoff cert — cert remains in-memory only"
                );
            }
        }
        // Drain peer V2 signatures that arrived before this
        // attestation was installed. Each goes through
        // `process_handoff_signature` for real verification
        // against `expected`; mismatched-attestation peers get
        // rejected normally (and stay rejected — they had
        // outdated bytes). The buffer is bounded by committee
        // size in practice.
        let drained: Vec<_> = std::mem::take(&mut *self.pending_handoff_signatures.lock());
        if !drained.is_empty() {
            info!(
                pending = drained.len(),
                epoch = attestation.epoch,
                "replaying buffered peer handoff signatures after attestation install"
            );
            for msg in drained {
                if let Err(e) = self.record_handoff_signature(&msg) {
                    warn!(
                        error = ?e,
                        signer = ?msg.signer,
                        "buffered handoff signature replay failed — dropping"
                    );
                }
            }
            self.metrics
                .dwallet_handoff_signatures_buffered
                .set(self.pending_handoff_signatures.lock().len() as i64);
        }
        Ok(())
    }

    /// Install the perpetual-tables handle used to persist a fresh
    /// `CertifiedHandoffAttestation` once the aggregator crosses
    /// quorum. Called once by `ika-node` at startup, after the
    /// perpetual DB is open. Before this is installed, certs are
    /// minted by the aggregator but not persisted; any joiner-
    /// bootstrap reads scheduled before install will miss them.
    pub fn install_perpetual_tables_for_handoff(
        &self,
        perpetual_tables: Arc<super::authority_perpetual_tables::AuthorityPerpetualTables>,
    ) {
        self.perpetual_tables_for_handoff
            .store(Some(perpetual_tables));
    }

    /// Returns the perpetual-tables handle, or `None` if it
    /// hasn't been installed yet (early bootstrap). Read-only
    /// access for callers that need to look up `mpc_artifact_blobs`
    /// — e.g. the per-validator local-readiness gate in
    /// `DWalletMPCManager::perform_cryptographic_computation`.
    pub fn perpetual_tables_for_handoff_load_full(
        &self,
    ) -> Option<Arc<super::authority_perpetual_tables::AuthorityPerpetualTables>> {
        self.perpetual_tables_for_handoff.load_full()
    }

    /// Assembles this validator's local handoff attestation by
    /// asking each `HandoffItemsBuilder` for its contribution and
    /// hashing the supplied next-committee pubkey set. Determinism
    /// across validators is what guarantees agreement on the
    /// produced attestation: identical inputs → identical bytes.
    /// Caller controls which contributors are active (typically
    /// the result of [`crate::validator_metadata::default_handoff_items_builders`]);
    /// new features can append their own builders without touching
    /// this code.
    pub fn build_local_handoff_attestation(
        &self,
        next_committee_pubkeys: impl IntoIterator<Item = ika_types::crypto::AuthorityName>,
        builders: &[Arc<dyn crate::validator_metadata::HandoffItemsBuilder>],
    ) -> IkaResult<ika_types::handoff::HandoffAttestation> {
        let next_committee_set: Vec<AuthorityName> = next_committee_pubkeys.into_iter().collect();
        let mut items: Vec<(ika_types::handoff::HandoffItemKey, [u8; 32])> = Vec::new();
        for builder in builders {
            items.extend(builder.build(self.epoch(), &next_committee_set)?);
        }
        let next_committee_hash = hash_next_committee_pubkey_set(next_committee_set);
        build_handoff_attestation(self.epoch(), next_committee_hash, items)
    }

    /// Computes `frozen ∩ (V_e ∪ V_{e+1})` — the effective
    /// validator mpc_data set consumed by both the handoff cert and
    /// reconfig MPC. Withdrawn announcers (frozen this epoch but
    /// absent from both committees) are dropped.
    pub fn get_effective_reconfig_input_set(
        &self,
        next_committee_pubkeys: impl IntoIterator<Item = AuthorityName>,
    ) -> IkaResult<std::collections::BTreeMap<AuthorityName, [u8; 32]>> {
        let frozen = self.get_frozen_validator_mpc_data_input_set()?;
        let frozen_btree: std::collections::BTreeMap<AuthorityName, [u8; 32]> =
            frozen.into_iter().collect();
        let current_committee_pubkeys =
            self.committee().voting_rights.iter().map(|(name, _)| *name);
        Ok(
            crate::validator_metadata::compute_effective_reconfig_input_set(
                &frozen_btree,
                current_committee_pubkeys,
                next_committee_pubkeys,
            ),
        )
    }

    /// Shared implementation behind `cache_network_dkg_output` and
    /// `cache_network_reconfiguration_output`. Computes the
    /// Blake2b256 digest of `output_bytes`, writes the digest into
    /// the appropriate per-epoch table, and writes the blob into
    /// perpetual `mpc_artifact_blobs` so the local node can resolve
    /// the bytes by digest in later epochs (via `EpochStoreBlobSource`,
    /// which reads perpetual directly). Unlike validator `mpc_data`
    /// blobs, these network-key outputs are resolved locally — never
    /// fetched peer-to-peer — so they intentionally do NOT go through
    /// the `BlobCache` write-through into the in-memory P2P serve store.
    /// Both writes are idempotent on byte-identical inputs.
    ///
    /// DETERMINISM: this digest feeds the cross-epoch handoff
    /// attestation, whose items a quorum of signers must byte-match.
    /// That rests on `output_bytes` being a *canonical* encoding of the
    /// protocol's public output — the same logical DKG / reconfiguration
    /// result must serialize to identical bytes on every honest
    /// validator. If the cryptography layer ever emitted a non-canonical
    /// encoding of the same output, signers would hash different digests
    /// and cross-reject as `AttestationMismatch` with no other symptom.
    fn cache_protocol_output(
        &self,
        kind: ProtocolOutputKind,
        dwallet_network_encryption_key_id: ObjectID,
        output_bytes: &[u8],
    ) -> IkaResult<()> {
        let digest = mpc_data_blob_hash(output_bytes);
        let tables = self.tables()?;
        match kind {
            ProtocolOutputKind::Dkg => tables
                .network_dkg_output_digests
                .insert(&dwallet_network_encryption_key_id, &digest)?,
            ProtocolOutputKind::Reconfiguration => tables
                .network_reconfiguration_output_digests
                .insert(&dwallet_network_encryption_key_id, &digest)?,
        }
        if let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() {
            if let Err(e) = perpetual.insert_mpc_artifact_blob(digest, output_bytes) {
                warn!(
                    error = ?e,
                    ?dwallet_network_encryption_key_id,
                    "failed to persist protocol output blob — cross-epoch local resolution may miss the bytes"
                );
            }
            // Mirror the per-epoch `key_id -> digest` into perpetual so
            // consumers in *later* epochs can still resolve the blob
            // bytes — the per-epoch table starts empty after each
            // reconfig. Without this, off_chain mode's overlay
            // returns `None` for any key whose output was produced in
            // a prior epoch, which propagates as `BcsError(Eof)` in
            // `spawn_network_encryption_key_public_data_instantiation`.
            let perpetual_insert = match kind {
                ProtocolOutputKind::Dkg => perpetual
                    .insert_network_dkg_output_digest(dwallet_network_encryption_key_id, digest),
                ProtocolOutputKind::Reconfiguration => perpetual
                    .insert_network_reconfiguration_output_digest(
                        dwallet_network_encryption_key_id,
                        digest,
                    ),
            };
            if let Err(e) = perpetual_insert {
                warn!(
                    error = ?e,
                    ?dwallet_network_encryption_key_id,
                    "failed to persist per-key digest mirror — cross-epoch lookups may miss"
                );
            }
        }
        Ok(())
    }

    /// Returns the merged `key_id -> digest` map of cached network
    /// DKG outputs. Per-epoch table takes precedence (latest writes
    /// in this epoch override prior cached digests); perpetual
    /// mirror fills in keys whose DKG completed in earlier epochs.
    /// Without the perpetual fallback the handoff items list would
    /// drop DKG entries for any key whose output was produced
    /// before the current epoch, causing the items list to diverge
    /// across validators that ran DKG at different times.
    pub fn get_network_dkg_output_digests(
        &self,
    ) -> IkaResult<std::collections::BTreeMap<ObjectID, [u8; 32]>> {
        let tables = self.tables()?;
        let mut out: std::collections::BTreeMap<ObjectID, [u8; 32]> =
            std::collections::BTreeMap::new();
        if let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() {
            for entry in perpetual.network_dkg_output_digests_by_key.safe_iter() {
                let (key_id, digest) = entry.map_err(IkaError::from)?;
                out.insert(key_id, digest);
            }
        }
        for entry in tables.network_dkg_output_digests.safe_iter() {
            let (key_id, digest) = entry.map_err(IkaError::from)?;
            out.insert(key_id, digest);
        }
        Ok(out)
    }

    /// Returns the `key_id -> digest` map of reconfiguration outputs
    /// recorded for `epoch` — the epoch-keyed perpetual slice written by
    /// [`Self::cache_network_reconfiguration_output`] under the
    /// reconfiguration session's *own* epoch. The handoff attestation
    /// for `epoch` MUST use this: it is deterministic across validators
    /// regardless of when each one processed the output locally. The
    /// prior per-epoch-table source was not — a late-finalized output
    /// crossing the epoch boundary landed under the wrong epoch on slow
    /// validators, so peers certified different
    /// `NetworkReconfigurationOutput` digests for the same epoch and
    /// cross-rejected as `AttestationMismatch`, wedging EndOfPublish. A
    /// validator that hasn't yet recorded `epoch`'s reconfiguration
    /// output simply has no entry here and is correctly excluded from
    /// the item.
    pub fn get_network_reconfiguration_output_digests_for_epoch(
        &self,
        epoch: EpochId,
    ) -> IkaResult<std::collections::BTreeMap<ObjectID, [u8; 32]>> {
        match self.perpetual_tables_for_handoff.load_full() {
            Some(perpetual) => {
                perpetual.get_network_reconfiguration_output_digests_for_epoch(epoch)
            }
            None => Ok(std::collections::BTreeMap::new()),
        }
    }

    /// Looks up the cached blob for a given network key + protocol
    /// output kind. Returns `None` only when no digest exists for
    /// this key/kind in either the per-epoch table or the perpetual
    /// mirror, or when the digest is known but the perpetual blob
    /// store doesn't hold the bytes.
    ///
    /// Lookup precedence:
    /// 1. Per-epoch `network_*_output_digests` (fresh writes in the
    ///    current epoch land here first).
    /// 2. Perpetual `network_*_output_digests_by_key` mirror (covers
    ///    keys whose output was produced in a prior epoch — the
    ///    per-epoch table starts empty after each reconfig).
    /// 3. Perpetual `mpc_artifact_blobs` keyed by the resolved
    ///    digest.
    fn lookup_protocol_output_blob(
        &self,
        kind: ProtocolOutputKind,
        network_key_id: &ObjectID,
    ) -> Option<Vec<u8>> {
        let perpetual = self.perpetual_tables_for_handoff.load_full()?;
        let tables = self.tables().ok()?;
        let digest = match kind {
            ProtocolOutputKind::Dkg => tables
                .network_dkg_output_digests
                .get(network_key_id)
                .ok()
                .flatten()
                .or_else(|| {
                    perpetual
                        .get_network_dkg_output_digest(network_key_id)
                        .ok()
                        .flatten()
                })?,
            ProtocolOutputKind::Reconfiguration => tables
                .network_reconfiguration_output_digests
                .get(network_key_id)
                .ok()
                .flatten()
                .or_else(|| {
                    perpetual
                        .get_network_reconfiguration_output_digest(network_key_id)
                        .ok()
                        .flatten()
                })?,
        };
        perpetual.get_mpc_artifact_blob(&digest).ok().flatten()
    }

    /// Builds the per-validator signed handoff message. Also installs
    /// the attestation locally so the per-epoch record path will
    /// accept incoming peer signatures matching it (otherwise they'd
    /// be rejected with `AttestationMismatch`).
    ///
    /// Returns just the signed message — the caller bundles it into
    /// an `EndOfPublishV2` consensus transaction.
    pub fn build_local_signed_handoff_message(
        &self,
        attestation: ika_types::handoff::HandoffAttestation,
        consensus_keypair: &fastcrypto::ed25519::Ed25519KeyPair,
    ) -> IkaResult<ika_types::handoff::HandoffSignatureMessage> {
        self.install_expected_handoff_attestation(attestation.clone())?;
        Ok(sign_handoff_attestation(
            attestation,
            self.name,
            consensus_keypair,
        ))
    }

    /// Publishes how far the MPC service trails the consensus commit path, and
    /// escalates to a loud log once the gap is unambiguous.
    ///
    /// A healthy validator sits a small, roughly constant distance behind: the
    /// MPC service consumes rounds slightly after the commit boundary produces
    /// them. A gap that grows without bound means MPC has stopped while
    /// consensus continues — the node follows consensus, serves requests,
    /// exports metrics, and contributes nothing.
    ///
    /// The threshold is deliberately generous. Genuine catch-up after a restart
    /// transiently produces a large gap and then closes it, and we would rather
    /// miss the first minutes of a real stall than teach operators to ignore
    /// this line. `MPC_LAG_ALARM_ROUNDS` is roughly an hour of production round
    /// production at observed testnet rates; the two production incidents this
    /// exists for sat far past it for many hours.
    ///
    /// Generous is not enough on its own, though: a gap the MPC service is
    /// itself reporting as a catch-up drain is explained, not unambiguous. A
    /// mid-epoch restart replays every round of the epoch so far, so past the
    /// first three quarters of an hour of a 24h epoch that replay alone exceeds
    /// the threshold and the alarm fires on every restart of a perfectly
    /// healthy validator — telling its operator to restart it again and discard
    /// the drain. So a reported catch-up holds this alarm, but only for as long
    /// as the service keeps renewing that report
    /// (`MPC_CATCH_UP_REPORT_FRESHNESS`): a service that stops mid-catch-up
    /// alarms like any other stopped service, and a drain that stops closing
    /// its gap raises `stuck_drain` instead. Nothing goes quiet.
    ///
    /// Logged on TRANSITION only, not per commit: this runs on every consensus
    /// commit, so an unconditional log would emit thousands of lines an hour
    /// and bury itself. The gauges carry the continuous signal.
    fn report_mpc_consensus_round_lag(&self, commit_round: Round) -> MpcLagReport {
        let Some(progress) = self.mpc_service_progress.load_full() else {
            // The MPC service has not reported a round yet (fresh epoch store,
            // still replaying). Round 0 is a legitimate round to have consumed,
            // so the gauge carries a sentinel rather than a plausible-looking 0.
            // The condition gauges are reset here too: the metrics registry is
            // process-wide while the alarm latches are per-epoch-store, so
            // without this an epoch that ended with a condition raised would
            // keep exporting 1 through the next epoch's sentinel window and
            // then drop to 0 without a Cleared log.
            self.metrics.mpc_consensus_round_lag.set(-1);
            self.metrics
                .mpc_stopped_contributing_condition_active
                .set(0);
            self.metrics.mpc_catch_up_stuck_condition_active.set(0);
            return MpcLagReport::UNCHANGED;
        };
        let lag = commit_round.saturating_sub(progress.consumed_round);
        self.metrics.mpc_consensus_round_lag.set(lag as i64);

        let report_age = progress.observed_at.elapsed();
        let draining = progress.catching_up && report_age < MPC_CATCH_UP_REPORT_FRESHNESS;
        let stuck_drain = self.report_catch_up_drain_progress(lag, draining, commit_round);

        let alarming = lag >= MPC_LAG_ALARM_ROUNDS && !draining;
        let was_alarming = self.mpc_lag_alarm_active.swap(alarming, Ordering::Relaxed);
        self.metrics
            .mpc_stopped_contributing_condition_active
            .set(alarming as i64);
        let stopped_contributing = match (was_alarming, alarming) {
            (false, true) => MpcLagTransition::Raised,
            (true, false) => MpcLagTransition::Cleared,
            _ => MpcLagTransition::Unchanged,
        };
        match stopped_contributing {
            MpcLagTransition::Raised => error!(
                lag_rounds = lag,
                commit_round,
                mpc_consumed_round = progress.consumed_round,
                mpc_catching_up = progress.catching_up,
                report_age_secs = report_age.as_secs(),
                "MPC subsystem has stopped keeping up with consensus: this validator is \
                 following consensus normally but is no longer contributing MPC work. No live \
                 catch-up explains the gap — a validator draining a post-restart backlog keeps \
                 reporting one, and its ika_dwallet_mpc_catchup_gap_rounds falls while it does. \
                 It will not recover on its own in every known case — check for an earlier fatal \
                 in the dWallet MPC service, and restart the node if none explains it"
            ),
            MpcLagTransition::Cleared => info!(
                lag_rounds = lag,
                "MPC subsystem has caught back up with consensus"
            ),
            MpcLagTransition::Unchanged => {}
        }
        MpcLagReport {
            stopped_contributing,
            stuck_drain,
        }
    }

    /// Follows the drain of the catch-up the MPC service is reporting, and
    /// escalates once it has stopped draining.
    ///
    /// `draining` is true only while a live catch-up report is holding the
    /// stopped-contributing alarm, which is exactly when this is the sole
    /// remaining signal. False ends the tracking: the catch-up either finished
    /// (the gate disengaged) or the service stopped reporting it, and the
    /// stopped-contributing alarm covers the second.
    fn report_catch_up_drain_progress(
        &self,
        lag: u64,
        draining: bool,
        commit_round: Round,
    ) -> MpcLagTransition {
        let stalled_for = if draining {
            let now = Instant::now();
            let mut drain = self.mpc_catch_up_drain.lock();
            let progress = drain.get_or_insert(CatchUpDrainProgress {
                lowest_lag_rounds: lag,
                lowest_lag_at: now,
            });
            if lag < progress.lowest_lag_rounds {
                // A new low: the backlog is still shrinking, so the drain is
                // healthy however long it has been running.
                *progress = CatchUpDrainProgress {
                    lowest_lag_rounds: lag,
                    lowest_lag_at: now,
                };
            }
            now.saturating_duration_since(progress.lowest_lag_at)
        } else {
            *self.mpc_catch_up_drain.lock() = None;
            Duration::ZERO
        };

        let alarming = stalled_for >= MPC_CATCH_UP_STUCK_DRAIN;
        let was_alarming = self
            .mpc_catch_up_stuck_alarm_active
            .swap(alarming, Ordering::Relaxed);
        self.metrics
            .mpc_catch_up_stuck_condition_active
            .set(alarming as i64);
        let transition = match (was_alarming, alarming) {
            (false, true) => MpcLagTransition::Raised,
            (true, false) => MpcLagTransition::Cleared,
            _ => MpcLagTransition::Unchanged,
        };
        match transition {
            MpcLagTransition::Raised => error!(
                lag_rounds = lag,
                commit_round,
                stalled_for_secs = stalled_for.as_secs(),
                "MPC catch-up backlog has stopped draining: the MPC service is still reporting \
                 progress and its catch-up gate is still engaged, but the consensus-round gap \
                 has not reached a new low for the whole window above, so this validator is not \
                 on its way back to contributing MPC work. Watch \
                 ika_dwallet_mpc_catchup_gap_rounds: while that gap falls the drain is healthy \
                 and needs no action; this line means it stopped falling. A restart does not \
                 help — it discards the drain's progress and replays it"
            ),
            MpcLagTransition::Cleared => info!(
                lag_rounds = lag,
                "MPC catch-up backlog is draining again, or the catch-up it was stuck in ended"
            ),
            MpcLagTransition::Unchanged => {}
        }
        transition
    }

    /// Queues `handoff_signatures` row mutations for the next commit's batch.
    /// `Some(signature)` upserts the signer's row, `None` deletes it; the last
    /// op staged for a signer before the flush wins, which is what a keyed
    /// table means and what keeps the staging map bounded by committee size.
    ///
    /// No writer of that table may bypass this: a direct write is durable the
    /// moment it is issued, while the close gate that sums the table is
    /// evaluated per commit, and the two then disagree about what state the
    /// commit was decided against (#1927, the class #1920 fixed for votes).
    fn stage_handoff_signature_rows(
        &self,
        rows: impl IntoIterator<Item = (AuthorityName, Option<Ed25519Signature>)>,
    ) {
        self.staged_handoff_signature_rows.lock().extend(rows);
    }

    /// Removes and returns everything staged so far, for folding into the
    /// commit currently being processed.
    fn take_staged_handoff_signature_rows(
        &self,
    ) -> BTreeMap<AuthorityName, Option<Ed25519Signature>> {
        std::mem::take(&mut *self.staged_handoff_signature_rows.lock())
    }

    /// The durable `handoff_signatures` rows as they will stand once `staged`
    /// is written — i.e. the committed table overlaid with a set of pending
    /// ops. Callers that must not see uncommitted state pass nothing and read
    /// the table directly instead.
    fn handoff_signature_rows_with(
        &self,
        staged: &BTreeMap<AuthorityName, Option<Ed25519Signature>>,
    ) -> IkaResult<BTreeMap<AuthorityName, Ed25519Signature>> {
        let mut rows = self
            .tables()?
            .handoff_signatures
            .safe_iter()
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for (signer, op) in staged {
            match op {
                Some(signature) => rows.insert(*signer, signature.clone()),
                None => rows.remove(signer),
            };
        }
        Ok(rows)
    }

    /// Records an incoming `HandoffSignatureMessage` from consensus.
    ///
    /// When no expected attestation is installed yet, the message
    /// is **buffered** into `pending_handoff_signatures` (bounded
    /// by committee size, last-write-wins per signer) so that
    /// `install_expected_handoff_attestation` can replay it once
    /// the local producer side computes the attestation. Messages
    /// from non-committee signers and messages that fail signature
    /// verification (any `HandoffSignatureVerdict` other than
    /// `Accept`) are dropped silently.
    ///
    /// On `Accept` (after an attestation is installed), persists
    /// the per-signer signature into `handoff_signatures`, drives
    /// the in-memory aggregator, and — once at quorum — writes the
    /// cert to perpetual storage, re-persisting the enriched cert as
    /// each later signer adds slack.
    ///
    /// The outcome NEVER affects the bundled `EndOfPublishV2` vote: the EOP
    /// tally must be a deterministic function of the consensus sequence,
    /// while acceptance here depends on per-validator local state (whether
    /// this validator's own expected attestation is installed, whether its
    /// consensus-pubkey provider has loaded). A rejected signature is
    /// dropped (and logged) for the handoff-cert aggregation only — the
    /// cert needs a quorum of valid signatures, not all of them.
    pub fn record_handoff_signature(
        &self,
        msg: &ika_types::handoff::HandoffSignatureMessage,
    ) -> IkaResult<()> {
        let Some(expected) = self.expected_handoff_attestation.load_full() else {
            // No expected attestation yet — this validator hasn't
            // finished its own snapshot ready check. Buffer the
            // peer's signature; `install_expected_handoff_attestation`
            // will replay it once we have something to match against.
            //
            // Membership pre-check: drop signatures from authorities
            // that aren't in the current committee BEFORE the buffer
            // insert. Without this, a byzantine peer can submit
            // arbitrarily many `HandoffSignatureMessage`s with random
            // `signer` names — the per-signer `pending.retain(…)`
            // dedup below would fail to match (every fake name is
            // unique), and the buffer would grow without bound until
            // OOM. With the membership check, the buffer is bounded
            // by committee size N regardless of byzantine spam.
            if self.committee.weight(&msg.signer) == 0 {
                debug!(
                    signer = ?msg.signer,
                    "non-committee handoff signature — dropping before buffer insert"
                );
                return Ok(());
            }
            let mut pending = self.pending_handoff_signatures.lock();
            // Per-signer dedup: a peer re-broadcasting the same V2
            // (or sending two slightly different attestations)
            // shouldn't grow the buffer unbounded. Last-write-wins
            // matches how `process_handoff_signature` treats an
            // already-recorded signer.
            pending.retain(|m| m.signer != msg.signer);
            pending.push(msg.clone());
            self.metrics
                .dwallet_handoff_signatures_buffered
                .set(pending.len() as i64);
            debug!(
                signer = ?msg.signer,
                pending_len = pending.len(),
                "buffering peer handoff signature until expected attestation installs"
            );
            // As soon as the buffered peer signatures show a quorum (by
            // stake) of distinct committee members agreeing on ONE
            // attestation, adopt it even though this validator's own
            // snapshot isn't ready. `install_expected_handoff_attestation`
            // replays the buffer (re-verifying every signature against the
            // adopted attestation) and persists the cert — so a lagging
            // continuing validator reliably holds its own prior-epoch cert
            // instead of having to re-fetch it from peers at the next epoch
            // boundary. Drop the buffer lock first: the install path locks
            // the aggregator and re-drains the buffer.
            let quorum_attestation =
                crate::handoff_cert::quorum_attestation_in_buffer(&self.committee, &pending);
            drop(pending);
            if let Some(attestation) = quorum_attestation {
                info!(
                    epoch = attestation.epoch,
                    "adopting quorum-agreed handoff attestation from buffered peer signatures \
                     (own snapshot not ready) — persisting the cert from the observed quorum"
                );
                self.install_expected_handoff_attestation(attestation)?;
            }
            return Ok(());
        };
        let mut guard = self.handoff_aggregator.lock();
        let Some(aggregator) = guard.as_mut() else {
            // Aggregator wasn't initialized — should be impossible
            // when `expected_handoff_attestation` is set, but bail
            // safely rather than panic.
            warn!("expected handoff attestation set but aggregator missing — dropping");
            return Ok(());
        };
        let outcome = process_handoff_signature(
            msg,
            expected.as_ref(),
            self.committee().as_ref(),
            aggregator,
        );
        let aggregator_signer_count = aggregator.signer_count();
        let aggregator_stake = aggregator.accumulated_stake();
        match outcome {
            HandoffSignatureRecordOutcome::Recorded => {
                self.metrics
                    .dwallet_handoff_signatures_collected
                    .set(aggregator_signer_count as i64);
                self.metrics
                    .dwallet_handoff_signatures_stake
                    .set(aggregator_stake as i64);
                self.stage_handoff_signature_rows([(msg.signer, Some(msg.signature.clone()))]);
                Ok(())
            }
            HandoffSignatureRecordOutcome::Certified(cert) => {
                // The once-per-epoch milestone of the handoff subsystem:
                // a stake quorum agreed on the attestation and the cert
                // exists (formation is logged regardless of whether the
                // persist below succeeds). Re-fires on each later signer's
                // enrichment — bounded by committee size per epoch.
                info!(
                    epoch = cert.attestation.epoch,
                    signers = cert.signatures.len(),
                    items = cert.attestation.items.len(),
                    "handoff attestation reached stake quorum — certified handoff \
                     attestation formed"
                );
                self.metrics
                    .dwallet_handoff_cert_epoch
                    .set(cert.attestation.epoch as i64);
                self.metrics
                    .dwallet_handoff_signatures_collected
                    .set(aggregator_signer_count as i64);
                self.metrics
                    .dwallet_handoff_signatures_stake
                    .set(aggregator_stake as i64);
                self.stage_handoff_signature_rows([(msg.signer, Some(msg.signature.clone()))]);
                // The cert goes to perpetual storage immediately, NOT through
                // the commit batch: it is the once-per-epoch artifact the next
                // epoch's barrier blocks on, it is self-verifying (a quorum of
                // signatures over one attestation), and nothing reads it to
                // decide a consensus-visible outcome. Only the close gate's
                // input needs commit attribution.
                if let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() {
                    if let Err(e) = perpetual
                        .insert_certified_handoff_attestation(cert.attestation.epoch, &cert)
                    {
                        warn!(
                            error = ?e,
                            epoch = cert.attestation.epoch,
                            "failed to persist CertifiedHandoffAttestation — cert remains in-memory only"
                        );
                    }
                } else {
                    debug!(
                        epoch = cert.attestation.epoch,
                        "perpetual tables not installed; handoff cert not persisted"
                    );
                }
                Ok(())
            }
            HandoffSignatureRecordOutcome::Rejected(verdict) => {
                self.metrics
                    .dwallet_handoff_signatures_rejected_total
                    .with_label_values(&[&format!("{verdict:?}")])
                    .inc();
                if matches!(
                    verdict,
                    crate::validator_metadata::HandoffSignatureVerdict::AttestationMismatch
                ) {
                    // Surface per-item digest diffs when keys agree —
                    // a same-keys/different-values mismatch points at
                    // a content-addressed source race (cache populated
                    // before vs. after chain finalization), which the
                    // key-only log can't distinguish from a structural
                    // disagreement.
                    let key_diffs: Vec<_> = expected
                        .items
                        .iter()
                        .zip(msg.attestation.items.iter())
                        .filter_map(|((lk, lv), (sk, sv))| {
                            if lk == sk && lv != sv {
                                Some((lk.clone(), *lv, *sv))
                            } else {
                                None
                            }
                        })
                        .collect();
                    warn!(
                        ?verdict,
                        signer = ?msg.signer,
                        local_epoch = expected.epoch,
                        local_committee_hash = ?expected.next_committee_pubkey_set_hash,
                        local_items_len = expected.items.len(),
                        local_items_keys = ?expected.items.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                        signer_epoch = msg.attestation.epoch,
                        signer_committee_hash = ?msg.attestation.next_committee_pubkey_set_hash,
                        signer_items_len = msg.attestation.items.len(),
                        signer_items_keys = ?msg.attestation.items.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                        same_key_value_diffs = ?key_diffs,
                        "handoff signature rejected: attestation mismatch"
                    );
                } else {
                    warn!(?verdict, signer = ?msg.signer, "handoff signature rejected");
                }
                Ok(())
            }
        }
    }

    pub fn get_validator_mpc_data_announcement(
        &self,
        validator: &AuthorityName,
    ) -> IkaResult<Option<ValidatorMpcDataAnnouncement>> {
        Ok(self
            .tables()?
            .validator_mpc_data_announcements
            .get(validator)?)
    }

    /// This signer's own recorded `EpochMpcDataReadySignal`, if one has
    /// landed this epoch. `MpcDataAnnouncementSender::new` seeds its
    /// re-emit gates from it so a mid-epoch restart resumes above the
    /// already-sequenced sequence numbers instead of colliding with them.
    pub fn get_epoch_mpc_data_ready_signal(
        &self,
        signer: &AuthorityName,
    ) -> IkaResult<Option<ika_types::validator_metadata::EpochMpcDataReadySignal>> {
        Ok(self.tables()?.epoch_mpc_data_ready_signals.get(signer)?)
    }

    /// Computes the set of authorities whose mpc_data blob is
    /// currently locally available AND decode-validates against
    /// the protocol-expected shape. This is what
    /// `EpochMpcDataReadySignal.validated_peers` should be
    /// populated with at emit time.
    ///
    /// Returns an empty vec when perpetual storage isn't attached, or
    /// when no announcements have arrived yet — callers should treat
    /// "fewer than stake-quorum coverage" as "not yet ready to
    /// signal."
    pub fn compute_locally_validated_peers(&self) -> IkaResult<Vec<AuthorityName>> {
        let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() else {
            return Ok(Vec::new());
        };
        let tables = self.tables()?;
        let mut announcements: Vec<(AuthorityName, [u8; 32])> = Vec::new();
        for entry in tables.validator_mpc_data_announcements.safe_iter() {
            let (authority, announcement) = entry?;
            announcements.push((authority, announcement.blob_hash));
        }
        let decision = crate::validator_metadata::decide_locally_validated_peers(
            self.name,
            announcements,
            |digest| {
                perpetual
                    .get_mpc_artifact_blob(digest)
                    .ok()
                    .flatten()
                    .map(|bytes| crate::validator_metadata::blob_decodes_to_valid_mpc_data(&bytes))
                    .unwrap_or(false)
            },
        );
        if decision.self_blob_unhealthy {
            // Own announcement is in the table but the corresponding
            // perpetual blob is missing or fails decode. Attesting
            // to self here would lie to peers (they'd fetch from us
            // and get nothing); surface loudly ONCE per epoch so
            // operators notice and restart this validator to re-persist
            // the blob — the condition has no in-epoch self-heal and
            // this function runs 1-2x per ~2s tick, so repeats go to
            // debug and the gauge carries the ongoing state for alerting.
            self.metrics.own_mpc_data_blob_unhealthy.set(1);
            if !self.self_blob_unhealthy_warned.swap(true, Ordering::AcqRel) {
                warn!(
                    validator = ?self.name,
                    "own announcement is in the per-epoch table but the \
                     corresponding mpc_data blob is missing or invalid in \
                     perpetual storage; refusing to self-attest until the \
                     blob is re-persisted (operator should restart this validator)"
                );
            } else {
                debug!(
                    validator = ?self.name,
                    "own mpc_data blob still missing or invalid in perpetual storage; \
                     refusing to self-attest"
                );
            }
        } else {
            self.metrics.own_mpc_data_blob_unhealthy.set(0);
        }
        self.metrics
            .dwallet_mpc_data_locally_validated_peers
            .set(decision.validated.len() as i64);
        Ok(decision.validated.into_iter().collect())
    }

    /// Like [`Self::compute_locally_validated_peers`], but pairs each
    /// validated peer with the blob hash this validator validated for
    /// it — the payload an `EpochMpcDataReadySignal` carries so the
    /// freeze can be tallied from consensus alone. Peer hashes come
    /// from the local announcement table (which already held them to
    /// fetch + validate the blob); our own hash — in the window before
    /// our announcement lands in the table — comes from
    /// `self_blob_hash` (the producer's freshly-built announcement).
    pub fn validated_peers_with_hashes(
        &self,
        self_blob_hash: [u8; 32],
    ) -> IkaResult<Vec<(AuthorityName, [u8; 32])>> {
        let validated = self.compute_locally_validated_peers()?;
        let tables = self.tables()?;
        let mut pairs = Vec::with_capacity(validated.len());
        for name in validated {
            let hash =
                if let Some(announcement) = tables.validator_mpc_data_announcements.get(&name)? {
                    announcement.blob_hash
                } else if name == self.name {
                    self_blob_hash
                } else {
                    // A validated non-self peer is always in the table (its
                    // blob hash had to be known to fetch + validate the
                    // blob). Skip defensively rather than emit a bogus pair.
                    continue;
                };
            pairs.push((name, hash));
        }
        Ok(pairs)
    }

    /// Whether the locally-validated peer set covers a stake
    /// quorum of the current committee. Used by the announcement
    /// sender as the emit-gate for `EpochMpcDataReadySignal`:
    /// honest validators should not signal "ready" until they
    /// have at least quorum-of-stake of peer mpc_data locally
    /// validated, otherwise downstream freeze could capture a
    /// premature input set and exclude legitimate validators.
    ///
    /// `compute_locally_validated_peers` includes our own authority
    /// when our own blob is locally available (either decode-
    /// validated in perpetual storage, or before our announcement
    /// has landed in the per-epoch table — the producer-just-
    /// submitted window). If our own perpetual blob is missing and
    /// our announcement is already in the table, self is omitted —
    /// see the comment inside that function. The stake sum below
    /// already accounts for self-stake without a separate fixup.
    pub fn local_blob_coverage_meets_quorum(&self) -> IkaResult<bool> {
        let validated = self.compute_locally_validated_peers()?;
        let committee = self.committee();
        let stake: u64 = validated
            .iter()
            .map(|authority| committee.weight(authority))
            .sum();
        Ok(stake >= committee.quorum_threshold())
    }

    /// Checks that a stake quorum of valid handoff signatures has been
    /// recorded this epoch — i.e. a certified handoff attestation can be
    /// minted. Sums the `handoff_signatures` table (written only for
    /// signatures that validated against the locally-installed expected
    /// attestation). Gates the epoch close (#1736): closing before this holds
    /// lets the epoch close while no validator can mint the cert the next
    /// epoch's prepare-then-start barrier requires.
    ///
    /// Evaluated against the state the given commit's batch will make durable:
    /// the committed table overlaid with the rows this commit staged (#1927).
    /// Both halves are needed. Reading only the table would push a signature
    /// recorded by this very commit's `EndOfPublishV2` arm into the NEXT
    /// commit's gate — a one-commit close delay against a binary that writes
    /// on sight, which is a mixed-rollout close-round split. Reading the
    /// un-flushed staging map instead would let rows destined for a LATER
    /// commit decide this one.
    ///
    /// STILL NOT a pure consensus function: rows land only once the LOCAL
    /// expected attestation installs, and a re-install of a DIFFERENT
    /// attestation deletes rows endorsing the superseded one — so the value
    /// can move down as well as up, at commits that differ across validators.
    /// What #1927 changed is that those moves are now attributable to a
    /// commit, so crash-replay reproduces the gate's input — ONCE the expected
    /// attestation is reinstalled — instead of resuming from a table that ran
    /// ahead of the last committed commit. Replay that outruns the reinstall
    /// buffers the redelivered bundles and reaches the close later, via the
    /// drain or the backstop; that is the same off-consensus dependency this
    /// paragraph opens with, not a separate hazard. See
    /// the call-site NOTE in `decide_deferred_epoch_close` for what holds the
    /// close safe against the residual skew, and
    /// dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md for the
    /// planned replacement by a sequence-pure tally.
    pub(crate) fn handoff_signatures_meet_quorum(
        &self,
        output: &ConsensusCommitOutput,
    ) -> IkaResult<bool> {
        let committee = self.committee();
        let stake: u64 = self
            .handoff_signature_rows_with(output.handoff_signature_rows())?
            .into_keys()
            .map(|signer| committee.weight(&signer))
            .sum();
        Ok(stake >= committee.quorum_threshold())
    }

    /// Pure epoch-close decision (#1736), factored out so the handoff-cert
    /// coupling is unit-tested independently of the consensus machinery.
    /// Returns `None` to keep waiting, `Some(false)` for a normal close
    /// (handoff-cert quorum reached), `Some(true)` for a liveness-backstop close
    /// (the quorum could not form within the bounded backstop window).
    ///
    /// The close requires the existing EndOfPublish readiness (`eop_ready` = all
    /// voted, or the grace elapsed) AND a handoff-cert quorum — EXCEPT after the
    /// backstop (a small multiple of the EndOfPublish grace), which closes
    /// regardless to preserve liveness against a genuinely non-signing
    /// validator. The close never fires before EndOfPublish readiness.
    fn decide_deferred_epoch_close(
        eop_ready: bool,
        handoff_cert_quorum: bool,
        rounds_since_quorum: u64,
        end_of_publish_grace_rounds: u64,
    ) -> Option<bool> {
        /// How many EndOfPublish-grace windows to wait for the handoff-cert
        /// quorum before closing on the liveness backstop.
        const HANDOFF_CERT_BACKSTOP_GRACE_MULTIPLIER: u64 = 4;
        if !eop_ready {
            return None;
        }
        if handoff_cert_quorum {
            Some(false)
        } else if rounds_since_quorum
            >= end_of_publish_grace_rounds.saturating_mul(HANDOFF_CERT_BACKSTOP_GRACE_MULTIPLIER)
        {
            Some(true)
        } else {
            None
        }
    }

    /// Records an `EpochMpcDataReadySignal`. A signer's signal may
    /// be re-emitted within the same epoch when their local
    /// `validated_peers` set grows (see
    /// `mpc_data_announcement_sender::send_epoch_ready_signal`).
    /// We honor that by accepting a follow-up signal from a
    /// recorded signer iff the new canonical peer set is a strict
    /// superset of the stored one; same-or-shrinking updates are
    /// dropped to keep one-shot semantics and prevent a byzantine
    /// signer from oscillating between attestation sets to mess
    /// with the tally. The *first* time the set of signers
    /// reaches `quorum_threshold` by stake, the
    /// attestation-tally freeze runs (idempotent on a non-empty
    /// frozen table).
    pub fn record_epoch_mpc_data_ready_signal(
        &self,
        signal: &ika_types::validator_metadata::EpochMpcDataReadySignal,
    ) -> IkaResult {
        let current_epoch = self.epoch();
        if signal.epoch != current_epoch {
            warn!(
                signal_epoch = signal.epoch,
                current_epoch, "epoch mpc data ready signal epoch mismatch — dropping"
            );
            return Ok(());
        }
        let tables = self.tables()?;
        let existing = tables.epoch_mpc_data_ready_signals.get(&signal.authority)?;
        let committee = self.committee();
        // Canonicalize via the pure helper — dedup + a current-committee
        // quorum-coverage floor + a deterministic length cap. CRITICAL:
        // this MUST be a pure function of the sequenced signal bytes, so
        // it does NOT consult the local announcements table (a
        // wall-clock-populated, JoinerPubkeyProvider-gated view). Instead
        // it KEEPS every deduped peer — including a next-epoch joiner with
        // zero current weight — so two honest validators with different
        // provider-install timing persist the identical canonical set for
        // the same sequenced signal. Coverage is measured on current
        // weight only, so a sparse signal still can't push the freeze
        // trigger; a joiner is frozen only when a stake-quorum of signers
        // attest it in the tally (`compute_freeze_partition`).
        //
        // Cap = K × current committee size: the deduped length is
        // identical across honest validators (same sequenced bytes), so
        // the cap decision is itself consensus-deterministic.
        const READY_SIGNAL_PEERS_CAP_MULTIPLIER: usize = 4;
        let cap = committee
            .num_members()
            .saturating_mul(READY_SIGNAL_PEERS_CAP_MULTIPLIER);
        let (outcome, diagnostics) = crate::validator_metadata::canonicalize_ready_signal_peers(
            &signal.validated_peers,
            |peer| committee.weight(peer),
            committee.quorum_threshold(),
            cap,
        );
        let canonical_peers = match outcome {
            crate::validator_metadata::CanonicalizeReadySignalOutcome::Accept {
                validated_peers,
            } => validated_peers,
            crate::validator_metadata::CanonicalizeReadySignalOutcome::BelowQuorumCoverage {
                coverage_stake,
                quorum,
            } => {
                warn!(
                    signer = ?signal.authority,
                    coverage_stake,
                    quorum,
                    "EpochMpcDataReadySignal below quorum coverage — dropping; \
                     signer should re-broadcast once they have more peer blobs validated"
                );
                return Ok(());
            }
            crate::validator_metadata::CanonicalizeReadySignalOutcome::OverCap { len, cap } => {
                warn!(
                    signer = ?signal.authority,
                    len,
                    cap,
                    "EpochMpcDataReadySignal exceeds the peer-count cap — dropping; \
                     likely a byzantine signer padding garbage names"
                );
                return Ok(());
            }
        };
        // Strict-superset re-emit gate: if we already have a
        // signal from this authority, only accept the new one if
        // it widens the attestation set. Same-or-shrinking sets
        // are dropped — keeps one-shot semantics for tally and
        // prevents a byzantine signer from oscillating attestation
        // sets to disturb the partition.
        if let Some(existing) = existing.as_ref() {
            // Monotonicity is over the set of attested *peers* (names),
            // not the `(peer, hash)` pairs: the validated set only ever
            // grows, and a rare re-announce that changes a peer's hash
            // shouldn't be treated as growth. The hashes ride along for
            // the freeze tally.
            let existing_set: BTreeSet<AuthorityName> = existing
                .validated_peers
                .iter()
                .map(|(name, _)| *name)
                .collect();
            let new_set: BTreeSet<AuthorityName> =
                canonical_peers.iter().map(|(name, _)| *name).collect();
            if !new_set.is_superset(&existing_set) || new_set.len() == existing_set.len() {
                debug!(
                    signer = ?signal.authority,
                    existing_len = existing_set.len(),
                    new_len = new_set.len(),
                    "ignoring non-superset EpochMpcDataReadySignal re-emit"
                );
                return Ok(());
            }
        }
        // Surface anomalies. Placed AFTER the strict-superset gate so a
        // byzantine signer re-submitting the same payload every consensus
        // round doesn't log-flood: the gate drops the repeat above, so only
        // the first anomalous payload (or a strictly-grown one) makes it
        // here. Two distinct signals, judged separately:
        // - DUPLICATES are a genuine byzantine tell — honest emitters dedup
        //   before broadcast — so they warn.
        // - Non-committee names are NOT: honest emitters deliberately
        //   include announced next-epoch JOINERS (zero current-epoch
        //   weight), so a non-empty `non_committee_kept` is the expected
        //   shape of every honest signal in a churn epoch. Only an
        //   implausibly large kept set (more kept zero-weight names than
        //   committee seats — no honest joiner population looks like that)
        //   warns; the routine case logs at debug. Kept names are inert for
        //   assembly unless a stake-quorum of signers attest them, but they
        //   DO land in `epoch_excluded_validators` and the excluded gauge,
        //   and each one holds the full-coverage fast path open (the freeze
        //   then fires via the grace path) — bounded, deterministic, and
        //   the price of keeping canonicalization a pure function of the
        //   sequenced bytes.
        if diagnostics.duplicates_collapsed != 0 {
            warn!(
                signer = ?signal.authority,
                duplicates_collapsed = diagnostics.duplicates_collapsed,
                "EpochMpcDataReadySignal padded with duplicate names — likely \
                 byzantine signer (honest emitters dedup before broadcast)"
            );
        }
        if !diagnostics.non_committee_kept.is_empty() {
            if diagnostics.non_committee_kept.len() > committee.num_members() {
                warn!(
                    signer = ?signal.authority,
                    non_committee_kept = ?diagnostics.non_committee_kept,
                    "EpochMpcDataReadySignal carries more zero-weight names than \
                     committee seats — likely byzantine padding (kept names are \
                     inert for assembly but hold the full-coverage fast path open \
                     until the freeze grace)"
                );
            } else {
                debug!(
                    signer = ?signal.authority,
                    non_committee_kept = ?diagnostics.non_committee_kept,
                    "EpochMpcDataReadySignal attests zero-weight names (expected \
                     for announced next-epoch joiners)"
                );
            }
        }
        let canonical = ika_types::validator_metadata::EpochMpcDataReadySignal {
            authority: signal.authority,
            epoch: signal.epoch,
            sequence_number: signal.sequence_number,
            validated_peers: canonical_peers,
        };
        tables
            .epoch_mpc_data_ready_signals
            .insert(&signal.authority, &canonical)?;
        let recorded_ready_signals = tables
            .epoch_mpc_data_ready_signals
            .safe_iter()
            .filter_map(Result::ok)
            .count();
        self.metrics
            .dwallet_mpc_data_ready_signals
            .set(recorded_ready_signals as i64);

        // NOTE: recording a ready-signal does not trigger the freeze.
        // The freeze is decided at the consensus commit boundary (see
        // `process_consensus_transactions_and_commit_boundary`): once a
        // stake-quorum of signals is in, it fires at full coverage or after
        // `mpc_data_freeze_grace_rounds` of consensus progress — never at
        // the first quorum, when slower validators' mpc_data hasn't
        // propagated yet. Signals keep accruing here (and validators
        // re-emit as their coverage grows) so the deferred freeze captures
        // the complete set.
        Ok(())
    }

    /// Computes the per-announcer attestation tally and snapshots
    /// the frozen working set + excluded set. Idempotent on a
    /// non-empty frozen table.
    ///
    /// Fired from the consensus commit boundary once a stake-quorum of
    /// `EpochMpcDataReadySignal`s has been recorded AND coverage is full
    /// (or the freeze grace elapsed) — see the freeze block in
    /// `process_consensus_transactions_and_commit_boundary`. For each
    /// validator V that announced this epoch:
    /// - sum the stake of every signer whose `validated_peers`
    ///   contains V,
    /// - if that stake ≥ committee quorum threshold, V enters
    ///   `frozen_validator_mpc_data_input_set`,
    /// - otherwise V enters `epoch_excluded_validators`.
    ///
    /// This makes "you're in the working set" consensus-
    /// deterministic and stake-quorum-attested: a malicious
    /// announcer who withheld their blob from honest peers can't
    /// be smuggled into the working set, even if they signed a
    /// valid announcement digest.
    /// The prior epoch's handoff-certificate `validator -> mpc_data
    /// digest` map, used to carry forward stable mpc_data for committee
    /// members that did not freshly announce this epoch (see
    /// `carry_forward_stable_mpc_data`). Empty (`Ok(HashMap::new())`) only
    /// for the chain-true no-cert epochs — genesis, a v3 prior epoch, or the
    /// first v4 epoch — where carry-forward legitimately degrades to
    /// announce-only uniformly across the committee. The certificate is
    /// perpetual and stake-quorum-signed. NOTE the uniformity of `Ok(None)`
    /// currently rests on the prepare-then-start barrier holding the
    /// prior-epoch certificate before this epoch's consensus is processed —
    /// which today is wired only into the continuing-validator reconfigure
    /// path; the joiner-promotion and cold-startup consensus-start paths do
    /// not yet pass the barrier (deferred — see
    /// dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md), so a
    /// first-time joiner racing its bootstrap fetch can still hit `Ok(None)`
    /// and freeze without the carry-forward map. This function closes the
    /// READ-ERROR flavor of the shrunken-set fork; the absent-cert flavor
    /// closes when the barrier covers all consensus-start paths.
    ///
    /// A cert READ ERROR is PROPAGATED, not degraded to empty: silently
    /// returning an empty map on a transient read failure would shrink THIS
    /// validator's frozen set (dropping every carry-forward member) while
    /// peers that read the cert fine keep them — a divergent frozen set is a
    /// consensus fork. Propagating makes the freeze fail-stop: the commit
    /// errors, the consensus handler's `.expect` panics the node, and the
    /// commit replays on restart until the read succeeds. This is the
    /// freeze-path realization of handoff.md invariant 4 ("fail open with
    /// retry on read errors"), and it mirrors the ready-signals read in
    /// `freeze_mpc_data_if_first`, which already `?`-propagates.
    ///
    /// Second consumer: the ready-signal emit gate
    /// (`MpcDataAnnouncementSender::ready_to_finalize`) reads the same map
    /// to know which members carry-forward covers, so they don't hold the
    /// gate open. THAT read is emit-timing only, so the caller degrades an
    /// `Err` to an empty map (wait longer) instead of propagating —
    /// fail-loud is a freeze-commit requirement, not a property of this
    /// function.
    pub(crate) fn prior_epoch_mpc_data_digests(
        &self,
    ) -> IkaResult<HashMap<AuthorityName, [u8; 32]>> {
        let Some(prior_epoch) = self.epoch().checked_sub(1) else {
            return Ok(HashMap::new());
        };
        // A missing perpetual handle at a freeze commit is a LOCAL
        // initialization fault, not a chain-true no-cert case: both
        // epoch-store creation sites install the handle before consensus can
        // process a commit, so the handle must be present at any freeze
        // commit. Fail the commit (replay) like the read
        // error below — a silent Ok(empty) here would reintroduce the exact
        // shrunken-set fork this function exists to close, via the arm two
        // lines above the fix. Unreachable today; guards future init-order
        // refactors.
        let Some(perpetual) = self.perpetual_tables_for_handoff.load_full() else {
            error!(
                prior_epoch,
                "perpetual-tables handle missing at the mpc_data freeze; failing the \
                 commit so it replays after initialization completes"
            );
            return Err(IkaError::Unknown(
                "perpetual-tables handle not installed at the mpc_data freeze".to_string(),
            ));
        };
        let cert = match perpetual.get_certified_handoff_attestation(prior_epoch) {
            Ok(Some(cert)) => cert,
            Ok(None) => return Ok(HashMap::new()),
            Err(e) => {
                error!(
                    error = ?e,
                    prior_epoch,
                    "failed to read prior-epoch handoff cert for mpc_data carry-forward; \
                     failing the freeze so the commit replays rather than freezing a \
                     divergent (shrunken) mpc_data set",
                );
                return Err(e);
            }
        };
        // The cert names its items in the PRIOR epoch's identity basis. At
        // the protocol-v6 activation boundary that differs from this epoch's,
        // and every carry-forward lookup would miss silently — dropping each
        // seated member that did not freshly announce this epoch into the
        // excluded set, which is precisely the safety net carry-forward
        // exists to provide. Translate into this epoch's basis at the source
        // so every consumer of these digests is keyed consistently; away from
        // the boundary the map is empty of surprises and this is a no-op.
        Ok(cert
            .attestation
            .items
            .iter()
            .filter_map(|(key, digest)| match key {
                ika_types::handoff::HandoffItemKey::ValidatorMpcData { validator } => {
                    Some((*validator, *digest))
                }
                _ => None,
            })
            .collect())
    }

    fn freeze_mpc_data_if_first(
        &self,
        tables: &AuthorityEpochTables,
        output: &mut ConsensusCommitOutput,
    ) -> IkaResult {
        if !tables.frozen_validator_mpc_data_input_set.is_empty() {
            return Ok(());
        }
        let committee = self.committee();
        // Tally purely from the consensus-ordered ready-signals — each
        // carrying `(peer, blob_hash)` pairs — so every honest
        // validator computes the identical frozen set. We deliberately
        // do NOT read the local announcement table here: a relayed
        // joiner announcement this validator dropped/buffered (while
        // its joiner-pubkey provider lagged) would otherwise shrink the
        // frozen set and diverge from peers. Materialized as a
        // `BTreeMap` so the pure tally function can be unit-tested
        // without an `AuthorityPerEpochStore`.
        let mut signals: std::collections::BTreeMap<AuthorityName, Vec<(AuthorityName, [u8; 32])>> =
            std::collections::BTreeMap::new();
        for entry in tables.epoch_mpc_data_ready_signals.safe_iter() {
            let (signer, signal) = entry?;
            signals.insert(signer, signal.validated_peers);
        }
        let committee_for_tally = committee.clone();
        let attested = crate::validator_metadata::compute_freeze_partition(
            &signals,
            |authority| committee_for_tally.weight(authority),
            committee.quorum_threshold(),
        );
        // Carry forward stable mpc_data: a committee member that did not
        // freshly announce this epoch is frozen at the digest the prior
        // epoch's handoff cert already agreed for it. The blob is a pure
        // function of the validator's root seed, so the carried digest is
        // byte-identical to a fresh announcement. Without this, a member
        // that entered the epoch late — a routine restart near the
        // boundary — is dropped from the frozen set, and the
        // reconfiguration into the next epoch is rejected forever because
        // a still-seated member's class-groups material is missing. Only
        // first-time joiners (no prior-cert digest) remain excludable.
        let attested_frozen = attested.frozen.len();
        let committee_members: Vec<AuthorityName> = committee
            .voting_rights
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let prior_mpc_data = self.prior_epoch_mpc_data_digests()?;
        let partition = crate::validator_metadata::carry_forward_stable_mpc_data(
            attested,
            &committee_members,
            &prior_mpc_data,
        );
        info!(
            current_epoch = self.epoch(),
            frozen = partition.frozen.len(),
            attested = attested_frozen,
            carried_forward = partition.frozen.len().saturating_sub(attested_frozen),
            excluded = partition.excluded.len(),
            excluded_set = ?partition.excluded,
            "ready quorum reached — freezing attestation-validated mpc_data input set (stable carry-forward applied)"
        );
        self.metrics
            .dwallet_mpc_data_freeze_epoch
            .set(self.epoch() as i64);
        self.metrics
            .dwallet_mpc_data_excluded_validators
            .set(partition.excluded.len() as i64);
        // Persist through the commit's batch, NOT per-row inserts: the frozen
        // + excluded rows must land atomically with this commit's
        // processed-markers (`last_consensus_stats`). A crash between per-row
        // inserts left a strict subset latched as frozen forever — the
        // non-empty-table idempotence guard above stopped the replayed commit
        // from re-firing, and the shrunken set byte-diverged this validator's
        // reconfiguration output from the committee's (issue #1829). With the
        // batch, a crash before the write replays the whole commit and the
        // freeze re-fires cleanly; after it, the full partition is on disk.
        output.set_mpc_data_freeze_partition(partition);
        Ok(())
    }

    /// Returns the per-epoch set of authorities the freeze gate
    /// excluded from the working set. Consensus-deterministic
    /// across honest validators; downstream consumers
    /// (`Committee.class_groups_public_keys_and_proofs` build,
    /// handoff item generation, reconfig MPC kickoff) treat
    /// membership as "this validator is excluded from MPC this
    /// epoch — same semantics as on-chain bad mpc_data today."
    pub fn get_epoch_excluded_validators(
        &self,
    ) -> IkaResult<std::collections::HashSet<AuthorityName>> {
        Ok(self
            .tables()?
            .epoch_excluded_validators
            .safe_iter()
            .filter_map(Result::ok)
            .map(|(authority, _)| authority)
            .collect())
    }

    /// Returns the frozen `validator -> blob_hash` snapshot, or an
    /// empty map if the freeze hasn't fired yet this epoch.
    pub fn get_frozen_validator_mpc_data_input_set(
        &self,
    ) -> IkaResult<HashMap<AuthorityName, [u8; 32]>> {
        Ok(self
            .tables()?
            .frozen_validator_mpc_data_input_set
            .safe_iter()
            .filter_map(Result::ok)
            .collect())
    }

    /// The epoch's consensus clock: the max `commit_timestamp_ms` over all
    /// consensus commits processed so far, or `None` if no commit has been
    /// processed since this store opened (fresh epoch, or a restart whose
    /// replay hasn't reached the handler yet). Emit-timing consumer only.
    pub(crate) fn max_processed_commit_timestamp_ms(&self) -> Option<u64> {
        match self
            .max_processed_commit_timestamp_ms
            .load(Ordering::Acquire)
        {
            0 => None,
            timestamp_ms => Some(timestamp_ms),
        }
    }

    /// Commit timestamp of the epoch's first processed consensus commit
    /// (the persisted ready-signal backstop anchor), or `None` before any
    /// commit landed.
    pub(crate) fn epoch_first_commit_timestamp_ms(&self) -> IkaResult<Option<u64>> {
        self.tables()?
            .epoch_first_commit_timestamp_ms
            .get(&0)
            .map_err(IkaError::from)
    }

    /// The consensus round at which this epoch's mpc_data ready-signal
    /// stake quorum was first observed (the freeze-grace anchor, written
    /// with that commit's batch), or `None` if quorum hasn't been reached.
    /// Consensus-anchored: identical across honest validators.
    pub(crate) fn mpc_data_ready_quorum_round(&self) -> IkaResult<Option<u64>> {
        self.tables()?
            .mpc_data_ready_quorum_round
            .get(&0)
            .map_err(IkaError::from)
    }

    /// The consensus leader round at which this validator observed the
    /// `EndOfPublish` stake quorum — the persisted anchor of the
    /// deferred-close grace countdown — or `None` if quorum hasn't been
    /// reached this epoch.
    pub fn end_of_publish_quorum_round(&self) -> IkaResult<Option<u64>> {
        Ok(self.tables()?.end_of_publish_quorum_round.get(&0)?)
    }

    /// Whether this validator has already emitted the epoch-close
    /// checkpoint message set. Persisted through the emitting commit's
    /// batch so a restart cannot re-emit the close at a later commit.
    pub fn is_epoch_close_emitted(&self) -> IkaResult<bool> {
        Ok(self.tables()?.epoch_close_emitted.get(&0)?.is_some())
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
    pub(crate) fn verify_consensus_transaction(
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
                kind: ConsensusTransactionKind::IdleStatusUpdate(update),
                ..
            }) => {
                if transaction.sender_authority() != update.authority {
                    warn!(
                        "IdleStatusUpdate authority {} does not match its author from consensus {}",
                        update.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::SuiChainObservationUpdate(update),
                ..
            }) => {
                if transaction.sender_authority() != update.authority {
                    warn!(
                        "SuiChainObservationUpdate authority {} does not match its author from consensus {}",
                        update.authority, transaction.certificate_author_index
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
                // The EndOfPublishV2 bundled variant is the only
                // legitimate way to vote EOP at every supported
                // protocol version. A peer emitting standalone V1 is
                // misconfigured — drop it so we don't count the vote
                // against a missing handoff.
                warn!(
                    %authority,
                    "EndOfPublish (V1) received — drop (V2 is the only valid variant)"
                );
                return None;
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind:
                    ConsensusTransactionKind::EndOfPublishV2 {
                        authority,
                        handoff_signature,
                    },
                ..
            }) => {
                if &transaction.sender_authority() != authority {
                    warn!(
                        "EndOfPublishV2 authority {} does not match its author from consensus {}",
                        authority, transaction.certificate_author_index
                    );
                    return None;
                }
                // The bundled handoff signature must be signed by the
                // same validator that is sending the EndOfPublish
                // vote — disallow replaying another validator's
                // handoff signature alongside one's own EOP.
                if handoff_signature.signer != *authority {
                    warn!(
                        "EndOfPublishV2 bundled handoff signer {} does not match EOP authority {}",
                        handoff_signature.signer, authority
                    );
                    return None;
                }
                // The bundled attestation must be for the current
                // epoch. Without this check, a peer could bundle a
                // stale-epoch attestation: `record_handoff_signature`
                // would reject the handoff half with
                // `AttestationMismatch`, but the EOP vote half of
                // `process_consensus_transaction` would still count.
                let current_epoch = self.epoch();
                if handoff_signature.attestation.epoch != current_epoch {
                    warn!(
                        attestation_epoch = handoff_signature.attestation.epoch,
                        current_epoch,
                        signer = %handoff_signature.signer,
                        "EndOfPublishV2 bundled attestation is for a different epoch — dropping"
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::GlobalPresignRequest(msg),
                ..
            }) => {
                if transaction.sender_authority() != msg.authority {
                    warn!(
                        "GlobalPresignRequest authority {} does not match its author from consensus {}",
                        msg.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::NOAObservation(msg),
                ..
            }) => {
                if transaction.sender_authority() != msg.authority {
                    warn!(
                        "NOAObservation authority {} does not match its author from consensus {}",
                        msg.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::NOAPresignDemand(msg),
                ..
            }) => {
                if transaction.sender_authority() != msg.authority {
                    warn!(
                        "NOAPresignDemand authority {} does not match its author from consensus {}",
                        msg.authority, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::ValidatorMpcDataAnnouncement(announcement, _),
                ..
            }) => {
                // Self-submission: the consensus block author IS the
                // announcer. Enforce it here so a validator can't
                // submit an announcement attributed to someone else
                // (that's what the relayed kind, with its Ed25519
                // joiner signature, is for).
                if transaction.sender_authority() != announcement.validator {
                    warn!(
                        "ValidatorMpcDataAnnouncement validator {} does not match its author from consensus {}",
                        announcement.validator, transaction.certificate_author_index
                    );
                    return None;
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(signed, _),
                ..
            }) => {
                // The wire authority binding is the *relayer* — any
                // current-committee validator may relay a joiner's
                // announcement, so there's no sender constraint here.
                // The joiner's Ed25519 consensus-key signature over
                // the inner announcement is what authenticates the
                // joiner's intent, and it's checked downstream when
                // the record handler runs.
                let _ = signed;
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::EpochMpcDataReadySignal(signal),
                ..
            }) => {
                if transaction.sender_authority() != signal.authority {
                    warn!(
                        "EpochMpcDataReadySignal authority {} does not match its author from consensus {}",
                        signal.authority, transaction.certificate_author_index
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
        C: DWalletCheckpointServiceNotify,
    >(
        &self,
        verified_transactions: Vec<VerifiedSequencedConsensusTransaction>,
        consensus_stats: &ExecutionIndicesWithStats,
        checkpoint_service: &Option<Arc<C>>,
        system_checkpoint_service: &Option<Arc<SystemCheckpointService>>,
        consensus_commit_info: &ConsensusCommitInfo,
        authority_metrics: &Arc<AuthorityMetrics>,
    ) -> IkaResult<(
        Vec<DWalletCheckpointMessageKind>,
        Vec<SystemCheckpointMessageKind>,
    )> {
        let mut output = ConsensusCommitOutput::new(consensus_commit_info.round);

        // Epoch consensus clock: advance the in-memory running max of
        // processed commit timestamps, and persist the FIRST commit's
        // timestamp once (the ready-signal backstop anchor — replay
        // resumes from the last processed commit, so "first" is
        // unrecoverable unless written with its own commit's batch).
        self.max_processed_commit_timestamp_ms
            .fetch_max(consensus_commit_info.timestamp, Ordering::AcqRel);
        if self
            .tables()?
            .epoch_first_commit_timestamp_ms
            .get(&0)?
            .is_none()
        {
            output.set_epoch_first_commit_timestamp_ms(consensus_commit_info.timestamp);
        }

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
                authority_metrics,
            )
            .await?;
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
        if make_checkpoint {
            output.record_verified_system_checkpoint_messages(
                verified_system_checkpoint_messages.clone(),
            );
        }
        if self.protocol_config().bls_checkpoints()
            && make_checkpoint
            && !verified_system_checkpoint_messages.is_empty()
        {
            let checkpoint_height = consensus_commit_info.round;

            let pending_system_checkpoint =
                PendingSystemCheckpoint::V1(PendingSystemCheckpointV1 {
                    messages: verified_system_checkpoint_messages.clone(),
                    details: PendingSystemCheckpointInfo { checkpoint_height },
                });
            self.write_pending_system_checkpoint(&mut output, &pending_system_checkpoint)?;
        }

        // Take the drain's inputs before the batch, hand them over after it.
        // After, so the drain never sees a round whose commit did not land;
        // outside the batch, so a wait on the drain does not hold a write
        // batch open.
        let round_payload = output.take_round_payload();

        let mut batch = self.db_batch()?;
        output.write_to_batch(self, &mut batch)?;
        batch.write()?;

        if let Some(transport) = self.round_transport() {
            // BLOCKS while the drain is behind — see `round_transport`.
            transport.send(round_payload).await;
        }

        // Only after batch is written, notify checkpoint service to start building any new
        // pending checkpoints.
        if self.protocol_config().bls_checkpoints()
            && make_checkpoint
            && !verified_system_checkpoint_messages.is_empty()
        {
            debug!(
                ?consensus_commit_info.round,
                "Notifying system_checkpoint service about new pending checkpoint(s)",
            );
            if let Some(service) = system_checkpoint_service {
                service.notify_checkpoint()?;
            }
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
        checkpoint_service: &Option<Arc<C>>,
        system_checkpoint_service: &Option<Arc<SystemCheckpointService>>,
        consensus_commit_info: &ConsensusCommitInfo,
        //roots: &mut BTreeSet<MessageDigest>,
        authority_metrics: &Arc<AuthorityMetrics>,
    ) -> IkaResult<(
        Vec<DWalletCheckpointMessageKind>, // transactions to schedule
        Vec<SystemCheckpointMessageKind>,
        Vec<SequencedConsensusTransactionKey>, // keys to notify as complete
    )> {
        let _scope = monitored_scope("ConsensusCommitHandler::process_consensus_transactions");

        // The freeze / epoch-close grace countdowns below are leader-round
        // deltas against `consensus_commit_info.round`; export the same
        // round so dashboards subtract in the identical domain (NOT
        // `ika_last_process_mpc_consensus_round`, the MPC service's consumed
        // round, which lags this one).
        self.metrics
            .last_committed_leader_consensus_round
            .set(consensus_commit_info.round as i64);
        self.metrics
            .consensus_last_committed_timestamp_seconds
            .set((consensus_commit_info.timestamp / 1000) as i64);
        // Self-health: is the MPC subsystem keeping up with consensus? Sampled
        // HERE, on the commit path, because that path is still running in every
        // case where MPC is not — including the deliberate service-loop `break`
        // on self-recognised maliciousness, which stops MPC for the life of the
        // process while the node keeps serving consensus and looking healthy
        // from outside (ika #1978, #1980).
        let _ = self.report_mpc_consensus_round_lag(consensus_commit_info.round);

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
            }
            if !ignored {
                output.record_consensus_message_processed(key.clone());
            }
        }

        // Fold every `handoff_signatures` row staged since the last commit
        // into this one — both the rows this commit's `EndOfPublishV2` arms
        // just staged and any staged off-thread by an attestation install
        // that finished before this commit was processed. Placed here, after
        // the transaction loop and before the close gate reads them, so the
        // gate decides against precisely the rows this commit will persist.
        // A drain landing mid-processing simply lands in the next commit; the
        // point is that it lands in ONE commit and never in the gap between
        // a decision and its batch (#1927).
        output.record_handoff_signature_rows(self.take_staged_handoff_signature_rows());

        // EndOfPublish close grace: once a stake-quorum of
        // EndOfPublish votes is in, defer the epoch close
        // `end_of_publish_grace_rounds` (protocol config) more consensus
        // rounds (unless every committee member has already voted) so
        // stragglers' `EndOfPublishV2` bundles — carrying their handoff
        // signatures — are still sequenced before the epoch closes. The anchor
        // round is persisted, so a validator restarting mid-grace closes at the
        // same round as its peers (the final checkpoint must be deterministic).
        let already_closed = matches!(
            self.reconfig_state.read().status,
            ReconfigCertStatus::RejectAllTx
        );
        if !already_closed {
            let (has_quorum, voted_count) = {
                let end_of_publish = self.end_of_publish.lock();
                (end_of_publish.has_quorum(), end_of_publish.keys().count())
            };
            if has_quorum {
                // The anchor round is written through the commit batch (not
                // out-of-band) so it commits atomically with the commit that
                // observed quorum — a crash before the batch replays the
                // whole commit and re-derives the same round.
                let quorum_round = match self.tables()?.end_of_publish_quorum_round.get(&0)? {
                    Some(round) => round,
                    None => {
                        // Once per epoch: the anchor of the deferred-close
                        // grace countdown. Without this, an epoch hanging
                        // between quorum and close leaves no info-level
                        // evidence that quorum was ever reached.
                        info!(
                            validator = ?self.name,
                            quorum_round = consensus_commit_info.round,
                            voted_count,
                            grace_rounds = self.protocol_config().end_of_publish_grace_rounds(),
                            "EndOfPublish stake quorum reached — deferring epoch close for \
                             grace rounds",
                        );
                        output.set_end_of_publish_quorum_round(consensus_commit_info.round);
                        consensus_commit_info.round
                    }
                };
                // The `all_voted` input is pinned at the quorum-observing
                // commit and read back from storage thereafter, so it cannot
                // grow underneath a restart (#1917). Reading the LIVE
                // aggregator here would make the close round depend on
                // whether this validator happened to restart: the live count
                // stops at the quorum-crossing membership, while the
                // restart-hydrated one is the full vote set.
                //
                // Written in the same commit batch as the anchor above, so
                // the two are always consistent. The `None` arm also covers
                // an epoch that reached quorum under a binary predating this
                // record: the in-memory count is then exactly what that
                // binary itself used at this commit, so adopting it keeps
                // close timing identical across the upgrade.
                let quorum_voted_count =
                    match self.tables()?.end_of_publish_quorum_voted_count.get(&0)? {
                        Some(count) => count,
                        None => {
                            let count = voted_count as u64;
                            output.set_end_of_publish_quorum_voted_count(count);
                            count
                        }
                    };
                let all_voted = quorum_voted_count >= self.committee().num_members() as u64;
                // Consensus leader rounds advance in sequence but NOT by a
                // fixed +1 per commit — rounds skip when a leader is not
                // committed — so the grace is measured as the leader-round
                // DELTA since quorum (robust to skips), not a commit count.
                let rounds_since_quorum = consensus_commit_info.round.saturating_sub(quorum_round);
                let grace_elapsed =
                    rounds_since_quorum >= self.protocol_config().end_of_publish_grace_rounds();
                let eop_ready = all_voted || grace_elapsed;

                // #1736: the next epoch's prepare-then-start barrier (ika-node)
                // blocks until it holds a certified handoff attestation — a
                // stake quorum of valid handoff signatures, carried in the
                // sequenced `EndOfPublishV2` bundles and recorded in
                // `handoff_signatures`. The EndOfPublish *vote* is counted even
                // when a validator's bundled handoff signature is REJECTED, so
                // closing on the EndOfPublish grace alone can close the epoch
                // while the handoff cert is born on NO validator — every
                // validator then blocks at the barrier and the chain wedges.
                // Require the handoff-cert quorum before closing. NOTE: this gate
                // is commit-attributable but still NOT a pure consensus function.
                // Every row now lands in exactly one commit's batch (#1927), so
                // the gate can no longer be decided against a table that ran
                // ahead of the last committed commit, and a crash-replay of this
                // commit re-derives the same input once the expected attestation
                // is reinstalled. But WHETHER a row exists at a
                // given round still depends on off-consensus state — this
                // validator's `expected_handoff_attestation` install and its
                // consensus-pubkey provider (a ~5s background Sui poll); until
                // both are present, sequenced `EndOfPublishV2` bundles buffer and
                // write no row. The gate can also move DOWN: re-installing a
                // different expected attestation deletes rows endorsing the
                // superseded one, so a validator that adopted the quorum's
                // attestation and then rebuilt a divergent local one flips this
                // gate true -> false and misses the quorum's close commit. So
                // close-determinism does NOT come from this gate being a
                // deterministic function of the sequence; it comes from
                // buffered-quorum adoption (a lagging validator reaches quorum
                // from peers' signatures at the same sequenced bundle index) plus
                // the `grace*4` liveness backstop in `decide_deferred_epoch_close`,
                // which also covers the deletion-flipped validator (it closes
                // late via the backstop; its cert recovery is the barrier
                // peer-fetch).
                let handoff_cert_quorum = self.handoff_signatures_meet_quorum(output)?;

                // The close decision (and the liveness backstop for a genuinely
                // non-signing validator) is the pure, unit-tested
                // `decide_deferred_epoch_close`: `Some(on_backstop)` closes, `None`
                // keeps waiting for the handoff-cert quorum.
                if let Some(backstop_close) = Self::decide_deferred_epoch_close(
                    eop_ready,
                    handoff_cert_quorum,
                    rounds_since_quorum,
                    self.protocol_config().end_of_publish_grace_rounds(),
                ) {
                    let (dwallet_close_messages, system_close_messages) =
                        self.build_epoch_close_checkpoint_messages()?;
                    for message in dwallet_close_messages {
                        verified_dwallet_checkpoint_certificates.push_back(message);
                    }
                    for message in system_close_messages {
                        verified_system_checkpoint_certificates.push_back(message);
                    }
                    // Persist the close marker through this commit's batch so a
                    // restart cannot re-emit the close set at a later commit.
                    output.set_epoch_close_emitted();
                    self.reconfig_state.write().status = ReconfigCertStatus::RejectAllTx;
                    if backstop_close {
                        warn!(
                            validator = ?self.name,
                            quorum_round,
                            close_round = consensus_commit_info.round,
                            "closing the epoch on the handoff-cert liveness backstop WITHOUT a \
                             handoff-cert quorum — the next epoch may stall at the \
                             prepare-then-start barrier; investigate validators that did not \
                             contribute a valid handoff signature",
                        );
                    } else {
                        info!(
                            validator = ?self.name,
                            quorum_round,
                            close_round = consensus_commit_info.round,
                            all_voted,
                            "EndOfPublish + handoff-cert quorum reached — closing the epoch",
                        );
                    }
                }
            }
        }

        // mpc_data freeze: decided HERE, at the commit boundary,
        // so the frozen set is a deterministic function of the consensus
        // sequence — every validator evaluates the same ready-signal table
        // at the same commit. (Triggering the freeze from the wall-clock
        // MPC-service loop let two validators tally different signal sets —
        // re-emits land between their service ticks — and the divergent
        // frozen/excluded sets fork the handoff items and the
        // reconfiguration participant set.) Freeze once a stake-quorum of
        // ready-signals is in AND either:
        //   - full coverage: every committee member has signaled and the
        //     freeze partition excludes no announcer (nothing left to wait
        //     for), or
        //   - the grace elapsed: `mpc_data_freeze_grace_rounds` (protocol
        //     config) leader rounds past the quorum-observing round —
        //     consensus progress, not wall-clock — giving slower
        //     validators' blobs time to propagate before the set is pinned.
        if !self.is_mpc_data_frozen().unwrap_or(false) {
            let tables = self.tables()?;
            let mut signals: std::collections::BTreeMap<
                AuthorityName,
                Vec<(AuthorityName, [u8; 32])>,
            > = std::collections::BTreeMap::new();
            for entry in tables.epoch_mpc_data_ready_signals.safe_iter() {
                let (signer, signal) = entry?;
                signals.insert(signer, signal.validated_peers);
            }
            let committee = self.committee();
            let signal_stake: u64 = signals
                .keys()
                .map(|authority| committee.weight(authority))
                .sum();
            self.metrics
                .dwallet_mpc_data_ready_signal_stake
                .set(signal_stake as i64);
            if signal_stake >= committee.quorum_threshold() {
                let quorum_round = match tables.mpc_data_ready_quorum_round.get(&0)? {
                    Some(round) => round,
                    None => {
                        // Once per epoch: the anchor of the freeze grace
                        // countdown. Lets an operator distinguish "quorum
                        // never reached" from "grace still counting" when
                        // the freeze is late.
                        info!(
                            validator = ?self.name,
                            quorum_round = consensus_commit_info.round,
                            signers = signals.len(),
                            signal_stake,
                            grace_rounds = self.protocol_config().mpc_data_freeze_grace_rounds(),
                            "mpc_data ready-signal stake quorum reached — freeze grace \
                             countdown anchored",
                        );
                        output.set_mpc_data_ready_quorum_round(consensus_commit_info.round);
                        self.metrics
                            .dwallet_mpc_data_ready_quorum_round
                            .set(consensus_commit_info.round as i64);
                        consensus_commit_info.round
                    }
                };
                let partition = crate::validator_metadata::compute_freeze_partition(
                    &signals,
                    |authority| committee.weight(authority),
                    committee.quorum_threshold(),
                );
                let full_coverage =
                    signals.len() >= committee.num_members() && partition.excluded.is_empty();
                let grace_elapsed = consensus_commit_info.round.saturating_sub(quorum_round)
                    >= self.protocol_config().mpc_data_freeze_grace_rounds();
                if full_coverage || grace_elapsed {
                    self.freeze_mpc_data_if_first(&tables, output)?;
                    self.metrics
                        .dwallet_mpc_data_freeze_round
                        .set(consensus_commit_info.round as i64);
                    info!(
                        validator = ?self.name,
                        quorum_round,
                        freeze_round = consensus_commit_info.round,
                        full_coverage,
                        "mpc_data ready — freezing the input set at the commit boundary",
                    );
                }
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
        output.set_idle_status_updates(Self::filter_idle_status_updates(transactions));
        output.set_sui_chain_observation_updates(Self::filter_sui_chain_observation_updates(
            transactions,
        ));
        output.set_global_presign_requests(Self::filter_global_presign_requests(transactions));
        output.set_noa_observations(Self::filter_noa_observations(transactions));
        output.set_noa_presign_demands(Self::filter_noa_presign_demands(transactions));

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

    fn filter_idle_status_updates(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<IdleStatusUpdate> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::IdleStatusUpdate(update),
                        ..
                    }) => Some(update.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    fn filter_sui_chain_observation_updates(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<SuiChainObservationUpdate> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::SuiChainObservationUpdate(update),
                        ..
                    }) => Some(update.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    fn filter_global_presign_requests(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<ConsensusGlobalPresignRequest> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::GlobalPresignRequest(msg),
                        ..
                    }) => Some(msg.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    fn filter_noa_observations(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<ConsensusNOAObservation> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::NOAObservation(msg),
                        ..
                    }) => Some(msg.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    fn filter_noa_presign_demands(
        transactions: &[VerifiedSequencedConsensusTransaction],
    ) -> Vec<ConsensusNOAPresignDemand> {
        transactions
            .iter()
            .filter_map(|transaction| {
                let VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                    transaction,
                    ..
                }) = transaction;
                match transaction {
                    SequencedConsensusTransactionKind::External(ConsensusTransaction {
                        kind: ConsensusTransactionKind::NOAPresignDemand(msg),
                        ..
                    }) => Some(msg.clone()),
                    _ => None,
                }
            })
            .collect()
    }

    #[instrument(level = "trace", skip_all)]
    async fn process_consensus_transaction<C: DWalletCheckpointServiceNotify>(
        &self,
        output: &mut ConsensusCommitOutput,
        transaction: &VerifiedSequencedConsensusTransaction,
        checkpoint_service: &Option<Arc<C>>,
        system_checkpoint_service: &Option<Arc<SystemCheckpointService>>,
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
                kind: ConsensusTransactionKind::IdleStatusUpdate(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::SuiChainObservationUpdate(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::GlobalPresignRequest(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::NOAObservation(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::NOAPresignDemand(..),
                ..
            }) => Ok(ConsensusCertificateResult::ConsensusMessage),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::ValidatorMpcDataAnnouncement(announcement, blob),
                ..
            }) => {
                self.record_validator_mpc_data_announcement(announcement, blob)?;
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(signed, blob),
                ..
            }) => {
                // A discarded copy must not consume the joiner's key. The key
                // is `(joiner, epoch, timestamp)` and this message kind carries
                // NO sender constraint — any committee member may relay for any
                // joiner — while the joiner's signature can only be checked
                // here, not at admission (the pubkey provider may not be
                // installed yet). Recording a rejected copy as processed
                // therefore let one member burn a joiner's slot with a
                // corrupted duplicate: every honest relay of the genuine
                // announcement shares that key and was dropped as already
                // processed, and the joiner cannot detect it because its
                // success signal is the relayer's accept, not consensus
                // inclusion. `Ignored` leaves the key free for the real one.
                match self.record_relayed_validator_mpc_data_announcement(signed, blob)? {
                    RelayedAnnouncementDisposition::Retained => {
                        Ok(ConsensusCertificateResult::ConsensusMessage)
                    }
                    RelayedAnnouncementDisposition::Discarded => {
                        Ok(ConsensusCertificateResult::Ignored)
                    }
                }
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::EpochMpcDataReadySignal(signal),
                ..
            }) => {
                self.record_epoch_mpc_data_ready_signal(signal)?;
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::DWalletCheckpointSignature(info),
                ..
            }) => {
                // Only process BLS checkpoint signatures when BLS checkpoints are enabled.
                // When only NOA checkpoints are active, BLS signature aggregation is skipped.
                if self.protocol_config().bls_checkpoints()
                    && let Some(service) = checkpoint_service
                {
                    // We usually call notify_checkpoint_signature in IkaTxValidator, but that
                    // step can be skipped when a batch is already part of a certificate, so we
                    // must also notify here.
                    service.notify_checkpoint_signature(self, info)?;
                }
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
                // Only process BLS checkpoint signatures when BLS checkpoints are enabled.
                if self.protocol_config().bls_checkpoints()
                    && let Some(service) = system_checkpoint_service
                {
                    service.notify_checkpoint_signature(self, data)?;
                }
                Ok(ConsensusCertificateResult::ConsensusMessage)
            }
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind: ConsensusTransactionKind::EndOfPublish(authority),
                ..
            }) => self.process_end_of_publish_vote(output, authority),
            SequencedConsensusTransactionKind::External(ConsensusTransaction {
                kind:
                    ConsensusTransactionKind::EndOfPublishV2 {
                        authority,
                        handoff_signature,
                    },
                ..
            }) => {
                // V2 bundles the signed handoff attestation with the
                // EndOfPublish vote. The EOP vote is counted
                // UNCONDITIONALLY: the vote tally feeds the epoch close,
                // which must be a deterministic function of the consensus
                // sequence — whether the bundled signature verifies
                // depends on per-validator local state (whether this
                // validator's own expected attestation is installed yet,
                // whether its pubkey provider has loaded), so gating the
                // vote on it lets honest validators disagree on the tally
                // and close the epoch at different rounds. The handoff
                // signature half is best-effort: a mismatched/bad
                // signature is rejected (and logged) inside
                // `record_handoff_signature` without affecting the vote —
                // the handoff cert only needs a quorum of valid
                // signatures, not all of them.
                self.record_handoff_signature(handoff_signature)?;
                self.process_end_of_publish_vote(output, authority)
            }
        }
    }

    /// Builds the end-of-epoch checkpoint messages produced when the epoch
    /// closes: the capabilities-driven protocol-version / move-contract-upgrade
    /// system transactions, followed by the `EndOfPublish` markers. Factored
    /// out of the (now commit-boundary-driven) close so it can be invoked once
    /// the EndOfPublish grace elapses. Returns `(dwallet_messages,
    /// system_messages)` for the caller to append, in order, to the per-commit
    /// certificate sets.
    fn build_epoch_close_checkpoint_messages(
        &self,
    ) -> IkaResult<(
        Vec<DWalletCheckpointMessageKind>,
        Vec<SystemCheckpointMessageKind>,
    )> {
        let capabilities = self.get_capabilities_v1()?;
        let AuthorityCapabilitiesVotingResults {
            protocol_version: new_version,
            move_contracts_to_upgrade,
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
            system_transactions.push(SystemCheckpointMessageKind::SetNextConfigVersion(
                new_version,
            ));
            if new_version.as_u64() == 2 && self.chain_identifier.chain() == Chain::Testnet {
                system_transactions.push(SystemCheckpointMessageKind::SetMinValidatorJoiningStake(
                    40_000_000 * 1_000_000_000,
                ));
                system_transactions.push(SystemCheckpointMessageKind::SetStakeSubsidyRate(200));
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
                system_transactions.push(SystemCheckpointMessageKind::SetApprovedUpgrade {
                    package_id: package_id.to_vec(),
                    digest: Some(digest.to_vec()),
                });
            }
        }
        system_transactions.push(SystemCheckpointMessageKind::EndOfPublish);
        Ok((
            vec![DWalletCheckpointMessageKind::EndOfPublish],
            system_transactions,
        ))
    }

    /// Shared EndOfPublish vote-recording + quorum-check logic. Used
    /// by both V1 (`EndOfPublish`) and V2 (`EndOfPublishV2`) consumer
    /// arms.
    fn process_end_of_publish_vote(
        &self,
        output: &mut ConsensusCommitOutput,
        authority: &AuthorityName,
    ) -> IkaResult<ConsensusCertificateResult> {
        // Through the commit batch, NOT an out-of-band table write. Both
        // durable views of the vote set must land or be lost together: an
        // immediate insert survives a crash that loses this commit's batch,
        // and replay would then rebuild the aggregator from a table holding
        // votes the replayed commit has not re-counted — pinning a larger
        // count than the sequence implies and reintroducing #1917 through
        // crash-replay. Batched, the table reflects exactly the pre-commit
        // state on replay and the votes re-count through the guard below in
        // consensus order.
        output.record_end_of_publish_vote(*authority);
        let mut end_of_publish = self.end_of_publish.lock();
        // Duplicate votes can't double-count (the aggregator is a HashMap).
        // The pre-quorum guard is load-bearing, not an optimization: it is
        // what stops post-quorum stragglers from raising the aggregator's
        // count, which is the `voted_count` the deferred-close grace reads.
        if !end_of_publish.has_quorum() {
            end_of_publish.insert_generic(*authority, ());
        }
        // The epoch NEVER closes inline at the quorum-crossing vote. It is
        // deferred `end_of_publish_grace_rounds` (protocol config) more
        // consensus rounds past quorum (the grace check at the commit
        // boundary in `process_consensus_transactions_and_commit_boundary`),
        // so straggler `EndOfPublishV2` bundles — carrying their handoff
        // signatures — are still collected before the epoch closes.
        Ok(ConsensusCertificateResult::ConsensusMessage)
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
    idle_status_updates: Vec<IdleStatusUpdate>,
    sui_chain_observation_updates: Vec<SuiChainObservationUpdate>,
    global_presign_requests: Vec<ConsensusGlobalPresignRequest>,
    noa_observations: Vec<ConsensusNOAObservation>,
    noa_presign_demands: Vec<ConsensusNOAPresignDemand>,

    verified_dwallet_checkpoint_messages: Vec<DWalletCheckpointMessageKind>,
    verified_system_checkpoint_messages: Vec<SystemCheckpointMessageKind>,

    /// EndOfPublish votes sequenced in this commit. Batched rather than
    /// written on sight so the durable vote set can never run ahead of the
    /// commit that sequenced it: on crash-replay the table must reflect the
    /// pre-commit state, or the aggregator rehydrates with votes the replayed
    /// commit has not re-counted (#1917).
    end_of_publish_votes: Vec<AuthorityName>,
    /// `handoff_signatures` row mutations folded into this commit —
    /// `Some(signature)` upserts, `None` deletes. Batched for the same reason
    /// the votes are, and consulted directly by the close gate so that the
    /// gate decides against exactly the state this commit's batch will make
    /// durable (#1927).
    handoff_signature_rows: BTreeMap<AuthorityName, Option<Ed25519Signature>>,
    /// First commit round at which the EndOfPublish stake quorum was
    /// observed (the grace anchor). Written through this batch so it
    /// commits atomically with the commit that observed it — an
    /// out-of-band write could desync from the commit on crash-replay.
    end_of_publish_quorum_round: Option<u64>,
    /// Size of the in-memory EndOfPublish aggregator at that same
    /// quorum-observing commit — the pinned `all_voted` input. Written in
    /// this batch alongside the anchor above so the two can never disagree
    /// (see the table's doc comment and #1917).
    end_of_publish_quorum_voted_count: Option<u64>,
    /// Set when this commit emitted the deferred epoch-close message
    /// set. Persisted atomically with the commit so a restarted validator
    /// neither re-emits the close (marker present ⇒ `reconfig_state` is
    /// restored to `RejectAllTx` on epoch-store open) nor loses it (a crash
    /// before the batch commit replays the whole commit deterministically).
    epoch_close_emitted: bool,
    /// First commit round at which the mpc_data ready-signal stake quorum
    /// was observed (the freeze-grace anchor). Same atomicity rationale as
    /// `end_of_publish_quorum_round`.
    mpc_data_ready_quorum_round: Option<u64>,

    /// Commit timestamp of the epoch's first processed consensus commit
    /// (the ready-signal backstop anchor). Set only on the commit observed
    /// first; same atomicity rationale as `mpc_data_ready_quorum_round`.
    epoch_first_commit_timestamp_ms: Option<u64>,

    /// The mpc_data freeze partition decided at this commit's boundary
    /// (`freeze_mpc_data_if_first`), or `None` when the freeze didn't fire
    /// at this commit. Written to `frozen_validator_mpc_data_input_set` +
    /// `epoch_excluded_validators` in the SAME batch as the commit's
    /// processed-markers: a partially-persisted freeze is a divergent
    /// (shrunken) frozen set on this validator only (issue #1829).
    mpc_data_freeze_partition: Option<crate::validator_metadata::FreezePartition>,
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

    pub(crate) fn record_end_of_publish_vote(&mut self, authority: AuthorityName) {
        self.end_of_publish_votes.push(authority);
    }

    pub(crate) fn record_handoff_signature_rows(
        &mut self,
        rows: BTreeMap<AuthorityName, Option<Ed25519Signature>>,
    ) {
        self.handoff_signature_rows.extend(rows);
    }

    pub(crate) fn handoff_signature_rows(
        &self,
    ) -> &BTreeMap<AuthorityName, Option<Ed25519Signature>> {
        &self.handoff_signature_rows
    }

    pub(crate) fn set_end_of_publish_quorum_round(&mut self, round: u64) {
        self.end_of_publish_quorum_round = Some(round);
    }

    pub(crate) fn set_end_of_publish_quorum_voted_count(&mut self, voted_count: u64) {
        self.end_of_publish_quorum_voted_count = Some(voted_count);
    }

    pub(crate) fn set_epoch_close_emitted(&mut self) {
        self.epoch_close_emitted = true;
    }

    pub(crate) fn set_mpc_data_ready_quorum_round(&mut self, round: u64) {
        self.mpc_data_ready_quorum_round = Some(round);
    }

    pub(crate) fn set_mpc_data_freeze_partition(
        &mut self,
        partition: crate::validator_metadata::FreezePartition,
    ) {
        self.mpc_data_freeze_partition = Some(partition);
    }

    pub(crate) fn set_epoch_first_commit_timestamp_ms(&mut self, timestamp_ms: u64) {
        self.epoch_first_commit_timestamp_ms = Some(timestamp_ms);
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

    pub(crate) fn set_idle_status_updates(&mut self, new_value: Vec<IdleStatusUpdate>) {
        self.idle_status_updates = new_value;
    }

    pub(crate) fn set_sui_chain_observation_updates(
        &mut self,
        new_value: Vec<SuiChainObservationUpdate>,
    ) {
        self.sui_chain_observation_updates = new_value;
    }

    pub(crate) fn set_global_presign_requests(
        &mut self,
        new_value: Vec<ConsensusGlobalPresignRequest>,
    ) {
        self.global_presign_requests = new_value;
    }

    pub(crate) fn set_noa_observations(&mut self, new_value: Vec<ConsensusNOAObservation>) {
        self.noa_observations = new_value;
    }

    pub(crate) fn set_noa_presign_demands(&mut self, new_value: Vec<ConsensusNOAPresignDemand>) {
        self.noa_presign_demands = new_value;
    }

    fn record_verified_dwallet_checkpoint_messages(
        &mut self,
        verified_dwallet_checkpoint_messages: Vec<DWalletCheckpointMessageKind>,
    ) {
        self.verified_dwallet_checkpoint_messages = verified_dwallet_checkpoint_messages;
    }

    fn record_verified_system_checkpoint_messages(
        &mut self,
        verified_system_checkpoint_messages: Vec<SystemCheckpointMessageKind>,
    ) {
        self.verified_system_checkpoint_messages = verified_system_checkpoint_messages;
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
    /// Moves this commit's drain inputs out of the output so they can be
    /// handed to the MPC drain over the round transport.
    ///
    /// Everything here is MOVED: none of it is written to a table any more.
    /// The two verified-message sets are the fold's own output and are also
    /// consumed in-memory by the checkpoint path in the same function, which
    /// is why they are cloned there rather than here.
    pub(crate) fn take_round_payload(&mut self) -> ConsensusRoundPayload {
        ConsensusRoundPayload {
            round: self.consensus_round,
            mpc_messages: std::mem::take(&mut self.dwallet_mpc_round_messages),
            mpc_outputs: std::mem::take(&mut self.dwallet_mpc_round_outputs),
            internal_mpc_outputs: std::mem::take(&mut self.dwallet_internal_mpc_round_outputs),
            verified_dwallet_checkpoint_messages: std::mem::take(
                &mut self.verified_dwallet_checkpoint_messages,
            ),
            verified_system_checkpoint_messages: std::mem::take(
                &mut self.verified_system_checkpoint_messages,
            ),
            idle_status_updates: std::mem::take(&mut self.idle_status_updates),
            sui_chain_observation_updates: std::mem::take(&mut self.sui_chain_observation_updates),
            global_presign_requests: std::mem::take(&mut self.global_presign_requests),
            noa_observations: std::mem::take(&mut self.noa_observations),
            noa_presign_demands: std::mem::take(&mut self.noa_presign_demands),
        }
    }

    pub fn write_to_batch(
        self,
        epoch_store: &AuthorityPerEpochStore,
        batch: &mut DBBatch,
    ) -> IkaResult {
        let tables = epoch_store.tables()?;

        // The last two per-round tables. The eight projection streams they
        // used to sit beside are gone: the MPC drain receives every round's
        // inputs over the bounded channel now
        // (`dev-docs/conventions/consensus-output-consumption.md`), so
        // nothing polls a table per round and the dense-stream alignment
        // these writes were gated to preserve no longer has a reader.
        //
        // NOTE: with the drain fed by the channel, these two have NO reader
        // left either — checkpoint construction consumes the in-memory values
        // in this same function via `pending_system_checkpoints`, never the
        // tables. They are retained pending a decision on removing them; if
        // that decision is to keep them, it needs a stated consumer, because
        // an unread table is write amplification with a schema.
        let noa = epoch_store.protocol_config().noa_checkpoints();

        batch.insert_batch(
            &tables.verified_dwallet_checkpoint_messages,
            [(
                self.consensus_round,
                self.verified_dwallet_checkpoint_messages,
            )],
        )?;
        if noa {
            batch.insert_batch(
                &tables.verified_system_checkpoint_messages,
                [(
                    self.consensus_round,
                    self.verified_system_checkpoint_messages,
                )],
            )?;
        }

        batch.insert_batch(
            &tables.end_of_publish,
            self.end_of_publish_votes
                .into_iter()
                .map(|authority| (authority, ())),
        )?;
        // Deletes first, then upserts: the map holds at most one op per
        // signer, so the two sets are disjoint and the order is cosmetic —
        // but writing it explicitly keeps it that way if the staging ever
        // grows a per-signer history.
        batch.delete_batch(
            &tables.handoff_signatures,
            self.handoff_signature_rows
                .iter()
                .filter(|(_, op)| op.is_none())
                .map(|(signer, _)| signer),
        )?;
        batch.insert_batch(
            &tables.handoff_signatures,
            self.handoff_signature_rows
                .iter()
                .filter_map(|(signer, op)| op.as_ref().map(|signature| (signer, signature))),
        )?;
        if let Some(round) = self.end_of_publish_quorum_round {
            batch.insert_batch(&tables.end_of_publish_quorum_round, [(0u64, round)])?;
        }
        if let Some(voted_count) = self.end_of_publish_quorum_voted_count {
            batch.insert_batch(
                &tables.end_of_publish_quorum_voted_count,
                [(0u64, voted_count)],
            )?;
        }
        if self.epoch_close_emitted {
            batch.insert_batch(&tables.epoch_close_emitted, [(0u64, ())])?;
        }
        if let Some(round) = self.mpc_data_ready_quorum_round {
            batch.insert_batch(&tables.mpc_data_ready_quorum_round, [(0u64, round)])?;
        }
        if let Some(partition) = self.mpc_data_freeze_partition {
            // The freeze fires at THIS commit's boundary, so the commit's
            // leader round IS the freeze round; persisted in the same batch
            // so a crash replays the whole commit and re-records the same
            // round.
            batch.insert_batch(
                &tables.mpc_data_freeze_round,
                [(0u64, self.consensus_round)],
            )?;
            batch.insert_batch(
                &tables.frozen_validator_mpc_data_input_set,
                partition.frozen,
            )?;
            batch.insert_batch(
                &tables.epoch_excluded_validators,
                partition
                    .excluded
                    .into_iter()
                    .map(|authority| (authority, ())),
            )?;
        }
        if let Some(timestamp_ms) = self.epoch_first_commit_timestamp_ms {
            batch.insert_batch(
                &tables.epoch_first_commit_timestamp_ms,
                [(0u64, timestamp_ms)],
            )?;
        }

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
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::authority::derived_epoch_state::EpochStateSnapshot;
    use ika_types::noa_checkpoint::{NOACheckpointKindName, NOACheckpointTxRef};
    use ika_types::supported_protocol_versions::{
        SupportedProtocolVersions, SupportedProtocolVersionsWithHashes,
    };
    use tokio::time::advance;

    /// `next_round_row` must return the first row STRICTLY after the anchor —
    /// including when the anchor row itself is ABSENT from the table. The
    /// previous `nth(1)` pattern positioned the iterator at the lower bound
    /// and skipped one entry, which consumed the first UNREAD row as the
    /// skip target whenever the anchor row was missing — and because every
    /// per-round stream would skip the same round in lockstep, the
    /// dense-stream alignment checks (which compare the streams to each
    /// other) could never catch it.
    ///
    /// Retargeted at `verified_dwallet_checkpoint_messages` now that the
    /// eight projection streams are gone. `next_round_row`'s only remaining
    /// consumers are the two `next_verified_*` accessors, which themselves
    /// have no caller since the drain moved to the channel — if those go, so
    /// do the helper and this test.
    #[tokio::test]
    async fn next_round_row_does_not_skip_a_live_round_when_the_anchor_row_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let tables = AuthorityEpochTables::open(0, dir.path(), None);
        let messages = &tables.verified_dwallet_checkpoint_messages;

        // Rounds 1, 2, 3, 6, 7 present — a gap at 4..=5.
        for round in [1u64, 2, 3, 6, 7] {
            messages
                .insert(&round, &Vec::<DWalletCheckpointMessageKind>::new())
                .unwrap();
        }

        // Fresh start: the first row.
        assert_eq!(next_round_row(messages, None).unwrap().unwrap().0, 1);
        // Anchor present: the strictly-next row, across a gap too.
        assert_eq!(next_round_row(messages, Some(1)).unwrap().unwrap().0, 2);
        assert_eq!(next_round_row(messages, Some(3)).unwrap().unwrap().0, 6);
        // Anchor ABSENT (no row at 4): the first live row after it — round 6
        // — must be RETURNED, not consumed as the skip target. (`nth(1)`
        // returned round 7 here, silently dropping round 6.)
        assert_eq!(next_round_row(messages, Some(4)).unwrap().unwrap().0, 6);
        // Past the end: no row, and no wraparound at the maximum round.
        assert!(next_round_row(messages, Some(7)).unwrap().is_none());
        assert!(next_round_row(messages, Some(u64::MAX)).unwrap().is_none());
    }
    use crate::dwallet_checkpoints::DWalletCheckpointService;
    use crate::handoff_cert::{build_handoff_attestation, sign_handoff_attestation};
    use dwallet_mpc_types::dwallet_mpc::DWalletSignatureAlgorithm;
    use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519Signature};
    use fastcrypto::traits::{KeyPair, ToFromBytes};
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
    use prometheus::Registry;
    use sui_types::base_types::ObjectID;

    fn create_tables() -> AuthorityEpochTables {
        let dir = tempfile::tempdir().unwrap();
        AuthorityEpochTables::open(0, dir.path(), None)
    }

    /// #1736: the epoch close must require a handoff-cert quorum (not just
    /// EndOfPublish readiness), with a bounded liveness backstop.
    #[test]
    fn epoch_close_requires_handoff_cert_quorum() {
        let grace = 50u64;
        let backstop = grace * 4; // HANDOFF_CERT_BACKSTOP_GRACE_MULTIPLIER
        let decide = AuthorityPerEpochStore::decide_deferred_epoch_close;

        // Not EndOfPublish-ready: never close, regardless of the cert quorum or
        // how many rounds have passed.
        assert_eq!(decide(false, false, 0, grace), None);
        assert_eq!(decide(false, true, backstop, grace), None);

        // EndOfPublish-ready AND handoff-cert quorum: normal close.
        assert_eq!(decide(true, true, 0, grace), Some(false));
        assert_eq!(decide(true, true, grace, grace), Some(false));

        // THE #1736 GUARANTEE: EndOfPublish-ready but NO handoff-cert quorum —
        // do NOT close before the backstop, however long the EndOfPublish grace
        // alone has elapsed. (Pre-fix this closed at `grace`, with no cert.)
        assert_eq!(decide(true, false, grace, grace), None);
        assert_eq!(decide(true, false, backstop - 1, grace), None);

        // Backstop reached without a handoff-cert quorum: close on the backstop
        // (liveness), flagged as a backstop close.
        assert_eq!(decide(true, false, backstop, grace), Some(true));
        assert_eq!(decide(true, false, backstop + 100, grace), Some(true));

        // Quorum arriving exactly at the backstop round is a normal close, not a
        // backstop close.
        assert_eq!(decide(true, true, backstop, grace), Some(false));

        // Degenerate zero-grace config collapses the backstop to 0: close as
        // soon as EndOfPublish-ready, never blocking.
        assert_eq!(decide(true, false, 0, 0), Some(true));
    }

    /// #1736 WIRING test: drives the REAL v4 epoch-close path through
    /// `process_consensus_transactions` (not the pure decision in isolation).
    /// With EndOfPublish at quorum and the grace elapsed — but NOT all-voted —
    /// the close must DEFER while `handoff_signatures` is sub-quorum, and FIRE
    /// once the handoff-cert quorum forms. This proves the close is coupled to
    /// the handoff-cert quorum, not EndOfPublish readiness alone.
    ///
    /// This DISCRIMINATES the fix from base: base closes on
    /// `all_voted || grace_elapsed` with no handoff-cert gate, so it would close
    /// at STEP 1 (reconfig flips to `RejectAllTx`, an `EndOfPublish` close
    /// message is emitted) and FAIL the STEP 1 assertions.
    /// A validator must be able to tell, from purely local state, that its MPC
    /// subsystem has stopped while consensus keeps running. Both production
    /// incidents this exists for (#1978, #1980) were invisible to their
    /// operators and diagnosable only from a fleet-wide view they do not have.
    /// An epoch store for the MPC-lag detector tests. The tempdir comes back
    /// with it because RocksDB needs its path to outlive the store.
    fn mpc_lag_test_epoch_store() -> (Arc<AuthorityPerEpochStore>, tempfile::TempDir) {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let names: Vec<AuthorityName> = committee.names().copied().collect();
        let dir = tempfile::tempdir().unwrap();
        let epoch_store =
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name: names[0],
                committee,
                parent_path: dir.path().to_path_buf(),
                db_options: None,
                metrics: EpochMetrics::new(&Registry::new()),
                epoch_start_configuration: EpochStartConfiguration::new(
                    EpochStartSystem::new_for_testing_with_epoch(0),
                )
                .unwrap(),
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
            .unwrap();
        (epoch_store, dir)
    }

    #[tokio::test]
    async fn mpc_lag_is_reported_and_alarms_only_once_stopped() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();
        let lag = || epoch_store.metrics.mpc_consensus_round_lag.get();

        // Before the MPC service reports anything the gauge must NOT read 0 —
        // round 0 is a legitimate consumed round, so 0 would be a
        // plausible-but-wrong "perfectly caught up".
        epoch_store.report_mpc_consensus_round_lag(1_000);
        assert_eq!(lag(), -1, "no MPC report yet must be a sentinel, not 0");

        // Healthy: the service trails the commit path slightly, no catch-up.
        epoch_store.record_mpc_consumed_consensus_round(990, false);
        epoch_store.report_mpc_consensus_round_lag(1_000);
        assert_eq!(lag(), 10);
        assert!(
            !epoch_store
                .mpc_lag_alarm_active
                .load(std::sync::atomic::Ordering::Relaxed),
            "an ordinary trailing distance must not alarm"
        );

        // Stopped: consensus advances, MPC does not. With no catch-up reported
        // this is the unchanged pre-#2036 behavior.
        epoch_store.report_mpc_consensus_round_lag(990 + MPC_LAG_ALARM_ROUNDS);
        assert_eq!(lag(), MPC_LAG_ALARM_ROUNDS as i64);
        assert!(
            epoch_store
                .mpc_lag_alarm_active
                .load(std::sync::atomic::Ordering::Relaxed),
            "a stopped MPC subsystem must raise the alarm"
        );

        // Recovery clears it, so a restart that fixes the node is visible too.
        epoch_store.record_mpc_consumed_consensus_round(990 + MPC_LAG_ALARM_ROUNDS, false);
        epoch_store.report_mpc_consensus_round_lag(990 + MPC_LAG_ALARM_ROUNDS);
        assert_eq!(lag(), 0);
        assert!(
            !epoch_store
                .mpc_lag_alarm_active
                .load(std::sync::atomic::Ordering::Relaxed),
            "catching up must clear the alarm"
        );
    }

    /// A validator restarted mid-epoch replays every round of the epoch so far,
    /// and consensus rounds restart at 0 each epoch — so past roughly the first
    /// three quarters of an hour of a 24h epoch, the replay gap alone exceeds
    /// `MPC_LAG_ALARM_ROUNDS` and the ERROR was arithmetically guaranteed on
    /// every restart (ika #2036, seen on all six production validators). Its
    /// advice — restart the node — would have discarded the drain and replayed
    /// it. A catch-up the MPC service is actively reporting must hold the alarm,
    /// however large the gap and however long the drain runs.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mpc_lag_alarm_is_held_while_the_service_reports_a_live_catch_up() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();

        epoch_store.record_mpc_consumed_consensus_round(1, true);
        let commit_round = 10 * MPC_LAG_ALARM_ROUNDS;
        let report = epoch_store.report_mpc_consensus_round_lag(commit_round);
        assert_eq!(
            report.stopped_contributing,
            MpcLagTransition::Unchanged,
            "a reported catch-up must hold the alarm at ten times the threshold"
        );
        assert!(!epoch_store.mpc_lag_alarm_active.load(Ordering::Relaxed));
        // Held, not hidden: the gauge still carries the real distance.
        assert_eq!(
            epoch_store.metrics.mpc_consensus_round_lag.get(),
            (commit_round - 1) as i64
        );

        // Twenty minutes of an actual drain — the cursor closing on the tip far
        // faster than the tip advances, which is what a suppressed-computation
        // catch-up does (~1-2k rounds/s against a ~19.5 rounds/s tip in
        // production). Longer than the stuck-drain bound on purpose: a drain
        // that keeps making progress must raise neither alarm however long it
        // runs.
        for minute in 1..=20u64 {
            advance(Duration::from_secs(60)).await;
            epoch_store.record_mpc_consumed_consensus_round(minute * 40_000, true);
            assert_eq!(
                epoch_store.report_mpc_consensus_round_lag(commit_round + minute * 1_000),
                MpcLagReport::UNCHANGED,
                "minute {minute} of a healthy drain must stay silent"
            );
        }

        // The drain finishes and the gate disengages: the ordinary path is back,
        // with no alarm ever having fired.
        epoch_store.record_mpc_consumed_consensus_round(commit_round + 20_000, false);
        assert_eq!(
            epoch_store.report_mpc_consensus_round_lag(commit_round + 20_000),
            MpcLagReport::UNCHANGED
        );
    }

    /// The hold is a lease the MPC service renews, not a flag it can leave set.
    /// The service-loop `break` on self-recognised maliciousness is reachable
    /// during the post-restart replay window, so a catch-up flag with no expiry
    /// would hide that stall for the life of the process — which is why the
    /// gate state is published on every consumed round and read with a
    /// freshness bound, and why it is sampled from the gate rather than from
    /// the gate's metric.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mpc_lag_alarm_raises_when_the_catch_up_report_goes_stale() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();
        let commit_round = MPC_LAG_ALARM_ROUNDS + 1;

        epoch_store.record_mpc_consumed_consensus_round(1, true);
        advance(MPC_CATCH_UP_REPORT_FRESHNESS - Duration::from_secs(1)).await;
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(commit_round)
                .stopped_contributing,
            MpcLagTransition::Unchanged,
            "a report still inside the freshness window holds the alarm"
        );

        // The service stops here: nothing renews the report.
        advance(Duration::from_secs(2)).await;
        let report = epoch_store.report_mpc_consensus_round_lag(commit_round);
        assert_eq!(
            report.stopped_contributing,
            MpcLagTransition::Raised,
            "a catch-up nobody is renewing IS the stall case, and must alarm"
        );
        assert_eq!(
            report.stuck_drain,
            MpcLagTransition::Unchanged,
            "the stuck-drain alarm is for a live drain; a dead service is the other alarm"
        );

        // The service comes back and resumes draining: the alarm clears once.
        epoch_store.record_mpc_consumed_consensus_round(commit_round, true);
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(commit_round)
                .stopped_contributing,
            MpcLagTransition::Cleared
        );
    }

    /// Holding the stopped-contributing alarm for a reported catch-up leaves a
    /// gap only a second alarm can cover: a drain that has stopped draining.
    /// The bound is generous — production backlogs of ~640k rounds drain
    /// completely in five to ten minutes — so a quarter hour without the gap
    /// reaching a new low means the validator is not coming back on its own.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stuck_catch_up_drain_raises_while_the_lag_alarm_is_held() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();
        // A gap that stays exactly the same size: the cursor advances at the
        // tip rate, so rounds keep being consumed (the report stays fresh) and
        // the backlog never shrinks.
        let held_lag = MPC_LAG_ALARM_ROUNDS + 1;
        let sample = |minute: u64| {
            epoch_store.record_mpc_consumed_consensus_round(1_000 * minute, true);
            epoch_store.report_mpc_consensus_round_lag(1_000 * minute + held_lag)
        };

        let mut reports = Vec::new();
        for minute in 1..=20u64 {
            reports.push(sample(minute));
            advance(Duration::from_secs(60)).await;
        }
        assert!(
            reports
                .iter()
                .all(|report| report.stopped_contributing == MpcLagTransition::Unchanged),
            "the stopped-contributing alarm stays held throughout: the service IS reporting"
        );
        // The tracker starts at the first sample, so the window closes on the
        // sample a full `MPC_CATCH_UP_STUCK_DRAIN` later — minute 16 of a
        // fifteen-minute bound sampled once a minute.
        let stuck: Vec<_> = reports.iter().map(|report| report.stuck_drain).collect();
        assert_eq!(
            stuck[15],
            MpcLagTransition::Raised,
            "a drain stuck past the bound must be reported: {stuck:?}"
        );
        assert_eq!(
            stuck
                .iter()
                .filter(|transition| **transition == MpcLagTransition::Raised)
                .count(),
            1,
            "the stuck-drain alarm must latch like the one it complements: {stuck:?}"
        );
        assert!(
            stuck[..15]
                .iter()
                .all(|transition| *transition == MpcLagTransition::Unchanged),
            "nothing may fire before the bound elapses: {stuck:?}"
        );

        // The drain gets moving again: a new low clears the alarm, once, and
        // the cleared alarm stays quiet while the drain holds that new low.
        epoch_store.record_mpc_consumed_consensus_round(1_000 * 21 + held_lag, true);
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(1_000 * 21 + held_lag)
                .stuck_drain,
            MpcLagTransition::Cleared
        );
        advance(Duration::from_secs(60)).await;
        epoch_store.record_mpc_consumed_consensus_round(1_000 * 22 + held_lag, true);
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(1_000 * 22 + held_lag)
                .stuck_drain,
            MpcLagTransition::Unchanged,
            "a cleared alarm must not re-fire without a new stall"
        );
    }

    /// A gap that wobbles upward between samples is still a draining gap. The
    /// tip keeps advancing while the cursor chases it, so a healthy catch-up
    /// produces individual samples that tick up; across five hours of them,
    /// with the gap closing on balance, neither alarm may fire. Tracking the
    /// low-water mark is what makes that hold without a smoothing window — any
    /// new low restarts the clock, whatever the samples did in between.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_drain_that_keeps_reaching_new_lows_never_raises() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();
        let mut lag = 400_000;

        for step in 1..=60u64 {
            // Two steps forward, one back, hours in total: no window of
            // `MPC_CATCH_UP_STUCK_DRAIN` ever passes without a new low.
            lag = if step % 3 == 0 {
                lag + 3_000
            } else {
                lag - 5_000
            };
            epoch_store.record_mpc_consumed_consensus_round(step * 10_000, true);
            assert_eq!(
                epoch_store.report_mpc_consensus_round_lag(step * 10_000 + lag),
                MpcLagReport::UNCHANGED,
                "step {step} of a jittery but progressing drain must stay silent"
            );
            advance(Duration::from_secs(5 * 60)).await;
        }
    }

    /// The alarm latches, so the loud line fires on transition rather than on
    /// every consensus commit — this runs per commit, and an unconditional log
    /// would emit thousands of lines an hour and bury itself.
    #[tokio::test]
    async fn mpc_lag_alarm_does_not_re_fire_while_it_stays_raised() {
        let (epoch_store, _dir) = mpc_lag_test_epoch_store();

        epoch_store.record_mpc_consumed_consensus_round(1, false);
        // A sustained stall across many commits must announce itself exactly
        // once. This asserts the LOGGING decision, not the flag: the flag ends
        // up `true` either way, so observing it cannot tell a latched alarm
        // from one that re-fires on every commit.
        let transitions: Vec<_> = (1..=5)
            .map(|i| {
                epoch_store
                    .report_mpc_consensus_round_lag(MPC_LAG_ALARM_ROUNDS + i)
                    .stopped_contributing
            })
            .collect();
        assert_eq!(
            transitions,
            vec![
                MpcLagTransition::Raised,
                MpcLagTransition::Unchanged,
                MpcLagTransition::Unchanged,
                MpcLagTransition::Unchanged,
                MpcLagTransition::Unchanged,
            ],
            "the alarm must latch — this runs on EVERY consensus commit"
        );
        // The gauge keeps tracking growth throughout, so the continuous signal
        // is not lost to the latching.
        assert_eq!(
            epoch_store.metrics.mpc_consensus_round_lag.get(),
            (MPC_LAG_ALARM_ROUNDS + 4) as i64
        );

        // Recovery announces itself once too, then goes quiet.
        epoch_store.record_mpc_consumed_consensus_round(MPC_LAG_ALARM_ROUNDS + 5, false);
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(MPC_LAG_ALARM_ROUNDS + 5)
                .stopped_contributing,
            MpcLagTransition::Cleared
        );
        assert_eq!(
            epoch_store
                .report_mpc_consensus_round_lag(MPC_LAG_ALARM_ROUNDS + 5)
                .stopped_contributing,
            MpcLagTransition::Unchanged
        );
    }

    #[tokio::test]
    async fn epoch_close_wiring_defers_until_handoff_cert_quorum() {
        // Four equal-weight validators: quorum_threshold = 3, validity = 2.
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let names: Vec<AuthorityName> = committee.names().copied().collect();

        // The tempdir must outlive the store (RocksDB needs the path live).
        let dir = tempfile::tempdir().unwrap();
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store =
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name: names[0],
                committee: committee.clone(),
                parent_path: dir.path().to_path_buf(),
                db_options: None,
                metrics: EpochMetrics::new(&Registry::new()),
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
            .unwrap();

        let grace = epoch_store.protocol_config().end_of_publish_grace_rounds();
        assert!(
            grace > 0,
            "grace must be positive for this test to be meaningful"
        );

        // EndOfPublish at quorum but NOT all-voted (3 of 4): the close block
        // reads the in-memory aggregator, which `record_end_of_publish_vote`
        // does not populate, so seed it directly. 3 < 4 ⇒ all_voted = false, so
        // EndOfPublish readiness hinges purely on the grace.
        {
            let mut end_of_publish = epoch_store.end_of_publish.lock();
            for name in names.iter().take(3) {
                end_of_publish.insert_generic(*name, ());
            }
            assert!(
                end_of_publish.has_quorum(),
                "EndOfPublish at quorum (3 of 4)"
            );
            assert_eq!(end_of_publish.keys().count(), 3, "not all-voted (3 < 4)");
        }

        // Anchor the grace countdown so the commit we drive is exactly
        // grace-elapsed (rounds_since_quorum == grace ⇒ grace_elapsed) but below
        // the backstop (grace < 4*grace) — the precise window where base closes
        // and the fix defers.
        let anchor = 100u64;
        epoch_store
            .tables()
            .unwrap()
            .end_of_publish_quorum_round
            .insert(&0u64, &anchor)
            .unwrap();
        let close_window_round = anchor + grace;
        let commit_info = ConsensusCommitInfo::new_for_test(close_window_round, 0, true);
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));

        // Handoff signatures SUB-quorum (2 of 4 = validity threshold, < quorum
        // 3). Only the signer KEYS are summed by weight, so the signature value
        // is irrelevant to `handoff_signatures_meet_quorum`.
        let dummy_signature = Ed25519Signature::from_bytes(&[0u8; 64]).unwrap();
        for name in names.iter().take(2) {
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &dummy_signature)
                .unwrap();
        }
        assert!(
            !epoch_store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(close_window_round))
                .unwrap(),
            "handoff signatures must start sub-quorum (2 of 4)"
        );

        // STEP 1: EndOfPublish-ready (grace elapsed) + handoff sub-quorum.
        // Fix: decide_deferred_epoch_close(true, false, grace, grace) == None ⇒ defer.
        // Base: `all_voted || grace_elapsed` == true ⇒ close (fails here).
        let mut output = ConsensusCommitOutput::new(close_window_round);
        let (dwallet_messages, _system_messages, _notify_keys) = epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &commit_info,
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            epoch_store.should_accept_tx(),
            "#1736: with the handoff-cert quorum missing the close must DEFER — \
             reconfig must remain open (base closes here)"
        );
        assert!(
            !dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "#1736: no EndOfPublish close message may be emitted while the close \
             is deferred (base emits one here)"
        );

        // STEP 2: bring the handoff signatures to quorum (the 3rd signer).
        epoch_store
            .tables()
            .unwrap()
            .handoff_signatures
            .insert(&names[2], &dummy_signature)
            .unwrap();
        assert!(
            epoch_store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(close_window_round))
                .unwrap(),
            "handoff signatures now at quorum (3 of 4)"
        );

        // Fix: decide_deferred_epoch_close(true, true, grace, grace) == Some(false) ⇒
        // close. A fresh output per commit (the output is a per-commit batch).
        let mut output = ConsensusCommitOutput::new(close_window_round);
        let (dwallet_messages, _system_messages, _notify_keys) = epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &commit_info,
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            !epoch_store.should_accept_tx(),
            "#1736: once EndOfPublish-ready AND the handoff-cert quorum holds, \
             the close must fire — reconfig flips to RejectAllTx"
        );
        assert!(
            dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "#1736: the close must emit the EndOfPublish close message once both \
             conditions hold"
        );
    }

    /// #1917: a validator that RESTARTS after every EndOfPublish vote has landed
    /// must still close at the same round as its never-restarted peers.
    ///
    /// The two views of the vote set disagree by construction. The live
    /// aggregator stops accepting inserts at the quorum-crossing membership (3
    /// of 4 here), while `record_end_of_publish_vote` persists ALL votes and
    /// restart hydration rebuilds the aggregator from that full table (4 of 4).
    /// Reading `all_voted` from the live aggregator therefore flips it from
    /// false to true across a restart, making `eop_ready` true immediately and
    /// closing the epoch before the grace elapses — while peers keep waiting.
    ///
    /// The fix pins the count at the quorum-observing commit and reads it back
    /// from storage. This test DISCRIMINATES fix from base: on base, the
    /// post-restart commit closes and both STEP 3 assertions fail.
    ///
    /// Committee size 4 is deliberate — it is the smallest size where the test
    /// helper's quorum formula `(2n).div_ceil(3)` and the chain's
    /// `2*(n/3)+1` agree (both 3), so the scenario matches production. At n = 3
    /// they differ (2 vs 3) and quorum is unanimity on chain, where `all_voted`
    /// is legitimately true and there is nothing to discriminate.
    #[tokio::test]
    async fn epoch_close_all_voted_survives_restart_after_all_votes_land() {
        let (base_committee, names) = freeze_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let epoch_store = open_freeze_test_store(
            dir.path(),
            &base_committee,
            0,
            EpochMetrics::new(&Registry::new()),
        );
        let grace = epoch_store.protocol_config().end_of_publish_grace_rounds();
        assert!(grace > 1, "test needs a non-trivial grace window");

        // Handoff-cert quorum satisfied throughout, so the close hinges purely
        // on EndOfPublish readiness — i.e. on `all_voted` vs the grace.
        let dummy_signature = Ed25519Signature::from_bytes(&[0u8; 64]).unwrap();
        for name in names.iter().take(3) {
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &dummy_signature)
                .unwrap();
        }
        assert!(
            epoch_store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(0))
                .unwrap()
        );

        // STEP 1: reproduce the live path's two views as they stand once
        // EARLIER commits have durably landed every vote — the table holds all
        // four, while the in-memory aggregator stopped at the quorum-crossing
        // membership (the pre-quorum guard in `process_end_of_publish_vote`).
        // Written straight to the table here because these votes belong to
        // already-committed batches, not the commit this test drives.
        for name in names.iter() {
            epoch_store
                .tables()
                .unwrap()
                .end_of_publish
                .insert(name, &())
                .unwrap();
        }
        {
            let mut end_of_publish = epoch_store.end_of_publish.lock();
            for name in names.iter().take(3) {
                end_of_publish.insert_generic(*name, ());
            }
            assert!(end_of_publish.has_quorum(), "quorum at 3 of 4");
            assert_eq!(end_of_publish.keys().count(), 3, "live view is capped");
        }

        // STEP 2: the quorum-observing commit pins both the anchor and the
        // count. Well inside the grace, so no close fires here.
        let quorum_round = 100u64;
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
        let mut output = ConsensusCommitOutput::new(quorum_round);
        epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(quorum_round, 0, true),
                &authority_metrics,
            )
            .await
            .unwrap();
        let mut batch = epoch_store.db_batch().unwrap();
        output.write_to_batch(&epoch_store, &mut batch).unwrap();
        batch.write().unwrap();
        assert!(
            epoch_store.should_accept_tx(),
            "no close yet — the grace has not elapsed"
        );
        assert_eq!(
            epoch_store
                .tables()
                .unwrap()
                .end_of_publish_quorum_voted_count
                .get(&0u64)
                .unwrap(),
            Some(3),
            "the capped count must be pinned at the quorum-observing commit"
        );
        drop(epoch_store);

        // STEP 3: restart. Hydration rebuilds the aggregator from the full
        // table, so the LIVE view now says 4 of 4 — the input that would make
        // `all_voted` true and close the epoch early.
        let epoch_store = open_freeze_test_store(
            dir.path(),
            &base_committee,
            0,
            EpochMetrics::new(&Registry::new()),
        );
        assert_eq!(
            epoch_store.end_of_publish.lock().keys().count(),
            4,
            "restart hydrates the FULL vote set — this is the hazard being guarded"
        );

        let mut output = ConsensusCommitOutput::new(quorum_round + 1);
        let (dwallet_messages, _system_messages, _notify_keys) = epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(quorum_round + 1, 0, true),
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            epoch_store.should_accept_tx(),
            "#1917: the restarted validator must NOT close early — `all_voted` \
             must come from the pinned count (3), not the hydrated view (4)"
        );
        assert!(
            !dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "#1917: no close message may be emitted one round past quorum"
        );
    }

    /// #1917 crash-replay variant: a crash between PROCESSING the
    /// quorum-observing commit and WRITING its batch must not let the pinned
    /// count come back larger than the consensus sequence implies.
    ///
    /// This is the window that survives pinning the count alone. If the vote
    /// insert is an out-of-band table write, it is durable the moment the
    /// commit is processed, while the anchor and the count ride the batch. Lose
    /// the batch and the table is AHEAD of the replayed commit: hydration
    /// rebuilds an already-over-quorum aggregator, the replayed commit's
    /// pre-quorum guard therefore counts nothing, and the count re-pins at the
    /// hydrated size instead of the quorum-crossing one — `all_voted` true, and
    /// the epoch closes early exactly as in #1917. It needs the quorum commit
    /// to carry more than the crossing vote, which is the common shape at an
    /// epoch boundary where every validator votes off the same signal.
    ///
    /// Routing the vote insert through `ConsensusCommitOutput` closes it: the
    /// table can only ever be as current as the last committed batch.
    ///
    /// No failpoint needed — "crash before the batch write" is faithfully
    /// modelled by processing the commit and simply never writing its batch.
    #[tokio::test]
    async fn epoch_close_all_voted_survives_crash_before_quorum_commit_batch() {
        let (base_committee, names) = freeze_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let epoch_store = open_freeze_test_store(
            dir.path(),
            &base_committee,
            0,
            EpochMetrics::new(&Registry::new()),
        );

        let dummy_signature = Ed25519Signature::from_bytes(&[0u8; 64]).unwrap();
        for name in names.iter().take(3) {
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &dummy_signature)
                .unwrap();
        }

        // The quorum-observing commit carries ALL FOUR votes: the third crosses
        // quorum, the fourth is the one that must not inflate the pinned count.
        let quorum_round = 100u64;
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
        let mut output = ConsensusCommitOutput::new(quorum_round);
        for name in names.iter() {
            epoch_store
                .process_end_of_publish_vote(&mut output, name)
                .unwrap();
        }
        epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(quorum_round, 0, true),
                &authority_metrics,
            )
            .await
            .unwrap();

        // CRASH: the batch is dropped, never written. Nothing this commit
        // produced — votes, anchor, count — may have reached storage.
        drop(output);
        assert!(
            epoch_store
                .tables()
                .unwrap()
                .end_of_publish
                .safe_iter()
                .next()
                .is_none(),
            "votes must ride the commit batch — an out-of-band insert would \
             have survived the crash and is what reopens the #1917 window"
        );
        drop(epoch_store);

        // Replay: consensus redelivers the lost commit, this time to completion.
        let epoch_store = open_freeze_test_store(
            dir.path(),
            &base_committee,
            0,
            EpochMetrics::new(&Registry::new()),
        );
        assert_eq!(
            epoch_store.end_of_publish.lock().keys().count(),
            0,
            "hydration must see the pre-commit state, not a half-applied commit"
        );
        let mut output = ConsensusCommitOutput::new(quorum_round);
        for name in names.iter() {
            epoch_store
                .process_end_of_publish_vote(&mut output, name)
                .unwrap();
        }
        epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(quorum_round, 0, true),
                &authority_metrics,
            )
            .await
            .unwrap();
        let mut batch = epoch_store.db_batch().unwrap();
        output.write_to_batch(&epoch_store, &mut batch).unwrap();
        batch.write().unwrap();

        assert_eq!(
            epoch_store
                .tables()
                .unwrap()
                .end_of_publish_quorum_voted_count
                .get(&0u64)
                .unwrap(),
            Some(3),
            "#1917: replay must re-derive the quorum-crossing count (3), not the \
             number of votes the commit carried (4)"
        );
        assert!(
            epoch_store.should_accept_tx(),
            "#1917: the replayed commit must not close the epoch early"
        );
    }

    /// #1736 LIVENESS BACKSTOP (wiring): EndOfPublish-ready but the handoff-cert
    /// quorum never forms (handoff_signatures stays 2/4). The close must still
    /// FIRE at the backstop (rounds_since_quorum == grace * 4) so a genuinely
    /// non-signing validator cannot wedge the epoch open forever. Drives the
    /// real `process_consensus_transactions` path, not the pure decision.
    ///
    /// Regression guard, not a fix/base discriminator (base also closes in this
    /// window, earlier at `grace`): it fails loudly if the backstop is removed
    /// or its multiplier changed — either of which would turn a permanently
    /// missing cert quorum into an indefinite epoch hang.
    #[tokio::test]
    async fn epoch_close_backstop_fires_without_handoff_cert_quorum() {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let names: Vec<AuthorityName> = committee.names().copied().collect();

        let dir = tempfile::tempdir().unwrap();
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store =
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name: names[0],
                committee: committee.clone(),
                parent_path: dir.path().to_path_buf(),
                db_options: None,
                metrics: EpochMetrics::new(&Registry::new()),
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
            .unwrap();

        let grace = epoch_store.protocol_config().end_of_publish_grace_rounds();
        assert!(
            grace > 0,
            "grace must be positive for this test to be meaningful"
        );

        // EndOfPublish at quorum but not all-voted (3 of 4): readiness hinges on
        // the grace. Seed the in-memory aggregator directly.
        {
            let mut end_of_publish = epoch_store.end_of_publish.lock();
            for name in names.iter().take(3) {
                end_of_publish.insert_generic(*name, ());
            }
            assert!(
                end_of_publish.has_quorum(),
                "EndOfPublish at quorum (3 of 4)"
            );
            assert_eq!(end_of_publish.keys().count(), 3, "not all-voted (3 < 4)");
        }

        let anchor = 100u64;
        epoch_store
            .tables()
            .unwrap()
            .end_of_publish_quorum_round
            .insert(&0u64, &anchor)
            .unwrap();

        // Handoff signatures SUB-quorum (2 of 4) — and they STAY there: the
        // quorum never forms in this test.
        let dummy_signature = Ed25519Signature::from_bytes(&[0u8; 64]).unwrap();
        for name in names.iter().take(2) {
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &dummy_signature)
                .unwrap();
        }
        assert!(
            !epoch_store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(anchor))
                .unwrap(),
            "handoff signatures stay sub-quorum (2 of 4) for the whole test"
        );
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));

        // One round BEFORE the backstop boundary (which is at
        // rounds_since_quorum == grace*4, inclusive): must still DEFER.
        let pre_backstop_round = anchor + grace * 4 - 1;
        let commit_info = ConsensusCommitInfo::new_for_test(pre_backstop_round, 0, true);
        let mut output = ConsensusCommitOutput::new(pre_backstop_round);
        let (dwallet_messages, _system_messages, _notify_keys) = epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &commit_info,
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            epoch_store.should_accept_tx(),
            "one round before the backstop the close must still DEFER"
        );
        assert!(
            !dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "no EndOfPublish may be emitted before the backstop"
        );

        // AT the backstop (anchor + grace*4): the close must FIRE even though
        // the handoff-cert quorum is permanently missing (a close at sub-quorum
        // is necessarily the backstop close).
        let backstop_round = anchor + grace * 4;
        let commit_info = ConsensusCommitInfo::new_for_test(backstop_round, 0, true);
        let mut output = ConsensusCommitOutput::new(backstop_round);
        let (dwallet_messages, _system_messages, _notify_keys) = epoch_store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &[],
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &commit_info,
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            !epoch_store.should_accept_tx(),
            "#1736 backstop: with the handoff-cert quorum permanently missing the \
             close must FIRE at rounds_since_quorum == grace*4 (liveness)"
        );
        assert!(
            dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "#1736 backstop: the backstop close must emit the EndOfPublish message"
        );
    }

    /// #1736 (cert persistence): `install_expected_handoff_attestation` rebuilds
    /// the aggregator from the persisted `handoff_signatures` table on install.
    /// When that replay crosses quorum it mints the cert WITHOUT going through
    /// `record_handoff_signature`'s `Certified` arm (the only other persist
    /// path), so the install path must itself persist the replay-minted cert —
    /// otherwise a validator that crossed quorum via replay holds the cert in
    /// memory only and a later restart / joiner read misses it.
    ///
    /// Discriminates the fix from base: pre-fix the cert was minted in memory on
    /// this path but never persisted, so the perpetual read below returned None.
    #[tokio::test]
    async fn install_expected_handoff_attestation_persists_replay_minted_cert() {
        let (base_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let names: Vec<AuthorityName> = base_committee.names().copied().collect();

        // Deterministic Ed25519 consensus keypairs (seeded — avoids the
        // multiple-rand-version conflict that bites direct generate() in
        // ika-core tests), one per validator, carried ON THE COMMITTEE so the
        // replay's signature re-verification (now committee-based, no side
        // provider) accepts them.
        let consensus_keypairs: Vec<Ed25519KeyPair> = (0..names.len())
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i + 1) as u8;
                Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&seed).unwrap())
            })
            .collect();
        let consensus_keys: HashMap<_, _> = names
            .iter()
            .copied()
            .zip(consensus_keypairs.iter().map(|kp| kp.public().clone()))
            .collect();
        let committee = Arc::new(Committee::new(
            base_committee.epoch,
            base_committee.voting_rights.clone(),
            HashMap::new(),
            consensus_keys,
            base_committee.quorum_threshold,
            base_committee.validity_threshold,
        ));

        let dir = tempfile::tempdir().unwrap();
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store =
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name: names[0],
                committee: committee.clone(),
                parent_path: dir.path().to_path_buf(),
                db_options: None,
                metrics: EpochMetrics::new(&Registry::new()),
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
            .unwrap();

        // Perpetual tables in their own tempdir, installed the way node startup
        // does — without this the replay-mint persist is a silent no-op.
        let perpetual_dir = tempfile::tempdir().unwrap();
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
        epoch_store.install_perpetual_tables_for_handoff(perpetual_tables.clone());

        // The attestation this validator expects to certify (empty items: only
        // the persistence round-trip is under test).
        let epoch = 0u64;
        let attestation = build_handoff_attestation(epoch, [0xABu8; 32], vec![]).unwrap();

        // Persist a quorum (3 of 4) of REAL handoff signatures over it. install
        // replays these into a fresh aggregator; at the 3rd it crosses quorum and
        // mints the cert during replay.
        for (name, keypair) in names.iter().zip(&consensus_keypairs).take(3) {
            let message = sign_handoff_attestation(attestation.clone(), *name, keypair);
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &message.signature)
                .unwrap();
        }

        assert!(
            perpetual_tables
                .get_certified_handoff_attestation(epoch)
                .unwrap()
                .is_none(),
            "no cert should be persisted before install"
        );

        epoch_store
            .install_expected_handoff_attestation(attestation)
            .unwrap();

        assert!(
            perpetual_tables
                .get_certified_handoff_attestation(epoch)
                .unwrap()
                .is_some(),
            "#1736: install_expected_handoff_attestation must persist the cert it \
             mints during signature replay (pre-fix it stayed in memory only)"
        );
    }

    /// V9b: re-installing a DIFFERENT attestation must delete the signature
    /// rows that endorsed the superseded one from the TABLE — not only from
    /// the in-memory aggregator — because the deferred-close quorum gate
    /// (`handoff_signatures_meet_quorum`) sums the table. Pre-fix the stale
    /// rows survived and the gate could count old endorsements.
    #[tokio::test]
    async fn install_reinstall_drops_stale_rows_from_table_and_gate() {
        let (base_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let names: Vec<AuthorityName> = base_committee.names().copied().collect();
        let consensus_keypairs: Vec<Ed25519KeyPair> = (0..names.len())
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i + 1) as u8;
                Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&seed).unwrap())
            })
            .collect();
        let consensus_keys: HashMap<_, _> = names
            .iter()
            .copied()
            .zip(consensus_keypairs.iter().map(|kp| kp.public().clone()))
            .collect();
        let committee = Arc::new(Committee::new(
            base_committee.epoch,
            base_committee.voting_rights.clone(),
            HashMap::new(),
            consensus_keys,
            base_committee.quorum_threshold,
            base_committee.validity_threshold,
        ));

        let dir = tempfile::tempdir().unwrap();
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store =
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name: names[0],
                committee: committee.clone(),
                parent_path: dir.path().to_path_buf(),
                db_options: None,
                metrics: EpochMetrics::new(&Registry::new()),
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
            .unwrap();

        let epoch = 0u64;
        // Attestation A and a DIFFERENT attestation B (distinct next-committee
        // hash), so signatures over A do not verify against B.
        let attestation_a = build_handoff_attestation(epoch, [0xAAu8; 32], vec![]).unwrap();
        let attestation_b = build_handoff_attestation(epoch, [0xBBu8; 32], vec![]).unwrap();

        // A full QUORUM (3 of 4, threshold 3) of A-endorsing rows lands in
        // the table — so the close gate reads TRUE before the re-install and
        // the gate assertion below actually reacts to the fix (with a
        // sub-quorum the final !gate assertion would pass even with the
        // deletion reverted — a vacuous check).
        for (name, keypair) in names.iter().zip(&consensus_keypairs).take(3) {
            let message = sign_handoff_attestation(attestation_a.clone(), *name, keypair);
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .insert(name, &message.signature)
                .unwrap();
        }
        epoch_store
            .install_expected_handoff_attestation(attestation_a)
            .unwrap();
        assert_eq!(
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            3,
            "the three A-endorsing rows are present after installing A"
        );
        assert!(
            epoch_store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(0))
                .unwrap(),
            "the close gate must read true with a quorum of A-endorsing rows and A installed"
        );

        // Re-install B: the A-endorsing rows no longer verify and must stop
        // counting toward the gate (which must not count endorsements of a
        // superseded attestation). Since #1927 the deletion is STAGED rather
        // than applied on sight, so it takes effect at a commit: the gate
        // reads false as soon as a commit picks the staged deletes up, and the
        // table is empty once that commit's batch is written.
        epoch_store
            .install_expected_handoff_attestation(attestation_b)
            .unwrap();
        let commit_round = 10u64;
        let mut output = ConsensusCommitOutput::new(commit_round);
        output.record_handoff_signature_rows(epoch_store.take_staged_handoff_signature_rows());
        assert!(
            !epoch_store.handoff_signatures_meet_quorum(&output).unwrap(),
            "the close gate must not count the superseded rows"
        );
        let mut batch = epoch_store.db_batch().unwrap();
        output.write_to_batch(&epoch_store, &mut batch).unwrap();
        batch.write().unwrap();
        assert_eq!(
            epoch_store
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            0,
            "stale A-endorsing rows must be deleted from the table on re-install to B"
        );
    }

    /// Test committee whose members carry real consensus keys, so bundled
    /// handoff signatures actually verify — `new_simple_test_committee_of_size`
    /// leaves `consensus_keys` empty, which rejects every signature.
    fn handoff_test_committee() -> (Arc<Committee>, Vec<AuthorityName>, Vec<Ed25519KeyPair>) {
        let (base_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let names: Vec<AuthorityName> = base_committee.names().copied().collect();
        let consensus_keypairs: Vec<Ed25519KeyPair> = (0..names.len())
            .map(|index| {
                let mut seed = [0u8; 32];
                seed[0] = (index + 1) as u8;
                Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&seed).unwrap())
            })
            .collect();
        let consensus_keys: HashMap<_, _> = names
            .iter()
            .copied()
            .zip(consensus_keypairs.iter().map(|kp| kp.public().clone()))
            .collect();
        let committee = Arc::new(Committee::new(
            base_committee.epoch,
            base_committee.voting_rights.clone(),
            HashMap::new(),
            consensus_keys,
            base_committee.quorum_threshold,
            base_committee.validity_threshold,
        ));
        (committee, names, consensus_keypairs)
    }

    fn open_handoff_test_store(
        dir: &Path,
        committee: Arc<Committee>,
        name: AuthorityName,
    ) -> Arc<AuthorityPerEpochStore> {
        let epoch_start_configuration = EpochStartConfiguration::new(
            EpochStartSystem::new_for_testing_with_epoch(committee.epoch),
        )
        .unwrap();
        AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
            name,
            committee,
            parent_path: dir.to_path_buf(),
            db_options: None,
            metrics: EpochMetrics::new(&Registry::new()),
            epoch_start_configuration,
            chain_identifier: ChainIdentifier::default(),
            packages_config: IkaNetworkConfig::new_for_testing(),
        })
        .unwrap()
    }

    fn end_of_publish_v2_tx(
        attestation: &ika_types::handoff::HandoffAttestation,
        name: AuthorityName,
        keypair: &Ed25519KeyPair,
    ) -> VerifiedSequencedConsensusTransaction {
        VerifiedSequencedConsensusTransaction::new_test(
            ConsensusTransaction::new_end_of_publish_v2(
                name,
                sign_handoff_attestation(attestation.clone(), name, keypair),
            ),
        )
    }

    /// Drives one commit through the real `process_consensus_transactions`
    /// path and writes its batch, returning the close-gate value the commit
    /// was decided against and the checkpoint messages it emitted.
    async fn run_handoff_commit(
        store: &Arc<AuthorityPerEpochStore>,
        round: u64,
        transactions: &[VerifiedSequencedConsensusTransaction],
        authority_metrics: &Arc<AuthorityMetrics>,
    ) -> (bool, Vec<DWalletCheckpointMessageKind>) {
        let mut output = ConsensusCommitOutput::new(round);
        let (dwallet_messages, _system_messages, _notify_keys) = store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                transactions,
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(round, 0, true),
                authority_metrics,
            )
            .await
            .unwrap();
        let gate = store.handoff_signatures_meet_quorum(&output).unwrap();
        let mut batch = store.db_batch().unwrap();
        output.write_to_batch(store, &mut batch).unwrap();
        batch.write().unwrap();
        (gate, dwallet_messages)
    }

    /// #1927: the close gate's signature rows must be attributable to a
    /// commit on BOTH sides of an attestation-install skew.
    ///
    /// Store A installs its expected attestation up front and records each
    /// bundled signature live on the consensus arm. Store B lags — every
    /// bundle buffers — and installs only later, at WALL-CLOCK local time,
    /// draining the whole buffer in one go. Pre-fix both writers put rows
    /// straight into `handoff_signatures`, so B's drained rows became durable
    /// at an instant no commit corresponds to, and the close gate could be
    /// decided against state that no commit carried.
    ///
    /// The DISCRIMINATING assertion is the one immediately after B's install:
    /// the drained rows must still be absent from the durable table, waiting
    /// for a commit to carry them. Pre-fix they are already in it.
    ///
    /// The two-store gate comparison records what this does and does not buy.
    /// Both stores agree on the gate at every commit here, because B's drain
    /// is picked up by the next commit and the quorum-crossing bundle reaches
    /// both at the same commit. It does NOT make the gate a pure function of
    /// the sequence: B's drained rows still land in whichever commit follows
    /// its local install, so a wider skew still moves B's quorum commit.
    /// Retiring that residue is the sequence-pure tally in
    /// dev-docs/plans/handoff-barrier-escape-and-pure-close-gate.md (item 3).
    #[tokio::test]
    async fn handoff_gate_rows_are_commit_attributable_across_install_skew() {
        let (committee, names, keypairs) = handoff_test_committee();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let store_a = open_handoff_test_store(dir_a.path(), committee.clone(), names[0]);
        let store_b = open_handoff_test_store(dir_b.path(), committee.clone(), names[1]);
        let attestation = build_handoff_attestation(0, [0xA7u8; 32], vec![]).unwrap();
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));

        // A is ready up front; B's own snapshot hasn't finished building.
        store_a
            .install_expected_handoff_attestation(attestation.clone())
            .unwrap();

        // Two commits, one bundle each. Deliberately kept SUB-quorum (2 of 4,
        // quorum 3) so B's buffer does not trip the quorum-adoption shortcut
        // in `record_handoff_signature` — that shortcut installs from the
        // buffer and would close the skew this test is about.
        let mut gate_a = Vec::new();
        let mut gate_b = Vec::new();
        for (index, round) in [101u64, 102].into_iter().enumerate() {
            let transactions = [end_of_publish_v2_tx(
                &attestation,
                names[index],
                &keypairs[index],
            )];
            let (gate, _) =
                run_handoff_commit(&store_a, round, &transactions, &authority_metrics).await;
            gate_a.push(gate);
            let (gate, _) =
                run_handoff_commit(&store_b, round, &transactions, &authority_metrics).await;
            gate_b.push(gate);
        }
        assert_eq!(
            gate_a,
            vec![false, false],
            "still sub-quorum on A after two of four signers"
        );
        assert_eq!(
            gate_b, gate_a,
            "#1927: the close gate must agree at every commit across the skew"
        );
        assert_eq!(
            store_a
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            2,
            "A's rows are durable, each carried by the commit that sequenced it"
        );
        assert_eq!(
            store_b.pending_handoff_signatures.lock().len(),
            2,
            "B buffered both bundles — it has no expected attestation to verify against"
        );

        // B finally builds and installs the same attestation, BETWEEN commits.
        // The drain re-verifies both buffered bundles and stages them.
        store_b
            .install_expected_handoff_attestation(attestation.clone())
            .unwrap();
        assert_eq!(
            store_b
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            0,
            "#1927: drained rows must not be durable until a commit carries them — \
             pre-fix the install wrote them to the table at wall-clock local time, \
             attributable to no commit at all"
        );
        assert_eq!(
            store_b.staged_handoff_signature_rows.lock().len(),
            2,
            "both drained rows are staged for whichever commit comes next"
        );

        // The quorum-crossing bundle. A records it live; B's commit carries it
        // plus the two rows its install drained. Both cross at THIS commit.
        let round = 103u64;
        let transactions = [end_of_publish_v2_tx(&attestation, names[2], &keypairs[2])];
        for store in [&store_a, &store_b] {
            let (gate, _) =
                run_handoff_commit(store, round, &transactions, &authority_metrics).await;
            assert!(
                gate,
                "both stores must observe the handoff quorum at the same commit"
            );
            assert_eq!(
                store
                    .tables()
                    .unwrap()
                    .handoff_signatures
                    .safe_iter()
                    .count(),
                3,
                "every row is durable exactly once its commit's batch is written"
            );
        }
    }

    /// #1927 crash-replay variant: a crash between PROCESSING the commit that
    /// carries the quorum-crossing handoff signatures and WRITING its batch
    /// must not leave the `handoff_signatures` table ahead of the last
    /// committed commit.
    ///
    /// Pre-fix `record_handoff_signature` inserted on sight, so the rows were
    /// durable the moment the commit was processed while the close marker,
    /// the votes and the anchor rode the batch. The table then described a
    /// commit that never landed — the out-of-band-write class of #1829/#1917,
    /// on the other half of the same gate.
    ///
    /// No failpoint needed: "crash before the batch write" is modelled
    /// faithfully by processing the commit and never writing its batch.
    #[tokio::test]
    async fn handoff_gate_survives_crash_before_signature_commit_batch() {
        let (committee, names, keypairs) = handoff_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let attestation = build_handoff_attestation(0, [0xC5u8; 32], vec![]).unwrap();
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));

        // Already-committed state from EARLIER commits: the EndOfPublish
        // quorum, its grace anchor and its pinned count. Written straight to
        // the tables because they belong to batches that already landed; the
        // reopen below is what loads them into the in-memory aggregator.
        let anchor = 100u64;
        {
            let store = open_handoff_test_store(dir.path(), committee.clone(), names[0]);
            let tables = store.tables().unwrap();
            for name in names.iter().take(3) {
                tables.end_of_publish.insert(name, &()).unwrap();
            }
            tables
                .end_of_publish_quorum_round
                .insert(&0u64, &anchor)
                .unwrap();
            tables
                .end_of_publish_quorum_voted_count
                .insert(&0u64, &3u64)
                .unwrap();
        }
        let store = open_handoff_test_store(dir.path(), committee.clone(), names[0]);
        let grace = store.protocol_config().end_of_publish_grace_rounds();
        assert!(grace > 1, "test needs a non-trivial grace window");
        assert!(
            store.end_of_publish.lock().has_quorum(),
            "EndOfPublish readiness must come from already-committed state, so the \
             close hinges purely on the handoff gate"
        );
        store
            .install_expected_handoff_attestation(attestation.clone())
            .unwrap();

        // The quorum commit: grace elapsed, and three bundles cross the
        // handoff quorum. This is the round every peer closes at.
        let quorum_round = anchor + grace;
        let transactions: Vec<_> = (0..3)
            .map(|index| end_of_publish_v2_tx(&attestation, names[index], &keypairs[index]))
            .collect();
        let mut output = ConsensusCommitOutput::new(quorum_round);
        let (dwallet_messages, _system_messages, _notify_keys) = store
            .process_consensus_transactions::<DWalletCheckpointService>(
                &mut output,
                &transactions,
                &None,
                &None::<Arc<SystemCheckpointService>>,
                &ConsensusCommitInfo::new_for_test(quorum_round, 0, true),
                &authority_metrics,
            )
            .await
            .unwrap();
        assert!(
            store.handoff_signatures_meet_quorum(&output).unwrap(),
            "the commit's own bundles must satisfy the gate at this commit — \
             deferring them to the next commit would delay the close by a round \
             against a binary that writes on sight"
        );
        assert!(
            dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "the quorum commit must close the epoch"
        );

        // CRASH: the batch is dropped, never written. Nothing this commit
        // produced — signature rows, votes, close marker — may have reached
        // storage.
        drop(output);
        assert_eq!(
            store
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            0,
            "#1927: signature rows must ride the commit batch — an out-of-band \
             insert survives the crash and leaves the durable table describing a \
             commit that never landed"
        );
        drop(store);

        // Replay: consensus redelivers the lost commit, this time to
        // completion. The gate and the close round must come out identical to
        // the original run.
        let store = open_handoff_test_store(dir.path(), committee.clone(), names[0]);
        assert!(
            store.should_accept_tx(),
            "the close marker rode the lost batch, so the reopened epoch is open"
        );
        store
            .install_expected_handoff_attestation(attestation.clone())
            .unwrap();
        assert!(
            !store
                .handoff_signatures_meet_quorum(&ConsensusCommitOutput::new(quorum_round))
                .unwrap(),
            "hydration must see the pre-commit state, not a half-applied commit"
        );
        let (gate, dwallet_messages) =
            run_handoff_commit(&store, quorum_round, &transactions, &authority_metrics).await;
        assert!(gate, "replay must re-derive the handoff quorum");
        assert!(
            dwallet_messages
                .iter()
                .any(|message| matches!(message, DWalletCheckpointMessageKind::EndOfPublish)),
            "replay must close at the same round the original run did"
        );
        assert_eq!(
            store
                .tables()
                .unwrap()
                .handoff_signatures
                .safe_iter()
                .count(),
            3,
            "the replayed commit's batch is what makes the rows durable"
        );
    }

    fn make_session_id(preimage: [u8; 32]) -> SessionIdentifier {
        SessionIdentifier::new(SessionType::InternalPresign, preimage)
    }

    #[tokio::test]
    async fn test_insert_and_pop_presign() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let session_id = make_session_id([1; 32]);
        let presigns = vec![vec![1u8, 2, 3], vec![4, 5, 6]];

        tables
            .insert_presigns(algorithm, key_id, 0, session_id, presigns)
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 2);

        let (popped_session, first_blending_index, first_presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(popped_session, session_id);
        assert_eq!(first_blending_index, 0);
        assert_eq!(first_presign, vec![1u8, 2, 3]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 1);

        let (_, second_blending_index, second_presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(second_blending_index, 1);
        assert_eq!(second_presign, vec![4u8, 5, 6]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);

        assert!(
            tables
                .pop_presign_for_testing(algorithm, key_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_presign_pool_isolation_across_key_ids() {
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

        let (popped_session, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id_a)
            .unwrap()
            .unwrap();
        assert_eq!(popped_session, session_id_a);
        assert_eq!(presign, vec![10u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id_a).unwrap(), 1);
        assert_eq!(tables.presign_pool_size(algorithm, key_id_b).unwrap(), 3);

        let (popped_session, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id_b)
            .unwrap()
            .unwrap();
        assert_eq!(popped_session, session_id_b);
        assert_eq!(presign, vec![20u8]);

        // Exhaust key_id_a
        tables
            .pop_presign_for_testing(algorithm, key_id_a)
            .unwrap()
            .unwrap();
        assert!(
            tables
                .pop_presign_for_testing(algorithm, key_id_a)
                .unwrap()
                .is_none()
        );
        assert_eq!(tables.presign_pool_size(algorithm, key_id_a).unwrap(), 0);

        // key_id_b still has presigns
        assert_eq!(tables.presign_pool_size(algorithm, key_id_b).unwrap(), 2);
        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id_b)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![21u8]);
    }

    #[tokio::test]
    async fn test_pop_presign_ordering_across_sessions() {
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
        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![5u8]);

        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![10u8]);

        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![20u8]);

        assert!(
            tables
                .pop_presign_for_testing(algorithm, key_id)
                .unwrap()
                .is_none()
        );
    }

    /// One replayed consensus round's effect on the presign pool: either an
    /// internal-presign output reaching quorum (a fill), or a global presign
    /// request being served out of the pool.
    enum PresignPoolRound {
        Fill {
            session_sequence_number: u64,
            presigns: Vec<Vec<u8>>,
        },
        Serve {
            request_sequence_number: u64,
        },
    }

    /// Replays a round stream against a pool, returning what each `Serve` round
    /// served — `None` when the pool had nothing left to serve, which is itself
    /// a divergence from a run that served that round.
    fn replay_presign_pool_rounds(
        tables: &AuthorityEpochTables,
        signature_algorithm: DWalletSignatureAlgorithm,
        dwallet_network_encryption_key_id: ObjectID,
        rounds: &[PresignPoolRound],
    ) -> Vec<Option<Vec<u8>>> {
        rounds
            .iter()
            .filter_map(|round| match round {
                PresignPoolRound::Fill {
                    session_sequence_number,
                    presigns,
                } => {
                    tables
                        .insert_presigns(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            *session_sequence_number,
                            make_session_id([*session_sequence_number as u8; 32]),
                            presigns.clone(),
                        )
                        .unwrap();
                    None
                }
                PresignPoolRound::Serve {
                    request_sequence_number,
                } => Some(bound_presign(
                    tables
                        .assign_presign_for_demand(
                            &PresignDemand::GlobalRequest {
                                session_sequence_number: *request_sequence_number,
                            },
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                        )
                        .unwrap(),
                )),
            })
            .collect()
    }

    /// The presign a drain bound to the demand, or `None` if it bound none —
    /// an empty pool, or (NOA only) a demand the park bound dropped. These
    /// tests compare WHICH presign a demand got, so the identifiers the
    /// outcome also carries are not part of the comparison.
    fn bound_presign(outcome: PresignAssignmentOutcome) -> Option<Vec<u8>> {
        match outcome {
            PresignAssignmentOutcome::Assigned { presign, .. } => Some(presign),
            PresignAssignmentOutcome::PoolEmpty | PresignAssignmentOutcome::Evicted => None,
        }
    }

    /// The DWallet MPC service replays EVERY consensus round of the epoch after
    /// a restart (its round cursor is in-memory and starts unset), but the
    /// presign pool is durable per-epoch state that the replay does NOT start
    /// from empty. A fill whose session sequence number is LOWER than one
    /// already in the pool — normal, since a batch of concurrently instantiated
    /// internal presign sessions completes in consensus order, not sequence
    /// order — survives the crash and is visible to pops replayed at rounds
    /// BEFORE its own fill round. A bare re-pop there binds a different presign
    /// than the original run did, so this validator's checkpoint message stops
    /// matching its never-crashed peers'.
    #[tokio::test]
    async fn presign_pool_replay_after_crash_serves_the_same_presigns() {
        let signature_algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let key_id = ObjectID::random();

        let rounds = vec![
            PresignPoolRound::Fill {
                session_sequence_number: 2,
                presigns: vec![vec![0xb0], vec![0xb1]],
            },
            PresignPoolRound::Serve {
                request_sequence_number: 10,
            },
            PresignPoolRound::Serve {
                request_sequence_number: 11,
            },
            // Sequence number 1 reaches output quorum only now, after 2's.
            PresignPoolRound::Fill {
                session_sequence_number: 1,
                presigns: vec![vec![0xa0], vec![0xa1]],
            },
            PresignPoolRound::Serve {
                request_sequence_number: 12,
            },
        ];

        // Control: a validator that never crashed.
        let control = create_tables();
        let control_served =
            replay_presign_pool_rounds(&control, signature_algorithm, key_id, &rounds);

        // Crashed validator: the same stream, then a restart that replays the
        // whole epoch from round zero on top of the pool that survived.
        let crashed = create_tables();
        replay_presign_pool_rounds(&crashed, signature_algorithm, key_id, &rounds);
        let replayed_served =
            replay_presign_pool_rounds(&crashed, signature_algorithm, key_id, &rounds);

        assert_eq!(
            replayed_served, control_served,
            "a replayed round must bind the same presign it bound before the crash; \
             binding a different one byte-diverges this validator's checkpoint message \
             from its never-crashed peers"
        );
        // A request that arrives AFTER the replay must draw a presign that was
        // never served before: a replay that re-absorbed its fills would have
        // resurrected already-served presigns and handed one to a second
        // on-chain presign id.
        let fresh_request_sequence_number = 13;
        let crashed_fresh = bound_presign(
            crashed
                .assign_presign_for_demand(
                    &PresignDemand::GlobalRequest {
                        session_sequence_number: fresh_request_sequence_number,
                    },
                    signature_algorithm,
                    key_id,
                )
                .unwrap(),
        );
        let control_fresh = bound_presign(
            control
                .assign_presign_for_demand(
                    &PresignDemand::GlobalRequest {
                        session_sequence_number: fresh_request_sequence_number,
                    },
                    signature_algorithm,
                    key_id,
                )
                .unwrap(),
        );
        assert!(
            !control_served.contains(&crashed_fresh),
            "the replay must not resurrect an already-served presign into the pool: \
             {crashed_fresh:?} was already served to an earlier request"
        );
        assert_eq!(
            crashed_fresh, control_fresh,
            "a post-replay request must be served the same presign a never-crashed \
             validator serves it"
        );

        assert_eq!(
            crashed
                .presign_pool_size(signature_algorithm, key_id)
                .unwrap(),
            control
                .presign_pool_size(signature_algorithm, key_id)
                .unwrap(),
            "the pool size counter must converge with a never-crashed validator's; \
             an inflated counter reads as a full pool, suppresses internal presign \
             top-ups, and starves the pool"
        );
    }

    /// Assignment is idempotent in the demand IDENTITY, for every demand kind.
    ///
    /// This is the property the whole API exists for: each consumer replays
    /// its demand stream from a per-epoch table after a restart, and a second
    /// pop would bind a different presign than the never-crashed peers bound
    /// (fills complete out of sequence order, so the pool head moves between
    /// the two pops) — a byte-divergent checkpoint or attestation from an
    /// honest validator.
    #[tokio::test]
    async fn assignment_is_idempotent_in_the_demand_identity() {
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;

        for demand in [
            PresignDemand::GlobalRequest {
                session_sequence_number: 7,
            },
            PresignDemand::Noa {
                demand_id: NOAPresignDemandId::Checkpoint {
                    tx_ref: NOACheckpointTxRef {
                        kind_name: NOACheckpointKindName::SuiDWallet,
                        sequence_number: 4,
                        tx_index: 0,
                        epoch: 1,
                    },
                    retry_round: 0,
                },
            },
        ] {
            let tables = create_tables();
            for (sequence_number, marker) in [(0u64, 0xAAu8), (1, 0xBB)] {
                tables
                    .insert_presigns(
                        algorithm,
                        key_id,
                        sequence_number,
                        SessionIdentifier::new(SessionType::InternalPresign, [marker; 32]),
                        vec![vec![marker; 8]],
                    )
                    .unwrap();
            }

            let first = tables
                .assign_presign_for_demand(&demand, algorithm, key_id)
                .unwrap();
            assert!(
                matches!(first, PresignAssignmentOutcome::Assigned { .. }),
                "{demand:?}: the pool is non-empty, so the demand must be assigned"
            );
            let pool_after_first = tables.presign_pool_size(algorithm, key_id).unwrap();

            let second = tables
                .assign_presign_for_demand(&demand, algorithm, key_id)
                .unwrap();

            assert_eq!(
                first, second,
                "{demand:?}: a re-seen demand must return the presign it was \
                 already given, not a fresh one"
            );
            assert_eq!(
                tables.presign_pool_size(algorithm, key_id).unwrap(),
                pool_after_first,
                "{demand:?}: re-seeing a demand must not pop the pool a second time"
            );

            // The NOA arm carries two writes the returned triple does not
            // show, and a merge dropping either would pass every assertion
            // above while failing at signing time: the used-presign marker
            // (without it the presign can be handed out twice) and the network
            // key id (the sign must instantiate under the SAME key the presign
            // came from).
            if let PresignDemand::Noa { demand_id } = &demand {
                let PresignAssignmentOutcome::Assigned {
                    session_identifier,
                    blending_index,
                    ..
                } = first
                else {
                    panic!("{demand:?}: expected an assignment, found {first:?}");
                };
                assert!(
                    tables
                        .is_presign_used(session_identifier, blending_index)
                        .unwrap(),
                    "the NOA arm must mark its popped presign used"
                );
                let Some(NoaPresignDemandResolution::Assigned {
                    network_encryption_key_id,
                    ..
                }) = tables
                    .noa_presign_demand_resolutions
                    .get(&demand_id.digest())
                    .unwrap()
                else {
                    panic!("the assignment was recorded as this demand's resolution");
                };
                assert_eq!(
                    network_encryption_key_id, key_id,
                    "the assignment must record the network key the presign came from"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_pop_from_empty_pool() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;

        assert!(
            tables
                .pop_presign_for_testing(algorithm, key_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);
    }

    #[tokio::test]
    async fn test_multiple_presigns_per_session() {
        let tables = create_tables();
        let key_id = ObjectID::random();
        let algorithm = DWalletSignatureAlgorithm::ECDSASecp256k1;
        let session_id = make_session_id([42; 32]);
        let presigns = vec![vec![1u8], vec![2], vec![3]];

        tables
            .insert_presigns(algorithm, key_id, 0, session_id, presigns)
            .unwrap();

        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 3);

        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![1u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 2);

        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![2u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 1);

        let (_, _, presign) = tables
            .pop_presign_for_testing(algorithm, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![3u8]);
        assert_eq!(tables.presign_pool_size(algorithm, key_id).unwrap(), 0);

        assert!(
            tables
                .pop_presign_for_testing(algorithm, key_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_presign_pool_isolation_across_algorithms() {
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

        let (_, _, presign) = tables
            .pop_presign_for_testing(ecdsa, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![100u8]);
        assert_eq!(tables.presign_pool_size(ecdsa, key_id).unwrap(), 0);

        // EdDSA pool unaffected
        assert_eq!(tables.presign_pool_size(eddsa, key_id).unwrap(), 1);
        let (_, _, presign) = tables
            .pop_presign_for_testing(eddsa, key_id)
            .unwrap()
            .unwrap();
        assert_eq!(presign, vec![200u8]);
    }

    #[tokio::test]
    async fn network_dkg_output_digest_table_roundtrip() {
        let tables = create_tables();
        let key_a = ObjectID::random();
        let key_b = ObjectID::random();
        tables
            .network_dkg_output_digests
            .insert(&key_a, &[0x11; 32])
            .unwrap();
        tables
            .network_dkg_output_digests
            .insert(&key_b, &[0x22; 32])
            .unwrap();
        // Replays are idempotent: re-inserting the same digest is a
        // no-op.
        tables
            .network_dkg_output_digests
            .insert(&key_a, &[0x11; 32])
            .unwrap();

        let collected: std::collections::BTreeMap<ObjectID, [u8; 32]> = tables
            .network_dkg_output_digests
            .safe_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected.get(&key_a), Some(&[0x11; 32]));
        assert_eq!(collected.get(&key_b), Some(&[0x22; 32]));
    }

    #[tokio::test]
    async fn network_dkg_and_reconfig_caches_are_independent() {
        // Same key id appearing in both caches doesn't collide —
        // they're separate tables addressing different artifacts.
        let tables = create_tables();
        let key = ObjectID::random();
        tables
            .network_dkg_output_digests
            .insert(&key, &[0xAA; 32])
            .unwrap();
        tables
            .network_reconfiguration_output_digests
            .insert(&key, &[0xBB; 32])
            .unwrap();

        assert_eq!(
            tables.network_dkg_output_digests.get(&key).unwrap(),
            Some([0xAA; 32])
        );
        assert_eq!(
            tables
                .network_reconfiguration_output_digests
                .get(&key)
                .unwrap(),
            Some([0xBB; 32])
        );
    }

    // ---- mpc_data freeze-progress metrics ----

    /// 4-member unit-stake committee (quorum 3, validity 2) for the
    /// freeze-metrics tests. Generated ONCE per test and re-derived per
    /// epoch/open from the same base — the restart tests reopen the
    /// store, and the persisted signal/anchor rows must still belong to
    /// the committee (fresh random test keys would zero out every
    /// signer's weight on reopen).
    fn freeze_test_committee() -> (Committee, Vec<AuthorityName>) {
        let (base_committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let names: Vec<AuthorityName> = base_committee.names().copied().collect();
        (base_committee, names)
    }

    fn open_freeze_test_store(
        dir: &Path,
        base_committee: &Committee,
        epoch: u64,
        metrics: Arc<EpochMetrics>,
    ) -> Arc<AuthorityPerEpochStore> {
        let committee = Arc::new(Committee::new(
            epoch,
            base_committee.voting_rights.clone(),
            HashMap::new(),
            HashMap::new(),
            base_committee.quorum_threshold,
            base_committee.validity_threshold,
        ));
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(epoch))
                .unwrap();
        AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
            name: *base_committee.names().next().unwrap(),
            committee,
            parent_path: dir.to_path_buf(),
            db_options: None,
            metrics,
            epoch_start_configuration,
            chain_identifier: ChainIdentifier::default(),
            packages_config: IkaNetworkConfig::new_for_testing(),
        })
        .unwrap()
    }

    fn ready_signal(
        signer: AuthorityName,
        epoch: u64,
        peers: &[AuthorityName],
    ) -> ika_types::validator_metadata::EpochMpcDataReadySignal {
        ika_types::validator_metadata::EpochMpcDataReadySignal {
            authority: signer,
            epoch,
            sequence_number: 0,
            validated_peers: peers.iter().map(|peer| (*peer, [7u8; 32])).collect(),
        }
    }

    /// Drives one consensus commit at `round` through the REAL commit
    /// boundary (where the freeze decision and the batch persistence
    /// live), with `commit_timestamp_ms = round * 1000` so the
    /// first-commit deadline anchor gets a realistic consensus-clock
    /// value.
    async fn drive_freeze_commit(epoch_store: &Arc<AuthorityPerEpochStore>, round: u64) {
        let commit_info = ConsensusCommitInfo::new_for_test(round, round * 1000, true);
        let authority_metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
        let stats = ExecutionIndicesWithStats {
            index: ExecutionIndices {
                last_committed_round: round,
                sub_dag_index: 0,
                transaction_index: 0,
            },
            hash: 0,
            stats: ConsensusStats::default(),
        };
        epoch_store
            .process_consensus_transactions_and_commit_boundary(
                vec![],
                &stats,
                &None::<Arc<DWalletCheckpointService>>,
                &None,
                &commit_info,
                &authority_metrics,
            )
            .await
            .unwrap();
    }

    /// Reads a gauge's current value straight from the Prometheus
    /// registry, so the tests assert what a scrape would actually see.
    fn registry_gauge(registry: &Registry, name: &str) -> i64 {
        registry
            .gather()
            .into_iter()
            .find(|family| family.name() == name)
            .unwrap_or_else(|| panic!("metric {name} not registered"))
            .get_metric()[0]
            .get_gauge()
            .value() as i64
    }

    /// Before ready-signal quorum every round anchor sits at its `-1`
    /// sentinel — round 0 / epoch 0 are valid values, so a 0 default
    /// would be a plausible-but-wrong reading — and the grace gauge
    /// carries the protocol-config value.
    #[tokio::test]
    async fn freeze_metrics_initial_state_before_quorum() {
        let registry = Registry::new();
        let dir = tempfile::tempdir().unwrap();
        let (base_committee, _names) = freeze_test_committee();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));

        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_last_committed_leader_consensus_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_consensus_last_committed_timestamp_seconds"),
            0
        );
        assert_eq!(
            registry_gauge(
                &registry,
                "ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds"
            ),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_grace_rounds"),
            epoch_store.protocol_config().mpc_data_freeze_grace_rounds() as i64
        );
    }

    /// The quorum anchor latches at the first quorum-observing commit and
    /// never slides; the freeze gauge stays `-1` through the grace window
    /// and records the commit round where the freeze fires. The frozen
    /// TABLE is asserted alongside the gauges at every step, pinning the
    /// freeze to exactly the pre-metrics rounds and set — i.e. the metric
    /// wiring provably changed no protocol behavior.
    #[tokio::test]
    async fn freeze_metrics_track_quorum_anchor_grace_and_freeze() {
        let registry = Registry::new();
        let dir = tempfile::tempdir().unwrap();
        let (base_committee, names) = freeze_test_committee();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));
        let grace = epoch_store.protocol_config().mpc_data_freeze_grace_rounds();
        assert!(grace > 1, "test needs a non-trivial grace window");

        // 3 of 4 signers (stake quorum = 3) attesting the same 3 peers:
        // enough stake for quorum, but signals.len() < committee size
        // keeps the full-coverage fast path closed, so the grace path is
        // what's under test.
        let signers: Vec<AuthorityName> = names[..3].to_vec();
        for signer in &signers {
            epoch_store
                .record_epoch_mpc_data_ready_signal(&ready_signal(*signer, 0, &signers))
                .unwrap();
        }

        drive_freeze_commit(&epoch_store, 100).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_last_committed_leader_consensus_round"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_consensus_last_committed_timestamp_seconds"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_consensus_last_committed_timestamp_seconds"),
            100,
            "scraping must not change the last-commit timestamp"
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_signal_stake"),
            3
        );
        assert!(!epoch_store.is_mpc_data_frozen().unwrap());

        // One leader round short of the grace: still counting.
        drive_freeze_commit(&epoch_store, 100 + grace - 1).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            100,
            "the quorum anchor must not slide on later commits"
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_last_committed_leader_consensus_round"),
            (100 + grace - 1) as i64
        );
        assert_eq!(
            registry_gauge(&registry, "ika_consensus_last_committed_timestamp_seconds"),
            (100 + grace - 1) as i64
        );
        assert!(!epoch_store.is_mpc_data_frozen().unwrap());

        // Grace elapsed: the freeze fires at exactly anchor + grace.
        drive_freeze_commit(&epoch_store, 100 + grace).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            (100 + grace) as i64
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_epoch"),
            0
        );
        assert!(epoch_store.is_mpc_data_frozen().unwrap());
        let mut frozen: Vec<AuthorityName> = epoch_store
            .get_frozen_validator_mpc_data_input_set()
            .unwrap()
            .into_keys()
            .collect();
        frozen.sort();
        let mut expected_frozen = signers.clone();
        expected_frozen.sort();
        assert_eq!(
            frozen, expected_frozen,
            "metric wiring must not change WHAT freezes: exactly the attested set"
        );
        assert_eq!(
            epoch_store
                .tables()
                .unwrap()
                .mpc_data_freeze_round
                .get(&0)
                .unwrap(),
            Some(100 + grace),
            "the freeze round must be persisted with the freeze batch"
        );

        // Later commits leave the frozen anchors untouched.
        drive_freeze_commit(&epoch_store, 100 + grace + 5).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            (100 + grace) as i64
        );
    }

    /// With every committee member signaling and no exclusions, the
    /// freeze fires at the SAME commit that anchors the quorum — the
    /// full-coverage fast path, well inside the grace window.
    #[tokio::test]
    async fn freeze_metrics_full_coverage_freezes_before_grace() {
        let registry = Registry::new();
        let dir = tempfile::tempdir().unwrap();
        let (base_committee, names) = freeze_test_committee();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));
        for signer in &names {
            epoch_store
                .record_epoch_mpc_data_ready_signal(&ready_signal(*signer, 0, &names))
                .unwrap();
        }

        drive_freeze_commit(&epoch_store, 200).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            200
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            200,
            "full coverage must freeze without waiting out the grace"
        );
        assert!(epoch_store.is_mpc_data_frozen().unwrap());
    }

    /// Mid-grace restart: reopening the epoch store re-seeds the quorum
    /// anchor, leader round, signal count, and deadline backstop from the
    /// persisted tables (no plausible-but-wrong zeros, no fresh
    /// countdown), keeps the freeze at `-1`, and the reopened store then
    /// freezes at the same anchored round its peers do.
    #[tokio::test]
    async fn freeze_metrics_restored_after_restart_before_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let (base_committee, names) = freeze_test_committee();
        {
            let registry = Registry::new();
            let epoch_store = open_freeze_test_store(
                dir.path(),
                &base_committee,
                0,
                EpochMetrics::new(&registry),
            );
            let signers: Vec<AuthorityName> = names[..3].to_vec();
            for signer in &signers {
                epoch_store
                    .record_epoch_mpc_data_ready_signal(&ready_signal(*signer, 0, &signers))
                    .unwrap();
            }
            drive_freeze_commit(&epoch_store, 100).await;
            epoch_store.release_db_handles();
        }

        // "Restart": a fresh registry + store over the same DB.
        let registry = Registry::new();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_last_committed_leader_consensus_round"),
            100
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_signals"),
            3
        );
        // Deadline backstop restored from the persisted first-commit
        // anchor (commit 100 stamped 100_000 ms by the drive helper).
        let expected_deadline_seconds = ready_signal_deadline_ms(
            Some(100_000),
            epoch_store.epoch_start_state().epoch_duration_ms(),
            None,
        )
        .unwrap()
            / 1000;
        assert_eq!(
            registry_gauge(
                &registry,
                "ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds"
            ),
            expected_deadline_seconds as i64
        );

        // The restarted validator freezes at the same anchored round.
        let grace = epoch_store.protocol_config().mpc_data_freeze_grace_rounds();
        drive_freeze_commit(&epoch_store, 100 + grace).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            (100 + grace) as i64
        );
        assert!(epoch_store.is_mpc_data_frozen().unwrap());
    }

    /// Restart after the freeze: the persisted freeze round re-seeds the
    /// gauge. If the freeze round row is absent (a freeze recorded by a
    /// binary predating its persistence), the gauge stays at `-1` — it is
    /// never invented from the current round — while the frozen set and
    /// freeze-epoch gauge still restore.
    #[tokio::test]
    async fn freeze_metrics_restored_after_restart_after_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let (base_committee, names) = freeze_test_committee();
        {
            let registry = Registry::new();
            let epoch_store = open_freeze_test_store(
                dir.path(),
                &base_committee,
                0,
                EpochMetrics::new(&registry),
            );
            for signer in &names {
                epoch_store
                    .record_epoch_mpc_data_ready_signal(&ready_signal(*signer, 0, &names))
                    .unwrap();
            }
            drive_freeze_commit(&epoch_store, 200).await;
            assert!(epoch_store.is_mpc_data_frozen().unwrap());
            epoch_store.release_db_handles();
        }

        let registry = Registry::new();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            200
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            200
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_epoch"),
            0
        );

        // Simulate a freeze recorded by a pre-persistence binary: the
        // round row is missing while the frozen set is present.
        epoch_store
            .tables()
            .unwrap()
            .mpc_data_freeze_round
            .remove(&0)
            .unwrap();
        epoch_store.release_db_handles();
        drop(epoch_store);
        let registry = Registry::new();
        let epoch_store =
            open_freeze_test_store(dir.path(), &base_committee, 0, EpochMetrics::new(&registry));
        assert!(epoch_store.is_mpc_data_frozen().unwrap());
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1,
            "an unrecoverable freeze round must stay -1, never be invented"
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_epoch"),
            0
        );
    }

    /// `EpochMetrics` is node-lifetime: opening the NEXT epoch's store on
    /// the same metrics instance must reset every freeze-progress gauge
    /// to its start-of-epoch state.
    #[tokio::test]
    async fn freeze_metrics_reset_on_next_epoch() {
        let registry = Registry::new();
        let metrics = EpochMetrics::new(&registry);
        let dir_epoch_zero = tempfile::tempdir().unwrap();
        let (base_committee, names) = freeze_test_committee();
        let epoch_store =
            open_freeze_test_store(dir_epoch_zero.path(), &base_committee, 0, metrics.clone());
        for signer in &names {
            epoch_store
                .record_epoch_mpc_data_ready_signal(&ready_signal(*signer, 0, &names))
                .unwrap();
        }
        drive_freeze_commit(&epoch_store, 200).await;
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            200
        );

        let dir_epoch_one = tempfile::tempdir().unwrap();
        let _next_epoch_store =
            open_freeze_test_store(dir_epoch_one.path(), &base_committee, 1, metrics);
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_quorum_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_freeze_round"),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_last_committed_leader_consensus_round"),
            -1
        );
        assert_eq!(
            registry_gauge(
                &registry,
                "ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds"
            ),
            -1
        );
        assert_eq!(
            registry_gauge(&registry, "ika_dwallet_mpc_data_ready_signals"),
            0
        );
    }

    // ------------------------------------------------------------------
    // Event-sourced epoch: the derived/preserved classification, the wipe
    // it drives, and the determinism of the fold that rebuilds what the
    // wipe removed. Model: dev-docs/specs/event-sourced-epoch.md.
    // ------------------------------------------------------------------

    /// Every per-epoch table has to be classified, or a restart either
    /// silently keeps state the replay will produce a second copy of, or
    /// silently drops state nothing will rebuild.
    ///
    /// The comparison is against the column families `DBMapUtils` generated
    /// from the struct — not a second hand-maintained list — so adding a field
    /// to `AuthorityEpochTables` without classifying it fails here.
    #[test]
    fn every_epoch_table_is_classified() {
        let declared: BTreeSet<&str> = EPOCH_STATE_REGISTRY
            .iter()
            .map(|entry| entry.field)
            .collect();
        let actual: BTreeSet<String> = AuthorityEpochTables::describe_tables()
            .into_keys()
            .collect();
        let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();

        let unclassified: Vec<_> = actual.difference(&declared).copied().collect();
        assert!(
            unclassified.is_empty(),
            "per-epoch tables with no derived/preserved classification: {unclassified:?} — add \
             them to the `epoch_state_registry!` invocation and to \
             dev-docs/derived-epoch-state-audit.md",
        );
        let stale: Vec<_> = declared.difference(&actual).copied().collect();
        assert!(
            stale.is_empty(),
            "classified tables that no longer exist: {stale:?}",
        );
    }

    #[test]
    fn epoch_state_registry_names_each_table_once() {
        let mut seen = BTreeSet::new();
        for entry in EPOCH_STATE_REGISTRY {
            assert!(
                seen.insert(entry.field),
                "`{}` is classified twice; the two arms could disagree",
                entry.field,
            );
            assert!(
                !entry.reason.is_empty(),
                "`{}` has no classification reason",
                entry.field,
            );
        }
    }

    /// A committee-member name plus the store it will fold commits into.
    ///
    /// `wipe_derived_state` picks between the two constructors so a test can
    /// stage a first run without the wipe and then reopen the way a validator
    /// boots.
    fn derived_state_test_store(
        dir: &Path,
        wipe_derived_state: bool,
    ) -> (Arc<AuthorityPerEpochStore>, AuthorityName) {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let committee = Arc::new(committee);
        let name = *committee.names().next().unwrap();
        let metrics = EpochMetrics::new(&Registry::new());
        let epoch_start_configuration =
            EpochStartConfiguration::new(EpochStartSystem::new_for_testing_with_epoch(0)).unwrap();
        let epoch_store = if wipe_derived_state {
            AuthorityPerEpochStore::new(EpochStoreParams {
                name,
                committee,
                parent_path: dir.to_path_buf(),
                db_options: None,
                metrics,
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
        } else {
            AuthorityPerEpochStore::new_retaining_derived_state_for_testing(EpochStoreParams {
                name,
                committee,
                parent_path: dir.to_path_buf(),
                db_options: None,
                metrics,
                epoch_start_configuration,
                chain_identifier: ChainIdentifier::default(),
                packages_config: IkaNetworkConfig::new_for_testing(),
            })
        }
        .unwrap();
        (epoch_store, name)
    }

    /// Drives `rounds` synthetic consensus commits through the real commit
    /// boundary. The content is fixed, not sampled, so the same call folds the
    /// same sequence every time — which is what makes the double-fold
    /// comparison meaningful.
    async fn fold_test_commits(
        epoch_store: &Arc<AuthorityPerEpochStore>,
        author: AuthorityName,
        rounds: u64,
    ) {
        let metrics = Arc::new(AuthorityMetrics::new(&Registry::new()));
        for round in 1..=rounds {
            let session_identifier = SessionIdentifier::new(SessionType::User, [round as u8; 32]);
            let transactions = vec![
                // Still writes a table: the protocol-upgrade vote tally.
                // Kept in the fixture because the MPC kinds below no longer
                // land in the epoch store at all — they go to the drain over
                // the round channel — and without a table-writing kind the
                // breadth checks in these tests would go vacuous.
                ConsensusTransaction::new_capability_notification_v1(AuthorityCapabilitiesV1 {
                    authority: author,
                    // Built by hand rather than through `new`, which stamps
                    // the generation from the wall clock: two folds of "the
                    // same" commit would then carry different transactions
                    // and the determinism comparison would fail on the
                    // fixture rather than on the system. (It did, the first
                    // time — which is the check working.)
                    generation: 7,
                    supported_protocol_versions:
                        SupportedProtocolVersionsWithHashes::from_supported_versions(
                            SupportedProtocolVersions {
                                min: ProtocolVersion::MIN,
                                max: ProtocolVersion::MAX,
                            },
                            Chain::Unknown,
                        ),
                    move_contracts_to_upgrade: Vec::new(),
                }),
                ConsensusTransaction::new_dwallet_mpc_message(
                    author,
                    session_identifier,
                    vec![round as u8; 8],
                ),
                ConsensusTransaction::new_dwallet_mpc_output(
                    author,
                    session_identifier,
                    Vec::new(),
                    Vec::new(),
                ),
                ConsensusTransaction::new_idle_status_update(IdleStatusUpdate {
                    authority: author,
                    nonce: [round as u8; 32],
                    is_idle: round % 2 == 0,
                }),
            ];
            let transactions = transactions
                .into_iter()
                .map(|transaction| {
                    VerifiedSequencedConsensusTransaction(SequencedConsensusTransaction {
                        certificate_author_index: 0,
                        certificate_author: author,
                        consensus_index: ExecutionIndices {
                            last_committed_round: round,
                            sub_dag_index: round,
                            transaction_index: 0,
                        },
                        transaction: SequencedConsensusTransactionKind::External(transaction),
                    })
                })
                .collect();
            let consensus_stats = ExecutionIndicesWithStats {
                index: ExecutionIndices {
                    last_committed_round: round,
                    sub_dag_index: round,
                    transaction_index: 0,
                },
                hash: 0,
                stats: ConsensusStats::new(4),
            };
            epoch_store
                .process_consensus_transactions_and_commit_boundary(
                    transactions,
                    &consensus_stats,
                    &None::<Arc<DWalletCheckpointService>>,
                    &None,
                    &ConsensusCommitInfo::new_for_test(round, 1_000 + round, true),
                    &metrics,
                )
                .await
                .unwrap();
        }
    }

    /// The serialized contents of every classified table, keyed by name.
    fn classified_table_snapshot(tables: &AuthorityEpochTables) -> EpochStateSnapshot {
        EPOCH_STATE_REGISTRY
            .iter()
            .map(|entry| (entry.field, tables.classified_table_rows(entry.field)))
            .collect()
    }

    /// Whether a table is derived is not a matter of opinion: if the consensus
    /// fold writes it, the replay writes it again, and it MUST be wiped first.
    ///
    /// This is the check that catches a misclassification, because it takes the
    /// truth from behaviour — which tables the real commit boundary actually
    /// wrote — and compares it against the declaration, rather than asserting
    /// the declaration against itself. Leaving a fold-written table preserved
    /// is not harmless even though the replay overwrites most of its rows: the
    /// rows the replay does NOT reach survive. A restart whose consensus store
    /// lost its tail (ika #2057) would keep the per-round rows for commits the
    /// store no longer has, and the MPC drain would replay rounds no commit
    /// backs.
    #[tokio::test]
    async fn every_table_the_consensus_fold_writes_is_classified_derived() {
        let dir = tempfile::tempdir().unwrap();
        let (epoch_store, author) =
            derived_state_test_store(dir.path(), /* wipe_derived_state */ false);
        let tables = epoch_store.tables().unwrap();

        let before = classified_table_snapshot(&tables);
        assert!(
            before.values().all(Vec::is_empty),
            "a freshly opened epoch store must hold no rows",
        );

        fold_test_commits(&epoch_store, author, 4).await;
        let after = classified_table_snapshot(&tables);

        let written: Vec<&'static str> = EPOCH_STATE_REGISTRY
            .iter()
            .map(|entry| entry.field)
            .filter(|field| !after[field].is_empty())
            .collect();
        // Five, not the eight this asserted before the round channel landed:
        // the eight projection tables are gone, so a commit's MPC content
        // reaches the drain over the channel and writes nothing here. What is
        // left still spans four different kinds of write — the processed-marker
        // set, the running stats, a fold output, a vote tally and the epoch
        // clock anchor — which is what keeps the check meaningful. If it drops
        // further, add a table-writing transaction kind to the fixture rather
        // than lowering this.
        assert!(
            written.len() >= 5,
            "the commit boundary wrote only {} tables ({written:?}); this check would be \
             near-vacuous",
            written.len(),
        );

        let misclassified: Vec<&'static str> = EPOCH_STATE_REGISTRY
            .iter()
            .filter(|entry| {
                entry.class == EpochStateClass::Preserved && written.contains(&entry.field)
            })
            .map(|entry| entry.field)
            .collect();
        assert!(
            misclassified.is_empty(),
            "these tables are written by the consensus fold but classified preserved: \
             {misclassified:?} — the boot replay rewrites them, so rows it does not reach \
             survive from a run whose commits may no longer exist",
        );
    }

    /// The wipe must empty every derived table and leave every preserved one
    /// exactly as it was. Getting either direction wrong is silent: a derived
    /// table that survives is double-applied by the replay, a preserved one
    /// that is wiped is simply gone.
    #[tokio::test]
    async fn wipe_empties_every_derived_table_and_preserves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (epoch_store, author) =
            derived_state_test_store(dir.path(), /* wipe_derived_state */ false);
        fold_test_commits(&epoch_store, author, 6).await;

        // Two preserved tables, populated the way production populates them:
        // a retired presign and this validator's own secret presign share.
        let tables = epoch_store.tables().unwrap();
        let presign_session = SessionIdentifier::new(SessionType::InternalPresign, [9; 32]);
        tables.mark_presign_as_used(presign_session, 0).unwrap();
        tables
            .store_presign_private_output(CommitmentSizedNumber::from(7u64), 0, vec![1, 2, 3])
            .unwrap();

        let before = classified_table_snapshot(&tables);
        let populated_derived = EPOCH_STATE_REGISTRY
            .iter()
            .filter(|entry| {
                entry.class == EpochStateClass::Derived && !before[entry.field].is_empty()
            })
            .count();
        // Guards against the whole assertion below passing because the fold
        // wrote nothing at all.
        assert!(
            populated_derived >= 5,
            "the fold populated only {populated_derived} derived tables; the wipe assertion \
             would be near-vacuous",
        );

        tables.wipe_derived_state().unwrap();
        let after = classified_table_snapshot(&tables);

        for entry in EPOCH_STATE_REGISTRY {
            match entry.class {
                EpochStateClass::Derived => assert!(
                    after[entry.field].is_empty(),
                    "derived table `{}` survived the wipe ({} rows); the replay would fold onto it",
                    entry.field,
                    after[entry.field].len(),
                ),
                EpochStateClass::Preserved => assert_eq!(
                    after[entry.field], before[entry.field],
                    "preserved table `{}` lost rows to the wipe; nothing rebuilds it",
                    entry.field,
                ),
            }
        }
        assert!(
            !after["used_presigns"].is_empty() && !after["presign_private_outputs"].is_empty(),
            "the preserved side of the check was vacuous — neither preserved table held a row",
        );
        assert!(tables.non_empty_derived_tables().is_empty());
    }

    /// The property the whole design rests on: derived state is a function of
    /// the commit sequence and nothing else. Fold a sequence, restart onto the
    /// same directory (which wipes), fold the identical sequence again — every
    /// derived table must come back with the identical contents, and the
    /// preserved ones must be untouched.
    ///
    /// Iterating the classification registry rather than a hand-picked list is
    /// what makes this the audit's enforcement: a new table classified derived
    /// that is not in fact re-derivable shows up here as a difference.
    ///
    /// The shape is consensus-core's own
    /// `leader_schedule_v3::test_recovery_replay_produces_same_state_as_live`
    /// — build state live, rebuild it from the store, require every observable
    /// projection equal — applied to the whole per-epoch store instead of one
    /// component's schedule.
    #[tokio::test]
    async fn folding_the_same_commits_twice_rebuilds_identical_derived_state() {
        const ROUNDS: u64 = 6;
        let dir = tempfile::tempdir().unwrap();

        let (epoch_store, author) =
            derived_state_test_store(dir.path(), /* wipe_derived_state */ false);
        fold_test_commits(&epoch_store, author, ROUNDS).await;
        let tables = epoch_store.tables().unwrap();
        let preserved_marker = SessionIdentifier::new(SessionType::InternalPresign, [5; 32]);
        tables.mark_presign_as_used(preserved_marker, 3).unwrap();

        let first_fold = classified_table_snapshot(&tables);
        let non_empty_first = EPOCH_STATE_REGISTRY
            .iter()
            .filter(|entry| {
                entry.class == EpochStateClass::Derived && !first_fold[entry.field].is_empty()
            })
            .count();
        assert!(
            non_empty_first >= 5,
            "only {non_empty_first} derived tables held rows after the first fold; the \
             comparison below would be near-vacuous",
        );
        drop(tables);
        drop(epoch_store);

        // The restart: reopening with the rebuild policy is exactly what a
        // validator does at boot, wipe included.
        let (epoch_store, author_again) =
            derived_state_test_store(dir.path(), /* wipe_derived_state */ true);
        assert_eq!(author, author_again, "the test committee must be stable");
        let tables = epoch_store.tables().unwrap();
        assert!(
            tables.non_empty_derived_tables().is_empty(),
            "the reopen did not wipe; the second fold would be folding onto the first's output",
        );
        assert!(
            tables.is_presign_used(preserved_marker, 3).unwrap(),
            "the reopen wiped a preserved table",
        );

        fold_test_commits(&epoch_store, author, ROUNDS).await;
        let second_fold = classified_table_snapshot(&tables);

        // Compared over EVERY classified table, not just the derived ones.
        // That is what makes this the audit's enforcement in both directions:
        // a table wrongly called preserved accumulates a second copy here, and
        // a table wrongly called derived comes back empty.
        for entry in EPOCH_STATE_REGISTRY {
            assert_eq!(
                second_fold[entry.field], first_fold[entry.field],
                "`{}` (classified {}) did not come back identical after a wipe-and-replay of \
                 the same commits",
                entry.field, entry.class,
            );
        }
    }
}
