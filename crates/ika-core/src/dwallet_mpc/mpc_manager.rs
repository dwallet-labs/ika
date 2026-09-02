// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::SuiDataReceivers;
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStoreTrait;
use crate::dwallet_mpc::catchup_gate::{
    CATCH_UP_ENTER_GAP_ROUNDS, CATCH_UP_EXIT_GAP_ROUNDS, CatchUpGate, CatchUpTransition,
    computation_suppressible_during_catch_up,
};
use crate::dwallet_mpc::crytographic_computation::{
    ComputationId, ComputationRequest, CryptographicComputationsOrchestrator,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::{
    AGE_BUCKET_OVERFLOW, AGE_BUCKETS, ALL_SESSION_STATES, ALL_SESSION_TYPES, DWalletMPCMetrics,
    KEY_ROLE_NETWORK_OWNED_ADDRESS_SIGNING, KEY_ROLE_OTHER, READY_RESULT_ERR,
    READY_RESULT_NOT_READY, READY_RESULT_READY, SESSION_STATE_ACTIVE, SESSION_STATE_COMPLETED,
    SESSION_STATE_COMPUTATION_COMPLETED, SESSION_STATE_FAILED, SESSION_STATE_WAITING_FOR_REQUEST,
    optional_session_type_label, session_type_label,
};
use crate::dwallet_mpc::mpc_diagnostics::{
    LocalAuthorityMaliciousReason, MPC_ANOMALY_SCHEMA_VERSION, MpcAnomalyContext, MpcAnomalyKind,
    OutputReportDiagnostic, OutputVoteDiagnostics, OutputVoteGroupDiagnostic, SessionOrigin,
    mpc_error_diagnostic, network_key_reconfiguration_raw_output_digest,
    persist_malicious_diagnostic_file,
};
use crate::dwallet_mpc::mpc_session::{
    AddMessageResult, AddOutputResult, DWalletMPCSessionOutput, DWalletSession, PublicInput,
    SessionComputationType, SessionStatus, TerminalStatus, session_input_from_request,
};
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, ValidatorPrivateDecryptionKeyData};
use crate::dwallet_mpc::network_dkg::{
    spawn_network_encryption_key_public_data_instantiation, spawn_network_key_id_registration,
};
use crate::dwallet_mpc::{
    ValidatorMpcKeysByPartyId, authority_name_to_party_id_from_committee,
    generate_access_structure_from_committee, get_validator_mpc_keys_by_party_id,
    party_id_to_authority_name,
};
use crate::dwallet_session_request::{DWalletSessionRequest, DWalletSessionRequestMetricData};
use crate::network_key_id_mapping::network_key_id_for;
use crate::validator_metadata::{OffChainMpcDataAssembly, assemble_committee_mpc_data_off_chain};
use arc_swap::ArcSwap;
use dwallet_classgroups_types::ValidatorMPCSecrets;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm, MPCPrivateInput,
    NetworkEncryptionKeyPublicData, NetworkKeyId, VersionedPresignOutput,
};
use dwallet_mpc_types::mpc_protocol_configuration::network_presign_pool_algorithms;
use dwallet_rng::RootSeed;
use fastcrypto::hash::HashFunction;
use group::PartyID;
use hex;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::{AuthorityName, DefaultHash};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::handoff::HandoffItemKey;
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::messages_dwallet_mpc::{
    ConsensusGlobalPresignRequest, ConsensusNOAObservation, Curve25519EdDSAProtocol,
    Curve25519EdDSAVSSProtocol, DWalletInternalMPCOutputKind, DWalletMPCMessage,
    DWalletMPCOutputKind, DWalletMPCOutputReport, DWalletNetworkEncryptionKeyData,
    GlobalPresignRequest, IdleStatusUpdate, RistrettoSchnorrkelProtocol,
    RistrettoSchnorrkelVSSProtocol, Secp256k1ECDSAProtocol, Secp256k1TaprootProtocol,
    Secp256k1TaprootVSSProtocol, Secp256r1ECDSAProtocol, SessionIdentifier, SessionType,
    SuiChainObservationUpdate,
};
use ika_types::noa_checkpoint::CounterpartyChainKind;
use mpc::{MajorityVote, WeightedThresholdAccessStructure};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sui_types::base_types::{ConciseableName, ObjectID};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

use ika_types::noa_checkpoint::{
    CounterpartyChain, NOACheckpointTxObservation, NOACheckpointTxRef, SuiChainContext,
    SuiChainObservation, SuiCounterpartyChain,
};

use crate::dwallet_mpc::NetworkOwnedAddressSignOutput;
use crate::request_protocol_data::NETWORK_KEY_RECONFIGURATION_PROTOCOL_NAME;

/// Protocols whose per-authority output observations are exported as
/// `ika_dwallet_mpc_session_output_*` metrics. Restricted deliberately: those
/// series are labeled by session id and authority, so exporting every protocol
/// would add one series per sign/presign session on production validators.
/// Extend this only when a compatibility scenario actually scrapes another
/// protocol's per-authority outputs.
const OUTPUT_OBSERVATION_EXPORT_PROTOCOLS: &[&str] = &[NETWORK_KEY_RECONFIGURATION_PROTOCOL_NAME];

const TERMINAL_MESSAGE_LOG_INTERVAL: Duration = Duration::from_secs(60);
const COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD: u64 = 100;

#[derive(Debug, Eq, PartialEq)]
enum TerminalMessageLogAction {
    None,
    Warn { completed: u64, failed: u64 },
    Recovered { completed: u64, failed: u64 },
}

/// Fixed-size aggregation for messages that arrive after a session becomes
/// terminal. No identifier is retained: Prometheus carries the bounded
/// status/type breakdown, while logs report only aggregate transitions.
struct TerminalMessageLogState {
    window_started: Instant,
    last_event: Option<Instant>,
    completed: u64,
    failed: u64,
    warning_active: bool,
    last_warning: Option<Instant>,
    last_failed_warning: Option<Instant>,
    recovery_eligible: bool,
    active_completed: u64,
    active_failed: u64,
}

impl TerminalMessageLogState {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            last_event: None,
            completed: 0,
            failed: 0,
            warning_active: false,
            last_warning: None,
            last_failed_warning: None,
            recovery_eligible: false,
            active_completed: 0,
            active_failed: 0,
        }
    }

    fn record(
        &mut self,
        now: Instant,
        terminal_status: TerminalStatus,
    ) -> TerminalMessageLogAction {
        if now.duration_since(self.window_started) >= TERMINAL_MESSAGE_LOG_INTERVAL {
            self.window_started = now;
            self.completed = 0;
            self.failed = 0;
        }
        self.last_event = Some(now);
        match terminal_status {
            TerminalStatus::Completed => self.completed += 1,
            TerminalStatus::Failed => self.failed += 1,
        }
        self.active_completed += u64::from(terminal_status == TerminalStatus::Completed);
        self.active_failed += u64::from(terminal_status == TerminalStatus::Failed);
        self.recovery_eligible |= self.active_completed + self.active_failed > 1;

        let interval_elapsed = self
            .last_warning
            .is_none_or(|last| now.duration_since(last) >= TERMINAL_MESSAGE_LOG_INTERVAL);
        let failed_interval_elapsed = self
            .last_failed_warning
            .is_none_or(|last| now.duration_since(last) >= TERMINAL_MESSAGE_LOG_INTERVAL);
        // A completed-volume warning must never delay the first failed-session
        // warning, while repeated failed arrivals still share their own limit.
        let warning_due = match terminal_status {
            TerminalStatus::Completed => {
                self.completed >= COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD && interval_elapsed
            }
            TerminalStatus::Failed => failed_interval_elapsed,
        };
        if warning_due {
            self.warning_active = true;
            self.last_warning = Some(now);
            if terminal_status == TerminalStatus::Failed {
                self.last_failed_warning = Some(now);
            }
            TerminalMessageLogAction::Warn {
                completed: self.completed,
                failed: self.failed,
            }
        } else {
            TerminalMessageLogAction::None
        }
    }

    fn check_recovery(&mut self, now: Instant) -> TerminalMessageLogAction {
        let quiet = self
            .last_event
            .is_some_and(|last| now.duration_since(last) >= TERMINAL_MESSAGE_LOG_INTERVAL);
        if !quiet {
            return TerminalMessageLogAction::None;
        }
        let action = if self.warning_active && self.recovery_eligible {
            TerminalMessageLogAction::Recovered {
                completed: self.active_completed,
                failed: self.active_failed,
            }
        } else {
            TerminalMessageLogAction::None
        };
        self.warning_active = false;
        self.last_warning = None;
        self.last_failed_warning = None;
        self.recovery_eligible = false;
        self.active_completed = 0;
        self.active_failed = 0;
        self.completed = 0;
        self.failed = 0;
        self.window_started = now;
        self.last_event = None;
        action
    }
}

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
        // The agreement recomputes every consensus round per chain; at info
        // this line alone was ~9K lines/min (half the log) on a localnet.
        debug!(
            consensus_round,
            chain = %C::KIND,
            "Chain context agreed upon"
        );
        *current_context = Some(context);
    }
}

/// An internal presign session that was BUILT (its session identifier is
/// fixed) but whose MPC input could not be constructed yet because the target
/// network key's data is not locally available — typically a VSS pool at
/// epoch entry before the consensus-frozen off-chain validator key set is
/// ingested, or a key installed on peers but not here. The sequence number
/// was already consumed at instantiation, so identifier derivation and the
/// batch counters stay committee-uniform; parking defers only this
/// validator's participation. Retried once per service iteration.
///
/// (There is no "identity not derivable" variant: instantiation resolves the
/// key's content-derived `NetworkKeyId` FIRST — an adopted key always has one
/// — and keys the per-pool sequence counter by it, so the identifier is
/// always buildable at instantiation time.)
#[derive(Debug, Clone)]
pub(crate) struct ParkedInternalPresignRequest(pub(crate) Box<DWalletSessionRequest>);

/// The [`DWalletMPCManager`] manages MPC sessions:
/// — Keeping track of all MPC sessions,
/// — Executing all active sessions, and
/// — (De)activating sessions.
///
/// Outcome of one attempt to source the CURRENT epoch's validator MPC keys
/// from the prior epoch's handoff certificate
/// (`DWalletMPCManager::try_ingest_current_epoch_keys_from_prior_handoff_cert`).
enum PriorCertKeysOutcome {
    /// Keys assembled and ingested; `current_epoch_keys_ingested` is set.
    Ingested,
    /// The prior epoch has no handoff certificate (or none observable yet):
    /// genesis, a pre-v4 prior epoch, a cert without mpc_data items, or a
    /// cold start whose bootstrap fetch hasn't landed the cert. The caller
    /// may consult the freeze-gated `current_epoch_mpc_keys` channel this
    /// iteration; the cert path re-runs next iteration regardless.
    NoPriorCert,
    /// Transient miss with the cert PRESENT (store read error, perpetual
    /// handle not installed, blobs still propagating). Retry next service
    /// iteration WITHOUT falling back to the channel — see the divergence
    /// note at the call site. The repair action behind the retry is the
    /// peer-blob fetcher's prior-cert pass
    /// (`fetch_missing_prior_cert_mpc_data_blobs`), which fetches missing
    /// cert-pinned blobs from committee peers into the perpetual store —
    /// without it a store that never held a long-dark member's blob would
    /// retry forever (issue #1881).
    RetryLater,
}

/// How a completed internal-presign output's network key resolves for the
/// per-pool counter bookkeeping — see
/// [`DWalletMPCManager::classify_internal_presign_completion`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InternalPresignCompletionKey {
    /// The key resolves to its content-derived id; the counter may advance.
    Resolved(NetworkKeyId),
    /// The key is adopted but does not resolve — a should-never-happen
    /// (adoption defers an unmapped key).
    AdoptedUnresolvable,
    /// The key is not adopted on this process yet: the ordinary
    /// pre-adoption consensus replay after a restart.
    NotAdopted,
}

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
    /// Latches `local_mpc_data_ready_for_frozen_set` once it first returns true.
    /// The frozen mpc_data input set is epoch-fixed and the manager is per-epoch,
    /// so once every frozen-set blob is present + valid it stays so — caching the
    /// result drops a per-tick N RocksDB reads + 2N class-groups BCS decodes (paid
    /// for every DKG/reconfiguration session on the 20ms service loop) to a single
    /// atomic load after convergence.
    local_mpc_data_ready_latched: AtomicBool,
    validator_name: AuthorityName,
    pub(crate) committee: Arc<Committee>,
    pub(crate) access_structure: WeightedThresholdAccessStructure,
    /// The CURRENT epoch's per-validator MPC keys (class groups + 3 PVSS HPKE +
    /// verified VSS), keyed by party id. It starts empty at construction and
    /// the whole set (class_groups
    /// included) is filled by `ingest_offchain_mpc_keys`: primarily assembled
    /// from the prior epoch's handoff certificate (restart-safe — issue
    /// #1879), falling back to the `current_epoch_mpc_keys` channel (fed once
    /// the consensus freeze decides the agreed set) only in the chain-true
    /// no-cert epochs. That agreed set may legitimately omit
    /// offline/withholding validators — the DKG deals only to the parties
    /// that have keys. Passed to `session_input_from_request` per
    /// session-input construction.
    pub(crate) validator_mpc_keys_by_party_id: ValidatorMpcKeysByPartyId,
    /// Set once the current epoch's off-chain key set has been ingested (the
    /// consensus-frozen agreed set). Gates session initiation so the DKG never
    /// runs before the agreed keys are in, and makes the ingest run exactly once.
    pub(crate) current_epoch_keys_ingested: bool,
    /// The NEXT epoch's per-validator MPC keys, ingested from the
    /// `next_epoch_mpc_keys` channel. Consumed by network reconfiguration (the
    /// dealers encrypt under the upcoming parties' PVSS keys). `None` until the
    /// next-epoch agreed set is delivered.
    pub(crate) next_epoch_validator_mpc_keys: Option<ValidatorMpcKeysByPartyId>,
    pub(crate) cryptographic_computations_orchestrator: CryptographicComputationsOrchestrator,

    /// Catch-up gate (issue #2023): while the MPC processing cursor trails
    /// the consensus tip beyond the trap radius, new cryptographic
    /// computations for internal-presign and user sessions are withheld so
    /// the round backlog drains at replay speed instead of being pinned
    /// below tip rate by dead-on-arrival crypto. Fed once per service
    /// iteration by [`Self::observe_consensus_round_gap`], consulted at the
    /// spawn decision in [`Self::perform_cryptographic_computation`].
    catchup_gate: CatchUpGate,

    /// The set of malicious actors that were agreed upon by a quorum of validators.
    /// This agreement is done synchronically, and thus is it safe to filter malicious actors.
    /// Any message/output from these authorities will be ignored.
    /// This list is maintained during the Epoch.
    /// This happens automatically because the [`DWalletMPCManager`]
    /// is part of the [`AuthorityPerEpochStore`].
    malicious_actors: HashSet<AuthorityName>,

    pub(crate) last_session_to_complete_in_current_epoch: u64,
    pub(crate) recognized_self_as_malicious: bool,
    recognized_self_as_malicious_session: Option<SessionIdentifier>,

    /// Directory for persisting self-malicious diagnostic snapshots (see
    /// [`persist_malicious_diagnostic_file`]). Set by the service at
    /// construction (`<db_path>/mpc_diagnostics`); `None` — persistence off —
    /// in tests that don't wire it.
    diagnostics_dir: Option<std::path::PathBuf>,
    pub(crate) network_keys: Box<DwalletMPCNetworkKeys>,
    /// Requests parked until their network key's PUBLIC DATA is locally
    /// available. Drained LEVEL-triggered on every
    /// `handle_mpc_request_batch` (any parked key whose data now exists),
    /// never edge-triggered on the consensus instantiation path — the key
    /// can also materialize via the cert-less chain-copy adoption on a
    /// fresh boot, which emits no such edge; an edge-only drain stranded a
    /// reshare in flight across a restart forever and wedged the epoch
    /// (issue #1834).
    pub(crate) requests_pending_for_network_key: HashMap<ObjectID, Vec<DWalletSessionRequest>>,
    pub(crate) requests_pending_for_next_active_committee: Vec<DWalletSessionRequest>,

    /// Network DKG / reconfig requests that arrived before the
    /// off-chain freeze gate was satisfied. Drained on every
    /// `handle_mpc_request_batch` by re-running each through
    /// `handle_mpc_request`; once the per-epoch freeze (and
    /// per-key DKG quorum, for DKG requests) is in place, they
    /// pass the gate and run normally.
    pub(crate) requests_pending_for_frozen_mpc_data: Vec<DWalletSessionRequest>,

    /// Internal presign requests deferred because the target network key's
    /// data is not locally available yet (see
    /// [`ParkedInternalPresignRequest`] for the two deferral shapes). The
    /// session sequence number was already consumed at instantiation —
    /// identifier derivation stays committee-uniform — and only this
    /// validator's participation is deferred: entries are retried once per
    /// service iteration and activated when the key data lands.
    /// Genuinely-fatal input errors never land here (they fail the session
    /// terminally at instantiation).
    pub(crate) internal_presign_requests_pending_for_network_key_data:
        Vec<ParkedInternalPresignRequest>,
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

    /// Tracks which parties have announced each presign request, keyed by the
    /// full request body: the body is what gets served and checkpointed, so it
    /// is what has to reach quorum. When a body reaches majority its sequence
    /// number moves to `completed_presign_sequence_numbers` and any other body
    /// recorded for that sequence number is dropped.
    presign_request_votes: HashMap<GlobalPresignRequest, HashSet<PartyID>>,

    /// Sequence numbers of presign requests that have reached majority vote.
    /// Once completed, we don't record new votes for these requests.
    completed_presign_sequence_numbers: HashSet<u64>,

    /// dWallets that already have an agreed, non-rejected response making their
    /// user secret key share public in this epoch.
    ///
    /// Keyed by the raw id bytes carried in the message, so no fallible parse
    /// is needed. In-memory and per-epoch, like
    /// `completed_presign_sequence_numbers`: the MPC service replays the
    /// epoch's consensus rounds from the first one on startup, so a restart
    /// rebuilds this from the same agreed outputs in the same order.
    made_public_dwallets: HashSet<Vec<u8>>,

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

    /// Last time the prior-cert current-epoch key ingestion warned about
    /// a retryable miss (cert read error, missing perpetual handle, or
    /// missing/undecodable mpc_data blobs). Same 20ms-loop rationale as
    /// `last_cert_read_warn`: warn at most every 10s, debug in between;
    /// the retry itself is unthrottled.
    last_prior_cert_keys_warn: Option<Instant>,

    /// `(key_id, local output digest)` pairs whose contradiction with the
    /// prior epoch's handoff cert was already warned about. The adoption
    /// pass re-runs whenever the overlay `Arc` republishes (every ~5s
    /// during incomplete-overlay convergence), so an unchanged mismatch
    /// would re-warn per republish; warn once per distinct local digest,
    /// debug thereafter.
    warned_cert_digest_mismatches: HashSet<(ObjectID, [u8; 32])>,

    /// Keys already reported as carrying an internal-presign completion
    /// while not yet adopted here. Consensus replays a burst of such
    /// completions after a restart, so the report is deduped to once per
    /// key (debug thereafter): a skip may be correct, but a *silent* skip
    /// never is — if a key is never adopted (its background `NetworkKeyId`
    /// derivation failed, or its overlay entry carries no DKG output), the
    /// top-up loop never runs for it and that key's presign pool starves
    /// for the epoch, and this is the recurring evidence of it.
    reported_unadopted_internal_presign_completions: HashSet<ObjectID>,

    /// Keys whose background `NetworkKeyId` derivation has been spawned by
    /// the adoption pass, memoized by the digest of the exact derivation
    /// inputs (DKG output + current reconfiguration output). The expensive
    /// class-groups derive runs at most once per key per distinct input set:
    /// a deterministic failure on unchanged inputs is not retried (no rayon
    /// hammering), but a NEW reconfiguration output (the overlay republishes
    /// during convergence) changes the digest and re-derives — so a
    /// transient-input failure self-heals. A successful derivation registers
    /// in the process-global mapping, short-circuiting before this gate.
    pub(crate) network_key_id_derivations_spawned: HashMap<ObjectID, [u8; 32]>,

    /// Network keys stranded by a mid-epoch restart, shared by `Arc` with the
    /// sui-connector network-keys sync task. The adoption pass inserts a key
    /// when its produced-this-epoch guard skips the overlay while this
    /// validator holds NOTHING for the key (not instantiated, no instantiation
    /// in flight, nothing adopted) — the restart strand, where the off-chain
    /// overlay serves only the next committee's output and nothing re-delivers
    /// an instantiable one. The syncer chain-reads ONLY flagged keys (serving
    /// the canonical current-epoch output); a confirmed instantiation removes
    /// the key, returning it to the off-chain read path. Empty in every
    /// healthy flow, which preserves the v4 no-steady-state-chain-read
    /// invariant (see `sync_dwallet_network_keys`).
    pub(crate) stranded_network_keys: Arc<ArcSwap<HashSet<ObjectID>>>,

    /// Sessions whose protocol-cryptographic-data generation already
    /// failed and was logged. The generation re-runs every 20ms service
    /// iteration, so a stuck session would otherwise emit ~50 identical
    /// errors/second; log once per session (the skip-and-retry behavior
    /// itself is unthrottled).
    warned_cryptographic_data_generation_failures: HashSet<SessionIdentifier>,
    terminal_message_log_state: TerminalMessageLogState,

    /// Deduplicates anomalies that arrive before a session can be constructed
    /// (for example a malformed first output). Capped to avoid attacker-chosen
    /// session identifiers growing memory without bound.
    untracked_anomalies: HashSet<(SessionIdentifier, MpcAnomalyKind)>,

    // The sequence number of the next internal presign session.
    // Starts from 1 in every epoch, and increases as they are spawned.
    // Different epochs will see repeating values of this variable,
    // but that is safe as they are synced within an epoch and
    // the session identifier is derived from the epoch as well.
    /// Next internal-presign session sequence number, PER
    /// (`NetworkKeyId`, curve, signature_algorithm) pool. Keyed by the key's
    /// content-derived `NetworkKeyId` — the SAME identity bound into the
    /// session identifier — so the counter and the identifier can never use
    /// divergent key axes. A single shared counter would let one pool's
    /// stream depend on another's instantiation timing: a key adopted at a
    /// different consensus round on different validators (adoption is
    /// cert-gated and not round-uniform) would shift every other pool's
    /// sequence numbers, so the session identifiers — bound to the sequence
    /// number — diverge and never reach quorum. Per-pool counters make each
    /// pool's ordinal stream start-time-invariant: a late-adopted key simply
    /// starts fresh at 1 whenever it starts, identically on every validator —
    /// PROVIDED the start skew stays under one batch lifecycle. A validator
    /// entering a pool only after a full batch quorum-completed elsewhere
    /// (mid-epoch restart, very late install) would otherwise be permanently
    /// ordinal-offset for that pool (#1952, #1830): the counter is in-memory,
    /// so it is seeded on first touch from the persisted
    /// `filled_presign_pool_slots` high-water and the consensus completion
    /// frontier (`highest_completed_internal_presign_ordinal`), the same
    /// frontier fast-forwards it whenever it falls inside already-completed
    /// history, and the mint path fast-forwards across ordinals whose
    /// sessions are already terminal — see
    /// `observe_completed_internal_presign_ordinal` and
    /// `instantiate_internal_presign_session`.
    pub(crate) next_internal_presign_sequence_number:
        HashMap<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// Highest internal-presign ordinal the CONSENSUS STREAM has shown
    /// completed for a pool — the committee's live-window frontier, per
    /// (network key, curve, signature algorithm).
    ///
    /// Taken from the `session_sequence_number` that every completed
    /// internal-presign output carries, so it is consensus-anchored data every
    /// validator holds no matter what it instantiated itself. That is what
    /// makes it the one convergence source with no local precondition: the
    /// persisted fill high-water needs this validator's own epoch store to
    /// hold the epoch's fills, and the mint-path terminal skip needs its
    /// session map to hold the epoch's reconstructed sessions. A validator
    /// with neither — a fresh or state-synced store, an epoch entered late —
    /// has only this (#1830).
    ///
    /// Read in `instantiate_internal_presign_session` (seed) and in
    /// `observe_completed_internal_presign_ordinal` (fast-forward), and
    /// exported as the reference of the `internal_presign_ordinal_lag` gauge.
    pub(crate) highest_completed_internal_presign_ordinal:
        HashMap<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// Pools whose ordinal stream was seeded mid-stream rather than at 1 —
    /// from the persisted fill high-water, the consensus completion frontier,
    /// or whichever was further along. However this process got there (a
    /// restart, a very late key install, a store holding none of the epoch's
    /// fills), it joined the pool mid-epoch. Drained on each pool's first live
    /// mint to emit the one-shot "resumed live instantiation" marker the #1952
    /// regression scenario gates on.
    internal_presign_mid_epoch_seeded_pools:
        HashSet<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm)>,

    /// Monotonically increasing count of instantiated internal presign sessions
    /// per (network_key, curve, signature_algorithm). Incremented when a
    /// session is created. Used with `completed_internal_presign_sessions` to
    /// prevent instantiating new sessions while existing ones haven't completed
    /// — each session produces a variable number of presigns (1 to n-t), so
    /// overlapping batches cause pool overshoot. Keyed by network key too so
    /// one key's in-flight batch never gates another key's pool of the same
    /// algorithm.
    /// Consensus-safe: instantiation is consensus-agreed, so all honest parties
    /// maintain identical values.
    pub(crate) instantiated_internal_presign_sessions:
        HashMap<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// Monotonically increasing count of completed internal presign sessions
    /// per (network_key, curve, signature_algorithm). Incremented when a
    /// session's output reaches consensus majority. When this equals
    /// `instantiated_internal_presign_sessions` for a given tuple, new sessions
    /// may be instantiated.
    pub(crate) completed_internal_presign_sessions:
        HashMap<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// Consensus round at which the most recent internal-presign top-up batch
    /// was instantiated, per (network_key, curve, signature_algorithm). Drives
    /// the stale-batch expiry in `instantiate_internal_presign_sessions`: a
    /// batch that never reaches an output quorum (e.g. every validator's
    /// computation failed locally) would otherwise block its pool's top-up
    /// for the rest of the epoch, starving the pool. Per-key so each pool
    /// carries its own batch-instantiated round.
    /// Consensus-safe: written only with consensus-agreed round numbers, so
    /// all honest parties maintain identical values.
    internal_presign_batch_instantiated_at_round:
        HashMap<(NetworkKeyId, DWalletCurve, DWalletSignatureAlgorithm), u64>,

    /// The epoch store for persisting presign pools to disk.
    pub(crate) epoch_store: Arc<dyn AuthorityPerEpochStoreTrait>,

    /// Channel sender for completed network-owned-address sign session outputs.
    pub(crate) network_owned_address_sign_output_sender: Sender<NetworkOwnedAddressSignOutput>,

    /// Each validator's latest Sui chain observation, keyed by party ID.
    /// Updated every time a status update with an observation is received.
    sui_chain_observations_by_party: HashMap<PartyID, SuiChainObservation>,
    /// The most recently consensus-agreed Sui chain context (None at startup).
    agreed_sui_chain_context: Option<SuiChainContext>,

    /// User-session sequence numbers that were last emitted to the per-seq
    /// `ika_dwallet_mpc_user_session_*` gauges. Used to zero out series for
    /// sessions that have left `self.sessions` so dashboards don't read a
    /// stale "this session is still in state X" forever.
    previously_emitted_user_session_seqs: HashSet<u64>,
    /// User-session sequence numbers whose terminal (Completed/Failed) state
    /// has already been emitted to the per-seq gauges. Terminal sessions stay
    /// in `self.sessions` until epoch end; without this set every refresh
    /// would re-emit the epoch's whole cumulative session history instead of
    /// only in-flight sessions.
    finalized_emitted_user_session_seqs: HashSet<u64>,
    /// When the observability gauges were last refreshed; refreshes are
    /// rate-limited because the service loop ticks every ~20ms and the
    /// refresh iterates every tracked session.
    last_observability_refresh: Option<Instant>,
    /// When the stalled-user-session warn was last emitted, so a wedged
    /// session logs once a minute instead of once per refresh.
    last_stalled_session_log: Option<Instant>,

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

#[derive(Clone, Debug)]
pub(crate) struct OutputsToFinalize {
    pub(crate) malicious_voters: HashSet<AuthorityName>,
    pub(crate) reported_malicious_authorities: HashSet<AuthorityName>,
    pub(crate) final_malicious_authorities: HashSet<AuthorityName>,
    pub(crate) majority_vote: DWalletMPCOutputKind,
    pub(crate) vote_diagnostics: OutputVoteDiagnostics,
}

impl DWalletMPCManager {
    pub(crate) fn new(
        validator_name: AuthorityName,
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
        max_computation_cores: Option<usize>,
        stranded_network_keys: Arc<ArcSwap<HashSet<ObjectID>>>,
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
            max_computation_cores,
            stranded_network_keys,
        )
        .unwrap_or_else(|err| {
            error!(error=?err, "Failed to create DWalletMPCManager.");
            // We panic on purpose, this should not happen.
            panic!("DWalletMPCManager initialization failed: {err:?}");
        })
    }

    pub fn try_new(
        validator_name: AuthorityName,
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
        max_computation_cores: Option<usize>,
        stranded_network_keys: Arc<ArcSwap<HashSet<ObjectID>>>,
    ) -> DwalletMPCResult<Self> {
        let access_structure = generate_access_structure_from_committee(&committee)?;

        let mpc_computations_orchestrator = CryptographicComputationsOrchestrator::try_new(
            root_seed.clone(),
            max_computation_cores,
        )?;
        let party_id = authority_name_to_party_id_from_committee(&committee, &validator_name)?;

        // Derive ALL of this validator's MPC key material once from the seed:
        // class-groups secret (AHE) + per-curve PVSS decryption keys (used by
        // VSS Shamir-share pre-derivation at network-key ingestion). The
        // matching public encryption keys come from the same derivation and
        // feed the publics struct so VSS shamir pre-derivation has both
        // halves without re-running `from_seed` per network key. Secrets and
        // publics are deliberately split into separate structs so the secret
        // type never shares a struct with public material.
        let (validator_mpc_secrets, validator_publics) = ValidatorMPCSecrets::from_seed(&root_seed);
        let validator_pvss_secrets_for_vss =
            crate::dwallet_mpc::network_dkg::ValidatorPvssSecretsForVss {
                secp256k1_decryption_key: validator_mpc_secrets.secp256k1_pvss_decryption_key,
                ristretto_decryption_key: validator_mpc_secrets.ristretto_pvss_decryption_key,
            };
        let validator_pvss_publics_for_vss =
            crate::dwallet_mpc::network_dkg::ValidatorPvssEncryptionKeysForVss {
                secp256k1_encryption_key: validator_publics.secp256k1_pvss.0,
                ristretto_encryption_key: validator_publics.ristretto_pvss.0,
            };

        let validator_private_data = ValidatorPrivateDecryptionKeyData {
            party_id,
            class_groups_decryption_key: validator_mpc_secrets.class_groups.decryption_key,
            validator_pvss_secrets_for_vss,
            validator_pvss_publics_for_vss,
            validator_decryption_key_shares: HashMap::new(),
            validator_vss_shamir_cache: HashMap::new(),
        };
        let dwallet_network_keys = DwalletMPCNetworkKeys::new(validator_private_data);

        // The per-seq user-session series are labeled by chain sequence numbers
        // this (per-epoch) manager will re-emit from scratch; clear the previous
        // epoch's series so its final tick doesn't linger as stale values.
        dwallet_mpc_metrics.reset_per_session_series();

        // Re-initialize the malicious handler every epoch. This is done intentionally:
        // We want to "forget" the malicious actors from the previous epoch and start from scratch.
        Ok(Self {
            sessions: HashMap::new(),
            local_mpc_data_ready_latched: AtomicBool::new(false),
            party_id: authority_name_to_party_id_from_committee(&committee, &validator_name)?,
            epoch_id,
            access_structure,
            // ALL keys — class_groups included — come from the off-chain
            // consensus-agreed set: start empty and let the ingest fill them
            // in.
            validator_mpc_keys_by_party_id: ValidatorMpcKeysByPartyId::empty(),
            current_epoch_keys_ingested: false,
            next_epoch_validator_mpc_keys: None,
            cryptographic_computations_orchestrator: mpc_computations_orchestrator,
            catchup_gate: CatchUpGate::new(),
            malicious_actors: HashSet::new(),
            last_session_to_complete_in_current_epoch: 0,
            recognized_self_as_malicious: false,
            recognized_self_as_malicious_session: None,
            diagnostics_dir: None,
            network_keys: Box::new(dwallet_network_keys),
            sui_data_receivers,
            requests_pending_for_next_active_committee: Vec::new(),
            requests_pending_for_network_key: HashMap::new(),
            requests_pending_for_frozen_mpc_data: Vec::new(),
            internal_presign_requests_pending_for_network_key_data: Vec::new(),
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
            made_public_dwallets: HashSet::new(),
            global_presign_requests: Vec::new(),
            sent_presign_sequence_numbers: HashSet::new(),
            logged_lock_deferred_presigns: HashSet::new(),
            adopted_network_key_data: HashMap::new(),
            last_adoption_input: None,
            last_instantiated_network_key_data: HashMap::new(),
            pending_network_key_instantiations: HashMap::new(),
            last_cert_read_warn: None,
            last_prior_cert_keys_warn: None,
            warned_cert_digest_mismatches: HashSet::new(),
            reported_unadopted_internal_presign_completions: HashSet::new(),
            network_key_id_derivations_spawned: HashMap::new(),
            stranded_network_keys,
            warned_cryptographic_data_generation_failures: HashSet::new(),
            terminal_message_log_state: TerminalMessageLogState::new(Instant::now()),
            untracked_anomalies: HashSet::new(),
            last_failed_network_key_data: HashMap::new(),
            next_internal_presign_sequence_number: HashMap::new(),
            highest_completed_internal_presign_ordinal: HashMap::new(),
            internal_presign_mid_epoch_seeded_pools: HashSet::new(),
            instantiated_internal_presign_sessions: HashMap::new(),
            completed_internal_presign_sessions: HashMap::new(),
            internal_presign_batch_instantiated_at_round: HashMap::new(),
            epoch_store,
            network_owned_address_sign_output_sender,
            sui_chain_observations_by_party: HashMap::new(),
            agreed_sui_chain_context: None,
            previously_emitted_user_session_seqs: HashSet::new(),
            finalized_emitted_user_session_seqs: HashSet::new(),
            last_observability_refresh: None,
            last_stalled_session_log: None,
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
                Some(outputs_to_finalize) => {
                    let malicious_voters = outputs_to_finalize.malicious_voters.clone();
                    let reported_malicious_authorities =
                        outputs_to_finalize.reported_malicious_authorities.clone();
                    let final_malicious_authorities =
                        outputs_to_finalize.final_malicious_authorities.clone();
                    let output_result = outputs_to_finalize.majority_vote;
                    let vote_diagnostics = outputs_to_finalize.vote_diagnostics;
                    let rejected = vote_diagnostics.rejected;
                    let local_output_observed = self
                        .sessions
                        .get(&session_identifier)
                        .is_some_and(|session| session.self_output_consensus_round.is_some());
                    // A session this validator only reconstructed from peer
                    // artifacts (its request never activated locally —
                    // dominant after a restart) can never have local output;
                    // that absence is definitional, not a completion race.
                    let session_reconstructed =
                        self.sessions
                            .get(&session_identifier)
                            .is_some_and(|session| {
                                session.origin == SessionOrigin::ReconstructedFromConsensus
                            });
                    let running_computation_count = self
                        .cryptographic_computations_orchestrator
                        .running_computation_count_for_session(&session_identifier);
                    // Stamp the quorum round on the session before
                    // `complete_mpc_session` clears its data — first-write-wins
                    // so a duplicate agreed output doesn't move the recorded
                    // quorum point. Feeds the per-seq quorum-round gauge and
                    // the self-output→quorum latency histogram (observed only
                    // on the first quorum transition, and only when this
                    // validator submitted its own output — otherwise the
                    // latency is meaningless from this node's perspective).
                    if let Some(session) = self.sessions.get_mut(&session_identifier) {
                        let first_quorum_transition = session.quorum_consensus_round.is_none();
                        session.record_quorum(
                            consensus_round,
                            vote_diagnostics.winning_output_digest,
                            rejected,
                        );
                        if first_quorum_transition
                            && let Some(self_output_round) = session.self_output_consensus_round
                        {
                            self.dwallet_mpc_metrics
                                .self_output_to_quorum_consensus_rounds
                                .observe(consensus_round.saturating_sub(self_output_round) as f64);
                        }
                        // Stash the winning network-key reconfiguration
                        // output's raw-bytes digest before `complete_mpc_session`
                        // makes the session non-active: a local computation
                        // finishing after that point is discarded without
                        // submission, and this digest is the only way its
                        // bytes can still be compared against the agreed
                        // output. Gated on the session's reconfiguration flag
                        // (set at request arrival, which necessarily precedes
                        // any local computation) so the envelope walk never
                        // runs for the common sign/presign outputs.
                        if !rejected
                            && session.network_key_reconfiguration
                            && let Some(raw_digest) =
                                network_key_reconfiguration_raw_output_digest(&output_result)
                        {
                            session.record_quorum_raw_output_digest(raw_digest);
                        }
                    }
                    // Recovery net: cache quorum-agreed network-key outputs
                    // locally even when this validator didn't produce them
                    // (see `cache_network_key_output_from_quorum`).
                    let quorum_output_cached =
                        self.cache_network_key_output_from_quorum(&output_result);
                    if quorum_output_cached
                        && let Some(session) = self.sessions.get_mut(&session_identifier)
                    {
                        session.record_quorum_output_cached();
                    }
                    let mut trigger_conditions = Vec::new();
                    if rejected {
                        trigger_conditions.push("rejected_output_reached_quorum");
                    }
                    if !malicious_voters.is_empty() {
                        trigger_conditions.push("weighted_majority_identified_malicious_voters");
                    }
                    if !reported_malicious_authorities.is_empty() {
                        trigger_conditions.push("winning_output_reported_malicious_authorities");
                    }
                    if !final_malicious_authorities.is_empty() {
                        trigger_conditions.push("malicious_authority_identified");
                    }
                    if vote_diagnostics.vote_groups.len() > 1 {
                        trigger_conditions.push("conflicting_output_reports_observed");
                    }
                    if vote_diagnostics.local_authority_malicious_reason.is_some() {
                        trigger_conditions.push("local_authority_in_final_malicious_set");
                    }
                    // Quorum forming before this validator's own output or
                    // computation catches up is the expected state for any
                    // validator outside the fastest two-thirds of a session,
                    // not a defect: count it on a plain counter, and attach
                    // it to the snapshot only as context when one of the
                    // defect triggers above fired for the same session.
                    let session_type = session_type_label(session_identifier.session_type());
                    if !local_output_observed && !session_reconstructed {
                        self.dwallet_mpc_metrics
                            .completion_races_total
                            .with_label_values(&[
                                "quorum_reached_before_local_output_observed",
                                session_type,
                            ])
                            .inc();
                    }
                    if running_computation_count > 0 {
                        self.dwallet_mpc_metrics
                            .completion_races_total
                            .with_label_values(&[
                                "local_computation_pending_at_session_completion",
                                session_type,
                            ])
                            .inc();
                    }
                    if !trigger_conditions.is_empty() {
                        if !local_output_observed && !session_reconstructed {
                            trigger_conditions.push("quorum_reached_before_local_output_observed");
                        }
                        if running_computation_count > 0 {
                            trigger_conditions
                                .push("local_computation_pending_at_session_completion");
                        }
                        self.emit_session_anomaly(
                            session_identifier,
                            MpcAnomalyKind::QuorumAnomaly,
                            MpcAnomalyContext {
                                current_consensus_round: Some(consensus_round),
                                trigger_conditions,
                                running_computation_count,
                                vote: Some(vote_diagnostics.clone()),
                                local_authority_malicious: final_malicious_authorities
                                    .contains(&self.validator_name),
                                quorum_output_cached_without_local_output: quorum_output_cached
                                    && !local_output_observed,
                                ..Default::default()
                            },
                        );
                    }
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
                        ?malicious_voters,
                        ?reported_malicious_authorities,
                        ?final_malicious_authorities,
                        local_output_observed,
                        local_computation_pending = running_computation_count > 0,
                        ?is_internal,
                        rejected,
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
    fn cache_network_key_output_from_quorum(&self, output: &DWalletMPCOutputKind) -> bool {
        let DWalletMPCOutputKind::External { output: kinds } = output else {
            return false;
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
        let cached_network_key_output = dkg_outputs.values().any(|bytes| !bytes.is_empty())
            || reconfiguration_outputs
                .values()
                .any(|bytes| !bytes.is_empty());
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
        cached_network_key_output
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
                ika_types::report_invariant_violation!(
                    "idle_update_unknown_authority",
                    sender_authority=?update.authority,
                    consensus_round,
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
                ika_types::report_invariant_violation!(
                    "chain_observation_unknown_authority",
                    sender_authority=?observation.authority,
                    consensus_round,
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
                ika_types::report_invariant_violation!(
                    "presign_request_unknown_authority",
                    sender_authority=?sender_authority,
                    consensus_round,
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

            // Agreement is content-addressed: a party votes for a specific
            // request body, not merely for its sequence number. Honest
            // validators derive the body from the same Sui event, so they
            // announce byte-identical requests and the agreed body is
            // unchanged.
            let parties = self.presign_request_votes.entry(request).or_default();
            parties.insert(sender_party_id);

            // Check if the parties that voted for THIS body form an authorized subset.
            if self.access_structure.is_authorized_subset(parties).is_ok() {
                self.completed_presign_sequence_numbers
                    .insert(sequence_number);
                // Any other body recorded for this sequence number can no
                // longer be agreed, so drop its tally rather than holding it
                // until the epoch ends.
                self.presign_request_votes
                    .retain(|voted, _| voted.session_sequence_number != sequence_number);
                agreed_presign_requests.push(request);
                debug!(
                    sequence_number,
                    consensus_round, "Presign request reached majority vote"
                );
            }
        }

        agreed_presign_requests
    }

    /// Ingest the per-epoch off-chain validator MPC keys (3 PVSS HPKE + VSS
    /// HPKE) into `validator_mpc_keys_by_party_id` (current) and
    /// `next_epoch_validator_mpc_keys` (next).
    ///
    /// CURRENT epoch: the primary source is the prior epoch's handoff
    /// certificate (`try_ingest_current_epoch_keys_from_prior_handoff_cert`)
    /// — the perpetual, quorum-signed pin of the prior epoch's frozen set,
    /// which is the committee-agreed value of this epoch's key set and is
    /// reachable after a mid-epoch restart (issue #1879). Only in the
    /// chain-true no-cert epochs (genesis, first epoch after the off-chain
    /// pipeline activated) does it fall back to the `current_epoch_mpc_keys`
    /// channel, whose producer delivers once THIS epoch's set is frozen by
    /// consensus (a stake-quorum of `EpochMpcDataReadySignal`s).
    ///
    /// NEXT epoch: delivered on the `next_epoch_mpc_keys` channel from this
    /// epoch's post-freeze assembly.
    ///
    /// Either way we ingest **once** and do NOT re-impose an all-committee
    /// completeness check: the agreed set may legitimately omit
    /// offline/withholding validators, and the DKG/reconfig deal only to the
    /// parties that have keys (the rest stay active in consensus, just undealt).
    pub(crate) fn ingest_offchain_mpc_keys(&mut self) -> DwalletMPCResult<()> {
        // Current epoch: fill the within-epoch network DKG key set, once.
        if !self.current_epoch_keys_ingested {
            let cert_outcome = self.try_ingest_current_epoch_keys_from_prior_handoff_cert()?;
            match cert_outcome {
                PriorCertKeysOutcome::Ingested => {}
                // Transient cert-path miss: retry next iteration WITHOUT
                // falling back to the channel. Post-freeze the channel
                // carries THIS epoch's frozen set, which in a joiner-churn
                // epoch is a strict superset of the boundary set the rest
                // of the committee latched at the flip — ingesting it here
                // would byte-diverge this validator's VSS presign public
                // inputs from every peer's.
                PriorCertKeysOutcome::RetryLater => {}
                PriorCertKeysOutcome::NoPriorCert => {
                    let delivered = self
                        .sui_data_receivers
                        .current_epoch_mpc_keys_receiver
                        .borrow()
                        .clone();
                    if let Some((epoch, bundles)) = delivered
                        && epoch == self.epoch_id
                    {
                        self.validator_mpc_keys_by_party_id =
                            get_validator_mpc_keys_by_party_id(&self.committee, &bundles)?;
                        self.current_epoch_keys_ingested = true;
                        // Ingestion is complete, so no prior-cert blob can
                        // still be "missing" — clear the gauge in case an
                        // earlier iteration's cert attempt set it before
                        // this epoch resolved as a chain-true no-cert one.
                        self.dwallet_mpc_metrics.prior_cert_blobs_missing.set(0);
                        info!(
                            epoch = self.epoch_id,
                            dealt = self.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
                            committee = self.committee.voting_rights.len(),
                            "ingested current-epoch off-chain validator MPC keys (agreed frozen set)"
                        );
                    }
                }
            }
        }

        // Next epoch: fill the reconfiguration key set, keyed by the next
        // committee's party ids (so it must be assembled against that committee),
        // once.
        if self.next_epoch_validator_mpc_keys.is_none()
            && let Some(next_committee) = self.next_active_committee.as_ref()
        {
            let delivered = self
                .sui_data_receivers
                .next_epoch_mpc_keys_receiver
                .borrow()
                .clone();
            if let Some((epoch, bundles)) = delivered
                && epoch == next_committee.epoch
            {
                let keys = get_validator_mpc_keys_by_party_id(next_committee, &bundles)?;
                info!(
                    epoch = self.epoch_id,
                    next_epoch = next_committee.epoch,
                    dealt = keys.secp256k1_pvss.len(),
                    next_committee = next_committee.voting_rights.len(),
                    "ingested next-epoch off-chain validator MPC keys (agreed frozen set)"
                );
                self.next_epoch_validator_mpc_keys = Some(keys);
            }
        }

        Ok(())
    }

    /// Assembles the CURRENT epoch's validator MPC key bundle from the prior
    /// epoch's handoff certificate (`ValidatorMpcData` items ∩ current
    /// committee) against the perpetual content-addressed blob store, and
    /// ingests it into `validator_mpc_keys_by_party_id`.
    ///
    /// WHY the cert: the committee-agreed value of the current epoch's key
    /// set is the PRIOR epoch's frozen set restricted to the current
    /// committee — that is what every continuing validator ingests at the
    /// epoch flip (the syncer assembles the prior epoch's post-freeze set
    /// during the boundary window, the manager latches it for the whole
    /// epoch, and the current epoch's own freeze never re-feeds it). The
    /// cert pins exactly that set (`compute_handoff_items` builds the
    /// `ValidatorMpcData` items 1:1 from the frozen map), is quorum-signed
    /// and perpetual, and — unlike the boundary window's process-local watch
    /// channel — is reachable after a mid-epoch restart (issue #1879). Blobs
    /// are content-addressed and digest-verified at the store's write
    /// boundary, so the assembled bundle is byte-identical to the boundary
    /// delivery.
    ///
    /// Committee members without a prior-cert digest were excluded from the
    /// prior epoch's frozen set (first-time joiners that missed its freeze
    /// window); the boundary delivery skips them identically — DKG and the
    /// VSS protocols deal only to the parties that have keys.
    fn try_ingest_current_epoch_keys_from_prior_handoff_cert(
        &mut self,
    ) -> DwalletMPCResult<PriorCertKeysOutcome> {
        let Some(prior_epoch) = self.epoch_id.checked_sub(1) else {
            return Ok(PriorCertKeysOutcome::NoPriorCert);
        };
        let cert = match self
            .epoch_store
            .get_certified_handoff_attestation(prior_epoch)
        {
            Ok(Some(cert)) => cert,
            // Ambiguous between "chain-true no cert" (a pre-v4 prior epoch,
            // where the freeze-gated channel is the fleet-uniform source)
            // and "bootstrap anchor still fetching" on a cold start. Fall
            // through to the channel: this method re-runs every service
            // iteration, and pre-freeze the channel delivers nothing, so the
            // cert wins the race in any epoch whose cert arrives before the
            // current epoch's freeze fires.
            Ok(None) => return Ok(PriorCertKeysOutcome::NoPriorCert),
            Err(e) => {
                // A read ERROR must not degrade to the channel path — the
                // cert may exist, and the channel post-freeze can carry a
                // divergent (superset) key set. Retry.
                if self.should_warn_prior_cert_keys() {
                    warn!(
                        error = ?e,
                        prior_epoch,
                        "failed to read the prior epoch's handoff cert while sourcing \
                         current-epoch validator MPC keys; retrying"
                    );
                }
                return Ok(PriorCertKeysOutcome::RetryLater);
            }
        };
        let prior_cert_digests: HashMap<AuthorityName, [u8; 32]> = cert
            .attestation
            .items
            .iter()
            .filter_map(|(key, digest)| match key {
                HandoffItemKey::ValidatorMpcData { validator } => Some((*validator, *digest)),
                _ => None,
            })
            .collect();
        if prior_cert_digests.is_empty() {
            // A cert that predates mpc_data handoff items (the first epoch
            // after the off-chain pipeline activated) — fleet-uniform, the
            // channel is the source.
            return Ok(PriorCertKeysOutcome::NoPriorCert);
        }
        let pairs: Vec<(AuthorityName, [u8; 32])> = self
            .committee
            .voting_rights
            .iter()
            .filter_map(|(name, _)| prior_cert_digests.get(name).map(|digest| (*name, *digest)))
            .collect();
        if pairs.is_empty() {
            // Cert has mpc_data items but none for any current committee
            // member — cannot happen on a continuing network (quorum
            // continuity), so surface it rather than silently ingesting
            // nothing.
            if self.should_warn_prior_cert_keys() {
                warn!(
                    prior_epoch,
                    "prior handoff cert carries mpc_data items but none for any current \
                     committee member — falling back to the freeze-gated delivery"
                );
            }
            return Ok(PriorCertKeysOutcome::NoPriorCert);
        }
        let Some(perpetual) = self.epoch_store.perpetual_tables_handle() else {
            // Near-unreachable: a missing perpetual handle already made the
            // cert read above return `Ok(None)` (its impl reads the cert
            // THROUGH this handle), so reaching here means the handle
            // vanished between the two loads. Defense-in-depth: retry rather
            // than fall to the channel while a cert was just observed.
            return Ok(PriorCertKeysOutcome::RetryLater);
        };
        let assembly = assemble_committee_mpc_data_off_chain(pairs, move |digest| {
            perpetual.get_mpc_artifact_blob(digest).ok().flatten()
        });
        match assembly {
            OffChainMpcDataAssembly::Complete(bundles) => {
                self.dwallet_mpc_metrics.prior_cert_blobs_missing.set(0);
                self.validator_mpc_keys_by_party_id =
                    get_validator_mpc_keys_by_party_id(&self.committee, &bundles)?;
                self.current_epoch_keys_ingested = true;
                info!(
                    epoch = self.epoch_id,
                    prior_epoch,
                    dealt = self.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
                    committee = self.committee.voting_rights.len(),
                    "ingested current-epoch off-chain validator MPC keys from the prior \
                     epoch's handoff certificate"
                );
                Ok(PriorCertKeysOutcome::Ingested)
            }
            OffChainMpcDataAssembly::Incomplete { missing, .. } => {
                // Surface the deferral without log access (issue #1881): the
                // gauge holds the missing-blob count until the peer-blob
                // fetcher's prior-cert repair lands the blobs and assembly
                // completes (which resets it to 0 above).
                self.dwallet_mpc_metrics
                    .prior_cert_blobs_missing
                    .set(missing.len() as i64);
                if self.should_warn_prior_cert_keys() {
                    warn!(
                        prior_epoch,
                        ?missing,
                        "prior-cert mpc_data blobs missing or undecodable in the perpetual \
                         store; current-epoch validator MPC keys not ingested yet — retrying"
                    );
                }
                Ok(PriorCertKeysOutcome::RetryLater)
            }
            OffChainMpcDataAssembly::EverythingExcluded => {
                // `assemble_committee_mpc_data_off_chain` never returns this
                // variant (it belongs to the pre-assembly decision); guard
                // defensively rather than panic.
                ika_types::report_invariant_violation!(
                    "prior_cert_everything_excluded",
                    prior_epoch,
                    "off-chain assembly returned EverythingExcluded for a non-empty \
                     prior-cert pair set"
                );
                Ok(PriorCertKeysOutcome::RetryLater)
            }
        }
    }

    /// 10s throttle for the prior-cert key-ingestion warns (the ingest runs
    /// every 20ms service iteration). Returns whether to warn now and, if
    /// so, stamps the throttle.
    fn should_warn_prior_cert_keys(&mut self) -> bool {
        let now = Instant::now();
        match self.last_prior_cert_keys_warn {
            Some(last) if now.duration_since(last) < Duration::from_secs(10) => false,
            _ => {
                self.last_prior_cert_keys_warn = Some(now);
                true
            }
        }
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
        // cert: absence is an answer (a reconfigured key is rejected below,
        // with a warn, as missing its quorum anchor; a DKG-only key adopts
        // its deterministic local output), while an error is no answer at
        // all. A transient store error therefore skips adoption entirely for
        // this tick (the service loop retries every iteration) rather than
        // mis-classifying keys on a store hiccup.
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
        let mut dkg_digests: HashMap<NetworkKeyId, [u8; 32]> = HashMap::new();
        let mut reconfiguration_digests: HashMap<NetworkKeyId, [u8; 32]> = HashMap::new();
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
        let mut deferred_unmapped_key = false;
        for (key_id, data) in overlay.iter() {
            if data.network_dkg_public_output.is_empty() {
                // Nothing computed/fetched locally yet. For a key DKG'd in a
                // PRIOR epoch this is not a convergence window — the local
                // producer cache will never fill (this validator never
                // computed the key's outputs): the JOINER / cold-start shape.
                // The cert-pinned blob install (barrier) covers only the
                // continuing-validator path today, so without intervention the
                // overlay stays empty and the key is never adopted — parking
                // every session on it for this validator. Flag it for the
                // syncer's stranded-key chain read (#1852 machinery): the
                // chain holds the real blobs (written at DKG/reconfiguration
                // regardless of the off-chain plane), the cert digest gates
                // below still verify whatever the read returns, and a
                // confirmed instantiation un-flags the key. A key DKG'd THIS
                // epoch is excluded — that is the healthy fresh-key bootstrap
                // window, where the producer cache converges within ticks.
                // (Before issue #1751 removed the migration chain-read
                // fallback, this state was silently covered by it: an empty
                // local handoff cache took the full chain read. This flag
                // restores that recovery through the audited stranded path.)
                let stranded = data.dkg_at_epoch < self.epoch_id
                    && !self
                        .network_keys
                        .network_encryption_keys
                        .contains_key(key_id)
                    && !self.pending_network_key_instantiations.contains_key(key_id)
                    && !self.adopted_network_key_data.contains_key(key_id);
                if stranded && !self.stranded_network_keys.load().contains(key_id) {
                    info!(
                        ?key_id,
                        dkg_at_epoch = data.dkg_at_epoch,
                        current_epoch = self.epoch_id,
                        "network key overlay is empty for a prior-epoch key this validator \
                         holds nothing for (joiner / cold-start) — requesting a \
                         chain-sourced read from the syncer"
                    );
                    self.stranded_network_keys.rcu(|keys| {
                        let mut keys = (**keys).clone();
                        keys.insert(*key_id);
                        Arc::new(keys)
                    });
                }
                continue;
            }
            // A reconfiguration output recorded under the CURRENT epoch was
            // produced by this epoch's reconfiguration MPC *for the next
            // epoch's committee*: its shares are encrypted to the next
            // committee's party IDs (which need not align with this epoch's —
            // the on-chain committee order is not stable across epochs), so
            // adopting it here, with this epoch's party ID and access
            // structure, fails decryption with ClassGroup(Decryption). The
            // next epoch's manager adopts and decrypts it with next-epoch
            // identity at epoch start. In steady-state v4 the cert anchor
            // below rejects it anyway (the prior epoch's handoff cert pins
            // the output produced *for* this epoch); this guard closes the
            // no-cert genesis-epoch window the same
            // way instead of blindly adopting the overlay, which flips to
            // the freshly-cached next-epoch output the moment the mid-epoch
            // reconfiguration finalizes locally — and its skip is what feeds
            // the stranded-key detection below.
            if !data.current_reconfiguration_public_output.is_empty() {
                let reconfiguration_digest =
                    mpc_data_blob_hash(&data.current_reconfiguration_public_output);
                let produced_this_epoch = self
                    .epoch_store
                    .perpetual_tables_handle()
                    .and_then(|perpetual| {
                        perpetual
                            .get_network_reconfiguration_output_digest_for_epoch(
                                self.epoch_id,
                                key_id,
                            )
                            .ok()
                            .flatten()
                    })
                    .is_some_and(|digest| digest == reconfiguration_digest);
                if produced_this_epoch {
                    // `already_instantiated = true` is the healthy shape (the
                    // running validator holds the current epoch's parameters
                    // and is only pre-staging this output for the boundary
                    // flip).
                    let already_instantiated = self
                        .network_keys
                        .network_encryption_keys
                        .contains_key(key_id);
                    info!(
                        ?key_id,
                        already_instantiated,
                        "adoption skipping network key: the overlay's reconfiguration output \
                         was produced this epoch (encrypted to the next committee)"
                    );
                    // The mid-epoch-restart strand (#1852): this validator
                    // holds NOTHING for the key — no instantiated parameters,
                    // no instantiation in flight, no adopted data awaiting one
                    // — while the overlay serves only the next committee's
                    // output. Nothing else re-delivers an instantiable
                    // current-epoch output, so flag the key for the syncer's
                    // chain-sourced recovery read. The in-flight/adopted
                    // checks keep the healthy flip out of the set: a running
                    // validator whose FIRST instantiation is still on the
                    // rayon pool when this epoch's reconfiguration completes
                    // already holds the right bytes and needs no chain read.
                    let stranded = !already_instantiated
                        && !self.pending_network_key_instantiations.contains_key(key_id)
                        && !self.adopted_network_key_data.contains_key(key_id);
                    if stranded && !self.stranded_network_keys.load().contains(key_id) {
                        info!(
                            ?key_id,
                            "network key stranded after a mid-epoch restart — requesting a \
                             chain-sourced current-epoch reconfiguration output from the syncer"
                        );
                        self.stranded_network_keys.rcu(|keys| {
                            let mut keys = (**keys).clone();
                            keys.insert(*key_id);
                            Arc::new(keys)
                        });
                    }
                    continue;
                }
            }
            let local_dkg_digest = mpc_data_blob_hash(&data.network_dkg_public_output);
            // Adoption is what upholds the invariant the rest of the manager
            // builds on: EVERY adopted key has a resolvable content-derived
            // `NetworkKeyId` (the cert digests, the internal-presign per-pool
            // counters, and the session identifiers all key by it). An
            // unmapped key therefore defers on EVERY adoption branch — not
            // only when the cert references keys. The cert-referenced case is
            // additionally a correctness cycle: the mapping registers at
            // instantiation, instantiation needs adoption, and adoption needs
            // the mapping to see the cert's digests — a joiner consuming the
            // cert lands exactly there, and treating its key as "not pinned"
            // either adopts parameters the committee never agreed to
            // (initial-DKG branch) or wedges forever on a phantom digest
            // mismatch (reconfigured branch). The cert-less case (v3, the
            // genesis epoch, a fresh key before any cert pins it) would
            // otherwise adopt an unresolvable key and make the top-up loop's
            // should-never-happen skip fire routinely on fresh networks.
            // Break the cycle the same way in both cases: derive this key's
            // NetworkKeyId from the locally-held blobs on the rayon pool (an
            // expensive class-groups computation) and defer adoption until
            // the background derivation registers the mapping. (Deployed
            // mainnet/testnet keys are seeded into the mapping as constants
            // and never defer; a fresh DKG registers at output processing on
            // every validator, so this defer is rare and short.)
            let network_key_id = crate::network_key_id_mapping::network_key_id_for(key_id);
            if network_key_id.is_none() {
                // Memoize on the derivation inputs, not just the key id, so a
                // failure while the overlay's reconfiguration output is
                // transiently empty/incomplete is retried once the overlay
                // republishes a different (complete) output — instead of
                // being pinned to failure for the whole epoch.
                let derivation_input_digest = mpc_data_blob_hash(
                    &bcs::to_bytes(&(
                        &data.network_dkg_public_output,
                        &data.current_reconfiguration_public_output,
                    ))
                    .unwrap_or_default(),
                );
                if self.network_key_id_derivations_spawned.get(key_id)
                    != Some(&derivation_input_digest)
                {
                    self.network_key_id_derivations_spawned
                        .insert(*key_id, derivation_input_digest);
                    info!(
                        ?key_id,
                        "adopting a network key whose ObjectID has no NetworkKeyId mapping \
                         (not seeded, never instantiated here) — deferring adoption and \
                         deriving the id from the locally-held key data in the background"
                    );
                    spawn_network_key_id_registration(
                        *key_id,
                        data.network_dkg_public_output.clone(),
                        data.current_reconfiguration_public_output.clone(),
                    );
                }
                deferred_unmapped_key = true;
                continue;
            }
            let cert_dkg_digest = network_key_id.as_ref().and_then(|id| dkg_digests.get(id));
            let cert_reconfig_digest = network_key_id
                .as_ref()
                .and_then(|id| reconfiguration_digests.get(id));
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
                if let Some(cert_reconfiguration_digest) = cert_reconfig_digest {
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
                if let Some(cert_dkg) = cert_dkg_digest
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
            } else if cert.is_some() {
                // Reconfigured key, off-chain mode with a prior handoff cert:
                // the overlay carries locally-cached blobs, so anchor them
                // against the prior epoch's cert — the DKG digest and the
                // epoch-specific reconfiguration digest must match.
                if cert_dkg_digest != Some(&local_dkg_digest) {
                    // The canonical DKG output is now stable across epochs, so
                    // a mismatch against the prior epoch's cert is never
                    // expected. Skip adoption either way; only an UNADOPTED key
                    // contradicting the cert is the security-relevant anomaly
                    // worth a warn (an already-adopted key keeps the value it
                    // has installed, and the output-quorum byte-equality tally
                    // guards against a genuinely divergent output).
                    if !self.adopted_network_key_data.contains_key(key_id) {
                        if self
                            .warned_cert_digest_mismatches
                            .insert((*key_id, local_dkg_digest))
                        {
                            warn!(
                                ?key_id,
                                cert_dkg_digest = ?cert_dkg_digest,
                                local_dkg_digest = ?local_dkg_digest,
                                "local network-key DKG output digest does not match the prior \
                                 epoch's handoff cert and the key has no adopted value — \
                                 skipping adoption, the key stays uninstantiated"
                            );
                        } else {
                            debug!(
                                ?key_id,
                                "local network-key DKG output still contradicts the handoff \
                                 cert (key unadopted) — skipping adoption"
                            );
                        }
                    }
                    continue;
                }
                let local_reconfiguration_digest =
                    mpc_data_blob_hash(&data.current_reconfiguration_public_output);
                if cert_reconfig_digest != Some(&local_reconfiguration_digest) {
                    // NOT contradiction-only: once THIS epoch's
                    // reconfiguration completes, the overlay carries the
                    // new epoch-keyed output which by design mismatches
                    // the PRIOR epoch's cert — that skip is the intended
                    // defer-to-next-epoch with the already-adopted prior
                    // value still installed. Only when the skip actually
                    // leaves the key unadopted is it the security-relevant
                    // divergence worth a warn.
                    if !self.adopted_network_key_data.contains_key(key_id) {
                        if self
                            .warned_cert_digest_mismatches
                            .insert((*key_id, local_reconfiguration_digest))
                        {
                            warn!(
                                ?key_id,
                                cert_reconfiguration_digest = ?cert_reconfig_digest,
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
            } else {
                // Reconfigured key with NO prior handoff cert to anchor
                // against. A handoff cert is built durably
                // every epoch, so a genuinely-absent cert alongside a
                // reconfigured overlay entry is anomalous (a cert READ ERROR
                // already returned above without reaching here). Adopting the
                // unanchored output would bypass the cert-digest security gate
                // — installing parameters no quorum certified — so reject it;
                // the pass retries every service iteration and adopts once the
                // cert resolves. Warn once per local digest (deduped), debug on
                // repeats — same pattern as the mismatch skips above.
                let local_reconfiguration_digest =
                    mpc_data_blob_hash(&data.current_reconfiguration_public_output);
                if self
                    .warned_cert_digest_mismatches
                    .insert((*key_id, local_reconfiguration_digest))
                {
                    warn!(
                        ?key_id,
                        ?local_reconfiguration_digest,
                        "reconfigured network key has no prior handoff cert to anchor \
                         against — rejecting adoption (a quorum-certified cert exists \
                         every off-chain epoch; adopting unanchored would bypass the \
                         cert-digest security gate)"
                    );
                } else {
                    debug!(
                        ?key_id,
                        "reconfigured network key still has no prior handoff cert — \
                         rejecting adoption"
                    );
                }
                continue;
            }
            self.adopted_network_key_data.insert(*key_id, data.clone());
        }
        // A deferred unmapped key resolves via the background NetworkKeyId
        // derivation, which changes nothing the memo below can see (the
        // overlay bytes stay identical; only the process-global mapping
        // gains an entry) — memoizing would make the deferral permanent.
        // Skip the memo so the pass re-runs every tick until the mapping
        // resolves.
        if deferred_unmapped_key {
            return;
        }
        // Never memoize an EMPTY overlay (#1952): the syncer only publishes a
        // new overlay Arc on a pass that fetched something, so a
        // wholly-empty first publish would otherwise pin `Arc::ptr_eq` true
        // for the rest of the epoch and this pass would never look again —
        // even after keys appear downstream of a recovered registry read.
        // The empty pass is O(1), so re-running it every tick costs nothing.
        if overlay.is_empty() {
            return;
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
                ika_types::report_invariant_violation!(
                    "noa_observation_unknown_authority",
                    sender_authority=?sender_authority,
                    consensus_round,
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

        match session.add_message(consensus_round, sender_party_id, message) {
            AddMessageResult::Stored | AddMessageResult::IgnoredNonMpcSession => {}
            AddMessageResult::IgnoredTerminal {
                terminal_status,
                session_type,
            } => {
                let session_type = optional_session_type_label(session_type);
                self.dwallet_mpc_metrics
                    .messages_after_terminal_session_total
                    .with_label_values(&[terminal_status.label(), session_type])
                    .inc();
                debug!(
                    terminal_status = terminal_status.label(),
                    session_type, "ignored MPC message received after the session became terminal"
                );
                if let TerminalMessageLogAction::Warn { completed, failed } = self
                    .terminal_message_log_state
                    .record(Instant::now(), terminal_status)
                {
                    warn!(
                        completed,
                        failed,
                        interval_seconds = TERMINAL_MESSAGE_LOG_INTERVAL.as_secs(),
                        "sustained MPC messages received after terminal sessions"
                    );
                }
            }
        }
    }

    /// Builds the MPC session input for a request from this manager's current
    /// committee/key state.
    fn session_input(
        &self,
        request: &DWalletSessionRequest,
    ) -> DwalletMPCResult<(PublicInput, MPCPrivateInput)> {
        session_input_from_request(
            request,
            &self.access_structure,
            &self.committee,
            &self.network_keys,
            self.next_active_committee.clone(),
            self.validator_mpc_keys_by_party_id.clone(),
            self.next_epoch_validator_mpc_keys.clone(),
        )
    }

    pub(super) fn session_status_from_request(
        &self,
        request: DWalletSessionRequest,
        is_internal: bool,
    ) -> SessionStatus {
        match self.session_input(&request) {
            Ok((public_input, private_input)) => SessionStatus::Active {
                public_input,
                private_input,
                request,
            },
            Err(e) => {
                // The not-ready class (key install / off-chain key ingest still
                // in flight) is a reachable transient at epoch entry, not an
                // invariant violation — don't page on it. Internal presign
                // requests park on it before ever getting here (see
                // `instantiate_internal_presign_session`).
                // `VssShamirCacheUnavailable` is terminal but BY-DESIGN
                // reachable: during the v3→v4 boundary epoch every network key
                // is pre-V3 (`NotApplicable` cache), so a NOA VSS sign attempt
                // hitting it is the expected state of the whole fleet, not an
                // invariant violation — log it as an error without paging.
                let is_expected_error_class = e.is_network_key_data_not_ready()
                    || matches!(e, DwalletMPCError::VssShamirCacheUnavailable(_));
                if is_internal && !is_expected_error_class {
                    ika_types::report_invariant_violation!(
                        "internal_session_input",
                        error=?e,
                        ?request,
                        "create internal session input from dWallet request with error"
                    );
                } else {
                    error!(error=?e, ?request, "create session input from dWallet request with error");
                }
                SessionStatus::Failed
            }
        }
    }

    /// Returns the network encryption key ID used for network-owned-address signing (the oldest by DKG epoch).
    /// Used by internal presign session instantiation to determine internal-signing-specific pool params.
    ///
    /// Ties on `dkg_at_epoch` (two keys DKG'd in the same epoch) break by key
    /// id: without the tie-break, `min_by` keeps the LAST minimum in `HashMap`
    /// iteration order — per-process-random, so validators could disagree on
    /// which key is the NOA key and apply different pool configs (different
    /// batch sizes ⇒ divergent internal-presign sequence numbers).
    pub(super) fn network_owned_address_signing_network_encryption_key_id(
        &self,
    ) -> Option<ObjectID> {
        // Select over the ADOPTED set, not the installed set
        // (`network_keys.network_encryption_keys`): installation completes on
        // wall-clock time per validator, so choosing over it would let two
        // honest validators pick a different NOA key while their installs lag,
        // apply different pool configs (batch sizes), and diverge the
        // internal-presign top-up decision. The adopted set drives the same
        // top-up loop, so the two stay consistent WITHIN a validator.
        //
        // That is the only guarantee here: the answer is NOT uniform across
        // validators at a given moment. `adopt_cert_verified_keys` is a
        // per-tick LOCAL pass over a LOCAL overlay — WHICH keys are adoptable
        // is network-uniform (the handoff cert pins them), but WHEN each
        // validator adopts is not. The adopted set starts empty every epoch
        // and fills as each key's blobs become locally resolvable, a key whose
        // overlay entry is still blob-empty is skipped while its siblings
        // adopt, and a handoff-cert read error skips the whole pass for a
        // tick. So this returns `None` on a validator whose peers already
        // answer `Some`, and with more than one key it can return a different
        // key than a peer whose adopted set is ahead. The divergence is
        // transient (the set only grows, so everyone converges on the same
        // minimum) but not tick-bounded — a stranded key can stay unresolved
        // for much of an epoch. Callers must not treat a peer's choice that
        // differs from this one as evidence of misbehavior; see issue #2019.
        self.adopted_network_key_data
            .values()
            .min_by(|a, b| a.dkg_at_epoch.cmp(&b.dkg_at_epoch).then(a.id.cmp(&b.id)))
            .map(|data| data.id)
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

        // Iterate the dedicated internal-pool driver — `network_presign_pool_algorithms`
        // is decoupled from `SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES`
        // (the externally-requestable list serialized into the on-chain
        // `support_config`). VSS variants live ONLY here: they feed NOA
        // (network-owned-address) VSS sign but are not externally requestable
        // on-chain.
        let pool_algorithms = network_presign_pool_algorithms();
        // Ordered (`BTreeSet`) for stable iteration/logging, but the sequence
        // counters are now PER (key, curve, algorithm) pool (not a single shared
        // counter consumed in iteration order), so a pool's sequence stream no
        // longer depends on when other keys are adopted or the iteration order.
        // Per-pool ordinals are START-TIME-INVARIANT: a key adopted at a
        // different round on different validators still derives identical
        // session identifiers for its pool. A validator whose first top-up of
        // a pool lags past a full batch's quorum completion (mid-epoch
        // restart, a very late install) would otherwise start its ordinal
        // stream offset from its peers' and never converge (#1952); the heal
        // is in `instantiate_internal_presign_session` — the counter seeds on
        // first touch from the persisted `filled_presign_pool_slots`
        // high-water, and the mint path fast-forwards across ordinals whose
        // sessions are already terminal.
        let agreed_key_ids: BTreeSet<_> = self.adopted_network_key_data.keys().copied().collect();
        let mut pools_filled: Vec<String> = Vec::new();
        for key_id in agreed_key_ids {
            // The per-pool counters and the session identifier both key by the
            // key's content-derived `NetworkKeyId`, so resolve it once here. An
            // adopted key always resolves (adoption defers an unmapped key), so
            // `None` is a should-never-happen — skip the key rather than fall
            // back to a divergent identity axis.
            let Some(network_key_id) = self.internal_presign_network_key_id(&key_id) else {
                ika_types::report_invariant_violation!(
                    "internal_presign_key_id_missing",
                    ?key_id,
                    "adopted network key has no resolvable NetworkKeyId in the internal-presign \
                     top-up loop; skipping its pools this iteration"
                );
                continue;
            };
            for (curve, signature_algorithm) in pool_algorithms.iter().copied() {
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
                            .get_internal_presign_consensus_round_delay(curve, signature_algorithm),
                        self.protocol_config
                            .get_internal_presign_sessions_to_instantiate(
                                curve,
                                signature_algorithm,
                            ),
                    )
                };

                // Export the pool size BEFORE the in-flight skip below, so a pool
                // wedged behind never-completing sessions is still observable. The
                // key dimension is reduced to a bounded `key_role` label.
                let current_pool_size =
                    self.internal_presign_pool_size(key_id, curve, signature_algorithm);
                let key_role = if is_network_owned_address_signing_presign {
                    KEY_ROLE_NETWORK_OWNED_ADDRESS_SIGNING
                } else {
                    KEY_ROLE_OTHER
                };
                let curve_label = curve.to_string();
                let signature_algorithm_label = signature_algorithm.to_string();
                self.dwallet_mpc_metrics
                    .internal_presign_pool_size
                    .with_label_values(&[
                        curve_label.as_str(),
                        signature_algorithm_label.as_str(),
                        key_role,
                    ])
                    .set(current_pool_size as i64);

                // How far this validator's next mint trails the committee's
                // completed frontier — the ordinal-stream divergence that is
                // otherwise invisible from outside the process (#1830). A pool
                // is minted before it completes, so a participating validator
                // sits at-or-ahead of the frontier and this reads 0; a pool
                // this process has never minted for has no stream to be
                // offset from and also reads 0.
                let ordinal_lag = self
                    .next_internal_presign_sequence_number
                    .get(&(network_key_id, curve, signature_algorithm))
                    .map(|next| {
                        self.highest_completed_internal_presign_ordinal
                            .get(&(network_key_id, curve, signature_algorithm))
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1)
                            .saturating_sub(*next)
                    })
                    .unwrap_or(0);
                self.dwallet_mpc_metrics
                    .internal_presign_ordinal_lag
                    .with_label_values(&[
                        curve_label.as_str(),
                        signature_algorithm_label.as_str(),
                        key_role,
                    ])
                    .set(ordinal_lag as i64);

                // Skip instantiation if previous sessions for this (curve, algorithm)
                // haven't completed yet. Each session produces a variable number of
                // presigns (1 to n-t), so overlapping batches cause pool overshoot.
                let instantiated = self
                    .instantiated_internal_presign_sessions
                    .get(&(network_key_id, curve, signature_algorithm))
                    .copied()
                    .unwrap_or(0);
                let completed = self
                    .completed_internal_presign_sessions
                    .get(&(network_key_id, curve, signature_algorithm))
                    .copied()
                    .unwrap_or(0);
                if instantiated != completed {
                    // A batch that dies without ever reaching an output quorum
                    // (e.g. every validator's round-one computation failed
                    // locally) never advances `completed`, so without an
                    // expiry it blocks this pool's top-up for the rest of the
                    // epoch and the pool starves. Presume such a batch dead
                    // after a bounded number of consensus rounds and forgive
                    // it by reconciling the counters; a presumed-dead batch
                    // that completes late is absorbed by the saturating
                    // increment in `record_internal_presign_output`.
                    // Consensus-safe: the decision reads only consensus-agreed
                    // inputs (round numbers and the shared counters), so every
                    // validator expires the same batch at the same round.
                    let Some(expiry_rounds) = self
                        .protocol_config
                        .internal_presign_stale_batch_expiry_rounds_as_option()
                    else {
                        continue;
                    };
                    let batch_round = self
                        .internal_presign_batch_instantiated_at_round
                        .get(&(network_key_id, curve, signature_algorithm))
                        .copied()
                        .unwrap_or(0);
                    if consensus_round.saturating_sub(batch_round) < expiry_rounds {
                        continue;
                    }
                    warn!(
                        ?curve,
                        ?signature_algorithm,
                        instantiated,
                        completed,
                        batch_round,
                        consensus_round,
                        "internal presign top-up batch never completed; presuming it dead and releasing the pool for new top-ups"
                    );
                    self.completed_internal_presign_sessions
                        .insert((network_key_id, curve, signature_algorithm), instantiated);
                }

                if (number_of_consensus_rounds.is_multiple_of(consensus_round_delay)
                    && current_pool_size < minimal_pool_size)
                    || (network_is_idle && current_pool_size < maximum_pool_size)
                {
                    let mut minted = 0u64;
                    for _ in 1..=sessions_to_instantiate {
                        // Only a mint that produced a live session (activated
                        // or parked-for-retry) counts against the
                        // instantiated/completed batch guard: a mint the
                        // fast-forward resolved as already-completed history
                        // will never produce a completion of its own, and
                        // counting it would wedge the guard (#1952).
                        if self.instantiate_internal_presign_session(
                            consensus_round,
                            network_key_id,
                            key_id,
                            curve,
                            signature_algorithm,
                        ) {
                            minted += 1;
                            *self
                                .instantiated_internal_presign_sessions
                                .entry((network_key_id, curve, signature_algorithm))
                                .or_insert(0) += 1;
                        }
                    }
                    self.internal_presign_batch_instantiated_at_round.insert(
                        (network_key_id, curve, signature_algorithm),
                        consensus_round,
                    );
                    pools_filled.push(format!(
                        "{curve:?}/{signature_algorithm:?}={current_pool_size}(min{minimal_pool_size})+{minted}"
                    ));
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

    /// How a completed internal-presign output's key resolves for counter
    /// bookkeeping. The three cases move no counter differently — only the
    /// `Resolved` arm advances one — but they mean very different things
    /// operationally, so they are classified here rather than at the log
    /// site, where the distinction would be untestable.
    ///
    /// Why `NotAdopted` is safe to pass over: resolution is **monotone within
    /// a process** — the `ObjectID → NetworkKeyId` mapping is a never-cleared
    /// process-global static (`network_key_id_mapping::register` only
    /// inserts) and installed keys are never evicted, so resolution can go
    /// `None → Some` but never `Some → None`. The only writer of
    /// `instantiated_internal_presign_sessions` is the top-up loop, which
    /// skips unresolvable keys. So "unresolvable now" implies "never
    /// resolved in this process", implies this process never instantiated a
    /// batch for that id: `instantiated` is 0 by construction and the
    /// saturating `completed < instantiated` guard would decline the
    /// increment even if the key resolved. Nothing is lost by not counting.
    pub(crate) fn classify_internal_presign_completion(
        &self,
        dwallet_network_encryption_key_id: &ObjectID,
    ) -> InternalPresignCompletionKey {
        match self.internal_presign_network_key_id(dwallet_network_encryption_key_id) {
            Some(network_key_id) => InternalPresignCompletionKey::Resolved(network_key_id),
            // Adoption defers an unmapped key, so an ADOPTED key that does
            // not resolve is a genuine invariant violation.
            None if self
                .adopted_network_key_data
                .contains_key(dwallet_network_encryption_key_id) =>
            {
                InternalPresignCompletionKey::AdoptedUnresolvable
            }
            // Ordinarily a post-restart replay: consensus redelivers outputs
            // of sessions the PREVIOUS process instantiated, while this
            // process's mapping still lacks the key (it is outside the
            // compiled-in seeds — every localnet/CI DKG — until the
            // background derivation lands with adoption, seconds later).
            None => InternalPresignCompletionKey::NotAdopted,
        }
    }

    /// The key's flip-invariant, content-derived `NetworkKeyId` — the identity
    /// bound into internal presign session identifiers and the key of the
    /// per-pool sequence/guard counters. Read from the installed key data when
    /// available, else from the pre-instantiation `ObjectID → NetworkKeyId`
    /// mapping (seeded deployed keys, handoff-cert background derivation,
    /// registrations from an earlier install). An ADOPTED key always resolves
    /// (adoption defers a key with no mapping — see `adopt_cert_verified_keys`),
    /// so the top-up path treats `None` as a should-never-happen skip.
    pub(crate) fn internal_presign_network_key_id(
        &self,
        dwallet_network_encryption_key_id: &ObjectID,
    ) -> Option<NetworkKeyId> {
        // Installed data first; on either "not installed" OR a (deterministic,
        // committee-uniform) derivation failure from the installed data, fall
        // through to the mapping — the doc contract is "installed data when
        // available, ELSE the mapping", and the mapping entry (seeded,
        // registered at DKG output processing, or background-derived) is the
        // same identity the installed data would derive.
        self.network_keys
            .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)
            .ok()
            .and_then(|key_data| key_data.network_key_id().ok())
            .or_else(|| network_key_id_for(dwallet_network_encryption_key_id))
    }

    /// The bounded metric label standing in for a pool's network key: the key
    /// that serves network-owned-address signing, or any other key.
    fn internal_presign_key_role(
        &self,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> &'static str {
        if self.network_owned_address_signing_network_encryption_key_id()
            == Some(dwallet_network_encryption_key_id)
        {
            KEY_ROLE_NETWORK_OWNED_ADDRESS_SIGNING
        } else {
            KEY_ROLE_OTHER
        }
    }

    /// Absorbs a completed internal-presign ordinal observed in the consensus
    /// stream: records the pool's completion frontier, and fast-forwards this
    /// validator's mint counter past it when the counter has fallen inside
    /// already-completed history (#1830).
    ///
    /// Why the counter can be behind at all: it is in-memory and re-derived
    /// per process, while the pool's ordinal stream belongs to the epoch. A
    /// validator that joins a pool's stream late — mid-epoch restart, a very
    /// late key install, an epoch entered late, a state-synced or otherwise
    /// empty epoch store — starts minting ordinals the committee finished
    /// long ago. Those mints can never produce live work (peers early-return
    /// on an already-resolved identifier) and the offset advances in lockstep
    /// with the live window, so without a heal the validator contributes
    /// nothing to that pool for the rest of the epoch.
    ///
    /// Why THIS is the heal that always applies: the two other convergence
    /// sources have local preconditions the wedge can remove — the seed reads
    /// this validator's persisted `filled_presign_pool_slots`, and the mint
    /// path's terminal skip walks this validator's session map (bounded per
    /// mint, and only while a top-up is actually firing). The completed
    /// ordinal here rides the sequenced output stream itself, so it is held
    /// by every validator that processes the round, whatever its local state,
    /// and it lands the counter in one step rather than one ordinal at a time.
    ///
    /// Committee-uniform by construction: the rule reads only consensus-agreed
    /// data (`session_sequence_number` of a quorum-agreed output), and it can
    /// only move a counter FORWARD to one past an ordinal the committee has
    /// already completed — never past what peers have minted, and never
    /// backwards over a validator that is already at the frontier.
    ///
    /// Batches complete out of sequence order, so the jump can also skip a
    /// still-in-flight ordinal that sits below the frontier: a lagging
    /// validator gives up joining at most that one batch late, keeping the
    /// n-1 peers already in those sessions. That is the same trade the
    /// persisted-high-water seed already makes (`high_water + 1` skips the
    /// same in-flight ordinals), deliberately kept identical so a pool's
    /// rejoin point does not depend on which source repaired the counter.
    fn observe_completed_internal_presign_ordinal(
        &mut self,
        network_key_id: NetworkKeyId,
        dwallet_network_encryption_key_id: ObjectID,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
        session_sequence_number: u64,
    ) {
        let counter_key = (network_key_id, curve, signature_algorithm);
        let frontier = self
            .highest_completed_internal_presign_ordinal
            .entry(counter_key)
            .or_insert(0);
        *frontier = (*frontier).max(session_sequence_number);
        let frontier = *frontier;

        // Only an EXISTING counter is fast-forwarded here. A pool this process
        // has never minted for has no stream to converge yet; it is born in
        // `instantiate_internal_presign_session`, which seeds it from this
        // same frontier together with the persisted fill high-water (the
        // frontier alone would miss the pre-adoption part of a restart replay,
        // which fills slots without resolving the key).
        let Some(next) = self
            .next_internal_presign_sequence_number
            .get_mut(&counter_key)
        else {
            return;
        };
        if *next > frontier {
            return;
        }
        let fast_forwarded = frontier + 1 - *next;
        let resumed_at_sequence_number = frontier + 1;
        *next = resumed_at_sequence_number;

        // Only the ordinal counter moves. The in-flight batch guard is left
        // alone deliberately, even though a jump implies this validator's own
        // outstanding mints (all below the frontier) may be dead: `completed`
        // is pool-aggregated and saturating, so each peer completion advances
        // it and the guard reopens on its own within one batch. Forcing
        // `completed = instantiated` here would release it sooner, but
        // batches complete out of sequence order — some of those mints can
        // still be live below the frontier — and releasing early overlaps
        // batches, which is the pool overshoot the guard exists to prevent.

        let key_role = self.internal_presign_key_role(dwallet_network_encryption_key_id);
        self.dwallet_mpc_metrics
            .internal_presign_ordinals_fast_forwarded_total
            .with_label_values(&[
                curve.to_string().as_str(),
                signature_algorithm.to_string().as_str(),
                key_role,
            ])
            .inc_by(fast_forwarded);

        // A multi-ordinal jump is the rejoin itself — at most one per lag
        // episode, so it is worth a line. The +1 dribble that follows on a
        // validator not minting for the pool at all would be one line per peer
        // completion; the counter metric carries that shape instead.
        if fast_forwarded > 1 {
            info!(
                ?curve,
                ?signature_algorithm,
                ?dwallet_network_encryption_key_id,
                fast_forwarded,
                resumed_at_sequence_number,
                "internal-presign ordinal stream fast-forwarded to the committee's completed \
                 frontier observed in consensus"
            );
        } else {
            debug!(
                ?curve,
                ?signature_algorithm,
                // Carried here too: the `key_role` metric label collapses
                // every non-NOA key onto one series, so the log line is the
                // per-key drill-down.
                ?dwallet_network_encryption_key_id,
                resumed_at_sequence_number,
                "internal-presign ordinal stream advanced to the committee's completed frontier"
            );
        }
    }

    fn instantiate_internal_presign_session(
        &mut self,
        consensus_round: u64,
        network_key_id: NetworkKeyId,
        dwallet_network_encryption_key_id: ObjectID,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
    ) -> bool {
        let counter_key = (network_key_id, curve, signature_algorithm);
        // Seed the pool's ordinal stream on its first touch this process from
        // the persisted fill high-water, NOT from 1 (#1952). The counter is
        // in-memory, so a mid-epoch restart used to restart the stream at 1 —
        // every minted ordinal was one the committee had already completed,
        // and each dead mint was "released" only by a live peer completion
        // advancing the pool-aggregated completed counter, so the offset to
        // the live ordinal window never closed and the validator sat out
        // registry-driven instantiation for the rest of the epoch. The
        // `filled_presign_pool_slots` markers are written on every fill and
        // re-confirmed by the post-restart consensus replay, so the
        // high-water is always at-or-behind the replay frontier: the small
        // remainder is covered by the fast-forward below.
        if !self
            .next_internal_presign_sequence_number
            .contains_key(&counter_key)
        {
            let persisted_high_water = match self.epoch_store.max_filled_presign_pool_slot(
                signature_algorithm,
                dwallet_network_encryption_key_id,
            ) {
                Ok(high_water) => high_water,
                Err(e) => {
                    warn!(
                        error=?e,
                        ?curve,
                        ?signature_algorithm,
                        "failed to read the persisted pool-slot high-water; seeding the \
                         internal-presign ordinal stream from the consensus completion \
                         frontier alone",
                    );
                    None
                }
            };
            // The consensus-observed frontier covers what the persisted
            // high-water cannot: a store that never held this epoch's fills at
            // all (state-synced, wiped, or an epoch entered late), and fills
            // whose slot write failed. The persisted high-water covers what
            // the frontier cannot: a restart replay's completions processed
            // before the key was adopted, which fill slots but resolve no
            // `NetworkKeyId` to record a frontier under. Take whichever is
            // further along (#1952, #1830).
            let observed_frontier = self
                .highest_completed_internal_presign_ordinal
                .get(&counter_key)
                .copied();
            let seed = match persisted_high_water.max(observed_frontier) {
                Some(high_water) => {
                    info!(
                        ?curve,
                        ?signature_algorithm,
                        ?dwallet_network_encryption_key_id,
                        high_water,
                        ?persisted_high_water,
                        ?observed_frontier,
                        "seeded internal-presign ordinal stream from the persisted \
                         pool-slot high-water and the consensus completion frontier \
                         (mid-epoch resume)",
                    );
                    self.internal_presign_mid_epoch_seeded_pools
                        .insert(counter_key);
                    high_water.saturating_add(1)
                }
                None => 1,
            };
            self.next_internal_presign_sequence_number
                .insert(counter_key, seed);
        }

        // Bound on ordinals skipped per mint. The seed lands at-or-behind the
        // replay frontier, so the residue (fills whose replay landed after the
        // first mint's seed read) is a handful of ordinals; hundreds of
        // consecutive already-terminal ordinals past the seed means the seed
        // source is stale relative to the session map, which should never
        // happen.
        const MAX_ORDINAL_FAST_FORWARD_PER_MINT: u64 = 512;
        let mut fast_forwarded: u64 = 0;
        loop {
            let sequence_entry = self
                .next_internal_presign_sequence_number
                .get_mut(&counter_key)
                .expect("seeded above");
            let session_sequence_number = *sequence_entry;
            *sequence_entry += 1;

            // `consensus_round` is logged for traceability but is
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
                &network_key_id.0,
            );

            match self
                .sessions
                .get(&request.session_identifier)
                .map(|s| &s.status)
            {
                // The committee already finished this ordinal (a restart
                // replay reconstructed it terminal). Minting it again can
                // never produce live work — skip ahead so the stream
                // converges on the live window instead of trailing it by a
                // constant offset (#1952).
                Some(
                    SessionStatus::Completed
                    | SessionStatus::ComputationCompleted
                    | SessionStatus::Failed,
                ) => {
                    fast_forwarded += 1;
                    if fast_forwarded >= MAX_ORDINAL_FAST_FORWARD_PER_MINT {
                        ika_types::report_invariant_violation!(
                            "internal_presign_ordinal_fast_forward_exhausted",
                            consensus_round,
                            ?curve,
                            ?signature_algorithm,
                            last_skipped_sequence_number = session_sequence_number,
                            fast_forwarded,
                            "internal-presign ordinal stream is still inside \
                             already-completed history after the per-mint fast-forward \
                             budget; the persisted seed disagrees with the session map — \
                             continuing from here next tick",
                        );
                        return false;
                    }
                    continue;
                }
                // Already instantiated by this process — a mint here would
                // double-count the batch guard.
                Some(SessionStatus::Active { .. }) => return false,
                Some(SessionStatus::WaitingForSessionRequest) | None => {}
            }

            if fast_forwarded > 0 {
                info!(
                    consensus_round,
                    ?curve,
                    ?signature_algorithm,
                    fast_forwarded,
                    resumed_at_sequence_number = session_sequence_number,
                    "internal-presign ordinal stream fast-forwarded past \
                     already-completed sessions and resumed at the live window",
                );
            }

            if let Err(request) =
                self.try_activate_internal_presign_request(consensus_round, request)
            {
                // The key's data isn't locally available yet (typically the VSS
                // pools at epoch entry, before the frozen off-chain validator
                // key set has been ingested; or a key installed on peers but not
                // here). Park the request and retry once per service iteration;
                // peers that already have the data run the session meanwhile,
                // and any of their messages buffer in a
                // `WaitingForSessionRequest` entry until activation.
                info!(
                    consensus_round,
                    ?curve,
                    ?signature_algorithm,
                    ?session_sequence_number,
                    session_identifier=?request.session_identifier,
                    "network key data not ready for internal presign session; parking it for retry",
                );
                self.internal_presign_requests_pending_for_network_key_data
                    .push(ParkedInternalPresignRequest(request));
            }
            // One-shot per pool after a seeded (re)join: the unambiguous
            // "this validator is participating in live registry-driven
            // instantiation again" marker — the #1952 regression scenario
            // gates on this line on the restarted validator.
            if self
                .internal_presign_mid_epoch_seeded_pools
                .remove(&counter_key)
            {
                info!(
                    consensus_round,
                    ?curve,
                    ?signature_algorithm,
                    live_sequence_number = session_sequence_number,
                    // The leading clause up to "mid-epoch restart" is the
                    // literal needle the `restart_spectator` upgrade scenario
                    // waits for; the widening is a suffix so that gate keeps
                    // matching. A rejoin needs no restart — a late key
                    // install or a store without this epoch's fills seeds
                    // mid-stream just the same.
                    "internal presign top-up resumed live instantiation after a \
                     mid-epoch restart or late rejoin",
                );
            }
            return true;
        }
    }

    /// Applies a built internal presign request to the session map: activates
    /// it when its MPC input is constructible, upgrading a
    /// `WaitingForSessionRequest` entry in place (peers that built the input
    /// earlier may already have sent messages, which buffer there and must
    /// survive). Returns `Err(request)` when input construction hit the
    /// not-ready class — the caller decides how to park it. Fatal input
    /// errors fail the session terminally (`Ok`).
    fn try_activate_internal_presign_request(
        &mut self,
        consensus_round: u64,
        request: DWalletSessionRequest,
    ) -> Result<(), Box<DWalletSessionRequest>> {
        let session_identifier = request.session_identifier;

        if let Some(session) = self.sessions.get(&session_identifier)
            && !matches!(session.status, SessionStatus::WaitingForSessionRequest)
        {
            // Already resolved without us (e.g. completed by a quorum of
            // peers before this validator could build the input).
            return Ok(());
        }

        match self.session_input(&request) {
            Ok((public_input, private_input)) => {
                let session_sequence_number = request.session_sequence_number;
                let session_type = request.session_type;
                let protocol_name = DWalletSessionRequestMetricData::from(&request.protocol_data)
                    .name()
                    .to_owned();
                let status = SessionStatus::Active {
                    public_input,
                    private_input,
                    request,
                };
                debug!(
                    status=?status,
                    consensus_round,
                    ?session_sequence_number,
                    ?session_identifier,
                    "instantiating new internal presign session",
                );
                if let Some(session) = self.sessions.get_mut(&session_identifier) {
                    // Normalize a non-MPC placeholder type before activating.
                    // A placeholder can be created with
                    // `SessionComputationType::Native` by an output report that
                    // arrives before the request: the output-receipt path
                    // derives the type from the sender-controlled `is_native()`
                    // flag, and an internal-presign identifier is derivable from
                    // public data alone. Left as-is, `add_message` would drop
                    // every real round message and the computation would route
                    // to the native path and fail `InvalidDWalletProtocolType`
                    // on every honest validator, so the ordinal could never
                    // produce a presign and would hold its pool's top-up guard
                    // closed. Resetting to a fresh MPC buffer discards that; a
                    // legitimate MPC placeholder keeps its buffered messages.
                    // Mirrors `handle_mpc_request` and the NOA sign path.
                    if !matches!(session.computation_type, SessionComputationType::MPC { .. }) {
                        session.computation_type = SessionComputationType::MPC {
                            messages_by_consensus_round: HashMap::new(),
                        };
                    }
                    if let SessionStatus::Active { request, .. } = &status {
                        session.set_request_diagnostic_metadata(request);
                    }
                    session.set_status(status);
                    session.set_request_metadata(session_sequence_number, session_type);
                    session.set_protocol_name(protocol_name);
                } else {
                    self.new_session(
                        &session_identifier,
                        status,
                        None,
                        SessionComputationType::MPC {
                            messages_by_consensus_round: HashMap::new(),
                        },
                    );
                }
                Ok(())
            }
            Err(e) if e.is_network_key_data_not_ready() => Err(Box::new(request)),
            Err(e) => {
                ika_types::report_invariant_violation!(
                    "internal_presign_session_input",
                    error=?e,
                    ?request,
                    "create internal session input from dWallet request with error"
                );
                self.new_session(
                    &session_identifier,
                    SessionStatus::Failed,
                    None,
                    SessionComputationType::MPC {
                        messages_by_consensus_round: HashMap::new(),
                    },
                );
                Ok(())
            }
        }
    }

    /// Retries internal presign sessions parked because their network key's
    /// data wasn't locally available at instantiation time (see
    /// `internal_presign_requests_pending_for_network_key_data`). Called once
    /// per service iteration — the inputs it waits on (network-key install,
    /// off-chain validator key ingest) complete on wall-clock time,
    /// independently of consensus rounds.
    /// Parks one synthetic internal presign request, so a test can drive the
    /// structure an MPC-inactive epoch must not accumulate (#2119).
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn park_internal_presign_request_for_testing(&mut self) {
        use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
        self.internal_presign_requests_pending_for_network_key_data
            .push(ParkedInternalPresignRequest(Box::new(
                crate::dwallet_session_request::DWalletSessionRequest {
                    counterparty_chain: None,
                    session_type: SessionType::System,
                    session_identifier: SessionIdentifier::new(SessionType::System, [9; 32]),
                    session_sequence_number: Some(1),
                    protocol_data:
                        crate::request_protocol_data::ProtocolData::NetworkEncryptionKeyDkg {
                            data: crate::request_protocol_data::NetworkEncryptionKeyDkgData {},
                            dwallet_network_encryption_key_id:
                                sui_types::base_types::ObjectID::random(),
                        },
                    epoch: 1,
                    requires_network_key_data: true,
                    requires_next_active_committee: false,
                    pulled: false,
                },
            )));
    }

    pub(crate) fn retry_internal_presign_requests_pending_for_network_key_data(&mut self) {
        if self
            .internal_presign_requests_pending_for_network_key_data
            .is_empty()
        {
            return;
        }

        let parked = mem::take(&mut self.internal_presign_requests_pending_for_network_key_data);
        for ParkedInternalPresignRequest(request) in parked {
            let request = *request;
            let session_identifier = request.session_identifier;
            let session_sequence_number = request.session_sequence_number;
            // Retry has no consensus-round context; 0 marks "activated on a
            // service tick" in the debug log.
            match self.try_activate_internal_presign_request(0, request) {
                Ok(()) => {
                    // Log only a real parked→active transition (not the
                    // already-resolved drop or a terminal failure) — the
                    // stall playbook pairs this line with the park line.
                    if self
                        .sessions
                        .get(&session_identifier)
                        .is_some_and(|session| {
                            matches!(session.status, SessionStatus::Active { .. })
                        })
                    {
                        info!(
                            session_identifier=?session_identifier,
                            ?session_sequence_number,
                            "network key data arrived; activating parked internal presign session",
                        );
                    }
                }
                Err(request) => {
                    // Input still not constructible — keep it parked (silently:
                    // this runs every service iteration).
                    self.internal_presign_requests_pending_for_network_key_data
                        .push(ParkedInternalPresignRequest(request));
                }
            }
        }
    }

    /// Instantiates a generic network-owned-address sign session.
    ///
    /// Creates the sign session using the presign assigned in consensus order by
    /// the service layer (passed in as raw bytes and wrapped here). Returns
    /// `true` if the session was successfully instantiated, `false` on error.
    pub(super) fn instantiate_network_owned_address_sign_session(
        &mut self,
        message: Vec<u8>,
        curve: DWalletCurve,
        signature_algorithm: DWalletSignatureAlgorithm,
        hash_scheme: DWalletHashScheme,
        presign_session_id: SessionIdentifier,
        presign_blending_index: u16,
        presign: Vec<u8>,
        dwallet_network_encryption_key_id: ObjectID,
    ) -> bool {
        // The network key is the one the presign was popped from in consensus
        // order (carried through the demand and the assignment), NOT a locally
        // re-resolved key: if the min-by-dkg-epoch resolution shifted between
        // announce and instantiate, re-resolving here would sign under a key the
        // presign wasn't generated for → InvalidParameters. Using the assigned
        // key for BOTH the presign and the session keeps them consistent.
        let hash_scheme_group: group::HashScheme = hash_scheme.into();
        let network_key_identity_bytes = match self
            .network_keys
            .get_network_encryption_key_public_data(&dwallet_network_encryption_key_id)
        {
            // Flip-invariant NetworkKeyId basis (see `instantiate_internal_presign_session`).
            Ok(key_data) => key_data
                .network_key_id()
                .map(|id| id.0.to_vec())
                .unwrap_or_else(|_| key_data.network_dkg_output().as_bytes().to_vec()),
            Err(e) => {
                ika_types::report_invariant_violation!(
                    "noa_sign_network_key_missing",
                    ?dwallet_network_encryption_key_id,
                    error = ?e,
                    "Failed to get network encryption key data for network-owned-address sign session"
                );
                return false;
            }
        };

        // The presign is assigned in consensus-delivery order by the service
        // layer (`assign_presign_for_demand`) and passed in as raw bytes, so every
        // validator pairs the same presign with the same demand. This function
        // no longer pops from the pool — doing so used LOCAL instantiation
        // order, which diverged across a staggered restart and wedged the epoch.
        // Wrap for the sign-input path: AHE presigns use V2, Fast Schnorr (VSS)
        // use V3.
        let versioned = if signature_algorithm.is_vss() {
            VersionedPresignOutput::V3(presign)
        } else {
            VersionedPresignOutput::V2(presign)
        };
        let wrapped_presign = match bcs::to_bytes(&versioned) {
            Ok(bytes) => bytes,
            Err(e) => {
                ika_types::report_invariant_violation!(
                    "noa_sign_presign_wrap",
                    error = ?e,
                    "Failed to wrap presign for network-owned-address sign session"
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
            &network_key_identity_bytes,
            message.clone(),
            wrapped_presign,
        );

        let session_identifier = request.session_identifier;
        let session_sequence_number = request.session_sequence_number;
        let session_type = request.session_type;
        let protocol_name = DWalletSessionRequestMetricData::from(&request.protocol_data)
            .name()
            .to_owned();

        let status = self.session_status_from_request(request, true);

        info!(
            ?curve,
            ?signature_algorithm,
            ?session_identifier,
            ?presign_session_id,
            presign_blending_index,
            message_length = message.len(),
            "instantiating network-owned-address sign session",
        );

        // Upgrade an existing `WaitingForSessionRequest` placeholder in place
        // rather than overwriting it with a fresh session. When this validator
        // instantiates the sign late — it restarted, or its signing key /
        // presign became available only after peers had already started the
        // round — the message-receipt path may have created a placeholder that
        // holds peers' buffered round messages. A blind `new_session` replaces
        // that placeholder with an empty message buffer, dropping those
        // messages; the late validator then can never advance (peers' earlier
        // rounds arrived in consensus rounds it has already processed and are
        // never redelivered), leaving the threshold sign permanently below
        // quorum and wedging the epoch on NOA-checkpoint finalization. The
        // event and internal-presign activation paths handle the same race
        // (`handle_mpc_request`, `try_activate_internal_presign_request`); the
        // two guards below match their short-circuit and type-normalization.
        if let Some(session) = self.sessions.get_mut(&session_identifier) {
            // A quorum of peers may have completed this sign 3-of-4 while our
            // own request was still parked (key/presign not yet local). Don't
            // flip an already-resolved session back to `Active` — that would
            // strand it `Active` forever and pin this validator's idle status.
            // The presign was assigned to this demand in consensus order
            // upstream and passed in, so every validator pairs the same presign
            // with the same demand regardless of who ran the session first.
            // Mirrors the non-`WaitingForSessionRequest` short-circuit in
            // `try_activate_internal_presign_request`.
            if !matches!(session.status, SessionStatus::WaitingForSessionRequest) {
                return true;
            }
            // Normalize a non-MPC placeholder type before activating. A
            // placeholder can be created with `SessionComputationType::Native`
            // by an output report that arrives before the request: the
            // output-receipt path derives the type from the sender-controlled
            // `is_native()` flag and the NOA session id is predictable from
            // public inputs. Left as-is, `add_message` would drop every real
            // round message and the sign would route to the native path and
            // fail `InvalidDWalletProtocolType` on every honest validator — one
            // byzantine message wedging the epoch unattributably. Resetting to a
            // fresh MPC buffer discards the poison; a legitimate MPC placeholder
            // keeps its buffered messages. Mirrors `handle_mpc_request`.
            if !matches!(session.computation_type, SessionComputationType::MPC { .. }) {
                session.computation_type = SessionComputationType::MPC {
                    messages_by_consensus_round: HashMap::new(),
                };
            }
            if let SessionStatus::Active { request, .. } = &status {
                session.set_request_diagnostic_metadata(request);
            }
            session.set_status(status);
            session.set_request_metadata(session_sequence_number, session_type);
            session.set_protocol_name(protocol_name);
        } else {
            self.new_session(
                &session_identifier,
                status,
                None,
                SessionComputationType::MPC {
                    messages_by_consensus_round: HashMap::new(),
                },
            );
        }
        true
    }

    /// Checks if this manager has an network-owned-address signing network key available
    pub(super) fn has_network_owned_address_signing_network_key(&self) -> bool {
        self.network_owned_address_signing_network_encryption_key_id()
            .is_some()
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
    /// Returns `true` when the frozen set is still empty
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
        // Once the gate has converged (all frozen-set blobs present + valid) it
        // stays converged for this epoch, so skip the per-tick reads+decodes.
        if self.local_mpc_data_ready_latched.load(Ordering::Relaxed) {
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
        // Converged: every frozen-set blob is present + valid. Latch so later
        // ticks short-circuit (monotonic for this epoch's fixed frozen set).
        self.local_mpc_data_ready_latched
            .store(true, Ordering::Relaxed);
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
        let session_origin = new_session.origin;
        if session_origin == SessionOrigin::ReconstructedFromConsensus {
            self.dwallet_mpc_metrics
                .sessions_reconstructed_total
                .with_label_values(&[session_type_label(session_identifier.session_type())])
                .inc();
        }

        info!(
            party_id=self.party_id,
            authority=?self.validator_name,
            active,
            session_origin = session_origin.label(),
            ?session_identifier,
            last_session_to_complete_in_current_epoch=?self.last_session_to_complete_in_current_epoch,
            "Adding a new MPC session to the active sessions map",
        );

        self.sessions.insert(*session_identifier, new_session);
    }

    /// Feed the catch-up gate (issue #2023) one observation of how far MPC
    /// round processing trails the consensus tip.
    ///
    /// Called by the service once per service-loop iteration at the entry of
    /// its round drain, with `tip_round` = the head of the persisted
    /// per-round MPC stream (`last_dwallet_mpc_message_round`, the newest
    /// consensus round available for this service to read — already in hand
    /// there, so the gate costs no extra DB read) and `last_processed_round`
    /// = the drain cursor before this iteration's drain. The drain always
    /// runs to the tip it read, so this entry gap is exactly the backlog the
    /// iteration is about to chew through — the live capture's oscillating
    /// 545-7,346-round gap is this value. `None` cursor (nothing processed
    /// yet, i.e. the first iteration after a restart) counts the full
    /// backlog, which is precisely the mid-epoch-restart entry condition.
    pub(crate) fn observe_consensus_round_gap(
        &mut self,
        tip_round: u64,
        last_processed_round: Option<u64>,
    ) {
        let gap_rounds = tip_round.saturating_sub(last_processed_round.unwrap_or(0));
        match self.catchup_gate.update(gap_rounds) {
            CatchUpTransition::Entered => {
                info!(
                    gap_rounds,
                    tip_round,
                    ?last_processed_round,
                    enter_threshold = CATCH_UP_ENTER_GAP_ROUNDS,
                    exit_threshold = CATCH_UP_EXIT_GAP_ROUNDS,
                    "MPC service entered catch-up mode: suppressing new internal-presign and \
                     user-session computations until the consensus-round backlog drains \
                     (issue #2023)"
                );
            }
            CatchUpTransition::Exited => {
                info!(
                    gap_rounds,
                    tip_round,
                    ?last_processed_round,
                    enter_threshold = CATCH_UP_ENTER_GAP_ROUNDS,
                    exit_threshold = CATCH_UP_EXIT_GAP_ROUNDS,
                    "MPC service exited catch-up mode: the consensus-round backlog drained, \
                     resuming all cryptographic computations"
                );
            }
            CatchUpTransition::Unchanged => {}
        }
        self.dwallet_mpc_metrics
            .catchup_mode
            .set(self.catchup_gate.is_catching_up() as i64);
        // Exported on EVERY observation, not just on a transition: the logs
        // above only fire when the gate flips, so the whole span in between —
        // which is the entire catch-up — would otherwise show no progress
        // signal at all. The gauge's slope is what says whether the backlog is
        // draining or the validator is stuck.
        self.dwallet_mpc_metrics
            .catchup_gap_rounds
            .set(i64::try_from(gap_rounds).unwrap_or(i64::MAX));
    }

    /// Whether the catch-up gate is currently engaged.
    ///
    /// Read straight off the gate, never off the `catchup_mode` gauge: that
    /// gauge is published by this service's loop, so it latches at its last
    /// value the moment the loop dies — and the consensus-path stall detector
    /// this feeds exists precisely for the case where the loop has died.
    pub(crate) fn is_catching_up(&self) -> bool {
        self.catchup_gate.is_catching_up()
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
        let in_catch_up = self.catchup_gate.is_catching_up();
        let mut catch_up_suppressed_user_sessions: u64 = 0;
        let mut catch_up_suppressed_internal_presign_sessions: u64 = 0;

        let mut ready_to_advance_sessions: Vec<_> = self
            .sessions
            .values()
            .filter_map(|session| {
                let SessionStatus::Active { request, .. } = &session.status else {
                    return None;
                };

                // Always advance system and internal sessions, and only advance user session
                // if they come before the last session to complete in the current epoch (at the current time).
                let should_advance = match request.session_type {
                    SessionType::User => {
                        if request.session_sequence_number.is_none() {
                            ika_types::report_invariant_violation!(
                                "user_session_sequence_missing",
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

                // Catch-up gate (issue #2023): while the round-processing
                // cursor trails the consensus tip beyond the trap radius,
                // withhold NEW computations for the high-volume session
                // types — computing them would chase sessions that already
                // completed network-wide and pin the drain below tip rate.
                // System-critical types are exempt (see
                // `computation_suppressible_during_catch_up`); everything
                // else about these sessions (message handling, quorum
                // observation, terminal bookkeeping) continues unchanged,
                // and the check is two cheap reads per session per tick.
                if in_catch_up && computation_suppressible_during_catch_up(request.session_type) {
                    match request.session_type {
                        SessionType::User => catch_up_suppressed_user_sessions += 1,
                        _ => catch_up_suppressed_internal_presign_sessions += 1,
                    }
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

        ready_to_advance_sessions.sort_by_key(|&(_, request)| request);

        // Publish how much would-be computation the gate is shedding this
        // tick (bulk `inc_by` — the per-session path stays two integer
        // reads, no label lookups).
        if catch_up_suppressed_user_sessions > 0 {
            self.dwallet_mpc_metrics
                .catchup_suppressed_computations_total
                .with_label_values(&[session_type_label(SessionType::User)])
                .inc_by(catch_up_suppressed_user_sessions);
        }
        if catch_up_suppressed_internal_presign_sessions > 0 {
            self.dwallet_mpc_metrics
                .catchup_suppressed_computations_total
                .with_label_values(&[session_type_label(SessionType::InternalPresign)])
                .inc_by(catch_up_suppressed_internal_presign_sessions);
        }

        // Suppressed sessions are still pending work: count them toward the
        // idle computation so a catching-up validator never reports itself
        // idle — an idle report would drive network-wide internal-presign
        // idle-fill, minting MORE of exactly the load the gate is shedding.
        let number_of_ready_to_advance_sessions = ready_to_advance_sessions.len()
            + (catch_up_suppressed_user_sessions + catch_up_suppressed_internal_presign_sessions)
                as usize;

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
                    ika_types::report_invariant_violation!(
                        "inactive_computation_session",
                        session_identifier=?session.session_identifier,
                        "session is not active, cannot perform cryptographic computation",
                    );

                    return None;
                };

                let protocol_metric_data =
                    DWalletSessionRequestMetricData::from(&request.protocol_data);
                let protocol_cryptographic_data = match self.generate_protocol_cryptographic_data(
                    &session.computation_type,
                    &request.protocol_data,
                    last_read_consensus_round,
                    public_input.clone(),
                    &self.protocol_config,
                ) {
                    Ok(protocol_cryptographic_data) => {
                        let ready_result = if protocol_cryptographic_data.is_some() {
                            READY_RESULT_READY
                        } else {
                            READY_RESULT_NOT_READY
                        };
                        self.dwallet_mpc_metrics
                            .ready_to_advance_result_total
                            .with_label_values(&[protocol_metric_data.name(), ready_result])
                            .inc();

                        protocol_cryptographic_data
                    }
                    Err(e) => {
                        // Counted unconditionally (unlike the once-per-session
                        // log dedup below) so the error rate stays visible for
                        // a session stuck failing every tick.
                        self.dwallet_mpc_metrics
                            .ready_to_advance_result_total
                            .with_label_values(&[protocol_metric_data.name(), READY_RESULT_ERR])
                            .inc();
                        self.dwallet_mpc_metrics
                            .protocol_data_generation_errors_total
                            .with_label_values(&[protocol_metric_data.name(), e.kind()])
                            .inc();

                        // The skip is correct (the session simply isn't
                        // advanceable this tick); the silence was the bug.
                        failed_cryptographic_data_generations.push((
                            session.session_identifier,
                            protocol_metric_data,
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
            let computation_was_already_seen = self
                .cryptographic_computations_orchestrator
                .has_seen_computation(&computation_id);
            let spawned_computation = self
                .cryptographic_computations_orchestrator
                .try_spawn_cryptographic_computation(
                    computation_id,
                    computation_request,
                    self.dwallet_mpc_metrics.clone(),
                )
                .await;

            if spawned_computation
                && !computation_was_already_seen
                && let Some(session) = self.sessions.get_mut(&computation_id.session_identifier)
            {
                session.record_computation_started(
                    computation_id.consensus_round,
                    computation_id.mpc_round,
                    computation_id.attempt_number,
                );
            }

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
    pub(crate) async fn poll_pending_network_key_instantiations(&mut self) {
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
                        let key_data = self.adopted_network_key_data.get(&key_id).cloned();
                        if let Some(key_data) = key_data {
                            if !key_data.network_dkg_public_output.is_empty() {
                                // Mirror the CANONICAL DKG output: the adopted
                                // anchor, which every validator holding this
                                // key agrees on byte-for-byte.
                                let canonical_dkg_output = &key_data.network_dkg_public_output;
                                if let Err(e) = self
                                    .epoch_store
                                    .cache_network_dkg_output(key_id, canonical_dkg_output)
                                {
                                    warn!(
                                        error = ?e,
                                        ?key_id,
                                        "failed to cache DKG output digest from adopted data"
                                    );
                                }
                                // Surface the canonical DKG-output version for
                                // observability (4 = aggregated, the end
                                // state; V3 is undecodable and V1/V2 are the
                                // pre-migration anchors).
                                let canonical_version: i64 =
                                    key.network_dkg_output().version() as i64;
                                self.dwallet_mpc_metrics
                                    .network_encryption_key_canonical_dkg_output_version
                                    .set(canonical_version);
                                // Same observability for the reconfiguration
                                // output: 3 = pre-aggregation (no longer
                                // produced; a V3 output is a hard error now),
                                // 4 = aggregated (the protocol-v5 format flip),
                                // 0 = none yet.
                                let reconfiguration_version: i64 =
                                    key.latest_network_reconfiguration_public_output()
                                        .map(|output| output.version())
                                        .unwrap_or(0) as i64;
                                self.dwallet_mpc_metrics
                                    .network_encryption_key_latest_reconfiguration_output_version
                                    .set(reconfiguration_version);
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
                        // A confirmed instantiation ends the restart-recovery
                        // read: un-flag the key so the sui-connector sync task
                        // returns it to the off-chain read path. Removed ONLY
                        // here (confirmed-instantiated), never on the
                        // decrypt-fail / epoch-mismatch branches above — a key
                        // that still cannot instantiate keeps its
                        // chain-sourced overlay and retries.
                        if self.stranded_network_keys.load().contains(&key_id) {
                            self.stranded_network_keys.rcu(|keys| {
                                let mut keys = (**keys).clone();
                                keys.remove(&key_id);
                                Arc::new(keys)
                            });
                        }
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
                // Never re-attempt bytes that already failed, regardless of
                // which branch below would otherwise select them. The
                // instantiation/decryption is deterministic, so identical
                // bytes fail identically; retry only once the bytes change
                // (the output carrying our share arrives). Without this guard
                // the `Some(prev)` comparison below re-selects failing bytes
                // every poll (they differ from the last *successfully*
                // instantiated ones by definition), burning a heavy
                // class-groups decrypt per tick and starving the service loop
                // — checkpoints (including EndOfPublish) never certify and
                // epoch advance wedges behind the decryption failure.
                if self
                    .last_failed_network_key_data
                    .get(key_id)
                    .is_some_and(|failed| {
                        failed.network_dkg_public_output == key_data.network_dkg_public_output
                            && failed.current_reconfiguration_public_output
                                == key_data.current_reconfiguration_public_output
                            && failed.state == key_data.state
                    })
                {
                    return false;
                }
                if !self
                    .network_keys
                    .network_encryption_keys
                    .contains_key(key_id)
                {
                    return true;
                }
                match self.last_instantiated_network_key_data.get(key_id) {
                    // Never instantiated this key. The already-failed bytes
                    // are filtered out above, so attempt it.
                    None => true,
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
    ) -> Option<OutputsToFinalize> {
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
            self.emit_session_anomaly(
                session_identifier,
                MpcAnomalyKind::InvalidOutputReceived,
                MpcAnomalyContext {
                    current_consensus_round: Some(consensus_round),
                    source_authority: Some(sender_authority),
                    trigger_conditions: vec!["output_sender_not_in_committee"],
                    error_code: Some("unknown_authority"),
                    ..Default::default()
                },
            );

            return None;
        };

        if !self.sessions.contains_key(&session_identifier) {
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
                    self.emit_session_anomaly(
                        session_identifier,
                        MpcAnomalyKind::InvalidOutputReceived,
                        MpcAnomalyContext {
                            current_consensus_round: Some(consensus_round),
                            source_authority: Some(sender_authority),
                            source_party_id: Some(sender_party_id),
                            trigger_conditions: vec!["invalid_output_computation_type"],
                            error_code: Some("invalid_output_computation_type"),
                            ..Default::default()
                        },
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
                session_computation_type,
            );
        }
        // Safe to `unwrap()`: the session existed or was just created.
        let session = self.sessions.get_mut(&session_identifier).unwrap();

        let add_output_result = session.add_output(consensus_round, sender_party_id, output_report);

        let outputs_by_consensus_round = session.outputs_by_consensus_round().clone();
        match add_output_result {
            AddOutputResult::Invalid { error_code } => {
                self.emit_session_anomaly(
                    session_identifier,
                    MpcAnomalyKind::InvalidOutputReceived,
                    MpcAnomalyContext {
                        current_consensus_round: Some(consensus_round),
                        source_authority: Some(sender_authority),
                        source_party_id: Some(sender_party_id),
                        trigger_conditions: vec!["invalid_mpc_output_received"],
                        error_code: Some(error_code),
                        ..Default::default()
                    },
                );
                return None;
            }
            AddOutputResult::Accepted {
                conflicting_output_digests,
                own_rejected_output,
            } => {
                if conflicting_output_digests {
                    self.emit_session_anomaly(
                        session_identifier,
                        MpcAnomalyKind::ConflictingOutputDigests,
                        MpcAnomalyContext {
                            current_consensus_round: Some(consensus_round),
                            trigger_conditions: vec!["more_than_one_output_digest_observed"],
                            ..Default::default()
                        },
                    );
                }
                if own_rejected_output {
                    self.emit_session_anomaly(
                        session_identifier,
                        MpcAnomalyKind::OwnRejectedOutputObserved,
                        MpcAnomalyContext {
                            current_consensus_round: Some(consensus_round),
                            trigger_conditions: vec!["own_rejected_output_observed_in_consensus"],
                            ..Default::default()
                        },
                    );
                }
            }
        }

        if let Some(mut outputs_to_finalize) =
            self.build_outputs_to_finalize(&session_identifier, outputs_by_consensus_round)
        {
            self.record_malicious_actors(&session_identifier, &outputs_to_finalize);

            match outputs_to_finalize.majority_vote.clone() {
                DWalletMPCOutputKind::Internal { output } => {
                    self.handle_mpc_internal_output(session_identifier, output);
                }
                DWalletMPCOutputKind::External { .. } => {}
            }

            if let DWalletMPCOutputKind::External { output } =
                &mut outputs_to_finalize.majority_vote
            {
                Self::reject_duplicate_make_public_responses(
                    &mut self.made_public_dwallets,
                    output,
                );
            }

            Some(outputs_to_finalize)
        } else {
            None
        }
    }

    /// Enforces one successful make-public response per dWallet per epoch.
    ///
    /// A dWallet's user secret key share is made public once; the first agreed
    /// response is the one that sets it, and a later one is reported as
    /// rejected. That is also the honest answer to the request, since the share
    /// is public by then either way.
    ///
    /// Deliberately operates on the AGREED output, after the majority vote:
    /// every validator then applies it to identical messages in identical
    /// consensus order and reaches the same answer. Doing this while building
    /// this node's PROPOSED output would instead make the output itself
    /// diverge between validators, which peers read as evidence of malice.
    fn reject_duplicate_make_public_responses(
        made_public_dwallets: &mut HashSet<Vec<u8>>,
        messages: &mut [DWalletCheckpointMessageKind],
    ) {
        for message in messages.iter_mut() {
            let DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(output) =
                message
            else {
                continue;
            };
            if output.rejected {
                continue;
            }
            if !made_public_dwallets.insert(output.dwallet_id.clone()) {
                warn!(
                    dwallet_id=?output.dwallet_id,
                    session_sequence_number = output.session_sequence_number,
                    "a make-public response was already agreed for this dWallet this epoch; \
                     reporting the later one as rejected"
                );
                output.rejected = true;
            }
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
                    DWalletSignatureAlgorithm::TaprootVSS => {
                        self.record_internal_presign_output::<Secp256k1TaprootVSSProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::EdDSAVSS => {
                        self.record_internal_presign_output::<Curve25519EdDSAVSSProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                    DWalletSignatureAlgorithm::SchnorrkelVSS => {
                        self.record_internal_presign_output::<RistrettoSchnorrkelVSSProtocol>(
                            signature_algorithm,
                            dwallet_network_encryption_key_id,
                            session_sequence_number,
                            session_identifier,
                            output,
                        );
                    }
                }
                // Saturating at `instantiated`: a batch presumed dead by the
                // stale-batch expiry already had its slot reconciled, so a
                // late completion must not push `completed` past
                // `instantiated` — the top-up skip compares them for
                // equality and would block the pool permanently. Keyed by the
                // same content-derived `NetworkKeyId` the top-up loop uses.
                match self.classify_internal_presign_completion(&dwallet_network_encryption_key_id)
                {
                    InternalPresignCompletionKey::Resolved(network_key_id) => {
                        // Consensus-anchored convergence of the pool's ordinal
                        // stream, before the batch bookkeeping below (#1830).
                        self.observe_completed_internal_presign_ordinal(
                            network_key_id,
                            dwallet_network_encryption_key_id,
                            curve,
                            signature_algorithm,
                            session_sequence_number,
                        );
                        let instantiated = self
                            .instantiated_internal_presign_sessions
                            .get(&(network_key_id, curve, signature_algorithm))
                            .copied()
                            .unwrap_or(0);
                        let completed = self
                            .completed_internal_presign_sessions
                            .entry((network_key_id, curve, signature_algorithm))
                            .or_insert(0);
                        if *completed < instantiated {
                            *completed += 1;
                        }
                    }
                    InternalPresignCompletionKey::AdoptedUnresolvable => {
                        ika_types::report_invariant_violation!(
                            "internal_presign_output_key_id_missing",
                            ?dwallet_network_encryption_key_id,
                            "completed internal presign output for an ADOPTED key with no resolvable \
                         NetworkKeyId; completion counter not advanced"
                        );
                    }
                    // Deduped to once per key: a restart replays a burst of
                    // these, but a key that is NEVER adopted starves its
                    // pool for the epoch, so the first one must not be
                    // silent.
                    InternalPresignCompletionKey::NotAdopted => {
                        if self
                            .reported_unadopted_internal_presign_completions
                            .insert(dwallet_network_encryption_key_id)
                        {
                            info!(
                                ?dwallet_network_encryption_key_id,
                                "completed internal presign output for a key not adopted here yet \
                                 (ordinarily a pre-adoption consensus replay after a restart); \
                                 completion counter not advanced. If this key is never adopted, \
                                 its internal presign pool will not refill this epoch"
                            );
                        } else {
                            debug!(
                                ?dwallet_network_encryption_key_id,
                                "completed internal presign output for a key not adopted here yet; \
                                 completion counter not advanced"
                            );
                        }
                    }
                }
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
                    ika_types::report_invariant_violation!(
                        "noa_sign_output_channel",
                        ?session_identifier,
                        error = ?e,
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
                ika_types::report_invariant_violation!(
                    "internal_presign_output_deserialize",
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
                ika_types::report_invariant_violation!(
                    "internal_presign_output_serialize",
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

    #[cfg(test)]
    pub(crate) fn untracked_anomaly_count(&self) -> usize {
        self.untracked_anomalies.len()
    }

    /// Records malicious actors that were identified as part of the execution of an MPC session.
    pub(crate) fn record_malicious_actors(
        &mut self,
        session_identifier: &SessionIdentifier,
        outputs_to_finalize: &OutputsToFinalize,
    ) {
        let authorities = &outputs_to_finalize.final_malicious_authorities;
        if !authorities.is_empty() {
            self.malicious_actors.extend(authorities);

            if self.is_malicious_actor(&self.validator_name) {
                self.recognized_self_as_malicious = true;
                self.recognized_self_as_malicious_session = Some(*session_identifier);

                let reason = outputs_to_finalize
                    .vote_diagnostics
                    .local_authority_malicious_reason;
                // Fleet-visible, not just local: this validator has concluded
                // it diverged from its peers, and without a metric that fact
                // reaches nobody but this operator. Labels are the two fixed
                // enums only — a session id or authority here would be
                // unbounded AND would identify the operator to every scraper.
                self.dwallet_mpc_metrics
                    .self_malicious_total
                    .with_label_values(&[
                        reason.map_or("unspecified", LocalAuthorityMaliciousReason::metric_label),
                        session_type_label(session_identifier.session_type()),
                    ])
                    .inc();

                error!(
                    ?session_identifier,
                    authority=?self.validator_name,
                    local_authority_malicious_reason = ?reason,
                    "node recognized itself as malicious"
                );
            }

            error!(
                ?session_identifier,
                authority=?self.validator_name,
                malicious_voters = ?outputs_to_finalize.malicious_voters,
                reported_malicious_authorities = ?outputs_to_finalize
                    .reported_malicious_authorities,
                final_malicious_authorities = ?authorities,
                local_authority_malicious_reason = ?outputs_to_finalize
                    .vote_diagnostics
                    .local_authority_malicious_reason,
                "malicious actors identified & recorded"
            );

            // Scrapable signal that detection fired (the cross-binary
            // malicious-detection test asserts on this instead of grepping logs).
            self.dwallet_mpc_metrics
                .malicious_actors_count
                .set(self.malicious_actors.len() as i64);
        }
    }

    /// Wire the directory self-malicious diagnostic snapshots are persisted
    /// to. Called once by the service at construction; unset (tests) means
    /// persistence is off.
    pub(crate) fn set_diagnostics_dir(&mut self, dir: std::path::PathBuf) {
        self.diagnostics_dir = Some(dir);
    }

    /// Persist a diagnostic that identifies THIS validator as malicious (see
    /// [`persist_malicious_diagnostic_file`] for why disk, not just logs).
    /// Failure is logged, never propagated — this runs on the conviction
    /// path, where the service is about to stop, and a failed write must not
    /// change behavior.
    fn persist_malicious_diagnostic(
        &self,
        anomaly_kind: MpcAnomalyKind,
        session_label: &str,
        diagnostic_json: &str,
    ) {
        let Some(dir) = &self.diagnostics_dir else {
            return;
        };
        match persist_malicious_diagnostic_file(
            dir,
            self.epoch_id,
            anomaly_kind.label(),
            session_label,
            diagnostic_json,
        ) {
            // Error level on purpose: this line belongs next to the other
            // conviction-time errors so an operator filtering on ERROR finds
            // the pointer to the preserved evidence.
            Ok(path) => error!(
                path = %path.display(),
                "persisted self-malicious diagnostic snapshot to disk (survives log rotation); attach this file when reporting"
            ),
            Err(err) => warn!(
                error = ?err,
                dir = %dir.display(),
                "failed to persist the self-malicious diagnostic snapshot"
            ),
        }
    }

    pub(crate) fn emit_session_anomaly(
        &mut self,
        session_identifier: SessionIdentifier,
        anomaly_kind: MpcAnomalyKind,
        mut context: MpcAnomalyContext,
    ) {
        if context.running_computation_count == 0 {
            context.running_computation_count = self
                .cryptographic_computations_orchestrator
                .running_computation_count_for_session(&session_identifier);
        }
        let Some(session) = self.sessions.get_mut(&session_identifier) else {
            if self
                .untracked_anomalies
                .contains(&(session_identifier, anomaly_kind))
            {
                return;
            }
            if self.untracked_anomalies.len() >= MAX_UNTRACKED_ANOMALIES {
                self.dwallet_mpc_metrics
                    .anomaly_snapshots_dropped_total
                    .with_label_values(&["untracked_capacity"])
                    .inc();
                return;
            }
            self.untracked_anomalies
                .insert((session_identifier, anomaly_kind));
            let session_type = session_identifier.session_type();
            self.record_session_anomaly_metrics(
                anomaly_kind,
                session_type,
                &context.trigger_conditions,
            );
            let diagnostic_json = serde_json::to_string(&context);
            let diagnostic_serialization_succeeded = diagnostic_json.is_ok();
            let diagnostic_json = diagnostic_json
                .unwrap_or_else(|_| r#"{"diagnostic_serialization_failed":true}"#.to_owned());
            if anomaly_kind.severity() == "error" {
                error!(
                    target: "ika_mpc_diagnostics",
                    event = "mpc_session_anomaly",
                    schema_version = MPC_ANOMALY_SCHEMA_VERSION,
                    diagnostic_shape = "context",
                    anomaly_kind = anomaly_kind.label(),
                    severity = anomaly_kind.severity(),
                    session_id = %hex::encode(session_identifier.into_bytes()),
                    session_type = session_type_label(session_type),
                    epoch = self.epoch_id,
                    local_authority = ?self.validator_name,
                    local_party_id = self.party_id,
                    tracked_session = false,
                    diagnostic_serialization_succeeded,
                    error_code = context.error_code.unwrap_or("none"),
                    error_backtrace_present = context.error_backtrace.is_some(),
                    error_backtrace_truncated = context.error_backtrace_truncated,
                    local_authority_malicious = context.local_authority_malicious,
                    diagnostic_json = %diagnostic_json,
                    "MPC anomaly occurred after session state was unavailable"
                );
            } else {
                warn!(
                    target: "ika_mpc_diagnostics",
                    event = "mpc_session_anomaly",
                    schema_version = MPC_ANOMALY_SCHEMA_VERSION,
                    diagnostic_shape = "context",
                    anomaly_kind = anomaly_kind.label(),
                    severity = anomaly_kind.severity(),
                    session_id = %hex::encode(session_identifier.into_bytes()),
                    session_type = session_type_label(session_type),
                    epoch = self.epoch_id,
                    local_authority = ?self.validator_name,
                    local_party_id = self.party_id,
                    tracked_session = false,
                    diagnostic_serialization_succeeded,
                    error_code = context.error_code.unwrap_or("none"),
                    error_backtrace_present = context.error_backtrace.is_some(),
                    error_backtrace_truncated = context.error_backtrace_truncated,
                    local_authority_malicious = context.local_authority_malicious,
                    diagnostic_json = %diagnostic_json,
                    "MPC anomaly occurred after session state was unavailable"
                );
            }
            if context.local_authority_malicious {
                self.persist_malicious_diagnostic(
                    anomaly_kind,
                    &hex::encode(session_identifier.into_bytes()),
                    &diagnostic_json,
                );
            }
            return;
        };
        let Some(snapshot) = session.anomaly_snapshot(anomaly_kind, self.epoch_id, context) else {
            return;
        };
        self.record_session_anomaly_metrics(
            anomaly_kind,
            snapshot.session_type,
            &snapshot.trigger_conditions,
        );
        let diagnostic_json = snapshot.to_json();
        let diagnostic_serialization_succeeded = diagnostic_json.is_ok();
        let diagnostic_json = diagnostic_json
            .unwrap_or_else(|_| r#"{"diagnostic_serialization_failed":true}"#.to_owned());

        if anomaly_kind.severity() == "error" {
            error!(
                target: "ika_mpc_diagnostics",
                event = "mpc_session_anomaly",
                schema_version = MPC_ANOMALY_SCHEMA_VERSION,
                diagnostic_shape = "snapshot",
                anomaly_kind = anomaly_kind.label(),
                severity = anomaly_kind.severity(),
                session_id = %hex::encode(snapshot.session_id),
                session_type = session_type_label(snapshot.session_type),
                session_origin = snapshot.session_origin.label(),
                epoch = snapshot.epoch,
                local_party_id = snapshot.local_party_id,
                tracked_session = true,
                diagnostic_serialization_succeeded,
                local_output_observed = snapshot.local_output_observed,
                local_authority_malicious = snapshot.local_authority_malicious,
                quorum_reached_without_local_output = snapshot.quorum_reached_without_local_output,
                local_output_rejected = ?snapshot.local_output_rejected,
                error_code = snapshot.error_code.unwrap_or("none"),
                error_backtrace_present = snapshot.error_backtrace.is_some(),
                error_backtrace_truncated = snapshot.error_backtrace_truncated,
                recent_trace_dropped_events = snapshot.recent_trace_dropped_events,
                diagnostic_json = %diagnostic_json,
                "abnormal MPC session diagnostic snapshot"
            );
        } else {
            warn!(
                target: "ika_mpc_diagnostics",
                event = "mpc_session_anomaly",
                schema_version = MPC_ANOMALY_SCHEMA_VERSION,
                diagnostic_shape = "snapshot",
                anomaly_kind = anomaly_kind.label(),
                severity = anomaly_kind.severity(),
                session_id = %hex::encode(snapshot.session_id),
                session_type = session_type_label(snapshot.session_type),
                session_origin = snapshot.session_origin.label(),
                epoch = snapshot.epoch,
                local_party_id = snapshot.local_party_id,
                tracked_session = true,
                diagnostic_serialization_succeeded,
                local_output_observed = snapshot.local_output_observed,
                local_authority_malicious = snapshot.local_authority_malicious,
                quorum_reached_without_local_output = snapshot.quorum_reached_without_local_output,
                local_output_rejected = ?snapshot.local_output_rejected,
                error_code = snapshot.error_code.unwrap_or("none"),
                error_backtrace_present = snapshot.error_backtrace.is_some(),
                error_backtrace_truncated = snapshot.error_backtrace_truncated,
                recent_trace_dropped_events = snapshot.recent_trace_dropped_events,
                diagnostic_json = %diagnostic_json,
                "abnormal MPC session diagnostic snapshot"
            );
        }
        // A snapshot that identifies THIS validator as malicious is the one
        // diagnostic whose loss is unrecoverable (the service stops right
        // after, and the emitting node's logs rotate) — mirror it to disk.
        if snapshot.local_authority_malicious {
            self.persist_malicious_diagnostic(
                anomaly_kind,
                &hex::encode(snapshot.session_id),
                &diagnostic_json,
            );
        }
    }

    fn record_session_anomaly_metrics(
        &self,
        anomaly_kind: MpcAnomalyKind,
        session_type: SessionType,
        trigger_conditions: &[&'static str],
    ) {
        let session_type = session_type_label(session_type);
        self.dwallet_mpc_metrics
            .anomaly_snapshots_total
            .with_label_values(&[anomaly_kind.label(), session_type, anomaly_kind.severity()])
            .inc();
        for trigger in trigger_conditions {
            self.dwallet_mpc_metrics
                .anomaly_triggers_total
                .with_label_values(&[*trigger, session_type])
                .inc();
        }
    }

    pub(crate) fn emit_self_malicious_service_exit_anomaly(
        &mut self,
        current_consensus_round: Option<u64>,
    ) {
        let Some(session_identifier) = self.recognized_self_as_malicious_session else {
            let anomaly_kind = MpcAnomalyKind::ServiceExitSelfMalicious;
            let trigger = "mpc_service_exit_after_self_malicious_recognition";
            let context = MpcAnomalyContext {
                current_consensus_round,
                trigger_conditions: vec![trigger],
                local_authority_malicious: true,
                service_loop_termination_reason: Some("local_validator_recognized_as_malicious"),
                ..Default::default()
            };
            let diagnostic_json = serde_json::to_string(&context);
            let diagnostic_serialization_succeeded = diagnostic_json.is_ok();
            let diagnostic_json = diagnostic_json
                .unwrap_or_else(|_| r#"{"diagnostic_serialization_failed":true}"#.to_owned());
            self.dwallet_mpc_metrics
                .anomaly_snapshots_total
                .with_label_values(&[anomaly_kind.label(), "unknown", anomaly_kind.severity()])
                .inc();
            self.dwallet_mpc_metrics
                .anomaly_triggers_total
                .with_label_values(&[trigger, "unknown"])
                .inc();
            error!(
                target: "ika_mpc_diagnostics",
                event = "mpc_session_anomaly",
                schema_version = MPC_ANOMALY_SCHEMA_VERSION,
                diagnostic_shape = "context",
                anomaly_kind = anomaly_kind.label(),
                severity = anomaly_kind.severity(),
                session_type = "unknown",
                epoch = self.epoch_id,
                local_authority = ?self.validator_name,
                local_party_id = self.party_id,
                tracked_session = false,
                local_authority_malicious = true,
                diagnostic_serialization_succeeded,
                diagnostic_json = %diagnostic_json,
                service_loop_termination_reason = "local_validator_recognized_as_malicious",
                "MPC service exited after local malicious recognition without a source session"
            );
            self.persist_malicious_diagnostic(anomaly_kind, "no_session", &diagnostic_json);
            return;
        };
        self.emit_session_anomaly(
            session_identifier,
            MpcAnomalyKind::ServiceExitSelfMalicious,
            MpcAnomalyContext {
                current_consensus_round,
                trigger_conditions: vec!["mpc_service_exit_after_self_malicious_recognition"],
                local_authority_malicious: true,
                service_loop_termination_reason: Some("local_validator_recognized_as_malicious"),
                ..Default::default()
            },
        );
    }

    /// Builds the outputs to finalize based on the outputs received in the consensus rounds.
    /// If a majority vote is reached, it keeps disagreeing voters separate from
    /// malicious authorities embedded in the winning report, then computes the
    /// same union returned by the old implementation.
    /// If the threshold is not reached, it returns `None`.
    pub(crate) fn build_outputs_to_finalize(
        &mut self,
        session_identifier: &SessionIdentifier,
        outputs_by_consensus_round: BTreeMap<u64, HashMap<PartyID, DWalletMPCSessionOutput>>,
    ) -> Option<OutputsToFinalize> {
        let mut latest_outputs: BTreeMap<PartyID, (u64, DWalletMPCSessionOutput)> = BTreeMap::new();

        for (consensus_round, outputs) in outputs_by_consensus_round {
            for (sender_party_id, output) in outputs {
                // take the last output from each sender party ID
                latest_outputs.insert(sender_party_id, (consensus_round, output));
            }
        }

        let outputs_to_finalize: HashMap<PartyID, DWalletMPCSessionOutput> = latest_outputs
            .iter()
            .map(|(party_id, (_, output))| (*party_id, output.clone()))
            .collect();
        match outputs_to_finalize.weighted_majority_vote(&self.access_structure) {
            Ok((malicious_voters, majority_vote)) => {
                let malicious_voter_authorities: HashSet<_> = malicious_voters
                    .iter()
                    .flat_map(|party_id| party_id_to_authority_name(*party_id, &self.committee))
                    .collect();
                let reported_malicious_authorities: HashSet<_> = majority_vote
                    .malicious_authorities
                    .iter()
                    .copied()
                    .collect();
                let final_malicious_authorities: HashSet<_> = malicious_voter_authorities
                    .iter()
                    .copied()
                    .chain(reported_malicious_authorities.iter().copied())
                    .collect();

                let local_authority_malicious_reason = match (
                    malicious_voter_authorities.contains(&self.validator_name),
                    reported_malicious_authorities.contains(&self.validator_name),
                ) {
                    (true, true) => Some(
                        LocalAuthorityMaliciousReason::MaliciousVoterAndReportedByMajorityOutput,
                    ),
                    (true, false) => Some(LocalAuthorityMaliciousReason::MaliciousVoter),
                    (false, true) => Some(LocalAuthorityMaliciousReason::ReportedByMajorityOutput),
                    (false, false) => None,
                };

                let reports: Vec<_> = latest_outputs
                    .iter()
                    .filter_map(|(party_id, (consensus_round, output))| {
                        party_id_to_authority_name(*party_id, &self.committee).map(
                            |sender_authority| OutputReportDiagnostic {
                                sender_party_id: *party_id,
                                sender_authority,
                                consensus_round: *consensus_round,
                                output_digest: output.output_digest,
                                report_digest: output.report_digest,
                                rejected: output.rejected,
                                voting_weight: self
                                    .access_structure
                                    .party_to_weight
                                    .get(party_id)
                                    .copied()
                                    .unwrap_or(0),
                                reported_malicious_authorities: output
                                    .malicious_authorities
                                    .clone(),
                            },
                        )
                    })
                    .collect();

                let mut grouped: BTreeMap<[u8; 32], ([u8; 32], Vec<PartyID>, PartyID)> =
                    BTreeMap::new();
                for (party_id, (_, output)) in &latest_outputs {
                    let group = grouped.entry(output.report_digest).or_insert((
                        output.output_digest,
                        Vec::new(),
                        0,
                    ));
                    group.1.push(*party_id);
                    group.2 = group.2.saturating_add(
                        self.access_structure
                            .party_to_weight
                            .get(party_id)
                            .copied()
                            .unwrap_or(0),
                    );
                }
                let vote_groups: Vec<_> = grouped
                    .into_iter()
                    .map(
                        |(report_digest, (output_digest, voter_party_ids, voting_weight))| {
                            let voter_authorities = voter_party_ids
                                .iter()
                                .filter_map(|party_id| {
                                    party_id_to_authority_name(*party_id, &self.committee)
                                })
                                .collect();
                            OutputVoteGroupDiagnostic {
                                report_digest,
                                output_digest,
                                voter_party_ids,
                                voter_authorities,
                                voting_weight,
                            }
                        },
                    )
                    .collect();
                let winning_weight = vote_groups
                    .iter()
                    .find(|group| group.report_digest == majority_vote.report_digest)
                    .map_or(0, |group| group.voting_weight);
                let total_observed_weight =
                    vote_groups.iter().map(|group| group.voting_weight).sum();
                let local_output_digest = self
                    .sessions
                    .get(session_identifier)
                    .and_then(|session| session.local_output_digest);
                let local_output_matches_winner =
                    local_output_digest.map(|digest| digest == majority_vote.output_digest);

                let mut malicious_voters: Vec<_> =
                    malicious_voter_authorities.iter().copied().collect();
                malicious_voters.sort();
                let mut reported_malicious: Vec<_> =
                    reported_malicious_authorities.iter().copied().collect();
                reported_malicious.sort();
                let mut final_malicious: Vec<_> =
                    final_malicious_authorities.iter().copied().collect();
                final_malicious.sort();
                let vote_diagnostics = OutputVoteDiagnostics {
                    reports,
                    vote_groups,
                    threshold_required: self.access_structure.threshold,
                    total_observed_weight,
                    winning_weight,
                    winning_output_digest: majority_vote.output_digest,
                    winning_report_digest: majority_vote.report_digest,
                    local_output_digest,
                    local_output_matches_winner,
                    rejected: majority_vote.rejected,
                    malicious_voters,
                    reported_malicious_authorities: reported_malicious,
                    final_malicious_authorities: final_malicious,
                    local_authority_malicious_reason,
                };

                Some(OutputsToFinalize {
                    malicious_voters: malicious_voter_authorities,
                    reported_malicious_authorities,
                    final_malicious_authorities,
                    majority_vote: majority_vote.output,
                    vote_diagnostics,
                })
            }
            Err(e) if matches!(e.kind, mpc::ErrorKind::ThresholdNotReached) => None,
            Err(e) => {
                let error_diagnostic = mpc_error_diagnostic(&e);
                self.emit_session_anomaly(
                    *session_identifier,
                    MpcAnomalyKind::VotingFailure,
                    MpcAnomalyContext {
                        trigger_conditions: vec!["weighted_majority_vote_failed"],
                        error_code: Some(error_diagnostic.error_code),
                        error_party_ids: error_diagnostic.party_ids,
                        error_backtrace: error_diagnostic.backtrace,
                        error_backtrace_truncated: error_diagnostic.backtrace_truncated,
                        ..Default::default()
                    },
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
        session_sequence_number: Option<u64>,
        on_chain_session_type: SessionType,
    ) {
        match self.sessions.entry(*session_identifier) {
            Entry::Occupied(session) => {
                let session = session.into_mut();
                session.mark_mpc_session_as_computation_completed();
                session.set_request_metadata(session_sequence_number, on_chain_session_type);
            }
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
                if let Some(session) = self.sessions.get_mut(session_identifier) {
                    session.set_request_metadata(session_sequence_number, on_chain_session_type);
                }
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

    /// Refreshes the gauges that summarize the in-memory `sessions` map, the
    /// request parking lots, the loaded network keys, and the per-user-session
    /// diagnostic series. O(sessions × committee) and idempotent; called once
    /// per service tick — the per-tick re-emission (explicit zeros included
    /// for empty buckets/states) is what clears stale values when sessions
    /// move between buckets or leave the map.
    pub(crate) fn refresh_observability_metrics(&mut self) {
        let now = Instant::now();
        // The service loop calls this every iteration (~20ms); gauges don't
        // need that cadence, and the refresh scans every session tracked this
        // epoch — rate-limit it off the hot path.
        if self
            .last_observability_refresh
            .is_some_and(|last| now.duration_since(last) < OBSERVABILITY_REFRESH_INTERVAL)
        {
            return;
        }
        self.last_observability_refresh = Some(now);

        if let TerminalMessageLogAction::Recovered { completed, failed } =
            self.terminal_message_log_state.check_recovery(now)
        {
            info!(
                completed,
                failed,
                quiet_interval_seconds = TERMINAL_MESSAGE_LOG_INTERVAL.as_secs(),
                "MPC messages-after-terminal burst recovered"
            );
        }

        let metrics = &self.dwallet_mpc_metrics;

        // ----- orchestrator core-slot occupancy -----
        // A slot is reserved at spawn and reclaimed only when the completion
        // update is drained, so a computation that never completes holds its
        // slot for the rest of the epoch — and at running == budget the
        // orchestrator silently refuses all new MPC work. Exported so slot
        // exhaustion (and a slow leak: a floor that survives idle periods)
        // is scrapable instead of living in a `debug!` field.
        metrics.cryptographic_computations_running.set(
            self.cryptographic_computations_orchestrator
                .currently_running_cryptographic_computations
                .len() as i64,
        );
        metrics.cryptographic_computation_core_budget.set(
            self.cryptographic_computations_orchestrator
                .available_cores() as i64,
        );

        // ----- session-state counts + Active-session age buckets -----
        // Only Active sessions get an age: Completed/Failed entries stay in
        // the map until epoch end and don't represent in-flight work.
        let mut state_counts: HashMap<&str, i64> = HashMap::new();
        let mut age_bucket_counts: HashMap<(&str, &str), i64> = HashMap::new();
        let mut sessions_with_self_output_no_quorum = 0i64;
        let mut protocol_sessions_pending: HashMap<String, i64> = HashMap::new();
        // "We never did our part" — the complement of
        // `sessions_with_self_output_no_quorum`: a user session that has been
        // Active well past any normal computation latency without this
        // validator ever submitting a local output. A session admitted but
        // never computed is invisible in the log stream (nothing fires after
        // admission), and one such session wedged an epoch close in issue
        // #2018 — so it gets a gauge AND a periodic warn.
        const STALLED_USER_SESSION_THRESHOLD: Duration = Duration::from_secs(120);
        let mut stalled_user_sessions: Vec<(Option<u64>, u64)> = Vec::new();
        for session in self.sessions.values() {
            *state_counts
                .entry(session_state_label(&session.status))
                .or_default() += 1;
            if let SessionStatus::Active { request, .. } = &session.status {
                let age = now.saturating_duration_since(session.created_at);
                let age_bucket = AGE_BUCKETS
                    .iter()
                    .find(|(_, threshold)| age < *threshold)
                    .map_or(AGE_BUCKET_OVERFLOW, |(label, _)| *label);
                *age_bucket_counts
                    .entry((session_type_label(request.session_type), age_bucket))
                    .or_default() += 1;
                if matches!(session.session_type, Some(SessionType::User))
                    && session.self_output_consensus_round.is_none()
                    && age >= STALLED_USER_SESSION_THRESHOLD
                {
                    stalled_user_sessions.push((session.session_sequence_number, age.as_secs()));
                }
            }
            // "We did our part, the network didn't" — the single most useful
            // gauge for "are we stuck waiting on quorum from peers".
            if session.session_sequence_number.is_some()
                && matches!(session.session_type, Some(SessionType::User))
                && session.self_output_consensus_round.is_some()
                && session.quorum_consensus_round.is_none()
            {
                sessions_with_self_output_no_quorum += 1;
            }
            if let Some(protocol_name) = &session.protocol_name {
                let pending = protocol_sessions_pending
                    .entry(protocol_name.clone())
                    .or_default();
                // `ComputationCompleted` means this validator finished the
                // computation and submitted its output — no pending work. It
                // isn't `Completed` (that awaits the quorum transition, tracked
                // separately by `sessions_with_self_output_no_quorum`), and a
                // session reloaded from the DB as already-computed
                // (`complete_computation_mpc_session_and_create_if_not_exists`)
                // lingers in this state until epoch-end pruning. Counting it as
                // pending would keep this gauge from ever draining to zero.
                if !matches!(
                    session.status,
                    SessionStatus::Completed
                        | SessionStatus::Failed
                        | SessionStatus::ComputationCompleted
                ) {
                    *pending += 1;
                }
                // The per-authority, per-session output digests are
                // high-cardinality (session id x authority); only export them
                // for the protocols a compatibility scenario scrapes.
                if OUTPUT_OBSERVATION_EXPORT_PROTOCOLS.contains(&protocol_name.as_str()) {
                    let session_id = hex::encode(session.session_identifier.as_ref());
                    for (authority, observation) in &session.output_observations {
                        let authority = authority.to_string();
                        for digest in &observation.digests {
                            let output_digest = hex::encode(digest);
                            metrics
                                .session_output_info
                                .with_label_values(&[
                                    protocol_name,
                                    &session_id,
                                    &authority,
                                    &output_digest,
                                ])
                                .set(1);
                        }
                        metrics
                            .session_reported_malicious_actors
                            .with_label_values(&[protocol_name, &session_id, &authority])
                            .set(observation.malicious_actor_count as i64);
                        metrics
                            .session_output_rejected
                            .with_label_values(&[protocol_name, &session_id, &authority])
                            .set(observation.rejected as i64);
                    }
                    // A locally computed output that returned after the
                    // session completed via the peers' quorum is discarded
                    // without submission, so it never appears in
                    // `output_observations`. Export its raw-bytes digest next
                    // to the quorum's raw-bytes digest so a compatibility
                    // scenario can still check byte-equality. Both digests
                    // are over raw output bytes — NOT comparable with the
                    // `output_digest` envelope labels above.
                    if let Some(late_output) = &session.late_output {
                        let authority = self.validator_name.to_string();
                        let output_digest = hex::encode(late_output.digest);
                        let quorum_output_digest = session
                            .quorum_raw_output_digest
                            .map(hex::encode)
                            .unwrap_or_else(|| "unknown".to_string());
                        metrics
                            .session_late_output_info
                            .with_label_values(&[
                                protocol_name,
                                &session_id,
                                &authority,
                                &output_digest,
                                &quorum_output_digest,
                            ])
                            .set(1);
                        metrics
                            .session_late_output_malicious_actors
                            .with_label_values(&[protocol_name, &session_id, &authority])
                            .set(late_output.reported_malicious_count as i64);
                    }
                }
            }
        }
        for (protocol_name, pending) in protocol_sessions_pending {
            metrics
                .protocol_sessions_pending
                .with_label_values(&[&protocol_name])
                .set(pending);
        }
        for state in ALL_SESSION_STATES.iter().copied() {
            metrics
                .session_state_count
                .with_label_values(&[state])
                .set(state_counts.get(state).copied().unwrap_or(0));
        }
        for session_type in ALL_SESSION_TYPES.iter().copied() {
            let age_buckets = AGE_BUCKETS
                .iter()
                .map(|(label, _)| *label)
                .chain([AGE_BUCKET_OVERFLOW]);
            for age_bucket in age_buckets {
                metrics
                    .active_sessions_by_age
                    .with_label_values(&[session_type, age_bucket])
                    .set(
                        age_bucket_counts
                            .get(&(session_type, age_bucket))
                            .copied()
                            .unwrap_or(0),
                    );
            }
        }

        // ----- request parking lots -----
        for (key_id, requests) in &self.requests_pending_for_network_key {
            metrics
                .requests_pending_for_network_key
                .with_label_values(&[&key_id.to_string()])
                .set(requests.len() as i64);
        }
        metrics
            .requests_pending_for_next_active_committee
            .set(self.requests_pending_for_next_active_committee.len() as i64);
        metrics
            .requests_pending_for_frozen_mpc_data
            .set(self.requests_pending_for_frozen_mpc_data.len() as i64);
        metrics
            .internal_presign_requests_pending_for_network_key_data
            .set(
                self.internal_presign_requests_pending_for_network_key_data
                    .len() as i64,
            );

        // ----- per-network-encryption-key loaded epoch -----
        // Drift between this and the current epoch is the silent-skip cause
        // ("network key epoch does not match current epoch, ignoring") —
        // operators can alert on |loaded_epoch − current_epoch| > 0.
        for (key_id, public_data) in &self.network_keys.network_encryption_keys {
            metrics
                .network_key_loaded_epoch
                .with_label_values(&[&key_id.to_string()])
                .set(public_data.epoch() as i64);
        }

        // ----- per-user-session series, labeled by sequence number -----
        // Registry cardinality grows with the epoch's user-session count (the
        // sessions map is only dropped at epoch end), but per-refresh WORK is
        // bounded by in-flight sessions: a terminal (Completed/Failed)
        // session gets one final emission recording its terminal state and is
        // skipped afterwards, its series frozen at those values.
        let mut current_seqs = HashSet::new();
        for session in self.sessions.values() {
            let (Some(session_sequence_number), Some(SessionType::User)) =
                (session.session_sequence_number, session.session_type)
            else {
                // Non-user sessions, and entries that haven't seen their
                // request yet (no sequence number to label by — they are
                // exposed once the request arrives).
                continue;
            };

            let terminal = matches!(
                session.status,
                SessionStatus::Completed | SessionStatus::Failed
            );
            if terminal {
                if !self
                    .finalized_emitted_user_session_seqs
                    .insert(session_sequence_number)
                {
                    // Final values already emitted. Keep the seq in
                    // current_seqs so the stale-zeroing block below doesn't
                    // wipe the terminal record while the session is tracked.
                    current_seqs.insert(session_sequence_number);
                    continue;
                }
            } else {
                // A session observed non-terminal must be re-armed for a
                // final emission if it ever terminates.
                self.finalized_emitted_user_session_seqs
                    .remove(&session_sequence_number);
            }

            let seq_label = session_sequence_number.to_string();
            let current_state = session_state_label(&session.status);
            for state in ALL_SESSION_STATES.iter().copied() {
                metrics
                    .user_session_state
                    .with_label_values(&[seq_label.as_str(), state])
                    .set((state == current_state) as i64);
            }

            metrics
                .user_session_first_output_consensus_round
                .with_label_values(&[&seq_label])
                .set(
                    session
                        .first_output_consensus_round
                        .map_or(-1, |round| round as i64),
                );
            metrics
                .user_session_self_output_consensus_round
                .with_label_values(&[&seq_label])
                .set(
                    session
                        .self_output_consensus_round
                        .map_or(-1, |round| round as i64),
                );
            metrics
                .user_session_quorum_consensus_round
                .with_label_values(&[&seq_label])
                .set(
                    session
                        .quorum_consensus_round
                        .map_or(-1, |round| round as i64),
                );
            metrics
                .user_session_distinct_output_authorities
                .with_label_values(&[&seq_label])
                .set(session.distinct_output_authorities.len() as i64);
            metrics
                .user_session_local_output_rejected
                .with_label_values(&[&seq_label])
                .set(match session.local_output_rejected {
                    None => -1,
                    Some(false) => 0,
                    Some(true) => 1,
                });
            metrics
                .user_session_distinct_output_digests
                .with_label_values(&[&seq_label])
                .set(session.distinct_output_digests.len() as i64);

            // Full committee iteration so "which validators have NOT
            // submitted for session N" is directly queryable.
            for authority_name in self.committee.names() {
                let received = session.distinct_output_authorities.contains(authority_name);
                metrics
                    .user_session_output_received_from
                    .with_label_values(&[&seq_label, &authority_name.concise().to_string()])
                    .set(received as i64);
            }

            current_seqs.insert(session_sequence_number);
        }
        metrics
            .sessions_with_self_output_no_quorum
            .set(sessions_with_self_output_no_quorum);
        metrics
            .user_sessions_active_without_local_output
            .set(stalled_user_sessions.len() as i64);
        if !stalled_user_sessions.is_empty()
            && self
                .last_stalled_session_log
                .is_none_or(|last| now.duration_since(last) >= STALLED_SESSION_LOG_INTERVAL)
        {
            self.last_stalled_session_log = Some(now);
            stalled_user_sessions.sort();
            let oldest_age_secs = stalled_user_sessions
                .iter()
                .map(|(_, age)| *age)
                .max()
                .unwrap_or(0);
            stalled_user_sessions.truncate(8);
            warn!(
                count = metrics.user_sessions_active_without_local_output.get(),
                oldest_age_secs,
                sessions_seq_and_age = ?stalled_user_sessions,
                threshold_secs = STALLED_USER_SESSION_THRESHOLD.as_secs(),
                authority=?self.validator_name,
                "user MPC session(s) active without a local output past the stall \
                 threshold — admitted but possibly never computing; if it sits in \
                 the epoch's locked close set this wedges the epoch (issue #2018)"
            );
        }

        // Sessions that left `self.sessions` since the previous tick get one
        // final emission flipping the state series to 0 and the round gauges
        // to their "not set" sentinels, so dashboards reflect "no longer
        // tracked here" instead of the last live value.
        for stale_seq in self
            .previously_emitted_user_session_seqs
            .difference(&current_seqs)
        {
            let seq_label = stale_seq.to_string();
            for state in ALL_SESSION_STATES.iter().copied() {
                metrics
                    .user_session_state
                    .with_label_values(&[seq_label.as_str(), state])
                    .set(0);
            }
            metrics
                .user_session_first_output_consensus_round
                .with_label_values(&[&seq_label])
                .set(-1);
            metrics
                .user_session_self_output_consensus_round
                .with_label_values(&[&seq_label])
                .set(-1);
            metrics
                .user_session_quorum_consensus_round
                .with_label_values(&[&seq_label])
                .set(-1);
            metrics
                .user_session_distinct_output_authorities
                .with_label_values(&[&seq_label])
                .set(0);
            metrics
                .user_session_local_output_rejected
                .with_label_values(&[&seq_label])
                .set(-1);
            metrics
                .user_session_distinct_output_digests
                .with_label_values(&[&seq_label])
                .set(0);
            for authority_name in self.committee.names() {
                metrics
                    .user_session_output_received_from
                    .with_label_values(&[&seq_label, &authority_name.concise().to_string()])
                    .set(0);
            }
        }
        self.previously_emitted_user_session_seqs = current_seqs;
    }
}

/// Minimum interval between observability-gauge refreshes; the caller (the
/// dwallet MPC service loop) ticks every ~20ms, far faster than gauges need.
const OBSERVABILITY_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Cadence of the stalled-user-session warn (see
/// `refresh_observability_metrics`): a wedged session logs once a minute,
/// not once per one-second refresh.
const STALLED_SESSION_LOG_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const MAX_UNTRACKED_ANOMALIES: usize = 1024;

fn session_state_label(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Active { .. } => SESSION_STATE_ACTIVE,
        SessionStatus::WaitingForSessionRequest => SESSION_STATE_WAITING_FOR_REQUEST,
        SessionStatus::ComputationCompleted => SESSION_STATE_COMPUTATION_COMPLETED,
        SessionStatus::Completed => SESSION_STATE_COMPLETED,
        SessionStatus::Failed => SESSION_STATE_FAILED,
    }
}

#[cfg(test)]
mod terminal_message_log_tests {
    use super::*;

    #[test]
    fn completed_terminal_messages_warn_once_per_burst_and_recover_once() {
        let start = Instant::now();
        let mut state = TerminalMessageLogState::new(start);
        for offset in 0..COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD - 1 {
            assert_eq!(
                state.record(
                    start + Duration::from_millis(offset),
                    TerminalStatus::Completed,
                ),
                TerminalMessageLogAction::None
            );
        }
        assert_eq!(
            state.record(start + Duration::from_secs(1), TerminalStatus::Completed,),
            TerminalMessageLogAction::Warn {
                completed: COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD,
                failed: 0,
            }
        );
        assert_eq!(
            state.record(start + Duration::from_secs(2), TerminalStatus::Completed,),
            TerminalMessageLogAction::None
        );

        assert_eq!(
            state.check_recovery(start + TERMINAL_MESSAGE_LOG_INTERVAL),
            TerminalMessageLogAction::None
        );
        assert_eq!(
            state.check_recovery(start + Duration::from_secs(2) + TERMINAL_MESSAGE_LOG_INTERVAL),
            TerminalMessageLogAction::Recovered {
                completed: COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD + 1,
                failed: 0,
            }
        );
        assert_eq!(
            state.check_recovery(start + Duration::from_secs(3) + TERMINAL_MESSAGE_LOG_INTERVAL),
            TerminalMessageLogAction::None
        );
    }

    #[test]
    fn failed_terminal_message_is_distinct_and_isolated_recovery_is_silent() {
        let start = Instant::now();
        let mut state = TerminalMessageLogState::new(start);
        assert_eq!(
            state.record(start, TerminalStatus::Failed),
            TerminalMessageLogAction::Warn {
                completed: 0,
                failed: 1,
            }
        );
        assert_eq!(
            state.check_recovery(start + TERMINAL_MESSAGE_LOG_INTERVAL),
            TerminalMessageLogAction::None
        );
    }

    #[test]
    fn failed_terminal_message_warnings_are_limited_to_one_per_interval() {
        let start = Instant::now();
        let mut state = TerminalMessageLogState::new(start);
        assert!(matches!(
            state.record(start, TerminalStatus::Failed),
            TerminalMessageLogAction::Warn { .. }
        ));
        assert_eq!(
            state.record(start + Duration::from_secs(1), TerminalStatus::Failed),
            TerminalMessageLogAction::None
        );
        assert!(matches!(
            state.record(
                start + TERMINAL_MESSAGE_LOG_INTERVAL,
                TerminalStatus::Failed
            ),
            TerminalMessageLogAction::Warn { .. }
        ));
    }

    #[test]
    fn first_failed_message_bypasses_completed_warning_throttle() {
        let start = Instant::now();
        let mut state = TerminalMessageLogState::new(start);
        for offset in 0..COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD {
            let action = state.record(
                start + Duration::from_millis(offset),
                TerminalStatus::Completed,
            );
            if offset + 1 == COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD {
                assert!(matches!(action, TerminalMessageLogAction::Warn { .. }));
            } else {
                assert_eq!(action, TerminalMessageLogAction::None);
            }
        }

        assert_eq!(
            state.record(start + Duration::from_secs(1), TerminalStatus::Failed),
            TerminalMessageLogAction::Warn {
                completed: COMPLETED_TERMINAL_MESSAGE_WARN_THRESHOLD,
                failed: 1,
            }
        );
        assert_eq!(
            state.record(start + Duration::from_secs(2), TerminalStatus::Failed),
            TerminalMessageLogAction::None
        );
    }
}

#[cfg(test)]
mod make_public_duplicate_guard_tests {
    use super::*;
    use ika_types::message::MakeDWalletUserSecretKeySharesPublicOutput;

    fn make_public(dwallet_id: &[u8], sequence_number: u64) -> DWalletCheckpointMessageKind {
        DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(
            MakeDWalletUserSecretKeySharesPublicOutput {
                dwallet_id: dwallet_id.to_vec(),
                public_user_secret_key_shares: vec![0xab; 4],
                rejected: false,
                session_sequence_number: sequence_number,
            },
        )
    }

    fn rejected_flag(message: &DWalletCheckpointMessageKind) -> bool {
        match message {
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(output) => {
                output.rejected
            }
            other => panic!("unexpected message kind: {}", other.name()),
        }
    }

    /// Only the first agreed response for a dWallet may carry success.
    #[test]
    fn second_response_for_the_same_dwallet_is_rejected() {
        let mut seen = HashSet::new();
        let mut messages = vec![
            make_public(b"dwallet-one", 1),
            make_public(b"dwallet-one", 2),
        ];

        DWalletMPCManager::reject_duplicate_make_public_responses(&mut seen, &mut messages);

        assert!(
            !rejected_flag(&messages[0]),
            "the first response must stand"
        );
        assert!(
            rejected_flag(&messages[1]),
            "the second response for the same dWallet must be rejected"
        );
    }

    /// The guard must not fire across different dWallets, and must survive the
    /// responses arriving in separate consensus rounds (separate calls).
    #[test]
    fn distinct_dwallets_are_untouched_and_state_persists_across_rounds() {
        let mut seen = HashSet::new();

        let mut first_round = vec![
            make_public(b"dwallet-one", 1),
            make_public(b"dwallet-two", 2),
        ];
        DWalletMPCManager::reject_duplicate_make_public_responses(&mut seen, &mut first_round);
        assert!(!rejected_flag(&first_round[0]));
        assert!(!rejected_flag(&first_round[1]));

        let mut second_round = vec![make_public(b"dwallet-one", 3)];
        DWalletMPCManager::reject_duplicate_make_public_responses(&mut seen, &mut second_round);
        assert!(
            rejected_flag(&second_round[0]),
            "a duplicate arriving in a later consensus round must still be rejected"
        );
    }

    /// An already-rejected response must not consume the one success slot, or
    /// it would suppress the genuine response that follows it.
    #[test]
    fn an_already_rejected_response_does_not_claim_the_dwallet() {
        let mut seen = HashSet::new();
        let mut rejected = vec![make_public(b"dwallet-one", 1)];
        match &mut rejected[0] {
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(output) => {
                output.rejected = true;
            }
            _ => unreachable!(),
        }

        DWalletMPCManager::reject_duplicate_make_public_responses(&mut seen, &mut rejected);

        let mut later = vec![make_public(b"dwallet-one", 2)];
        DWalletMPCManager::reject_duplicate_make_public_responses(&mut seen, &mut later);
        assert!(
            !rejected_flag(&later[0]),
            "a rejected response must leave the success slot open"
        );
    }
}
