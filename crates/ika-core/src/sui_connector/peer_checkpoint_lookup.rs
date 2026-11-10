// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Recover an object a `sui-state-direct` node cannot prove, by asking the other
//! direct nodes which Sui checkpoint proves it and then verifying that
//! checkpoint itself from the checkpoint archive.
//!
//! # The gap
//!
//! A direct node proves an Ika object from its own fullnode: the checkpoint
//! that wrote the object's current version, or its verified cache's snapshot at
//! exactly that reference. When the fullnode has pruned the checkpoint and the
//! cache has no such snapshot, the object is unprovable. The pusher's
//! lost-checkpoint records (`push_worker::LostCheckpoint`) repair that for a
//! checkpoint the node itself saw and failed on. A node that never saw the loss
//! has no record: a new operator, a wiped and resynced database, a node that
//! fast-forwarded past the span. In the mainnet epoch-463 incident such nodes
//! hung in boot at `verified_system_inner` until an operator found the
//! `System` object's defining checkpoint by hand and listed it in
//! `sui-checkpoint-archive-backfill`. Any up-to-date direct peer knows that
//! number: it is the source checkpoint of its own cached snapshot.
//!
//! # Trigger
//!
//! The verified reader reports an object it could not prove
//! ([`PeerCheckpointRecovery::note_unprovable`]) on a direct node, at the two
//! places a read fails for good rather than missing the cache: a single-object
//! read (the singleton anchors behind the boot barrier and the epoch loop, and
//! the bag-walk children resolved one by one) whose provider answered
//! `NotFound`, and a batch read (the validator set) with a missing slot. The
//! provider only answers `NotFound` after `recover_pruned_proof` found no
//! snapshot at the fullnode's exact reference, so an ordinary cache miss never
//! gets here. Relay requests served to mirrored peers do not report: only this
//! node's own reads start a lookup.
//!
//! A report starts a lookup only once the same object has stayed unprovable for
//! [`RecoveryBounds::stuck_after`] — a just-written object whose transaction is
//! not in a checkpoint yet is unprovable for a moment too.
//!
//! # Trust
//!
//! A peer's answer is an untrusted pointer, a bare sequence number: no object
//! data comes from a peer at all. The candidate goes to the pusher's archive
//! backfill exactly as a lost checkpoint does — recorded, pinned, fetched from
//! the archive, verified (`verify_archive_checkpoint`, then `build_entries`) and
//! folded only for objects the node's own fullnode reports at exactly the
//! archived reference. A wrong answer therefore costs one archive download and
//! folds nothing it should not; there is no quorum, no stake weighting and no
//! protocol gate.
//!
//! # Bounds
//!
//! Every report is gated ([`RecoveryBounds`]): per object, one lookup per
//! interval and at most a few distinct candidates per object reference, tried
//! one at a time, stopping at the first that proves it; node-wide, a lookup
//! budget and a concurrency cap; and a candidate must be at or below the node's
//! processed checkpoint and inside the archive's retention
//! ([`ARCHIVE_RETENTION`]). The serving side rate-limits each requester.
//!
//! # Mixed fleets
//!
//! A peer that does not serve the lookup — an older binary, a mirrored node —
//! answers anemo's route-miss `NotFound`, which is a "don't know". Peers
//! older than the lost-checkpoint backfill still answer from their cache.
//! Nothing here needs a protocol version.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ika_network::sui_state_mirror::{ObjectCheckpointPeers, PeerCheckpointAnswers};
use ika_sui_client::transport::{SuiTransport, TransportError};
use parking_lot::Mutex;
use sui_types::base_types::{ObjectID, ObjectRef};
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;

/// A checkpoint a peer named, handed to the pusher's archive backfill. The
/// pusher drops `settled` once the backfill of `seq` has settled — or at once
/// if it does not take the request — and the requester then checks its cache.
pub struct PeerBackfillRequest {
    pub seq: CheckpointSequenceNumber,
    pub settled: oneshot::Sender<()>,
}

/// Requests waiting for the pusher's next tick. The requester submits at most
/// [`RecoveryBounds::max_concurrent`] at a time, so this never fills in
/// practice; a full queue fails the lookup rather than blocking the reader.
const PEER_BACKFILL_QUEUE: usize = 16;

pub fn peer_backfill_channel() -> (
    mpsc::Sender<PeerBackfillRequest>,
    mpsc::Receiver<PeerBackfillRequest>,
) {
    mpsc::channel(PEER_BACKFILL_QUEUE)
}

/// How long the public Sui checkpoint archives keep an ordinary checkpoint. A
/// candidate older than that is refused before any download.
pub const ARCHIVE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The limits on peer lookups. `Default` is production; tests shrink the
/// durations.
#[derive(Clone, Debug)]
pub struct RecoveryBounds {
    /// How long an object must stay unprovable before its first lookup.
    pub stuck_after: Duration,
    /// A report this long after the previous one restarts the stuck clock: the
    /// object was not continuously unprovable in between.
    pub stuck_reset: Duration,
    /// Minimum time between two lookups of the same object.
    pub lookup_interval: Duration,
    /// Node-wide lookup budget: at most this many back to back...
    pub lookup_burst: u32,
    /// ...then one per this interval.
    pub lookup_refill: Duration,
    /// Distinct candidates tried per object reference, ever (in this process).
    pub max_candidates_per_object: usize,
    /// Lookups running at once.
    pub max_concurrent: usize,
    /// Objects tracked at once; a report for a new object past this is dropped.
    pub max_tracked: usize,
    /// How long to wait for the archive backfill of one candidate before trying
    /// the next. The backfill keeps going after that, like any lost
    /// checkpoint's. Above the backfill's fetch timeout (90 s) plus a first
    /// retry.
    pub candidate_wait: Duration,
}

impl Default for RecoveryBounds {
    fn default() -> Self {
        Self {
            stuck_after: Duration::from_secs(20),
            stuck_reset: Duration::from_secs(120),
            lookup_interval: Duration::from_secs(60),
            lookup_burst: 4,
            lookup_refill: Duration::from_secs(30),
            max_candidates_per_object: 3,
            max_concurrent: 2,
            max_tracked: 256,
            candidate_wait: Duration::from_secs(240),
        }
    }
}

/// The lowest checkpoint the archive surely still holds — candidates below it
/// are refused. Recomputed per lookup.
pub type RetentionFloor = Arc<dyn Fn() -> CheckpointSequenceNumber + Send + Sync>;

/// The lowest checkpoint sequence whose timestamp is surely at or after
/// `cutoff_ms`, from the end-of-epoch checkpoints the committee chain retains
/// (`end_of_epoch(epoch) = (seq, timestamp_ms)` of the last checkpoint of
/// `epoch`, for epochs below `head_epoch`).
///
/// A checkpoint after the end of epoch `e` is no older than that end, so the
/// answer is one past the end of the oldest epoch that ended at or after the
/// cutoff. It is conservative by at most one epoch (a day on the public
/// chains). Walks back from the head — about one read per day of retention.
/// Without a retained end-of-epoch checkpoint older than the cutoff, nothing
/// is known to be expired and the floor is 0; a hole in the retained history
/// stops the walk there, since nothing below it can be committee-verified
/// either.
pub fn archive_retention_floor(
    head_epoch: Option<u64>,
    end_of_epoch: impl Fn(u64) -> Option<(CheckpointSequenceNumber, u64)>,
    cutoff_ms: u64,
) -> CheckpointSequenceNumber {
    let Some(mut epoch) = head_epoch else {
        return 0;
    };
    let mut oldest_inside: Option<CheckpointSequenceNumber> = None;
    while epoch > 0 {
        epoch -= 1;
        let Some((seq, timestamp_ms)) = end_of_epoch(epoch) else {
            return oldest_inside.map_or(0, |seq| seq + 1);
        };
        if timestamp_ms >= cutoff_ms {
            oldest_inside = Some(seq);
            continue;
        }
        return oldest_inside.unwrap_or(seq) + 1;
    }
    0
}

/// [`archive_retention_floor`] over the committee chain persisted in
/// `perpetual`, with the cutoff [`ARCHIVE_RETENTION`] before now.
pub fn perpetual_retention_floor(perpetual: Arc<AuthorityPerpetualTables>) -> RetentionFloor {
    Arc::new(move || {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff_ms = now_ms.saturating_sub(ARCHIVE_RETENTION.as_millis() as u64);
        let head_epoch = perpetual.highest_sui_committee_epoch().ok().flatten();
        archive_retention_floor(
            head_epoch,
            |epoch| {
                perpetual
                    .get_sui_committee_summary(epoch)
                    .ok()
                    .flatten()
                    .map(|summary| (*summary.sequence_number(), summary.timestamp_ms))
            },
            cutoff_ms,
        )
    })
}

/// How one lookup ended; the `outcome` label of
/// `ika_ocs_peer_checkpoint_lookups_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupOutcome {
    /// A candidate's archive backfill folded the object.
    Recovered,
    /// The cache already holds the object at the fullnode's reference.
    AlreadyCached,
    /// The fullnode no longer reports the object (deleted or wrapped).
    NotLive,
    /// The fullnode could not say what the object's current reference is.
    FullnodeError,
    /// No peer named an acceptable checkpoint.
    NoCandidate,
    /// Every candidate tried folded nothing for the object.
    NotRecovered,
    /// The object reference's candidate budget is spent.
    Exhausted,
    /// The pusher does not take requests (gone, or its queue is full).
    BackfillUnavailable,
    /// The p2p network is not attached yet.
    NoPeers,
}

impl LookupOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Recovered => "recovered",
            Self::AlreadyCached => "already_cached",
            Self::NotLive => "not_live",
            Self::FullnodeError => "fullnode_error",
            Self::NoCandidate => "no_candidate",
            Self::NotRecovered => "not_recovered",
            Self::Exhausted => "exhausted",
            Self::BackfillUnavailable => "backfill_unavailable",
            Self::NoPeers => "no_peers",
        }
    }

    /// Whether the object no longer needs tracking.
    fn resolves(self) -> bool {
        matches!(self, Self::Recovered | Self::AlreadyCached | Self::NotLive)
    }
}

/// What a report did; returned for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// First report, or the first after a pause: the stuck clock started.
    Tracking,
    /// Not stuck long enough yet, a lookup is running, the per-object interval
    /// has not passed, or the network is not attached yet.
    Waiting,
    /// Stuck, but a node-wide bound refused the lookup for now.
    Throttled(Throttle),
    /// A lookup starts.
    Admitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Throttle {
    RateLimit,
    Concurrency,
    TrackedFull,
}

impl Throttle {
    fn label(self) -> &'static str {
        match self {
            Self::RateLimit => "rate_limit",
            Self::Concurrency => "concurrency",
            Self::TrackedFull => "tracked_full",
        }
    }
}

/// One object this node could not prove.
struct TrackedObject {
    first_unprovable: Instant,
    last_reported: Instant,
    next_lookup: Instant,
    in_flight: bool,
    /// The reference the candidates in `tried` were tried for. A new
    /// reference (the object was written again) starts a fresh budget.
    object_ref: Option<ObjectRef>,
    tried: BTreeSet<CheckpointSequenceNumber>,
}

/// Node-wide lookup budget: a token bucket of whole lookups.
struct LookupBudget {
    tokens: u32,
    burst: u32,
    refill: Duration,
    refilled_at: Instant,
}

impl LookupBudget {
    fn new(burst: u32, refill: Duration, now: Instant) -> Self {
        Self {
            tokens: burst,
            burst,
            refill,
            refilled_at: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        if self.tokens >= self.burst {
            self.refilled_at = now;
        } else {
            let elapsed = now.saturating_duration_since(self.refilled_at);
            let earned = elapsed.as_nanos() / self.refill.as_nanos().max(1);
            if earned > 0 {
                let earned = earned.min(u128::from(self.burst)) as u32;
                self.tokens = (self.tokens + earned).min(self.burst);
                self.refilled_at += self.refill * earned;
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

struct RecoveryState {
    objects: HashMap<ObjectID, TrackedObject>,
    budget: LookupBudget,
    in_flight: usize,
}

/// The connector stack's hand-off to node startup: `recovery` gets the p2p
/// network attached once it is up ([`PeerCheckpointRecovery::attach_peers`]),
/// and `backfill_requests` goes to the checkpoint pusher
/// (`IkaCheckpointPusher::with_peer_backfill_requests`).
pub struct PeerCheckpointRecoveryWiring {
    pub recovery: Arc<PeerCheckpointRecovery>,
    pub backfill_requests: mpsc::Receiver<PeerBackfillRequest>,
}

/// See the module docs. Built with the connector stack on a direct node with an
/// archive; the p2p network is attached once it is up
/// ([`Self::attach_peers`]).
pub struct PeerCheckpointRecovery {
    /// This node's own fullnode: the object's current reference.
    fullnode: Arc<dyn SuiTransport>,
    cache: SharedVerifiedStateCache,
    /// The pusher's archive backfill.
    backfill: mpsc::Sender<PeerBackfillRequest>,
    retention_floor: RetentionFloor,
    peers: OnceLock<Arc<dyn ObjectCheckpointPeers>>,
    bounds: RecoveryBounds,
    state: Mutex<RecoveryState>,
    metrics: Arc<OcsMetrics>,
}

impl PeerCheckpointRecovery {
    pub fn new(
        fullnode: Arc<dyn SuiTransport>,
        cache: SharedVerifiedStateCache,
        backfill: mpsc::Sender<PeerBackfillRequest>,
        retention_floor: RetentionFloor,
        bounds: RecoveryBounds,
        metrics: Arc<OcsMetrics>,
    ) -> Self {
        let budget = LookupBudget::new(bounds.lookup_burst, bounds.lookup_refill, Instant::now());
        Self {
            fullnode,
            cache,
            backfill,
            retention_floor,
            peers: OnceLock::new(),
            bounds,
            state: Mutex::new(RecoveryState {
                objects: HashMap::new(),
                budget,
                in_flight: 0,
            }),
            metrics,
        }
    }

    /// Attach the peers to ask, once the p2p network is up. Reports before
    /// that only start the stuck clock.
    pub fn attach_peers(&self, peers: Arc<dyn ObjectCheckpointPeers>) {
        if self.peers.set(peers).is_err() {
            debug!("peer checkpoint lookup: peers already attached");
        }
    }

    /// The reader could not prove `id` (see the module docs). Never blocks:
    /// a lookup, when admitted, runs in its own task.
    pub fn note_unprovable(self: &Arc<Self>, id: ObjectID) {
        if self.admit(id, Instant::now()) == Admission::Admitted {
            let this = self.clone();
            tokio::spawn(async move {
                this.run_admitted(id).await;
            });
        }
    }

    /// The gate in front of every lookup.
    pub(crate) fn admit(&self, id: ObjectID, now: Instant) -> Admission {
        let bounds = &self.bounds;
        let mut state = self.state.lock();
        let tracked = match state.objects.get_mut(&id) {
            Some(tracked) => tracked,
            None => {
                if state.objects.len() >= bounds.max_tracked {
                    state.objects.retain(|_, tracked| {
                        tracked.in_flight
                            || now.saturating_duration_since(tracked.last_reported)
                                < bounds.stuck_reset
                    });
                }
                if state.objects.len() >= bounds.max_tracked {
                    drop(state);
                    return self.throttled(Throttle::TrackedFull);
                }
                state.objects.insert(
                    id,
                    TrackedObject {
                        first_unprovable: now,
                        last_reported: now,
                        next_lookup: now + bounds.stuck_after,
                        in_flight: false,
                        object_ref: None,
                        tried: BTreeSet::new(),
                    },
                );
                return Admission::Tracking;
            }
        };
        let paused = now.saturating_duration_since(tracked.last_reported) >= bounds.stuck_reset;
        tracked.last_reported = now;
        if paused && !tracked.in_flight {
            tracked.first_unprovable = now;
            tracked.next_lookup = tracked.next_lookup.max(now + bounds.stuck_after);
            return Admission::Tracking;
        }
        if tracked.in_flight || now < tracked.next_lookup || self.peers.get().is_none() {
            return Admission::Waiting;
        }
        if state.in_flight >= bounds.max_concurrent {
            drop(state);
            return self.throttled(Throttle::Concurrency);
        }
        if !state.budget.try_take(now) {
            drop(state);
            return self.throttled(Throttle::RateLimit);
        }
        state.in_flight += 1;
        let tracked = state
            .objects
            .get_mut(&id)
            .expect("tracked above, under the same lock");
        tracked.in_flight = true;
        tracked.next_lookup = now + bounds.lookup_interval;
        debug!(
            ?id,
            stuck_for = ?now.saturating_duration_since(tracked.first_unprovable),
            "peer checkpoint lookup admitted"
        );
        Admission::Admitted
    }

    fn throttled(&self, throttle: Throttle) -> Admission {
        self.metrics
            .peer_checkpoint_lookups_throttled_total
            .with_label_values(&[throttle.label()])
            .inc();
        Admission::Throttled(throttle)
    }

    /// Run an admitted lookup and release its slot.
    pub(crate) async fn run_admitted(&self, id: ObjectID) -> LookupOutcome {
        let outcome = self.lookup(id).await;
        self.finish(id, outcome);
        outcome
    }

    /// Count an admitted lookup's outcome and release its slot.
    pub(crate) fn finish(&self, id: ObjectID, outcome: LookupOutcome) {
        self.metrics
            .peer_checkpoint_lookups_total
            .with_label_values(&[outcome.label()])
            .inc();
        let mut state = self.state.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
        if outcome.resolves() {
            state.objects.remove(&id);
        } else if let Some(tracked) = state.objects.get_mut(&id) {
            tracked.in_flight = false;
        }
    }

    #[cfg(test)]
    pub(crate) fn is_tracking(&self, id: ObjectID) -> bool {
        self.state.lock().objects.contains_key(&id)
    }

    /// Whether the cache can now serve `object_ref`: it holds that exact
    /// reference, or a newer version of the object.
    fn resolved(&self, object_ref: ObjectRef) -> bool {
        self.cache.checkpoint_of(object_ref).is_some()
            || self
                .cache
                .get(object_ref.0)
                .is_some_and(|snapshot| snapshot.object.version() > object_ref.1)
    }

    async fn lookup(&self, id: ObjectID) -> LookupOutcome {
        let Some(peers) = self.peers.get().cloned() else {
            return LookupOutcome::NoPeers;
        };
        let object_ref = match self.fullnode.get_object(id).await {
            Ok(object) => object.compute_object_reference(),
            Err(TransportError::NotFound(_)) => return LookupOutcome::NotLive,
            Err(e) => {
                debug!(?id, error = %e, "peer checkpoint lookup: fullnode object read failed");
                return LookupOutcome::FullnodeError;
            }
        };
        if self.resolved(object_ref) {
            return LookupOutcome::AlreadyCached;
        }
        let (budget, tried) = {
            let mut state = self.state.lock();
            let Some(tracked) = state.objects.get_mut(&id) else {
                return LookupOutcome::NotRecovered;
            };
            if tracked.object_ref != Some(object_ref) {
                tracked.object_ref = Some(object_ref);
                tracked.tried.clear();
            }
            (
                self.bounds
                    .max_candidates_per_object
                    .saturating_sub(tracked.tried.len()),
                tracked.tried.clone(),
            )
        };
        if budget == 0 {
            return LookupOutcome::Exhausted;
        }

        let answers = peers.ask(object_ref).await;
        self.record_answers(&answers);
        let head = self.cache.processed_head_seq();
        let floor = (self.retention_floor)();
        let mut candidates = Vec::new();
        for seq in answers.candidates.iter().copied() {
            let refused = if seq > head {
                Some("above_head")
            } else if seq < floor {
                Some("beyond_retention")
            } else if tried.contains(&seq) {
                Some("already_tried")
            } else if candidates.len() >= budget {
                Some("over_budget")
            } else {
                None
            };
            match refused {
                Some(result) => self
                    .metrics
                    .peer_checkpoint_candidates_total
                    .with_label_values(&[result])
                    .inc(),
                None => candidates.push(seq),
            }
        }
        if candidates.is_empty() {
            info!(
                ?object_ref,
                asked = answers.asked,
                named = ?answers.candidates,
                unknown = answers.unknown,
                unimplemented = answers.unimplemented,
                failed = answers.failed,
                head,
                retention_floor = floor,
                "peer checkpoint lookup: no peer named an acceptable checkpoint for an object this \
                 node cannot prove; asking again later"
            );
            return LookupOutcome::NoCandidate;
        }

        for seq in candidates {
            if let Some(tracked) = self.state.lock().objects.get_mut(&id) {
                tracked.tried.insert(seq);
            }
            let (settled, backfill_settled) = oneshot::channel();
            if self
                .backfill
                .try_send(PeerBackfillRequest { seq, settled })
                .is_err()
            {
                warn!(
                    ?object_ref,
                    seq, "peer checkpoint lookup: the checkpoint pusher does not take requests"
                );
                return LookupOutcome::BackfillUnavailable;
            }
            self.metrics
                .peer_checkpoint_candidates_total
                .with_label_values(&["submitted"])
                .inc();
            info!(
                ?object_ref,
                seq,
                asked = answers.asked,
                named = answers.named,
                "peer checkpoint lookup: a peer named the checkpoint that proves an object this \
                 node cannot prove; verifying it from the archive"
            );
            // Settled, refused, or still retrying past the wait: the cache
            // says whether the object is provable now.
            let _ = tokio::time::timeout(self.bounds.candidate_wait, backfill_settled).await;
            if self.resolved(object_ref) {
                self.metrics
                    .peer_checkpoint_candidates_total
                    .with_label_values(&["folded"])
                    .inc();
                info!(
                    ?object_ref,
                    seq,
                    "peer checkpoint lookup: recovered the object from the archive checkpoint a \
                     peer named"
                );
                return LookupOutcome::Recovered;
            }
            self.metrics
                .peer_checkpoint_candidates_total
                .with_label_values(&["not_folded"])
                .inc();
            warn!(
                ?object_ref,
                seq,
                "peer checkpoint lookup: the checkpoint a peer named did not prove the object \
                 (it failed verification, does not attest this reference, or the archive has not \
                 served it yet); trying the next candidate"
            );
        }
        LookupOutcome::NotRecovered
    }

    fn record_answers(&self, answers: &PeerCheckpointAnswers) {
        for (answer, count) in [
            ("named", answers.named),
            ("unknown", answers.unknown),
            ("unimplemented", answers.unimplemented),
            ("failed", answers.failed),
        ] {
            if count > 0 {
                self.metrics
                    .peer_checkpoint_answers_total
                    .with_label_values(&[answer])
                    .inc_by(count as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, ProofProvider, ProofProviderMetrics,
        VerifiedDynamicFieldsPageRequest, VerifiedDynamicFieldsPageResponse, VerifiedObjectEntry,
        VerifiedObjectResponse,
    };
    use ika_network::sui_state_mirror::{
        MirrorCheckpointPeers, ObjectCheckpointLocator, SuiMirrorPeers, SuiMirrorProofProvider,
        SuiMirrorTransport, make_server,
    };
    use ika_sui_client::archive::{ArchiveError, CheckpointArchive};
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction};
    use ika_types::messages_dwallet_mpc::IkaPackageConfig;
    use ika_types::sui::system_inner_v1::{
        BlsCommittee, ProtocolTreasuryV1, SystemInnerV1, SystemObjectCap, ValidatorSetV1,
    };
    use ika_types::sui::{ExtendedField, System, SystemInnerTrait};
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::TypeTag;
    use sui_types::balance::{Balance, Supply};
    use sui_types::base_types::{
        ExecutionDigests, MoveObjectType, SequenceNumber, TransactionDigest,
    };
    use sui_types::coin::TreasuryCap;
    use sui_types::collection_types::{Bag, Table, VecMap};
    use sui_types::committee::Committee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::dynamic_field::Field;
    use sui_types::effects::{EffectsObjectChange, TransactionEffects};
    use sui_types::execution_status::ExecutionStatus;
    use sui_types::full_checkpoint_content::{CheckpointData, CheckpointTransaction};
    use sui_types::gas::GasCostSummary;
    use sui_types::id::UID;
    use sui_types::message_envelope::Message;
    use sui_types::messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointCommitment, CheckpointContents,
        CheckpointSummary,
    };
    use sui_types::object::{MoveObject, Object, Owner};
    use sui_types::parse_sui_type_tag;
    use sui_types::test_checkpoint_data_builder::TestCheckpointBuilder;

    use crate::sui_connector::committee_store::{CommitteeBootstrap, CommitteeStore};
    use crate::sui_connector::push_worker::{
        IkaCheckpointPusher, LostCheckpoint, load_lost_checkpoints,
    };
    use crate::sui_connector::verified_reader::OcsVerifiedReader;
    use crate::sui_connector::verified_state_cache::VerifiedStateCache;

    /// The fresh node's fullnode head, and its persisted pusher cursor.
    const HEAD: CheckpointSequenceNumber = 1_000;
    const RETAIN_WINDOW: u64 = 1_000;

    // -- fixtures ---------------------------------------------------------------------------

    /// This node's fullnode: at `HEAD`, every checkpoint pruned, reporting
    /// `live` as the current objects.
    struct PrunedFullnode {
        live: HashMap<ObjectID, Object>,
    }

    impl PrunedFullnode {
        fn reporting(live: &[&Object]) -> Arc<dyn SuiTransport> {
            Arc::new(Self {
                live: live.iter().map(|o| (o.id(), (*o).clone())).collect(),
            })
        }
    }

    #[async_trait]
    impl SuiTransport for PrunedFullnode {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!("the pusher probes the watermark")
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            Ok(HEAD)
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Err(TransportError::NotFound(format!("checkpoint {seq} pruned")))
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
            self.live
                .get(&id)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("object {id} not found")))
        }
        async fn get_object_with_version(
            &self,
            _: ObjectID,
            _: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(&self, _: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _: ObjectID,
            _: Option<u32>,
            _: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// The checkpoint archive: serves `checkpoints`, NotFound for the rest,
    /// and records every fetch.
    #[derive(Default)]
    struct MockArchive {
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        fetches: Mutex<Vec<CheckpointSequenceNumber>>,
    }

    impl MockArchive {
        fn serving(checkpoints: Vec<CheckpointData>) -> Arc<Self> {
            Arc::new(Self {
                checkpoints: checkpoints
                    .into_iter()
                    .map(|data| (*data.checkpoint_summary.sequence_number(), data))
                    .collect(),
                fetches: Mutex::new(Vec::new()),
            })
        }

        fn fetched(&self, seq: CheckpointSequenceNumber) -> usize {
            self.fetches.lock().iter().filter(|s| **s == seq).count()
        }
    }

    #[async_trait]
    impl CheckpointArchive for MockArchive {
        async fn enumerate_end_of_epoch_seqs(
            &self,
        ) -> Result<Vec<CheckpointSequenceNumber>, ArchiveError> {
            unimplemented!()
        }
        async fn fetch_checkpoint(
            &self,
            _: CheckpointSequenceNumber,
        ) -> Result<(CertifiedCheckpointSummary, CheckpointContents), ArchiveError> {
            unimplemented!()
        }
        async fn fetch_checkpoint_data(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, ArchiveError> {
            self.fetches.lock().push(seq);
            self.checkpoints
                .get(&seq)
                .cloned()
                .ok_or_else(|| ArchiveError::Fetch {
                    url: "mock".into(),
                    seq,
                    source: anyhow::anyhow!("Checkpoint {seq} not found in archive"),
                })
        }
    }

    /// Peers that give a set answer, counting how often they are asked.
    struct FakePeers {
        answers: Mutex<PeerCheckpointAnswers>,
        asks: AtomicUsize,
    }

    fn named(candidates: &[CheckpointSequenceNumber]) -> PeerCheckpointAnswers {
        PeerCheckpointAnswers {
            candidates: candidates.to_vec(),
            asked: candidates.len(),
            named: candidates.len(),
            ..Default::default()
        }
    }

    impl FakePeers {
        fn answering(answers: PeerCheckpointAnswers) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers),
                asks: AtomicUsize::new(0),
            })
        }

        fn naming(candidates: &[CheckpointSequenceNumber]) -> Arc<Self> {
            Self::answering(named(candidates))
        }
    }

    #[async_trait]
    impl ObjectCheckpointPeers for FakePeers {
        async fn ask(&self, _: ObjectRef) -> PeerCheckpointAnswers {
            self.asks.fetch_add(1, Ordering::Relaxed);
            self.answers.lock().clone()
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        committee: Committee,
        keys: Vec<AuthorityKeyPair>,
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        cache: SharedVerifiedStateCache,
        metrics: Arc<OcsMetrics>,
        packages: IkaPackageConfig,
    }

    /// A direct node at genesis committee[0] whose pusher cursor is persisted
    /// at `HEAD`, with an empty durable cache built as the connector stack
    /// builds it (pinning every recorded lost checkpoint).
    fn fixture() -> Fixture {
        let (committee, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        perpetual.put_sui_pusher_last_seq(HEAD).unwrap();
        let cache = durable_cache(&perpetual);
        Fixture {
            _dir: dir,
            committee,
            keys,
            perpetual,
            committees,
            cache,
            metrics: OcsMetrics::new_for_testing(),
            packages: IkaPackageConfig {
                ika_package_id: ObjectID::from_single_byte(0x1A),
                ika_common_package_id: ObjectID::from_single_byte(0x1B),
                ika_dwallet_2pc_mpc_package_id: ObjectID::from_single_byte(0x1C),
                ika_dwallet_2pc_mpc_package_id_v2: None,
                ika_system_package_id: ObjectID::from_single_byte(0x1D),
            },
        }
    }

    fn durable_cache(perpetual: &Arc<AuthorityPerpetualTables>) -> SharedVerifiedStateCache {
        Arc::new(
            VerifiedStateCache::open(perpetual.clone())
                .unwrap()
                .with_retain_window(Some(RETAIN_WINDOW))
                .with_pinned_checkpoints(load_lost_checkpoints(perpetual).into_keys().collect()),
        )
    }

    /// Start this node's pusher — the archive backfill the lookup feeds — over
    /// `fullnode` and `archive`, and return its request queue.
    async fn start_pusher(
        fx: &Fixture,
        fullnode: Arc<dyn SuiTransport>,
        archive: Arc<MockArchive>,
    ) -> mpsc::Sender<PeerBackfillRequest> {
        let (requests, backfill_requests) = peer_backfill_channel();
        let pusher = IkaCheckpointPusher::new(
            fullnode,
            fx.perpetual.clone(),
            fx.metrics.clone(),
            &fx.packages,
            Duration::from_millis(10),
            fx.cache.clone(),
            fx.committees.clone(),
            Some(archive),
        )
        .await
        .unwrap()
        .with_archive_backfill(BTreeSet::new())
        .with_peer_backfill_requests(Some(backfill_requests));
        tokio::spawn(pusher.run());
        requests
    }

    fn test_bounds() -> RecoveryBounds {
        RecoveryBounds {
            stuck_after: Duration::ZERO,
            stuck_reset: Duration::from_secs(24 * 60 * 60),
            lookup_interval: Duration::ZERO,
            lookup_burst: 1_000,
            lookup_refill: Duration::from_secs(1),
            max_candidates_per_object: 3,
            max_concurrent: 8,
            max_tracked: 256,
            candidate_wait: Duration::from_millis(750),
        }
    }

    fn recovery(
        fx: &Fixture,
        fullnode: Arc<dyn SuiTransport>,
        backfill: mpsc::Sender<PeerBackfillRequest>,
        peers: Arc<dyn ObjectCheckpointPeers>,
        retention_floor: CheckpointSequenceNumber,
        bounds: RecoveryBounds,
    ) -> Arc<PeerCheckpointRecovery> {
        let recovery = Arc::new(PeerCheckpointRecovery::new(
            fullnode,
            fx.cache.clone(),
            backfill,
            Arc::new(move || retention_floor),
            bounds,
            fx.metrics.clone(),
        ));
        recovery.attach_peers(peers);
        recovery
    }

    /// Admit a lookup for `id` past the stuck clock (`test_bounds` has none)
    /// and run it.
    async fn look_up(recovery: &PeerCheckpointRecovery, id: ObjectID) -> LookupOutcome {
        let now = Instant::now();
        let mut admission = recovery.admit(id, now);
        if admission == Admission::Tracking {
            admission = recovery.admit(id, now);
        }
        assert_eq!(admission, Admission::Admitted);
        recovery.run_admitted(id).await
    }

    fn counter(vec: &prometheus::IntCounterVec, label: &str) -> u64 {
        vec.with_label_values(&[label]).get()
    }

    fn ika_object(fx: &Fixture, byte: u8, version: u64) -> Object {
        let ika = parse_sui_type_tag(&format!("{}::ika::IKA", fx.packages.ika_package_id)).unwrap();
        Object::new_move(
            MoveObject::new_coin(
                ika,
                SequenceNumber::from(version),
                ObjectID::from_single_byte(byte),
                1,
            ),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
            TransactionDigest::ZERO,
        )
    }

    /// A committee-signed checkpoint at `seq` with one transaction writing
    /// `written` (all at one version): the shape of a genuine archive blob,
    /// which passes the archive verification and `build_entries`.
    fn checkpoint_writing(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        written: &[Object],
    ) -> CheckpointData {
        let lamport_version = written[0].version();
        assert!(written.iter().all(|o| o.version() == lamport_version));
        let mut template = TestCheckpointBuilder::new(seq)
            .start_transaction(0)
            .finish_transaction();
        let transaction = CheckpointData::from(template.build_checkpoint())
            .transactions
            .remove(0)
            .transaction;
        let effects = TransactionEffects::new_from_execution_v2(
            ExecutionStatus::Success,
            committee.epoch(),
            GasCostSummary::default(),
            vec![],
            *transaction.digest(),
            lamport_version,
            written
                .iter()
                .map(|o| (o.id(), EffectsObjectChange::new(None, Some(o), true, false)))
                .collect(),
            None,
            None,
            vec![],
        );
        let contents =
            CheckpointContents::new_with_digests_only_for_tests([ExecutionDigests::new(
                *transaction.digest(),
                effects.digest(),
            )]);
        let artifacts_digest = CheckpointArtifacts::from([&effects].as_slice())
            .digest()
            .unwrap();
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 1,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts_digest)],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CheckpointData {
            checkpoint_summary: CertifiedCheckpointSummary::new_from_keypairs_for_testing(
                summary, keys, committee,
            ),
            checkpoint_contents: contents,
            transactions: vec![CheckpointTransaction {
                transaction,
                effects,
                events: None,
                input_objects: vec![],
                output_objects: written.to_vec(),
            }],
        }
    }

    /// The verified entries of `objects` in `data`, as a direct node's pusher
    /// folds them — what a peer that folded `data` holds.
    fn entries_of(data: &CheckpointData, objects: &[&Object]) -> Vec<VerifiedObjectEntry> {
        let tree = ModifiedObjectTree::new(&CheckpointArtifacts::from(data)).unwrap();
        objects
            .iter()
            .map(|object| VerifiedObjectEntry {
                object: (*object).clone(),
                checkpoint_seq: *data.checkpoint_summary.sequence_number(),
                proof: tree
                    .get_inclusion_proof(object.compute_object_reference())
                    .unwrap(),
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            })
            .collect()
    }

    /// Fold a filler object at `seq`, far past the retain window, so the
    /// sweep drops every snapshot it does not keep.
    fn sweep_at(fx: &Fixture, seq: CheckpointSequenceNumber) {
        let filler = ika_object(fx, 0xF1, 1);
        let data = checkpoint_writing(&fx.committee, &fx.keys, seq, slice_of(&filler));
        fx.cache
            .absorb_entries(&data.checkpoint_summary, &entries_of(&data, &[&filler]));
    }

    fn slice_of(object: &Object) -> &[Object] {
        std::slice::from_ref(object)
    }

    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // -- serving ------------------------------------------------------------------------------

    /// A peer answers the checkpoint of its verified snapshot at exactly the
    /// asked reference.
    #[tokio::test]
    async fn serving_answers_the_checkpoint_of_an_exact_reference() {
        let fx = fixture();
        let x = ika_object(&fx, 0xA1, 7);
        let data = checkpoint_writing(&fx.committee, &fx.keys, 42, slice_of(&x));
        fx.cache
            .absorb_entries(&data.checkpoint_summary, &entries_of(&data, &[&x]));
        assert_eq!(
            fx.cache.checkpoint_proving(x.compute_object_reference()),
            Some(42)
        );
    }

    /// Another version — older or newer — or another digest at the same
    /// version is not what the peer holds: it answers "don't know", never the
    /// checkpoint of the version it does hold. So does an object it never saw.
    #[tokio::test]
    async fn serving_does_not_know_a_version_or_digest_it_does_not_hold() {
        let fx = fixture();
        let x = ika_object(&fx, 0xA1, 7);
        let data = checkpoint_writing(&fx.committee, &fx.keys, 42, slice_of(&x));
        fx.cache
            .absorb_entries(&data.checkpoint_summary, &entries_of(&data, &[&x]));
        let (id, version, digest) = x.compute_object_reference();
        for asked in [
            ika_object(&fx, 0xA1, 6).compute_object_reference(),
            ika_object(&fx, 0xA1, 8).compute_object_reference(),
            (id, version, ika_object(&fx, 0xB2, 7).digest()),
            ika_object(&fx, 0xC3, 7).compute_object_reference(),
        ] {
            assert_ne!(asked, (id, version, digest));
            assert_eq!(fx.cache.checkpoint_proving(asked), None, "{asked:?}");
        }
    }

    /// A peer that recovered an object through its own lost-checkpoint
    /// backfill answers that checkpoint too — long after it fell out of the
    /// retain window, since the record keeps it pinned.
    #[tokio::test]
    async fn serving_answers_from_a_lost_checkpoint_the_peer_backfilled() {
        let fx = fixture();
        const LOST: CheckpointSequenceNumber = 300;
        fx.perpetual
            .put_sui_pusher_lost_checkpoint(
                LOST,
                LostCheckpoint::Pending {
                    archive_not_found_since: None,
                },
            )
            .unwrap();
        // Rebuilt as at boot: the record pins its checkpoint.
        let fx = Fixture {
            cache: durable_cache(&fx.perpetual),
            ..fx
        };
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(vec![checkpoint_writing(
            &fx.committee,
            &fx.keys,
            LOST,
            slice_of(&x),
        )]);
        let _requests = start_pusher(&fx, PrunedFullnode::reporting(&[&x]), archive).await;
        let x_ref = x.compute_object_reference();
        eventually("the lost checkpoint's backfill", || {
            fx.cache.checkpoint_of(x_ref).is_some()
        })
        .await;
        sweep_at(&fx, HEAD + 10 * RETAIN_WINDOW);
        assert_eq!(fx.cache.checkpoint_proving(x_ref), Some(LOST));
    }

    // -- requester ----------------------------------------------------------------------------

    /// A correct answer: the named checkpoint is fetched from the archive,
    /// verified, folded for the object at exactly the fullnode's reference,
    /// recorded as a lost checkpoint and pinned — so the snapshot survives
    /// the sweep and a restart backfills it again if it must.
    #[tokio::test]
    async fn a_named_checkpoint_is_verified_from_the_archive_folded_and_pinned() {
        let fx = fixture();
        const NAMED: CheckpointSequenceNumber = 400;
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(vec![checkpoint_writing(
            &fx.committee,
            &fx.keys,
            NAMED,
            slice_of(&x),
        )]);
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;
        let peers = FakePeers::naming(&[NAMED]);
        let recovery = recovery(&fx, fullnode, requests, peers.clone(), 0, test_bounds());

        assert_eq!(look_up(&recovery, x.id()).await, LookupOutcome::Recovered);

        let x_ref = x.compute_object_reference();
        assert_eq!(fx.cache.checkpoint_of(x_ref), Some(NAMED));
        assert_eq!(archive.fetched(NAMED), 1);
        assert_eq!(
            load_lost_checkpoints(&fx.perpetual).get(&NAMED),
            Some(&LostCheckpoint::Settled)
        );
        assert!(fx.cache.is_checkpoint_pinned(NAMED));
        for (outcome, count) in [("fetched", 1), ("verified", 1), ("folded", 1)] {
            assert_eq!(
                counter(&fx.metrics.pusher_backfill_outcomes_total, outcome),
                count,
                "{outcome}"
            );
        }
        let candidates = &fx.metrics.peer_checkpoint_candidates_total;
        assert_eq!(counter(candidates, "submitted"), 1);
        assert_eq!(counter(candidates, "folded"), 1);
        assert_eq!(
            counter(&fx.metrics.peer_checkpoint_lookups_total, "recovered"),
            1
        );
        assert!(!recovery.is_tracking(x.id()), "a recovered object is done");

        sweep_at(&fx, HEAD + 10 * RETAIN_WINDOW);
        assert_eq!(fx.cache.checkpoint_of(x_ref), Some(NAMED), "pinned");
    }

    /// A malicious answer whose archive blob fails verification (signed by a
    /// committee that is not Sui's) folds nothing.
    #[tokio::test]
    async fn a_named_checkpoint_that_fails_verification_folds_nothing() {
        let fx = fixture();
        const FORGED: CheckpointSequenceNumber = 400;
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(vec![checkpoint_writing(
            &foreign,
            &foreign_keys,
            FORGED,
            slice_of(&x),
        )]);
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;
        let recovery = recovery(
            &fx,
            fullnode,
            requests,
            FakePeers::naming(&[FORGED]),
            0,
            test_bounds(),
        );

        assert_eq!(
            look_up(&recovery, x.id()).await,
            LookupOutcome::NotRecovered
        );
        assert!(fx.cache.get(x.id()).is_none(), "nothing folded");
        assert!(archive.fetched(FORGED) >= 1);
        assert!(counter(&fx.metrics.pusher_backfill_failures_total, "verification") >= 1);
        assert_eq!(
            counter(&fx.metrics.peer_checkpoint_candidates_total, "not_folded"),
            1
        );
    }

    /// A genuine checkpoint that wrote the object at another version than the
    /// fullnode reports — an older write — folds nothing: the archived object
    /// must be exactly the current one.
    #[tokio::test]
    async fn a_named_checkpoint_of_another_version_folds_nothing() {
        let fx = fixture();
        const OLDER: CheckpointSequenceNumber = 350;
        let x = ika_object(&fx, 0xA1, 7);
        let x_older = ika_object(&fx, 0xA1, 6);
        let archive = MockArchive::serving(vec![checkpoint_writing(
            &fx.committee,
            &fx.keys,
            OLDER,
            slice_of(&x_older),
        )]);
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;
        let recovery = recovery(
            &fx,
            fullnode,
            requests,
            FakePeers::naming(&[OLDER]),
            0,
            test_bounds(),
        );

        assert_eq!(
            look_up(&recovery, x.id()).await,
            LookupOutcome::NotRecovered
        );
        assert_eq!(archive.fetched(OLDER), 1);
        assert!(
            fx.cache.get(x.id()).is_none(),
            "neither the archived nor the current version is folded"
        );
        assert_eq!(
            counter(
                &fx.metrics.pusher_backfill_outcomes_total,
                "nothing_to_fold"
            ),
            1
        );
        assert!(
            !load_lost_checkpoints(&fx.perpetual).contains_key(&OLDER),
            "a checkpoint that folded nothing leaves no record or pin behind"
        );
        assert!(!fx.cache.is_checkpoint_pinned(OLDER));
    }

    /// Wrong answers first, then the right one: each wrong candidate folds
    /// nothing and the next is tried, until one proves the object.
    #[tokio::test]
    async fn after_a_wrong_answer_the_next_candidate_is_tried() {
        let fx = fixture();
        const FORGED: CheckpointSequenceNumber = 300;
        const OLDER: CheckpointSequenceNumber = 350;
        const NAMED: CheckpointSequenceNumber = 400;
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(vec![
            checkpoint_writing(&foreign, &foreign_keys, FORGED, slice_of(&x)),
            checkpoint_writing(
                &fx.committee,
                &fx.keys,
                OLDER,
                slice_of(&ika_object(&fx, 0xA1, 6)),
            ),
            checkpoint_writing(&fx.committee, &fx.keys, NAMED, slice_of(&x)),
        ]);
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;
        let recovery = recovery(
            &fx,
            fullnode,
            requests,
            FakePeers::naming(&[FORGED, OLDER, NAMED]),
            0,
            test_bounds(),
        );

        assert_eq!(look_up(&recovery, x.id()).await, LookupOutcome::Recovered);
        assert_eq!(
            fx.cache.checkpoint_of(x.compute_object_reference()),
            Some(NAMED)
        );
        for seq in [FORGED, OLDER, NAMED] {
            assert!(archive.fetched(seq) >= 1, "{seq} fetched");
        }
        let candidates = &fx.metrics.peer_checkpoint_candidates_total;
        assert_eq!(counter(candidates, "submitted"), 3);
        assert_eq!(counter(candidates, "not_folded"), 2);
        assert_eq!(counter(candidates, "folded"), 1);
    }

    /// Peers that do not serve the lookup — older binaries, mirrored nodes —
    /// and peers that fail are "don't know": the lookup ends without a
    /// candidate and without an error, and asks again later. Mixed with a peer
    /// that knows, the lookup recovers.
    #[tokio::test]
    async fn an_old_peer_counts_as_dont_know() {
        let fx = fixture();
        const NAMED: CheckpointSequenceNumber = 400;
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(vec![checkpoint_writing(
            &fx.committee,
            &fx.keys,
            NAMED,
            slice_of(&x),
        )]);
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;

        let only_old = FakePeers::answering(PeerCheckpointAnswers {
            asked: 3,
            unimplemented: 2,
            failed: 1,
            ..Default::default()
        });
        let old_only = recovery(
            &fx,
            fullnode.clone(),
            requests.clone(),
            only_old,
            0,
            test_bounds(),
        );
        assert_eq!(look_up(&old_only, x.id()).await, LookupOutcome::NoCandidate);
        assert!(old_only.is_tracking(x.id()), "asked again later");
        assert_eq!(
            counter(&fx.metrics.peer_checkpoint_answers_total, "unimplemented"),
            2
        );
        assert_eq!(archive.fetched(NAMED), 0);

        let mixed = FakePeers::answering(PeerCheckpointAnswers {
            candidates: vec![NAMED],
            asked: 3,
            named: 1,
            unimplemented: 2,
            ..Default::default()
        });
        let mixed = recovery(&fx, fullnode, requests, mixed, 0, test_bounds());
        assert_eq!(look_up(&mixed, x.id()).await, LookupOutcome::Recovered);
    }

    /// At most `max_candidates_per_object` distinct candidates per object
    /// reference, ever: one already tried is not tried again, the rest of an
    /// answer past the budget is refused before any download, and once the
    /// budget is spent the peers are not even asked.
    #[tokio::test]
    async fn the_candidates_per_object_are_capped_and_deduplicated() {
        let fx = fixture();
        let x = ika_object(&fx, 0xA1, 7);
        // Genuine checkpoints of an object that no longer exists: each settles
        // at once with nothing to fold.
        let gone = ika_object(&fx, 0xD4, 2);
        let seqs: [CheckpointSequenceNumber; 4] = [301, 302, 303, 304];
        let archive = MockArchive::serving(
            seqs.iter()
                .map(|seq| checkpoint_writing(&fx.committee, &fx.keys, *seq, slice_of(&gone)))
                .collect(),
        );
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;

        let peers = FakePeers::naming(&[301]);
        let first = recovery(
            &fx,
            fullnode.clone(),
            requests.clone(),
            peers.clone(),
            0,
            test_bounds(),
        );
        assert_eq!(look_up(&first, x.id()).await, LookupOutcome::NotRecovered);

        // Asked again, the peers name more.
        *peers.answers.lock() = named(&seqs);
        assert_eq!(look_up(&first, x.id()).await, LookupOutcome::NotRecovered);
        let candidates = &fx.metrics.peer_checkpoint_candidates_total;
        assert_eq!(counter(candidates, "submitted"), 3);
        assert_eq!(counter(candidates, "already_tried"), 1);
        assert_eq!(counter(candidates, "over_budget"), 1);
        assert_eq!(archive.fetched(301), 1, "never downloaded twice");
        assert_eq!(archive.fetched(304), 0, "over the budget: never downloaded");

        assert_eq!(look_up(&first, x.id()).await, LookupOutcome::Exhausted);
        assert_eq!(
            peers.asks.load(Ordering::Relaxed),
            2,
            "an exhausted object does not ask the peers again"
        );
    }

    /// A candidate older than the archive's retention, or above this node's
    /// processed checkpoint, is refused before any download.
    #[tokio::test]
    async fn candidates_beyond_the_retention_or_above_the_head_are_refused() {
        let fx = fixture();
        const EXPIRED: CheckpointSequenceNumber = 200;
        const NAMED: CheckpointSequenceNumber = 600;
        const AHEAD: CheckpointSequenceNumber = HEAD + 5;
        let x = ika_object(&fx, 0xA1, 7);
        let archive = MockArchive::serving(
            [EXPIRED, NAMED, AHEAD]
                .iter()
                .map(|seq| checkpoint_writing(&fx.committee, &fx.keys, *seq, slice_of(&x)))
                .collect(),
        );
        let fullnode = PrunedFullnode::reporting(&[&x]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;

        let refused = recovery(
            &fx,
            fullnode.clone(),
            requests.clone(),
            FakePeers::naming(&[EXPIRED, AHEAD]),
            500,
            test_bounds(),
        );
        assert_eq!(look_up(&refused, x.id()).await, LookupOutcome::NoCandidate);
        let candidates = &fx.metrics.peer_checkpoint_candidates_total;
        assert_eq!(counter(candidates, "beyond_retention"), 1);
        assert_eq!(counter(candidates, "above_head"), 1);
        assert_eq!(counter(candidates, "submitted"), 0);
        assert!(archive.fetches.lock().is_empty(), "nothing downloaded");
        assert!(fx.cache.get(x.id()).is_none());

        let accepted = recovery(
            &fx,
            fullnode,
            requests,
            FakePeers::naming(&[EXPIRED, NAMED, AHEAD]),
            500,
            test_bounds(),
        );
        assert_eq!(look_up(&accepted, x.id()).await, LookupOutcome::Recovered);
        assert_eq!(archive.fetched(EXPIRED), 0);
        assert_eq!(archive.fetched(AHEAD), 0);
    }

    /// A recovery with only its gate in use, and its own metrics.
    fn gate(
        fx: &Fixture,
        bounds: RecoveryBounds,
    ) -> (Arc<PeerCheckpointRecovery>, Arc<OcsMetrics>) {
        let (requests, _queue) = peer_backfill_channel();
        let metrics = OcsMetrics::new_for_testing();
        let recovery = Arc::new(PeerCheckpointRecovery::new(
            PrunedFullnode::reporting(&[]),
            fx.cache.clone(),
            requests,
            Arc::new(|| 0),
            bounds,
            metrics.clone(),
        ));
        (recovery, metrics)
    }

    fn oid(byte: u8) -> ObjectID {
        ObjectID::from_single_byte(byte)
    }

    /// Per object, on a controlled clock: nothing starts before the p2p
    /// network is attached; a lookup starts only once the object has stayed
    /// unprovable for `stuck_after`, never while one runs, then at most once
    /// per `lookup_interval`; and a pause in the reports restarts the stuck
    /// clock.
    #[tokio::test]
    async fn lookups_wait_for_a_stuck_object_and_are_spaced_per_object() {
        let fx = fixture();
        let b = RecoveryBounds::default();
        let (recovery, _) = gate(&fx, b.clone());
        let t0 = Instant::now();

        assert_eq!(recovery.admit(oid(1), t0), Admission::Tracking);
        assert_eq!(
            recovery.admit(oid(1), t0 + b.stuck_after),
            Admission::Waiting,
            "not attached yet"
        );
        recovery.attach_peers(FakePeers::naming(&[]));
        assert_eq!(
            recovery.admit(oid(1), t0 + b.stuck_after / 2),
            Admission::Waiting
        );
        let first = t0 + b.stuck_after;
        assert_eq!(recovery.admit(oid(1), first), Admission::Admitted);
        assert_eq!(
            recovery.admit(oid(1), first + Duration::from_secs(1)),
            Admission::Waiting,
            "in flight"
        );
        recovery.finish(oid(1), LookupOutcome::NoCandidate);
        assert_eq!(
            recovery.admit(oid(1), first + b.lookup_interval / 2),
            Admission::Waiting
        );
        assert_eq!(
            recovery.admit(oid(1), first + b.lookup_interval),
            Admission::Admitted
        );
        recovery.finish(oid(1), LookupOutcome::NoCandidate);

        let resumed = first + b.lookup_interval + b.stuck_reset;
        assert_eq!(recovery.admit(oid(1), resumed), Admission::Tracking);
        assert_eq!(
            recovery.admit(oid(1), resumed + b.stuck_after / 2),
            Admission::Waiting
        );
        assert_eq!(
            recovery.admit(oid(1), resumed + b.stuck_after),
            Admission::Admitted
        );
    }

    /// Node-wide: a lookup budget (a burst, then one per `lookup_refill`), at
    /// most `max_concurrent` lookups at once, and at most `max_tracked`
    /// objects tracked — an idle one makes room.
    #[tokio::test]
    async fn lookups_are_bounded_node_wide() {
        let fx = fixture();
        let t0 = Instant::now();

        let b = RecoveryBounds {
            stuck_after: Duration::ZERO,
            lookup_burst: 2,
            lookup_refill: Duration::from_secs(60),
            ..RecoveryBounds::default()
        };
        let (budget, metrics) = gate(&fx, b.clone());
        budget.attach_peers(FakePeers::naming(&[]));
        for byte in [1, 2, 3] {
            assert_eq!(budget.admit(oid(byte), t0), Admission::Tracking);
        }
        for byte in [1, 2] {
            assert_eq!(budget.admit(oid(byte), t0), Admission::Admitted);
            budget.finish(oid(byte), LookupOutcome::NoCandidate);
        }
        assert_eq!(
            budget.admit(oid(3), t0 + b.lookup_refill / 2),
            Admission::Throttled(Throttle::RateLimit)
        );
        assert_eq!(
            budget.admit(oid(3), t0 + b.lookup_refill),
            Admission::Admitted
        );
        assert_eq!(
            counter(
                &metrics.peer_checkpoint_lookups_throttled_total,
                "rate_limit"
            ),
            1
        );

        let b = RecoveryBounds {
            stuck_after: Duration::ZERO,
            max_concurrent: 2,
            ..RecoveryBounds::default()
        };
        let (concurrency, metrics) = gate(&fx, b);
        concurrency.attach_peers(FakePeers::naming(&[]));
        for byte in [1, 2, 3] {
            concurrency.admit(oid(byte), t0);
        }
        assert_eq!(concurrency.admit(oid(1), t0), Admission::Admitted);
        assert_eq!(concurrency.admit(oid(2), t0), Admission::Admitted);
        assert_eq!(
            concurrency.admit(oid(3), t0),
            Admission::Throttled(Throttle::Concurrency)
        );
        concurrency.finish(oid(1), LookupOutcome::NoCandidate);
        assert_eq!(concurrency.admit(oid(3), t0), Admission::Admitted);
        assert_eq!(
            counter(
                &metrics.peer_checkpoint_lookups_throttled_total,
                "concurrency"
            ),
            1
        );

        let b = RecoveryBounds {
            max_tracked: 2,
            ..RecoveryBounds::default()
        };
        let (tracked, metrics) = gate(&fx, b.clone());
        assert_eq!(tracked.admit(oid(1), t0), Admission::Tracking);
        assert_eq!(tracked.admit(oid(2), t0), Admission::Tracking);
        assert_eq!(
            tracked.admit(oid(3), t0),
            Admission::Throttled(Throttle::TrackedFull)
        );
        let later = t0 + b.stuck_reset;
        assert_eq!(tracked.admit(oid(2), later), Admission::Tracking);
        assert_eq!(
            tracked.admit(oid(3), later),
            Admission::Tracking,
            "the idle object made room"
        );
        assert!(!tracked.is_tracking(oid(1)));
        assert_eq!(
            counter(
                &metrics.peer_checkpoint_lookups_throttled_total,
                "tracked_full"
            ),
            1
        );
    }

    /// One read per retained day back from the head; conservative by one
    /// epoch; 0 when nothing retained is older than the cutoff; a hole in the
    /// retained history stops the walk.
    #[test]
    fn the_retention_floor_follows_the_end_of_epoch_timestamps() {
        // Epoch e ends at checkpoint 100 * (e + 1), at 1_000 * (e + 1) ms.
        let chain = |epoch: u64| Some((100 * (epoch + 1), 1_000 * (epoch + 1)));
        // Head epoch 10; epochs 0..=9 ended. Epochs ending at or after 5_500 ms
        // are 5..=9; the oldest of them, 5, ends at checkpoint 600.
        assert_eq!(archive_retention_floor(Some(10), chain, 5_500), 601);
        assert_eq!(archive_retention_floor(Some(10), chain, 5_000), 501);
        assert_eq!(archive_retention_floor(Some(10), chain, 0), 0);
        assert_eq!(archive_retention_floor(None, chain, 5_000), 0);
        assert_eq!(archive_retention_floor(Some(0), chain, 5_000), 0);
        // The newest end is already older than the cutoff: only the current
        // epoch remains.
        assert_eq!(archive_retention_floor(Some(10), chain, 99_000), 1_001);
        // A hole at epoch 6: nothing below it is trusted.
        let holed = |epoch: u64| (epoch != 6).then(|| (100 * (epoch + 1), 1_000 * (epoch + 1)));
        assert_eq!(archive_retention_floor(Some(10), holed, 0), 801);
    }

    // -- the reader's trigger -----------------------------------------------------------------

    struct PrunedProvider {
        batch: Mutex<Option<BatchVerifiedObjectsResponse>>,
    }

    #[async_trait]
    impl ProofProvider for PrunedProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::NotFound(format!(
                "the defining checkpoint of {id} is pruned and no snapshot matches"
            )))
        }
        async fn batch_verified_objects(
            &self,
            _: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            Ok(self.batch.lock().take().expect("one batch per test"))
        }
        async fn verified_dynamic_fields_page(
            &self,
            _: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unimplemented!()
        }
    }

    fn reader(
        fx: &Fixture,
        cache_first: bool,
        batch: Option<BatchVerifiedObjectsResponse>,
        recovery: Arc<PeerCheckpointRecovery>,
    ) -> OcsVerifiedReader {
        OcsVerifiedReader::new(
            Arc::new(PrunedProvider {
                batch: Mutex::new(batch),
            }),
            fx.committees.clone(),
            fx.metrics.clone(),
            None,
            fx.cache.clone(),
            cache_first,
            Some(100),
        )
        .with_peer_checkpoint_recovery(Some(recovery))
    }

    /// The reader reports exactly the reads that fail for good on a direct
    /// node — a single read the provider could not prove, a batch slot it
    /// could not prove — and nothing on a cache hit or on a mirrored node.
    #[tokio::test]
    async fn the_reader_reports_the_objects_it_cannot_prove_on_a_direct_node() {
        let fx = fixture();
        let (requests, _queue) = peer_backfill_channel();
        let recovery = recovery(
            &fx,
            PrunedFullnode::reporting(&[]),
            requests,
            FakePeers::naming(&[]),
            0,
            RecoveryBounds::default(),
        );
        let single = ObjectID::from_single_byte(0xA1);
        let in_batch = ObjectID::from_single_byte(0xB2);
        let cached = ika_object(&fx, 0xC3, 4);
        let data = checkpoint_writing(&fx.committee, &fx.keys, 42, slice_of(&cached));
        fx.cache
            .absorb_entries(&data.checkpoint_summary, &entries_of(&data, &[&cached]));

        let mirrored = reader(&fx, false, None, recovery.clone());
        assert!(mirrored.verified_object(single).await.is_err());
        assert!(
            !recovery.is_tracking(single),
            "a mirrored node never reports"
        );

        // Claims the cache's own head, so the staleness tripwire stays quiet
        // and the cached object below is a genuine cache hit.
        let batch = BatchVerifiedObjectsResponse {
            summaries: BTreeMap::new(),
            results: vec![None],
            claimed_latest_checkpoint_seq: 42,
        };
        let direct = reader(&fx, true, Some(batch), recovery.clone());
        assert!(direct.verified_object(single).await.is_err());
        assert!(recovery.is_tracking(single));
        assert!(direct.verified_objects(&[in_batch]).await.is_err());
        assert!(recovery.is_tracking(in_batch));
        assert!(direct.verified_object(cached.id()).await.is_ok());
        assert!(
            !recovery.is_tracking(cached.id()),
            "a cache hit is no report"
        );
    }

    // -- end to end ---------------------------------------------------------------------------

    fn network(router: anemo::Router) -> anemo::Network {
        anemo::Network::bind("localhost:0")
            .private_key(rand::random::<[u8; 32]>())
            .server_name("test")
            .start(router)
            .unwrap()
    }

    struct AlwaysNames(CheckpointSequenceNumber);

    impl ObjectCheckpointLocator for AlwaysNames {
        fn checkpoint_proving(&self, _: ObjectRef) -> Option<CheckpointSequenceNumber> {
            Some(self.0)
        }
    }

    /// A direct peer serving the real `SuiStateMirror` server, with `locator`
    /// answering the lookup (its transport and provider are never reached).
    fn direct_peer(locator: Arc<dyn ObjectCheckpointLocator>) -> anemo::Network {
        let metrics = ProofProviderMetrics::new_for_testing();
        let peers = SuiMirrorPeers::new(network(anemo::Router::new()), vec![], metrics.clone());
        let transport = Arc::new(SuiMirrorTransport::new(peers.clone()));
        let provider = Arc::new(SuiMirrorProofProvider::new(peers, metrics.clone()));
        network(anemo::Router::new().add_rpc_service(make_server(
            transport,
            provider,
            metrics,
            Some(locator),
        )))
    }

    fn move_object(type_tag: &str, version: u64, contents: Vec<u8>, owner: Owner) -> Object {
        let TypeTag::Struct(tag) = parse_sui_type_tag(type_tag).unwrap() else {
            panic!("{type_tag} is a struct type");
        };
        // `MoveObject`'s fields are private and its constructor for an
        // arbitrary type is `unsafe`; its serialized layout is public. Neither
        // anchor type has `store`, so `has_public_transfer` is false.
        let layout = (
            MoveObjectType::from(*tag),
            false,
            SequenceNumber::from(version),
            contents,
        );
        let object: MoveObject = bcs::from_bytes(&bcs::to_bytes(&layout).unwrap()).unwrap();
        Object::new_move(object, owner, TransactionDigest::ZERO)
    }

    fn empty_bls_committee() -> BlsCommittee {
        BlsCommittee {
            members: vec![],
            aggregated_protocol_pubkey: bcs::from_bytes(&bcs::to_bytes(&Vec::<u8>::new()).unwrap())
                .unwrap(),
            quorum_threshold: 0,
            validity_threshold: 0,
        }
    }

    fn system_inner(epoch: u64) -> SystemInnerV1 {
        let oid = ObjectID::from_single_byte;
        SystemInnerV1 {
            epoch,
            epoch_start_tx_digest: vec![7; 32],
            system_object_cap: SystemObjectCap { id: oid(0x31) },
            protocol_version: 1,
            next_protocol_version: None,
            upgrade_caps: vec![],
            approved_upgrades: VecMap { contents: vec![] },
            validator_set: ValidatorSetV1 {
                total_stake: 0,
                reward_slashing_rate: 0,
                validators: Table::default(),
                active_committee: empty_bls_committee(),
                next_epoch_committee: None,
                previous_committee: empty_bls_committee(),
                pending_active_set: ExtendedField { id: oid(0x32) },
                validator_report_records: VecMap { contents: vec![] },
                extra_fields: Bag::default(),
            },
            epoch_duration_ms: 86_400_000,
            stake_subsidy_start_epoch: 1,
            protocol_treasury: ProtocolTreasuryV1 {
                treasury_cap: TreasuryCap {
                    id: UID::new(oid(0x33)),
                    total_supply: Supply { value: 0 },
                },
                stake_subsidy_distribution_counter: 0,
                stake_subsidy_rate: 0,
                stake_subsidy_amount_per_distribution: 0,
                stake_subsidy_period_length: 0,
                total_supply_at_period_start: 0,
                extra_fields: Bag::default(),
            },
            epoch_start_timestamp_ms: 0,
            last_processed_checkpoint_sequence_number: 0,
            previous_epoch_last_checkpoint_sequence_number: 0,
            total_messages_processed: 0,
            remaining_rewards: Balance::new(0),
            authorized_protocol_cap_ids: vec![],
            witness_approving_advance_epoch: vec![],
            received_end_of_publish: false,
            extra_fields: Bag::default(),
        }
    }

    /// The `System` anchor and its versioned inner, both last written by one
    /// transaction at object version `version`.
    fn system_anchor(fx: &Fixture, system_id: ObjectID, version: u64) -> (Object, Object) {
        let package = fx.packages.ika_system_package_id;
        let outer = System {
            id: system_id,
            version: 1,
            package_id: package,
            new_package_id: None,
            migration_epoch: None,
        };
        let inner_id = ika_sui_client::transport::derive_versioned_child_id(system_id, 1).unwrap();
        let inner = Field {
            id: UID::new(inner_id),
            name: 1u64,
            value: system_inner(463),
        };
        (
            move_object(
                &format!("{package}::system::System"),
                version,
                bcs::to_bytes(&outer).unwrap(),
                Owner::Shared {
                    initial_shared_version: SequenceNumber::from(1u64),
                },
            ),
            move_object(
                &format!("0x2::dynamic_field::Field<u64, {package}::system_inner::SystemInner>"),
                version,
                bcs::to_bytes(&inner).unwrap(),
                Owner::ObjectOwner(system_id.into()),
            ),
        )
    }

    /// The incident shape, end to end over real anemo networks. A fresh direct
    /// node — empty cache, no lost-checkpoint record — whose fullnode reports
    /// the `System` anchor but has pruned the checkpoint that wrote it is stuck
    /// at the `verified_system_inner` boot barrier. Its peers: a direct node
    /// that holds the anchor's snapshot, a malicious one naming a checkpoint
    /// that proves nothing (tried first), and an older binary without the
    /// method. The fresh node asks, verifies the named checkpoint from the
    /// archive itself, folds the anchor and gets past the barrier.
    #[tokio::test]
    async fn a_fresh_direct_node_gets_past_the_system_barrier_through_a_direct_peer() {
        let fx = fixture();
        const DEFINING: CheckpointSequenceNumber = 700;
        const BOGUS: CheckpointSequenceNumber = 650;
        let system_id = ObjectID::from_single_byte(0x5A);
        let (outer, inner) = system_anchor(&fx, system_id, 11);
        let defining = checkpoint_writing(
            &fx.committee,
            &fx.keys,
            DEFINING,
            &[outer.clone(), inner.clone()],
        );

        // The peer that folded the defining checkpoint while it was live.
        let holder_cache = Arc::new(VerifiedStateCache::new());
        holder_cache.absorb_entries(
            &defining.checkpoint_summary,
            &entries_of(&defining, &[&outer, &inner]),
        );
        let holder = direct_peer(holder_cache);
        let malicious = direct_peer(Arc::new(AlwaysNames(BOGUS)));
        let old_binary = network(anemo::Router::new());

        // The fresh node.
        let fullnode = PrunedFullnode::reporting(&[&outer, &inner]);
        let archive = MockArchive::serving(vec![defining]);
        let requests = start_pusher(&fx, fullnode.clone(), archive.clone()).await;
        let fresh = network(anemo::Router::new());
        for peer in [&holder, &malicious, &old_binary] {
            fresh.connect(peer.local_addr()).await.unwrap();
        }
        let recovery = recovery(
            &fx,
            fullnode,
            requests,
            Arc::new(MirrorCheckpointPeers::new(fresh.clone())),
            0,
            RecoveryBounds {
                stuck_after: Duration::from_millis(100),
                lookup_interval: Duration::from_millis(100),
                candidate_wait: Duration::from_millis(500),
                ..RecoveryBounds::default()
            },
        );
        let reader = reader(&fx, true, None, recovery);

        // The barrier, as `must_get_system_inner` runs it.
        let started = Instant::now();
        let (system, inner_state) = loop {
            match reader.verified_system_inner(system_id).await {
                Ok(read) => break read,
                Err(e) => {
                    assert!(
                        started.elapsed() < Duration::from_secs(30),
                        "still stuck at the System barrier: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        assert_eq!(system.id, system_id);
        assert_eq!(inner_state.epoch(), 463);

        assert_eq!(
            fx.cache.checkpoint_of(outer.compute_object_reference()),
            Some(DEFINING)
        );
        assert_eq!(
            fx.cache.checkpoint_of(inner.compute_object_reference()),
            Some(DEFINING)
        );
        assert_eq!(
            load_lost_checkpoints(&fx.perpetual).get(&DEFINING),
            Some(&LostCheckpoint::Settled)
        );
        assert!(archive.fetched(BOGUS) >= 1, "the bogus answer was tried");
        let answers = &fx.metrics.peer_checkpoint_answers_total;
        assert!(counter(answers, "named") >= 2);
        assert!(counter(answers, "unimplemented") >= 1);
        let candidates = &fx.metrics.peer_checkpoint_candidates_total;
        assert!(counter(candidates, "not_folded") >= 1);
        assert_eq!(counter(candidates, "folded"), 1);
    }
}
