// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! sui-state-direct worker that polls Sui for new checkpoints, filters to
//! Ika-relevant ones (any output object whose Move type tree touches an Ika
//! package id — see `object_touches_ika`) plus all end-of-epoch checkpoints,
//! builds OCS inclusion proofs for the Ika-modified objects, and folds
//! `(summary, [(object, proof), ...])` into the local verified state cache
//! that sui-state-direct consumers read cache-first.
//!
//! This is the authoritative cache populator on a direct node: it folds
//! every Ika-modified object of every checkpoint, in order, so a cache hit
//! is the object's current state up to the poll lag.
//!
//! Bandwidth: scanning every Sui checkpoint requires a raw fetch; that cost
//! is unchanged. Only Ika-touched objects (with their proofs) are kept; all
//! non-Ika objects plus tx / effects are dropped.
//!
//! A checkpoint the scan cannot fold is retried as a pending gap
//! (`pending_gaps`, in memory). One the pusher finally gives up on — dropped
//! at the gap retry deadline, or sacrificed by a far-behind fast-forward — is
//! recorded in the perpetual `sui_pusher_lost_checkpoints` table
//! ([`LostCheckpoint`]) and re-folded from the checkpoint archive by the
//! archive backfill, now and after every restart, with its snapshots pinned
//! against the cache's retain window until they are superseded. A gap that
//! exists but this binary cannot read — it fails to decode or to fold — is
//! recorded earlier, on its first such failure, so a restart inside its retry
//! window does not lose it. A later
//! binary that can fold what this one could not therefore recovers it without a
//! hardcoded list or an operator config change.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::{StreamExt, stream};
use ika_network::proof_provider::VerifiedObjectEntry;
use ika_sui_client::archive::{ArchiveError, CheckpointArchive};
use ika_sui_client::transport::{SuiTransport, TransportError};
use ika_types::error::error_chain;
use ika_types::messages_dwallet_mpc::IkaPackageConfig;
use serde::{Deserialize, Serialize};
use sui_light_client::proof::ocs::ModifiedObjectTree;
use sui_types::TypeTag;
use sui_types::base_types::{ObjectID, ObjectRef};
use sui_types::digests::CheckpointArtifactsDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use sui_types::object::Object;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::sui_connector::committee_store::{
    CommitteeStore, CommitteeTransition, SummaryVerifyError,
};
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;
use crate::sui_connector::watermark_guard::WatermarkGuard;

/// Bound both outstanding RPCs and fetched checkpoints awaiting their turn
/// to fold. Overlap fullnode latency without buffering an entire catch-up span.
const MAX_CONCURRENT_CHECKPOINT_FETCHES: usize = 8;

/// Per-attempt bound on an archive backfill fetch. Sui's object-store reader
/// retries every error except NotFound internally for up to 60 s — HTTP
/// failures, and also a blob that fails to decompress, decode or convert — so
/// this sits above that window: a blob this binary cannot decode then surfaces
/// as its decode error instead of as a timeout. The fetch runs in its own task,
/// so the bound never holds back the scan; a timeout means the store kept
/// failing transiently for the whole internal retry window.
const ARCHIVE_BACKFILL_FETCH_TIMEOUT: Duration = Duration::from_secs(90);
/// First retry delay after a failed backfill attempt; doubles per failure.
const ARCHIVE_BACKFILL_RETRY_INITIAL: Duration = Duration::from_secs(5);
/// Cap on the backfill retry delay. Retries continue until the attempt
/// succeeds: a listed checkpoint is one the node needs, and the store may
/// recover.
const ARCHIVE_BACKFILL_RETRY_MAX: Duration = Duration::from_secs(600);
/// Bound on the fullnode lookups that check whether a backfilled object is
/// still current — one `get_object` per Ika object of the checkpoint, run
/// inside the tick, so this caps how long one attempt can hold the scan.
const ARCHIVE_BACKFILL_CURRENCY_TIMEOUT: Duration = Duration::from_secs(10);
/// Archive-backfill fetches in flight at once. A due checkpoint beyond this
/// waits for a slot on a later tick, so a burst of recorded lost checkpoints
/// (a pruned-at-head window can drop thousands) rolls through the archive
/// instead of hitting it all at once.
const MAX_CONCURRENT_BACKFILL_FETCHES: usize = 4;
/// Most lost checkpoints recorded at once (see [`LostCheckpoint`]). A
/// pruned-at-head window followed by a fast-forward can give up on thousands
/// of checkpoints at mainnet rates; most of them carry no Ika object and are
/// collected on their first successful backfill, so the cap only binds when
/// the archive cannot serve them either. A loss past the cap is not recorded:
/// it warns and counts in `pusher_lost_checkpoints_overflow_total`.
const MAX_LOST_CHECKPOINTS: usize = 1_024;
/// How long a recorded lost checkpoint is retried after the archive first
/// answered NotFound for it. NotFound is the store's definitive answer, and
/// the public stores ingest a checkpoint within minutes, so a NotFound that
/// persists this long means the store has expired it (ordinary checkpoints
/// are kept ~30 days).
/// The record is then abandoned loudly. Operator-listed checkpoints never give
/// up.
const ARCHIVE_NOT_FOUND_GIVE_UP_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// How often settled lost-checkpoint records are checked for collection: one
/// pass over the cache for all of them.
const LOST_CHECKPOINT_COLLECT_INTERVAL: Duration = Duration::from_secs(60);

/// The persisted record of one Sui checkpoint the pusher gave up on, or is
/// about to — in the perpetual `sui_pusher_lost_checkpoints` table, keyed by
/// sequence number.
///
/// Written when the pusher gives up on a pending gap (the retry deadline, or a
/// far-behind fast-forward), and earlier for a gap that exists but this binary
/// cannot read — the fullnode served it and it failed to decode or to fold, or
/// the archive served a verified blob that failed to fold: on its first such
/// failure (see `record_failing_gap`). The pending gap itself is in
/// memory while the scan cursor is already persisted past it, so without the
/// early record a restart inside the gap's retry window — when operators
/// restart and upgrade nodes — loses it for good. The early record is not
/// scheduled for the backfill in that process: the live gap retry stays the
/// only path for the seq until the deadline, which schedules it, or a repair,
/// which deletes the record and releases the pin. Only a restart in between
/// turns it into a backfill, from the boot path like any other record.
///
/// A record is just a pointer: the checkpoint is re-folded from the archive by
/// the archive backfill, which runs the full archive verification
/// (`verify_archive_checkpoint`, then `build_entries`) and folds only objects
/// the node's own fullnode still reports at exactly the archived reference.
/// While the record exists its checkpoint is pinned against the verified
/// cache's retain window, from boot (the connector stack pins every record
/// when it builds the cache) and from the moment it is recorded at runtime.
///
/// The value layout is part of the database's rollback contract (see the
/// column family): never change it in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LostCheckpoint {
    /// Not folded from the archive yet. Never collected: no snapshot from it
    /// exists yet, which is exactly why it is kept.
    Pending {
        /// Unix seconds of the archive's first NotFound answer since it last
        /// served the checkpoint — the clock of the give-up
        /// (`ARCHIVE_NOT_FOUND_GIVE_UP_AFTER`).
        archive_not_found_since: Option<u64>,
    },
    /// The backfill settled. Kept, and its snapshots pinned, until no snapshot
    /// from the checkpoint is left in the cache — every object it folded has
    /// been superseded by a newer version. Deleting it on the fold alone would
    /// unpin it at the next boot, and the next sweep would drop exactly what
    /// was recovered.
    Settled,
}

impl LostCheckpoint {
    const NEW: Self = Self::Pending {
        archive_not_found_since: None,
    };
}

/// The recorded lost checkpoints in `perpetual`. A table that cannot be read
/// degrades to an empty set with a warn rather than failing the boot: the
/// records are a recovery aid, and the pusher records new losses regardless.
pub fn load_lost_checkpoints(
    perpetual: &AuthorityPerpetualTables,
) -> BTreeMap<CheckpointSequenceNumber, LostCheckpoint> {
    perpetual
        .load_sui_pusher_lost_checkpoints()
        .unwrap_or_else(|e| {
            warn!(
                error = ?e,
                "the recorded lost checkpoints could not be read; they are neither pinned nor \
                 backfilled by this process"
            );
            BTreeMap::new()
        })
}

pub struct IkaCheckpointPusher {
    /// Raw Sui transport used to fetch full checkpoints for proof
    /// construction. Kept off the cached layer so this scan doesn't
    /// pollute consumer caches.
    transport: Arc<dyn SuiTransport>,
    perpetual: Arc<AuthorityPerpetualTables>,
    metrics: Arc<OcsMetrics>,
    ika_packages: HashSet<ObjectID>,
    poll_interval: Duration,
    cursor: CheckpointSequenceNumber,
    /// Direct-side write target for the verified state cache: each
    /// checkpoint's `(summary, entries)` is folded here so sui-state-direct
    /// consumers read it cache-first without a network round-trip.
    cache: SharedVerifiedStateCache,
    /// Committee chain. Each end-of-epoch checkpoint this worker streams past
    /// carries `committee[E+1]`, so we capture it here the moment we see it —
    /// the chain is then never forced to reach back for a (possibly-pruned)
    /// end-of-epoch checkpoint. The background ratchet remains the fallback.
    committees: Arc<CommitteeStore>,
    /// Scanned checkpoints whose full contents were not yet fetchable, keyed
    /// to when they were first seen missing. The fullnode materializes a
    /// checkpoint's contents AFTER its summary certifies — tens of seconds
    /// later under load — so the scan must not stall behind one (freezing
    /// the whole cache) nor skip it silently (a PERMANENT cache gap: an Ika
    /// object whose only mutation rode the missed checkpoint — e.g. a
    /// session_events bag entry — never enters the cache, the bag event
    /// pump never delivers the session, and the epoch-close gate pins the
    /// epoch forever). Gaps are retried every tick and folded LATE when
    /// they materialize — safe because the verified state cache is
    /// monotonic-by-version, so an out-of-order fold can only fill gaps,
    /// never regress state. A gap the fullnode keeps refusing is fetched
    /// from the checkpoint `archive` instead (same committee verification
    /// at fold time); only a gap that BOTH sources fail to serve until the
    /// retry deadline is dropped with a loud warn. In-memory only, behind a
    /// cursor already persisted past them: a gap is lost on restart, where
    /// the on-chain uncompleted-session re-pull is the backstop — except one
    /// that has failed to decode or fold, which is recorded in
    /// `lost_checkpoints` on its first such failure, so the next boot
    /// backfills it. A gap the pusher
    /// gives up on is recorded (if it is not already) and handed to the
    /// archive backfill.
    pending_gaps: BTreeMap<CheckpointSequenceNumber, PendingGap>,
    /// Verified-fallback source for gap checkpoints the fullnode pruned
    /// before the pusher could fetch them. The public Sui checkpoint stores
    /// retain ordinary checkpoints ~30 days — far beyond any fullnode
    /// pruning window — and everything fetched is committee-verified at
    /// fold time, so this is an availability source, never a trust source.
    /// `None` when no archive resolved (a localnet without one configured):
    /// gaps then behave as before — retried against the fullnode until the
    /// deadline, then dropped.
    archive: Option<Arc<dyn CheckpointArchive>>,
    /// Rate bound on the (unauthenticated) latest-checkpoint watermark.
    /// Everything this worker does with the watermark lands in state that
    /// cannot come back down — the persisted cursor and the cache's monotone
    /// processed head — so an inflated sample used to poison both
    /// permanently, across restarts (ika #2041). See [`WatermarkGuard`] for
    /// why the bound meters advance admitted within this process rather than
    /// distance from the persisted cursor.
    watermark: WatermarkGuard,
    /// The far-behind fast-forward target proposed by the PREVIOUS tick, if
    /// that tick saw the far-behind condition. The fast-forward is the one
    /// single-shot, persisted, span-sacrificing consumer of the watermark, so
    /// it acts only on a target two consecutive ticks agree on. Taken at the
    /// top of every tick — before the probe and before the rate bound — so a
    /// tick that errored, was refused, or simply was not far behind disarms
    /// it: confirmation can only ever come from the immediately preceding
    /// tick.
    pending_fast_forward: Option<CheckpointSequenceNumber>,
    /// Whether the stall warn has already fired for the current stretch. Both
    /// this and [`Self::watermark_refusal_warned`] are transition latches: the
    /// conditions they describe persist for as long as they last, and at a
    /// 250 ms poll a per-tick warn is ~14k lines an hour each. Log on entering
    /// the condition and once on leaving it; the gauges stay per-tick, which
    /// is where duration belongs.
    stall_warned: bool,
    /// Whether the watermark-refusal warn has already fired for the current
    /// stretch. See [`Self::stall_warned`].
    watermark_refusal_warned: bool,
    /// Checkpoints still to be re-folded from the archive (see
    /// [`Self::with_archive_backfill`]). Unlike `pending_gaps` these are
    /// checkpoints behind the cursor whose objects the node lost for good —
    /// the fullnode pruned them before any fold succeeded — so they are
    /// retried until they fold. Only a recorded lost checkpoint the archive no
    /// longer holds is ever given up on (`ARCHIVE_NOT_FOUND_GIVE_UP_AFTER`).
    archive_backfill: BTreeMap<CheckpointSequenceNumber, BackfillState>,
    /// The persisted lost-checkpoint records ([`LostCheckpoint`]), mirrored in
    /// memory. Loaded at construction, added to when a pending gap first fails
    /// to decode or fold and when the pusher gives up on a checkpoint, deleted
    /// when a gap
    /// recorded early is repaired, settled by the backfill and collected once
    /// nothing from the checkpoint is left in the cache.
    lost_checkpoints: BTreeMap<CheckpointSequenceNumber, LostCheckpoint>,
    /// The operator's `sui-checkpoint-archive-backfill` list. Those seqs keep
    /// the operator semantics even when also recorded: they never give up, and
    /// collecting their record does not unpin them (the config pins them).
    operator_backfill: BTreeSet<CheckpointSequenceNumber>,
    /// When settled records were last checked for collection.
    lost_checkpoints_collected_at: Instant,
    /// Whether the record-full warn has fired for the current stretch at the
    /// cap — the same transition latch as [`Self::stall_warned`]; the counter
    /// carries the volume.
    lost_overflow_warned: bool,
    /// The Sui epoch (plus one; 0 = none yet) whose committee wait was last
    /// logged ([`Self::log_committee_wait`]). A wait repeats on every retry
    /// until the committee installs, and an installed committee never goes
    /// missing again, so one line per epoch is the whole story. Atomic because
    /// the fold path that logs it takes `&self`.
    committee_wait_logged: AtomicU64,
}

/// Retry state of one scanned-but-unfetchable checkpoint.
struct PendingGap {
    first_seen: Instant,
    /// When the archive was last consulted for this gap, so archive fetches
    /// are paced at `ARCHIVE_RETRY_INTERVAL` instead of every 250ms tick.
    last_archive_attempt: Option<Instant>,
}

type ArchiveFetch =
    JoinHandle<Result<Result<CheckpointData, ArchiveError>, tokio::time::error::Elapsed>>;

/// Retry state of one archive-backfill checkpoint.
struct BackfillState {
    failures: u32,
    next_attempt: Instant,
    /// The archive fetch, run in its own task so a slow store never holds back
    /// the scan; the pusher only folds its result, on the tick it finishes.
    in_flight: Option<ArchiveFetch>,
}

impl BackfillState {
    fn due(now: Instant) -> Self {
        Self {
            failures: 0,
            next_attempt: now,
            in_flight: None,
        }
    }
}

/// Why one archive-backfill attempt failed; the metric label of
/// `pusher_backfill_failures_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackfillFailure {
    /// The store answered NotFound: it does not (or no longer) hold the blob.
    ArchiveNotFound,
    /// Any other store error, including a blob this binary cannot decode.
    ArchiveFetch,
    /// No answer within `ARCHIVE_BACKFILL_FETCH_TIMEOUT`.
    ArchiveTimeout,
    /// The committee for the checkpoint's Sui epoch is not in the committee
    /// store.
    MissingCommittee,
    /// The blob failed the archive verification (sequence binding, committee
    /// signature or artifacts digest), or an output object of it is not the
    /// object the checkpoint attests for its id.
    Verification,
    /// The node's own fullnode could not say whether an object is current.
    CurrencyLookup,
}

impl BackfillFailure {
    fn label(self) -> &'static str {
        match self {
            Self::ArchiveNotFound => "archive_not_found",
            Self::ArchiveFetch => "archive_fetch",
            Self::ArchiveTimeout => "archive_timeout",
            Self::MissingCommittee => "missing_committee",
            Self::Verification => "verification",
            Self::CurrencyLookup => "currency_lookup",
        }
    }
}

/// How one archive-backfill checkpoint was settled; the `outcome` label of
/// `pusher_backfill_outcomes_total` (alongside the per-attempt `fetched`,
/// `verified` and `failed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackfillSettled {
    /// At least one object was folded.
    Folded,
    /// Every current object of the checkpoint was already cached.
    AlreadyCached,
    /// The checkpoint has no Ika object that is still current: none at all, or
    /// each was since modified, deleted or wrapped on chain.
    NothingToFold,
    /// Given up: a recorded lost checkpoint the archive no longer holds (see
    /// `ARCHIVE_NOT_FOUND_GIVE_UP_AFTER`). Nothing was folded.
    Abandoned,
}

impl BackfillSettled {
    fn label(self) -> &'static str {
        match self {
            Self::Folded => "folded",
            Self::AlreadyCached => "already_cached",
            Self::NothingToFold => "nothing_to_fold",
            Self::Abandoned => "abandoned",
        }
    }
}

impl IkaCheckpointPusher {
    pub async fn new(
        transport: Arc<dyn SuiTransport>,
        perpetual: Arc<AuthorityPerpetualTables>,
        metrics: Arc<OcsMetrics>,
        packages: &IkaPackageConfig,
        poll_interval: Duration,
        cache: SharedVerifiedStateCache,
        committees: Arc<CommitteeStore>,
        archive: Option<Arc<dyn CheckpointArchive>>,
    ) -> anyhow::Result<Self> {
        let mut ika_packages = HashSet::new();
        ika_packages.insert(packages.ika_package_id);
        ika_packages.insert(packages.ika_common_package_id);
        ika_packages.insert(packages.ika_dwallet_2pc_mpc_package_id);
        if let Some(v2) = packages.ika_dwallet_2pc_mpc_package_id_v2 {
            ika_packages.insert(v2);
        }
        ika_packages.insert(packages.ika_system_package_id);

        let watermark = WatermarkGuard::new();
        let cursor = match perpetual.get_sui_pusher_last_seq()? {
            Some(persisted) => {
                info!(
                    persisted,
                    "checkpoint pusher resuming from perpetual cursor"
                );
                persisted
            }
            None => {
                // Watermark probe, not a summary fetch: a fullnode pruning at
                // head NotFounds its own latest, which would fail node boot
                // here.
                let cursor = transport.get_latest_checkpoint_sequence().await?;
                // The FIRST watermark observation of this process: there is no
                // prior to meter it against — a node starting against a chain
                // millions of checkpoints in must pass — so it seeds the
                // guard's head, and the advance admitted after it is what the
                // rate bound meters.
                watermark.admit(cursor);
                info!(
                    cursor,
                    "checkpoint pusher first start — initializing at upstream latest"
                );
                perpetual.put_sui_pusher_last_seq(cursor)?;
                cursor
            }
        };
        metrics.pusher_cursor_seq.set(cursor as i64);
        metrics.pusher_lag_checkpoints.set(0);
        // Seed the cache's processed head so the reader's staleness tripwire
        // doesn't spuriously fire before the first poll tick advances it.
        cache.note_processed(cursor);
        let lost_checkpoints = load_lost_checkpoints(&perpetual);
        metrics
            .pusher_lost_checkpoints
            .set(lost_checkpoints.len() as i64);

        Ok(Self {
            transport,
            perpetual,
            metrics,
            ika_packages,
            poll_interval,
            cursor,
            cache,
            committees,
            pending_gaps: BTreeMap::new(),
            archive,
            watermark,
            pending_fast_forward: None,
            stall_warned: false,
            watermark_refusal_warned: false,
            archive_backfill: BTreeMap::new(),
            lost_checkpoints,
            operator_backfill: BTreeSet::new(),
            lost_checkpoints_collected_at: Instant::now(),
            lost_overflow_warned: false,
            committee_wait_logged: AtomicU64::new(0),
        })
    }

    /// Re-fold `seqs` — the operator's `sui-checkpoint-archive-backfill` list —
    /// and every recorded lost checkpoint ([`LostCheckpoint`]) from the
    /// checkpoint archive, without moving the cursor.
    ///
    /// Each checkpoint is one the node needs but never folded: the fold
    /// failed while the fullnode still served it, or the fullnode never served
    /// it, and the fullnode has since pruned it, so neither the scan, the
    /// pending-gap repair (in-memory, minutes) nor the proof provider (fullnode
    /// or this cache only) can bring its objects back. The archive retains
    /// ordinary checkpoints far longer. Checkpoints the pusher gives up on
    /// while running are recorded and scheduled the same way
    /// (`give_up_on_checkpoint`), so a restart resumes them here — as it does a
    /// pending gap recorded on its first decode or fold failure that the
    /// restart cut off before its deadline (`record_failing_gap`).
    ///
    /// Every attempt runs the archive-gap verification unchanged
    /// (`verify_archive_checkpoint`, then the fold-time verification inside
    /// `build_entries`); a blob that fails it is refused loudly and retried,
    /// never folded. Of the verified Ika objects, only those the node's own
    /// fullnode still reports at exactly that object reference are folded.
    /// The in-order scan never re-folds an old version over a newer one, but
    /// this checkpoint is far older than anything the scan reaches: a newer
    /// version of the object may have aged out of the cache's retain window
    /// since, and an object may have been deleted. Folding either would let a
    /// cache-first read serve state that is no longer current. This is the
    /// same currency bar the proof provider applies before reusing a snapshot.
    ///
    /// Skipped, with an info log: seqs with a snapshot already in the cache
    /// (folded earlier, and pinned — see
    /// `VerifiedStateCache::with_pinned_checkpoints`), and everything when no
    /// archive resolved. A seq above the cursor waits until the scan has
    /// passed it — the scan may fold it, or a far-behind fast-forward may skip
    /// it — and folding it first would move the cache's processed head past
    /// the cursor. Attempts run at the top of every tick, at most
    /// `MAX_CONCURRENT_BACKFILL_FETCHES` at a time, and are retried with capped
    /// exponential backoff until they settle.
    ///
    /// A record that settled in an earlier run but has no snapshot left is
    /// backfilled again rather than collected: this boot cannot tell whether
    /// its objects were superseded (the backfill then settles with nothing to
    /// fold and the record is collected) or evicted by something that did not
    /// honour the pin, such as a rolled-back binary (the backfill folds them
    /// again).
    pub fn with_archive_backfill(mut self, seqs: BTreeSet<CheckpointSequenceNumber>) -> Self {
        self.operator_backfill = seqs.clone();
        // The connector stack already pinned every record when it built the
        // cache; idempotent here, for a cache built without them.
        for seq in self.lost_checkpoints.keys() {
            self.cache.pin_checkpoint(*seq);
        }
        let all: BTreeSet<CheckpointSequenceNumber> = seqs
            .iter()
            .chain(self.lost_checkpoints.keys())
            .copied()
            .collect();
        if all.is_empty() {
            return self;
        }
        if self.archive.is_none() {
            info!(
                ?seqs,
                recorded = self.lost_checkpoints.len(),
                "no Sui checkpoint archive is configured; skipping the archive backfill"
            );
            return self;
        }
        let cached = self.cache.checkpoints_with_snapshots(&all);
        let now = Instant::now();
        for seq in all {
            let recorded = self.lost_checkpoints.get(&seq).copied();
            if cached.contains(&seq) {
                info!(
                    seq,
                    recorded = recorded.is_some(),
                    "archive backfill skipped: the checkpoint's objects are already cached"
                );
                self.record_backfill_settled(BackfillSettled::AlreadyCached);
                self.settle_lost_checkpoint(seq, BackfillSettled::AlreadyCached);
                continue;
            }
            if recorded == Some(LostCheckpoint::Settled) {
                self.update_lost_checkpoint(seq, LostCheckpoint::NEW);
            }
            info!(
                seq,
                cursor = self.cursor,
                deferred_until_scanned = seq > self.cursor,
                recorded = recorded.is_some(),
                "archive backfill scheduled"
            );
            self.archive_backfill.insert(seq, BackfillState::due(now));
        }
        self.metrics
            .pusher_backfill_pending
            .set(self.archive_backfill.len() as i64);
        self
    }

    /// Record `seq` — a pending gap below the cursor — as lost: persist the
    /// record and pin the checkpoint, before anything can fold it, so the
    /// first sweep after the fold keeps it. Does NOT schedule the archive
    /// backfill; that is [`Self::give_up_on_checkpoint`]. Persisted, so a
    /// restart pins and backfills it (`with_archive_backfill`) even if this
    /// process never gave up on it.
    ///
    /// Two callers: a pending gap's first failure that says this binary cannot
    /// read a checkpoint that exists ([`Self::record_failing_gap`] — the live
    /// gap retry keeps trying it, and stays the only path for the seq in this
    /// process), and every give-up. Returns whether `seq` is recorded and not
    /// scheduled for the backfill yet, by this call or an earlier one.
    ///
    /// Not recorded: anything when no archive resolved (nothing could re-fold
    /// it, and a drop is already counted), a seq already scheduled (an
    /// operator entry, which the backfill already owns), and a seq past the
    /// cap (`MAX_LOST_CHECKPOINTS`), which warns and counts instead.
    fn record_lost_checkpoint(
        &mut self,
        seq: CheckpointSequenceNumber,
        cause: &'static str,
    ) -> bool {
        if self.archive.is_none() || self.archive_backfill.contains_key(&seq) {
            return false;
        }
        if self.lost_checkpoints.contains_key(&seq) {
            return true;
        }
        if self.lost_checkpoints.len() >= MAX_LOST_CHECKPOINTS {
            self.metrics.pusher_lost_checkpoints_overflow_total.inc();
            if !self.lost_overflow_warned {
                warn!(
                    seq,
                    cause,
                    cap = MAX_LOST_CHECKPOINTS,
                    "the lost-checkpoint record is full: this checkpoint is NOT recorded and will \
                     not be backfilled from the archive; further losses count in \
                     ika_ocs_pusher_lost_checkpoints_overflow_total until records are collected \
                     (logged once per stretch)"
                );
                self.lost_overflow_warned = true;
            }
            return false;
        }
        self.lost_overflow_warned = false;
        if let Err(e) = self
            .perpetual
            .put_sui_pusher_lost_checkpoint(seq, LostCheckpoint::NEW)
        {
            warn!(
                seq,
                error = ?e,
                "failed to persist the lost-checkpoint record; it is backfilled by this process only"
            );
        }
        self.lost_checkpoints.insert(seq, LostCheckpoint::NEW);
        // Before anything can fold it, so the first sweep after the fold keeps
        // it.
        self.cache.pin_checkpoint(seq);
        self.metrics
            .pusher_lost_checkpoints
            .set(self.lost_checkpoints.len() as i64);
        info!(
            seq,
            cause,
            "recorded the checkpoint as lost: persisted and pinned, so a restart backfills it \
             from the archive"
        );
        true
    }

    /// A pending gap failed in a way that says the checkpoint exists but this
    /// binary cannot read it; the gap is retried until its deadline. Record it
    /// now ([`Self::record_lost_checkpoint`]): the gap lives in memory behind a
    /// persisted cursor, so a restart before the deadline would lose it. The
    /// triggers (`cause`):
    ///
    /// - `first_fold_failure`: the fullnode served it and the fold failed;
    /// - `first_decode_failure`: the fullnode served it and this binary could
    ///   not decode it — `get_full_checkpoint` failed with
    ///   [`TransportError::Encoding`], the shape that lost mainnet checkpoint
    ///   342064089 (a `TransactionExpiration` variant v1.4.1 did not know).
    ///   Recorded at the scan's first fetch, else at the first retry;
    /// - `first_archive_fold_failure`: the archive served a blob that passed
    ///   `verify_archive_checkpoint` and the fold still failed.
    ///
    /// Any other fetch failure — NotFound, a network error, a timeout, a rate
    /// limit — keeps the deadline-only rule, so a slow or pruning fullnode
    /// writes no records. A no-op once recorded, so only the first failure
    /// writes. At the cap it is skipped quietly: the gap is not lost yet, and a
    /// give-up at the deadline counts the overflow if it comes to that. For a
    /// deterministic failure (a binary that cannot decode a new type fails on
    /// every checkpoint carrying it) the early records are the ones the
    /// deadline would write, only sooner, so the cap fills no faster and the
    /// same losses overflow; a transient failure holds a slot it gives back on
    /// repair, for at most the retry window.
    fn record_failing_gap(&mut self, seq: CheckpointSequenceNumber, cause: &'static str) {
        if self.lost_checkpoints.len() < MAX_LOST_CHECKPOINTS {
            self.record_lost_checkpoint(seq, cause);
        }
    }

    /// Give up on `seq` — a pending gap below the cursor, dropped at its
    /// retry deadline or sacrificed by a far-behind fast-forward: record it
    /// unless its first decode or fold failure already did, and schedule its
    /// archive backfill, due at once (the scan has passed it).
    fn give_up_on_checkpoint(&mut self, seq: CheckpointSequenceNumber, cause: &'static str) {
        if !self.record_lost_checkpoint(seq, cause) {
            return;
        }
        self.archive_backfill
            .insert(seq, BackfillState::due(Instant::now()));
        self.metrics
            .pusher_backfill_pending
            .set(self.archive_backfill.len() as i64);
        info!(
            seq,
            cause, "gave up on the lost checkpoint; it is backfilled from the archive now"
        );
    }

    /// A pending gap was repaired before its deadline — folded from the
    /// fullnode or from the archive, as gaps were before lost checkpoints were
    /// recorded at all. Delete the record its first decode or fold failure
    /// wrote, if any, and release its pin unless the operator's list pins the
    /// seq too:
    /// the gap's snapshots are as current as anything the scan folds and age
    /// with the window like them (the singleton anchors are pinned by id
    /// anyway). Otherwise every transient fold failure — `MissingCommittee`
    /// at each Sui epoch boundary — would leave a record and a pin behind.
    fn forget_repaired_gap(&mut self, seq: CheckpointSequenceNumber) {
        if self.lost_checkpoints.contains_key(&seq) {
            self.forget_lost_checkpoint(seq);
            info!(
                seq,
                "the gap was repaired: deleted the lost-checkpoint record its first failure wrote"
            );
        }
    }

    /// Persist a changed record.
    fn update_lost_checkpoint(&mut self, seq: CheckpointSequenceNumber, record: LostCheckpoint) {
        if self.lost_checkpoints.get(&seq) == Some(&record) {
            return;
        }
        if let Err(e) = self.perpetual.put_sui_pusher_lost_checkpoint(seq, record) {
            warn!(seq, error = ?e, "failed to persist a lost-checkpoint record update");
        }
        self.lost_checkpoints.insert(seq, record);
    }

    /// Delete a record and release its pin — unless the operator's list pins
    /// the seq too.
    fn forget_lost_checkpoint(&mut self, seq: CheckpointSequenceNumber) {
        if self.lost_checkpoints.remove(&seq).is_none() {
            return;
        }
        if let Err(e) = self.perpetual.delete_sui_pusher_lost_checkpoint(seq) {
            warn!(seq, error = ?e, "failed to delete a lost-checkpoint record");
        }
        if !self.operator_backfill.contains(&seq) {
            self.cache.unpin_checkpoint(seq);
        }
        self.metrics
            .pusher_lost_checkpoints
            .set(self.lost_checkpoints.len() as i64);
    }

    /// The backfill of `seq` settled: keep the record (now `Settled`) while a
    /// snapshot from it is in the cache, collect it otherwise — nothing to
    /// fold, or every object it would have kept is already cached at a newer
    /// checkpoint. A no-op for a seq that is not recorded.
    fn settle_lost_checkpoint(&mut self, seq: CheckpointSequenceNumber, settled: BackfillSettled) {
        if !self.lost_checkpoints.contains_key(&seq) {
            return;
        }
        if settled == BackfillSettled::NothingToFold
            || self.cache.snapshots_from_checkpoint(seq) == 0
        {
            self.forget_lost_checkpoint(seq);
            info!(
                seq,
                outcome = settled.label(),
                "lost-checkpoint record collected: no snapshot from it is left to keep"
            );
        } else {
            self.update_lost_checkpoint(seq, LostCheckpoint::Settled);
        }
    }

    /// Collect every settled record none of whose snapshots is left in the
    /// cache — each object it folded has been superseded by a newer version,
    /// so its pin keeps nothing. One pass over the cache for all of them, at
    /// most every `LOST_CHECKPOINT_COLLECT_INTERVAL`. A pending record is never
    /// collected here: it has no snapshot because it has not folded yet.
    fn collect_lost_checkpoints(&mut self) {
        self.lost_checkpoints_collected_at = Instant::now();
        let settled: BTreeSet<CheckpointSequenceNumber> = self
            .lost_checkpoints
            .iter()
            .filter(|(_, record)| **record == LostCheckpoint::Settled)
            .map(|(seq, _)| *seq)
            .collect();
        let still_cached = self.cache.checkpoints_with_snapshots(&settled);
        for seq in settled.difference(&still_cached) {
            self.forget_lost_checkpoint(*seq);
            info!(
                seq,
                "lost-checkpoint record collected: every snapshot from it has been superseded"
            );
        }
    }

    /// Note a NotFound answer from the archive for `seq` and say whether the
    /// record's give-up time has come. Only recorded, still-pending,
    /// non-operator seqs ever give up.
    fn archive_not_found_expired(&mut self, seq: CheckpointSequenceNumber) -> bool {
        if self.operator_backfill.contains(&seq) {
            return false;
        }
        let Some(LostCheckpoint::Pending {
            archive_not_found_since,
        }) = self.lost_checkpoints.get(&seq).copied()
        else {
            return false;
        };
        let now = unix_seconds_now();
        match archive_not_found_since {
            Some(since) => now.saturating_sub(since) >= ARCHIVE_NOT_FOUND_GIVE_UP_AFTER.as_secs(),
            None => {
                self.update_lost_checkpoint(
                    seq,
                    LostCheckpoint::Pending {
                        archive_not_found_since: Some(now),
                    },
                );
                false
            }
        }
    }

    /// The archive served `seq`: it holds the checkpoint, so restart the
    /// give-up clock of its record.
    fn note_archive_served(&mut self, seq: CheckpointSequenceNumber) {
        if let Some(LostCheckpoint::Pending {
            archive_not_found_since: Some(_),
        }) = self.lost_checkpoints.get(&seq)
        {
            self.update_lost_checkpoint(seq, LostCheckpoint::NEW);
        }
    }

    /// Give up on a recorded lost checkpoint the archive no longer holds: stop
    /// the backfill, delete the record, release the pin. Loud — the objects
    /// only that checkpoint wrote stay missing from the cache until their next
    /// mutation.
    fn abandon_lost_checkpoint(&mut self, seq: CheckpointSequenceNumber, detail: &str) {
        self.archive_backfill.remove(&seq);
        self.metrics
            .pusher_backfill_pending
            .set(self.archive_backfill.len() as i64);
        self.record_backfill_settled(BackfillSettled::Abandoned);
        self.forget_lost_checkpoint(seq);
        warn!(
            seq,
            give_up_after = ?ARCHIVE_NOT_FOUND_GIVE_UP_AFTER,
            error = detail,
            "archive backfill abandoned: the archive has answered NotFound for this recorded lost \
             checkpoint since longer than the give-up window, so it no longer holds it (public \
             stores keep ordinary checkpoints about 30 days); objects only this checkpoint wrote \
             stay missing from the verified cache until their next mutation"
        );
    }

    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(self.poll_interval);
        loop {
            tick.tick().await;
            if let Err(e) = self.advance().await {
                warn!(
                    error = %error_chain(&e),
                    "checkpoint pusher tick failed; will retry"
                );
            }
        }
    }

    async fn advance(&mut self) -> anyhow::Result<()> {
        // Needs no watermark and never blocks on the archive (the fetch runs in
        // its own task), so it runs ahead of everything that can end the tick.
        self.drive_archive_backfill().await;
        self.retry_pending_gaps().await;
        if self.lost_checkpoints_collected_at.elapsed() >= LOST_CHECKPOINT_COLLECT_INTERVAL {
            self.collect_lost_checkpoints();
        }

        // Disarm the previous tick's fast-forward proposal HERE, before the
        // probe can fail and before a sample can be refused: confirmation must
        // come from the immediately preceding tick, so any tick that does not
        // re-propose — including one that errored or was refused — leaves the
        // proposal behind it.
        let proposed_fast_forward = self.pending_fast_forward.take();

        // Watermark probe, not a summary fetch: `get_latest_checkpoint` reads
        // through the fullnode's availability window, so a fullnode pruning at
        // head NotFounds its own latest and aborts this tick — permanently,
        // while the window stays empty. The height watermark survives pruning.
        let latest_seq = self.transport.get_latest_checkpoint_sequence().await?;

        // Legacy lag flag: a moving cursor can still remain behind upstream.
        // Last-progress time separately identifies a stopped scanner. Lag
        // can cause cache-first reads to fall through to the network
        // (`cache_first_stale_total`). `STALL_THRESHOLD` sits between the
        // normal per-tick lag (a handful) and the FAR_BEHIND fast-forward.
        // Computed from the raw sample, BEFORE the rate bound below decides
        // whether to use it: the gauge is neither monotone nor persisted, so a
        // bad sample cannot latch it, and a run of refused ticks is a real
        // stall — the folder is not advancing — which must not read healthy
        // just because the reason was a refusal.
        // The warn is latched to the transition (see `stall_warned`); the
        // gauge is not, because duration is what a gauge is for.
        const STALL_THRESHOLD: u64 = 100;
        let lag = latest_seq.saturating_sub(self.cursor);
        self.metrics.pusher_lag_checkpoints.set(lag as i64);
        let stalled = lag > STALL_THRESHOLD;
        self.metrics.pusher_stalled.set(stalled as i64);
        match (stalled, self.stall_warned) {
            (true, false) => warn!(
                cursor = self.cursor,
                latest_seq, lag, "pusher lag exceeds 100 checkpoints"
            ),
            (false, true) => info!(
                cursor = self.cursor,
                latest_seq, "pusher caught back up with upstream"
            ),
            _ => {}
        }
        self.stall_warned = stalled;

        // The watermark is an unauthenticated integer, and everything below
        // folds it into state that cannot come back down (the persisted
        // cursor, the cache's processed head). Refuse a sample claiming advance
        // faster than real checkpoint production can explain and skip the tick
        // entirely: nothing is scanned, persisted or noted, and the next tick
        // 250 ms later re-probes. Pending-gap repair already ran above and is
        // unaffected — it needs no watermark.
        if !self.watermark.admit(latest_seq) {
            // The counter carries the per-tick volume; the warn is latched to
            // the transition (see `watermark_refusal_warned`), since a refusal
            // stretch can last as long as the upstream keeps it up.
            self.metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .inc();
            if !self.watermark_refusal_warned {
                warn!(
                    cursor = self.cursor,
                    latest_seq,
                    "pusher stalled: upstream watermark exceeds the available rate allowance \
                     — skipping scans while allowance accrues \
                     (logged once until samples are accepted again)"
                );
                self.watermark_refusal_warned = true;
            }
            return Ok(());
        }
        if self.watermark_refusal_warned {
            info!(
                cursor = self.cursor,
                latest_seq, "upstream watermark samples are within the rate bound again"
            );
            self.watermark_refusal_warned = false;
        }
        if latest_seq <= self.cursor {
            return Ok(());
        }

        // Fast-forward past the prune horizon if we've fallen too far behind.
        const FAR_BEHIND_THRESHOLD: u64 = 1_000;
        const CATCHUP_LOOKBACK: u64 = 100;
        if latest_seq.saturating_sub(self.cursor) > FAR_BEHIND_THRESHOLD {
            // The fast-forward is irreversible: it persists a cursor far ahead
            // of what was folded and drops every pending gap below it, before
            // fetching anything. Act only on a target two consecutive ticks
            // AGREE on — the second within `CONFIRMATION_BAND` of the first,
            // in either direction — and then jump to the LOWER of the two.
            // Agreement has to be two-sided and the target conservative: with
            // a one-sided "at least as high" test, the confirming sample is
            // itself unbounded above the proposal, so an inflated confirmer
            // (or an alternating load balancer whose high backend always lands
            // in the confirming slot) would execute an inflated jump — the
            // confirmation would be checking the wrong sample.
            //
            // The band is one minute of real production (~4/s): two ticks are
            // 250 ms apart, and even a tick delayed by every bounded retry
            // budget in `retry_pending_gaps` (tens of seconds) leaves genuine
            // production far inside it. Two samples further apart than that
            // are not one head observed twice, so the tick re-proposes instead
            // of jumping. A source that keeps flapping outside the band never
            // fast-forwards and stays visibly stalled (`pusher_stalled`),
            // which is the correct outcome: unexplained samples must not
            // sacrifice a span.
            //
            // Confirmation is by repeated observation rather than by fetching
            // the target checkpoint: an unfetchable target does not
            // distinguish an inflated watermark from an upstream prune, which
            // is the very condition that makes the fast-forward necessary —
            // gating on fetchability would turn a pruned-at-head window into a
            // scan of thousands of failing fetches and as many pending gaps.
            // Repeated observation is availability-independent and costs one
            // poll interval (250 ms) and no extra RPC.
            const CONFIRMATION_BAND: u64 = 250;
            let confirmed_target = proposed_fast_forward
                .filter(|proposed| latest_seq.abs_diff(*proposed) <= CONFIRMATION_BAND)
                .map(|proposed| proposed.min(latest_seq));
            let Some(target) = confirmed_target else {
                self.pending_fast_forward = Some(latest_seq);
                warn!(
                    cursor = self.cursor,
                    latest_seq,
                    proposed = ?proposed_fast_forward,
                    "pusher cursor far behind upstream — deferring the fast-forward one tick \
                     for watermark confirmation"
                );
                return Ok(());
            };
            let new_cursor = target.saturating_sub(CATCHUP_LOOKBACK);
            // Object state for the skipped span is sacrificed (a cache miss
            // there falls through / degrades), but the committee chain must NOT
            // skip an epoch boundary: capture every still-available end-of-epoch
            // committee in the span we're about to jump over first.
            self.capture_committees_through(new_cursor).await;
            warn!(
                old_cursor = self.cursor,
                new_cursor, latest_seq, "pusher cursor too far behind upstream — fast-forwarding"
            );
            self.cursor = new_cursor;
            self.metrics.pusher_cursor_seq.set(new_cursor as i64);
            self.metrics.pusher_last_progress_timestamp_seconds.set(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            );
            let _ = self.perpetual.put_sui_pusher_last_seq(new_cursor);
            // Pending gaps are given up on with the jump (covered by the
            // fast-forward warn above). They sit below the old cursor, in the
            // span the scan did reach, so each is a single known loss like a
            // gap dropped at its deadline: counted toward the drop alarm and
            // recorded (if a decode or fold failure has not already) and
            // scheduled for the archive backfill. The skipped span itself was
            // never fetched and is not recorded: it is the fast-forward's
            // deliberate sacrifice, unbounded in size.
            let kept = self.pending_gaps.split_off(&new_cursor.saturating_add(1));
            let sacrificed = std::mem::replace(&mut self.pending_gaps, kept);
            if !sacrificed.is_empty() {
                self.metrics
                    .pusher_gap_dropped_total
                    .inc_by(sacrificed.len() as u64);
                for seq in sacrificed.into_keys() {
                    self.give_up_on_checkpoint(seq, "fast_forward");
                }
            }
        }

        let transport = self.transport.clone();
        let mut checkpoints = stream::iter((self.cursor + 1)..=latest_seq)
            .map(|seq| {
                let transport = transport.clone();
                async move { (seq, transport.get_full_checkpoint(seq).await) }
            })
            // Results must reach the fold in sequence order: an end-of-epoch
            // checkpoint installs the committee needed by the next epoch.
            // Dropping this stream on a fold error cancels the remaining
            // fetches without advancing their cursors or caching their data.
            .buffered(MAX_CONCURRENT_CHECKPOINT_FETCHES);
        while let Some((seq, result)) = checkpoints.next().await {
            let undecodable = match result {
                Ok(data) => {
                    self.fold_checkpoint(seq, &data)?;
                    false
                }
                Err(e) => {
                    self.metrics.pusher_fetch_failures_total.inc();
                    // Keep scanning — later checkpoints usually ARE
                    // fetchable — and queue this one as a pending gap,
                    // retried at the top of every tick (see `pending_gaps`
                    // for why neither stalling here nor skipping silently
                    // is acceptable).
                    debug!(
                        seq,
                        error = ?e,
                        "full-checkpoint fetch failed; queued as a pending gap"
                    );
                    self.pending_gaps.entry(seq).or_insert_with(|| PendingGap {
                        first_seen: Instant::now(),
                        last_archive_attempt: None,
                    });
                    matches!(e, TransportError::Encoding(_))
                }
            };
            self.cursor = seq;
            self.metrics.pusher_cursor_seq.set(seq as i64);
            self.metrics.pusher_last_progress_timestamp_seconds.set(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            );
            if let Err(e) = self.perpetual.put_sui_pusher_last_seq(seq) {
                warn!(seq, error = ?e, "failed to persist pusher cursor");
            }
            // The fullnode served the checkpoint and this binary could not
            // decode it: the earliest moment it is known to be unreadable,
            // recorded once the cursor has passed it (see
            // `record_failing_gap`).
            if undecodable {
                self.record_failing_gap(seq, "first_decode_failure");
            }
        }
        // The cache reflects every checkpoint up to the cursor now — including
        // the ones with no Ika objects, which don't advance the fold head. The
        // reader's tripwire keys off this so a quiet stretch doesn't force a
        // (prune-prone) reach-back for a still-current cached object.
        self.cache.note_processed(self.cursor);
        Ok(())
    }

    /// Fold one fetched checkpoint: capture the committee transition the
    /// moment we stream past an end-of-epoch checkpoint (so the chain never
    /// reaches back for it), retain it so we can serve it to mirrored peers
    /// after our own fullnode prunes it, and absorb its Ika-modified objects
    /// into the local verified state cache that sui-state-direct consumers
    /// read cache-first. Shared by the in-order scan and the pending-gap
    /// retries (a late fold is version-safe — see `pending_gaps`).
    ///
    /// `build_entries` runs FIRST: it committee-verifies every end-of-epoch
    /// or object-folding checkpoint, so the retained end-of-epoch store is
    /// only ever written after the summary passed verification —
    /// `persist_end_of_epoch` itself does not verify, and writing before
    /// verifying would let a forged blob overwrite a genuine retained entry
    /// (an availability, not forgery, hazard for the mirrored peers served
    /// from that store — they re-verify — but a needless one).
    fn fold_checkpoint(
        &mut self,
        seq: CheckpointSequenceNumber,
        data: &CheckpointData,
    ) -> anyhow::Result<()> {
        let entries = self.build_entries(data)?;
        self.capture_committee(data);
        self.persist_end_of_epoch(data, seq);
        if let Some((summary, entries)) = entries {
            self.cache.absorb_entries(&summary, &entries);
            self.metrics.pusher_pushed_total.inc();
        } else {
            self.metrics.pusher_skipped_irrelevant_total.inc();
        }
        Ok(())
    }

    /// Verification an archive-served checkpoint must pass BEFORE it may
    /// clear a pending gap — strictly MORE than the fullnode fold path
    /// applies, because the archive is the lower-trust source (on the public
    /// chains it defaults to a third-party HTTP store) and `build_entries`
    /// verifies nothing for a checkpoint with no Ika-typed outputs — a blob
    /// that folds vacuously would silently clear the gap and suppress the
    /// `pusher_gap_dropped_total` alarm this fallback exists to feed:
    ///
    /// 1. the blob IS the requested checkpoint: `summary.sequence_number ==
    ///    seq` (the seq is inside the committee-signed summary, so a
    ///    mislabeled genuine blob fails here);
    /// 2. committee BLS on the summary, unconditionally;
    /// 3. the artifacts-digest binding over the blob's ENTIRE object set,
    ///    unconditionally — an emptied or altered object set produces a tree
    ///    root the committee never signed, so "no Ika objects on this
    ///    checkpoint" cannot be forged.
    fn verify_archive_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
        data: &CheckpointData,
    ) -> anyhow::Result<()> {
        let summary = &data.checkpoint_summary;
        if *summary.sequence_number() != seq {
            anyhow::bail!(
                "archive served checkpoint {} for requested seq {seq}",
                summary.sequence_number()
            );
        }
        let artifacts = CheckpointArtifacts::from(data);
        let tree = ModifiedObjectTree::new(&artifacts)
            .map_err(|e| anyhow::anyhow!("ModifiedObjectTree over archive blob: {e}"))?;
        self.verify_before_fold(summary, &tree, true)
    }

    /// Retry every pending gap once. A gap that materializes is folded late
    /// (version-safe) and cleared; one the fullnode keeps refusing past
    /// `ARCHIVE_FALLBACK_AFTER` is fetched from the checkpoint archive
    /// instead (paced at `ARCHIVE_RETRY_INTERVAL`, capped per tick) and
    /// folded through the same committee verification. Only a gap that BOTH
    /// sources fail to serve until the deadline is dropped with a loud warn
    /// and counted (`pusher_gap_dropped_total`) — and recorded as a lost
    /// checkpoint ([`LostCheckpoint`]) and scheduled for the archive backfill
    /// (`give_up_on_checkpoint`), which keeps re-folding it, across restarts,
    /// until it folds or the archive expires it; without that it is a
    /// permanent cache gap that can pin an epoch close (issue #2018).
    ///
    /// Fold failures stay pending rather than dropping immediately because
    /// they are not all deterministic: `verify_before_fold` fails with
    /// MissingCommittee while the checkpoint's epoch committee hasn't
    /// installed yet (follower lag at a Sui epoch boundary, or a restart near
    /// one) — exactly the transient the in-order scan path retries by pinning
    /// its cursor. A genuinely deterministic failure warns once per tick and
    /// expires at the same deadline — and stays recorded, so a later binary
    /// that can fold it recovers it from the archive. Until a backfill folds
    /// it, objects whose only mutation rode the checkpoint stay missing from
    /// the cache unless a later mutation or a consumer's network fallback
    /// repairs them.
    ///
    /// The record of a gap that exists but this binary cannot read is written
    /// on its FIRST such failure, not at the deadline (`record_failing_gap`):
    /// a fullnode fold failure, a fullnode fetch that fails to DECODE
    /// ([`TransportError::Encoding`] — the shape that lost mainnet checkpoint
    /// 342064089; decoding happens inside `get_full_checkpoint`, so that
    /// checkpoint never reached the fold), or a verified archive blob that
    /// fails to fold. The scan cursor is already persisted past the gap, so a
    /// restart inside the retry window — exactly when operators restart and
    /// upgrade nodes — would otherwise lose it for good. Every other fetch
    /// failure keeps the deadline-only rule. The record is not scheduled for
    /// the backfill here, so the live retry stays the only path for the seq in
    /// this process; the deadline schedules it, and the next boot schedules it
    /// if a restart comes first. A gap repaired before its deadline — from the
    /// fullnode or from the archive — deletes that record and releases its pin
    /// (`forget_repaired_gap`), so a transient failure leaves nothing behind.
    async fn retry_pending_gaps(&mut self) {
        const GAP_RETRY_DEADLINE: Duration = Duration::from_secs(600);
        // How long to give the fullnode alone before consulting the archive.
        // Covers the common late-materialization case (contents certify
        // seconds after the summary) without taxing the archive; a gap still
        // missing after this is very likely pruned upstream, and a fast
        // archive repair is what keeps the session's SDK-side wait (~600s)
        // from expiring.
        const ARCHIVE_FALLBACK_AFTER: Duration = Duration::from_secs(5);
        const ARCHIVE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
        // Bound the archive fetches of one tick so a prune burst (hundreds of
        // gaps at once under CI-grade load) rolls through the archive over a
        // few ticks instead of hammering it — and so a hung archive can stall
        // one tick by at most ATTEMPTS × FETCH_TIMEOUT (20s). The gap-retry
        // loop runs BEFORE the head scan, so an unbounded stall here would
        // hold the cursor back while the fullnode prunes more checkpoints —
        // the fallback amplifying the very loss it exists to prevent.
        const ARCHIVE_ATTEMPTS_PER_TICK: usize = 4;
        // Bound the FULLNODE retries of one tick for the same reason the
        // archive attempts are bounded above. A pruning-at-head window now
        // gets traversed rather than aborting the tick (which is the point —
        // see the watermark probe in `advance`), and every unfetchable
        // checkpoint in it becomes a pending gap: at mainnet rates that is
        // thousands by the retry deadline. Retrying all of them serially,
        // every 250ms tick, against the very fullnode that is already failing
        // to serve them is the self-amplification the archive cap exists to
        // avoid — reached through the uncapped half of the loop. Gaps are
        // retried oldest-first (`BTreeMap` order), so the ones nearest their
        // deadline keep priority and the rest roll through over later ticks.
        const FULLNODE_ATTEMPTS_PER_TICK: usize = 64;

        let mut archive_attempts_this_tick = 0usize;
        let seqs: Vec<CheckpointSequenceNumber> = self.pending_gaps.keys().copied().collect();
        for seq in seqs.into_iter().take(FULLNODE_ATTEMPTS_PER_TICK) {
            let Some((first_seen, last_archive_attempt)) = self
                .pending_gaps
                .get(&seq)
                .map(|gap| (gap.first_seen, gap.last_archive_attempt))
            else {
                continue;
            };
            let expired = first_seen.elapsed() > GAP_RETRY_DEADLINE;
            match self.transport.get_full_checkpoint(seq).await {
                Ok(data) => match self.fold_checkpoint(seq, &data) {
                    Ok(()) => {
                        info!(seq, "late-materialized checkpoint folded — gap repaired");
                        self.pending_gaps.remove(&seq);
                        self.forget_repaired_gap(seq);
                    }
                    Err(e) if expired => {
                        self.pending_gaps.remove(&seq);
                        self.metrics.pusher_gap_dropped_total.inc();
                        warn!(
                            seq,
                            error = ?e,
                            "gap checkpoint kept failing to fold until the retry deadline — dropping \
                             it from the gap retries and scheduling it for the archive backfill"
                        );
                        self.give_up_on_checkpoint(seq, "fold_failed");
                    }
                    Err(e) => {
                        warn!(
                            seq,
                            error = %error_chain(&e),
                            "gap checkpoint fetched but failed to fold — will retry"
                        );
                        self.record_failing_gap(seq, "first_fold_failure");
                    }
                },
                Err(fullnode_error) => {
                    let archive_due = self.archive.is_some()
                        && first_seen.elapsed() > ARCHIVE_FALLBACK_AFTER
                        && last_archive_attempt
                            .is_none_or(|at| at.elapsed() > ARCHIVE_RETRY_INTERVAL)
                        && archive_attempts_this_tick < ARCHIVE_ATTEMPTS_PER_TICK;
                    if archive_due {
                        archive_attempts_this_tick += 1;
                        let first_attempt = last_archive_attempt.is_none();
                        if self.try_archive_repair(seq, first_attempt, expired).await {
                            continue;
                        }
                    }
                    // Served, but not decodable by this binary: recorded now
                    // (the scan usually did already), unlike a gap the
                    // fullnode has not served (yet).
                    if matches!(fullnode_error, TransportError::Encoding(_)) {
                        self.record_failing_gap(seq, "first_decode_failure");
                    }
                    if expired {
                        self.pending_gaps.remove(&seq);
                        self.metrics.pusher_gap_dropped_total.inc();
                        warn!(
                            seq,
                            error = ?fullnode_error,
                            archive_configured = self.archive.is_some(),
                            "checkpoint never materialized within the gap retry deadline — dropping \
                             it from the gap retries (recorded for the archive backfill when an \
                             archive is configured)"
                        );
                        self.give_up_on_checkpoint(seq, "never_materialized");
                    }
                }
            }
        }
    }

    /// Try to repair one pending gap from the checkpoint archive: fetch the
    /// full checkpoint data, pass it through `verify_archive_checkpoint`
    /// (seq binding + committee BLS + unconditional artifacts-digest
    /// binding — see there for why the archive path verifies MORE than the
    /// fullnode path), and fold it. Returns `true` when the gap was repaired
    /// and removed. On any failure the gap stays pending (the caller applies
    /// the deadline). The fetch is bounded by `ARCHIVE_FETCH_TIMEOUT`
    /// because the underlying object-store client retries internally for up
    /// to 60s on anything but NotFound (e.g. a truncated blob from a
    /// mid-write fullnode crash) — unbounded, a hung archive would stall the
    /// whole pusher loop.
    async fn try_archive_repair(
        &mut self,
        seq: CheckpointSequenceNumber,
        first_attempt: bool,
        expired: bool,
    ) -> bool {
        const ARCHIVE_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
        let Some(archive) = self.archive.clone() else {
            return false;
        };
        if let Some(gap) = self.pending_gaps.get_mut(&seq) {
            gap.last_archive_attempt = Some(Instant::now());
        }
        let fetched = tokio::time::timeout(ARCHIVE_FETCH_TIMEOUT, async {
            archive.fetch_checkpoint_data(seq).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("archive fetch timed out after {ARCHIVE_FETCH_TIMEOUT:?}"))
        .and_then(|fetch_result| fetch_result.map_err(anyhow::Error::from));
        match fetched {
            Ok(data) => {
                if let Err(e) = self.verify_archive_checkpoint(seq, &data) {
                    match awaited_committee_epoch(&e) {
                        Some(epoch) => self.log_committee_wait(seq, epoch),
                        None => warn!(
                            seq,
                            error = %e,
                            "archive served a checkpoint that failed verification — refusing it"
                        ),
                    }
                    return false;
                }
                match self.fold_checkpoint(seq, &data) {
                    Ok(()) => {
                        info!(
                            seq,
                            "pruned checkpoint recovered from the archive and folded — gap repaired"
                        );
                        self.metrics.pusher_gap_archive_repairs_total.inc();
                        self.pending_gaps.remove(&seq);
                        // An earlier decode or fold failure may have recorded it.
                        self.forget_repaired_gap(seq);
                        true
                    }
                    Err(e) => {
                        // Same transient-vs-deterministic ambiguity as the
                        // fullnode fold path; the caller's deadline bounds it.
                        // The blob passed the archive verification above, so
                        // the checkpoint exists and this binary cannot fold
                        // it: recorded like a fullnode fold failure. A blob
                        // that fails verification is not.
                        warn!(
                            seq,
                            error = %error_chain(&e),
                            "archive checkpoint fetched but failed to fold — will retry"
                        );
                        self.record_failing_gap(seq, "first_archive_fold_failure");
                        false
                    }
                }
            }
            Err(e) => {
                // The first failure per gap warns so a misconfigured archive
                // (a typo'd file:// path) is visible immediately at the
                // default log level, not only after gaps start dropping at
                // the 600s deadline.
                if first_attempt || expired {
                    warn!(seq, error = %e, "archive could not serve the gap checkpoint");
                } else {
                    debug!(seq, error = %e, "archive fetch for gap checkpoint failed; will retry");
                }
                false
            }
        }
    }

    /// One pass over the archive backfill (see [`Self::with_archive_backfill`]):
    /// fold the result of every fetch that has finished, and start the fetches
    /// that are due. Never waits for the archive.
    async fn drive_archive_backfill(&mut self) {
        let Some(archive) = self.archive.clone() else {
            return;
        };
        let seqs: Vec<CheckpointSequenceNumber> = self.archive_backfill.keys().copied().collect();
        // Every started fetch holds its slot until its result is taken below.
        let mut in_flight = self
            .archive_backfill
            .values()
            .filter(|state| state.in_flight.is_some())
            .count();
        for seq in seqs {
            let Some(state) = self.archive_backfill.get_mut(&seq) else {
                continue;
            };
            let finished = match state.in_flight.take() {
                Some(fetch) if fetch.is_finished() => {
                    in_flight -= 1;
                    fetch
                }
                Some(fetch) => {
                    state.in_flight = Some(fetch);
                    continue;
                }
                // Not due, or not scanned yet (see `with_archive_backfill`),
                // or every fetch slot is taken.
                None if Instant::now() < state.next_attempt
                    || seq > self.cursor
                    || in_flight >= MAX_CONCURRENT_BACKFILL_FETCHES =>
                {
                    continue;
                }
                None => {
                    // The scan may have folded it since it was scheduled.
                    if self.cache.snapshots_from_checkpoint(seq) > 0 {
                        self.settle_backfill(seq, BackfillSettled::AlreadyCached);
                    } else {
                        let archive = archive.clone();
                        state.in_flight = Some(tokio::spawn(async move {
                            tokio::time::timeout(
                                ARCHIVE_BACKFILL_FETCH_TIMEOUT,
                                archive.fetch_checkpoint_data(seq),
                            )
                            .await
                        }));
                        in_flight += 1;
                    }
                    continue;
                }
            };
            let fetched = match finished.await {
                Ok(Ok(Ok(data))) => Ok(data),
                Ok(Ok(Err(e))) => {
                    let detail = error_chain(anyhow::Error::from(e)).to_string();
                    // The object-store reader turns a 404 into this message and
                    // returns at once; everything else it retried first.
                    let failure = if detail.contains("not found in archive") {
                        BackfillFailure::ArchiveNotFound
                    } else {
                        BackfillFailure::ArchiveFetch
                    };
                    Err((failure, detail))
                }
                Ok(Err(_elapsed)) => Err((
                    BackfillFailure::ArchiveTimeout,
                    format!(
                        "no answer within {ARCHIVE_BACKFILL_FETCH_TIMEOUT:?}; the object-store \
                         reader retries HTTP errors and undecodable blobs internally for 60s, so \
                         the store kept failing for that whole window"
                    ),
                )),
                Err(join_error) => Err((
                    BackfillFailure::ArchiveFetch,
                    format!("archive fetch task failed: {join_error}"),
                )),
            };
            let result = match fetched {
                Ok(data) => {
                    self.metrics
                        .pusher_backfill_outcomes_total
                        .with_label_values(&["fetched"])
                        .inc();
                    self.note_archive_served(seq);
                    self.fold_backfill_checkpoint(seq, &data).await
                }
                Err(failure) => Err(failure),
            };
            match result {
                Ok(settled) => self.settle_backfill(seq, settled),
                Err((failure, detail)) => self.schedule_backfill_retry(seq, failure, &detail),
            }
        }
    }

    fn settle_backfill(&mut self, seq: CheckpointSequenceNumber, settled: BackfillSettled) {
        self.archive_backfill.remove(&seq);
        self.metrics
            .pusher_backfill_pending
            .set(self.archive_backfill.len() as i64);
        self.record_backfill_settled(settled);
        info!(
            seq,
            outcome = settled.label(),
            pending = self.archive_backfill.len(),
            "archive backfill settled"
        );
        self.settle_lost_checkpoint(seq, settled);
    }

    /// Verify a backfill checkpoint served by the archive and fold its Ika
    /// objects that are still current (see [`Self::with_archive_backfill`]).
    /// Nothing is folded unless every verification passes.
    async fn fold_backfill_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
        data: &CheckpointData,
    ) -> Result<BackfillSettled, (BackfillFailure, String)> {
        // Classified ahead of the verification below, which would report the
        // same condition as a generic failure. Verifying an old checkpoint
        // needs the committee of ITS Sui epoch: the store derives it from the
        // persisted end-of-epoch summary before it, which every node whose
        // committee chain walked past that epoch holds. Missing above the head
        // means the ratchet has not reached it yet; missing at or below the
        // head means the chain has a hole the ratchet will not refill.
        let epoch = data.checkpoint_summary.epoch();
        if self.committees.committee(epoch).is_none() {
            let head = self.committees.head_epoch();
            return Err((
                BackfillFailure::MissingCommittee,
                if epoch > head {
                    format!(
                        "no committee for Sui epoch {epoch} yet: the committee head is at {head}"
                    )
                } else {
                    format!(
                        "no committee for Sui epoch {epoch} although the committee head is at \
                         {head}: the persisted committee chain has no entry for that epoch"
                    )
                },
            ));
        }
        self.verify_archive_checkpoint(seq, data)
            .map_err(|e| (BackfillFailure::Verification, error_chain(&e).to_string()))?;
        self.metrics
            .pusher_backfill_outcomes_total
            .with_label_values(&["verified"])
            .inc();
        // Re-runs the fold-time verification, so the fold below sees exactly
        // what a fullnode-served checkpoint would — including that each object
        // is the output object the checkpoint attests for its id.
        let entries = self
            .build_entries(data)
            .map_err(|e| (BackfillFailure::Verification, error_chain(&e).to_string()))?;
        self.capture_committee(data);
        self.persist_end_of_epoch(data, seq);
        let Some((summary, entries)) = entries else {
            return Ok(BackfillSettled::NothingToFold);
        };

        let ika_objects = entries.len();
        let (cached, candidates): (Vec<_>, Vec<_>) = entries.into_iter().partition(|entry| {
            self.cache
                .get(entry.object.id())
                .is_some_and(|snapshot| snapshot.object.version() >= entry.object.version())
        });
        // Inline in the tick (the fold needs `&self`), hence the bound.
        let lookups = tokio::time::timeout(ARCHIVE_BACKFILL_CURRENCY_TIMEOUT, async {
            let mut current = Vec::with_capacity(candidates.len());
            let mut superseded = Vec::new();
            let mut not_live = Vec::new();
            for entry in candidates {
                let id = entry.object.id();
                match self.transport.get_object(id).await {
                    Ok(live)
                        if live.compute_object_reference()
                            == entry.object.compute_object_reference() =>
                    {
                        current.push(entry)
                    }
                    Ok(live) => superseded.push((id, live.version().value())),
                    Err(TransportError::NotFound(_)) => not_live.push(id),
                    Err(e) => return Err(e),
                }
            }
            Ok((current, superseded, not_live))
        })
        .await;
        let (current, superseded, not_live) = match lookups {
            Ok(Ok(lookups)) => lookups,
            Ok(Err(e)) => return Err((BackfillFailure::CurrencyLookup, e.to_string())),
            Err(_elapsed) => {
                return Err((
                    BackfillFailure::CurrencyLookup,
                    format!(
                        "fullnode object lookups timed out after {ARCHIVE_BACKFILL_CURRENCY_TIMEOUT:?}"
                    ),
                ));
            }
        };
        let folded: Vec<(ObjectID, u64)> = current
            .iter()
            .map(|entry| (entry.object.id(), entry.object.version().value()))
            .collect();
        if !current.is_empty() {
            self.cache.absorb_entries(&summary, &current);
        }
        // Once per listed checkpoint, and the record of what it restored.
        info!(
            seq,
            ika_objects,
            ?folded,
            already_cached = ?cached.iter().map(|entry| entry.object.id()).collect::<Vec<_>>(),
            superseded_since = ?superseded,
            not_live = ?not_live,
            "archive backfill verified the checkpoint and folded its Ika objects that are still \
             current and missing from the cache"
        );
        Ok(if !current.is_empty() {
            BackfillSettled::Folded
        } else if !cached.is_empty() {
            BackfillSettled::AlreadyCached
        } else {
            BackfillSettled::NothingToFold
        })
    }

    fn record_backfill_settled(&self, settled: BackfillSettled) {
        self.metrics
            .pusher_backfill_outcomes_total
            .with_label_values(&[settled.label()])
            .inc();
    }

    fn schedule_backfill_retry(
        &mut self,
        seq: CheckpointSequenceNumber,
        failure: BackfillFailure,
        detail: &str,
    ) {
        self.metrics
            .pusher_backfill_outcomes_total
            .with_label_values(&["failed"])
            .inc();
        self.metrics
            .pusher_backfill_failures_total
            .with_label_values(&[failure.label()])
            .inc();
        if failure == BackfillFailure::ArchiveNotFound && self.archive_not_found_expired(seq) {
            self.abandon_lost_checkpoint(seq, detail);
            return;
        }
        let Some(state) = self.archive_backfill.get_mut(&seq) else {
            return;
        };
        state.failures = state.failures.saturating_add(1);
        let retry_in = archive_backfill_retry_delay(state.failures);
        state.next_attempt = Instant::now() + retry_in;
        let failures = state.failures;
        if failure == BackfillFailure::Verification {
            error!(
                security_critical = true,
                seq,
                failures,
                ?retry_in,
                error = detail,
                "archive backfill: the archive served a checkpoint that failed verification — \
                 refusing to fold it"
            );
        } else {
            // Paced by the backoff (at most every ten minutes once it caps),
            // and each line is actionable: the node keeps lacking objects it
            // needs until the attempt succeeds.
            warn!(
                seq,
                failures,
                reason = failure.label(),
                ?retry_in,
                error = detail,
                "archive backfill attempt failed; will retry"
            );
        }
    }

    /// Eagerly install the committee transition `data` commits to, if it is the
    /// end-of-epoch checkpoint of the current head epoch. A no-op otherwise.
    /// Best-effort: a verify failure is logged and left to the background
    /// ratchet rather than aborting the push.
    fn capture_committee(&self, data: &CheckpointData) {
        match self.committees.install_next_from_checkpoint(data) {
            Ok(CommitteeTransition::Installed(epoch)) => {
                info!(
                    epoch,
                    seq = *data.checkpoint_summary.sequence_number(),
                    "pusher captured Sui committee from streamed end-of-epoch checkpoint"
                );
            }
            Ok(CommitteeTransition::NotNextTransition) => {}
            Err(e) => {
                warn!(
                    error = ?e,
                    seq = *data.checkpoint_summary.sequence_number(),
                    "pusher committee capture failed; leaving to the background ratchet"
                );
            }
        }
    }

    /// Drive the committee chain forward over a span we are about to
    /// fast-forward the object cursor past, so no end-of-epoch committee is
    /// skipped: walk each still-available end-of-epoch checkpoint from the
    /// current head and install its committee, stopping at the first boundary
    /// beyond `through_seq` or the first unavailable (pruned) checkpoint. The
    /// latter is the accepted gap — the committee chain then falls back to the
    /// ratchet / a re-anchor rather than silently skipping a boundary.
    async fn capture_committees_through(&self, through_seq: CheckpointSequenceNumber) {
        loop {
            let head = self.committees.head_epoch();
            let eoe_seq = match self.transport.last_checkpoint_of_epoch(head).await {
                Ok(seq) => seq,
                // The head epoch hasn't ended yet (or the boundary is
                // unknowable) — nothing to capture ahead of `through_seq`.
                Err(_) => break,
            };
            if eoe_seq > through_seq {
                break;
            }
            let data = match self.transport.get_full_checkpoint(eoe_seq).await {
                Ok(data) => data,
                Err(e) => {
                    warn!(
                        head,
                        eoe_seq,
                        error = ?e,
                        "pusher catch-up: end-of-epoch checkpoint unavailable; committee \
                         chain falls back to the ratchet / re-anchor"
                    );
                    break;
                }
            };
            match self.committees.install_next_from_checkpoint(&data) {
                Ok(CommitteeTransition::Installed(epoch)) => {
                    info!(
                        epoch,
                        eoe_seq, "pusher captured Sui committee during catch-up"
                    );
                    self.persist_end_of_epoch(&data, eoe_seq);
                }
                // Not the next transition (head moved, or not end-of-epoch), or a
                // verify failure — stop and let the ratchet handle it.
                _ => break,
            }
        }
    }

    /// Retain a streamed end-of-epoch checkpoint (its epoch→seq mapping and the
    /// full checkpoint) so this node can serve a mirrored peer's ratchet the
    /// committee transition after its own fullnode prunes it
    /// (`RetainedFullnodeTransport`). A no-op for non-end-of-epoch checkpoints.
    fn persist_end_of_epoch(&self, data: &CheckpointData, seq: CheckpointSequenceNumber) {
        if data.checkpoint_summary.end_of_epoch_data.is_none() {
            return;
        }
        let epoch = data.checkpoint_summary.epoch();
        // One batch: the epoch→seq index and its backing CheckpointData are
        // persisted atomically, so a crash can't leave a dangling half.
        if let Err(e) = self.perpetual.put_sui_end_of_epoch(epoch, seq, data) {
            warn!(epoch, seq, error = ?e, "failed to persist end-of-epoch (seq + checkpoint) for mirrored peers");
        }
    }

    /// Returns `Some((summary, entries))` for Ika-relevant or end-of-epoch
    /// checkpoints (with a proof for each Ika-modified object) and `None`
    /// otherwise.
    ///
    /// "Ika-relevant" is determined per-output, by walking the Move
    /// type of each output and checking whether any address in the
    /// type tree matches an Ika package id. This catches:
    /// - Top-level Ika types (e.g. `System`, `DWalletCoordinator`,
    ///   `DWalletCoordinatorInner`): outer struct address is Ika.
    /// - Bag/Table entries `0x2::dynamic_field::Field<K, V>` where
    ///   `V` is an Ika type: walking type-params hits the Ika
    ///   address. The outer `Field` struct address is `0x2`, so a
    ///   simple "outer address only" filter would miss them.
    ///
    /// The previous filter ("tx has any Ika event → all outputs")
    /// missed mutations performed by system txs that didn't emit
    /// Ika-namespace events (notably bag-removal during session
    /// completion via epoch advance), which left consumer caches
    /// stale and produced spurious bag-omission warnings.
    ///
    /// Each entry's object is the output object whose reference is the one the
    /// checkpoint's verified tree attests for its id (see [`attested_output`]),
    /// so the object a cache-first read serves is the object its proof proves.
    /// An id the checkpoint ends by deleting or wrapping has no attested object
    /// and gets no entry.
    fn build_entries(
        &self,
        data: &CheckpointData,
    ) -> anyhow::Result<Option<(CertifiedCheckpointSummary, Vec<VerifiedObjectEntry>)>> {
        let is_end_of_epoch = data.checkpoint_summary.end_of_epoch_data.is_some();
        let ika_outputs = ika_outputs_by_id(data, &self.ika_packages);

        if !is_end_of_epoch && ika_outputs.is_empty() {
            return Ok(None);
        }

        // Build the modified-objects tree once for the whole checkpoint;
        // each Ika-modified object's proof is then a cheap path lookup.
        let artifacts = CheckpointArtifacts::from(data);
        let tree = ModifiedObjectTree::new(&artifacts)
            .map_err(|e| anyhow::anyhow!("ModifiedObjectTree: {e}"))?;

        let mut attested_objects = Vec::with_capacity(ika_outputs.len());
        for (id, outputs) in &ika_outputs {
            let Some(object_ref) = tree.get_object_state(*id).copied() else {
                // Object referenced by an Ika event but not in the
                // modified-objects set — treat as a benign mismatch and
                // skip rather than abort the push.
                debug!(?id, "ika object not in artifacts; skipping");
                continue;
            };
            if !object_ref.2.is_alive() {
                // A later transaction of the checkpoint deleted or wrapped the
                // object: the checkpoint attests no object to fold, and the
                // earlier writes are intermediate states it does not end in.
                debug!(
                    ?id,
                    "ika object deleted or wrapped by the checkpoint; skipping"
                );
                continue;
            }
            let proof = match tree.get_inclusion_proof(object_ref) {
                Ok(p) => p,
                Err(e) => {
                    warn!(?id, error = ?e, "failed to build inclusion proof; skipping");
                    continue;
                }
            };
            attested_objects.push((object_ref, proof, outputs.as_slice()));
        }

        if !is_end_of_epoch && attested_objects.is_empty() {
            return Ok(None);
        }

        // Verify the checkpoint against its committee, then bind each object to
        // the reference the verified tree attests for it, BEFORE folding
        // anything into the cache, so a direct node caches committee-attested
        // state rather than whatever its source served.
        let summary = &data.checkpoint_summary;
        let checkpoint_seq = *summary.sequence_number();
        let started = Instant::now();
        let verified = self
            .verify_before_fold(summary, &tree, !attested_objects.is_empty())
            .and_then(|()| {
                attested_objects
                    .into_iter()
                    .map(|(object_ref, proof, outputs)| {
                        Ok(VerifiedObjectEntry {
                            object: attested_output(object_ref, outputs)?.clone(),
                            checkpoint_seq,
                            proof,
                            dynamic_field_name_type: String::new(),
                            dynamic_field_name_bcs: Vec::new(),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
            });
        let objects_with_proofs = match verified {
            Ok(objects_with_proofs) => objects_with_proofs,
            Err(e) => {
                // A committee that is not installed yet is a wait, not a
                // verification failure: nothing was checked, and the caller
                // retries. Everything else is the security event.
                match awaited_committee_epoch(&e) {
                    Some(epoch) => self.log_committee_wait(checkpoint_seq, epoch),
                    None => error!(
                        security_critical = true,
                        seq = checkpoint_seq,
                        epoch = summary.epoch(),
                        error = %e,
                        "refusing to fold a checkpoint that failed committee verification — \
                         own fullnode served state that does not verify against the committee"
                    ),
                }
                return Err(e);
            }
        };
        // Record only the success path's cost: a rejection is a security event
        // surfaced by the log above, not a steady-state latency sample. `_count`
        // then equals the checkpoints verified before folding, `_sum` the CPU
        // the committee checks and the object binding added to the fold loop.
        self.metrics
            .pusher_fold_verify_seconds
            .observe(started.elapsed().as_secs_f64());

        Ok(Some((summary.clone(), objects_with_proofs)))
    }

    /// Log that the checkpoint at `seq` waits for the committee of its Sui
    /// `epoch`: it cannot be verified, and so is not folded, until that
    /// committee is installed (follower lag at a Sui epoch boundary, or a
    /// restart near one), and it is retried. Not a verification failure —
    /// nothing was checked — so not `security_critical`. Once per epoch (see
    /// `committee_wait_logged`). A committee missing below the committee head
    /// is a hole in the persisted chain rather than a wait, and warns.
    fn log_committee_wait(&self, seq: CheckpointSequenceNumber, epoch: u64) {
        let latch = epoch.saturating_add(1);
        if self.committee_wait_logged.swap(latch, Ordering::Relaxed) == latch {
            return;
        }
        let committee_head = self.committees.head_epoch();
        if epoch > committee_head {
            info!(
                seq,
                epoch,
                committee_head,
                "checkpoint waits for its Sui epoch's committee to be installed — not folded \
                 yet, will retry (logged once per epoch)"
            );
        } else {
            warn!(
                seq,
                epoch,
                committee_head,
                "no committee for the checkpoint's Sui epoch although the committee head is past \
                 it: the persisted committee chain has a hole — not folded, will retry (logged \
                 once per epoch)"
            );
        }
    }

    /// Verify a checkpoint against its committee BEFORE its objects are folded
    /// into the cache, so a direct node trusts committee-attested state rather
    /// than whatever its own fullnode served — a compromised or buggy fullnode
    /// cannot seed the cache with forged objects. These are the same two checks
    /// [`OcsVerifiedReader`]'s network read path performs, hoisted to fold time
    /// (once per checkpoint, off the read hot path):
    ///
    ///   1. the checkpoint summary carries a valid committee quorum signature;
    ///   2. when objects are being folded, the locally-built modified-objects
    ///      tree root matches the committee-signed checkpoint-artifacts digest —
    ///      binding every reference in that tree, and so every inclusion proof
    ///      derived from it, to committee-attested state. The tree is built
    ///      from the effects, so this says nothing about the object contents
    ///      served alongside them: `build_entries` binds each folded object to
    ///      its attested reference separately ([`attested_output`]).
    ///
    /// A failure means the fullnode served state that does not verify against
    /// the committee — except a committee that is not installed yet
    /// ([`awaited_committee_epoch`]), where nothing could be checked: the
    /// caller refuses to fold it either way (propagating the error, so the
    /// cursor stays put and a transient missing-committee self-heals on the
    /// next poll) rather than caching unverified state.
    fn verify_before_fold(
        &self,
        summary: &CertifiedCheckpointSummary,
        tree: &ModifiedObjectTree,
        folding_objects: bool,
    ) -> anyhow::Result<()> {
        self.committees
            .verify_summary(summary.clone())
            .map_err(|e| anyhow::Error::new(SummaryRejected(e)))?;
        if folding_objects {
            let signed = summary.data().checkpoint_artifacts_digest().map_err(|e| {
                anyhow::anyhow!("summary carries no checkpoint-artifacts digest: {e}")
            })?;
            let local = CheckpointArtifactsDigest::from_artifact_digests(vec![tree.tree_root])
                .map_err(|e| anyhow::anyhow!("computing artifacts digest from local tree: {e}"))?;
            if local != *signed {
                anyhow::bail!(
                    "checkpoint-artifacts digest mismatch — the fullnode's modified-objects \
                     tree does not match the committee-signed digest"
                );
            }
        }
        Ok(())
    }
}

/// Every output object of `data` that touches an Ika package
/// ([`object_touches_ika`]), by id, in transaction order. One pass over the
/// checkpoint's outputs, so pairing an attested id with its object is a lookup
/// instead of a scan of every output per id.
fn ika_outputs_by_id<'a>(
    data: &'a CheckpointData,
    ika: &HashSet<ObjectID>,
) -> HashMap<ObjectID, Vec<&'a Object>> {
    data.transactions
        .iter()
        .flat_map(|tx| tx.output_objects.iter())
        .filter(|output| object_touches_ika(output, ika))
        .fold(HashMap::new(), |mut by_id, output| {
            by_id.entry(output.id()).or_default().push(output);
            by_id
        })
}

/// The object among `outputs` — the output objects of the checkpoint carrying
/// one id, in transaction order — whose reference is `attested`, the live
/// state the checkpoint's committee-verified tree attests for that id.
///
/// The inclusion proof folded with the object proves `attested`, and a
/// cache-first read serves the cached object without re-checking that proof,
/// so the object must be the one `attested` names, not merely one with its id.
/// The reference includes the object digest, a hash of the whole object, so
/// equality binds the contents as well as the version.
///
/// An honest checkpoint always has the match. The tree holds, per id, the
/// reference of the id's last write in the checkpoint (`CheckpointArtifacts`
/// folds every transaction's written references in order). A live reference
/// there is an object write, and a transaction's output objects are exactly
/// the objects of its object writes: Sui derives them from the effects' changed
/// objects, looked up in the checkpoint's object set by id and version. So the
/// attested object is among `outputs` — the last of them, since any later write
/// of the id would be the attested one. (A deleted or wrapped final state has
/// no object; the caller skips it before getting here.) No match therefore
/// means the source served object contents the committee did not attest: an
/// intermediate version in place of the final one, or altered bytes.
fn attested_output<'a>(attested: ObjectRef, outputs: &[&'a Object]) -> anyhow::Result<&'a Object> {
    // Last first: in an honest checkpoint that is the match, so one object is
    // hashed per id.
    outputs
        .iter()
        .rev()
        .find(|output| output.compute_object_reference() == attested)
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no output object of the checkpoint is the committee-attested reference \
                 {attested:?}: the source served object contents the committee did not attest"
            )
        })
}

/// A checkpoint summary `verify_before_fold` rejected, carried typed through
/// `anyhow` so a caller can tell a committee that is not installed yet — a
/// wait — from a summary that does not verify ([`awaited_committee_epoch`]).
/// Displays exactly as the untyped error did.
#[derive(Debug, thiserror::Error)]
#[error("checkpoint summary failed committee verification: {0}")]
struct SummaryRejected(SummaryVerifyError);

/// The Sui epoch whose committee `error` is waiting for, when that is all it
/// is: the summary could not be checked because the committee of its epoch is
/// not in the committee store — a temporary state at every Sui epoch boundary
/// while a gap is pending. `None` for every genuine verification failure: a
/// bad signature, an artifacts-digest mismatch, or object contents that are
/// not the attested ones.
fn awaited_committee_epoch(error: &anyhow::Error) -> Option<u64> {
    match error.downcast_ref::<SummaryRejected>() {
        Some(SummaryRejected(SummaryVerifyError::MissingCommittee(epoch))) => Some(*epoch),
        _ => None,
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Delay before the next archive-backfill attempt after `failures`
/// consecutive failures: doubling from `ARCHIVE_BACKFILL_RETRY_INITIAL`,
/// capped at `ARCHIVE_BACKFILL_RETRY_MAX`.
fn archive_backfill_retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    ARCHIVE_BACKFILL_RETRY_INITIAL
        .saturating_mul(1 << doublings)
        .min(ARCHIVE_BACKFILL_RETRY_MAX)
}

/// `true` if any address in the object's Move type tree matches an
/// Ika package id. Walks through generic parameters, so wrapper types
/// like `0x2::dynamic_field::Field<K, IkaEvent>` qualify when `K` or
/// `V` is Ika-defined.
fn object_touches_ika(o: &Object, ika: &HashSet<ObjectID>) -> bool {
    let Some(move_obj) = o.data.try_as_move() else {
        return false;
    };
    let object_type = move_obj.type_();
    if ika.contains(&ObjectID::from(object_type.address())) {
        return true;
    }
    object_type
        .type_params()
        .iter()
        .any(|t| type_touches_ika(t, ika))
}

fn type_touches_ika(t: &TypeTag, ika: &HashSet<ObjectID>) -> bool {
    match t {
        TypeTag::Struct(boxed) => {
            let st = &**boxed;
            if ika.contains(&ObjectID::from(st.address)) {
                return true;
            }
            st.type_params.iter().any(|p| type_touches_ika(p, ika))
        }
        TypeTag::Vector(inner) => type_touches_ika(inner, ika),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::{BTreeMap, HashMap};
    use std::io;
    use std::slice;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, ProofBuildResult, ProofProvider,
        VerifiedDynamicFieldsPageRequest, VerifiedDynamicFieldsPageResponse,
        VerifiedObjectResponse, recover_pruned_proof,
    };
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction, TransportError};
    use parking_lot::RwLock;
    use sui_light_client::proof::base::{Proof, ProofContents, ProofTarget, ProofVerifier};
    use sui_light_client::proof::ocs::OCSProof;
    use sui_types::base_types::{
        ExecutionDigests, ObjectDigest, SequenceNumber, TransactionDigest,
    };
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::effects::{EffectsObjectChange, TransactionEffects};
    use sui_types::execution_status::ExecutionStatus;
    use sui_types::full_checkpoint_content::CheckpointTransaction;
    use sui_types::gas::GasCostSummary;
    use sui_types::message_envelope::Message;
    use sui_types::messages_checkpoint::{
        CheckpointCommitment, CheckpointContents, CheckpointSummary, EndOfEpochData,
    };
    use sui_types::object::{MoveObject, Owner};
    use sui_types::parse_sui_type_tag;
    use sui_types::test_checkpoint_data_builder::TestCheckpointBuilder;
    use tokio::time::{Instant as TokioInstant, sleep};
    use tracing::Dispatch;
    use tracing::subscriber::{self, DefaultGuard, NoSubscriber};

    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::ocs_currency::ChangesetIndex;
    use crate::sui_connector::verified_reader::{OcsVerifiedReader, VerifiedDynamicFieldsPage};
    use crate::sui_connector::verified_state_cache::{
        SharedVerifiedStateCache, VerifiedStateCache,
    };

    /// Mock transport that serves a fixed `get_latest_checkpoint` and a
    /// configurable set of full checkpoints; a missing seq is `NotFound`
    /// (modeling an upstream prune). Only the reads the pusher makes are implemented;
    /// the rest panic so an unexpected call is loud.
    struct MockTransport {
        fetch_control: Option<Arc<FetchControl>>,
        latest: CertifiedCheckpointSummary,
        /// Emulates a fullnode pruning AT head: the availability window is
        /// empty, so summary reads NotFound even for `latest`, while the
        /// height watermark (`GetServiceInfo`) still answers.
        latest_summary_pruned: bool,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        /// `epoch -> last checkpoint seq of that epoch`, for
        /// `last_checkpoint_of_epoch` (the catch-up boundary walk). Empty for
        /// the slices that never reach `capture_committees_through`.
        eoe_seqs: HashMap<u64, CheckpointSequenceNumber>,
        /// The fullnode's CURRENT objects, for `get_object` (the archive
        /// backfill's currency check). An id absent here is `NotFound` —
        /// deleted or wrapped on chain.
        live_objects: HashMap<ObjectID, Object>,
    }

    #[derive(Default)]
    struct FetchControl {
        delays: HashMap<CheckpointSequenceNumber, Duration>,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
        completed: Mutex<Vec<CheckpointSequenceNumber>>,
    }

    struct InFlightFetch<'a> {
        control: &'a FetchControl,
    }

    impl Drop for InFlightFetch<'_> {
        fn drop(&mut self) {
            self.control.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl SuiTransport for MockTransport {
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            if self.latest_summary_pruned {
                return Err(TransportError::NotFound(format!(
                    "Checkpoint {} not found",
                    self.latest.sequence_number()
                )));
            }
            Ok(self.latest.clone())
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            // The height watermark survives pruning — mirrors the real
            // transport's `GetServiceInfo.checkpoint_height` probe.
            Ok(*self.latest.sequence_number())
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            let _in_flight = self.fetch_control.as_ref().map(|control| {
                let in_flight = control.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                control
                    .peak_in_flight
                    .fetch_max(in_flight, Ordering::Relaxed);
                InFlightFetch { control }
            });
            if let Some(control) = &self.fetch_control {
                sleep(
                    control
                        .delays
                        .get(&seq)
                        .copied()
                        .unwrap_or(Duration::from_millis(650)),
                )
                .await;
                control.completed.lock().push(seq);
            }
            self.checkpoints
                .get(&seq)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} pruned")))
        }

        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn last_checkpoint_of_epoch(
            &self,
            epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.eoe_seqs
                .get(&epoch)
                .copied()
                .ok_or_else(|| TransportError::NotFound(format!("epoch {epoch} boundary unknown")))
        }
        async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
            self.live_objects
                .get(&id)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("object {id} not found")))
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// The artifacts commitment matching a checkpoint with no transactions
    /// (the shape every helper below builds), so archive-path verification —
    /// which binds the artifacts digest unconditionally — passes for honest
    /// mock checkpoints.
    fn empty_artifacts_commitment() -> CheckpointCommitment {
        CheckpointCommitment::CheckpointArtifactsDigest(
            CheckpointArtifacts::from_object_states(BTreeMap::new())
                .digest()
                .unwrap(),
        )
    }

    /// An end-of-epoch `CheckpointData` for the committee's epoch at `seq`,
    /// committee-signed and committing to the next epoch's committee (same
    /// members, epoch E+1). `verify_with_contents` passes because the summary's
    /// `content_digest` is set from the (empty) contents.
    fn end_of_epoch_checkpoint(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CheckpointData {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![empty_artifacts_commitment()],
            end_of_epoch_data: Some(EndOfEpochData {
                next_epoch_committee: committee.voting_rights.clone(),
                next_epoch_protocol_version: ProtocolVersion::MIN,
                epoch_commitments: vec![],
            }),
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    fn test_packages() -> IkaPackageConfig {
        IkaPackageConfig {
            ika_package_id: ObjectID::random(),
            ika_common_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id: ObjectID::random(),
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: ObjectID::random(),
        }
    }

    /// A plain (non-end-of-epoch) `CheckpointData` at `seq` with no
    /// transactions. `build_entries` returns `None` for it (nothing Ika to
    /// fold), so it advances the cursor / processed head without folding.
    fn plain_checkpoint(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CheckpointData {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![empty_artifacts_commitment()],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    async fn pusher_over(
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        transport: Arc<dyn SuiTransport>,
    ) -> IkaCheckpointPusher {
        pusher_over_with_cache(
            perpetual,
            committees,
            transport,
            Arc::new(VerifiedStateCache::new()),
            OcsMetrics::new_for_testing(),
        )
        .await
    }

    async fn pusher_over_with_cache(
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        transport: Arc<dyn SuiTransport>,
        cache: SharedVerifiedStateCache,
        metrics: Arc<OcsMetrics>,
    ) -> IkaCheckpointPusher {
        let packages = test_packages();
        IkaCheckpointPusher::new(
            transport,
            perpetual,
            metrics,
            &packages,
            Duration::from_secs(2),
            cache,
            committees,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_checkpoint_fetches_fold_in_order_across_epochs() {
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
        let checkpoint_count = 19;
        let checkpoints = (0..checkpoint_count)
            .map(|epoch| {
                let committee =
                    Committee::new(epoch, committee.voting_rights.iter().copied().collect());
                let seq = 100 + epoch;
                (seq, end_of_epoch_checkpoint(&committee, &keys, seq))
            })
            .collect::<HashMap<_, _>>();
        let latest_seq = 99 + checkpoint_count;
        let control = Arc::new(FetchControl {
            delays: HashMap::from([(100, Duration::from_secs(2))]),
            ..Default::default()
        });
        let transport = Arc::new(MockTransport {
            fetch_control: Some(control.clone()),
            latest: checkpoints[&latest_seq].checkpoint_summary.clone(),
            latest_summary_pruned: false,
            checkpoints,
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();
        let cache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;

        let started = TokioInstant::now();
        pusher
            .advance()
            .await
            .expect("in-order folding must install each epoch committee before using it");
        let peak = control.peak_in_flight.load(Ordering::Relaxed);
        assert!(peak > 1, "checkpoint fetches must overlap");
        assert!(
            peak <= MAX_CONCURRENT_CHECKPOINT_FETCHES,
            "fetch concurrency exceeded its bound"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "650 ms checkpoint RPCs must not serialize the whole catch-up scan"
        );
        let completed = control.completed.lock();
        assert_ne!(
            completed[0], 100,
            "the epoch boundary must arrive out of order"
        );
        assert_eq!(completed.len(), checkpoint_count as usize);
        assert_eq!(control.in_flight.load(Ordering::Relaxed), 0);
        assert_eq!(committees.head_epoch(), checkpoint_count);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        assert_eq!(cache.processed_head_seq(), latest_seq);
        assert_eq!(metrics.pusher_pushed_total.get(), checkpoint_count);
        assert!(pusher.pending_gaps.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_checkpoint_fetches_stop_at_a_verification_failure() {
        let (committee, keys) = Committee::new_simple_test_committee_of_size(4);
        let (foreign_committee, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        let control = Arc::new(FetchControl {
            delays: HashMap::from([
                (100, Duration::from_secs(2)),
                (102, Duration::from_secs(20)),
            ]),
            ..Default::default()
        });
        let transport = Arc::new(MockTransport {
            fetch_control: Some(control.clone()),
            latest: plain_checkpoint(&committee, &keys, 102).checkpoint_summary,
            latest_summary_pruned: false,
            checkpoints: HashMap::from([
                (
                    100,
                    end_of_epoch_checkpoint(&foreign_committee, &foreign_keys, 100),
                ),
                (101, end_of_epoch_checkpoint(&committee, &keys, 101)),
                (102, plain_checkpoint(&committee, &keys, 102)),
            ]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();
        let cache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;

        let error = pusher.advance().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("checkpoint summary failed committee verification")
        );
        assert_eq!(*control.completed.lock(), vec![101, 100]);
        assert_eq!(control.peak_in_flight.load(Ordering::Relaxed), 3);
        assert_eq!(
            control.in_flight.load(Ordering::Relaxed),
            0,
            "a failed fold must cancel outstanding fetches"
        );
        assert_eq!(pusher.cursor, 99);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(99));
        assert_eq!(cache.processed_head_seq(), 99);
        assert_eq!(committees.head_epoch(), 0);
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(101)
                .unwrap()
                .is_none()
        );
        assert_eq!(metrics.pusher_pushed_total.get(), 0);
        assert!(pusher.pending_gaps.is_empty());
    }

    /// Slice 1: the pusher installs `committee[E+1]` the moment it streams past
    /// the end-of-epoch checkpoint — the committee head advances without the
    /// ratchet ever reaching back for that (prune-prone) checkpoint.
    /// The pusher's FIRST START inside a pruned-at-head window: no persisted
    /// cursor, so `new` must take its initial cursor from the watermark. With
    /// a summary fetch there, constructing the pusher fails — and because
    /// `SuiClient` construction sits upstream of this on every node-start
    /// path, that failure surfaces as a node that does not come up at all.
    #[tokio::test]
    async fn pusher_first_start_survives_a_fullnode_pruning_at_head() {
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

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: true,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        // No `put_sui_pusher_last_seq` — this is a first start.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), None);

        let _pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;

        // The cursor initialized from the watermark rather than failing.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
    }

    /// A fullnode pruning AT head empties its availability window and serves
    /// NotFound for its OWN latest checkpoint — persistently, while the window
    /// stays empty. The tick must survive that (the height watermark is
    /// pruning-immune) and keep folding what IS available; before this, the
    /// summary fetch at the top of `advance` aborted the whole tick with `?`,
    /// freezing the cursor and the verified cache behind it.
    #[tokio::test]
    async fn pusher_tick_survives_a_fullnode_pruning_at_head() {
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

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            // The summary read NotFounds — as a pruned-at-head fullnode does.
            latest_summary_pruned: true,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher
            .advance()
            .await
            .expect("a pruned-at-head latest must not abort the tick");

        // The cursor advanced and the available checkpoint still folded.
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
        assert_eq!(committees.head_epoch(), 1);
    }

    #[tokio::test]
    async fn pusher_eagerly_captures_end_of_epoch_committee() {
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
        assert_eq!(committees.head_epoch(), 0);

        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        // Resume from seq 99 so advance() streams exactly seq 100.
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        assert_eq!(committees.head_epoch(), 1);
        // The end-of-epoch checkpoint is retained so this node can serve it to a
        // mirrored peer's ratchet after its own fullnode prunes it.
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some()
        );
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(0).unwrap(), Some(100));
    }

    /// A NotFound checkpoint does not stall the scan NOR leave a permanent
    /// gap: the cursor advances past it (nothing folded), the seq is queued
    /// as a pending gap, and once the checkpoint materializes a later tick
    /// folds it late — recovering its committee capture and end-of-epoch
    /// retention.
    #[tokio::test(start_paused = true)]
    async fn unavailable_checkpoint_becomes_pending_gap_and_folds_when_it_materializes() {
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

        // The unavailable boundary responds after two later checkpoints.
        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = plain_checkpoint(&committee, &keys, 102).checkpoint_summary;
        let control = Arc::new(FetchControl {
            delays: HashMap::from([(100, Duration::from_secs(2))]),
            ..Default::default()
        });
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: Some(control.clone()),
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: HashMap::from([
                (101, plain_checkpoint(&committee, &keys, 101)),
                (102, plain_checkpoint(&committee, &keys, 102)),
            ]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        pusher.advance().await.unwrap();

        // Nothing folded, but the scan did NOT stall: the cursor advanced
        // past the gap, which is now pending repair.
        assert_eq!(committees.head_epoch(), 0);
        assert_ne!(control.completed.lock()[0], 100);
        assert_eq!(control.peak_in_flight.load(Ordering::Relaxed), 3);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(102));
        assert_eq!(pusher.cache.processed_head_seq(), 102);
        assert_eq!(pusher.metrics.pusher_fetch_failures_total.get(), 1);
        assert_eq!(pusher.metrics.pusher_skipped_irrelevant_total.get(), 2);
        assert!(pusher.pending_gaps.contains_key(&100));

        // The checkpoint materializes; the next tick repairs the gap.
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, eoe)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        pusher.transport = transport;
        pusher.advance().await.unwrap();

        assert_eq!(committees.head_epoch(), 1);
        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(102));
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some(),
            "a gap-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// Fast-forward catch-up walks the still-available end-of-epoch boundaries
    /// in order, installing each committee — but it must NOT skip a pruned
    /// boundary. With boundaries at seqs 30/60/90 and seq 60 pruned (NotFound),
    /// the walk installs epoch-0's transition (head → 1) from seq 30, then stops
    /// at the pruned seq-60 boundary: the committee head advances only to the
    /// epoch *before* the gap, never jumping past it to a later boundary.
    #[tokio::test]
    async fn fast_forward_captures_all_boundaries_then_stops_at_a_pruned_one() {
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
        assert_eq!(committees.head_epoch(), 0);

        // End-of-epoch boundaries at 30, 60, 90. Seq 60 is pruned: present in the
        // epoch→seq map (so the boundary is *known*) but absent from the fetchable
        // checkpoints, so `get_full_checkpoint(60)` is NotFound.
        let eoe_30 = end_of_epoch_checkpoint(&committee, &keys, 30);
        let eoe_90 = end_of_epoch_checkpoint(&committee, &keys, 90);

        // latest far beyond FAR_BEHIND_THRESHOLD (1_000) so advance() fast-forwards
        // and runs the catch-up boundary walk. new_cursor = latest - 100 = 2_000,
        // which is > 90, so the walk's `eoe_seq > through_seq` guard never trips
        // before the prune does.
        let latest = end_of_epoch_checkpoint(&committee, &keys, 2_100).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(30u64, eoe_30), (90u64, eoe_90)]),
            eoe_seqs: HashMap::from([(0u64, 30), (1u64, 60), (2u64, 90)]),
            live_objects: HashMap::new(),
        });
        // Resume from seq 0 → lag 2_100 > FAR_BEHIND_THRESHOLD → fast-forward path.
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let mut pusher = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        // The first far-behind tick only proposes the fast-forward; the second
        // observes the same watermark and confirms it (see
        // `far_behind_fast_forward_waits_for_a_confirming_watermark`).
        pusher.advance().await.unwrap();
        pusher.advance().await.unwrap();

        // Seq 30 installed epoch-0's transition; the pruned seq-60 boundary halted
        // the walk before epoch 1's boundary (seq 90) could be reached. The head
        // never jumps the gap to a later boundary.
        assert_eq!(committees.head_epoch(), 1);
        // Boundary actually walked-through is retained for mirrored peers.
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(0).unwrap(), Some(30));
        // The boundary past the prune gap was never captured.
        assert_eq!(perpetual.get_sui_end_of_epoch_seq(2).unwrap(), None);
    }

    /// A transport that returns `NotFound` for every third checkpoint (modeling
    /// a sparse upstream prune) must not wedge: `advance()` streams to the
    /// latest, advancing the processed head all the way, incrementing the
    /// fetch-failure metric once per missing seq. No object is folded for a
    /// failed seq (a gap in the cache), and an end-of-epoch checkpoint that
    /// lands on a failed (NotFound) seq is NOT retained — the fetch fails before
    /// Fetch failures mid-stream become pending gaps while the scan folds
    /// everything else in order; when the missing checkpoints materialize,
    /// a later tick repairs them all — including an end-of-epoch checkpoint
    /// on a previously failed seq, whose committee capture and retention are
    /// RECOVERED rather than lost (under the old advance-past behavior a
    /// transient NotFound silently dropped it and every Ika object on that
    /// seq from the verified cache forever).
    #[tokio::test]
    async fn fetch_failures_become_pending_gaps_and_repair_when_checkpoints_materialize() {
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

        // Stream seqs 1..=9 from cursor 0. Seqs 3, 6, 9 are OMITTED from the
        // served map at first (their fetches are NotFound); seq 6 is an
        // end-of-epoch checkpoint once it materializes.
        let latest_seq = 9u64;
        let mut checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData> = HashMap::new();
        for seq in 1..=latest_seq {
            if seq % 3 == 0 {
                continue; // omit → NotFound on fetch
            }
            checkpoints.insert(seq, plain_checkpoint(&committee, &keys, seq));
        }
        let latest = plain_checkpoint(&committee, &keys, latest_seq).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: checkpoints.clone(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();

        // The scan folded everything fetchable and advanced to the head; the
        // three missing seqs are pending gaps, not silent losses.
        assert_eq!(cache.processed_head_seq(), latest_seq);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        assert_eq!(metrics.pusher_fetch_failures_total.get(), 3);
        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![3, 6, 9]
        );

        // A tick with the checkpoints still missing keeps them pending (the
        // retry deadline is far away) — nothing is dropped.
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_gaps.len(), 3);

        // The missing checkpoints materialize (6 as end-of-epoch); the next
        // tick repairs all three gaps: the committee is installed and the
        // end-of-epoch checkpoint retained.
        checkpoints.insert(3, plain_checkpoint(&committee, &keys, 3));
        checkpoints.insert(6, end_of_epoch_checkpoint(&committee, &keys, 6));
        checkpoints.insert(9, plain_checkpoint(&committee, &keys, 9));
        pusher.transport = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints,
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(committees.head_epoch(), 1);
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(6)
                .unwrap()
                .is_some(),
            "a gap-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// A mock checkpoint archive serving full checkpoint data from memory,
    /// for the pending-gap archive-fallback tests. The ratchet-facing methods
    /// are never called by the pusher and panic loudly if they ever are.
    #[derive(Default)]
    struct MockCheckpointArchive {
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        /// Fetches to fail (a transient store error) before serving.
        failures_left: AtomicUsize,
        /// Every `fetch_checkpoint_data` call, failed or not.
        fetches: AtomicUsize,
    }

    #[async_trait]
    impl CheckpointArchive for MockCheckpointArchive {
        async fn enumerate_end_of_epoch_seqs(
            &self,
        ) -> Result<Vec<CheckpointSequenceNumber>, ika_sui_client::archive::ArchiveError> {
            unimplemented!()
        }
        async fn fetch_checkpoint(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<
            (
                CertifiedCheckpointSummary,
                sui_types::messages_checkpoint::CheckpointContents,
            ),
            ika_sui_client::archive::ArchiveError,
        > {
            unimplemented!()
        }
        async fn fetch_checkpoint_data(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, ika_sui_client::archive::ArchiveError> {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            if self
                .failures_left
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return Err(ika_sui_client::archive::ArchiveError::Fetch {
                    url: "mock".into(),
                    seq,
                    source: anyhow::anyhow!("HTTP 503 from the mock archive"),
                });
            }
            self.checkpoints.get(&seq).cloned().ok_or_else(|| {
                ika_sui_client::archive::ArchiveError::Fetch {
                    url: "mock".into(),
                    seq,
                    source: anyhow::anyhow!("Checkpoint {seq} not found in archive"),
                }
            })
        }
    }

    /// A gap checkpoint the fullnode NEVER serves (pruned) is recovered from
    /// the checkpoint archive once the local-materialization grace passes,
    /// folded through the same committee verification (its committee capture
    /// and end-of-epoch retention land), and counted as an archive repair —
    /// instead of being dropped at the deadline (issue #2018).
    #[tokio::test]
    async fn pruned_gap_checkpoint_is_recovered_from_the_archive() {
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

        // The fullnode advertises seq 100 but never serves its contents
        // (pruned); only the archive has it — as an end-of-epoch checkpoint so
        // the test can observe the fold's committee capture and retention.
        let eoe = end_of_epoch_checkpoint(&committee, &keys, 100);
        let latest = eoe.checkpoint_summary.clone();
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(100u64, eoe)]),
            ..Default::default()
        }));

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));

        // Within the local-materialization grace the archive is NOT consulted
        // yet — the fullnode alone is retried.
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);

        // Age the gap past the grace; the next tick repairs it from the
        // archive.
        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(6);
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 1);
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 0);
        assert_eq!(committees.head_epoch(), 1);
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(100)
                .unwrap()
                .is_some(),
            "an archive-repaired end-of-epoch checkpoint must be retained"
        );
    }

    /// An archive blob whose committee-signed summary is for a DIFFERENT
    /// sequence number than the one requested must NOT clear the gap.
    /// Gap-clearance would otherwise trust the archive's file naming: a
    /// mislabeled-but-genuine blob (or one substituted by a malicious
    /// store) would "repair" the gap vacuously, the real checkpoint's
    /// events would stay lost, and the dropped-gap alarm this fallback
    /// feeds would be suppressed — the issue #2018 loss shape, silently.
    #[tokio::test]
    async fn archive_blob_for_a_different_seq_is_refused() {
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

        let latest = plain_checkpoint(&committee, &keys, 100).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        // The archive's entry FOR seq 100 is a genuine, correctly-signed
        // end-of-epoch checkpoint — of seq 999.
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(100u64, end_of_epoch_checkpoint(&committee, &keys, 999))]),
            ..Default::default()
        }));

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&100));

        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(6);
        pusher.advance().await.unwrap();

        assert!(
            pusher.pending_gaps.contains_key(&100),
            "a wrong-seq archive blob must not clear the gap"
        );
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);
        assert_eq!(
            committees.head_epoch(),
            0,
            "the refused blob's committee transition must not install"
        );
    }

    /// A gap that neither the fullnode nor the archive can serve is dropped
    /// at the retry deadline and counted (`pusher_gap_dropped_total`) — the
    /// loud permanent-loss signal — while a younger co-pending gap stays.
    #[tokio::test]
    async fn gap_missing_from_fullnode_and_archive_is_dropped_at_the_deadline() {
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

        let latest = plain_checkpoint(&committee, &keys, 101).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache,
            metrics.clone(),
        )
        .await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::new(),
            ..Default::default()
        }));

        pusher.advance().await.unwrap();
        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![100, 101]
        );

        // Age seq 100 past the retry deadline; seq 101 stays young.
        pusher.pending_gaps.get_mut(&100).unwrap().first_seen =
            Instant::now() - Duration::from_secs(601);
        pusher.advance().await.unwrap();

        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![101],
            "only the expired gap is dropped"
        );
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(metrics.pusher_gap_archive_repairs_total.get(), 0);
    }

    /// The pusher resumes from its persisted cursor across a restart: once
    /// `advance()` has driven the cursor to N and persisted it, a fresh pusher
    /// constructed over the SAME perpetual tables boots at cursor N and, on
    /// construction, seeds the cache's processed head to N (so the reader's
    /// tripwire doesn't fire before the first tick). A second `advance()` with
    /// no new upstream checkpoints is a no-op that leaves the cursor at N.
    #[tokio::test]
    async fn restart_resumes_from_persisted_cursor() {
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

        // First run: stream 1..=5 from cursor 0; the cursor lands on 5.
        let latest_seq = 5u64;
        let checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData> = (1..=latest_seq)
            .map(|seq| (seq, plain_checkpoint(&committee, &keys, seq)))
            .collect();
        let latest = plain_checkpoint(&committee, &keys, latest_seq).checkpoint_summary;
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: latest.clone(),
            checkpoints: checkpoints.clone(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(0).unwrap();

        let mut first = pusher_over(perpetual.clone(), committees.clone(), transport).await;
        first.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        drop(first);

        // Restart: a fresh pusher over the SAME perpetual tables resumes at the
        // persisted cursor (5) — it does NOT re-fetch from upstream latest. Its
        // construction seeds the cache's processed head to the resumed cursor.
        let resume_cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let transport2: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints,
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        let mut resumed = pusher_over_with_cache(
            perpetual.clone(),
            committees,
            transport2,
            resume_cache.clone(),
            OcsMetrics::new_for_testing(),
        )
        .await;
        assert_eq!(
            resume_cache.processed_head_seq(),
            latest_seq,
            "a fresh pusher seeds the cache processed head from its resumed cursor"
        );

        // Upstream hasn't advanced past 5, so a second advance is a no-op: the
        // cursor stays at 5 (no re-stream of already-processed checkpoints).
        resumed.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
    }

    /// A transport whose watermark probe reports `latest_seq` and that serves
    /// exactly `checkpoints` (everything else NotFound). Lets a test move the
    /// (unauthenticated) watermark between ticks — including to a value no
    /// fetchable checkpoint backs, which is the inflated-watermark shape.
    fn transport_reporting(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        latest_seq: CheckpointSequenceNumber,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
    ) -> Arc<dyn SuiTransport> {
        Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: plain_checkpoint(committee, keys, latest_seq).checkpoint_summary,
            checkpoints,
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        })
    }

    /// The plausibility bound must never punish legitimate catch-up. A node
    /// down for a long time (or starting against a mature chain) sees a
    /// watermark millions of checkpoints past its persisted cursor on its
    /// FIRST observation — there is no prior observation to judge it against,
    /// so it is admitted and becomes the baseline, and the pusher catches up
    /// normally. Keying the bound on the persisted cursor instead would refuse
    /// exactly this case.
    #[tokio::test]
    async fn first_observation_after_long_downtime_catches_up_without_a_refusal() {
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

        // Resumed cursor 0, upstream five million checkpoints ahead.
        let latest_seq = 5_000_000u64;
        perpetual.put_sui_pusher_last_seq(0).unwrap();
        let transport = transport_reporting(&committee, &keys, latest_seq, HashMap::new());

        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            Arc::new(VerifiedStateCache::new()),
            metrics.clone(),
        )
        .await;

        // Tick one proposes the fast-forward, tick two (same watermark)
        // confirms it — no refusal anywhere.
        pusher.advance().await.unwrap();
        pusher.advance().await.unwrap();

        assert_eq!(
            metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .get(),
            0,
            "a legitimate first observation must not be clamped"
        );
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq),
            "the pusher must catch up to a legitimately distant head"
        );
    }

    #[tokio::test]
    async fn watermark_refusal_recovers_and_resumes_folding_without_restart() {
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
        perpetual.put_sui_pusher_last_seq(100).unwrap();
        let cache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees,
            transport_reporting(&committee, &keys, 100, HashMap::new()),
            cache.clone(),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();
        let latest_seq = 20_100;
        let checkpoints = ((latest_seq - 99)..=latest_seq)
            .map(|seq| (seq, plain_checkpoint(&committee, &keys, seq)))
            .collect();
        pusher.transport = transport_reporting(&committee, &keys, latest_seq, checkpoints);
        pusher.advance().await.unwrap();
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
        assert!(pusher.watermark_refusal_warned);
        assert_eq!(metrics.pusher_stalled.get(), 1);

        pusher
            .watermark
            .elapse_for_testing(Duration::from_secs(500));
        pusher.advance().await.unwrap();
        assert!(!pusher.watermark_refusal_warned);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(100),
            "recovery still requires a second tick to confirm the fast-forward"
        );
        pusher.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(latest_seq)
        );
        assert_eq!(cache.processed_head_seq(), latest_seq);
        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(metrics.pusher_skipped_irrelevant_total.get(), 100);
        pusher.advance().await.unwrap();
        assert_eq!(metrics.pusher_stalled.get(), 0);
    }

    /// One inflated watermark must change NOTHING: not the persisted cursor
    /// (which a restart would resume), not the pending gaps (dropping them is
    /// permanent state loss), and not the cache's monotone processed head
    /// (which the reader's staleness tripwire measures against — a poisoned
    /// processed head pins the tripwire "healthy" while nothing folds).
    #[tokio::test]
    async fn implausible_watermark_jump_is_refused_and_changes_nothing() {
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

        // An ordinary tick first: it establishes the in-process baseline (100)
        // and leaves seq 100 as a pending gap (its contents never materialize).
        perpetual.put_sui_pusher_last_seq(99).unwrap();
        let transport = transport_reporting(&committee, &keys, 100, HashMap::new());
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(100));
        assert!(pusher.pending_gaps.contains_key(&100));
        assert_eq!(cache.processed_head_seq(), 100);

        // Now the fullnode reports a head fifty million checkpoints ahead (a
        // wrong-network endpoint / corrupted response). Twice, so the refusal —
        // not the fast-forward's two-tick confirmation — is what holds: a
        // repeated sample would otherwise confirm itself.
        pusher.transport = transport_reporting(&committee, &keys, 50_000_000, HashMap::new());
        pusher.advance().await.unwrap();
        pusher.advance().await.unwrap();

        assert_eq!(
            metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .get(),
            2
        );
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(100),
            "an implausible watermark must not poison the persisted cursor"
        );
        assert_eq!(
            cache.processed_head_seq(),
            100,
            "an implausible watermark must not advance the monotone processed head"
        );
        assert!(
            pusher.pending_gaps.contains_key(&100),
            "an implausible watermark must not sacrifice pending gaps"
        );
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 0);
        assert_eq!(
            metrics.pusher_stalled.get(),
            1,
            "a run of refused ticks is a real stall — the folder is not advancing — and must \
             not read healthy just because the reason was a refusal"
        );
        // Two refused ticks, one warn: the refusal warn is latched to the
        // transition (the counter carries the per-tick volume).
        assert!(pusher.watermark_refusal_warned);

        // The genuine watermark returns and is still admitted — the refused
        // sample never became the baseline.
        pusher.transport = transport_reporting(&committee, &keys, 101, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(101));
        assert!(
            !pusher.watermark_refusal_warned,
            "the latch must clear so a later stretch warns again"
        );
    }

    /// The fast-forward is the single-shot, persisted, span-sacrificing
    /// consumer of the watermark, so it acts only on a watermark two
    /// consecutive ticks agree on: the first far-behind tick proposes and
    /// changes nothing, the second confirms and executes.
    #[tokio::test]
    async fn far_behind_fast_forward_waits_for_a_confirming_watermark() {
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

        // Cursor 0, head 1_200: past FAR_BEHIND_THRESHOLD (1_000).
        perpetual.put_sui_pusher_last_seq(0).unwrap();
        let transport = transport_reporting(&committee, &keys, 1_200, HashMap::new());
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;

        pusher.advance().await.unwrap();
        assert_eq!(
            pusher.pending_fast_forward,
            Some(1_200),
            "the first far-behind tick only proposes"
        );
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(0),
            "an unconfirmed fast-forward must not persist a cursor"
        );
        assert_eq!(cache.processed_head_seq(), 0);

        // The same watermark on the next tick confirms it.
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_fast_forward, None);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(1_200),
            "a confirmed fast-forward jumps to latest - CATCHUP_LOOKBACK and scans on"
        );
    }

    /// Confirmation catches what the plausibility bound cannot: an inflation
    /// small enough to sit INSIDE the bound (here +9_800, under the slack) is
    /// still admitted as a watermark, but the fast-forward it proposes is
    /// never executed because the next tick's genuine head does not corroborate
    /// it — so the cursor never jumps past thousands of real checkpoints and
    /// the pending gap in the would-be sacrificed span survives.
    #[tokio::test]
    async fn a_fast_forward_proposal_the_next_tick_contradicts_is_dropped() {
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

        // An ordinary tick: baseline 200, and seq 200 stays a pending gap.
        perpetual.put_sui_pusher_last_seq(199).unwrap();
        let transport = transport_reporting(&committee, &keys, 200, HashMap::new());
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&200));

        // A single inflated-but-in-bound sample proposes a fast-forward.
        pusher.transport = transport_reporting(&committee, &keys, 10_000, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_fast_forward, Some(10_000));
        assert_eq!(
            metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .get(),
            0,
            "this inflation is inside the plausibility bound — confirmation is what catches it"
        );

        // The genuine head returns: the proposal is not corroborated, so it is
        // dropped rather than executed.
        pusher.transport = transport_reporting(&committee, &keys, 201, HashMap::new());
        pusher.advance().await.unwrap();

        assert_eq!(pusher.pending_fast_forward, None);
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(201),
            "the cursor tracks the genuine head, not the inflated proposal"
        );
        assert!(
            pusher.pending_gaps.contains_key(&200),
            "no span was sacrificed, so the pending gap in it survives"
        );
        assert_eq!(metrics.pusher_gap_dropped_total.get(), 0);
    }

    /// A watermark ramp — each tick reports a head far past the last one, but
    /// never by enough for a single-step limit to notice — must not walk the
    /// cursor away. The rate bound spends allowance on every accepted advance,
    /// so the ramp is admitted until the burst is consumed and refused after
    /// that; the cursor ends bounded by one burst rather than by the ramp's
    /// length. (Guard-level counterpart:
    /// `watermark_guard::tests::a_sustained_ramp_drains_the_bucket_and_is_refused`.)
    #[tokio::test]
    async fn a_watermark_ramp_cannot_walk_the_cursor_away() {
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

        let start = 1_000u64;
        perpetual.put_sui_pusher_last_seq(start).unwrap();
        let transport = transport_reporting(&committee, &keys, start, HashMap::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            Arc::new(VerifiedStateCache::new()),
            metrics.clone(),
        )
        .await;
        // Establish the in-process baseline at the genuine head.
        pusher.advance().await.unwrap();

        // Ten ticks, each claiming ~10_000 past the last: every step is
        // modest, the aggregate is not.
        let mut claimed = start;
        for _ in 0..10 {
            claimed += 10_000;
            pusher.transport = transport_reporting(&committee, &keys, claimed, HashMap::new());
            // Twice per claim, so a far-behind fast-forward would be confirmed
            // and executed if the rate bound admitted the claim.
            pusher.advance().await.unwrap();
            pusher.advance().await.unwrap();
        }

        assert!(
            metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .get()
                > 0,
            "the ramp must start being refused once the burst is spent"
        );
        let cursor = perpetual.get_sui_pusher_last_seq().unwrap().unwrap();
        assert!(
            cursor <= start + 20_000,
            "a ramp must not walk the cursor past roughly one burst; cursor was {cursor}"
        );
        assert!(
            claimed - cursor > 50_000,
            "the ramp claimed far more than the cursor followed"
        );
    }

    /// The confirming sample is checked, not just compared: a confirmer that
    /// is itself inflated (an alternating load balancer whose high backend
    /// lands in the confirming slot) is outside the agreement band, so no
    /// fast-forward executes — and when a later pair does agree, the jump
    /// targets the LOWER of the two samples, never the inflated one.
    #[tokio::test]
    async fn an_inflated_confirmer_does_not_execute_an_inflated_fast_forward() {
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

        // A genuine far-behind proposal at 1_200 (cursor 0).
        perpetual.put_sui_pusher_last_seq(0).unwrap();
        let transport = transport_reporting(&committee, &keys, 1_200, HashMap::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            Arc::new(VerifiedStateCache::new()),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_fast_forward, Some(1_200));

        // The confirming tick is inflated by 9_000 — inside the rate bound, so
        // it is admitted as a watermark, but far outside the agreement band.
        pusher.transport = transport_reporting(&committee, &keys, 10_200, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(
            perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(0),
            "an out-of-band confirmer must not execute the fast-forward"
        );
        assert_eq!(pusher.pending_fast_forward, Some(10_200));

        // The genuine head returns, close to the ORIGINAL proposal but far
        // from the inflated one: still no agreement, so still no jump.
        pusher.transport = transport_reporting(&committee, &keys, 1_210, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(0));
        assert_eq!(pusher.pending_fast_forward, Some(1_210));

        // A pending gap inside the span the two samples disagree about: it
        // survives iff the jump targets the LOWER sample.
        pusher.pending_gaps.insert(
            1_150,
            PendingGap {
                first_seen: Instant::now(),
                last_archive_attempt: None,
            },
        );

        // A confirmer 240 ahead — inside the agreement band, so the pair
        // executes — but the jump takes the lower of the two, so the
        // sacrificed span ends at 1_110 rather than 1_350.
        pusher.transport = transport_reporting(&committee, &keys, 1_450, HashMap::new());
        pusher.advance().await.unwrap();
        assert!(
            pusher.pending_gaps.contains_key(&1_150),
            "the jump must target the lower of the two agreeing samples, sparing this gap"
        );
        assert_eq!(
            metrics.pusher_gap_dropped_total.get(),
            0,
            "no gap may be sacrificed beyond the lower agreeing sample"
        );
    }

    /// A tick that refuses its watermark disarms the pending proposal: the
    /// refused sample must not stand in as the confirmation for a proposal
    /// made before it. (The same `take()` covers a tick whose probe errored.)
    #[tokio::test]
    async fn a_refused_tick_disarms_a_pending_fast_forward_proposal() {
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

        perpetual.put_sui_pusher_last_seq(0).unwrap();
        let transport = transport_reporting(&committee, &keys, 1_200, HashMap::new());
        let metrics = OcsMetrics::new_for_testing();
        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            Arc::new(VerifiedStateCache::new()),
            metrics.clone(),
        )
        .await;
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_fast_forward, Some(1_200));

        // A refused sample in between.
        pusher.transport = transport_reporting(&committee, &keys, 50_000_000, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(
            metrics
                .watermark_implausible_total
                .with_label_values(&["folder"])
                .get(),
            1
        );
        assert_eq!(
            pusher.pending_fast_forward, None,
            "a refused tick must leave no proposal behind it"
        );

        // The genuine head reappears: it has to propose again from scratch
        // rather than being confirmed by the tick that was refused.
        pusher.transport = transport_reporting(&committee, &keys, 1_200, HashMap::new());
        pusher.advance().await.unwrap();
        assert_eq!(pusher.pending_fast_forward, Some(1_200));
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(0));
    }

    /// A non-end-of-epoch, committee-signed summary at `seq` carrying exactly
    /// `commitment` (used to plant a correct or a deliberately-wrong
    /// checkpoint-artifacts digest).
    fn signed_summary_with_commitment(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        commitment: CheckpointCommitment,
    ) -> CertifiedCheckpointSummary {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![commitment],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee)
    }

    /// The modified-objects tree over a single object plus its
    /// `CheckpointArtifactsDigest`, mirroring what the pusher builds from a
    /// fetched checkpoint.
    fn tree_and_digest_over(object: &Object) -> (ModifiedObjectTree, CheckpointArtifactsDigest) {
        let (id, version, digest) = object.compute_object_reference();
        let states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> =
            std::iter::once((id, (version, digest))).collect();
        let artifacts = CheckpointArtifacts::from_object_states(states);
        let tree = ModifiedObjectTree::new(&artifacts).unwrap();
        let artifacts_digest = artifacts.digest().unwrap();
        (tree, artifacts_digest)
    }

    /// A direct node must never fold state its own fullnode failed to prove
    /// against the committee. A foldable (end-of-epoch) checkpoint whose summary
    /// is signed by the WRONG committee is rejected at fold time: `advance()`
    /// surfaces the error, the committee head does not move, and nothing is
    /// cached. Without the fold-time committee check a compromised fullnode
    /// could seed the cache with forged state that cache-first reads serve
    /// unverified. (The honest counterpart is
    /// `pusher_eagerly_captures_end_of_epoch_committee`, which folds the same
    /// shape when it IS correctly signed.)
    #[tokio::test]
    async fn pusher_refuses_to_fold_a_checkpoint_that_fails_committee_verification() {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        // A different committee at the same epoch (0): its authorities are not
        // in the store's committee[0], so any summary it signs fails
        // verification. A different size guarantees a disjoint authority set
        // (the test-committee constructor is deterministic per size).
        let (foreign_committee, foreign_keys) = Committee::new_simple_test_committee_of_size(7);

        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(
                perpetual.clone(),
                Some(CommitteeBootstrap::Genesis(committee.clone())),
            )
            .unwrap(),
        );
        assert_eq!(committees.head_epoch(), 0);

        // An end-of-epoch checkpoint at epoch 0 signed by the foreign committee.
        let forged = end_of_epoch_checkpoint(&foreign_committee, &foreign_keys, 100);
        let latest = forged.checkpoint_summary.clone();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest,
            checkpoints: HashMap::from([(100u64, forged)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        perpetual.put_sui_pusher_last_seq(99).unwrap();

        let mut pusher = pusher_over_with_cache(
            perpetual.clone(),
            committees.clone(),
            transport,
            cache.clone(),
            OcsMetrics::new_for_testing(),
        )
        .await;

        // The fold-time committee check rejects it: advance() returns the error
        // rather than caching unverified state.
        assert!(
            pusher.advance().await.is_err(),
            "a checkpoint that fails committee verification must not be folded"
        );
        // The committee head never advanced past the unverifiable transition,
        // the cursor stayed put (the error halts it before the cursor write), so
        // a later honest checkpoint at the same seq is reprocessed, and nothing
        // was cached.
        assert_eq!(committees.head_epoch(), 0);
        assert_eq!(perpetual.get_sui_pusher_last_seq().unwrap(), Some(99));
        assert!(cache.is_empty());
    }

    /// The second fold-time check: even with a valid committee signature, the
    /// locally-built modified-objects tree must match the committee-signed
    /// checkpoint-artifacts digest before any object is folded — otherwise a
    /// fullnode could serve a genuine summary alongside a forged object tree.
    /// An honest summary (committing to THIS tree's digest) is accepted; one
    /// committing to a different tree's digest is rejected.
    #[tokio::test]
    async fn fold_verify_rejects_an_artifacts_digest_that_does_not_match_the_tree() {
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
        let transport: Arc<dyn SuiTransport> = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: end_of_epoch_checkpoint(&committee, &keys, 1).checkpoint_summary,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        let pusher = pusher_over(perpetual, committees, transport).await;

        // The tree the pusher would build for this checkpoint, and its digest.
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            SequenceNumber::from(1),
            Owner::AddressOwner(ObjectID::random().into()),
        );
        let (tree, artifacts_digest) = tree_and_digest_over(&object);

        // Honest: the summary commits to THIS tree's artifacts digest → folds.
        let honest = signed_summary_with_commitment(&committee, &keys, 1, artifacts_digest.into());
        assert!(
            pusher.verify_before_fold(&honest, &tree, true).is_ok(),
            "a summary committing to the matching tree digest must fold"
        );

        // Forged: a valid signature, but the summary commits to a DIFFERENT
        // tree's digest, so the binding to THIS tree fails → rejected.
        let other = Object::with_id_owner_version_for_testing(
            ObjectID::random(),
            SequenceNumber::from(7),
            Owner::AddressOwner(ObjectID::random().into()),
        );
        let (_other_tree, wrong_digest) = tree_and_digest_over(&other);
        let forged = signed_summary_with_commitment(&committee, &keys, 1, wrong_digest.into());
        assert!(
            pusher.verify_before_fold(&forged, &tree, true).is_err(),
            "a summary whose committed digest does not match the folded tree must be rejected"
        );
    }

    // ---- archive backfill ----

    /// An object typed `0x2::coin::Coin<{package}::ika::IKA>`: Ika-relevant to
    /// the pusher through a type parameter, the way a `Field<K, V>` bag entry
    /// with an Ika `V` is.
    fn ika_object(package: ObjectID, id: ObjectID, version: u64, owner: Owner) -> Object {
        ika_object_with_value(package, id, version, owner, 1)
    }

    fn ika_object_with_value(
        package: ObjectID,
        id: ObjectID,
        version: u64,
        owner: Owner,
        value: u64,
    ) -> Object {
        let ika = parse_sui_type_tag(&format!("{package}::ika::IKA")).unwrap();
        Object::new_move(
            MoveObject::new_coin(ika, SequenceNumber::from(version), id, value),
            owner,
            TransactionDigest::ZERO,
        )
    }

    /// A committee-signed checkpoint at `seq` with one transaction per entry
    /// of `transactions`, each writing its objects (all at one version, its
    /// lamport version). The effects carry each object's real digest and the
    /// summary commits to the matching artifacts digest — the shape of a
    /// genuine archive blob, which passes `verify_archive_checkpoint` and
    /// `build_entries`.
    fn checkpoint_writing(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        transactions: &[&[Object]],
    ) -> CheckpointData {
        let transactions: Vec<TestTransaction> = transactions
            .iter()
            .map(|written| {
                let lamport_version = written[0].version();
                assert!(written.iter().all(|o| o.version() == lamport_version));
                TestTransaction {
                    lamport_version,
                    written,
                    deleted: &[],
                    wrapped: &[],
                }
            })
            .collect();
        checkpoint_of(committee, keys, seq, &transactions)
    }

    /// One transaction of [`checkpoint_of`], executed at `lamport_version`:
    /// it writes `written` (each at that version), and deletes `deleted` and
    /// wraps `wrapped` (each given at the state the transaction consumes).
    struct TestTransaction<'a> {
        lamport_version: SequenceNumber,
        written: &'a [Object],
        deleted: &'a [Object],
        wrapped: &'a [Object],
    }

    /// [`checkpoint_writing`] for transactions that also delete or wrap
    /// objects. The effects record a deleted or wrapped object as Sui does, so
    /// the checkpoint's tree attests the deletion or wrap and the transaction
    /// has no output object for it.
    fn checkpoint_of(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        transactions: &[TestTransaction],
    ) -> CheckpointData {
        let transactions: Vec<CheckpointTransaction> = transactions
            .iter()
            .enumerate()
            .map(|(index, test_transaction)| {
                // A well-formed transaction to carry the effects below.
                let mut template = TestCheckpointBuilder::new(seq)
                    .start_transaction(index as u8)
                    .finish_transaction();
                let transaction = CheckpointData::from(template.build_checkpoint())
                    .transactions
                    .remove(0)
                    .transaction;
                let consumed = |o: &Object, id_deleted: bool| {
                    EffectsObjectChange::new(
                        Some(((o.version(), o.digest()), o.owner().clone())),
                        None,
                        false,
                        id_deleted,
                    )
                };
                let changed_objects = test_transaction
                    .written
                    .iter()
                    .map(|o| (o.id(), EffectsObjectChange::new(None, Some(o), true, false)))
                    .chain(
                        test_transaction
                            .deleted
                            .iter()
                            .map(|o| (o.id(), consumed(o, true))),
                    )
                    .chain(
                        test_transaction
                            .wrapped
                            .iter()
                            .map(|o| (o.id(), consumed(o, false))),
                    )
                    .collect();
                let effects = TransactionEffects::new_from_execution_v2(
                    ExecutionStatus::Success,
                    committee.epoch(),
                    GasCostSummary::default(),
                    vec![],
                    *transaction.digest(),
                    test_transaction.lamport_version,
                    changed_objects,
                    None,
                    None,
                    vec![],
                );
                CheckpointTransaction {
                    transaction,
                    effects,
                    events: None,
                    input_objects: vec![],
                    output_objects: test_transaction.written.to_vec(),
                }
            })
            .collect();
        let contents = CheckpointContents::new_with_digests_only_for_tests(
            transactions
                .iter()
                .map(|tx| ExecutionDigests::new(*tx.transaction.digest(), tx.effects.digest())),
        );
        let effects: Vec<&TransactionEffects> = transactions.iter().map(|tx| &tx.effects).collect();
        let artifacts_digest = CheckpointArtifacts::from(effects.as_slice())
            .digest()
            .unwrap();
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: transactions.len() as u64,
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
            transactions,
        }
    }

    /// Committee store at genesis committee[0], a cursor persisted at 99 and
    /// an upstream at 99 as well — so a tick scans nothing, and any cursor
    /// movement could only come from the backfill.
    struct BackfillFixture {
        _dir: tempfile::TempDir,
        committee: Committee,
        keys: Vec<AuthorityKeyPair>,
        perpetual: Arc<AuthorityPerpetualTables>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
    }

    const BACKFILL_CURSOR: CheckpointSequenceNumber = 99;

    fn backfill_fixture() -> BackfillFixture {
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
        perpetual.put_sui_pusher_last_seq(BACKFILL_CURSOR).unwrap();
        BackfillFixture {
            _dir: dir,
            committee,
            keys,
            perpetual,
            committees,
            metrics: OcsMetrics::new_for_testing(),
        }
    }

    /// The node's own fullnode: at the cursor, with every checkpoint pruned,
    /// reporting `live` as the current objects.
    fn pruned_fullnode(fx: &BackfillFixture, live: &[&Object]) -> Arc<dyn SuiTransport> {
        Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: plain_checkpoint(&fx.committee, &fx.keys, BACKFILL_CURSOR).checkpoint_summary,
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: live.iter().map(|o| (o.id(), (*o).clone())).collect(),
        })
    }

    fn durable_cache(
        fx: &BackfillFixture,
        pinned: &[CheckpointSequenceNumber],
    ) -> SharedVerifiedStateCache {
        Arc::new(
            VerifiedStateCache::open(fx.perpetual.clone())
                .unwrap()
                .with_retain_window(Some(1_000))
                .with_pinned_checkpoints(pinned.iter().copied().collect()),
        )
    }

    /// A pusher over `cache` at the fixture's cursor, with no archive and a
    /// fullnode reporting no live objects; tests then install both (the Ika
    /// package the pusher filters on is only known once it exists — see
    /// `ika_package_of`).
    async fn backfill_pusher(
        fx: &BackfillFixture,
        cache: SharedVerifiedStateCache,
    ) -> IkaCheckpointPusher {
        pusher_over_with_cache(
            fx.perpetual.clone(),
            fx.committees.clone(),
            pruned_fullnode(fx, &[]),
            cache,
            fx.metrics.clone(),
        )
        .await
    }

    fn ika_package_of(pusher: &IkaCheckpointPusher) -> ObjectID {
        *pusher.ika_packages.iter().next().unwrap()
    }

    /// One tick to start the due fetches, a wait for them, and one tick to
    /// fold what they returned — consecutive pusher ticks, compressed.
    async fn tick_backfill(pusher: &mut IkaCheckpointPusher) {
        pusher.advance().await.unwrap();
        for _ in 0..400 {
            let busy = pusher.archive_backfill.values().any(|state| {
                state
                    .in_flight
                    .as_ref()
                    .is_some_and(|fetch| !fetch.is_finished())
            });
            if !busy {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
        pusher.advance().await.unwrap();
    }

    fn backfill_outcome(metrics: &OcsMetrics, outcome: &str) -> u64 {
        metrics
            .pusher_backfill_outcomes_total
            .with_label_values(&[outcome])
            .get()
    }

    fn backfill_failures(metrics: &OcsMetrics, reason: &str) -> u64 {
        metrics
            .pusher_backfill_failures_total
            .with_label_values(&[reason])
            .get()
    }

    /// A single-object, committee-signed entry at `seq`, for folding filler
    /// into the cache directly.
    fn signed_entry_at(
        fx: &BackfillFixture,
        seq: CheckpointSequenceNumber,
        object: &Object,
    ) -> (CertifiedCheckpointSummary, VerifiedObjectEntry) {
        let (tree, digest) = tree_and_digest_over(object);
        let summary = signed_summary_with_commitment(&fx.committee, &fx.keys, seq, digest.into());
        let entry = VerifiedObjectEntry {
            object: object.clone(),
            checkpoint_seq: seq,
            proof: tree
                .get_inclusion_proof(object.compute_object_reference())
                .unwrap(),
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        (summary, entry)
    }

    /// The incident shape: a bag entry whose defining checkpoint the fullnode
    /// has pruned and no cache ever folded. The backfill re-folds it from the
    /// archive into the cache — without moving the scan cursor — pins it
    /// against the retain window, and a restarted pusher finds it cached and
    /// does not touch the archive again.
    #[tokio::test]
    async fn archive_backfill_folds_a_pruned_checkpoint_without_moving_the_cursor() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let bag = ObjectID::from_single_byte(0xBA);
        let entry = ika_object(
            package,
            ObjectID::from_single_byte(0xE1),
            7,
            Owner::ObjectOwner(bag.into()),
        );
        let unrelated = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x0F),
            SequenceNumber::from(7u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
        );
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(
                    &fx.committee,
                    &fx.keys,
                    42,
                    &[&[entry.clone(), unrelated.clone()]],
                ),
            )]),
            ..Default::default()
        });
        pusher.transport = pruned_fullnode(&fx, &[&entry, &unrelated]);
        pusher.archive = Some(archive.clone());
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 1);
        assert!(cache.get(entry.id()).is_none());

        tick_backfill(&mut pusher).await;

        let snapshot = cache
            .get(entry.id())
            .expect("the backfilled bag entry is cached");
        assert_eq!(snapshot.source_checkpoint_seq, 42);
        assert_eq!(
            snapshot.object.compute_object_reference(),
            entry.compute_object_reference()
        );
        assert!(cache.get(unrelated.id()).is_none(), "only Ika objects fold");
        assert_eq!(cache.children_of(bag), vec![entry.id()]);
        assert_eq!(
            pusher.cursor, BACKFILL_CURSOR,
            "the backfill never moves the cursor"
        );
        assert_eq!(
            fx.perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(BACKFILL_CURSOR)
        );
        for (outcome, count) in [
            ("fetched", 1),
            ("verified", 1),
            ("folded", 1),
            ("failed", 0),
        ] {
            assert_eq!(backfill_outcome(&fx.metrics, outcome), count, "{outcome}");
        }
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 1);

        // Pinned: a fold far past the retain window sweeps everything else of
        // that age and keeps the backfilled snapshot.
        let filler = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0xF1),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
        );
        let (summary, filler_entry) = signed_entry_at(&fx, 5_000, &filler);
        cache.absorb_entries(&summary, &[filler_entry]);
        assert!(
            cache.get(entry.id()).is_some(),
            "the backfilled snapshot is pinned"
        );
        drop(pusher);
        drop(cache);

        // Restart: the reopened (re-pinned) cache still holds it, so the new
        // pusher settles the checkpoint as cached without fetching it again.
        let reopened = durable_cache(&fx, &[42]);
        assert!(reopened.get(entry.id()).is_some());
        let mut restarted = backfill_pusher(&fx, reopened).await;
        let untouched = Arc::new(MockCheckpointArchive::default());
        restarted.archive = Some(untouched.clone());
        let mut restarted = restarted.with_archive_backfill(BTreeSet::from([42]));
        assert!(restarted.archive_backfill.is_empty());
        tick_backfill(&mut restarted).await;
        assert_eq!(untouched.fetches.load(Ordering::Relaxed), 0);
        assert_eq!(backfill_outcome(&fx.metrics, "already_cached"), 1);
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);
    }

    /// Nothing the archive serves is folded unless it verifies: a blob signed
    /// by a foreign committee, a genuine blob of another sequence, a genuine
    /// summary and effects with tampered object contents, and a checkpoint
    /// whose committee the store does not hold. Each attempt fails loudly with
    /// its reason, folds nothing, and stays scheduled for a retry.
    #[tokio::test]
    async fn archive_backfill_never_folds_a_checkpoint_that_fails_verification() {
        let fx = backfill_fixture();
        let (foreign_committee, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let later_epoch = Committee::new(5, fx.committee.voting_rights.iter().cloned().collect());

        // Each case builds the archive's blob for seq 42 from the genuine bag
        // entry and the pusher's Ika package.
        type Blob = Box<dyn Fn(&BackfillFixture, &Object, ObjectID) -> CheckpointData>;
        let cases: Vec<(&str, Blob, &str)> = vec![
            (
                "signed by a foreign committee",
                Box::new(move |_, entry, _| {
                    checkpoint_writing(
                        &foreign_committee,
                        &foreign_keys,
                        42,
                        &[slice::from_ref(entry)],
                    )
                }),
                "verification",
            ),
            (
                "a genuine blob of another sequence",
                Box::new(|fx, entry, _| {
                    checkpoint_writing(&fx.committee, &fx.keys, 43, &[slice::from_ref(entry)])
                }),
                "verification",
            ),
            (
                "tampered object contents under a genuine summary and effects",
                Box::new(|fx, entry, package| {
                    let mut blob =
                        checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(entry)]);
                    blob.transactions[0].output_objects = vec![ika_object_with_value(
                        package,
                        entry.id(),
                        entry.version().value(),
                        entry.owner().clone(),
                        1_000_000,
                    )];
                    blob
                }),
                "verification",
            ),
            (
                "a Sui epoch the committee store does not hold",
                Box::new(move |fx, entry, _| {
                    checkpoint_writing(&later_epoch, &fx.keys, 42, &[slice::from_ref(entry)])
                }),
                "missing_committee",
            ),
        ];

        for (case, blob, reason) in cases {
            let cache = durable_cache(&fx, &[42]);
            let mut pusher = backfill_pusher(&fx, cache.clone()).await;
            let package = ika_package_of(&pusher);
            let entry = ika_object(
                package,
                ObjectID::from_single_byte(0xE1),
                7,
                Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into()),
            );
            pusher.transport = pruned_fullnode(&fx, &[&entry]);
            pusher.archive = Some(Arc::new(MockCheckpointArchive {
                checkpoints: HashMap::from([(42u64, blob(&fx, &entry, package))]),
                ..Default::default()
            }));
            let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
            let failures_before = backfill_failures(&fx.metrics, reason);

            tick_backfill(&mut pusher).await;

            assert!(cache.get(entry.id()).is_none(), "{case}: nothing may fold");
            assert_eq!(
                backfill_failures(&fx.metrics, reason),
                failures_before + 1,
                "{case}: failure reason"
            );
            let state = pusher
                .archive_backfill
                .get(&42)
                .unwrap_or_else(|| panic!("{case}: must stay scheduled"));
            assert_eq!(state.failures, 1, "{case}");
            assert!(state.next_attempt > Instant::now(), "{case}: backs off");
        }
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 0);
    }

    /// The archive failing transiently is retried with doubling, capped
    /// backoff — no fetch before the backoff elapses — until it serves, and
    /// the checkpoint then folds.
    #[tokio::test]
    async fn archive_backfill_retries_with_backoff_until_the_archive_serves() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = ika_object(
            ika_package_of(&pusher),
            ObjectID::from_single_byte(0xE1),
            7,
            Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into()),
        );
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&entry)]),
            )]),
            failures_left: AtomicUsize::new(2),
            ..Default::default()
        });
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(archive.clone());
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));

        tick_backfill(&mut pusher).await;
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 1);
        assert_eq!(backfill_failures(&fx.metrics, "archive_fetch"), 1);
        let retry_in = pusher.archive_backfill[&42]
            .next_attempt
            .saturating_duration_since(Instant::now());
        assert!(retry_in > Duration::from_secs(4) && retry_in <= Duration::from_secs(5));

        // Not due yet: ticks do not touch the archive.
        tick_backfill(&mut pusher).await;
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 1);

        pusher.archive_backfill.get_mut(&42).unwrap().next_attempt = Instant::now();
        tick_backfill(&mut pusher).await;
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 2);
        assert_eq!(backfill_failures(&fx.metrics, "archive_fetch"), 2);
        let retry_in = pusher.archive_backfill[&42]
            .next_attempt
            .saturating_duration_since(Instant::now());
        assert!(retry_in > Duration::from_secs(9) && retry_in <= Duration::from_secs(10));
        assert!(cache.get(entry.id()).is_none());

        pusher.archive_backfill.get_mut(&42).unwrap().next_attempt = Instant::now();
        tick_backfill(&mut pusher).await;
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 3);
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(backfill_outcome(&fx.metrics, "failed"), 2);
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);
    }

    #[test]
    fn archive_backfill_retry_delay_doubles_and_caps() {
        let delays: Vec<u64> = [1, 2, 3, 4, 7, 8, 9, 1_000]
            .into_iter()
            .map(|failures| archive_backfill_retry_delay(failures).as_secs())
            .collect();
        assert_eq!(delays, vec![5, 10, 20, 40, 320, 600, 600, 600]);
    }

    /// Only objects the node's own fullnode still reports at exactly the
    /// archived reference fold: a newer version may have aged out of the cache
    /// and an object may have been deleted, and folding either would let a
    /// cache-first read serve state that is no longer current. Objects the
    /// cache already holds at that version or newer are left alone.
    #[tokio::test]
    async fn archive_backfill_folds_only_objects_that_are_still_current() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let bag = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let object = |byte: u8, version: u64| {
            ika_object(
                package,
                ObjectID::from_single_byte(byte),
                version,
                bag.clone(),
            )
        };
        let current = object(0xC1, 7);
        let superseded = object(0xC2, 7);
        let deleted = object(0xC3, 7);
        let cached_newer = object(0xC4, 7);
        let (summary, newer_entry) = signed_entry_at(&fx, 60, &object(0xC4, 8));
        cache.absorb_entries(&summary, &[newer_entry]);

        pusher.transport = pruned_fullnode(&fx, &[&current, &object(0xC2, 9), &object(0xC4, 8)]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(
                    &fx.committee,
                    &fx.keys,
                    42,
                    &[&[
                        current.clone(),
                        superseded.clone(),
                        deleted.clone(),
                        cached_newer.clone(),
                    ]],
                ),
            )]),
            ..Default::default()
        }));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
        tick_backfill(&mut pusher).await;

        assert_eq!(cache.get(current.id()).unwrap().source_checkpoint_seq, 42);
        assert!(cache.get(superseded.id()).is_none(), "superseded since");
        assert!(cache.get(deleted.id()).is_none(), "deleted since");
        let kept = cache.get(cached_newer.id()).unwrap();
        assert_eq!(kept.object.version(), SequenceNumber::from(8u64));
        assert_eq!(kept.source_checkpoint_seq, 60);
        assert_eq!(cache.snapshots_from_checkpoint(42), 1);
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);

        // A checkpoint with nothing current left settles without folding.
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let gone = ika_object(
            ika_package_of(&pusher),
            ObjectID::from_single_byte(0xD1),
            7,
            bag.clone(),
        );
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                43u64,
                checkpoint_writing(&fx.committee, &fx.keys, 43, &[slice::from_ref(&gone)]),
            )]),
            ..Default::default()
        }));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([43]));
        tick_backfill(&mut pusher).await;
        assert!(pusher.archive_backfill.is_empty());
        assert!(cache.get(gone.id()).is_none());
        assert_eq!(backfill_outcome(&fx.metrics, "nothing_to_fold"), 1);
    }

    /// When several transactions of the checkpoint wrote the object, the
    /// backfill folds the version the committee attests for the checkpoint
    /// (the last write), never an intermediate one.
    #[tokio::test]
    async fn archive_backfill_folds_the_attested_version_of_an_object_written_twice() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let id = ObjectID::from_single_byte(0xE1);
        let first_write = ika_object(package, id, 7, owner.clone());
        let last_write = ika_object_with_value(package, id, 8, owner, 2);
        pusher.transport = pruned_fullnode(&fx, &[&last_write]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(
                    &fx.committee,
                    &fx.keys,
                    42,
                    &[&[first_write], slice::from_ref(&last_write)],
                ),
            )]),
            ..Default::default()
        }));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
        tick_backfill(&mut pusher).await;

        assert_eq!(
            cache.get(id).unwrap().object.compute_object_reference(),
            last_write.compute_object_reference()
        );
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
    }

    /// Without an archive the backfill is a no-op. A listed checkpoint the
    /// scan has not reached yet waits for it — the scan may fold it, or a
    /// far-behind fast-forward may skip it — and is backfilled once the cursor
    /// has passed it, unless the scan folded it meanwhile.
    #[tokio::test]
    async fn archive_backfill_waits_for_the_scan_and_needs_an_archive() {
        let fx = backfill_fixture();
        let pusher = backfill_pusher(&fx, durable_cache(&fx, &[])).await;
        let pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);

        let ahead = BACKFILL_CURSOR + 1;
        let cache = durable_cache(&fx, &[ahead, ahead + 1]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let skipped_by_the_scan =
            ika_object(package, ObjectID::from_single_byte(0xE1), 7, owner.clone());
        let folded_by_the_scan = ika_object(package, ObjectID::from_single_byte(0xE2), 7, owner);
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                ahead,
                checkpoint_writing(
                    &fx.committee,
                    &fx.keys,
                    ahead,
                    &[slice::from_ref(&skipped_by_the_scan)],
                ),
            )]),
            ..Default::default()
        });
        pusher.transport = pruned_fullnode(&fx, &[&skipped_by_the_scan, &folded_by_the_scan]);
        pusher.archive = Some(archive.clone());
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([ahead, ahead + 1]));
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 2);
        tick_backfill(&mut pusher).await;
        assert_eq!(
            archive.fetches.load(Ordering::Relaxed),
            0,
            "not scanned yet"
        );

        // The cursor passes both — one skipped (as a fast-forward would), one
        // folded by the scan itself.
        let (summary, entry) = signed_entry_at(&fx, ahead + 1, &folded_by_the_scan);
        cache.absorb_entries(&summary, &[entry]);
        pusher.cursor = ahead + 1;
        tick_backfill(&mut pusher).await;

        assert_eq!(
            archive.fetches.load(Ordering::Relaxed),
            1,
            "only the skipped one is fetched"
        );
        assert_eq!(
            cache
                .get(skipped_by_the_scan.id())
                .unwrap()
                .source_checkpoint_seq,
            ahead
        );
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(backfill_outcome(&fx.metrics, "already_cached"), 1);
    }

    // ---- lost checkpoints: recorded, backfilled, pinned, collected ----

    /// The node's own fullnode at the fixture's cursor, serving exactly
    /// `checkpoints` (every other seq pruned) and reporting `live` as current.
    fn fullnode_at_cursor(
        fx: &BackfillFixture,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        live: &[&Object],
    ) -> Arc<dyn SuiTransport> {
        fullnode_at(fx, BACKFILL_CURSOR, checkpoints, live)
    }

    /// [`fullnode_at_cursor`] with its head at `head`.
    fn fullnode_at(
        fx: &BackfillFixture,
        head: CheckpointSequenceNumber,
        checkpoints: HashMap<CheckpointSequenceNumber, CheckpointData>,
        live: &[&Object],
    ) -> Arc<dyn SuiTransport> {
        Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: plain_checkpoint(&fx.committee, &fx.keys, head).checkpoint_summary,
            checkpoints,
            eoe_seqs: HashMap::new(),
            live_objects: live.iter().map(|o| (o.id(), (*o).clone())).collect(),
        })
    }

    /// A pending gap at `seq`, first seen `age` ago.
    fn gap_seen(pusher: &mut IkaCheckpointPusher, seq: CheckpointSequenceNumber, age: Duration) {
        pusher.pending_gaps.insert(
            seq,
            PendingGap {
                first_seen: Instant::now() - age,
                last_archive_attempt: None,
            },
        );
    }

    /// A pending gap at `seq`, already past the gap retry deadline: the next
    /// tick's retry is its last.
    fn expired_gap(pusher: &mut IkaCheckpointPusher, seq: CheckpointSequenceNumber) {
        gap_seen(pusher, seq, Duration::from_secs(601));
    }

    fn bag_entry(pusher: &IkaCheckpointPusher, byte: u8, version: u64) -> Object {
        ika_object(
            ika_package_of(pusher),
            ObjectID::from_single_byte(byte),
            version,
            Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into()),
        )
    }

    /// The cache a restarted direct node builds: pinned, as the connector stack
    /// pins it, from the operator list (empty here) and the recorded lost
    /// checkpoints.
    fn rebooted_cache(fx: &BackfillFixture) -> SharedVerifiedStateCache {
        let recorded: Vec<CheckpointSequenceNumber> =
            load_lost_checkpoints(&fx.perpetual).into_keys().collect();
        durable_cache(fx, &recorded)
    }

    fn recorded(fx: &BackfillFixture) -> BTreeMap<CheckpointSequenceNumber, LostCheckpoint> {
        fx.perpetual.load_sui_pusher_lost_checkpoints().unwrap()
    }

    /// The 342064089 shape, end to end: a gap neither the fullnode nor the
    /// archive serves before the retry deadline is dropped — and recorded,
    /// pinned and scheduled for the archive backfill instead of forgotten. A
    /// restarted node (a later binary whose archive read succeeds) re-folds it
    /// from the record alone, with no operator config, without moving the
    /// cursor.
    #[tokio::test]
    async fn a_gap_dropped_at_the_deadline_is_refolded_from_the_archive_after_a_restart() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let checkpoint =
            checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&entry)]);
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        expired_gap(&mut pusher, 42);

        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::NEW)]),
            "the dropped gap is persisted"
        );
        assert!(cache.is_checkpoint_pinned(42), "pinned before any fold");
        assert!(pusher.archive_backfill.contains_key(&42));
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
        assert!(cache.get(entry.id()).is_none());
        let packages = pusher.ika_packages.clone();
        drop(pusher);
        drop(cache);

        let cache = rebooted_cache(&fx);
        let mut restarted = backfill_pusher(&fx, cache.clone()).await;
        restarted.ika_packages = packages;
        restarted.transport = pruned_fullnode(&fx, &[&entry]);
        restarted.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(42u64, checkpoint)]),
            ..Default::default()
        }));
        let mut restarted = restarted.with_archive_backfill(BTreeSet::new());
        assert!(
            restarted.archive_backfill.contains_key(&42),
            "the record alone schedules the backfill"
        );
        tick_backfill(&mut restarted).await;

        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(restarted.cursor, BACKFILL_CURSOR);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::Settled)]),
            "kept after the fold, now settled"
        );
        assert!(cache.is_checkpoint_pinned(42));
    }

    /// A gap the fullnode serves but the node cannot fold (here: a blob that
    /// fails committee verification) is dropped at the deadline, recorded and
    /// handed to the archive backfill in the same process — which folds the
    /// genuine checkpoint once the archive serves it.
    #[tokio::test]
    async fn a_gap_that_keeps_failing_to_fold_is_recorded_and_backfilled() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let (foreign_committee, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let unfoldable = checkpoint_writing(
            &foreign_committee,
            &foreign_keys,
            42,
            &[slice::from_ref(&entry)],
        );
        pusher.transport = fullnode_at_cursor(&fx, HashMap::from([(42, unfoldable)]), &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&entry)]),
            )]),
            ..Default::default()
        }));
        expired_gap(&mut pusher, 42);

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert!(cache.get(entry.id()).is_none(), "the bad blob never folds");

        tick_backfill(&mut pusher).await;
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::Settled)])
        );
    }

    /// The far-behind fast-forward gives up on every pending gap: each is
    /// counted as dropped and recorded for the archive backfill. The span it
    /// jumps over was never fetched and is not recorded.
    #[tokio::test]
    async fn a_far_behind_fast_forward_records_the_gaps_it_sacrifices() {
        let fx = backfill_fixture();
        let mut pusher = backfill_pusher(&fx, durable_cache(&fx, &[])).await;
        pusher.transport = transport_reporting(
            &fx.committee,
            &fx.keys,
            BACKFILL_CURSOR + 1_500,
            HashMap::new(),
        );
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        for seq in [50, 60] {
            pusher.pending_gaps.insert(
                seq,
                PendingGap {
                    first_seen: Instant::now(),
                    last_archive_attempt: None,
                },
            );
        }

        // Propose, then confirm, the fast-forward.
        pusher.advance().await.unwrap();
        assert_eq!(pusher.cursor, BACKFILL_CURSOR);
        pusher.advance().await.unwrap();

        assert_eq!(pusher.cursor, BACKFILL_CURSOR + 1_500);
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 2);
        assert_eq!(
            recorded(&fx).into_keys().collect::<Vec<_>>(),
            vec![50, 60],
            "only the sacrificed pending gaps are recorded"
        );
        assert!(pusher.pending_gaps.keys().all(|seq| *seq > 1_000));
    }

    /// A recorded checkpoint stays pinned across restarts after its fold, and
    /// its record is collected only once no snapshot from it is left — never
    /// on the fold alone (the next boot would unpin it and the sweep would
    /// drop what was recovered), and never while it is still pending.
    #[tokio::test]
    async fn recorded_checkpoints_stay_pinned_across_restarts_until_superseded() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&entry)]),
            )]),
            // The gap repair's own archive attempt fails, so the gap drops.
            failures_left: AtomicUsize::new(1),
            ..Default::default()
        }));
        // 42 folds from the archive; 43 the archive cannot serve, so it stays
        // pending with no snapshot.
        expired_gap(&mut pusher, 42);
        expired_gap(&mut pusher, 43);
        pusher.advance().await.unwrap();
        tick_backfill(&mut pusher).await;
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        let records = recorded(&fx);
        assert_eq!(records.get(&42), Some(&LostCheckpoint::Settled));
        assert!(matches!(
            records.get(&43),
            Some(LostCheckpoint::Pending { .. })
        ));
        let packages = pusher.ika_packages.clone();
        drop(pusher);
        drop(cache);

        // Restart. The rebooted cache is pinned from the records before its
        // first absorb, which sweeps far past the window: the backfilled
        // snapshot survives.
        let cache = rebooted_cache(&fx);
        let filler = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0xF1),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
        );
        let (summary, filler_entry) = signed_entry_at(&fx, 5_000, &filler);
        cache.absorb_entries(&summary, &[filler_entry]);
        assert!(
            cache.get(entry.id()).is_some(),
            "the recorded checkpoint is pinned across the restart"
        );

        let mut restarted = backfill_pusher(&fx, cache.clone()).await;
        restarted.ika_packages = packages;
        restarted.transport = pruned_fullnode(&fx, &[&entry]);
        restarted.archive = Some(Arc::new(MockCheckpointArchive::default()));
        let mut restarted = restarted.with_archive_backfill(BTreeSet::new());
        assert!(
            !restarted.archive_backfill.contains_key(&42),
            "cached: not fetched again"
        );
        assert!(restarted.archive_backfill.contains_key(&43));

        // A collection pass keeps both: 42 still sources a snapshot, and 43
        // has none only because it has not folded.
        restarted.lost_checkpoints_collected_at = Instant::now() - LOST_CHECKPOINT_COLLECT_INTERVAL;
        restarted.advance().await.unwrap();
        assert_eq!(recorded(&fx).into_keys().collect::<Vec<_>>(), vec![42, 43]);

        // A newer version of the object supersedes the backfilled snapshot:
        // the next collection pass deletes the record and releases the pin.
        let newer = bag_entry(&restarted, 0xE1, 8);
        let (summary, newer_entry) = signed_entry_at(&fx, 5_001, &newer);
        cache.absorb_entries(&summary, &[newer_entry]);
        assert_eq!(cache.snapshots_from_checkpoint(42), 0);
        restarted.lost_checkpoints_collected_at = Instant::now() - LOST_CHECKPOINT_COLLECT_INTERVAL;
        restarted.advance().await.unwrap();
        assert_eq!(recorded(&fx).into_keys().collect::<Vec<_>>(), vec![43]);
        assert!(!cache.is_checkpoint_pinned(42));
        assert!(cache.is_checkpoint_pinned(43));
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
    }

    /// A record that settled earlier but has no snapshot left at boot is
    /// backfilled again rather than collected: the boot cannot tell a
    /// superseded snapshot from one a binary without the pin evicted. Still
    /// current, it folds again; superseded, it settles with nothing to fold and
    /// is collected.
    #[tokio::test]
    async fn a_settled_record_with_no_snapshot_left_is_reverified_at_boot() {
        let fx = backfill_fixture();
        fx.perpetual
            .put_sui_pusher_lost_checkpoint(42, LostCheckpoint::Settled)
            .unwrap();
        fx.perpetual
            .put_sui_pusher_lost_checkpoint(43, LostCheckpoint::Settled)
            .unwrap();
        let cache = rebooted_cache(&fx);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let evicted = bag_entry(&pusher, 0xE1, 7);
        let superseded = bag_entry(&pusher, 0xE2, 7);
        pusher.transport = pruned_fullnode(&fx, &[&evicted, &bag_entry(&pusher, 0xE2, 9)]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([
                (
                    42u64,
                    checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&evicted)]),
                ),
                (
                    43u64,
                    checkpoint_writing(
                        &fx.committee,
                        &fx.keys,
                        43,
                        &[slice::from_ref(&superseded)],
                    ),
                ),
            ]),
            ..Default::default()
        }));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::new());
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::NEW), (43, LostCheckpoint::NEW)]),
            "back to pending until the backfill settles"
        );
        tick_backfill(&mut pusher).await;

        assert_eq!(cache.get(evicted.id()).unwrap().source_checkpoint_seq, 42);
        assert!(cache.get(superseded.id()).is_none());
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::Settled)])
        );
        assert!(!cache.is_checkpoint_pinned(43));
    }

    /// The record is bounded: past `MAX_LOST_CHECKPOINTS` a lost checkpoint is
    /// not recorded, persisted, pinned or scheduled — it counts in the
    /// overflow metric (and warns once per stretch). Room frees as records are
    /// collected.
    #[tokio::test]
    async fn the_lost_checkpoint_record_is_capped() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        // A full record (in memory: the cap counts the records this process
        // holds).
        for seq in 1_000_000..1_000_000 + MAX_LOST_CHECKPOINTS as u64 {
            pusher.lost_checkpoints.insert(seq, LostCheckpoint::Settled);
        }

        expired_gap(&mut pusher, 42);
        expired_gap(&mut pusher, 43);
        pusher.advance().await.unwrap();

        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 2);
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 2);
        assert!(
            recorded(&fx).is_empty(),
            "nothing past the cap is persisted"
        );
        assert!(!pusher.lost_checkpoints.contains_key(&42));
        assert!(!pusher.archive_backfill.contains_key(&42));
        assert!(!cache.is_checkpoint_pinned(42));

        pusher.forget_lost_checkpoint(1_000_000);
        expired_gap(&mut pusher, 44);
        pusher.advance().await.unwrap();
        assert_eq!(recorded(&fx).into_keys().collect::<Vec<_>>(), vec![44]);
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 2);
        assert_eq!(
            fx.metrics.pusher_lost_checkpoints.get(),
            MAX_LOST_CHECKPOINTS as i64
        );
    }

    /// A recorded checkpoint the archive answers NotFound for is retried — the
    /// first NotFound starts a persisted clock — and abandoned once the clock
    /// passes `ARCHIVE_NOT_FOUND_GIVE_UP_AFTER`: loudly (the `abandoned`
    /// outcome), with its record deleted and its pin released. An operator
    /// entry never gives up.
    #[tokio::test]
    async fn a_recorded_checkpoint_the_archive_no_longer_holds_is_abandoned() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[44]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        // 44 is an operator entry, also recorded, with a long-expired clock.
        let expired_clock = LostCheckpoint::Pending {
            archive_not_found_since: Some(
                unix_seconds_now() - ARCHIVE_NOT_FOUND_GIVE_UP_AFTER.as_secs() - 60,
            ),
        };
        fx.perpetual
            .put_sui_pusher_lost_checkpoint(44, expired_clock)
            .unwrap();
        pusher.lost_checkpoints.insert(44, expired_clock);
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([44]));
        expired_gap(&mut pusher, 42);
        pusher.advance().await.unwrap();
        assert!(pusher.archive_backfill.contains_key(&42));

        tick_backfill(&mut pusher).await;
        assert_eq!(backfill_failures(&fx.metrics, "archive_not_found"), 2);
        let Some(LostCheckpoint::Pending {
            archive_not_found_since: Some(since),
        }) = recorded(&fx).get(&42).copied()
        else {
            panic!("the first NotFound starts the persisted give-up clock");
        };
        assert!(pusher.archive_backfill.contains_key(&42), "still retried");

        // The clock runs out; the next NotFound abandons it.
        let expired = LostCheckpoint::Pending {
            archive_not_found_since: Some(since - ARCHIVE_NOT_FOUND_GIVE_UP_AFTER.as_secs()),
        };
        pusher.lost_checkpoints.insert(42, expired);
        for seq in [42, 44] {
            pusher.archive_backfill.get_mut(&seq).unwrap().next_attempt = Instant::now();
        }
        tick_backfill(&mut pusher).await;

        assert!(!pusher.archive_backfill.contains_key(&42));
        assert!(!recorded(&fx).contains_key(&42));
        assert!(!cache.is_checkpoint_pinned(42));
        assert_eq!(backfill_outcome(&fx.metrics, "abandoned"), 1);
        assert!(
            pusher.archive_backfill.contains_key(&44),
            "an operator entry never gives up"
        );
        assert!(cache.is_checkpoint_pinned(44));
    }

    /// A burst of due backfill checkpoints is fetched at most
    /// `MAX_CONCURRENT_BACKFILL_FETCHES` at a time; the rest wait for a slot.
    #[tokio::test]
    async fn backfill_fetches_are_bounded_in_flight() {
        let fx = backfill_fixture();
        let mut pusher = backfill_pusher(&fx, durable_cache(&fx, &[])).await;
        let archive = Arc::new(MockCheckpointArchive::default());
        pusher.archive = Some(archive.clone());
        let seqs: BTreeSet<CheckpointSequenceNumber> = (1..=10).collect();
        let mut pusher = pusher.with_archive_backfill(seqs);
        let in_flight = |pusher: &IkaCheckpointPusher| {
            pusher
                .archive_backfill
                .values()
                .filter(|state| state.in_flight.is_some())
                .count()
        };

        pusher.advance().await.unwrap();
        assert_eq!(in_flight(&pusher), MAX_CONCURRENT_BACKFILL_FETCHES);
        // Each attempt fails (NotFound) and backs off, so every seq is fetched
        // once while the slots roll through all ten.
        for _ in 0..10 {
            if archive.fetches.load(Ordering::Relaxed) == 10 {
                break;
            }
            tick_backfill(&mut pusher).await;
            assert!(in_flight(&pusher) <= MAX_CONCURRENT_BACKFILL_FETCHES);
        }
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 10);
        assert_eq!(
            backfill_failures(&fx.metrics, "archive_not_found"),
            10 - in_flight(&pusher) as u64
        );
    }

    // ---- lost checkpoints: recorded on a gap's first fold failure ----

    /// `entry`'s checkpoint at `seq`, signed by a committee the node does not
    /// know: served by the fullnode, it fails to fold on every attempt.
    fn unfoldable_checkpoint(seq: CheckpointSequenceNumber, entry: &Object) -> CheckpointData {
        let (committee, keys) = Committee::new_simple_test_committee_of_size(7);
        checkpoint_writing(&committee, &keys, seq, &[slice::from_ref(entry)])
    }

    /// The genuine checkpoint at `seq` writing `entry`.
    fn genuine_checkpoint(
        fx: &BackfillFixture,
        seq: CheckpointSequenceNumber,
        entry: &Object,
    ) -> CheckpointData {
        checkpoint_writing(&fx.committee, &fx.keys, seq, &[slice::from_ref(entry)])
    }

    /// A fold failure cut short by a restart: the scan passes a checkpoint
    /// whose contents are not served yet (a pending gap, the cursor persisted
    /// past it), the fullnode then serves it but this node cannot fold it, and
    /// the node restarts before the gap's deadline. The first fold failure
    /// records and pins it — without scheduling it, the live retry still owns
    /// it — so the restart, which loses the in-memory gap, backfills it from
    /// the record alone.
    #[tokio::test]
    async fn a_gap_that_fails_to_fold_is_backfilled_after_a_restart_before_its_deadline() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let seq = BACKFILL_CURSOR + 1;
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(seq, genuine_checkpoint(&fx, seq, &entry))]),
            ..Default::default()
        });
        pusher.archive = Some(archive.clone());
        pusher.transport = fullnode_at(&fx, seq, HashMap::new(), &[&entry]);
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&seq));
        assert_eq!(
            fx.perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(seq),
            "the cursor is persisted past the pending gap"
        );
        assert!(recorded(&fx).is_empty(), "an unserved gap is not recorded");

        pusher.transport = fullnode_at(
            &fx,
            seq,
            HashMap::from([(seq, unfoldable_checkpoint(seq, &entry))]),
            &[&entry],
        );
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&seq), "still retried live");
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(seq, LostCheckpoint::NEW)]),
            "recorded on the first fold failure"
        );
        assert!(cache.is_checkpoint_pinned(seq));
        assert!(
            pusher.archive_backfill.is_empty(),
            "not scheduled: the live retry is the only path for the seq"
        );
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 0);
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 0);
        let packages = pusher.ika_packages.clone();
        drop(pusher);
        drop(cache);

        // Restart inside the retry window.
        let cache = rebooted_cache(&fx);
        assert!(cache.is_checkpoint_pinned(seq), "pinned at boot");
        let mut restarted = backfill_pusher(&fx, cache.clone()).await;
        assert_eq!(restarted.cursor, seq, "the scan never revisits the gap");
        assert!(restarted.pending_gaps.is_empty(), "the gap itself is gone");
        restarted.ika_packages = packages;
        restarted.transport = fullnode_at(&fx, seq, HashMap::new(), &[&entry]);
        restarted.archive = Some(archive.clone());
        let mut restarted = restarted.with_archive_backfill(BTreeSet::new());
        assert!(
            restarted.archive_backfill.contains_key(&seq),
            "the record alone schedules the backfill"
        );
        tick_backfill(&mut restarted).await;

        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, seq);
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(restarted.cursor, seq);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(seq, LostCheckpoint::Settled)])
        );
        assert!(cache.is_checkpoint_pinned(seq));
    }

    /// The transient every Sui epoch boundary produces: a gap in the next
    /// epoch fails to fold with MissingCommittee until that epoch's committee
    /// installs, then folds on a later live retry. Repaired as before records
    /// existed, it leaves nothing behind: the early record is deleted, the pin
    /// released, and no backfill was ever scheduled.
    #[tokio::test]
    async fn a_gap_recorded_on_a_fold_failure_is_forgotten_when_the_live_retry_folds_it() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        // Sui epoch 1, signed by its committee (epoch 0's members).
        let next_committee =
            Committee::new(1, fx.committee.voting_rights.iter().cloned().collect());
        let checkpoint =
            checkpoint_writing(&next_committee, &fx.keys, 42, &[slice::from_ref(&entry)]);
        pusher.transport = fullnode_at_cursor(&fx, HashMap::from([(42, checkpoint)]), &[&entry]);
        let archive = Arc::new(MockCheckpointArchive::default());
        pusher.archive = Some(archive.clone());
        gap_seen(&mut pusher, 42, Duration::ZERO);

        let (logs, _guard) = CapturedLogs::start();
        pusher.advance().await.unwrap();
        assert!(
            logs.text().contains("no Sui committee for epoch 1"),
            "the fold fails for the missing committee: {}",
            logs.text()
        );
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert!(cache.is_checkpoint_pinned(42));
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);

        // Epoch 1's committee installs; the next retry folds the gap.
        fx.committees
            .install_next_from_checkpoint(&end_of_epoch_checkpoint(&fx.committee, &fx.keys, 41))
            .unwrap();
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert!(recorded(&fx).is_empty(), "the early record is deleted");
        assert!(!cache.is_checkpoint_pinned(42), "and its pin released");
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 0);
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);
        assert_eq!(
            archive.fetches.load(Ordering::Relaxed),
            0,
            "no backfill ever ran"
        );
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 0);
    }

    /// A gap that fails to fold and is then pruned by the fullnode is repaired
    /// from the archive by the gap retry — and that repair, too, deletes the
    /// record its fold failure wrote.
    #[tokio::test]
    async fn a_gap_recorded_on_a_fold_failure_is_forgotten_when_the_archive_repairs_it() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([(42, unfoldable_checkpoint(42, &entry))]),
            &[&entry],
        );
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(42u64, genuine_checkpoint(&fx, 42, &entry))]),
            ..Default::default()
        });
        pusher.archive = Some(archive.clone());
        // Past the fullnode-only grace, so the archive is consulted as soon as
        // the fullnode stops serving the gap.
        gap_seen(&mut pusher, 42, Duration::from_secs(6));

        pusher.advance().await.unwrap();
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 0);

        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(fx.metrics.pusher_gap_archive_repairs_total.get(), 1);
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert!(recorded(&fx).is_empty(), "the early record is deleted");
        assert!(!cache.is_checkpoint_pinned(42));
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 0);
    }

    /// A gap that keeps failing to fold is recorded on its first failure but
    /// scheduled for the archive backfill only when it is dropped at its
    /// deadline — exactly once, although the record already exists.
    #[tokio::test]
    async fn a_gap_that_fails_to_fold_until_its_deadline_is_scheduled_once() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([(42, unfoldable_checkpoint(42, &entry))]),
            &[&entry],
        );
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(42u64, genuine_checkpoint(&fx, 42, &entry))]),
            ..Default::default()
        });
        pusher.archive = Some(archive.clone());
        gap_seen(&mut pusher, 42, Duration::ZERO);

        for _ in 0..3 {
            pusher.advance().await.unwrap();
        }
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 0);

        pusher.pending_gaps.get_mut(&42).unwrap().first_seen =
            Instant::now() - Duration::from_secs(601);
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 1);
        assert!(
            pusher.archive_backfill.contains_key(&42),
            "the deadline schedules the recorded gap"
        );
        assert_eq!(fx.metrics.pusher_backfill_pending.get(), 1);
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 0);

        tick_backfill(&mut pusher).await;
        assert_eq!(
            archive.fetches.load(Ordering::Relaxed),
            1,
            "one backfill, one archive fetch"
        );
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(42, LostCheckpoint::Settled)])
        );
        assert!(pusher.archive_backfill.is_empty());
    }

    /// An operator-listed seq keeps its pin when the record its fold failure
    /// wrote is deleted on the repair: the config pins it, not the record.
    /// (The operator entry's backfill has settled — the cache already holds a
    /// snapshot from it — so its fold failure as a live gap records it like
    /// any other.)
    #[tokio::test]
    async fn an_operator_listed_gap_repaired_after_a_fold_failure_stays_pinned() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let (summary, cached) = signed_entry_at(&fx, 42, &bag_entry(&pusher, 0xE2, 7));
        cache.absorb_entries(&summary, &[cached]);
        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([(42, unfoldable_checkpoint(42, &entry))]),
            &[&entry],
        );
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));
        assert!(
            pusher.archive_backfill.is_empty(),
            "the operator entry settled"
        );
        gap_seen(&mut pusher, 42, Duration::ZERO);

        pusher.advance().await.unwrap();
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));

        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([(42, genuine_checkpoint(&fx, 42, &entry))]),
            &[&entry],
        );
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert!(recorded(&fx).is_empty(), "the early record is deleted");
        assert!(
            cache.is_checkpoint_pinned(42),
            "the operator's list still pins the seq"
        );
    }

    /// At the record cap a fold failure records nothing and counts nothing —
    /// the gap is not lost yet — and the give-up at its deadline counts the
    /// overflow once, as for any loss past the cap.
    #[tokio::test]
    async fn at_the_cap_a_fold_failure_counts_no_overflow_before_the_deadline() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([(42, unfoldable_checkpoint(42, &entry))]),
            &[&entry],
        );
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        for seq in 1_000_000..1_000_000 + MAX_LOST_CHECKPOINTS as u64 {
            pusher.lost_checkpoints.insert(seq, LostCheckpoint::Settled);
        }
        gap_seen(&mut pusher, 42, Duration::ZERO);

        for _ in 0..2 {
            pusher.advance().await.unwrap();
        }
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 0);
        assert!(!pusher.lost_checkpoints.contains_key(&42));
        assert!(!cache.is_checkpoint_pinned(42));

        pusher.pending_gaps.get_mut(&42).unwrap().first_seen =
            Instant::now() - Duration::from_secs(601);
        pusher.advance().await.unwrap();
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 1);
        assert!(recorded(&fx).is_empty());
        assert!(!pusher.archive_backfill.contains_key(&42));
    }

    // ---- lost checkpoints: recorded on a gap's first decode failure ----

    /// `inner`, except that fetching any of `seqs` fails with `error(seq)`:
    /// with [`undecodable`], a fullnode serving checkpoints this binary cannot
    /// decode, as `get_full_checkpoint` reports a conversion failure.
    struct FailingFullnode {
        inner: Arc<dyn SuiTransport>,
        seqs: BTreeSet<CheckpointSequenceNumber>,
        error: fn(CheckpointSequenceNumber) -> TransportError,
    }

    fn failing_fullnode(
        inner: Arc<dyn SuiTransport>,
        seqs: &[CheckpointSequenceNumber],
        error: fn(CheckpointSequenceNumber) -> TransportError,
    ) -> Arc<dyn SuiTransport> {
        Arc::new(FailingFullnode {
            inner,
            seqs: seqs.iter().copied().collect(),
            error,
        })
    }

    /// What the gRPC transport returns for a checkpoint holding a
    /// `TransactionExpiration` variant this binary does not know.
    fn undecodable(seq: CheckpointSequenceNumber) -> TransportError {
        TransportError::Encoding(format!(
            "decode full checkpoint {seq}: invalid transaction.bcs: unknown variant index 3"
        ))
    }

    /// What the gRPC transport returns for a fetch that ran out of time.
    fn timed_out(seq: CheckpointSequenceNumber) -> TransportError {
        TransportError::Network(format!(
            "status: DeadlineExceeded, message: \"checkpoint {seq}\""
        ))
    }

    #[async_trait]
    impl SuiTransport for FailingFullnode {
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            self.inner.get_latest_checkpoint().await
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.inner.get_latest_checkpoint_sequence().await
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            if self.seqs.contains(&seq) {
                return Err((self.error)(seq));
            }
            self.inner.get_full_checkpoint(seq).await
        }
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            self.inner.get_chain_identifier().await
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            self.inner.get_current_epoch().await
        }
        async fn get_committee(&self, epoch: Option<u64>) -> Result<Committee, TransportError> {
            self.inner.get_committee(epoch).await
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            self.inner.get_checkpoint_summary_by_digest(digest).await
        }
        async fn last_checkpoint_of_epoch(
            &self,
            epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.inner.last_checkpoint_of_epoch(epoch).await
        }
        async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
            self.inner.get_object(id).await
        }
        async fn get_object_with_version(
            &self,
            id: ObjectID,
            version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            self.inner.get_object_with_version(id, version).await
        }
        async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
            self.inner.batch_get_objects(ids).await
        }
        async fn list_dynamic_fields(
            &self,
            parent: ObjectID,
            page_size: Option<u32>,
            page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            self.inner
                .list_dynamic_fields(parent, page_size, page_token)
                .await
        }
        async fn get_transaction(
            &self,
            tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            self.inner.get_transaction(tx).await
        }
    }

    /// The 342064089 shape cut short by a restart: the fullnode serves the
    /// checkpoint but this binary cannot decode it, so its fetch fails with
    /// `TransportError::Encoding` and it never reaches the fold. The scan
    /// records and pins it the moment the fetch fails — without scheduling it —
    /// and a restart before the deadline, which loses the in-memory gap behind
    /// the persisted cursor, backfills it from the record alone (here the
    /// archive's copy is one the restarted binary can fold).
    #[tokio::test]
    async fn an_undecodable_gap_is_backfilled_after_a_restart_before_its_deadline() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let seq = BACKFILL_CURSOR + 1;
        let archive = Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(seq, genuine_checkpoint(&fx, seq, &entry))]),
            ..Default::default()
        });
        pusher.archive = Some(archive.clone());
        pusher.transport = failing_fullnode(
            fullnode_at(&fx, seq, HashMap::new(), &[&entry]),
            &[seq],
            undecodable,
        );

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&seq));
        assert_eq!(fx.perpetual.get_sui_pusher_last_seq().unwrap(), Some(seq));
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(seq, LostCheckpoint::NEW)]),
            "recorded at the scan's first, undecodable, fetch"
        );
        assert!(cache.is_checkpoint_pinned(seq));
        assert!(pusher.archive_backfill.is_empty(), "not scheduled");
        pusher.advance().await.unwrap();
        assert_eq!(recorded(&fx), BTreeMap::from([(seq, LostCheckpoint::NEW)]));
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 0);
        let packages = pusher.ika_packages.clone();
        drop(pusher);
        drop(cache);

        let cache = rebooted_cache(&fx);
        let mut restarted = backfill_pusher(&fx, cache.clone()).await;
        assert_eq!(restarted.cursor, seq);
        assert!(restarted.pending_gaps.is_empty());
        restarted.ika_packages = packages;
        restarted.transport = fullnode_at(&fx, seq, HashMap::new(), &[&entry]);
        restarted.archive = Some(archive.clone());
        let mut restarted = restarted.with_archive_backfill(BTreeSet::new());
        assert!(restarted.archive_backfill.contains_key(&seq));
        tick_backfill(&mut restarted).await;

        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, seq);
        assert_eq!(backfill_outcome(&fx.metrics, "folded"), 1);
        assert_eq!(
            recorded(&fx),
            BTreeMap::from([(seq, LostCheckpoint::Settled)])
        );
        assert!(cache.is_checkpoint_pinned(seq));
    }

    /// The scan and the retries both fail to decode the same checkpoint: one
    /// record is written, once — the scan's — and nothing more on the retries.
    #[tokio::test]
    async fn an_undecodable_checkpoint_is_recorded_once_across_the_scan_and_its_retries() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let seq = BACKFILL_CURSOR + 1;
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        pusher.transport = failing_fullnode(
            fullnode_at(&fx, seq, HashMap::new(), &[]),
            &[seq],
            undecodable,
        );

        let (logs, _guard) = CapturedLogs::start();
        for _ in 0..3 {
            pusher.advance().await.unwrap();
        }
        let text = logs.text();
        let writes: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("recorded the checkpoint as lost"))
            .collect();
        assert_eq!(writes.len(), 1, "one record write: {text}");
        assert!(writes[0].contains("first_decode_failure"), "{}", writes[0]);
        assert_eq!(recorded(&fx), BTreeMap::from([(seq, LostCheckpoint::NEW)]));
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 1);
    }

    /// A decode failure that a later fetch no longer has — the gap folds on a
    /// live retry — leaves nothing behind, and the archive is never consulted.
    #[tokio::test]
    async fn an_undecodable_gap_is_forgotten_when_a_later_fetch_folds_it() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let served = || {
            fullnode_at_cursor(
                &fx,
                HashMap::from([(42, genuine_checkpoint(&fx, 42, &entry))]),
                &[&entry],
            )
        };
        let archive = Arc::new(MockCheckpointArchive::default());
        pusher.archive = Some(archive.clone());
        pusher.transport = failing_fullnode(served(), &[42], undecodable);
        gap_seen(&mut pusher, 42, Duration::ZERO);

        pusher.advance().await.unwrap();
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert!(cache.is_checkpoint_pinned(42));

        pusher.transport = served();
        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(cache.get(entry.id()).unwrap().source_checkpoint_seq, 42);
        assert!(recorded(&fx).is_empty(), "the early record is deleted");
        assert!(!cache.is_checkpoint_pinned(42));
        assert!(pusher.archive_backfill.is_empty());
        assert_eq!(archive.fetches.load(Ordering::Relaxed), 0);
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 0);
    }

    /// A fetch that fails for any other reason — a pruned checkpoint
    /// (NotFound) or a timeout — says nothing about whether this binary can
    /// read the checkpoint: no early record, in the scan or in the retries, so
    /// a slow or pruning fullnode writes none.
    #[tokio::test]
    async fn a_fetch_that_fails_without_a_decode_error_records_nothing_early() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let head = BACKFILL_CURSOR + 1;
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        // 42 is pruned (NotFound); 43 and the scanned head time out.
        pusher.transport = failing_fullnode(
            fullnode_at(&fx, head, HashMap::new(), &[]),
            &[43, head],
            timed_out,
        );
        gap_seen(&mut pusher, 42, Duration::ZERO);
        gap_seen(&mut pusher, 43, Duration::from_secs(6));

        for _ in 0..3 {
            pusher.advance().await.unwrap();
        }

        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![42, 43, head]
        );
        assert!(recorded(&fx).is_empty());
        assert!(pusher.lost_checkpoints.is_empty());
        assert_eq!(fx.metrics.pusher_lost_checkpoints.get(), 0);
        for seq in [42, 43, head] {
            assert!(!cache.is_checkpoint_pinned(seq));
        }
    }

    /// The archive serves a gap the fullnode pruned, the blob passes the
    /// archive verification, and the fold still fails (here: one object's
    /// contents are not the attested ones): the checkpoint exists and this
    /// binary cannot fold it, so the first such failure records and pins it,
    /// without scheduling it.
    #[tokio::test]
    async fn a_verified_archive_blob_that_fails_to_fold_is_recorded() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let entry = bag_entry(&pusher, 0xE1, 7);
        let blob = with_contents_altered(genuine_checkpoint(&fx, 42, &entry), package, entry.id());
        pusher
            .verify_archive_checkpoint(42, &blob)
            .expect("the blob passes the archive verification");
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(42u64, blob)]),
            ..Default::default()
        }));
        gap_seen(&mut pusher, 42, Duration::from_secs(6));

        pusher.advance().await.unwrap();

        assert!(pusher.pending_gaps.contains_key(&42), "still retried");
        assert_eq!(fx.metrics.pusher_gap_archive_repairs_total.get(), 0);
        assert_eq!(recorded(&fx), BTreeMap::from([(42, LostCheckpoint::NEW)]));
        assert!(cache.is_checkpoint_pinned(42));
        assert!(pusher.archive_backfill.is_empty());
    }

    /// An archive blob that fails the archive verification — not signed by the
    /// committee, or a genuine checkpoint of another seq — is refused and says
    /// nothing about this checkpoint: no record.
    #[tokio::test]
    async fn an_archive_blob_that_fails_verification_records_nothing() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([
                (42u64, unfoldable_checkpoint(42, &entry)),
                (43u64, genuine_checkpoint(&fx, 999, &entry)),
            ]),
            ..Default::default()
        }));
        gap_seen(&mut pusher, 42, Duration::from_secs(6));
        gap_seen(&mut pusher, 43, Duration::from_secs(6));

        pusher.advance().await.unwrap();

        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![42, 43]
        );
        assert_eq!(fx.metrics.pusher_gap_archive_repairs_total.get(), 0);
        assert!(recorded(&fx).is_empty());
        assert!(!cache.is_checkpoint_pinned(42));
        assert!(!cache.is_checkpoint_pinned(43));
    }

    /// At the record cap an undecodable checkpoint is skipped quietly by the
    /// scan and the retries alike — the gap is not lost yet — and counts one
    /// overflow, at its deadline.
    #[tokio::test]
    async fn at_the_cap_an_undecodable_gap_counts_one_overflow_at_its_deadline() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let seq = BACKFILL_CURSOR + 1;
        pusher.archive = Some(Arc::new(MockCheckpointArchive::default()));
        pusher.transport = failing_fullnode(
            fullnode_at(&fx, seq, HashMap::new(), &[]),
            &[seq],
            undecodable,
        );
        for filler in 1_000_000..1_000_000 + MAX_LOST_CHECKPOINTS as u64 {
            pusher
                .lost_checkpoints
                .insert(filler, LostCheckpoint::Settled);
        }

        for _ in 0..2 {
            pusher.advance().await.unwrap();
        }
        assert!(pusher.pending_gaps.contains_key(&seq));
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 0);
        assert!(!pusher.lost_checkpoints.contains_key(&seq));
        assert!(!cache.is_checkpoint_pinned(seq));

        pusher.pending_gaps.get_mut(&seq).unwrap().first_seen =
            Instant::now() - Duration::from_secs(601);
        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.is_empty());
        assert_eq!(fx.metrics.pusher_gap_dropped_total.get(), 1);
        assert_eq!(fx.metrics.pusher_lost_checkpoints_overflow_total.get(), 1);
        assert!(recorded(&fx).is_empty());
    }

    /// A checkpoint whose Sui epoch's committee is not installed yet is a wait,
    /// not a verification failure: no security-critical error, and one info
    /// line per epoch however often the retry hits it. A checkpoint that does
    /// not verify — here, signed by another committee — is still refused at
    /// `ERROR` with `security_critical`, on every attempt.
    #[tokio::test]
    async fn a_missing_committee_is_logged_as_a_wait_not_a_security_failure() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let entry = bag_entry(&pusher, 0xE1, 7);
        let next_committee =
            Committee::new(1, fx.committee.voting_rights.iter().cloned().collect());
        pusher.transport = fullnode_at_cursor(
            &fx,
            HashMap::from([
                (
                    42,
                    checkpoint_writing(&next_committee, &fx.keys, 42, &[slice::from_ref(&entry)]),
                ),
                (43, unfoldable_checkpoint(43, &bag_entry(&pusher, 0xE2, 7))),
            ]),
            &[],
        );
        gap_seen(&mut pusher, 42, Duration::ZERO);
        gap_seen(&mut pusher, 43, Duration::ZERO);

        let (logs, _guard) = CapturedLogs::start();
        for _ in 0..2 {
            pusher.advance().await.unwrap();
        }
        assert_eq!(
            pusher.pending_gaps.keys().copied().collect::<Vec<_>>(),
            vec![42, 43],
            "neither folds"
        );
        let text = logs.text();
        let security: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("security_critical=true"))
            .collect();
        assert_eq!(
            security.len(),
            2,
            "the bad signature, once per attempt: {text}"
        );
        for line in &security {
            assert!(line.contains("ERROR"), "{line}");
            assert!(line.contains("seq=43"), "only the bad signature: {line}");
            assert!(line.contains("refusing to fold a checkpoint"), "{line}");
        }
        let waits: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("waits for its Sui epoch's committee"))
            .collect();
        assert_eq!(waits.len(), 1, "once per epoch: {text}");
        assert!(waits[0].contains("INFO"), "{}", waits[0]);
        assert!(waits[0].contains("seq=42"), "{}", waits[0]);
        assert!(waits[0].contains("epoch=1"), "{}", waits[0]);
        assert!(
            !text
                .lines()
                .any(|line| line.contains("ERROR") && line.contains("seq=42")),
            "{text}"
        );
    }

    // ---- folded objects are the attested ones ----

    /// Everything logged on this thread while its [`LogGuard`] lives. The
    /// pusher's tests run on a current-thread runtime, so this sees every line
    /// a tick logs — used to assert that a refusal is reported as the
    /// security-critical verification failure, which is the only report the
    /// scan and the pending-gap repair make of it.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    /// Keeps the capture installed. `tracing` caches each callsite's interest
    /// process-wide, computed when the callsite is first hit; while only one
    /// dispatcher is registered it computes it from the default of whichever
    /// thread hits the callsite first. A parallel test without a subscriber
    /// would then cache the shared refusal callsite as uninteresting and the
    /// capture would miss the line. The idle second dispatcher makes every
    /// computation consult all live dispatchers, the capture included.
    struct LogGuard {
        _capture: DefaultGuard,
        _idle: Dispatch,
    }

    impl io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLogs {
        fn start() -> (Self, LogGuard) {
            let idle = Dispatch::new(NoSubscriber::default());
            let logs = Self::default();
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let guard = LogGuard {
                _capture: subscriber::set_default(subscriber),
                _idle: idle,
            };
            (logs, guard)
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock()).into_owned()
        }

        /// The fold-time refusal: `error!` with `security_critical`, naming
        /// the checkpoint and why its objects are not the attested ones.
        fn assert_refused_as_verification(&self, seq: CheckpointSequenceNumber) {
            let text = self.text();
            let refusal = text
                .lines()
                .find(|line| line.contains("refusing to fold a checkpoint"))
                .unwrap_or_else(|| panic!("no fold refusal was logged:\n{text}"));
            for expected in [
                "ERROR",
                "security_critical=true",
                &format!("seq={seq}"),
                "committee-attested reference",
            ] {
                assert!(
                    refusal.contains(expected),
                    "the refusal must carry {expected:?}: {refusal}"
                );
            }
        }
    }

    /// The node's own fullnode serving `checkpoint`, at its head: a tick from
    /// the fixture's cursor scans exactly that checkpoint.
    fn fullnode_serving(checkpoint: CheckpointData) -> Arc<dyn SuiTransport> {
        let seq = *checkpoint.checkpoint_summary.sequence_number();
        Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: checkpoint.checkpoint_summary.clone(),
            checkpoints: HashMap::from([(seq, checkpoint)]),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        })
    }

    /// A blob identical to `checkpoint` except that the output object of
    /// `id` carries other contents: the same id, version and owner, and the
    /// same summary and effects — so it passes the committee signature and the
    /// artifacts digest, which covers the effects and not the object bytes.
    fn with_contents_altered(
        mut checkpoint: CheckpointData,
        package: ObjectID,
        id: ObjectID,
    ) -> CheckpointData {
        let output = checkpoint
            .transactions
            .iter_mut()
            .flat_map(|tx| tx.output_objects.iter_mut())
            .find(|o| o.id() == id)
            .unwrap();
        *output = ika_object_with_value(
            package,
            id,
            output.version().value(),
            output.owner().clone(),
            1_000_000,
        );
        checkpoint
    }

    /// Several transactions of one checkpoint write the same Ika object — the
    /// common case for the coordinator and its inner dynamic field. The scan
    /// folds the version the committee attests for the checkpoint (the last
    /// write) under a proof that verifies for it, never an earlier write: a
    /// cache-first read serves the cached object without re-checking its proof.
    #[tokio::test]
    async fn scan_folds_the_attested_version_of_an_object_written_twice() {
        let fx = backfill_fixture();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let id = ObjectID::from_single_byte(0xC0);
        let first_write = ika_object(package, id, 7, owner.clone());
        let last_write = ika_object_with_value(package, id, 8, owner, 2);
        let seq = BACKFILL_CURSOR + 1;
        pusher.transport = fullnode_serving(checkpoint_writing(
            &fx.committee,
            &fx.keys,
            seq,
            &[slice::from_ref(&first_write), slice::from_ref(&last_write)],
        ));

        pusher.advance().await.unwrap();

        assert_eq!(pusher.cursor, seq);
        let snapshot = cache.get(id).expect("the object is cached");
        assert_eq!(snapshot.source_checkpoint_seq, seq);
        assert_eq!(
            snapshot.object.compute_object_reference(),
            last_write.compute_object_reference(),
            "the cache must hold the attested (last) write, not an intermediate one"
        );
        Proof {
            targets: ProofTarget::new_ocs_inclusion(snapshot.object.compute_object_reference()),
            checkpoint_summary: snapshot.summary,
            proof_contents: ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(
                snapshot.proof,
            )),
        }
        .verify(&fx.committee)
        .expect("the cached proof verifies for the cached object");
        assert_eq!(fx.metrics.pusher_fold_verify_seconds.get_sample_count(), 1);
    }

    /// A checkpoint whose genuine summary and effects come with altered
    /// contents for one Ika object — here from the node's own fullnode. Nothing
    /// of it is folded, not even its other, genuine Ika object; the refusal is
    /// logged as the security-critical verification failure; and the scan stays
    /// on the checkpoint, failing the tick every time as for any other
    /// verification failure, without recording a fold-verify latency sample.
    #[tokio::test]
    async fn scan_refuses_a_checkpoint_whose_object_contents_are_not_the_attested_ones() {
        let fx = backfill_fixture();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let genuine = ika_object(package, ObjectID::from_single_byte(0xC1), 7, owner.clone());
        let altered = ika_object(package, ObjectID::from_single_byte(0xC2), 7, owner);
        let seq = BACKFILL_CURSOR + 1;
        pusher.transport = fullnode_serving(with_contents_altered(
            checkpoint_writing(
                &fx.committee,
                &fx.keys,
                seq,
                &[&[genuine.clone(), altered.clone()]],
            ),
            package,
            altered.id(),
        ));

        let (logs, _guard) = CapturedLogs::start();
        for _ in 0..2 {
            let error = pusher
                .advance()
                .await
                .expect_err("a checkpoint whose objects are not the attested ones must not fold");
            assert!(
                error_chain(&error)
                    .to_string()
                    .contains("committee-attested reference"),
                "{error:?}"
            );
            assert_eq!(pusher.cursor, BACKFILL_CURSOR);
        }
        assert!(cache.is_empty(), "nothing of the checkpoint may fold");
        assert_eq!(
            fx.perpetual.get_sui_pusher_last_seq().unwrap(),
            Some(BACKFILL_CURSOR)
        );
        assert_eq!(fx.metrics.pusher_pushed_total.get(), 0);
        assert_eq!(fx.metrics.pusher_fold_verify_seconds.get_sample_count(), 0);
        logs.assert_refused_as_verification(seq);
    }

    /// The same refusal on the pending-gap repair from the archive, an
    /// untrusted store: the blob passes the archive verification — sequence,
    /// committee signature, and the artifacts digest over its whole object
    /// set — and is still refused at fold time. Nothing is folded and the gap
    /// is not repaired; it stays pending for the next attempt.
    #[tokio::test]
    async fn archive_gap_repair_refuses_a_blob_whose_object_contents_are_not_the_attested_ones() {
        let fx = backfill_fixture();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let altered = ika_object(
            package,
            ObjectID::from_single_byte(0xC2),
            7,
            Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into()),
        );
        let seq = BACKFILL_CURSOR + 1;
        let blob = with_contents_altered(
            checkpoint_writing(&fx.committee, &fx.keys, seq, &[slice::from_ref(&altered)]),
            package,
            altered.id(),
        );
        pusher
            .verify_archive_checkpoint(seq, &blob)
            .expect("the blob passes the archive verification");
        // The fullnode advertises the checkpoint but never serves it (pruned).
        pusher.transport = Arc::new(MockTransport {
            fetch_control: None,
            latest_summary_pruned: false,
            latest: blob.checkpoint_summary.clone(),
            checkpoints: HashMap::new(),
            eoe_seqs: HashMap::new(),
            live_objects: HashMap::new(),
        });
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(seq, blob)]),
            ..Default::default()
        }));

        pusher.advance().await.unwrap();
        assert!(pusher.pending_gaps.contains_key(&seq));
        pusher.pending_gaps.get_mut(&seq).unwrap().first_seen =
            Instant::now() - Duration::from_secs(6);
        let (logs, _guard) = CapturedLogs::start();
        pusher.advance().await.unwrap();

        assert!(
            pusher.pending_gaps.contains_key(&seq),
            "the refused blob must not clear the gap"
        );
        assert_eq!(fx.metrics.pusher_gap_archive_repairs_total.get(), 0);
        assert!(cache.is_empty(), "nothing of the blob may fold");
        logs.assert_refused_as_verification(seq);
    }

    /// An Ika object written and then deleted or wrapped within one
    /// checkpoint: the checkpoint attests the deletion or wrap, so no state of
    /// the object is folded — not the intermediate write — and the checkpoint
    /// is not refused: its other objects fold and the scan moves on. Refusing
    /// would stall the scan on an honest checkpoint for good.
    #[tokio::test]
    async fn scan_folds_no_state_of_an_object_deleted_or_wrapped_after_its_write() {
        let fx = backfill_fixture();
        let cache: SharedVerifiedStateCache = Arc::new(VerifiedStateCache::new());
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let package = ika_package_of(&pusher);
        let owner = Owner::ObjectOwner(ObjectID::from_single_byte(0xBA).into());
        let object =
            |byte: u8| ika_object(package, ObjectID::from_single_byte(byte), 7, owner.clone());
        let (kept, deleted, wrapped) = (object(0xC1), object(0xC2), object(0xC3));
        let seq = BACKFILL_CURSOR + 1;
        pusher.transport = fullnode_serving(checkpoint_of(
            &fx.committee,
            &fx.keys,
            seq,
            &[
                TestTransaction {
                    lamport_version: SequenceNumber::from(7u64),
                    written: &[kept.clone(), deleted.clone(), wrapped.clone()],
                    deleted: &[],
                    wrapped: &[],
                },
                TestTransaction {
                    lamport_version: SequenceNumber::from(8u64),
                    written: &[],
                    deleted: slice::from_ref(&deleted),
                    wrapped: slice::from_ref(&wrapped),
                },
            ],
        ));

        pusher.advance().await.unwrap();

        assert_eq!(pusher.cursor, seq);
        assert_eq!(
            cache
                .get(kept.id())
                .unwrap()
                .object
                .compute_object_reference(),
            kept.compute_object_reference()
        );
        assert!(
            cache.get(deleted.id()).is_none(),
            "deleted in the checkpoint"
        );
        assert!(
            cache.get(wrapped.id()).is_none(),
            "wrapped in the checkpoint"
        );
    }

    /// The direct node's proof provider over a bag whose defining checkpoint
    /// the fullnode has pruned. It lists the bag's live children and reports
    /// their current objects but can no longer rebuild their proofs, so —
    /// as `LocalProofProvider::build_object_entry` does — it falls back to
    /// `recover_pruned_proof` over the node's verified cache, reporting the
    /// children it cannot prove in `skipped_entry_ids`. With
    /// `unprovable_entries`, every child is reported skipped instead, the way
    /// the provider reports an entry whose proof fails with an encoding error.
    struct PrunedBagProvider {
        bag: ObjectID,
        live_children: Vec<Object>,
        cache: SharedVerifiedStateCache,
        claimed_head: CheckpointSequenceNumber,
        unprovable_entries: bool,
    }

    impl PrunedBagProvider {
        fn prove(&self, object: &Object) -> ProofBuildResult {
            if self.unprovable_entries {
                return Err(TransportError::Encoding("undecodable checkpoint".into()));
            }
            recover_pruned_proof(
                Err(TransportError::NotFound(
                    "defining checkpoint pruned".into(),
                )),
                Some(self.cache.as_ref()),
                object.compute_object_reference(),
            )
            .0
        }
    }

    #[async_trait]
    impl ProofProvider for PrunedBagProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            let object = self
                .live_children
                .iter()
                .find(|o| o.id() == id)
                .ok_or_else(|| TransportError::NotFound(format!("object {id}")))?;
            let (_, entry, summary) = self.prove(object)?;
            Ok(VerifiedObjectResponse {
                object: entry.object,
                summary,
                proof: entry.proof,
                claimed_latest_checkpoint_seq: self.claimed_head,
            })
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unimplemented!()
        }
        async fn verified_dynamic_fields_page(
            &self,
            request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            assert_eq!(request.parent_id, self.bag);
            let mut summaries = BTreeMap::new();
            let mut entries = Vec::new();
            let mut skipped_entry_ids = Vec::new();
            for (index, object) in self.live_children.iter().enumerate() {
                match self.prove(object) {
                    Ok((seq, mut entry, summary)) => {
                        entry.dynamic_field_name_type = "u64".to_string();
                        entry.dynamic_field_name_bcs = bcs::to_bytes(&(index as u64)).unwrap();
                        summaries.entry(seq).or_insert(summary);
                        entries.push(entry);
                    }
                    Err(TransportError::NotFound(_) | TransportError::Encoding(_)) => {
                        skipped_entry_ids.push(object.id())
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(VerifiedDynamicFieldsPageResponse {
                summaries,
                entries,
                next_page_token: None,
                claimed_latest_checkpoint_seq: self.claimed_head,
                skipped_entry_ids,
            })
        }
    }

    /// The same provider seen across the relay: every response crosses the
    /// wire as BCS, as it does from the mirror server to a mirrored peer.
    struct OverTheWire(Arc<PrunedBagProvider>);

    fn over_the_wire<T: serde::Serialize + serde::de::DeserializeOwned>(value: T) -> T {
        bcs::from_bytes(&bcs::to_bytes(&value).unwrap()).unwrap()
    }

    #[async_trait]
    impl ProofProvider for OverTheWire {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            self.0.verified_object(id).await.map(over_the_wire)
        }
        async fn batch_verified_objects(
            &self,
            ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            self.0.batch_verified_objects(ids).await.map(over_the_wire)
        }
        async fn verified_dynamic_fields_page(
            &self,
            request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            self.0
                .verified_dynamic_fields_page(request)
                .await
                .map(over_the_wire)
        }
    }

    /// End to end over the pieces a direct node and its mirrored peers share:
    /// a bag entry whose defining checkpoint is pruned upstream and absent from
    /// the cache is invisible to both the direct reader and a mirrored reader.
    /// After the pusher backfills that checkpoint from the archive, the direct
    /// provider's pruned-proof fallback serves the entry with its committee
    /// proof, and both readers verify and return it — the mirrored one across
    /// a BCS wire and a changeset index whose window no longer covers the
    /// entry's checkpoint (currency `Unknown`, accepted). The direct reader also
    /// resolves the entry when the provider can only report it as skipped.
    #[tokio::test]
    async fn a_backfilled_bag_entry_reaches_direct_and_mirrored_readers() {
        let fx = backfill_fixture();
        let cache = durable_cache(&fx, &[42]);
        let mut pusher = backfill_pusher(&fx, cache.clone()).await;
        let bag = ObjectID::from_single_byte(0xBA);
        let entry = ika_object(
            ika_package_of(&pusher),
            ObjectID::from_single_byte(0xE1),
            7,
            Owner::ObjectOwner(bag.into()),
        );
        pusher.transport = pruned_fullnode(&fx, &[&entry]);
        pusher.archive = Some(Arc::new(MockCheckpointArchive {
            checkpoints: HashMap::from([(
                42u64,
                checkpoint_writing(&fx.committee, &fx.keys, 42, &[slice::from_ref(&entry)]),
            )]),
            ..Default::default()
        }));
        let mut pusher = pusher.with_archive_backfill(BTreeSet::from([42]));

        let provider = |unprovable_entries| {
            Arc::new(PrunedBagProvider {
                bag,
                live_children: vec![entry.clone()],
                cache: cache.clone(),
                claimed_head: BACKFILL_CURSOR,
                unprovable_entries,
            })
        };
        let direct_reader = |unprovable_entries| {
            OcsVerifiedReader::new(
                provider(unprovable_entries),
                fx.committees.clone(),
                OcsMetrics::new_for_testing(),
                None,
                cache.clone(),
                true,
                Some(100),
            )
        };
        // The mirrored peer's changeset index covers only checkpoint 90, so
        // its window no longer brackets the entry's checkpoint 42.
        let index = {
            let anchor = Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(0xAA),
                SequenceNumber::from(1u64),
                Owner::AddressOwner(ObjectID::from_single_byte(0x01).into()),
            );
            let (id, version, digest) = anchor.compute_object_reference();
            let states = BTreeMap::from([(id, (version, digest))]);
            let summary = signed_summary_with_commitment(
                &fx.committee,
                &fx.keys,
                90,
                CheckpointArtifacts::from_object_states(states.clone())
                    .digest()
                    .unwrap()
                    .into(),
            );
            let mut index = ChangesetIndex::new();
            index.absorb(&summary, states).unwrap();
            Arc::new(RwLock::new(index))
        };
        let mirrored_reader = OcsVerifiedReader::new(
            Arc::new(OverTheWire(provider(false))),
            fx.committees.clone(),
            OcsMetrics::new_for_testing(),
            None,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        )
        .with_changeset_index(Some(index));

        let page_ids = |page: VerifiedDynamicFieldsPage| -> Vec<ObjectID> {
            page.entries.iter().map(|e| e.object.id()).collect()
        };

        // Before the backfill nobody can prove the entry.
        let direct = direct_reader(false)
            .verified_dynamic_fields_page(bag, None, None)
            .await
            .unwrap();
        assert!(page_ids(direct).is_empty());
        let mirrored = mirrored_reader
            .verified_dynamic_fields_page(bag, None, None)
            .await
            .unwrap();
        assert!(page_ids(mirrored).is_empty());

        tick_backfill(&mut pusher).await;
        assert_eq!(cache.snapshots_from_checkpoint(42), 1);

        let direct = direct_reader(false)
            .verified_dynamic_fields_page(bag, None, None)
            .await
            .unwrap();
        assert_eq!(page_ids(direct), vec![entry.id()]);
        let mirrored = mirrored_reader
            .verified_dynamic_fields_page(bag, None, None)
            .await
            .unwrap();
        assert_eq!(mirrored.entries.len(), 1);
        assert_eq!(
            mirrored.entries[0].object.compute_object_reference(),
            entry.compute_object_reference()
        );
        assert_eq!(mirrored.entries[0].source_checkpoint_seq, 42);

        // The provider reports the entry only as skipped: the direct reader
        // resolves it from its verified cache.
        let direct = direct_reader(true)
            .verified_dynamic_fields_page(bag, None, None)
            .await
            .unwrap();
        assert_eq!(page_ids(direct), vec![entry.id()]);
    }
}
