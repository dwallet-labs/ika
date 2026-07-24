// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Consumer-facing verified-read surface.
//!
//! [`OcsVerifiedReader`] wraps a [`ProofProvider`] (local or remote-anemo)
//! and bolts on the three checks we need to safely consume Ika objects
//! served from an untrusted relay:
//!
//! 1. Inclusion-proof verification against [`CommitteeStore`].
//! 2. Per-object version monotonicity (rejects stale-state attacks).
//! 3. Optional freshness bound (proof seq vs relay's claimed head).
//!
//! Dynamic-field pages additionally bind each child to the requested parent
//! collection via its proof-bound owner (a plain field is owned by the
//! collection UID; an object-field value by its `Field` wrapper). Omission
//! detection is left to the consumer, which compares the listed count against
//! the collection `size` it reads from verified parent state.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use sui_light_client::proof::base::{
    Proof, ProofContents, ProofContentsVerifier, ProofTarget, ProofVerifier,
};
use sui_light_client::proof::ocs::{OCSInclusionProof, OCSProof};
use sui_types::base_types::{ObjectID, SequenceNumber};
use sui_types::dynamic_field::Field;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointSequenceNumber, VerifiedCheckpoint,
};
use sui_types::object::Object;

use ika_sui_client::transport::{TransportError, dynamic_field_child_owned_by};

use ika_network::proof_provider::{
    ProofProvider, VerifiedDynamicFieldsPageRequest, VerifiedObjectResponse,
};

use ika_types::sui::system_inner_v1::{DWalletCoordinatorInnerV1, SystemInnerV1};
use ika_types::sui::{DWalletCoordinator, DWalletCoordinatorInner, System, SystemInner};

use crate::sui_connector::changeset_receiver::SharedChangesetIndex;
use crate::sui_connector::committee_store::{CommitteeStore, SummaryVerifyError};
use crate::sui_connector::ocs_currency::CurrencyVerdict;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;
use ika_network::proof_provider::VerifiedObjectEntry;
use tracing::warn;

/// Hard ceiling on dynamic-field entries the reader will accept from one relay
/// page, used when the caller didn't pin a `page_size`. Comfortably above the
/// serving side's own clamp (`MAX_DYNAMIC_FIELDS_PAGE_SIZE` = 1000 in
/// `ika-network`) so a legitimate full page passes, but bounds a byzantine peer
/// that ignores its own cap and over-stuffs the response.
const MAX_VERIFIED_PAGE_ENTRIES: usize = 1024;

/// How long the singleton-anchor cache-first read may serve a snapshot before it
/// forces a verified network re-read to re-confirm it. Bounds anchor staleness
/// so an anchor whose update the pusher skipped (a pruned checkpoint, never
/// re-folded for a rare singleton like the system inner) can't be served stale
/// indefinitely and wedge the epoch (#1736). Kept well above the executor's
/// ~120ms anchor poll so the cache absorbs the vast majority of reads — at most
/// one network re-read per anchor per interval, far below the per-tick reach-back
/// rate that the cache-first anchor path exists to avoid.
const ANCHOR_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(thiserror::Error, Debug)]
pub enum ReaderError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("proof verify: {0}")]
    InvalidProof(String),
    #[error("missing committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("stale: object {id} version {got:?} < high-water {cached:?}")]
    StaleVersion {
        id: ObjectID,
        got: SequenceNumber,
        cached: SequenceNumber,
    },
    #[error(
        "stale: proof at checkpoint {object_seq} is {gap} behind claimed head \
         {head}, bound {bound}"
    )]
    StaleCheckpoint {
        object_seq: CheckpointSequenceNumber,
        head: CheckpointSequenceNumber,
        gap: u64,
        bound: u64,
    },
    #[error("decode: {0}")]
    Decode(String),
    #[error("relay returned {got} dynamic-field entries, over the {allowed} requested/allowed")]
    OverlongPage { got: usize, allowed: usize },
    #[error("unsupported version {kind}={version}")]
    UnsupportedVersion { kind: &'static str, version: u64 },
    #[error(
        "dynamic-field membership: entry {entry} in a page for parent {parent_id} is owned by \
         {owner} — not a dynamic-field child of the requested collection"
    )]
    DynamicFieldMembership {
        parent_id: ObjectID,
        entry: ObjectID,
        owner: String,
    },
    #[error(
        "not current: object {id} authenticated at checkpoint {anchored_seq} is {verdict} per the \
         committee-signed changeset stream"
    )]
    NotCurrent {
        id: ObjectID,
        anchored_seq: CheckpointSequenceNumber,
        verdict: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct VerifiedObject {
    pub object: Object,
    pub source_checkpoint_seq: CheckpointSequenceNumber,
}

#[derive(Debug)]
pub struct VerifiedDynamicFieldsPage {
    pub entries: Vec<VerifiedObject>,
    pub next_page_token: Option<Vec<u8>>,
}

pub struct OcsVerifiedReader {
    provider: Arc<dyn ProofProvider>,
    committees: Arc<CommitteeStore>,
    metrics: Arc<OcsMetrics>,
    /// Per well-known object id, the highest version we've ever accepted.
    /// Bag-entry children are intentionally *not* tracked — their ids are
    /// short-lived (dynamic fields), so tracking would just leak memory.
    high_water: RwLock<HashMap<ObjectID, SequenceNumber>>,
    /// Skipped bag children (pruned defining checkpoint) that failed even
    /// the cache-fallback resolution and were already warned about — a
    /// permanent hole recurs on every pump walk, so the warn fires once per
    /// id and clears if the id later resolves. Bounded like the ids
    /// themselves: entries leave the bag (and stop being listed) when their
    /// session completes.
    warned_unresolvable_children: RwLock<HashSet<ObjectID>>,
    /// Reject any proof whose checkpoint is more than this many behind the
    /// provider's claimed head. None disables the bound.
    freshness_bound: Option<u64>,
    /// Verified-state cache. Always shadow-populated on the network path.
    /// When `cache_first` is set we also *serve* `verified_object` reads
    /// from it (see [`Self::try_cache_hit`]).
    cache: SharedVerifiedStateCache,
    /// Serve `verified_object` from `cache` before hitting the network.
    /// Sound only where the cache is complete and contiguous — i.e. on
    /// sui-state-direct, where the local `IkaCheckpointPusher` folds every
    /// Ika-modified object of every checkpoint, in order, into the cache.
    /// Left off on sui-state-mirrored: that cache is a read-through memo of
    /// an untrusted relay and can lag arbitrarily, so reads must stay on
    /// the (per-read verified) relay path.
    cache_first: bool,
    /// Highest upstream checkpoint seq we've observed from a provider response
    /// (`claimed_latest_checkpoint_seq`). Updated on every network read /
    /// dynamic-field walk — and those walks run every pump tick independently of the pusher —
    /// so this stays fresh even if the pusher stalls. Used by the cache-first
    /// staleness tripwire below.
    observed_upstream_head: AtomicU64,
    /// Cache-first staleness tripwire: if the cache head lags
    /// `observed_upstream_head` by more than this many checkpoints, the cache
    /// is too stale (e.g. a stalled pusher), so `try_cache_hit` falls through
    /// to the network instead of serving frozen state. `None` disables it.
    staleness_bound: Option<u64>,
    /// Per-singleton-anchor wall-clock of the last verified network re-read.
    /// `verified_anchor_object` serves the cached snapshot only while the last
    /// refresh is within `ANCHOR_REFRESH_INTERVAL`; past that it forces a network
    /// re-read so a stale anchor (an update the pusher skipped, never re-folded)
    /// can't be served indefinitely (#1736).
    anchor_refreshed_at: Mutex<HashMap<ObjectID, Instant>>,
    /// Committee-signed changeset index, on a mirrored / peer-only node. When
    /// present, a verified read additionally proves *currency* against it: the
    /// inclusion proof authenticates `X@V` at its last-modifying checkpoint `M`,
    /// and this index says whether `M` is still `X`'s latest version. `None` on
    /// sui-state-direct (its cache is already a complete, contiguous fold) and
    /// before the changeset receiver is wired — currency then falls back to the
    /// per-read high-water + freshness defenses.
    changeset_index: Option<SharedChangesetIndex>,
}

impl OcsVerifiedReader {
    pub fn new(
        provider: Arc<dyn ProofProvider>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
        freshness_bound: Option<u64>,
        cache: SharedVerifiedStateCache,
        cache_first: bool,
        staleness_bound: Option<u64>,
    ) -> Self {
        Self {
            provider,
            committees,
            metrics,
            high_water: RwLock::new(HashMap::new()),
            warned_unresolvable_children: RwLock::new(HashSet::new()),
            freshness_bound,
            cache,
            cache_first,
            observed_upstream_head: AtomicU64::new(0),
            staleness_bound,
            anchor_refreshed_at: Mutex::new(HashMap::new()),
            changeset_index: None,
        }
    }

    /// Attach a changeset index (a mirrored / peer-only node) so verified reads
    /// also enforce currency. Builder: `None` leaves the reader on the per-read
    /// defenses, which is the direct-node default.
    pub fn with_changeset_index(mut self, changeset_index: Option<SharedChangesetIndex>) -> Self {
        self.changeset_index = changeset_index;
        self
    }

    /// Fold a provider-reported upstream head into `observed_upstream_head`
    /// (monotonic). Called on every network read so the cache-first staleness
    /// tripwire has a fresh reference even when cache-first short-circuits.
    fn note_upstream_head(&self, seq: CheckpointSequenceNumber) {
        self.observed_upstream_head
            .fetch_max(seq, Ordering::Relaxed);
    }

    pub async fn verified_object(&self, id: ObjectID) -> Result<VerifiedObject, ReaderError> {
        let started = std::time::Instant::now();
        if self.cache_first
            && let Some(hit) = self.try_cache_hit(id)
        {
            self.observe_verify_latency("object_cache_hit", started);
            return Ok(hit);
        }
        self.verified_object_over_network(id, started).await
    }

    /// The network half of [`Self::verified_object`]: pull + verify from the
    /// provider with no cache-first short-circuit (a `NotFound` still falls back
    /// to the cached snapshot on a direct node). [`Self::verified_anchor_object`]
    /// calls this directly to force a refresh past `try_cache_hit`.
    async fn verified_object_over_network(
        &self,
        id: ObjectID,
        started: Instant,
    ) -> Result<VerifiedObject, ReaderError> {
        let resp = match self.provider.verified_object(id).await {
            Ok(resp) => resp,
            // The network reach-back failed because the object's defining
            // transaction was pruned upstream. Serve the committee-verified
            // snapshot the pusher last folded instead of wedging: it is
            // post-verification state, and high-water still rejects a rollback.
            // This is the object-read analogue of the committee follower — a
            // locally populated cache that doesn't depend on prune-prone
            // reach-backs. Direct nodes only (the cache is our own verified
            // state, not an untrusted relay memo). Accepts a slightly-stale (but
            // verified, monotonic) anchor when the pusher is behind — strictly
            // better than the alternative, which is the executor wedging forever.
            Err(TransportError::NotFound(reason)) if self.cache_first => {
                if let Some(hit) = self.cache_fallback(id) {
                    self.metrics
                        .cache_read_total
                        .with_label_values(&["fallback"])
                        .inc();
                    warn!(
                        ?id,
                        reason,
                        "verified read: upstream pruned the object's defining tx; \
                         served the committee-verified cached snapshot (pusher behind)"
                    );
                    self.observe_verify_latency("object_cache_fallback", started);
                    return Ok(hit);
                }
                return Err(ReaderError::Transport(TransportError::NotFound(reason)));
            }
            Err(e) => return Err(e.into()),
        };
        let result = self.verify_response(id, resp);
        self.record_verify_outcome("object", &result);
        self.observe_verify_latency("object", started);
        result
    }

    /// Hot-path read for the singleton System / DWalletCoordinator inner anchors,
    /// which the executor polls every ~120ms and which change only on the order
    /// of epoch boundaries. Serve the committee-verified cached snapshot whenever
    /// it is present — bypassing the cache-staleness tripwire — so that under
    /// load (the pusher lagging past the tripwire bound) these reads don't reach
    /// back to the fullnode every tick. That per-tick reach-back is itself what
    /// slows the pusher further and latches the tripwire: a feedback loop that
    /// throttles dwallet advancement (the heaviest integration file). `high_water`
    /// still rejects a rollback, so only a stale-BUT-monotonic anchor is served;
    /// a genuine cache miss (or a high-water rejection — a newer version was
    /// already served) falls through to the verified network path. Both roles
    /// serve here: a direct node from its fold-backed always-cache; a mirror
    /// node from its shadow cache, but only when the committee-signed changeset
    /// index confirms the cached version is still current (see
    /// [`Self::anchor_cache_hit`]).
    async fn verified_anchor_object(&self, id: ObjectID) -> Result<VerifiedObject, ReaderError> {
        // Serve the committee-verified cached snapshot, but only while it is
        // within `ANCHOR_REFRESH_INTERVAL` of its last verified network re-read.
        // Past that, force a network re-read (below): a rare singleton like the
        // system inner whose update the pusher skipped past a pruned checkpoint
        // is never re-folded, so without this bound the stale snapshot would be
        // served forever and wedge the epoch (#1736). The interval keeps this off
        // the hot path — the ~120ms executor polls serve cache between refreshes —
        // so it can't relatch the per-tick reach-back feedback loop the
        // cache-first anchor path exists to avoid. The same interval is the
        // mirror path's safety bound: a stalled changeset stream that freezes
        // `currency` at `Current` still gets a forced verified re-read every
        // interval, so it can never serve a stale anchor indefinitely.
        if !self.anchor_refresh_due(id)
            && let Some((hit, label)) = self.anchor_cache_hit(id)
        {
            self.metrics
                .cache_read_total
                .with_label_values(&[label])
                .inc();
            return Ok(hit);
        }
        // Refresh due, cache miss, or mirror node: take the verified network path
        // DIRECTLY (not `verified_object`, whose `try_cache_hit` would just
        // re-serve the same stale snapshot — its tripwire keys off the pusher's
        // processed head, which stays current even when one anchor update was
        // skipped). On success, stamp the refresh so subsequent reads serve cache.
        let result = self.verified_object_over_network(id, Instant::now()).await;
        if result.is_ok() {
            self.anchor_refreshed_at.lock().insert(id, Instant::now());
        }
        result
    }

    /// Anchor cache hit for whichever node role has one (with its metric label);
    /// `None` forces the verified network read.
    ///
    /// - **Direct** (`cache_first`): the fold-backed always-cache
    ///   ([`Self::cache_fallback`]). The local pusher fold is authoritative, so
    ///   `high_water` monotonicity is the only extra gate.
    /// - **Mirror** (a changeset index is wired): the shadow cache, served only
    ///   on a *positive* currency confirmation — the committee-signed changeset
    ///   index says the cached version is still the id's latest (`Current`).
    ///   `Unknown` (the index can't vouch: anchor outside the folded range),
    ///   `Stale`/`NotLive`, or an empty shadow cache all return `None` and fall
    ///   through to the per-read-verified network path. Bounded staleness comes
    ///   from the caller's `ANCHOR_REFRESH_INTERVAL` re-read, not currency alone:
    ///   `Current` only proves "unchanged up to the changeset index's contiguous
    ///   head," which can lag the relay head, so a positive verdict is necessary
    ///   but not sufficient — the interval re-read is what caps the gap.
    fn anchor_cache_hit(&self, id: ObjectID) -> Option<(VerifiedObject, &'static str)> {
        if self.cache_first {
            return self.cache_fallback(id).map(|hit| (hit, "anchor"));
        }
        let index = self.changeset_index.as_ref()?;
        // `cache_fallback` records high-water; on a non-`Current` verdict below
        // that is a monotonic no-op (the shadow version was already served on a
        // prior read), so reusing it before the currency gate is harmless.
        let hit = self.cache_fallback(id)?;
        match index.read().currency(id, hit.source_checkpoint_seq) {
            CurrencyVerdict::Current => Some((hit, "mirror_anchor")),
            _ => None,
        }
    }

    /// Whether the cached anchor `id` is due for a forced verified network
    /// re-read. The first sight of an anchor starts its clock and is NOT due (so
    /// the cache is served immediately, never reaching the network on a fresh
    /// cache); thereafter it is due once `ANCHOR_REFRESH_INTERVAL` elapses since
    /// the last refresh.
    fn anchor_refresh_due(&self, id: ObjectID) -> bool {
        let mut refreshed_at = self.anchor_refreshed_at.lock();
        match refreshed_at.get(&id) {
            Some(at) => at.elapsed() >= ANCHOR_REFRESH_INTERVAL,
            None => {
                refreshed_at.insert(id, Instant::now());
                false
            }
        }
    }

    /// Batch counterpart of [`Self::verified_object`]: one provider
    /// round-trip for all `ids`, then the same per-object guarantees —
    /// freshness against the monotonic observed head, inclusion proof
    /// against a BLS-verified summary (verified once per distinct
    /// checkpoint, as in [`Self::verified_dynamic_fields_page`]), high-water version
    /// tracking, and cache shadow-population. Errors if any id is missing
    /// from the response: callers ask for objects that must exist (e.g.
    /// the validator set), so a hole is a failed read, not an empty slot.
    pub async fn verified_objects(
        &self,
        ids: &[ObjectID],
    ) -> Result<Vec<VerifiedObject>, ReaderError> {
        let started = std::time::Instant::now();
        let resp = self.provider.batch_verified_objects(ids).await?;
        self.note_upstream_head(resp.claimed_latest_checkpoint_seq);
        let observed_head = self.observed_upstream_head.load(Ordering::Relaxed);

        // A short results vec from a malicious/faulty relay must not silently
        // truncate via `zip`: the trailing ids would never get their per-slot
        // NotFound + id-binding checks, and the function would return a partial
        // set as `Ok`. Require exactly one slot per requested id up front.
        if resp.results.len() != ids.len() {
            return Err(self.record_fail(
                "batch_objects",
                ReaderError::Transport(TransportError::NotFound(format!(
                    "batch response has {} slots for {} requested ids",
                    resp.results.len(),
                    ids.len()
                ))),
            ));
        }

        let mut verified_summaries: HashMap<CheckpointSequenceNumber, VerifiedCheckpoint> =
            HashMap::new();
        let mut out = Vec::with_capacity(ids.len());
        for (id, slot) in ids.iter().zip(resp.results) {
            let entry = slot.ok_or_else(|| {
                ReaderError::Transport(TransportError::NotFound(format!(
                    "object {id} missing from batch response"
                )))
            })?;
            if entry.object.id() != *id {
                let entry_result: Result<(), ReaderError> =
                    Err(ReaderError::InvalidProof(format!(
                        "batch response slot for {id} carries object {}",
                        entry.object.id()
                    )));
                self.record_verify_outcome_unit("batch_objects", &entry_result);
                entry_result?;
            }
            let seq = entry.checkpoint_seq;
            self.check_freshness(seq, observed_head)
                .map_err(|e| self.record_fail("batch_objects", e))?;
            // Verify each distinct checkpoint's summary once, then reuse it.
            let verified_summary = match verified_summaries.entry(seq) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    let summary = resp
                        .summaries
                        .get(&seq)
                        .ok_or_else(|| {
                            self.record_fail(
                                "batch_objects",
                                ReaderError::Decode(format!(
                                    "missing summary {seq} for batch entry {id}"
                                )),
                            )
                        })?
                        .clone();
                    let verified_summary = self
                        .verify_summary(summary)
                        .map_err(|e| self.record_fail("batch_objects", e))?;
                    e.insert(verified_summary)
                }
            };

            let cache_proof = clone_inclusion_proof(&entry.proof);
            let cache_object = entry.object.clone();
            let entry_result =
                self.verify_ocs_inclusion(&entry.object, entry.proof, verified_summary);
            self.record_verify_outcome_unit("batch_objects", &entry_result);
            entry_result?;
            self.check_currency(entry.object.id(), seq)
                .map_err(|e| self.record_fail("batch_objects", e))?;
            self.record_high_water(entry.object.id(), entry.object.version())
                .map_err(|e| self.record_fail("batch_objects", e))?;
            if let Some(proof) = cache_proof {
                let cache_summary = resp
                    .summaries
                    .get(&seq)
                    .expect("summary present for entry")
                    .clone();
                let cache_entry = VerifiedObjectEntry {
                    object: cache_object,
                    checkpoint_seq: seq,
                    proof,
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                };
                self.cache
                    .absorb_shadow_entries(&cache_summary, &[cache_entry]);
            }
            out.push(VerifiedObject {
                object: entry.object,
                source_checkpoint_seq: seq,
            });
        }
        self.observe_verify_latency("batch_objects", started);
        Ok(out)
    }

    /// Cache-first fast path for [`Self::verified_object`]. Returns `Some`
    /// only when the object is present in the locally pusher-populated
    /// cache and passes version-monotonicity. The cache only ever holds
    /// committee-verified state (folded post-verification by the pusher,
    /// push handler, or our own network reads), so we deliberately do
    /// *not* re-run the inclusion proof here — skipping that round-trip
    /// plus re-verify is the whole point. `None` means "fall through to
    /// the network": the object is absent, or a stale-version tripwire
    /// fired (the cached copy is older than one we've already served, so
    /// we re-fetch a fresh one).
    fn try_cache_hit(&self, id: ObjectID) -> Option<VerifiedObject> {
        // Staleness tripwire: if the populating worker has fallen too far behind
        // the observed upstream head (a genuinely stalled pusher), don't serve
        // frozen state — fall through to the per-read-verified network path.
        // This strictly *adds* verification, so there's no stale-read regression.
        //
        // Keyed off the worker's *processed* head, NOT the fold head: the fold
        // head only advances on Ika-relevant checkpoints, so a quiet stretch
        // with no Ika modifications would otherwise look like a stall and force
        // every read — including a still-current singleton anchor like the
        // system inner — onto the network path, where the anchor's defining
        // transaction may already be pruned (a permanent wedge). The processed
        // head keeps tracking the tip through quiet stretches, so the tripwire
        // fires only when the worker is actually behind.
        if let Some(bound) = self.staleness_bound {
            let upstream = self.observed_upstream_head.load(Ordering::Relaxed);
            let cache_head = self.cache.processed_head_seq();
            if upstream.saturating_sub(cache_head) > bound {
                self.metrics.cache_first_stale_total.inc();
                self.metrics
                    .cache_read_total
                    .with_label_values(&["miss"])
                    .inc();
                return None;
            }
        }
        let Some(snapshot) = self.cache.get(id) else {
            self.metrics
                .cache_read_total
                .with_label_values(&["miss"])
                .inc();
            return None;
        };
        let object_id = snapshot.object.id();
        let version = snapshot.object.version();
        match self.record_high_water(object_id, version) {
            Ok(()) => {
                self.metrics
                    .cache_read_total
                    .with_label_values(&["hit"])
                    .inc();
                Some(VerifiedObject {
                    object: snapshot.object,
                    source_checkpoint_seq: snapshot.source_checkpoint_seq,
                })
            }
            Err(_) => {
                self.metrics.high_water_violations_total.inc();
                self.metrics
                    .cache_read_total
                    .with_label_values(&["miss"])
                    .inc();
                None
            }
        }
    }

    /// Last-resort cache read for when the network reach-back failed because the
    /// object's defining transaction was pruned upstream. Unlike
    /// [`Self::try_cache_hit`] it does NOT consult the staleness tripwire — the
    /// pusher being behind is exactly the situation here — but it still enforces
    /// version-monotonicity, so it can only ever serve forward, never roll back.
    /// The snapshot is committee-verified (folded post-verification), so serving
    /// it adds no trust; it can be stale, which is the accepted trade for not
    /// wedging the executor when upstream has pruned the anchor's history.
    fn cache_fallback(&self, id: ObjectID) -> Option<VerifiedObject> {
        let snapshot = self.cache.get(id)?;
        let object_id = snapshot.object.id();
        let version = snapshot.object.version();
        self.record_high_water(object_id, version).ok()?;
        Some(VerifiedObject {
            object: snapshot.object,
            source_checkpoint_seq: snapshot.source_checkpoint_seq,
        })
    }

    pub async fn verified_dynamic_fields_page(
        &self,
        parent_id: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<VerifiedDynamicFieldsPage, ReaderError> {
        let started = std::time::Instant::now();
        let resp = self
            .provider
            .verified_dynamic_fields_page(VerifiedDynamicFieldsPageRequest {
                parent_id,
                page_size,
                page_token,
            })
            .await?;
        // Bound the response length BEFORE allocating / verifying. The serving
        // side clamps page size, but a byzantine peer can ignore its own cap, so
        // the consumer independently rejects an over-long page — capping both the
        // `Vec::with_capacity` and the O(entries) BLS/Merkle verify work below.
        // Accept at most what we asked for, and never more than the hard ceiling
        // (covers a `None` request where the server picks the size).
        let allowed = page_size
            .map(|n| (n as usize).min(MAX_VERIFIED_PAGE_ENTRIES))
            .unwrap_or(MAX_VERIFIED_PAGE_ENTRIES);
        if resp.entries.len() > allowed {
            return Err(self.record_fail(
                "dynamic_field_entry",
                ReaderError::OverlongPage {
                    got: resp.entries.len(),
                    allowed,
                },
            ));
        }
        let head = resp.claimed_latest_checkpoint_seq;
        self.note_upstream_head(head);

        // No freshness bound on dynamic-field entries: a collection child
        // (e.g. a session event) can sit across many checkpoints, so its
        // proof's checkpoint seq legitimately lags far behind the relay's
        // head. The freshness bound applies to objects we expect to advance
        // frequently (coordinator/system); per-entry monotonicity protections
        // are out of scope here because these child ObjectIDs are short-lived.
        //
        // The parent collection object isn't fetchable (it's wrapped inside
        // its own parent struct), so we don't verify the collection itself
        // here. Omission detection lives in the consumer, which has the
        // expected collection `size` from a verified parent state and can
        // accumulate child counts across pages.
        let _ = head;
        let mut verified = Vec::with_capacity(resp.entries.len());
        // Per-summary BLS dedup: a page's entries usually all anchor to a
        // handful of checkpoints, and the committee BLS verify is the dominant
        // cost. The page's `summaries` map is 1:1 with checkpoint seq, so
        // verifying each distinct summary once (→ `VerifiedCheckpoint`) and
        // reusing it for every entry at that seq is safe — each entry still
        // gets its own Merkle/artifacts-digest check below. Drops BLS verifies
        // from O(entries) to O(distinct checkpoints).
        let mut verified_summaries: HashMap<CheckpointSequenceNumber, VerifiedCheckpoint> =
            HashMap::new();
        for entry in resp.entries {
            let seq = entry.checkpoint_seq;
            // Verify each distinct checkpoint's summary once, then reuse it.
            let verified_summary = match verified_summaries.entry(seq) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => {
                    let summary = resp
                        .summaries
                        .get(&seq)
                        .ok_or_else(|| {
                            self.record_fail(
                                "dynamic_field_entry",
                                ReaderError::Decode(
                                    "missing summary for dynamic-field entry".into(),
                                ),
                            )
                        })?
                        .clone();
                    let verified_summary = self
                        .verify_summary(summary)
                        .map_err(|e| self.record_fail("dynamic_field_entry", e))?;
                    e.insert(verified_summary)
                }
            };

            let cache_proof = clone_inclusion_proof(&entry.proof);
            let cache_object = entry.object.clone();
            // The cache stores `(object, proof, summary)`; reconstruct the
            // unverified summary from the page map for absorption.
            let cache_summary = resp
                .summaries
                .get(&seq)
                .expect("summary present for entry")
                .clone();
            let entry_result =
                self.verify_ocs_inclusion(&entry.object, entry.proof, verified_summary);
            self.record_verify_outcome_unit("dynamic_field_entry", &entry_result);
            entry_result?;
            // Bind the entry to the requested collection. The inclusion proof
            // above only attests that this object existed on-chain at a
            // verified checkpoint — NOT that it is a member of `parent_id`. The
            // binding is the entry's owner, which is part of the
            // proof-verified object digest, and depends on the collection
            // kind:
            //   - A plain `Bag`/`Table` stores the value inline in a
            //     `Field<K, V>` owned directly by the collection UID:
            //     `Owner::ObjectOwner(parent_id)`.
            //   - An `ObjectTable`/`ObjectBag` resolves to the wrapped value
            //     object, which is owned by its `Field<Wrapper<K>, ID>`
            //     wrapper, whose id is
            //     `derive_dynamic_field_id(parent_id, Wrapper<K>, key)`. The
            //     relay's key is untrusted, but the derivation is
            //     collision-resistant against the proven owner, so a relay
            //     cannot supply a name that derives to a *foreign* object's
            //     owner.
            // Without this a malicious relay could return a validly-proven
            // dynamic field of a *different* collection (e.g. replayed session
            // events), which the count-only omission detector wouldn't catch.
            let bound_to_collection = dynamic_field_child_owned_by(
                entry.object.owner(),
                parent_id,
                &entry.dynamic_field_name_type,
                &entry.dynamic_field_name_bcs,
            );
            if !bound_to_collection {
                return Err(self.record_fail(
                    "dynamic_field_entry",
                    ReaderError::DynamicFieldMembership {
                        parent_id,
                        entry: entry.object.id(),
                        owner: format!("{:?}", entry.object.owner()),
                    },
                ));
            }
            // Currency: reject a relay serving a stale or already-deleted dynamic-field
            // child (its id modified after this checkpoint). Out-of-range or
            // unindexed anchors fall back (`Unknown`), as for direct reads.
            self.check_currency(entry.object.id(), seq)
                .map_err(|e| self.record_fail("dynamic_field_entry", e))?;
            if let Some(proof) = cache_proof {
                let cache_entry = VerifiedObjectEntry {
                    object: cache_object,
                    checkpoint_seq: seq,
                    proof,
                    dynamic_field_name_type: String::new(),
                    dynamic_field_name_bcs: Vec::new(),
                };
                self.cache
                    .absorb_shadow_entries(&cache_summary, &[cache_entry]);
            }
            verified.push(VerifiedObject {
                object: entry.object,
                source_checkpoint_seq: seq,
            });
        }

        // Resolve children the provider LISTED but could not build proofs
        // for — their defining checkpoint was pruned upstream, which is
        // permanent, so without this they would silently vanish from every
        // page forever (observed: a session_events bag entry re-pulled
        // across an epoch boundary never reached the MPC manager and the
        // epoch-close gate pinned the epoch). `verified_object` carries its
        // own proof verification, currency check, and the committee-verified
        // cache fallback that serves exactly these pruned-defining-tx reads.
        // Trusted-listing only: on a mirrored node the relay's skipped ids
        // are untrusted (no membership binding is possible without a proof),
        // so they stay omitted there and the existing size-vs-listed
        // omission policing covers them.
        if self.cache_first {
            for id in &resp.skipped_entry_ids {
                match Box::pin(self.verified_object(*id)).await {
                    Ok(resolved) => {
                        // Bag-entry children are short-lived ids the
                        // high-water map intentionally does not track (see
                        // the field doc) — `verified_object` recorded one;
                        // drop it so per-child entries don't accumulate.
                        self.forget_high_water(id);
                        self.warned_unresolvable_children.write().remove(id);
                        verified.push(resolved);
                    }
                    Err(e) => {
                        // Once per id: a permanently unresolvable child
                        // recurs on every ~50ms pump walk until its session
                        // completes and the entry leaves the bag — warning
                        // each walk floods the log without adding signal.
                        if self.warned_unresolvable_children.write().insert(*id) {
                            warn!(
                                ?id,
                                error=?e,
                                "listed dynamic-field child with a pruned defining checkpoint \
                                 could not be resolved from the verified cache either"
                            );
                        }
                    }
                }
            }
        }

        self.observe_verify_latency("dynamic_fields_page", started);
        Ok(VerifiedDynamicFieldsPage {
            entries: verified,
            next_page_token: resp.next_page_token,
        })
    }

    pub fn forget_high_water(&self, id: &ObjectID) {
        self.high_water.write().remove(id);
    }

    /// Whether dynamic-field walks served by this reader come from an
    /// *untrusted relay*, so a consumer should police
    /// collection-`size`-vs-listed-children omission (a relay could hide
    /// entries). True on sui-state-mirrored.
    ///
    /// False on sui-state-direct (`cache_first`): there the pages come
    /// from the local trusted gRPC provider — nothing to omit — while the
    /// parent's collection `size` is served cache-first and therefore lags the
    /// (fresh) walk by up to the pusher's poll interval. A
    /// size-greater-than-listed mismatch there is an expected freshness
    /// artifact (entries removed on session completion), not misbehavior,
    /// so policing it would just cry wolf.
    pub fn relay_source_is_untrusted(&self) -> bool {
        !self.cache_first
    }

    fn record_verify_outcome<T>(&self, kind: &'static str, result: &Result<T, ReaderError>) {
        match result {
            Ok(_) => {
                self.metrics
                    .proof_verify_total
                    .with_label_values(&[kind])
                    .inc();
            }
            Err(e) => self.record_verify_failure(kind, e),
        }
    }

    /// Count one verify failure under `(kind, reason)`, plus the high-water
    /// violation gauge for a stale version.
    fn record_verify_failure(&self, kind: &'static str, e: &ReaderError) {
        let reason = classify_verify_error(e);
        self.metrics
            .proof_verify_failures_total
            .with_label_values(&[kind, reason])
            .inc();
        if matches!(e, ReaderError::StaleVersion { .. }) {
            self.metrics.high_water_violations_total.inc();
        }
    }

    fn record_verify_outcome_unit(&self, kind: &'static str, result: &Result<(), ReaderError>) {
        self.record_verify_outcome(kind, result);
    }

    /// Record a verify failure under `kind` (lands in
    /// `proof_verify_failures_total`, and `high_water_violations_total` for a
    /// stale version) and return it. For failure points on the batch/dynamic-field
    /// paths that would otherwise `?`-propagate or return *around* the
    /// per-entry [`Self::record_verify_outcome`] — the summary BLS verify, the
    /// missing-summary decode, the freshness/high-water checks, and the
    /// dynamic-field-membership binding — so no verified-read failure mode is silent.
    fn record_fail(&self, kind: &'static str, e: ReaderError) -> ReaderError {
        self.record_verify_failure(kind, &e);
        e
    }

    fn observe_verify_latency(&self, kind: &'static str, started: std::time::Instant) {
        self.metrics
            .verify_latency_seconds
            .with_label_values(&[kind])
            .observe(started.elapsed().as_secs_f64());
    }

    /// OCS-verified read of the `DWalletCoordinator` outer + its versioned
    /// inner. Outer carries a `u64 version` field; the actual data lives
    /// at `Field<u64, DWalletCoordinatorInnerV1>` whose object id is
    /// derived deterministically from `(coordinator_id, version)` — we
    /// never trust a relayer's listing for which child backs a given
    /// version.
    pub async fn verified_dwallet_coordinator_inner(
        &self,
        coordinator_id: ObjectID,
    ) -> Result<(DWalletCoordinator, DWalletCoordinatorInner), ReaderError> {
        let outer_obj = self.verified_anchor_object(coordinator_id).await?;
        let outer_bcs = move_object_contents(&outer_obj.object)?;
        let outer: DWalletCoordinator = bcs::from_bytes(outer_bcs)
            .map_err(|e| ReaderError::Decode(format!("DWalletCoordinator: {e}")))?;

        match outer.version {
            1 | 2 => {
                let child_id = derive_versioned_child_id(coordinator_id, outer.version)?;
                let child_obj = self.verified_anchor_object(child_id).await?;
                let child_bcs = move_object_contents(&child_obj.object)?;
                let field: Field<u64, DWalletCoordinatorInnerV1> = bcs::from_bytes(child_bcs)
                    .map_err(|e| {
                        ReaderError::Decode(format!("Field<u64, DWalletCoordinatorInnerV1>: {e}"))
                    })?;
                Ok((outer, DWalletCoordinatorInner::V1(field.value)))
            }
            v => Err(ReaderError::UnsupportedVersion {
                kind: "DWalletCoordinator",
                version: v,
            }),
        }
    }

    /// OCS-verified read of the `System` outer + its versioned inner.
    /// Same versioned-dynamic-field pattern as
    /// [`Self::verified_dwallet_coordinator_inner`].
    pub async fn verified_system_inner(
        &self,
        system_id: ObjectID,
    ) -> Result<(System, SystemInner), ReaderError> {
        let outer_obj = self.verified_anchor_object(system_id).await?;
        let outer_bcs = move_object_contents(&outer_obj.object)?;
        let outer: System =
            bcs::from_bytes(outer_bcs).map_err(|e| ReaderError::Decode(format!("System: {e}")))?;

        match outer.version {
            1 | 2 => {
                let child_id = derive_versioned_child_id(system_id, outer.version)?;
                let child_obj = self.verified_anchor_object(child_id).await?;
                let child_bcs = move_object_contents(&child_obj.object)?;
                let field: Field<u64, SystemInnerV1> = bcs::from_bytes(child_bcs)
                    .map_err(|e| ReaderError::Decode(format!("Field<u64, SystemInnerV1>: {e}")))?;
                Ok((outer, SystemInner::V1(field.value)))
            }
            v => Err(ReaderError::UnsupportedVersion {
                kind: "System",
                version: v,
            }),
        }
    }

    fn verify_response(
        &self,
        requested_id: ObjectID,
        resp: VerifiedObjectResponse,
    ) -> Result<VerifiedObject, ReaderError> {
        // Bind the response to the request: the inclusion proof attests that
        // the returned object existed on-chain, NOT that it is the object we
        // asked for. Without this a malicious relay could answer `get(X)` with
        // any other validly-proven object `Y`. (The batch path does the same
        // per-entry check.)
        if resp.object.id() != requested_id {
            return Err(ReaderError::InvalidProof(format!(
                "verified_object response for {requested_id} carries object {}",
                resp.object.id()
            )));
        }
        let proof_seq = *resp.summary.sequence_number();
        self.note_upstream_head(resp.claimed_latest_checkpoint_seq);
        // Freshness is measured against the locally-monotonic observed head,
        // not the response's claimed head: the claimed head is the relay's
        // word, so a malicious relay could under-report it to make a stale
        // proof look fresh. `observed_upstream_head` only ratchets up
        // (fetch_max in `note_upstream_head`), so once any response has shown
        // a newer head, no later response can talk us back below it.
        let observed_head = self.observed_upstream_head.load(Ordering::Relaxed);
        self.check_freshness(proof_seq, observed_head)?;
        // Clone the proof + summary for cache absorption before the
        // verifier consumes them. The proof isn't `Clone`; bcs round-trip.
        let cache_proof = clone_inclusion_proof(&resp.proof);
        let cache_summary = resp.summary.clone();
        let cache_object = resp.object.clone();
        self.verify_proof_inner(&resp.object, resp.proof, resp.summary)?;
        // The proof authenticates `X@V` at its last-modifying checkpoint
        // `proof_seq` — existence, not currency. If a changeset index is wired,
        // prove `proof_seq` is still `X`'s latest version (catches a relay
        // serving a validly-signed-but-rolled-back version that high-water
        // alone can't, since the version never decreased on this node).
        self.check_currency(resp.object.id(), proof_seq)?;
        self.record_high_water(resp.object.id(), resp.object.version())?;
        // Shadow-populate the cache with the just-verified entry. Step 2
        // only writes; readers still hit the network.
        if let Some(proof) = cache_proof {
            let entry = VerifiedObjectEntry {
                object: cache_object,
                checkpoint_seq: proof_seq,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            };
            self.cache.absorb_shadow_entries(&cache_summary, &[entry]);
        }
        Ok(VerifiedObject {
            object: resp.object,
            source_checkpoint_seq: proof_seq,
        })
    }

    /// Currency gate: with a changeset index wired, reject an object whose
    /// authenticating checkpoint `anchored_seq` is no longer its latest. With
    /// no index — direct nodes, or before the receiver has caught up — this is
    /// a no-op and currency rests on the per-read high-water + freshness
    /// defenses. `Unknown` (the anchor is outside the folded range) also falls
    /// back, never rejecting: the index simply can't speak to it yet.
    fn check_currency(
        &self,
        id: ObjectID,
        anchored_seq: CheckpointSequenceNumber,
    ) -> Result<(), ReaderError> {
        let Some(index) = &self.changeset_index else {
            return Ok(());
        };
        let verdict = index.read().currency(id, anchored_seq);
        match verdict {
            CurrencyVerdict::Current | CurrencyVerdict::Unknown => Ok(()),
            CurrencyVerdict::Stale => Err(ReaderError::NotCurrent {
                id,
                anchored_seq,
                verdict: "stale (modified after this checkpoint)",
            }),
            CurrencyVerdict::NotLive => Err(ReaderError::NotCurrent {
                id,
                anchored_seq,
                verdict: "deleted/wrapped at this checkpoint",
            }),
        }
    }

    fn verify_proof_inner(
        &self,
        object: &Object,
        proof: OCSInclusionProof,
        summary: CertifiedCheckpointSummary,
    ) -> Result<(), ReaderError> {
        let epoch = summary.epoch();
        let committee = self
            .committees
            .committee(epoch)
            .ok_or(ReaderError::MissingCommittee(epoch))?;
        let object_ref = object.compute_object_reference();
        let full_proof = Proof {
            targets: ProofTarget::new_ocs_inclusion(object_ref),
            checkpoint_summary: summary,
            proof_contents: ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof)),
        };
        full_proof
            .verify(&committee)
            .map_err(|e| ReaderError::InvalidProof(format!("{e:?}")))
    }

    /// BLS-verify a checkpoint summary against its epoch committee, yielding a
    /// [`VerifiedCheckpoint`] that the per-entry inclusion check below reuses.
    /// This is the deduped first half of [`Self::verify_proof_inner`].
    fn verify_summary(
        &self,
        summary: CertifiedCheckpointSummary,
    ) -> Result<VerifiedCheckpoint, ReaderError> {
        self.committees
            .verify_summary(summary)
            .map_err(|e| match e {
                SummaryVerifyError::MissingCommittee(epoch) => ReaderError::MissingCommittee(epoch),
                bad @ SummaryVerifyError::BadSignature { .. } => {
                    ReaderError::InvalidProof(bad.to_string())
                }
            })
    }

    /// Verify one object's OCS inclusion proof (Merkle path + artifacts-digest
    /// binding) against an already-BLS-verified summary. Cheap relative to the
    /// BLS verify, so it stays per-entry; pairs with [`Self::verify_summary`].
    fn verify_ocs_inclusion(
        &self,
        object: &Object,
        proof: OCSInclusionProof,
        verified_summary: &VerifiedCheckpoint,
    ) -> Result<(), ReaderError> {
        let object_ref = object.compute_object_reference();
        ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof))
            .verify(
                &ProofTarget::new_ocs_inclusion(object_ref),
                verified_summary,
            )
            .map_err(|e| ReaderError::InvalidProof(format!("{e:?}")))
    }

    // Eclipse residual: `head` is the relay's *claimed* upstream head (folded
    // monotonically into `observed_upstream_head`). A fresh peer-only node
    // talking to a single malicious relay can be pinned to a self-consistent
    // stale world — the relay simply under-reports the head so nothing looks
    // stale. The bound below catches a relay that *later* lies low after a
    // higher head was seen, not a from-boot eclipse. Mitigations: an enabled
    // `freshness_bound` and/or multiple independent relays; the real fix is the
    // changeset-stream currency design. See `dev-docs/specs/ocs-verified-sui-reads.md`
    // (Freshness and rollback protection → Eclipse residual).
    fn check_freshness(
        &self,
        proof_seq: CheckpointSequenceNumber,
        head: CheckpointSequenceNumber,
    ) -> Result<(), ReaderError> {
        let Some(bound) = self.freshness_bound else {
            return Ok(());
        };
        let gap = head.saturating_sub(proof_seq);
        if gap > bound {
            return Err(ReaderError::StaleCheckpoint {
                object_seq: proof_seq,
                head,
                gap,
                bound,
            });
        }
        Ok(())
    }

    fn record_high_water(&self, id: ObjectID, version: SequenceNumber) -> Result<(), ReaderError> {
        let mut hw = self.high_water.write();
        if let Some(&cached) = hw.get(&id)
            && version < cached
        {
            return Err(ReaderError::StaleVersion {
                id,
                got: version,
                cached,
            });
        }
        hw.insert(id, version);
        Ok(())
    }
}

fn classify_verify_error(e: &ReaderError) -> &'static str {
    match e {
        ReaderError::Transport(_) => "transport",
        ReaderError::InvalidProof(_) => "invalid_proof",
        ReaderError::MissingCommittee(_) => "missing_committee",
        ReaderError::StaleVersion { .. } => "stale_version",
        ReaderError::StaleCheckpoint { .. } => "stale_checkpoint",
        ReaderError::Decode(_) => "decode",
        ReaderError::OverlongPage { .. } => "overlong_page",
        ReaderError::UnsupportedVersion { .. } => "unsupported_version",
        ReaderError::DynamicFieldMembership { .. } => "dynamic_field_membership",
        ReaderError::NotCurrent { .. } => "not_current",
    }
}

fn move_object_contents(object: &Object) -> Result<&[u8], ReaderError> {
    ika_sui_client::transport::move_object_contents(object).ok_or_else(|| {
        ReaderError::Decode(format!(
            "expected Move object, got package at {}",
            object.id()
        ))
    })
}

/// Derive the dynamic-field child id for a `Field<u64, V>` whose name is
/// `version`. Used to walk from a versioned outer wrapper (e.g.
/// `DWalletCoordinator`) into its inner versioned data.
fn derive_versioned_child_id(parent: ObjectID, version: u64) -> Result<ObjectID, ReaderError> {
    ika_sui_client::transport::derive_versioned_child_id(parent, version)
        .map_err(ReaderError::Decode)
}

/// `OCSInclusionProof` isn't `Clone`. We need a copy so the verifier
/// can take ownership while we still hand the original to the cache.
/// Returns `None` if the round-trip fails — never poisons the cache
/// with bogus data.
fn clone_inclusion_proof(
    p: &sui_light_client::proof::ocs::OCSInclusionProof,
) -> Option<sui_light_client::proof::ocs::OCSInclusionProof> {
    let bytes = bcs::to_bytes(p).ok()?;
    bcs::from_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use crate::sui_connector::ocs_currency::ChangesetIndex;
    use crate::sui_connector::verified_state_cache::VerifiedStateCache;
    use async_trait::async_trait;
    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, VerifiedDynamicFieldsPageResponse,
    };
    use ika_sui_client::transport::derive_object_field_wrapper_id;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::ObjectDigest;
    use sui_types::committee::Committee as SuiCommittee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::{CheckpointContentsDigest, CheckpointDigest};
    use sui_types::gas::GasCostSummary;
    use sui_types::message_envelope::Message;
    use sui_types::messages_checkpoint::{
        CheckpointArtifacts, CheckpointCommitment, CheckpointSummary,
    };
    use sui_types::object::Owner;

    /// The two rejection gates exercised below — high-water rollback and
    /// freshness — are pure local checks that never reach the network, so the
    /// provider must never be called. Every method panics to prove that.
    struct UnusedProvider;

    #[async_trait]
    impl ProofProvider for UnusedProvider {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
        async fn verified_dynamic_fields_page(
            &self,
            _request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unreachable!("provider must not be hit by a local rejection test")
        }
    }

    /// A reader wired to a never-called provider and an empty cache. The
    /// committee is an unsafe-genesis test committee — irrelevant to the
    /// rollback/freshness gates, which touch neither committees nor the cache,
    /// but required to construct the store.
    fn test_reader(freshness_bound: Option<u64>) -> (tempfile::TempDir, OcsVerifiedReader) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let (committee, _keys) = SuiCommittee::new_simple_test_committee_of_size(4);
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee))).unwrap(),
        );
        let reader = OcsVerifiedReader::new(
            Arc::new(UnusedProvider),
            committees,
            OcsMetrics::new_for_testing(),
            freshness_bound,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        );
        (dir, reader)
    }

    /// A cache-first reader (sui-state-direct) with a staleness `bound`, an
    /// empty cache, and a never-called provider — for exercising the tripwire
    /// gate, which is a pure local check.
    fn test_reader_cache_first(bound: u64) -> (tempfile::TempDir, OcsVerifiedReader) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let (committee, _keys) = SuiCommittee::new_simple_test_committee_of_size(4);
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee))).unwrap(),
        );
        let reader = OcsVerifiedReader::new(
            Arc::new(UnusedProvider),
            committees,
            OcsMetrics::new_for_testing(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true,
            Some(bound),
        );
        (dir, reader)
    }

    /// The cache-staleness tripwire keys off the worker's *processed* head, not
    /// the fold head. During a quiet stretch the fold head stalls while the
    /// processed head keeps tracking the tip, so the tripwire stays closed and a
    /// still-current cached anchor is served — instead of forcing a reach-back
    /// that would hit the anchor's pruned defining transaction and wedge.
    /// (Here the cache is empty, so the read still misses — but the point is
    /// *why*: an absent-object miss, not a staleness trip.)
    #[tokio::test]
    async fn tripwire_keys_off_processed_head_not_fold_head() {
        let id = ObjectID::from_single_byte(0x07);

        // Worker has processed up to 950 (only 50 behind the tip at 1000) with no
        // recent Ika fold (fold head still 0). The tripwire must NOT fire — it
        // would if it were keyed off the stalled fold head.
        let (_dir, reader) = test_reader_cache_first(100);
        reader.note_upstream_head(1000);
        reader.cache.note_processed(950);
        let before = reader.metrics.cache_first_stale_total.get();
        assert!(
            reader.try_cache_hit(id).is_none(),
            "empty cache → plain miss"
        );
        assert_eq!(
            reader.metrics.cache_first_stale_total.get(),
            before,
            "processed head current → tripwire must stay closed"
        );

        // Worker genuinely behind (processed head 200 back): the tripwire fires.
        let (_dir2, reader2) = test_reader_cache_first(100);
        reader2.note_upstream_head(1000);
        reader2.cache.note_processed(800);
        let before2 = reader2.metrics.cache_first_stale_total.get();
        assert!(reader2.try_cache_hit(id).is_none());
        assert_eq!(
            reader2.metrics.cache_first_stale_total.get(),
            before2 + 1,
            "processed head far behind → tripwire fires"
        );
    }

    /// Per-object version monotonicity: once we've accepted version N for an
    /// id, a later response carrying an older version is a rollback (a relay
    /// replaying stale state) and must be rejected — without lowering the mark.
    #[tokio::test]
    async fn high_water_rejects_a_version_rollback() {
        let (_dir, reader) = test_reader(None);
        let id = ObjectID::from_single_byte(0x07);

        // First sight sets the mark; same-or-newer is always fine.
        reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        reader
            .record_high_water(id, SequenceNumber::from(9u64))
            .unwrap();

        let err = reader
            .record_high_water(id, SequenceNumber::from(8u64))
            .unwrap_err();
        match err {
            ReaderError::StaleVersion {
                id: got_id,
                got,
                cached,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(got, SequenceNumber::from(8u64));
                assert_eq!(cached, SequenceNumber::from(9u64));
            }
            other => panic!("expected StaleVersion, got {other:?}"),
        }

        // The rejected rollback must not have lowered the mark: 9 still holds,
        // so an even-older version is still rejected.
        reader
            .record_high_water(id, SequenceNumber::from(9u64))
            .unwrap();
        assert!(matches!(
            reader.record_high_water(id, SequenceNumber::from(0u64)),
            Err(ReaderError::StaleVersion { .. })
        ));

        // A different id has its own independent mark.
        let other = ObjectID::from_single_byte(0x08);
        reader
            .record_high_water(other, SequenceNumber::from(1u64))
            .unwrap();
    }

    /// A proof anchored more than `freshness_bound` checkpoints behind the
    /// provider's claimed head is too stale to trust and must be rejected.
    #[tokio::test]
    async fn freshness_rejects_a_checkpoint_too_far_behind_the_head() {
        let (_dir, reader) = test_reader(Some(10));

        // gap <= bound is accepted (10 == bound is the boundary, still ok).
        reader.check_freshness(100, 100).unwrap();
        reader.check_freshness(90, 100).unwrap();

        let err = reader.check_freshness(89, 100).unwrap_err();
        match err {
            ReaderError::StaleCheckpoint {
                object_seq,
                head,
                gap,
                bound,
            } => {
                assert_eq!(object_seq, 89);
                assert_eq!(head, 100);
                assert_eq!(gap, 11);
                assert_eq!(bound, 10);
            }
            other => panic!("expected StaleCheckpoint, got {other:?}"),
        }
    }

    /// `freshness_bound: None` disables the gate entirely — an arbitrarily old
    /// proof passes. (Production peer-only readers run with no bound.)
    #[tokio::test]
    async fn freshness_is_disabled_when_no_bound_is_set() {
        let (_dir, reader) = test_reader(None);
        reader.check_freshness(0, 1_000_000).unwrap();
    }

    /// The freshness gate is `gap <= bound` for `gap = head - proof_seq`, swept
    /// across representative bounds {0, 1, 100}: a proof exactly `bound` behind
    /// the head is the last accepted one (`gap == bound`), one closer still
    /// passes (`gap == bound - 1`), and one checkpoint further (`gap == bound + 1`)
    /// is the first rejection — surfaced as `StaleCheckpoint { gap, bound, .. }`
    /// with the gap and bound it was judged against. (`bound == 0` has no
    /// `bound - 1` case: zero gap is the tightest possible.)
    #[tokio::test]
    async fn freshness_boundary_conditions() {
        // Pin the head so `proof_seq` follows from the desired gap. Picked high
        // enough that `head - (bound + 1)` never underflows for these bounds.
        let head: CheckpointSequenceNumber = 1_000;
        for bound in [0u64, 1, 100] {
            let (_dir, reader) = test_reader(Some(bound));

            // gap == bound: the boundary, still fresh.
            let at_bound = head - bound;
            reader
                .check_freshness(at_bound, head)
                .unwrap_or_else(|e| panic!("bound {bound}: gap == bound must pass, got {e:?}"));

            // gap == bound - 1: one closer, fresh. (Skip for bound 0.)
            if bound > 0 {
                let inside_bound = head - (bound - 1);
                reader
                    .check_freshness(inside_bound, head)
                    .unwrap_or_else(|e| {
                        panic!("bound {bound}: gap == bound - 1 must pass, got {e:?}")
                    });
            }

            // gap == bound + 1: the first stale proof.
            let past_bound = head - (bound + 1);
            let err = reader
                .check_freshness(past_bound, head)
                .expect_err("gap == bound + 1 must be rejected");
            match err {
                ReaderError::StaleCheckpoint {
                    object_seq,
                    head: err_head,
                    gap,
                    bound: err_bound,
                } => {
                    assert_eq!(object_seq, past_bound, "bound {bound}");
                    assert_eq!(err_head, head, "bound {bound}");
                    assert_eq!(gap, bound + 1, "bound {bound}");
                    assert_eq!(err_bound, bound, "bound {bound}");
                }
                other => panic!("bound {bound}: expected StaleCheckpoint, got {other:?}"),
            }
        }
    }

    /// `observed_upstream_head` only ratchets up (`fetch_max` in
    /// `note_upstream_head`), so once any provider response has shown a newer
    /// head, a later response under-reporting a lower one cannot talk freshness
    /// back below it. A relay that first reveals head 1000, then claims 10, is
    /// still held to 1000: a proof anchored at 950 (gap 50 vs the real tip) stays
    /// judged against 1000, not the relay's freshly-lowered 10 (against which its
    /// gap would saturate to 0 and pass). Pins the monotonic floor.
    #[tokio::test]
    async fn observed_upstream_head_is_monotonic_and_pins_freshness() {
        // Bound 10: a 50-checkpoint gap is stale iff judged against 1000.
        let (_dir, reader) = test_reader(Some(10));

        reader.note_upstream_head(1000);
        // A later, lower claim must NOT lower the pin.
        reader.note_upstream_head(10);
        let observed_head = reader.observed_upstream_head.load(Ordering::Relaxed);
        assert_eq!(
            observed_head, 1000,
            "fetch_max must not lower the observed head"
        );

        // Against the monotonic 1000, a proof at 950 (gap 50 > bound 10) is stale.
        let err = reader
            .check_freshness(950, observed_head)
            .expect_err("gap 50 vs the pinned head 1000 exceeds bound 10");
        match err {
            ReaderError::StaleCheckpoint {
                gap, head, bound, ..
            } => {
                assert_eq!(head, 1000);
                assert_eq!(gap, 50);
                assert_eq!(bound, 10);
            }
            other => panic!("expected StaleCheckpoint, got {other:?}"),
        }

        // Had the pin followed the relay's lowered claim of 10, the same proof
        // would have judged fresh (gap saturates to 0) — the failure mode this
        // guards against.
        reader
            .check_freshness(950, 10)
            .expect("sanity: against a head of 10 the proof is trivially 'fresh'");
    }

    /// The per-object high-water mark is the single source of truth for version
    /// monotonicity on *both* the cache fast-path and the network/verify path.
    /// After serving a newer version (mark at 5), a later read returning an older
    /// version of the same id is a rollback and must be rejected on whichever
    /// path it arrives — and the rejection must not lower the mark. The cache
    /// path (`try_cache_hit`) folds the rollback into a `None` (fall through);
    /// the network path (`verify_response`) surfaces it as `StaleVersion`.
    #[tokio::test]
    async fn high_water_rejects_network_rollback_after_cache_hit() {
        let id = ObjectID::from_single_byte(0x07);

        // --- cache path: a cached v3 below the mark is not served ---
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let cache_reader = OcsVerifiedReader::new(
            Arc::new(UnusedProvider), // a cache-rejected read must not hit the network
            committees,
            OcsMetrics::new_for_testing(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true, // cache_first
            None, // no staleness bound — isolate the high-water gate
        );

        // A newer version (5) was already served, so the mark sits at 5.
        cache_reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        // Seed the cache with a stale v3 of the same id.
        let stale = test_object(id, 3, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        let entry = VerifiedObjectEntry {
            object: stale,
            checkpoint_seq: 42,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        cache_reader.cache.absorb_entries(&summary, &[entry]);

        // The cache fast-path consults the same mark: v3 < 5, so it falls through
        // (None) rather than serving the rollback — and the mark is untouched.
        assert!(
            cache_reader.try_cache_hit(id).is_none(),
            "cache must not serve a version below the high-water mark"
        );

        // --- network path: a valid proof for v3 is still a StaleVersion ---
        let proven = test_object(id, 3, address_owner(0xAA));
        let (net_summary, net_proof) = sign_inclusion(&committee, &keys, 100, &[&proven], &proven);
        let provider = StagedProvider::object(object_response(proven, net_summary, net_proof, 100));
        let (_dir, net_reader, metrics) = reader_with(provider, committee, None);
        net_reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();

        let err = net_reader.verified_object(id).await.unwrap_err();
        match err {
            ReaderError::StaleVersion {
                id: got_id,
                got,
                cached,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(got, SequenceNumber::from(3u64));
                assert_eq!(cached, SequenceNumber::from(5u64));
            }
            other => panic!("expected StaleVersion, got {other:?}"),
        }
        assert_eq!(failure_count(&metrics, "object", "stale_version"), 1);

        // The rejected rollback left the mark at 5: re-asserting 5 still succeeds,
        // and anything below it is still rejected.
        net_reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        assert!(matches!(
            net_reader.record_high_water(id, SequenceNumber::from(4u64)),
            Err(ReaderError::StaleVersion { .. })
        ));
    }

    /// The anchor cache fast-path is forward-only. After a newer anchor version
    /// has been served (mark at 6), the cache still holding an older v5 must not
    /// be served back by `verified_anchor_object`: `cache_fallback` re-checks the
    /// high-water mark (`record_high_water(_, v5)` fails since 5 < 6) and returns
    /// `None`, so the anchor falls through to the network instead of serving the
    /// stale-but-cached snapshot. Here the network is `PrunedProvider`, so the
    /// fall-through surfaces as `NotFound` — proving the read did NOT short-circuit
    /// to the stale v5.
    #[tokio::test]
    async fn anchor_fallback_rejects_a_cached_version_below_high_water() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            Arc::new(PrunedProvider), // network reach-back fails NotFound
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true,      // cache_first (sui-state-direct)
            Some(100), // staleness bound — tripped below so try_cache_hit also bypasses
        );

        // Seed the cache with anchor@v5 at seq 42.
        let id = ObjectID::from_single_byte(0x55);
        let stale = test_object(id, 5, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        let entry = VerifiedObjectEntry {
            object: stale,
            checkpoint_seq: 42,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        reader.cache.absorb_entries(&summary, &[entry]);

        // A newer version (6) was already served: the mark is now ahead of the
        // cached v5.
        reader
            .record_high_water(id, SequenceNumber::from(6u64))
            .unwrap();

        // Trip the staleness tripwire too (processed 42 vs head 1000, bound 100),
        // so neither the anchor short-circuit nor `try_cache_hit` can serve the
        // stale v5 — both consult the high-water mark, which now rejects it.
        reader.cache.note_processed(42);
        reader.note_upstream_head(1000);

        let err = reader.verified_anchor_object(id).await.unwrap_err();
        assert!(
            matches!(err, ReaderError::Transport(TransportError::NotFound(_))),
            "anchor must fall through to the (pruned) network, not serve stale v5; got {err:?}"
        );

        // The cache-served counters stayed at zero: nothing was ever served from
        // the cache for this id.
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["anchor"])
                .get(),
            0,
            "the anchor short-circuit must not have served the stale snapshot"
        );
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["fallback"])
                .get(),
            0,
            "the NotFound fallback must not have served the stale snapshot"
        );
        // The mark is untouched at 6: a fresh v6 read still succeeds, v5 still fails.
        reader
            .record_high_water(id, SequenceNumber::from(6u64))
            .unwrap();
        assert!(matches!(
            reader.record_high_water(id, SequenceNumber::from(5u64)),
            Err(ReaderError::StaleVersion { .. })
        ));
    }

    /// The singleton-anchor read bounds its own staleness: it serves the cached
    /// snapshot within `ANCHOR_REFRESH_INTERVAL`, but once that elapses it forces
    /// a verified network re-read — so an anchor whose update the pusher skipped
    /// past a pruned checkpoint (never re-folded) cannot be served stale forever
    /// and wedge the epoch (#1736). The within-interval assertion shows the stale
    /// snapshot IS served (the wedge condition the escape must bound); the
    /// past-interval assertion shows the escape refreshes it.
    #[tokio::test]
    async fn anchor_read_refreshes_from_network_after_the_interval() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();

        // The fullnode holds the FRESH anchor (v6@seq 50); the local cache holds a
        // STALE snapshot (v5@seq 42) — the version whose update was never re-folded.
        let id = ObjectID::from_single_byte(0x55);
        let fresh = test_object(id, 6, address_owner(0x02));
        let (net_summary, net_proof) = sign_inclusion(&committee, &keys, 50, &[&fresh], &fresh);
        let reader = OcsVerifiedReader::new(
            StagedProvider::object(object_response(fresh, net_summary, net_proof, 50)),
            committees,
            metrics.clone(),
            None, // freshness disabled
            Arc::new(VerifiedStateCache::new()),
            true, // cache_first (sui-state-direct)
            None,
        );

        let stale = test_object(id, 5, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        reader.cache.absorb_entries(
            &summary,
            &[VerifiedObjectEntry {
                object: stale,
                checkpoint_seq: 42,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            }],
        );

        // First read starts the clock and serves the cached snapshot (no network).
        let first = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(first.object.version(), SequenceNumber::from(5u64));
        // A second read WITHIN the interval still serves the stale cache — exactly
        // the indefinite-stale serving the escape must bound.
        let within = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(
            within.object.version(),
            SequenceNumber::from(5u64),
            "within the interval the stale cache is served"
        );

        // Age the refresh clock past the interval (deterministic — no sleep).
        {
            let mut refreshed_at = reader.anchor_refreshed_at.lock();
            let aged = Instant::now()
                .checked_sub(ANCHOR_REFRESH_INTERVAL + Duration::from_secs(1))
                .expect("monotonic clock far enough along to back-date");
            refreshed_at.insert(id, aged);
        }

        // Now due: the read forces a verified network re-read and returns the FRESH
        // anchor — the stale cache is no longer served.
        let refreshed = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(
            refreshed.object.version(),
            SequenceNumber::from(6u64),
            "past the interval the anchor refreshes from the network"
        );
    }

    /// Build a single-changeset index whose contiguous frontier is exactly
    /// `[seq, seq]`, recording each object in `objects` as modified at `seq`. So
    /// `currency(id, seq)` is `Current` for those ids, and `Unknown` for a lower
    /// `anchored_seq` (below the folded floor).
    fn index_folded_at(
        committee: &SuiCommittee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        objects: &[&Object],
    ) -> SharedChangesetIndex {
        let object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = objects
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        let artifacts = CheckpointArtifacts::from_object_states(object_states.clone());
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts.digest().unwrap())],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let cert =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        let mut index = ChangesetIndex::new();
        index
            .absorb(&cert, object_states)
            .expect("bootstrap changeset absorbs");
        Arc::new(RwLock::new(index))
    }

    /// A mirror node (`cache_first = false`, changeset index wired) serves the
    /// shadow-cached anchor when the committee-signed changeset index confirms
    /// it current (`currency == Current`) — killing the per-tick relay re-verify.
    /// Critically, the `ANCHOR_REFRESH_INTERVAL` re-read still fires even while
    /// the verdict stays `Current`, so a *stalled* changeset stream (which would
    /// freeze `Current` forever) can never serve the stale snapshot indefinitely
    /// and wedge the epoch (the #1736 stale-anchor class). Removing the TTL
    /// re-read would make the past-interval assertion serve the stale v5.
    #[tokio::test]
    async fn mirror_serves_current_anchor_from_cache_yet_ttl_still_refreshes() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();

        let id = ObjectID::from_single_byte(0x55);
        let stale = test_object(id, 5, address_owner(0x02));
        // The changeset index says id was last modified at seq 42 -> Current@42.
        let index = index_folded_at(&committee, &keys, 42, &[&stale]);

        // The relay holds a fresher v6@seq50 for the forced re-read below.
        let fresh = test_object(id, 6, address_owner(0x02));
        let (net_summary, net_proof) = sign_inclusion(&committee, &keys, 50, &[&fresh], &fresh);
        let reader = OcsVerifiedReader::new(
            StagedProvider::object(object_response(fresh, net_summary, net_proof, 50)),
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            false, // cache_first = false -> MIRROR (sui-state-mirrored)
            None,
        )
        .with_changeset_index(Some(index));

        // Shadow-populate the cache with the anchor at v5@seq42, as a prior read would.
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        reader.cache.absorb_entries(
            &summary,
            &[VerifiedObjectEntry {
                object: stale,
                checkpoint_seq: 42,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            }],
        );

        // Within the interval + currency Current -> served from the shadow cache
        // (v5), no relay round-trip.
        let served = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(
            served.object.version(),
            SequenceNumber::from(5u64),
            "mirror serves the current cached anchor without a relay round-trip"
        );

        // Age the refresh clock past the interval. Currency is STILL Current (the
        // index is unchanged — a frozen stream), yet the forced re-read returns the
        // FRESH network anchor: the TTL, not currency, is what bounds staleness.
        {
            let mut refreshed_at = reader.anchor_refreshed_at.lock();
            let aged = Instant::now()
                .checked_sub(ANCHOR_REFRESH_INTERVAL + Duration::from_secs(1))
                .expect("monotonic clock far enough along to back-date");
            refreshed_at.insert(id, aged);
        }
        let refreshed = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(
            refreshed.object.version(),
            SequenceNumber::from(6u64),
            "past the interval the anchor refreshes from the network even while currency stays Current"
        );
    }

    /// A mirror node NEVER serves the shadow cache without a positive `Current`
    /// verdict: here the changeset index can't vouch for the anchor (its
    /// checkpoint is below the folded frontier -> `Unknown`), so the read takes
    /// the per-read-verified network path and returns the fresh version, not the
    /// stale cached snapshot.
    #[tokio::test]
    async fn mirror_does_not_serve_cache_without_a_current_verdict() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();

        let id = ObjectID::from_single_byte(0x55);
        let stale = test_object(id, 5, address_owner(0x02));
        // Index folded only at seq 60 (a different object) -> currency(id, 42) is
        // `Unknown` (42 is below the folded floor), so the cache is not served.
        let other = test_object(ObjectID::from_single_byte(0x66), 1, address_owner(0x02));
        let index = index_folded_at(&committee, &keys, 60, &[&other]);

        let fresh = test_object(id, 6, address_owner(0x02));
        let (net_summary, net_proof) = sign_inclusion(&committee, &keys, 50, &[&fresh], &fresh);
        let reader = OcsVerifiedReader::new(
            StagedProvider::object(object_response(fresh, net_summary, net_proof, 50)),
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        )
        .with_changeset_index(Some(index));

        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        reader.cache.absorb_entries(
            &summary,
            &[VerifiedObjectEntry {
                object: stale,
                checkpoint_seq: 42,
                proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            }],
        );

        // currency == Unknown -> the shadow cache is NOT served; the network read
        // returns the fresh v6, not the stale cached v5.
        let read = reader.verified_anchor_object(id).await.unwrap();
        assert_eq!(
            read.object.version(),
            SequenceNumber::from(6u64),
            "without a Current verdict the mirror reads the network, not the stale cache"
        );
    }

    // ===== End-to-end crypto-fixture tests =====
    //
    // These build a *self-consistent* OCS fixture: a test committee signs a
    // checkpoint summary that commits (via its `CheckpointArtifactsDigest`) to a
    // `ModifiedObjectTree` of synthesized objects, plus the matching inclusion
    // proof. The reader, bootstrapped with the same committee, accepts the valid
    // fixture and rejects every tampered variant — exercising the BLS, Merkle,
    // id-binding, and bag-membership gates the local-only tests above can't
    // reach. No chain data or real checkpoint files are needed.

    /// A provider that hands back one pre-staged response, then is empty.
    struct StagedProvider {
        object: Mutex<Option<VerifiedObjectResponse>>,
        batch: Mutex<Option<BatchVerifiedObjectsResponse>>,
        bag: Mutex<Option<VerifiedDynamicFieldsPageResponse>>,
    }

    impl StagedProvider {
        fn object(resp: VerifiedObjectResponse) -> Arc<Self> {
            Arc::new(Self {
                object: Mutex::new(Some(resp)),
                batch: Mutex::new(None),
                bag: Mutex::new(None),
            })
        }
        fn batch(resp: BatchVerifiedObjectsResponse) -> Arc<Self> {
            Arc::new(Self {
                object: Mutex::new(None),
                batch: Mutex::new(Some(resp)),
                bag: Mutex::new(None),
            })
        }
        fn bag(resp: VerifiedDynamicFieldsPageResponse) -> Arc<Self> {
            Arc::new(Self {
                object: Mutex::new(None),
                batch: Mutex::new(None),
                bag: Mutex::new(Some(resp)),
            })
        }
    }

    #[async_trait]
    impl ProofProvider for StagedProvider {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Ok(self
                .object
                .lock()
                .take()
                .expect("no staged verified_object response"))
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            Ok(self
                .batch
                .lock()
                .take()
                .expect("no staged batch_verified_objects response"))
        }
        async fn verified_dynamic_fields_page(
            &self,
            _request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            Ok(self
                .bag
                .lock()
                .take()
                .expect("no staged verified_dynamic_fields_page response"))
        }
    }

    fn reader_with(
        provider: Arc<dyn ProofProvider>,
        committee: SuiCommittee,
        freshness_bound: Option<u64>,
    ) -> (tempfile::TempDir, OcsVerifiedReader, Arc<OcsMetrics>) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee))).unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            provider,
            committees,
            metrics.clone(),
            freshness_bound,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        );
        (dir, reader, metrics)
    }

    fn test_object(id: ObjectID, version: u64, owner: Owner) -> Object {
        Object::with_id_owner_version_for_testing(id, SequenceNumber::from(version), owner)
    }

    fn address_owner(byte: u8) -> Owner {
        Owner::AddressOwner(ObjectID::from_single_byte(byte).into())
    }

    /// Build a committee-signed summary committing to a tree of `leaves`, plus
    /// the inclusion proof for `target`. Summary + proof verify together against
    /// `committee` — the digest linkage holds because both the summary's
    /// commitment and the proof's tree root come from the *same* artifacts.
    fn sign_inclusion(
        committee: &SuiCommittee,
        keypairs: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        leaves: &[&Object],
        target: &Object,
    ) -> (CertifiedCheckpointSummary, OCSInclusionProof) {
        let object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = leaves
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect();
        let artifacts = CheckpointArtifacts::from_object_states(object_states);
        let artifacts_digest = artifacts.digest().expect("artifacts digest");
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts_digest)],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let cert =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keypairs, committee);
        let proof = ModifiedObjectTree::new(&artifacts)
            .expect("modified object tree")
            .get_inclusion_proof(target.compute_object_reference())
            .expect("inclusion proof");
        (cert, proof)
    }

    fn object_response(
        object: Object,
        summary: CertifiedCheckpointSummary,
        proof: OCSInclusionProof,
        seq: CheckpointSequenceNumber,
    ) -> VerifiedObjectResponse {
        VerifiedObjectResponse {
            object,
            summary,
            proof,
            claimed_latest_checkpoint_seq: seq,
        }
    }

    /// A provider whose object read always fails `NotFound` — models the
    /// upstream fullnode having pruned the object's defining transaction.
    struct PrunedProvider;

    #[async_trait]
    impl ProofProvider for PrunedProvider {
        async fn verified_object(
            &self,
            id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::NotFound(format!("tx for {id} pruned")))
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            unreachable!("batch not exercised by the fallback test")
        }
        async fn verified_dynamic_fields_page(
            &self,
            _request: VerifiedDynamicFieldsPageRequest,
        ) -> Result<VerifiedDynamicFieldsPageResponse, TransportError> {
            unreachable!("bag not exercised by the fallback test")
        }
    }

    /// When the network reach-back fails because upstream pruned the object's
    /// defining transaction, a cache-first reader serves the committee-verified
    /// cached snapshot instead of wedging — even with the staleness tripwire
    /// tripped (a behind pusher is exactly when this matters). With nothing
    /// cached, the prune is surfaced as the original `NotFound`.
    #[tokio::test]
    async fn pruned_reach_back_falls_back_to_the_cached_snapshot() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            Arc::new(PrunedProvider),
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true,      // cache_first (sui-state-direct)
            Some(100), // staleness bound
        );

        // Fold a committee-verified snapshot of `id` (version 5) at seq 42.
        let id = ObjectID::from_single_byte(0x55);
        let obj = test_object(id, 5, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&obj], &obj);
        let entry = VerifiedObjectEntry {
            object: obj.clone(),
            checkpoint_seq: 42,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        reader.cache.absorb_entries(&summary, &[entry]);

        // The pusher (processed head 42) is far behind the tip (1000), so the
        // tripwire trips and the read falls through to the network — pruned.
        reader.note_upstream_head(1000);

        let got = reader
            .verified_object(id)
            .await
            .expect("fallback serves the cached snapshot rather than wedging");
        assert_eq!(got.object.id(), id);
        assert_eq!(got.object.version(), SequenceNumber::from(5u64));
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["fallback"])
                .get(),
            1
        );

        // An id that was never cached: no fallback, the prune is surfaced.
        let absent = ObjectID::from_single_byte(0x66);
        let err = reader.verified_object(absent).await.unwrap_err();
        assert!(matches!(
            err,
            ReaderError::Transport(TransportError::NotFound(_))
        ));
    }

    /// The singleton anchors (System / DWalletCoordinator inner) are polled
    /// every ~120ms via [`OcsVerifiedReader::verified_anchor_object`]. When the
    /// pusher lags past the staleness bound the tripwire trips — but an anchor
    /// read must still be served from the committee-verified cache rather than
    /// reaching back to the fullnode every tick (the feedback loop that throttles
    /// dwallet advancement). `UnusedProvider` panics if the network is touched,
    /// so a successful read proves the cache short-circuit fired through the
    /// tripped tripwire.
    #[tokio::test]
    async fn anchor_reads_serve_cache_through_a_tripped_tripwire() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            Arc::new(UnusedProvider), // unreachable!() if the read hits the network
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true,      // cache_first (sui-state-direct)
            Some(100), // staleness bound
        );

        // Fold a committee-verified snapshot of the anchor (version 5) at seq 42.
        let id = ObjectID::from_single_byte(0x55);
        let obj = test_object(id, 5, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&obj], &obj);
        let entry = VerifiedObjectEntry {
            object: obj.clone(),
            checkpoint_seq: 42,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        reader.cache.absorb_entries(&summary, &[entry]);

        // Pusher far behind the tip (processed 42 vs head 1000, bound 100): the
        // tripwire is tripped, so a plain `verified_object` would reach back to
        // the network — which here would panic.
        reader.cache.note_processed(42);
        reader.note_upstream_head(1000);
        assert!(
            reader.try_cache_hit(id).is_none(),
            "tripwire must be tripped for this test to exercise the bypass",
        );

        // The anchor read serves the cached snapshot WITHOUT touching the provider.
        let got = reader
            .verified_anchor_object(id)
            .await
            .expect("anchor read serves the committee-verified cache through the tripwire");
        assert_eq!(got.object.id(), id);
        assert_eq!(got.object.version(), SequenceNumber::from(5u64));
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["anchor"])
                .get(),
            1,
            "served via the anchor short-circuit",
        );
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["fallback"])
                .get(),
            0,
            "anchor short-circuit precedes — and avoids — the NotFound fallback path",
        );
    }

    #[tokio::test]
    async fn batch_read_rejects_a_short_results_vec_instead_of_truncating() {
        // ocs-verifier-core-1: a relay that returns fewer slots than requested
        // must be rejected, not silently `zip`-truncated into a partial `Ok`
        // (the trailing ids would skip their per-slot NotFound + id-binding checks).
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        // ONE valid entry, but TWO ids requested. Without the length guard the
        // zip truncates to the single valid slot and returns a one-element `Ok`
        // (the test-test: this entry verifies, so a vacuous fixture would pass).
        let id0 = ObjectID::from_single_byte(0x21);
        let id1 = ObjectID::from_single_byte(0x22);
        let object = test_object(id0, 7, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let entry = field_entry(object, proof, 100, "", Vec::new());
        let resp = BatchVerifiedObjectsResponse {
            summaries: BTreeMap::from([(100, summary)]),
            results: vec![Some(entry)],
            claimed_latest_checkpoint_seq: 100,
        };
        let (_dir, reader, _metrics) = reader_with(StagedProvider::batch(resp), committee, None);
        let err = reader
            .verified_objects(&[id0, id1])
            .await
            .expect_err("a short results vec must be rejected, not truncated to a partial Ok");
        assert!(
            matches!(err, ReaderError::Transport(TransportError::NotFound(_))),
            "expected NotFound for the slot/id count mismatch, got {err:?}",
        );
    }

    fn field_entry(
        object: Object,
        proof: OCSInclusionProof,
        seq: CheckpointSequenceNumber,
        name_type: &str,
        name_bcs: Vec<u8>,
    ) -> VerifiedObjectEntry {
        VerifiedObjectEntry {
            object,
            checkpoint_seq: seq,
            proof,
            dynamic_field_name_type: name_type.to_string(),
            dynamic_field_name_bcs: name_bcs,
        }
    }

    fn field_page_response(
        summary: CertifiedCheckpointSummary,
        entry: VerifiedObjectEntry,
        seq: CheckpointSequenceNumber,
    ) -> VerifiedDynamicFieldsPageResponse {
        VerifiedDynamicFieldsPageResponse {
            summaries: BTreeMap::from([(seq, summary)]),
            entries: vec![entry],
            next_page_token: None,
            claimed_latest_checkpoint_seq: seq,
            skipped_entry_ids: Vec::new(),
        }
    }

    fn failure_count(metrics: &Arc<OcsMetrics>, kind: &str, reason: &str) -> u64 {
        metrics
            .proof_verify_failures_total
            .with_label_values(&[kind, reason])
            .get()
    }

    /// The fixture itself is sound: a committee-signed summary + matching
    /// inclusion proof verifies through the full BLS + Merkle path. Without
    /// this, every rejection test below would be vacuous.
    #[tokio::test]
    async fn a_valid_inclusion_proof_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 7, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let verified = reader
            .verified_object(id)
            .await
            .expect("a committee-signed, correctly-proven object must verify");
        assert_eq!(verified.object.id(), id);
        assert_eq!(verified.source_checkpoint_seq, 100);
    }

    /// A proof for object X is cryptographically valid, but the relay is
    /// answering `get(Y)` with it. The id binding must reject the substitution.
    #[tokio::test]
    async fn an_object_id_substitution_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let proven_id = ObjectID::from_single_byte(0x21);
        let requested_id = ObjectID::from_single_byte(0x99);
        let object = test_object(proven_id, 1, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader.verified_object(requested_id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// The summary is well-formed and the proof matches it, but it is signed by
    /// a committee the reader does not trust — the BLS gate must reject it.
    /// (The test committees are seeded deterministically, so the "foreign" one
    /// is given a different size to guarantee a divergent authority set.)
    #[tokio::test]
    async fn a_summary_signed_by_a_foreign_committee_is_rejected() {
        let (store_committee, _) = SuiCommittee::new_simple_test_committee_of_size(4);
        let (foreign_committee, foreign_keys) = SuiCommittee::new_simple_test_committee_of_size(7);
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 1, address_owner(0xAA));
        let (summary, proof) =
            sign_inclusion(&foreign_committee, &foreign_keys, 100, &[&object], &object);
        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, store_committee, None);

        let err = reader.verified_object(id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// Prove version 1, but serve the *same* id at version 2: the id binding
    /// passes, but the served object's ref isn't the one the tree commits to —
    /// the Merkle path must reject the substituted state.
    #[tokio::test]
    async fn a_substituted_object_state_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let proven = test_object(id, 1, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&proven], &proven);
        let lied = test_object(id, 2, address_owner(0xAA));
        let provider = StagedProvider::object(object_response(lied, summary, proof, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader.verified_object(id).await.unwrap_err();
        assert!(matches!(err, ReaderError::InvalidProof(_)), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "invalid_proof"), 1);
    }

    /// Plain `Bag`/`Table`: the value `Field` is owned directly by the bag UID.
    #[tokio::test]
    async fn a_field_entry_owned_by_the_bag_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let object = test_object(entry_id, 1, Owner::ObjectOwner(parent_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(field_page_response(
            summary,
            field_entry(object, proof, 100, "", vec![]),
            100,
        ));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let page = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .expect("an entry owned by the bag must be accepted");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].object.id(), entry_id);
    }

    /// network-mirror-2: a byzantine relay that over-stuffs the page with more
    /// entries than the caller asked for is rejected UP FRONT — before the
    /// `Vec::with_capacity` and the O(entries) BLS/Merkle verify loop — rather
    /// than silently processed. The three staged entries are individually valid
    /// (so the only thing that can reject the page is the length bound, not a
    /// proof failure), but the caller requested a page size of one.
    #[tokio::test]
    async fn an_overlong_dynamic_fields_page_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let object = test_object(
            ObjectID::from_single_byte(0x56),
            1,
            Owner::ObjectOwner(parent_id.into()),
        );
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let resp = VerifiedDynamicFieldsPageResponse {
            summaries: BTreeMap::from([(100, summary)]),
            entries: vec![
                field_entry(
                    object.clone(),
                    clone_inclusion_proof(&proof).unwrap(),
                    100,
                    "",
                    vec![],
                ),
                field_entry(
                    object.clone(),
                    clone_inclusion_proof(&proof).unwrap(),
                    100,
                    "",
                    vec![],
                ),
                field_entry(object, proof, 100, "", vec![]),
            ],
            next_page_token: None,
            claimed_latest_checkpoint_seq: 100,
            skipped_entry_ids: Vec::new(),
        };
        let (_dir, reader, metrics) = reader_with(StagedProvider::bag(resp), committee, None);

        let err = reader
            .verified_dynamic_fields_page(parent_id, Some(1), None)
            .await
            .expect_err("a page longer than the requested size must be rejected");
        assert!(
            matches!(err, ReaderError::OverlongPage { got: 3, allowed: 1 }),
            "expected OverlongPage, got {err:?}"
        );
        assert_eq!(
            failure_count(&metrics, "dynamic_field_entry", "overlong_page"),
            1
        );
    }

    /// `ObjectTable`/`ObjectBag`: the value object is owned by its
    /// `Field<Wrapper<K>, ID>` wrapper, whose id derives from `(parent_id, key)`.
    #[tokio::test]
    async fn a_field_entry_owned_via_the_object_field_wrapper_is_accepted() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let name_type = "u64";
        let name_bcs = bcs::to_bytes(&7u64).unwrap();
        let field_id = derive_object_field_wrapper_id(parent_id, name_type, &name_bcs)
            .expect("wrapper id derivation");
        let object = test_object(entry_id, 1, Owner::ObjectOwner(field_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(field_page_response(
            summary,
            field_entry(object, proof, 100, name_type, name_bcs),
            100,
        ));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);

        let page = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .expect("an ObjectTable entry owned by its derived field must be accepted");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].object.id(), entry_id);
    }

    /// Validly proven, but owned by a *different* collection — a relay replaying
    /// a foreign dynamic field. `foreign_id` is neither `parent_id` nor the derived
    /// field id, so the binding must reject it.
    #[tokio::test]
    async fn a_field_entry_owned_by_a_foreign_object_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let foreign_id = ObjectID::from_single_byte(0x77);
        let object = test_object(entry_id, 1, Owner::ObjectOwner(foreign_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(field_page_response(
            summary,
            field_entry(object, proof, 100, "u64", bcs::to_bytes(&7u64).unwrap()),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReaderError::DynamicFieldMembership { .. }),
            "got {err:?}"
        );
        assert_eq!(
            failure_count(&metrics, "dynamic_field_entry", "dynamic_field_membership"),
            1
        );
    }

    /// Address-owned (not object-owned at all): a dynamic-field child is always
    /// object-owned, so this can never be a member of the bag.
    #[tokio::test]
    async fn a_field_entry_owned_by_an_address_is_rejected() {
        let (committee, keypairs) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let object = test_object(entry_id, 1, address_owner(0x77));
        let (summary, proof) = sign_inclusion(&committee, &keypairs, 100, &[&object], &object);
        let provider = StagedProvider::bag(field_page_response(
            summary,
            field_entry(object, proof, 100, "", vec![]),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReaderError::DynamicFieldMembership { .. }),
            "got {err:?}"
        );
        assert_eq!(
            failure_count(&metrics, "dynamic_field_entry", "dynamic_field_membership"),
            1
        );
    }

    // ---- read-path currency gate (changeset-stream wiring) ----

    fn object_states_of(leaves: &[&Object]) -> BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> {
        leaves
            .iter()
            .map(|o| {
                let (id, version, digest) = o.compute_object_reference();
                (id, (version, digest))
            })
            .collect()
    }

    /// A committee-signed changeset summary chained onto `previous` (for folding
    /// a second checkpoint into the index; the inclusion-proof fixture uses
    /// `sign_inclusion`).
    fn chained_summary(
        committee: &SuiCommittee,
        keypairs: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        previous: Option<CheckpointDigest>,
        object_states: &BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
    ) -> CertifiedCheckpointSummary {
        let artifacts = CheckpointArtifacts::from_object_states(object_states.clone());
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: previous,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![CheckpointCommitment::from(artifacts.digest().unwrap())],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keypairs, committee)
    }

    /// With a changeset index wired, a read whose authenticating checkpoint is
    /// the id's latest modification is accepted — currency holds.
    #[tokio::test]
    async fn currency_accepts_a_current_object() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 7, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keys, 100, &[&object], &object);

        // Index: the id was last modified at checkpoint 100.
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        index
            .write()
            .absorb(&summary, object_states_of(&[&object]))
            .unwrap();

        let provider = StagedProvider::object(object_response(object, summary, proof, 100));
        let (_dir, reader, _metrics) = reader_with(provider, committee, None);
        let reader = reader.with_changeset_index(Some(index));

        let verified = reader
            .verified_object(id)
            .await
            .expect("a current object must verify");
        assert_eq!(verified.object.id(), id);
    }

    /// The currency payoff: a relay serving a validly-signed but *rolled-back*
    /// version is rejected because the index shows the id was modified again at
    /// a later checkpoint — even though the version never decreased on this
    /// node, so the high-water gate alone would not catch it.
    #[tokio::test]
    async fn currency_rejects_a_rolled_back_object() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let stale = test_object(id, 7, address_owner(0xAA));
        let (summary100, proof100) = sign_inclusion(&committee, &keys, 100, &[&stale], &stale);

        // Fold: the id at v7 at checkpoint 100, then modified to v8 at 101.
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let digest100 = summary100.data().digest();
        index
            .write()
            .absorb(&summary100, object_states_of(&[&stale]))
            .unwrap();
        let current = test_object(id, 8, address_owner(0xAA));
        let states101 = object_states_of(&[&current]);
        let summary101 = chained_summary(&committee, &keys, 101, Some(digest100), &states101);
        index.write().absorb(&summary101, states101).unwrap();

        // The relay serves the stale v7, validly anchored at 100.
        let provider = StagedProvider::object(object_response(stale, summary100, proof100, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);
        let reader = reader.with_changeset_index(Some(index));

        let err = reader.verified_object(id).await.unwrap_err();
        assert!(matches!(err, ReaderError::NotCurrent { .. }), "got {err:?}");
        assert_eq!(failure_count(&metrics, "object", "not_current"), 1);
    }

    // ---- currency on the batch and bag read paths ----

    fn batch_response(
        summary: CertifiedCheckpointSummary,
        entry: VerifiedObjectEntry,
        seq: CheckpointSequenceNumber,
    ) -> BatchVerifiedObjectsResponse {
        BatchVerifiedObjectsResponse {
            summaries: BTreeMap::from([(seq, summary)]),
            results: vec![Some(entry)],
            claimed_latest_checkpoint_seq: seq,
        }
    }

    /// Fold the index so an object's latest modification is checkpoint 101, then
    /// have the relay serve the rolled-back v7 anchored at 100. Returns the
    /// fixture for whichever read path the test drives.
    fn rolled_back_fixture(
        committee: &SuiCommittee,
        keys: &[AuthorityKeyPair],
        index: &SharedChangesetIndex,
        id: ObjectID,
        owner: Owner,
    ) -> (Object, CertifiedCheckpointSummary, OCSInclusionProof) {
        let stale = test_object(id, 7, owner.clone());
        let (summary100, proof100) = sign_inclusion(committee, keys, 100, &[&stale], &stale);
        let digest100 = summary100.data().digest();
        index
            .write()
            .absorb(&summary100, object_states_of(&[&stale]))
            .unwrap();
        let current = test_object(id, 8, owner);
        let states101 = object_states_of(&[&current]);
        let summary101 = chained_summary(committee, keys, 101, Some(digest100), &states101);
        index.write().absorb(&summary101, states101).unwrap();
        (stale, summary100, proof100)
    }

    /// The currency gate also covers the batch path: a rolled-back entry in a
    /// `verified_objects` batch is rejected.
    #[tokio::test]
    async fn currency_rejects_a_rolled_back_object_in_a_batch() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let (stale, summary100, proof100) =
            rolled_back_fixture(&committee, &keys, &index, id, address_owner(0xAA));

        let entry = field_entry(stale, proof100, 100, "", vec![]);
        let provider = StagedProvider::batch(batch_response(summary100, entry, 100));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);
        let reader = reader.with_changeset_index(Some(index));

        let err = reader.verified_objects(&[id]).await.unwrap_err();
        assert!(matches!(err, ReaderError::NotCurrent { .. }), "got {err:?}");
        assert_eq!(failure_count(&metrics, "batch_objects", "not_current"), 1);
    }

    /// And the bag path: a relay serving a stale (since-modified) bag child is
    /// rejected, even though its membership binding to the bag is valid.
    #[tokio::test]
    async fn currency_rejects_a_stale_field_entry() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        // The child is owned by the bag (membership binds); currency is the
        // independent check that the served version is still current.
        let (stale, summary100, proof100) = rolled_back_fixture(
            &committee,
            &keys,
            &index,
            entry_id,
            Owner::ObjectOwner(parent_id.into()),
        );

        let provider = StagedProvider::bag(field_page_response(
            summary100,
            field_entry(stale, proof100, 100, "", vec![]),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);
        let reader = reader.with_changeset_index(Some(index));

        let err = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ReaderError::NotCurrent { .. }), "got {err:?}");
        assert_eq!(
            failure_count(&metrics, "dynamic_field_entry", "not_current"),
            1
        );
    }

    // ===== Regression tests for the verified-read failure modes =====

    /// The `NotFound → cache_fallback` branch of `verified_object` (not the
    /// `verified_anchor_object` short-circuit) is forward-only. After a newer
    /// version has been served (mark at 10), the cache still holding an older v5
    /// must not be served by the fallback: `cache_fallback` re-runs the
    /// high-water check (`record_high_water(_, v5)` fails since 5 < 10) and
    /// returns `None`, so the read surfaces the upstream `NotFound` rather than
    /// the stale v5. This is the `verified_object` analogue of
    /// `anchor_fallback_rejects_a_cached_version_below_high_water`.
    #[tokio::test]
    async fn cache_fallback_on_notfound_rejects_below_high_water() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee.clone())))
                .unwrap(),
        );
        let metrics = OcsMetrics::new_for_testing();
        let reader = OcsVerifiedReader::new(
            Arc::new(PrunedProvider), // network reach-back fails NotFound
            committees,
            metrics.clone(),
            None,
            Arc::new(VerifiedStateCache::new()),
            true, // cache_first (sui-state-direct) — enables the NotFound fallback
            None, // no staleness tripwire: isolate the cache_fallback high-water gate
        );

        // Cache holds id@v5 at seq 42.
        let id = ObjectID::from_single_byte(0x55);
        let stale = test_object(id, 5, address_owner(0x02));
        let (summary, proof) = sign_inclusion(&committee, &keys, 42, &[&stale], &stale);
        let entry = VerifiedObjectEntry {
            object: stale,
            checkpoint_seq: 42,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        reader.cache.absorb_entries(&summary, &[entry]);

        // A newer version (10) was already served: the mark is ahead of the cached v5.
        reader
            .record_high_water(id, SequenceNumber::from(10u64))
            .unwrap();

        // verified_object: the provider answers NotFound, so we hit the
        // NotFound→cache_fallback branch. cache_fallback consults high-water,
        // which rejects v5 (< 10) and returns None — so the read surfaces the
        // original NotFound, never the stale v5.
        let err = reader.verified_object(id).await.unwrap_err();
        assert!(
            matches!(err, ReaderError::Transport(TransportError::NotFound(_))),
            "fallback must reject the below-high-water v5 and surface NotFound; got {err:?}"
        );

        // Nothing was served from the cache for this id.
        assert_eq!(
            metrics
                .cache_read_total
                .with_label_values(&["fallback"])
                .get(),
            0,
            "the NotFound fallback must not have served the stale snapshot"
        );

        // The mark is untouched at 10: re-asserting 10 succeeds, v5 still fails.
        reader
            .record_high_water(id, SequenceNumber::from(10u64))
            .unwrap();
        assert!(matches!(
            reader.record_high_water(id, SequenceNumber::from(5u64)),
            Err(ReaderError::StaleVersion { .. })
        ));
    }

    /// The cache-first staleness tripwire in `try_cache_hit` is
    /// `upstream.saturating_sub(cache_head) > bound`, with the `cache_first_stale_total`
    /// counter moving iff the tripwire fires. Three regimes, with an empty cache
    /// (so a non-tripped read still misses on absence, never serving state — the
    /// counter is the sole signal of whether the tripwire itself fired):
    ///   (a) bound 0: gap 0 (upstream == cache_head) passes; any positive gap trips.
    ///   (b) gap exactly == bound passes; gap == bound + 1 trips.
    ///   (c) cache_head > upstream saturates the gap to 0, which never trips.
    #[tokio::test]
    async fn staleness_tripwire_boundary_and_saturation() {
        let id = ObjectID::from_single_byte(0x07);

        // (a) bound == 0: only a zero gap (cache fully caught up) passes.
        let (_dir, reader) = test_reader_cache_first(0);
        reader.note_upstream_head(500);
        reader.cache.note_processed(500); // gap 0 == bound 0 → no trip
        let before = reader.metrics.cache_first_stale_total.get();
        assert!(
            reader.try_cache_hit(id).is_none(),
            "empty cache → plain miss"
        );
        assert_eq!(
            reader.metrics.cache_first_stale_total.get(),
            before,
            "bound 0, gap 0 (upstream == cache_head): tripwire must stay closed"
        );
        // Now make the cache lag by one: gap 1 > bound 0 → trips.
        reader.note_upstream_head(501);
        assert!(reader.try_cache_hit(id).is_none());
        assert_eq!(
            reader.metrics.cache_first_stale_total.get(),
            before + 1,
            "bound 0, gap 1: tripwire must fire exactly once"
        );

        // (b) gap exactly == bound passes; gap == bound + 1 trips.
        let bound = 100u64;
        let (_dir2, reader2) = test_reader_cache_first(bound);
        reader2.note_upstream_head(1000);
        reader2.cache.note_processed(1000 - bound); // gap == bound → no trip
        let before2 = reader2.metrics.cache_first_stale_total.get();
        assert!(reader2.try_cache_hit(id).is_none());
        assert_eq!(
            reader2.metrics.cache_first_stale_total.get(),
            before2,
            "gap == bound is the boundary, still fresh: tripwire must stay closed"
        );
        // One checkpoint further behind: gap == bound + 1 → trips.
        reader2.cache.note_processed(1000 - bound); // monotonic; stays at 900
        reader2.note_upstream_head(1001); // gap now 101 == bound + 1
        assert!(reader2.try_cache_hit(id).is_none());
        assert_eq!(
            reader2.metrics.cache_first_stale_total.get(),
            before2 + 1,
            "gap == bound + 1 is the first stale: tripwire must fire exactly once"
        );

        // (c) cache_head > upstream: the gap saturates to 0 and never trips,
        // even though the cache head is "ahead" of the observed head.
        let (_dir3, reader3) = test_reader_cache_first(0);
        reader3.note_upstream_head(50);
        reader3.cache.note_processed(200); // cache_head 200 > upstream 50
        let before3 = reader3.metrics.cache_first_stale_total.get();
        assert!(reader3.try_cache_hit(id).is_none());
        assert_eq!(
            reader3.metrics.cache_first_stale_total.get(),
            before3,
            "cache_head > upstream saturates to 0: tripwire must not fire"
        );
    }

    /// A batch read is all-or-nothing per the contract that requested ids must
    /// exist: one bad entry fails the whole `verified_objects` call with `Err`
    /// and yields no partial `Vec`, while the per-entry failure counter moves.
    /// Two failure modes:
    ///   - a rolled-back entry (currency `Stale`) → `NotCurrent`;
    ///   - a batch slot carrying a *different* object id than requested →
    ///     `InvalidProof` (the id-binding check), before any proof verify.
    #[tokio::test]
    async fn batch_fails_on_first_bad_entry_and_serves_no_partial_results() {
        // --- a rolled-back second entry fails the batch (no partial Vec) ---
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id_a = ObjectID::from_single_byte(0x21);
        let id_b = ObjectID::from_single_byte(0x22);

        // Both objects are proven at the same checkpoint 100 (one shared
        // summary committing to both leaves, so each entry's own inclusion proof
        // verifies against it). The index folds 100 = {a@v7, b@v7} then 101 =
        // {b@v8}: so `a`'s last modification is its anchor 100 (`Current`),
        // while `b` was modified again at 101 — a rollback the relay is replaying
        // (`Stale`). `a` is processed first and passes; `b` then fails the batch.
        let a_v7 = test_object(id_a, 7, address_owner(0xAA));
        let b_v7 = test_object(id_b, 7, address_owner(0xBB));
        let (summary100, proof_a) = sign_inclusion(&committee, &keys, 100, &[&a_v7, &b_v7], &a_v7);
        let proof_b = ModifiedObjectTree::new(&CheckpointArtifacts::from_object_states(
            object_states_of(&[&a_v7, &b_v7]),
        ))
        .expect("modified object tree")
        .get_inclusion_proof(b_v7.compute_object_reference())
        .expect("inclusion proof for b");

        let index: SharedChangesetIndex = Arc::new(RwLock::new(ChangesetIndex::new()));
        let digest100 = summary100.data().digest();
        // Fold 100 = {a@v7, b@v7}: a's last_seq becomes 100, b's becomes 100.
        index
            .write()
            .absorb(&summary100, object_states_of(&[&a_v7, &b_v7]))
            .unwrap();
        // Fold 101 = {b@v8}: bumps b's last_seq to 101 (a stays at 100).
        let b_v8 = test_object(id_b, 8, address_owner(0xBB));
        let states101 = object_states_of(&[&b_v8]);
        let summary101 = chained_summary(&committee, &keys, 101, Some(digest100), &states101);
        index.write().absorb(&summary101, states101).unwrap();

        let entry_a = field_entry(a_v7, proof_a, 100, "", vec![]);
        let entry_b = field_entry(b_v7, proof_b, 100, "", vec![]);
        let resp = BatchVerifiedObjectsResponse {
            summaries: BTreeMap::from([(100, summary100)]),
            results: vec![Some(entry_a), Some(entry_b)],
            claimed_latest_checkpoint_seq: 101,
        };
        let provider = StagedProvider::batch(resp);
        let (_dir, reader, metrics) = reader_with(provider, committee.clone(), None);
        let reader = reader.with_changeset_index(Some(index));

        let result = reader.verified_objects(&[id_a, id_b]).await;
        let err = result.expect_err("a rolled-back entry must fail the whole batch");
        assert!(matches!(err, ReaderError::NotCurrent { .. }), "got {err:?}");
        assert_eq!(failure_count(&metrics, "batch_objects", "not_current"), 1);

        // --- a slot carrying the wrong object id fails the batch ---
        let (committee2, keys2) = SuiCommittee::new_simple_test_committee();
        let requested = ObjectID::from_single_byte(0x31);
        let wrong = ObjectID::from_single_byte(0x32);
        let wrong_obj = test_object(wrong, 1, address_owner(0xAA));
        let (summary2, proof2) =
            sign_inclusion(&committee2, &keys2, 100, &[&wrong_obj], &wrong_obj);
        let resp2 = batch_response(
            summary2,
            field_entry(wrong_obj, proof2, 100, "", vec![]),
            100,
        );
        let provider2 = StagedProvider::batch(resp2);
        let (_dir2, reader2, metrics2) = reader_with(provider2, committee2, None);

        let err2 = reader2
            .verified_objects(&[requested])
            .await
            .expect_err("a slot carrying a foreign object id must fail the batch");
        assert!(matches!(err2, ReaderError::InvalidProof(_)), "got {err2:?}");
        assert_eq!(
            failure_count(&metrics2, "batch_objects", "invalid_proof"),
            1
        );
    }

    /// A batch response whose `summaries` map omits the seq an entry references
    /// is a `Decode` failure: the entry can't be checked against any verified
    /// summary, so the whole batch fails (no entry served) and the decode
    /// failure counter moves.
    #[tokio::test]
    async fn batch_missing_summary_for_an_entry_is_a_decode_error() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 7, address_owner(0xAA));
        // The entry references seq 100, but the summaries map is keyed at 999.
        let (summary, proof) = sign_inclusion(&committee, &keys, 100, &[&object], &object);
        let resp = BatchVerifiedObjectsResponse {
            summaries: BTreeMap::from([(999u64, summary)]),
            results: vec![Some(field_entry(object, proof, 100, "", vec![]))],
            claimed_latest_checkpoint_seq: 100,
        };
        let provider = StagedProvider::batch(resp);
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_objects(&[id])
            .await
            .expect_err("a missing summary for the entry's seq must fail the batch");
        match err {
            ReaderError::Decode(msg) => assert!(
                msg.contains("missing summary"),
                "expected the missing-summary decode error, got {msg:?}"
            ),
            other => panic!("expected Decode, got {other:?}"),
        }
        assert_eq!(failure_count(&metrics, "batch_objects", "decode"), 1);
    }

    /// The bag-membership binding derives the `Field<Wrapper<K>, ID>` wrapper id
    /// from the entry's `dynamic_field_name_type`. A malformed type string fails
    /// to parse as a `TypeTag`, so `derive_object_field_wrapper_id` returns
    /// `None` and the wrapper branch can't match; with the entry object-owned by
    /// a non-bag id, the binding fails with `DynamicFieldMembership` and the failure
    /// counter moves.
    #[tokio::test]
    async fn bag_binding_rejects_a_malformed_dynamic_field_key_type() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let parent_id = ObjectID::from_single_byte(0x55);
        let entry_id = ObjectID::from_single_byte(0x56);
        // Object-owned by a non-bag id: the direct `owner_id == parent_id` branch
        // fails, so the binding falls through to the wrapper-id derivation.
        let foreign_id = ObjectID::from_single_byte(0x77);
        let object = test_object(entry_id, 1, Owner::ObjectOwner(foreign_id.into()));
        let (summary, proof) = sign_inclusion(&committee, &keys, 100, &[&object], &object);

        // A malformed name type: `TypeTag::from_str` fails → derivation None.
        let bad_type = "not a valid type";
        assert!(
            derive_object_field_wrapper_id(parent_id, bad_type, &bcs::to_bytes(&7u64).unwrap())
                .is_none(),
            "the malformed type must make the wrapper-id derivation return None"
        );
        let provider = StagedProvider::bag(field_page_response(
            summary,
            field_entry(object, proof, 100, bad_type, bcs::to_bytes(&7u64).unwrap()),
            100,
        ));
        let (_dir, reader, metrics) = reader_with(provider, committee, None);

        let err = reader
            .verified_dynamic_fields_page(parent_id, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReaderError::DynamicFieldMembership { .. }),
            "got {err:?}"
        );
        assert_eq!(
            failure_count(&metrics, "dynamic_field_entry", "dynamic_field_membership"),
            1
        );
    }

    /// `clone_inclusion_proof` is a bcs round-trip: the cloned proof must
    /// serialize byte-for-byte identically to the original, and a cloned proof
    /// must still verify against its committee-signed summary — so the cache
    /// stores a faithful copy of exactly the proof the verifier accepted.
    #[tokio::test]
    async fn clone_inclusion_proof_round_trips_identically() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0x21);
        let object = test_object(id, 7, address_owner(0xAA));
        let (summary, proof) = sign_inclusion(&committee, &keys, 100, &[&object], &object);

        let clone = clone_inclusion_proof(&proof).expect("a valid proof must clone");
        assert_eq!(
            bcs::to_bytes(&clone).unwrap(),
            bcs::to_bytes(&proof).unwrap(),
            "the clone must serialize byte-for-byte identically to the original"
        );

        // The cloned proof still verifies against the same committee + summary.
        let (_dir, reader, _metrics) = reader_with(Arc::new(UnusedProvider), committee, None);
        reader
            .verify_proof_inner(&object, clone, summary)
            .expect("the cloned proof must still verify");
    }

    /// `forget_high_water` (currently unused in prod) clears an id's mark so a
    /// previously-rejected older version is accepted again. Records v5, confirms
    /// v3 is a `StaleVersion` rollback, forgets the id, then confirms v3 is
    /// accepted — documenting the intended semantics.
    #[tokio::test]
    async fn forget_high_water_re_enables_acceptance() {
        let (_dir, reader) = test_reader(None);
        let id = ObjectID::from_single_byte(0x07);

        reader
            .record_high_water(id, SequenceNumber::from(5u64))
            .unwrap();
        // v3 < mark 5: a rollback, rejected.
        assert!(matches!(
            reader.record_high_water(id, SequenceNumber::from(3u64)),
            Err(ReaderError::StaleVersion { .. })
        ));

        // Forget the id: the mark is cleared.
        reader.forget_high_water(&id);

        // v3 is now first-sight again → accepted.
        reader
            .record_high_water(id, SequenceNumber::from(3u64))
            .expect("after forgetting, the previously-rejected v3 must be accepted");
    }
}
