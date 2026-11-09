// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-validator cache of OCS-verified Ika state.
//!
//! On `sui-state-direct`, populated by `IkaCheckpointPusher` as it folds
//! each Ika-relevant checkpoint's modified objects (with inclusion proofs)
//! via `absorb_entries`. On `sui-state-mirrored` it is a read-through memo
//! populated by the reader's own per-read-verified relay reads.
//!
//! # What the cache stores
//!
//! For each `ObjectID`, the latest `VerifiedSnapshot { object, proof,
//! summary, source_checkpoint_seq }` we've seen. Plus a parent →
//! children index so verified bag walks resolve from the cache without
//! a network call.
//!
//! Bounded by a retain window ([`VerifiedStateCache::with_retain_window`]):
//! object snapshots more than `window` checkpoints behind the head are pruned
//! from both the in-memory maps and the persisted column. The window prunes
//! freely. The direct proof provider can also reuse an exact-current snapshot
//! when the source checkpoint has been pruned; if the snapshot has aged out,
//! that fallback is unavailable and the provider retries its normal source. The
//! *served* end-of-epoch checkpoint summaries are retained deeper — back to the
//! oldest committee-verifiable anchor — because a mirrored peer's committee
//! ratchet can't re-derive a pruned one. Tombstone eviction on on-chain
//! deletion is not yet implemented, but the retain window bounds growth
//! regardless.
//!
//! # Pinned checkpoints
//!
//! A snapshot whose source checkpoint is in the pinned set is never pruned. The
//! set is the checkpoints the pusher backfills from the archive: checkpoints
//! already pruned upstream whose objects were never folded, typically far older
//! than the window, so without the pin the next sweep would drop exactly the
//! snapshot the backfill exists to provide. Two sources feed it: the operator's
//! `sui-checkpoint-archive-backfill` list, and the checkpoints the pusher
//! itself gave up on and recorded in the perpetual `sui_pusher_lost_checkpoints`
//! table (see `push_worker::LostCheckpoint`).
//!
//! Lifetime. The pin belongs to the snapshot, not to the object id: absorbing a
//! newer version of the object replaces the snapshot, whose source checkpoint
//! is then the newer one, so the object is unpinned and ages out with the
//! window as usual. The cache persists nothing pin-specific: the pinned set is
//! applied when the cache is built ([`VerifiedStateCache::with_pinned_checkpoints`],
//! from the config list and the recorded lost checkpoints), before the first
//! absorb and therefore before the first sweep, and it matches the persisted
//! snapshots by their stored source checkpoint. At runtime the pusher pins a
//! checkpoint as it records it ([`VerifiedStateCache::pin_checkpoint`]) and
//! unpins it once its record is collected
//! ([`VerifiedStateCache::unpin_checkpoint`]) — when no snapshot from it is left,
//! so nothing is released. Removing a sequence from the operator's config list
//! releases its snapshots to the next sweep.
//!
//! Deletion. Without tombstones, an object deleted or wrapped on chain keeps its
//! last snapshot; a pinned one keeps it while its sequence stays pinned. The
//! growth is bounded by the Ika objects of the pinned checkpoints. Such a
//! snapshot is not served as a live bag entry: direct bag walks list children
//! from the node's own fullnode, and the proof provider reuses a snapshot only
//! when the fullnode reports the identical current object reference. A direct
//! cache-first read of that exact object id would still return it — the same
//! exposure every deleted object already has until the window prunes it.
//!
//! # Pinned objects: the singleton anchors
//!
//! A snapshot whose object id is in the pinned-object set
//! ([`VerifiedStateCache::with_pinned_objects`]) is never pruned either. On a
//! direct node the set is the singleton anchors — the `System` and
//! `DWalletCoordinator` objects and the versioned-child inner of each, for every
//! inner version this binary decodes (`verified_reader::singleton_anchor_ids`).
//! The cache holds one snapshot per id, so pinning by id keeps exactly the
//! latest one. These objects are written only by the transactions that touch
//! them, and the `System` inner can go unwritten for longer than the window
//! when an epoch stalls; the pre-consensus `System` read needs that snapshot,
//! and without the pin the sweep would evict it while it is still the latest
//! version. The ids derive from the configured object ids, so the set is
//! recomputed identically at every boot, before the first sweep; it covers
//! every decodable inner version, so a `migrate()` that moves the inner to a
//! new version (a new id) is already covered. The retired inner is deleted on
//! chain and keeps its last snapshot — one object per anchor and version.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ika_network::proof_provider::{ProofSnapshotCache, VerifiedObjectEntry};
use ika_types::error::IkaResult;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sui_light_client::proof::ocs::OCSInclusionProof;
use sui_types::base_types::ObjectID;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::{Object, Owner};
use tracing::{info, warn};
use typed_store::TypedStoreError;

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;

/// One verified Ika object, frozen at the checkpoint that last modified it.
///
/// `OCSInclusionProof` is not `Clone`, so this struct's `Clone` goes
/// through `bcs` for the proof field. Costs O(proof depth) bytes per
/// clone — negligible relative to the network round-trip we're avoiding.
/// `Serialize`/`Deserialize` (each field is already bcs-encodable — the proof
/// round-trips through bcs in `clone_proof`) let it persist directly into the
/// perpetual `verified_object_cache` column so the cache survives a restart.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedSnapshot {
    pub object: Object,
    pub proof: OCSInclusionProof,
    pub summary: CertifiedCheckpointSummary,
    pub source_checkpoint_seq: CheckpointSequenceNumber,
}

impl Clone for VerifiedSnapshot {
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            proof: clone_proof(&self.proof),
            summary: self.summary.clone(),
            source_checkpoint_seq: self.source_checkpoint_seq,
        }
    }
}

pub struct VerifiedStateCache {
    objects: RwLock<HashMap<ObjectID, VerifiedSnapshot>>,
    /// Parent `ObjectID` → set of dynamic-field child ids whose owner
    /// resolves to that parent. Maintained on every `insert`. Rebuilt from the
    /// persisted objects on `open` (derived from each object's owner — not
    /// itself persisted).
    children: RwLock<HashMap<ObjectID, BTreeSet<ObjectID>>>,
    /// Highest checkpoint seq whose state we've folded in.
    head_seq: AtomicU64,
    /// Highest checkpoint the populating worker has *processed* (folded, or
    /// streamed past as non-Ika), as opposed to [`Self::head_seq`] which only
    /// advances on a fold. During a quiet stretch with no Ika modifications the
    /// fold head stalls while this keeps tracking the tip — letting the reader's
    /// staleness tripwire tell "pusher is current, just nothing Ika-relevant
    /// lately" apart from "pusher is actually behind". Liveness-only, not
    /// persisted (the worker re-establishes it from its cursor on restart).
    processed_head_seq: AtomicU64,
    /// When `Some`, the cache is durable: every `absorb_entries` writes the
    /// folded snapshots (and the head) through to the perpetual
    /// `verified_object_cache` column, and `open` rehydrates from it on boot —
    /// so a restart resumes from DB instead of re-fetching from the (possibly
    /// pruned) Sui fullnode. `None` is an in-memory-only cache (`new`, for
    /// tests / `Default`).
    perpetual: Option<Arc<AuthorityPerpetualTables>>,
    /// Drop object snapshots whose source checkpoint fell more than this many
    /// checkpoints behind the head. (The *served* end-of-epoch checkpoints are
    /// retained deeper — back to the anchor — see `eop_retention_floor`.)
    /// `None` = unbounded. Set via [`Self::with_retain_window`].
    retain_window: Option<u64>,
    /// Floor (`head - window`) at the last prune sweep; the next sweep waits
    /// until the floor rises a stride, so the sweep is amortized O(1) per absorb.
    last_pruned_floor: AtomicU64,
    /// Source checkpoints whose snapshots the retain-window sweep keeps (see
    /// the module docs). Set via [`Self::with_pinned_checkpoints`] and changed
    /// at runtime by [`Self::pin_checkpoint`] / [`Self::unpin_checkpoint`].
    pinned_checkpoints: RwLock<BTreeSet<CheckpointSequenceNumber>>,
    /// Object ids whose snapshot the retain-window sweep keeps regardless of
    /// age: the singleton anchors (see the module docs). Set via
    /// [`Self::with_pinned_objects`].
    pinned_objects: BTreeSet<ObjectID>,
}

impl VerifiedStateCache {
    /// In-memory-only cache (no persistence). Use [`Self::open`] in production
    /// so the cache survives restarts.
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            head_seq: AtomicU64::new(0),
            processed_head_seq: AtomicU64::new(0),
            perpetual: None,
            retain_window: None,
            last_pruned_floor: AtomicU64::new(0),
            pinned_checkpoints: RwLock::new(BTreeSet::new()),
            pinned_objects: BTreeSet::new(),
        }
    }

    /// Keep every snapshot whose source checkpoint is in `checkpoints` out of
    /// the retain-window sweep (see the module docs for the pin's lifetime).
    /// Must be applied before the first absorb: the first absorb after a boot
    /// runs a sweep.
    pub fn with_pinned_checkpoints(self, checkpoints: BTreeSet<CheckpointSequenceNumber>) -> Self {
        *self.pinned_checkpoints.write() = checkpoints;
        self
    }

    /// Keep the snapshot of every object id in `ids` out of the retain-window
    /// sweep, whatever its age — the singleton anchors (see the module docs).
    /// Must be applied before the first absorb, like
    /// [`Self::with_pinned_checkpoints`].
    pub fn with_pinned_objects(mut self, ids: BTreeSet<ObjectID>) -> Self {
        self.pinned_objects = ids;
        self
    }

    /// Pin `seq` from now on: the next sweep keeps its snapshots. For a
    /// checkpoint the pusher records as lost, pinned before its backfill can
    /// fold anything.
    pub fn pin_checkpoint(&self, seq: CheckpointSequenceNumber) {
        self.pinned_checkpoints.write().insert(seq);
    }

    /// Release `seq` to the sweep. The pusher calls it only once no snapshot
    /// from `seq` is left in the cache, so it releases nothing current.
    pub fn unpin_checkpoint(&self, seq: CheckpointSequenceNumber) {
        self.pinned_checkpoints.write().remove(&seq);
    }

    pub fn is_checkpoint_pinned(&self, seq: CheckpointSequenceNumber) -> bool {
        self.pinned_checkpoints.read().contains(&seq)
    }

    /// Number of cached snapshots whose source checkpoint is `seq`.
    pub fn snapshots_from_checkpoint(&self, seq: CheckpointSequenceNumber) -> usize {
        self.objects
            .read()
            .values()
            .filter(|snapshot| snapshot.source_checkpoint_seq == seq)
            .count()
    }

    /// The members of `seqs` that are the source checkpoint of at least one
    /// cached snapshot. One pass over the cache, for checking many
    /// checkpoints at once.
    pub fn checkpoints_with_snapshots(
        &self,
        seqs: &BTreeSet<CheckpointSequenceNumber>,
    ) -> BTreeSet<CheckpointSequenceNumber> {
        if seqs.is_empty() {
            return BTreeSet::new();
        }
        self.objects
            .read()
            .values()
            .map(|snapshot| snapshot.source_checkpoint_seq)
            .filter(|seq| seqs.contains(seq))
            .collect()
    }

    /// Bound the object cache to snapshots within `window` checkpoints of the
    /// head (`None` = unbounded). The sweep is amortized — it only runs once the
    /// floor rises a stride. (`ChangesetIndex` has its own, separate retain
    /// window for the currency stream; this one governs only the verified-object
    /// snapshots.)
    pub fn with_retain_window(mut self, window: Option<u64>) -> Self {
        self.retain_window = window;
        self
    }

    /// Durable cache: rehydrate the in-memory maps from the persisted
    /// `verified_object_cache` column (rebuilding the parent→children index
    /// from each object's owner) and restore the folded head, then write
    /// through every subsequent absorb. A restart therefore resumes serving
    /// from DB without reaching back to the Sui fullnode.
    pub fn open(perpetual: Arc<AuthorityPerpetualTables>) -> IkaResult<Self> {
        let persisted = match perpetual.load_verified_object_cache() {
            Ok(persisted) => persisted,
            // A (de)serialization failure means the on-disk snapshots are from a
            // stale format — typically after a Sui version upgrade changed the
            // BCS layout of `Object` / `CertifiedCheckpointSummary`. Rather than
            // halt the node on boot, wipe the rebuildable direct-cache columns
            // and start cold: the pusher re-folds every object from the node's
            // own (re-verified) Sui access, so no trust is lost — only the
            // restart-resume optimization is paid for once. A transient RocksDB
            // IO error is NOT format rot and still propagates. (Release-build
            // behavior; in debug, `safe_iter`'s `debug_fatal!` panics first,
            // which is an acceptable loud dev signal.)
            Err(TypedStoreError::SerializationError(reason)) => {
                warn!(
                    reason,
                    "verified object cache could not be deserialized (likely a Sui \
                     version upgrade changed the on-disk format); wiping the \
                     rebuildable direct-cache columns and rebuilding from the fullnode"
                );
                perpetual.reset_direct_cache_for_format_recovery()?;
                Vec::new()
            }
            Err(e) => return Err(e.into()),
        };
        let head = perpetual.get_verified_object_cache_head()?.unwrap_or(0);
        let objects_count = persisted.len();
        let mut objects = HashMap::with_capacity(objects_count);
        let mut children: HashMap<ObjectID, BTreeSet<ObjectID>> = HashMap::new();
        for (id, snapshot) in persisted {
            if let Some(parent) = parent_id(&snapshot.object) {
                children.entry(parent).or_default().insert(id);
            }
            objects.insert(id, snapshot);
        }
        info!(
            objects = objects_count,
            head, "opened verified state cache from perpetual tables"
        );
        Ok(Self {
            objects: RwLock::new(objects),
            children: RwLock::new(children),
            head_seq: AtomicU64::new(head),
            // Floor only; the worker bumps it to its real cursor on the first
            // tick. Starting at the fold head avoids a spurious early tripwire.
            processed_head_seq: AtomicU64::new(head),
            perpetual: Some(perpetual),
            retain_window: None,
            last_pruned_floor: AtomicU64::new(0),
            pinned_checkpoints: RwLock::new(BTreeSet::new()),
            pinned_objects: BTreeSet::new(),
        })
    }

    pub fn get(&self, id: ObjectID) -> Option<VerifiedSnapshot> {
        self.objects.read().get(&id).cloned()
    }

    /// Snapshot of the current children of `parent_id`. Order is
    /// arbitrary; callers that care should sort.
    pub fn children_of(&self, parent_id: ObjectID) -> Vec<ObjectID> {
        self.children
            .read()
            .get(&parent_id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn head_seq(&self) -> CheckpointSequenceNumber {
        self.head_seq.load(Ordering::Relaxed)
    }

    /// Record that the populating worker has processed up to `seq` (whether or
    /// not anything was folded there). Monotonic. See [`Self::processed_head_seq`].
    pub fn note_processed(&self, seq: CheckpointSequenceNumber) {
        self.processed_head_seq.fetch_max(seq, Ordering::Relaxed);
    }

    pub fn processed_head_seq(&self) -> CheckpointSequenceNumber {
        self.processed_head_seq.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.objects.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.read().is_empty()
    }

    /// Fold every `(object, proof)` from one checkpoint into the cache, as the
    /// in-order **pusher**: persists the folded snapshots through to DB. Updates
    /// the parent→children index from each object's owner and bumps `head_seq`
    /// to the summary's sequence (monotonically). The caller is responsible for
    /// having verified each entry against `summary` first.
    pub fn absorb_entries(
        &self,
        summary: &CertifiedCheckpointSummary,
        entries: &[VerifiedObjectEntry],
    ) {
        self.absorb_entries_inner(summary, entries, true);
    }

    /// Like [`Self::absorb_entries`] but for a reader's out-of-band "shadow"
    /// cache-write of a network-verified object: it does NOT persist. On a direct
    /// node the single-threaded, in-order pusher owns persistence; a reader folds
    /// objects it just read at arbitrary (possibly newer-than-the-pusher)
    /// checkpoints, so letting it persist would race the pusher and could write
    /// the cache head ahead of the durably-folded objects (see [`Self::persist`]).
    /// The pusher re-folds and persists the object in order anyway. On a mirrored
    /// node persistence is off (`perpetual` is `None`), so this is identical to
    /// `absorb_entries` there.
    pub fn absorb_shadow_entries(
        &self,
        summary: &CertifiedCheckpointSummary,
        entries: &[VerifiedObjectEntry],
    ) {
        self.absorb_entries_inner(summary, entries, false);
    }

    fn absorb_entries_inner(
        &self,
        summary: &CertifiedCheckpointSummary,
        entries: &[VerifiedObjectEntry],
        persist: bool,
    ) {
        let source_seq = *summary.sequence_number();
        let mut inserted_ids = Vec::new();
        for entry in entries {
            if self.insert_inner(entry, summary, source_seq) {
                inserted_ids.push(entry.object.id());
            }
        }
        self.advance_head(source_seq);
        // Folding `source_seq` means it was processed; keep the invariant
        // processed_head >= fold head even without a separate worker callback
        // (e.g. the reader's own network-read folds, and direct-cache tests).
        self.note_processed(source_seq);
        if persist {
            // Persist `source_seq` (this fold's own seq), never the shared
            // `head_seq()`: a concurrent reader shadow-write can bump `head_seq`
            // past what is durably folded.
            self.persist(&inserted_ids, source_seq);
        }
        self.maybe_prune();
    }

    /// Object-snapshot retention floor: `head - retain_window`. Snapshots whose
    /// source checkpoint is older than this are dropped. `None` when pruning is
    /// disabled.
    ///
    /// Deliberately **not** clamped to the bootstrap anchor. This cache backs
    /// both the direct node's cache-first reads and the proof provider's
    /// exact-current fallback after upstream pruning. A snapshot older than the
    /// window intentionally loses that fallback and returns to the normal
    /// gRPC proof path. Clamping the floor down to the (slow-moving) anchor
    /// would pin it below `head - window` forever, so the window would never
    /// prune and the cache would leak one entry per distinct object id. The
    /// anchor clamp belongs only on [`Self::eop_retention_floor`], whose
    /// checkpoints a mirrored peer's ratchet genuinely can't re-derive.
    fn prune_floor(&self) -> Option<CheckpointSequenceNumber> {
        Some(self.head_seq().saturating_sub(self.retain_window?))
    }

    /// Retention floor for the *served* end-of-epoch checkpoint summaries: the
    /// object floor, but never above the oldest committee-verifiable checkpoint.
    /// A pruned end-of-epoch checkpoint can't be re-derived for a relayed
    /// bootstrap, so a mirrored peer ratcheting its committee from that anchor
    /// still needs every summary from there forward (a bounded O(epochs) set,
    /// unlike the per-object cache). `None` when pruning is disabled.
    fn eop_retention_floor(&self) -> Option<CheckpointSequenceNumber> {
        let mut floor = self.prune_floor()?;
        if let Some(perpetual) = &self.perpetual
            && let Ok(Some(oldest)) = perpetual.oldest_sui_committee_summary()
        {
            floor = floor.min(*oldest.sequence_number());
        }
        Some(floor)
    }

    /// Amortized sweep: prune only once the floor has risen by a stride, so the
    /// cache over-retains by less than a stride and the O(n) sweep runs rarely.
    fn maybe_prune(&self) {
        let Some(floor) = self.prune_floor() else {
            return;
        };
        let stride = (self.retain_window.unwrap_or(0) / 8).max(1);
        if floor
            < self
                .last_pruned_floor
                .load(Ordering::Relaxed)
                .saturating_add(stride)
        {
            return;
        }
        self.prune(floor);
        self.last_pruned_floor.store(floor, Ordering::Relaxed);
    }

    /// Drop every snapshot last modified before `floor` from the in-memory maps
    /// and the persisted column, keeping the parent→children index consistent.
    /// Snapshots from a pinned checkpoint, and the snapshot of a pinned object,
    /// are kept regardless of `floor`.
    fn prune(&self, floor: CheckpointSequenceNumber) {
        // Retained end-of-epoch checkpoints are served to mirrored peers for
        // their committee ratchet, so they're kept back to the bootstrap anchor
        // — a deeper floor than the object cache (see `eop_retention_floor`) —
        // pruned on the same amortized schedule.
        if let (Some(perpetual), Some(eop_floor)) = (&self.perpetual, self.eop_retention_floor())
            && let Err(e) = perpetual.retain_sui_end_of_epoch_checkpoints(eop_floor)
        {
            warn!(error = ?e, "failed to prune retained end-of-epoch checkpoints");
        }
        let removed: Vec<(ObjectID, Option<ObjectID>)> = {
            let pinned_checkpoints = self.pinned_checkpoints.read();
            let mut objects = self.objects.write();
            let mut removed = Vec::new();
            objects.retain(|id, snap| {
                if snap.source_checkpoint_seq < floor
                    && !pinned_checkpoints.contains(&snap.source_checkpoint_seq)
                    && !self.pinned_objects.contains(id)
                {
                    removed.push((*id, parent_id(&snap.object)));
                    false
                } else {
                    true
                }
            });
            removed
        };
        if removed.is_empty() {
            return;
        }
        {
            let mut children = self.children.write();
            for (id, parent) in &removed {
                if let Some(parent) = parent
                    && let Some(set) = children.get_mut(parent)
                {
                    set.remove(id);
                    if set.is_empty() {
                        children.remove(parent);
                    }
                }
            }
        }
        if let Some(perpetual) = &self.perpetual {
            let keys: Vec<ObjectID> = removed.iter().map(|(id, _)| *id).collect();
            if let Err(e) = perpetual.delete_verified_object_cache_keys(&keys) {
                warn!(error = ?e, "failed to prune persisted verified cache");
            }
        }
        info!(
            removed = removed.len(),
            floor, "pruned verified state cache"
        );
    }

    /// Write the just-folded snapshots through to the perpetual
    /// `verified_object_cache` column in one batch, with the cache head set to
    /// `head`, so the cache survives a restart. No-op for an in-memory-only
    /// cache. Best-effort: a DB error is logged, not propagated — the in-memory
    /// cache stays authoritative for the running process and the next absorb
    /// re-persists.
    ///
    /// `head` MUST be the caller's own in-order fold seq (the pusher's
    /// `source_seq`), NOT the shared `head_seq()` atomic. A concurrent reader
    /// shadow-write can bump `head_seq` to an object it just read at a
    /// newer-than-the-pusher checkpoint; persisting that here would write a head
    /// ahead of the objects actually durably folded, so a crash at that instant
    /// would leave the restored cache claiming a freshness it doesn't have (the
    /// staleness tripwire then under-fires). Only the single-threaded pusher
    /// persists (reader shadow-writes use `absorb_shadow_entries`); its scan
    /// is in-order, but a pending-gap checkpoint folds LATE with its own
    /// older seq, so the persisted head write is max-semantics in
    /// `write_verified_object_cache` — a per-call `source_seq` never
    /// overstates, and the persisted head never regresses.
    fn persist(&self, inserted_ids: &[ObjectID], head: CheckpointSequenceNumber) {
        let Some(perpetual) = &self.perpetual else {
            return;
        };
        let snapshots: Vec<(ObjectID, VerifiedSnapshot)> = {
            let objects = self.objects.read();
            inserted_ids
                .iter()
                .filter_map(|id| objects.get(id).map(|s| (*id, s.clone())))
                .collect()
        };
        if let Err(e) = perpetual.write_verified_object_cache(snapshots, head) {
            warn!(error = ?e, "failed to persist verified state cache batch");
        }
    }

    /// Returns `true` if the entry was inserted, `false` if skipped as a
    /// version downgrade (so the caller persists only what actually changed).
    fn insert_inner(
        &self,
        entry: &VerifiedObjectEntry,
        summary: &CertifiedCheckpointSummary,
        source_seq: CheckpointSequenceNumber,
    ) -> bool {
        let id = entry.object.id();
        let new_parent = parent_id(&entry.object);
        let new_version = entry.object.version();

        // Monotonic-by-version: never downgrade a cached object. Out-of-order
        // absorbs (a network shadow-write racing a push) could otherwise
        // overwrite a newer cached entry with an older one. The version check
        // and the insert happen under the *same* `objects` write lock so two
        // concurrent absorbs can't interleave check-then-write. On skip we
        // leave the parent→children index untouched — the newer cached object
        // already reflects the correct parent.
        let prior_parent = {
            let mut objects = self.objects.write();
            let prior_parent = match objects.get(&id) {
                Some(existing) => {
                    if new_version < existing.object.version() {
                        return false;
                    }
                    parent_id(&existing.object)
                }
                None => None,
            };
            // BCS-clone the proof; OCSInclusionProof isn't Clone but
            // round-trips through bcs. Costs O(proof depth) bytes per absorb —
            // negligible relative to the network round-trip we're saving.
            let snapshot = VerifiedSnapshot {
                object: entry.object.clone(),
                proof: clone_proof(&entry.proof),
                summary: summary.clone(),
                source_checkpoint_seq: source_seq,
            };
            objects.insert(id, snapshot);
            prior_parent
        };

        // Maintain parent→children (separate lock; we no longer hold `objects`).
        // If this object moved owners since we last cached it, evict from the
        // old parent's set.
        if prior_parent != new_parent {
            if let Some(prev) = prior_parent
                && let Some(set) = self.children.write().get_mut(&prev)
            {
                set.remove(&id);
            }
            if let Some(p) = new_parent {
                self.children.write().entry(p).or_default().insert(id);
            }
        } else if let Some(p) = new_parent {
            // Same parent — still ensure membership (first-seen case).
            self.children.write().entry(p).or_default().insert(id);
        }
        true
    }

    fn advance_head(&self, seq: CheckpointSequenceNumber) {
        let mut current = self.head_seq.load(Ordering::Relaxed);
        while seq > current {
            match self.head_seq.compare_exchange_weak(
                current,
                seq,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(c) => current = c,
            }
        }
    }
}

impl Default for VerifiedStateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofSnapshotCache for VerifiedStateCache {
    fn get_proof_snapshot(
        &self,
        id: ObjectID,
    ) -> Option<(VerifiedObjectEntry, CertifiedCheckpointSummary)> {
        self.get(id).map(|snapshot| {
            let entry = VerifiedObjectEntry {
                object: snapshot.object,
                checkpoint_seq: snapshot.source_checkpoint_seq,
                proof: snapshot.proof,
                dynamic_field_name_type: String::new(),
                dynamic_field_name_bcs: Vec::new(),
            };
            (entry, snapshot.summary)
        })
    }
}

fn parent_id(o: &Object) -> Option<ObjectID> {
    match o.owner() {
        Owner::ObjectOwner(addr) => Some(ObjectID::from(*addr)),
        _ => None,
    }
}

fn clone_proof(p: &OCSInclusionProof) -> OCSInclusionProof {
    let bytes = bcs::to_bytes(p).expect("OCSInclusionProof must serialize");
    bcs::from_bytes(&bytes).expect("OCSInclusionProof round-trip")
}

/// Convenience alias for places that pass the cache through.
pub type SharedVerifiedStateCache = Arc<VerifiedStateCache>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::{ObjectDigest, SequenceNumber};
    use sui_types::committee::Committee as SuiCommittee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointContentsDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointArtifacts, CheckpointCommitment, CheckpointSummary,
    };

    /// A committee-signed summary committing to a one-object tree, plus the
    /// matching inclusion proof, wrapped as a `VerifiedObjectEntry` (mirrors the
    /// real fold input). The proof's validity is irrelevant to the cache — it is
    /// stored verbatim — but building a real one exercises the bcs round-trip.
    fn signed_entry(
        committee: &SuiCommittee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        object: &Object,
    ) -> (CertifiedCheckpointSummary, VerifiedObjectEntry) {
        let (id, version, digest) = object.compute_object_reference();
        let object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> =
            BTreeMap::from([(id, (version, digest))]);
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
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        let proof = ModifiedObjectTree::new(&artifacts)
            .expect("modified object tree")
            .get_inclusion_proof(object.compute_object_reference())
            .expect("inclusion proof");
        let entry = VerifiedObjectEntry {
            object: object.clone(),
            checkpoint_seq: seq,
            proof,
            dynamic_field_name_type: String::new(),
            dynamic_field_name_bcs: Vec::new(),
        };
        (cert, entry)
    }

    /// The processed head tracks the populating worker through quiet stretches
    /// (no Ika fold), independently of the fold head — and a fold never leaves
    /// the processed head trailing the fold head. This is what lets the reader's
    /// staleness tripwire distinguish "current, just nothing Ika lately" from
    /// "actually behind".
    #[tokio::test]
    async fn processed_head_tracks_worker_independently_of_fold_head() {
        let cache = VerifiedStateCache::new();
        assert_eq!(cache.head_seq(), 0);
        assert_eq!(cache.processed_head_seq(), 0);

        // Quiet stretch: the worker streams past up to 500 with nothing to fold.
        cache.note_processed(500);
        assert_eq!(cache.processed_head_seq(), 500);
        assert_eq!(cache.head_seq(), 0, "fold head only moves on a fold");

        // Monotonic: a stale note never lowers it.
        cache.note_processed(400);
        assert_eq!(cache.processed_head_seq(), 500);

        // A fold at 600 advances the fold head and keeps processed head >= it.
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x01),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (summary, entry) = signed_entry(&committee, &keys, 600, &object);
        cache.absorb_entries(&summary, &[entry]);
        assert_eq!(cache.head_seq(), 600);
        assert_eq!(cache.processed_head_seq(), 600);
    }

    #[tokio::test]
    async fn persisted_cache_rehydrates_after_db_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let parent = ObjectID::from_single_byte(0xAB);
        let child = ObjectID::from_single_byte(0xCD);
        let object = Object::with_id_owner_version_for_testing(
            child,
            SequenceNumber::from(3u64),
            Owner::ObjectOwner(parent.into()),
        );
        let (summary, entry) = signed_entry(&committee, &keys, 42, &object);

        // First run: absorb + write-through, then close the cache AND the DB.
        {
            let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
            let cache = VerifiedStateCache::open(perpetual).unwrap();
            assert!(cache.is_empty());
            cache.absorb_entries(&summary, &[entry]);
            assert_eq!(cache.len(), 1);
            assert_eq!(cache.head_seq(), 42);
            assert_eq!(cache.children_of(parent), vec![child]);
        }

        // Restart: reopen the DB from the same dir and rehydrate. Objects, head,
        // and the rebuilt parent→children index all survive without any network.
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let reopened = VerifiedStateCache::open(perpetual).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.head_seq(), 42);
        let snap = reopened
            .get(child)
            .expect("child snapshot survived restart");
        assert_eq!(snap.object.version(), SequenceNumber::from(3u64));
        assert_eq!(snap.source_checkpoint_seq, 42);
        assert_eq!(reopened.children_of(parent), vec![child]);
    }

    #[tokio::test]
    async fn reader_shadow_write_does_not_persist_a_head_ahead_of_the_pusher() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let cache = VerifiedStateCache::open(perpetual.clone()).unwrap();
        let obj = |byte: u8| {
            Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(byte),
                SequenceNumber::from(1u64),
                Owner::AddressOwner(ObjectID::from_single_byte(0xEE).into()),
            )
        };

        // The in-order pusher folds checkpoint 5 → persists head 5.
        let (sum5, e5) = signed_entry(&committee, &keys, 5, &obj(0x01));
        cache.absorb_entries(&sum5, &[e5]);
        assert_eq!(perpetual.get_verified_object_cache_head().unwrap(), Some(5));

        // A reader shadow-writes an object it just read at checkpoint 10 — newer
        // than the pusher. It must NOT advance the *persisted* head past 5: the
        // pusher hasn't durably folded everything through 10, so a crash here must
        // not leave the restored cache claiming freshness to 10 (the N2 race).
        let (sum10, e10) = signed_entry(&committee, &keys, 10, &obj(0x02));
        cache.absorb_shadow_entries(&sum10, &[e10]);
        assert_eq!(
            perpetual.get_verified_object_cache_head().unwrap(),
            Some(5),
            "a reader shadow-write must not persist a head ahead of the in-order pusher"
        );
        // The shadow object is still cached in-memory for the running process.
        assert!(cache.get(ObjectID::from_single_byte(0x02)).is_some());

        // The next in-order pusher fold advances the persisted head normally.
        let (sum11, e11) = signed_entry(&committee, &keys, 11, &obj(0x03));
        cache.absorb_entries(&sum11, &[e11]);
        assert_eq!(
            perpetual.get_verified_object_cache_head().unwrap(),
            Some(11)
        );
    }

    #[tokio::test]
    async fn retain_window_prunes_old_snapshots_in_mem_and_db() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let owner = Owner::AddressOwner(ObjectID::from_single_byte(0x01).into());
        let obj = |byte: u8, version: u64| {
            Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(byte),
                SequenceNumber::from(version),
                owner.clone(),
            )
        };
        let a = obj(0xA1, 1);
        let b = obj(0xB2, 1);
        let c = obj(0xC3, 1);
        let (s_a, e_a) = signed_entry(&committee, &keys, 10, &a);
        let (s_b, e_b) = signed_entry(&committee, &keys, 60, &b);
        let (s_c, e_c) = signed_entry(&committee, &keys, 100, &c);

        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let cache = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(30));
        cache.absorb_entries(&s_a, &[e_a]);
        cache.absorb_entries(&s_b, &[e_b]);
        cache.absorb_entries(&s_c, &[e_c]);

        // head=100, window=30 → floor=70: a(10) and b(60) are pruned, c(100) kept.
        assert_eq!(cache.head_seq(), 100);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(a.id()).is_none());
        assert!(cache.get(b.id()).is_none());
        assert!(cache.get(c.id()).is_some());

        // The persisted column was pruned in place — a reopen sees only c.
        drop(cache);
        let reopened = VerifiedStateCache::open(perpetual).unwrap();
        assert_eq!(reopened.len(), 1);
        assert!(reopened.get(c.id()).is_some());
        assert!(reopened.get(a.id()).is_none());
    }

    /// A snapshot from a pinned checkpoint survives every retain-window sweep,
    /// including the first sweep after a reopen (re-pinned from configuration
    /// before any absorb), while an unpinned snapshot of the same age is
    /// pruned. Reopening without the pin releases it to the next sweep, which
    /// is how a sequence leaving the backfill list stops being retained.
    #[tokio::test]
    async fn pinned_snapshot_survives_prune_sweeps_and_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let parent = ObjectID::from_single_byte(0xBA);
        let obj = |byte: u8| {
            Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(byte),
                SequenceNumber::from(1u64),
                Owner::ObjectOwner(parent.into()),
            )
        };
        let pinned = obj(0xA1);
        let unpinned = obj(0xB2);
        let (s_pinned, e_pinned) = signed_entry(&committee, &keys, 10, &pinned);
        let (s_unpinned, e_unpinned) = signed_entry(&committee, &keys, 20, &unpinned);
        let (s_head, e_head) = signed_entry(&committee, &keys, 100, &obj(0xC3));

        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let cache = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(30))
            .with_pinned_checkpoints(BTreeSet::from([10]));
        cache.absorb_entries(&s_pinned, &[e_pinned]);
        cache.absorb_entries(&s_unpinned, &[e_unpinned]);
        cache.absorb_entries(&s_head, &[e_head]);

        // head=100, window=30 → floor=70: both 10 and 20 are below it, only the
        // pinned one survives, and the children index keeps it.
        assert!(cache.get(pinned.id()).is_some());
        assert!(cache.get(unpinned.id()).is_none());
        assert_eq!(cache.snapshots_from_checkpoint(10), 1);
        assert!(cache.children_of(parent).contains(&pinned.id()));
        drop(cache);

        // Reopen with the same pin: the first absorb after boot sweeps, and the
        // pinned snapshot is still there — in memory and on disk.
        let reopened = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(30))
            .with_pinned_checkpoints(BTreeSet::from([10]));
        assert!(reopened.get(pinned.id()).is_some());
        let (s_later, e_later) = signed_entry(&committee, &keys, 200, &obj(0xD4));
        reopened.absorb_entries(&s_later, &[e_later]);
        assert_eq!(reopened.prune_floor(), Some(170));
        assert!(reopened.get(pinned.id()).is_some());
        assert!(reopened.get(ObjectID::from_single_byte(0xC3)).is_none());
        drop(reopened);

        // Reopen WITHOUT the pin: the next sweep prunes it like any other.
        let unpinned_cache = VerifiedStateCache::open(perpetual)
            .unwrap()
            .with_retain_window(Some(30));
        assert!(unpinned_cache.get(pinned.id()).is_some());
        let (s_last, e_last) = signed_entry(&committee, &keys, 300, &obj(0xE5));
        unpinned_cache.absorb_entries(&s_last, &[e_last]);
        assert!(
            unpinned_cache.get(pinned.id()).is_none(),
            "a checkpoint that left the pinned set must be released to the sweep"
        );
    }

    /// The pin belongs to the snapshot of the pinned checkpoint, not to the
    /// object id: once a newer version is absorbed the object follows the
    /// retain window again.
    #[tokio::test]
    async fn a_newer_absorbed_version_unpins_the_object() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let id = ObjectID::from_single_byte(0xA1);
        let owner = Owner::AddressOwner(ObjectID::from_single_byte(0x01).into());
        let version = |v: u64| {
            Object::with_id_owner_version_for_testing(id, SequenceNumber::from(v), owner.clone())
        };
        let cache = VerifiedStateCache::new()
            .with_retain_window(Some(30))
            .with_pinned_checkpoints(BTreeSet::from([10]));

        let (s_pinned, e_pinned) = signed_entry(&committee, &keys, 10, &version(1));
        cache.absorb_entries(&s_pinned, &[e_pinned]);
        let (s_newer, e_newer) = signed_entry(&committee, &keys, 50, &version(2));
        cache.absorb_entries(&s_newer, &[e_newer]);
        assert_eq!(cache.get(id).unwrap().source_checkpoint_seq, 50);
        assert_eq!(cache.snapshots_from_checkpoint(10), 0);

        // head=200 → floor=170: the object's snapshot (seq 50) is unpinned and
        // ages out.
        let other = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0xB2),
            SequenceNumber::from(1u64),
            owner.clone(),
        );
        let (s_head, e_head) = signed_entry(&committee, &keys, 200, &other);
        cache.absorb_entries(&s_head, &[e_head]);
        assert!(
            cache.get(id).is_none(),
            "a newer absorbed version must not inherit the pin"
        );
    }

    /// The singleton anchors' current snapshots survive every sweep whatever
    /// their age — including the first sweep after a reopen, with the pin set
    /// re-applied before any absorb — while a non-anchor snapshot of the same
    /// age is swept. The pin is by id, so it follows the anchor to its newer
    /// version and the cache still holds exactly one snapshot of it.
    #[tokio::test]
    async fn anchor_snapshots_survive_the_sweep_whatever_their_age() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let owner = Owner::AddressOwner(ObjectID::from_single_byte(0x01).into());
        let object = |byte: u8, version: u64| {
            Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(byte),
                SequenceNumber::from(version),
                owner.clone(),
            )
        };
        let anchor = object(0xA1, 1);
        let ordinary = object(0xB2, 1);
        let anchors = BTreeSet::from([anchor.id()]);
        let (s_anchor, e_anchor) = signed_entry(&committee, &keys, 10, &anchor);
        let (s_ordinary, e_ordinary) = signed_entry(&committee, &keys, 10, &ordinary);
        let (s_head, e_head) = signed_entry(&committee, &keys, 100, &object(0xC3, 1));

        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let cache = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(30))
            .with_pinned_objects(anchors.clone());
        cache.absorb_entries(&s_anchor, &[e_anchor]);
        cache.absorb_entries(&s_ordinary, &[e_ordinary]);
        cache.absorb_entries(&s_head, &[e_head]);

        // head=100, window=30 -> floor=70: both seq-10 snapshots are below it.
        assert_eq!(cache.prune_floor(), Some(70));
        assert!(cache.get(anchor.id()).is_some(), "the anchor is kept");
        assert!(cache.get(ordinary.id()).is_none(), "a non-anchor is swept");
        drop(cache);

        // Reopen with the same anchor set: the first absorb sweeps, and the
        // anchor is still there, in memory and on disk.
        let reopened = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(30))
            .with_pinned_objects(anchors.clone());
        let (s_later, e_later) = signed_entry(&committee, &keys, 200, &object(0xD4, 1));
        reopened.absorb_entries(&s_later, &[e_later]);
        assert_eq!(reopened.prune_floor(), Some(170));
        assert!(reopened.get(anchor.id()).is_some());
        assert!(reopened.get(ObjectID::from_single_byte(0xC3)).is_none());

        // A newer version replaces the snapshot and stays pinned by id.
        let (s_newer, e_newer) = signed_entry(&committee, &keys, 250, &object(0xA1, 2));
        reopened.absorb_entries(&s_newer, &[e_newer]);
        let (s_last, e_last) = signed_entry(&committee, &keys, 900, &object(0xE5, 1));
        reopened.absorb_entries(&s_last, &[e_last]);
        let kept = reopened.get(anchor.id()).unwrap();
        assert_eq!(kept.object.version(), SequenceNumber::from(2u64));
        assert_eq!(kept.source_checkpoint_seq, 250);
        drop(reopened);
        let on_disk = VerifiedStateCache::open(perpetual).unwrap();
        assert_eq!(
            on_disk.get(anchor.id()).unwrap().source_checkpoint_seq,
            250,
            "the persisted column keeps the anchor too"
        );
    }

    /// A checkpoint pinned at runtime is kept by the next sweep; unpinned, it
    /// is released to the sweep after that. `checkpoints_with_snapshots`
    /// reports which of a set of checkpoints still source a snapshot.
    #[tokio::test]
    async fn checkpoints_pinned_at_runtime_survive_until_unpinned() {
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let owner = Owner::AddressOwner(ObjectID::from_single_byte(0x01).into());
        let object = |byte: u8| {
            Object::with_id_owner_version_for_testing(
                ObjectID::from_single_byte(byte),
                SequenceNumber::from(1u64),
                owner.clone(),
            )
        };
        let cache = VerifiedStateCache::new().with_retain_window(Some(30));
        cache.pin_checkpoint(10);
        assert!(cache.is_checkpoint_pinned(10));
        let (s_pinned, e_pinned) = signed_entry(&committee, &keys, 10, &object(0xA1));
        cache.absorb_entries(&s_pinned, &[e_pinned]);
        assert_eq!(
            cache.checkpoints_with_snapshots(&BTreeSet::from([10, 11])),
            BTreeSet::from([10])
        );

        let (s_head, e_head) = signed_entry(&committee, &keys, 100, &object(0xB2));
        cache.absorb_entries(&s_head, &[e_head]);
        assert!(cache.get(ObjectID::from_single_byte(0xA1)).is_some());

        cache.unpin_checkpoint(10);
        assert!(!cache.is_checkpoint_pinned(10));
        let (s_later, e_later) = signed_entry(&committee, &keys, 200, &object(0xC3));
        cache.absorb_entries(&s_later, &[e_later]);
        assert!(cache.get(ObjectID::from_single_byte(0xA1)).is_none());
        assert!(
            cache
                .checkpoints_with_snapshots(&BTreeSet::from([10]))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn in_memory_cache_keeps_state_but_does_not_persist() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x01),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (summary, entry) = signed_entry(&committee, &keys, 7, &object);

        let cache = VerifiedStateCache::new();
        cache.absorb_entries(&summary, &[entry]);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.head_seq(), 7);

        // `new()` has no perpetual handle, so nothing was written through: a
        // fresh durable cache over independent tables sees an empty column.
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let durable = VerifiedStateCache::open(perpetual).unwrap();
        assert!(durable.is_empty());
        assert_eq!(durable.head_seq(), 0);
    }

    /// The object cache's retention floor follows the window and prunes PAST the
    /// bootstrap anchor — fixing the leak where it was pinned to the oldest
    /// committee summary forever (so `head - window` never engaged once the
    /// anchor fell behind). Only the *served* end-of-epoch checkpoint retention
    /// floor keeps the anchor, because a mirrored peer's ratchet can't re-derive
    /// a pruned summary.
    #[tokio::test]
    async fn object_window_prunes_past_the_anchor_while_eop_retention_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();

        // Anchor: a committee transition whose end-of-epoch summary sits at
        // checkpoint seq S = 50. `oldest_sui_committee_summary()` then returns a
        // summary with `sequence_number() == 50`.
        let target = ObjectID::from_single_byte(0xF0);
        let summary_object = Object::with_id_owner_version_for_testing(
            target,
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (committee_summary, _) = signed_entry(&committee, &keys, 50, &summary_object);

        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        perpetual
            .record_sui_committee_transition(&committee_summary)
            .unwrap();
        assert_eq!(
            *perpetual
                .oldest_sui_committee_summary()
                .unwrap()
                .unwrap()
                .sequence_number(),
            50
        );

        let cache = VerifiedStateCache::open(perpetual.clone())
            .unwrap()
            .with_retain_window(Some(20));

        // Fold an object at seq 100. The OBJECT floor follows the window
        // (head - window = 80) and is NOT pinned to the anchor (50). The served
        // end-of-epoch retention floor keeps the anchor: min(80, 50) = 50.
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x01),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (summary100, entry100) = signed_entry(&committee, &keys, 100, &object);
        cache.absorb_entries(&summary100, &[entry100]);
        assert_eq!(cache.head_seq(), 100);
        assert_eq!(
            cache.prune_floor(),
            Some(80),
            "object floor follows head - window (80), no longer pinned to the anchor (50)"
        );
        assert_eq!(
            cache.eop_retention_floor(),
            Some(50),
            "served end-of-epoch checkpoints are kept back to the anchor (50)"
        );

        // Fold a snapshot at seq 55 (>= anchor 50 but below the object floor),
        // then advance the head to 120 so a prune sweep runs.
        let object55 = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x03),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (summary55, entry55) = signed_entry(&committee, &keys, 55, &object55);
        cache.absorb_entries(&summary55, &[entry55]);
        let object_head = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x04),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );
        let (summary_head, entry_head) = signed_entry(&committee, &keys, 120, &object_head);
        cache.absorb_entries(&summary_head, &[entry_head]);

        // head=120, window=20 → object floor = 100. The seq-55 snapshot is below
        // it and is PRUNED — the leak is gone (previously the floor was pinned at
        // 50 and seq-55 survived forever).
        assert_eq!(cache.prune_floor(), Some(100));
        assert!(
            cache.get(object55.id()).is_none(),
            "a snapshot below head - window must be pruned; the anchor no longer pins the floor"
        );
        // The anchor's end-of-epoch summary is still retained for mirrored bootstrap.
        assert_eq!(
            *perpetual
                .oldest_sui_committee_summary()
                .unwrap()
                .unwrap()
                .sequence_number(),
            50,
            "the served end-of-epoch summary at the anchor (50) survives for mirrored bootstrap"
        );
    }

    /// A version downgrade is skipped end-to-end: after caching `id@v8`, an
    /// `absorb` of `id@v5` returns `false` from `insert_inner`, so the cached
    /// version stays `v8`, the skipped id is not persisted, and the
    /// parent→children index is untouched.
    #[tokio::test]
    async fn absorb_never_downgrades_a_cached_version() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let cache = VerifiedStateCache::open(perpetual.clone()).unwrap();

        let id = ObjectID::from_single_byte(0x01);
        let parent = ObjectID::from_single_byte(0xAB);
        let v8 = Object::with_id_owner_version_for_testing(
            id,
            SequenceNumber::from(8u64),
            Owner::ObjectOwner(parent.into()),
        );
        let (summary_v8, entry_v8) = signed_entry(&committee, &keys, 80, &v8);
        cache.absorb_entries(&summary_v8, &[entry_v8]);
        assert_eq!(
            cache.get(id).unwrap().object.version(),
            SequenceNumber::from(8u64)
        );
        assert_eq!(cache.children_of(parent), vec![id]);

        // Now an out-of-order absorb of the SAME id at the OLDER version 5,
        // arriving at a later checkpoint (a network shadow-write racing the
        // pusher). It must be skipped: the cached object stays v8.
        let v5 = Object::with_id_owner_version_for_testing(
            id,
            SequenceNumber::from(5u64),
            // A different parent — to prove the children index is NOT touched on
            // a skipped downgrade.
            Owner::ObjectOwner(ObjectID::from_single_byte(0xCD).into()),
        );
        let (summary_v5, entry_v5) = signed_entry(&committee, &keys, 90, &v5);

        // The insert is skipped directly.
        assert!(
            !cache.insert_inner(&entry_v5, &summary_v5, 90),
            "a lower-version absorb must report skipped (insert_inner == false)"
        );

        // Cached version is still v8.
        assert_eq!(
            cache.get(id).unwrap().object.version(),
            SequenceNumber::from(8u64),
            "the cache must not downgrade v8 to v5"
        );
        // The children index is untouched: the old parent still owns the id, the
        // downgrade's would-be parent was never inserted.
        assert_eq!(cache.children_of(parent), vec![id]);
        assert!(
            cache
                .children_of(ObjectID::from_single_byte(0xCD))
                .is_empty()
        );

        // The persisted column still carries the v8 snapshot, not v5: a reopen
        // sees v8 (the downgrade was never written through).
        drop(cache);
        let reopened = VerifiedStateCache::open(perpetual).unwrap();
        assert_eq!(
            reopened.get(id).unwrap().object.version(),
            SequenceNumber::from(8u64)
        );
    }

    /// `open` seeds the processed head from the persisted fold head, so the
    /// reader's boot-time staleness tripwire doesn't fire spuriously before the
    /// worker's first tick re-establishes its cursor. After folding through seq
    /// 500 on a durable cache, a drop+reopen restores `head_seq() == 500` AND
    /// `processed_head_seq() == 500` (rather than 0).
    #[tokio::test]
    async fn open_sets_processed_head_to_fold_head_avoiding_spurious_tripwire() {
        let dir = tempfile::tempdir().unwrap();
        let (committee, keys) = SuiCommittee::new_simple_test_committee();
        let object = Object::with_id_owner_version_for_testing(
            ObjectID::from_single_byte(0x01),
            SequenceNumber::from(1u64),
            Owner::AddressOwner(ObjectID::from_single_byte(0x02).into()),
        );

        {
            let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
            let cache = VerifiedStateCache::open(perpetual).unwrap();
            let (summary, entry) = signed_entry(&committee, &keys, 500, &object);
            cache.absorb_entries(&summary, &[entry]);
            assert_eq!(cache.head_seq(), 500);
        }

        // Reopen: both the fold head and the processed head come back at 500.
        // Processed head starting at 0 would make the reader believe the pusher
        // is 500 checkpoints behind on boot and trip the staleness tripwire.
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let reopened = VerifiedStateCache::open(perpetual).unwrap();
        assert_eq!(reopened.head_seq(), 500);
        assert_eq!(
            reopened.processed_head_seq(),
            500,
            "processed head must boot from the fold head, not 0, to avoid a spurious tripwire"
        );
    }
}
