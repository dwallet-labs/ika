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
//! snapshots more than `window` checkpoints behind the head are pruned from
//! both the in-memory maps and the persisted column (never below the oldest
//! committee-verifiable checkpoint, which a mirrored peer may still bootstrap
//! from). Tombstone eviction on on-chain deletion is not yet implemented, but
//! the retain window bounds growth regardless.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ika_network::proof_provider::VerifiedObjectEntry;
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
    /// Drop snapshots whose source checkpoint fell more than this many
    /// checkpoints behind the head (also the mirrored-peer bootstrap depth).
    /// `None` = unbounded. Set via [`Self::with_retain_window`].
    retain_window: Option<u64>,
    /// Floor (`head - window`) at the last prune sweep; the next sweep waits
    /// until the floor rises a stride, so the sweep is amortized O(1) per absorb.
    last_pruned_floor: AtomicU64,
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
        }
    }

    /// Bound the cache to snapshots within `window` checkpoints of the head
    /// (`None` = unbounded). Mirrors `ChangesetIndex::with_retain_window`; the
    /// sweep is amortized — it only runs once the floor rises a stride.
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

    /// Retention floor: drop snapshots whose source checkpoint is more than
    /// `retain_window` behind the head, but never below the oldest
    /// committee-verifiable checkpoint (a mirrored peer bootstrapping from there
    /// still needs those objects). `None` when pruning is disabled.
    fn prune_floor(&self) -> Option<CheckpointSequenceNumber> {
        let window = self.retain_window?;
        let mut floor = self.head_seq().saturating_sub(window);
        if let Some(perpetual) = &self.perpetual {
            if let Ok(Some(oldest)) = perpetual.oldest_sui_committee_summary() {
                floor = floor.min(*oldest.sequence_number());
            }
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
    fn prune(&self, floor: CheckpointSequenceNumber) {
        // Retained end-of-epoch checkpoints (served to mirrored peers) share the
        // cache's retention floor; prune them on the same amortized schedule,
        // independently of whether any object snapshot aged out this sweep.
        if let Some(perpetual) = &self.perpetual {
            if let Err(e) = perpetual.retain_sui_end_of_epoch_checkpoints(floor) {
                warn!(error = ?e, "failed to prune retained end-of-epoch checkpoints");
            }
        }
        let removed: Vec<(ObjectID, Option<ObjectID>)> = {
            let mut objects = self.objects.write();
            let mut removed = Vec::new();
            objects.retain(|id, snap| {
                if snap.source_checkpoint_seq < floor {
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
                if let Some(parent) = parent {
                    if let Some(set) = children.get_mut(parent) {
                        set.remove(id);
                        if set.is_empty() {
                            children.remove(parent);
                        }
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
    /// staleness tripwire then under-fires). Only the single-threaded, in-order
    /// pusher persists (reader shadow-writes use `absorb_shadow_entries`), so a
    /// per-call `source_seq` is contiguous and never overstates.
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
            if let Some(prev) = prior_parent {
                if let Some(set) = self.children.write().get_mut(&prev) {
                    set.remove(&id);
                }
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
}
