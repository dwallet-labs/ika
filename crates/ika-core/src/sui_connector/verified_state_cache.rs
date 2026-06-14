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
//! Eviction on deletion is not yet implemented; the cache only grows, and
//! live-set churn (sessions completing) keeps it bounded enough to be
//! harmless in practice.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ika_network::proof_provider::VerifiedObjectEntry;
use parking_lot::RwLock;
use sui_light_client::proof::ocs::OCSInclusionProof;
use sui_types::base_types::ObjectID;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::{Object, Owner};

/// One verified Ika object, frozen at the checkpoint that last modified it.
///
/// `OCSInclusionProof` is not `Clone`, so this struct's `Clone` goes
/// through `bcs` for the proof field. Costs O(proof depth) bytes per
/// clone — negligible relative to the network round-trip we're avoiding.
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
    /// resolves to that parent. Maintained on every `insert`.
    children: RwLock<HashMap<ObjectID, BTreeSet<ObjectID>>>,
    /// Highest checkpoint seq whose state we've folded in.
    head_seq: AtomicU64,
}

impl VerifiedStateCache {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            head_seq: AtomicU64::new(0),
        }
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

    pub fn len(&self) -> usize {
        self.objects.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.read().is_empty()
    }

    /// Fold every `(object, proof)` from one checkpoint into the cache.
    /// Updates the parent→children index from each object's owner and bumps
    /// `head_seq` to the summary's sequence (monotonically). The caller
    /// (direct pusher, or the reader after a per-read verify) is responsible
    /// for having verified each entry against `summary` first.
    pub fn absorb_entries(
        &self,
        summary: &CertifiedCheckpointSummary,
        entries: &[VerifiedObjectEntry],
    ) {
        let source_seq = *summary.sequence_number();
        for entry in entries {
            self.insert_inner(entry, summary, source_seq);
        }
        self.advance_head(source_seq);
    }

    fn insert_inner(
        &self,
        entry: &VerifiedObjectEntry,
        summary: &CertifiedCheckpointSummary,
        source_seq: CheckpointSequenceNumber,
    ) {
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
                        return;
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
