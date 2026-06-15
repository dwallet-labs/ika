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
use ika_types::error::IkaResult;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sui_light_client::proof::ocs::OCSInclusionProof;
use sui_types::base_types::ObjectID;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::{Object, Owner};
use tracing::{info, warn};

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
    /// When `Some`, the cache is durable: every `absorb_entries` writes the
    /// folded snapshots (and the head) through to the perpetual
    /// `verified_object_cache` column, and `open` rehydrates from it on boot —
    /// so a restart resumes from DB instead of re-fetching from the (possibly
    /// pruned) Sui fullnode. `None` is an in-memory-only cache (`new`, for
    /// tests / `Default`).
    perpetual: Option<Arc<AuthorityPerpetualTables>>,
}

impl VerifiedStateCache {
    /// In-memory-only cache (no persistence). Use [`Self::open`] in production
    /// so the cache survives restarts.
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            children: RwLock::new(HashMap::new()),
            head_seq: AtomicU64::new(0),
            perpetual: None,
        }
    }

    /// Durable cache: rehydrate the in-memory maps from the persisted
    /// `verified_object_cache` column (rebuilding the parent→children index
    /// from each object's owner) and restore the folded head, then write
    /// through every subsequent absorb. A restart therefore resumes serving
    /// from DB without reaching back to the Sui fullnode.
    pub fn open(perpetual: Arc<AuthorityPerpetualTables>) -> IkaResult<Self> {
        let persisted = perpetual.load_verified_object_cache()?;
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
            perpetual: Some(perpetual),
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
        let mut inserted_ids = Vec::new();
        for entry in entries {
            if self.insert_inner(entry, summary, source_seq) {
                inserted_ids.push(entry.object.id());
            }
        }
        self.advance_head(source_seq);
        self.persist(&inserted_ids);
    }

    /// Write the just-folded snapshots (and the head) through to the perpetual
    /// `verified_object_cache` column in one batch, so the cache survives a
    /// restart. No-op for an in-memory-only cache. Best-effort: a DB error is
    /// logged, not propagated — the in-memory cache stays authoritative for the
    /// running process and the next absorb re-persists.
    fn persist(&self, inserted_ids: &[ObjectID]) {
        let Some(perpetual) = &self.perpetual else {
            return;
        };
        let head = self.head_seq();
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
