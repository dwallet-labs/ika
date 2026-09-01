// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Currency primitives for mirrored / peer-only validators.
//!
//! A mirrored node's OCS inclusion proof attests *authenticity* (object `X`
//! was at version `V` in some committee-signed checkpoint `M`) but not
//! *currency* (`V` is still the latest version at head `N`). The changeset
//! stream closes that gap by folding a committee-signed stream of
//! modified-object-id sets and proving `X@V` current iff `X`'s id appears in no
//! checkpoint after `M`. The audit / fallback path for that "appears in no
//! checkpoint" claim is a Merkle *non-inclusion* proof against each checkpoint's
//! `ModifiedObjectTree`.
//!
//! This module IS that subsystem, and it is **live**: [`ChangesetIndex`] folds
//! the committee-signed changeset stream (contiguity-enforced) and `check_currency`
//! gates every verified read (single / batch / bag) on mirrored / peer-only nodes
//! — a `Stale`/`NotLive` verdict is rejected `NotCurrent`. Its load-bearing
//! primitive is the **id-binding** check on non-inclusion proofs: without it a
//! relay can serve a proof for the wrong id. Design notes:
//! `dev-docs/specs/ocs-verified-sui-reads.md`.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::sui_connector::committee_store::CommitteeStore;
use sui_light_client::proof::ocs::OCSNonInclusionProof;
use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber};
use sui_types::digests::CheckpointDigest;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};
use tracing::warn;

/// Does `proof` actually attest the absence of the *id* `target_id`, rather
/// than merely the absence of some `ObjectRef` that happens to carry it?
///
/// The Merkle non-inclusion verifier (`fastcrypto`) proves a *leaf* is absent:
/// it checks `left_leaf < target < right_leaf` plus Merkle membership of the
/// neighbours, and nothing about the leaves' `ObjectID`s. OCS targets a
/// non-inclusion proof at a *dummy* ref `(id, SequenceNumber(0),
/// ObjectDigest::MIN)`, which sorts strictly below any genuine `(id, v>0, d)`
/// leaf. So a byzantine prover can present the *real, present* leaf `(id, v, d)`
/// as the right neighbour of the dummy and obtain a perfectly valid
/// non-inclusion proof — "id was not modified in this checkpoint" while it was
/// modified to `v`. That would let a relay pass a rolled-back object off as
/// current.
///
/// The fix needs no `fastcrypto` change: the verifier already *carries* the
/// neighbour leaves (`left_leaf` / `right_leaf` are public, and are full
/// `ObjectRef`s). A genuine absence has neighbours with ids *different* from
/// the target; if either neighbour's id equals `target_id`, the id is in fact
/// present and the proof must be rejected. Callers run this **in addition to**
/// the existing Merkle + artifacts-digest verification, never instead of it.
pub fn non_inclusion_binds_id(proof: &OCSNonInclusionProof, target_id: ObjectID) -> bool {
    let p = &proof.non_inclusion_proof;
    let left_binds = p
        .left_leaf
        .as_ref()
        .is_none_or(|(object_ref, _)| object_ref.0 != target_id);
    let right_binds = p
        .right_leaf
        .as_ref()
        .is_none_or(|(object_ref, _)| object_ref.0 != target_id);
    left_binds && right_binds
}

/// Lifecycle status of an id at the checkpoint that last touched it, derived
/// from the object's digest in the changeset (`object_states` carries deletes
/// and wraps as marker digests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdStatus {
    /// A live object written to a new version.
    Modified,
    /// Deleted in this checkpoint (`OBJECT_DIGEST_DELETED`).
    Deleted,
    /// Wrapped into a parent in this checkpoint (`OBJECT_DIGEST_WRAPPED`).
    Wrapped,
}

impl IdStatus {
    fn from_digest(digest: &ObjectDigest) -> Self {
        if *digest == ObjectDigest::OBJECT_DIGEST_DELETED {
            Self::Deleted
        } else if *digest == ObjectDigest::OBJECT_DIGEST_WRAPPED {
            Self::Wrapped
        } else {
            Self::Modified
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdRecord {
    /// Highest checkpoint (within the folded contiguous range) that touched the id.
    last_seq: CheckpointSequenceNumber,
    status: IdStatus,
}

/// What `absorb` did with a changeset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsorbOutcome {
    /// Extended the contiguous frontier (possibly draining queued successors).
    Advanced { new_head: CheckpointSequenceNumber },
    /// Out of order (a gap precedes it) — queued until its predecessor arrives.
    Queued,
    /// At or below the frontier already — ignored (idempotent).
    AlreadyFolded,
}

/// Read-time currency verdict for an object served at version-anchored
/// checkpoint `M` (its last-modifying checkpoint, per the inclusion proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrencyVerdict {
    /// `M` is the id's latest modification within the contiguous frontier — the
    /// served version is current.
    Current,
    /// The id was modified again after `M` — the served version is rolled back.
    Stale,
    /// The id was deleted/wrapped at `M` — not a live object to serve.
    NotLive,
    /// The frontier doesn't cover `M`, or the id isn't tracked (outside the
    /// fold filter) — no currency claim either way; the caller falls back to
    /// per-read verification.
    Unknown,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ChangesetError {
    #[error(
        "changeset object-set at seq {0} does not match the summary's committed artifacts digest"
    )]
    ArtifactsMismatch(CheckpointSequenceNumber),
    #[error("changeset at seq {seq} does not forward-chain onto the contiguous head")]
    BrokenChain { seq: CheckpointSequenceNumber },
    #[error("changeset summary failed committee verification: {0}")]
    Unverified(String),
    #[error("internal: {0}")]
    Internal(String),
}

struct PendingChangeset {
    digest: CheckpointDigest,
    previous_digest: Option<CheckpointDigest>,
    object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
}

/// Hard cap on the out-of-order `pending` queue. A byzantine relay can withhold
/// the contiguous-head checkpoint while feeding a run of higher, real,
/// committee-signed changesets — each one queues in `pending` and never drains.
/// Bound it so the relay can't grow our memory without limit; at the cap, a new
/// out-of-order entry is dropped (it is re-pulled from the contiguous head once
/// the gap fills, and the affected ids read a safe `Unknown` meanwhile). Sized
/// for many epochs of legitimate brief reordering.
const MAX_PENDING_CHANGESETS: usize = 256;

/// A mirrored node's fold of the committee-signed changeset stream into a
/// per-id `(last-modifying seq, status)` index with an **enforced contiguous
/// frontier**. All currency reasoning uses the contiguous head, never the
/// highest seen — a gossiped stream can arrive out of order or with gaps, and
/// a byzantine relay must not be able to skip a checkpoint that would have
/// modified an id.
pub struct ChangesetIndex {
    index: HashMap<ObjectID, IdRecord>,
    /// `(seq, digest)` of the highest contiguously-folded checkpoint.
    contiguous_head: Option<(CheckpointSequenceNumber, CheckpointDigest)>,
    /// Lowest folded checkpoint — the floor below which currency is `Unknown`.
    oldest_folded: Option<CheckpointSequenceNumber>,
    /// Highest checkpoint seq ever absorbed (contiguous or not) — observability.
    highest_seen: Option<CheckpointSequenceNumber>,
    /// Out-of-order changesets awaiting their predecessor.
    pending: BTreeMap<CheckpointSequenceNumber, PendingChangeset>,
    /// Bound on memory: keep currency for objects last modified within this many
    /// checkpoints of the contiguous head; drop older entries (raising the
    /// `Unknown` floor with them, so reads anchored below it fall back to the
    /// per-read defenses). `None` retains forever. Idle objects modified only at
    /// epoch boundaries stay covered as long as the window exceeds the epoch
    /// length. On a busy chain this still grows with the per-checkpoint modified
    /// set; the complementary bound is Ika-filtering the folded set (see the
    /// design doc).
    retain_window: Option<u64>,
    /// Restrict folding to this id set (`None` = fold every id). The full
    /// changeset is still verified against the summary's artifacts digest
    /// (no omission), but only filtered-in ids enter the index — bounding
    /// memory to the objects this node reads (the mutable Ika roots + their
    /// versioned inners). Reads of filtered-out ids get `Unknown` (fallback),
    /// which is sound because the filter is *stable*: every checkpoint that
    /// modifies a filtered-in id folds it, so its record is always its latest.
    fold_filter: Option<HashSet<ObjectID>>,
}

impl Default for ChangesetIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangesetIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            contiguous_head: None,
            oldest_folded: None,
            highest_seen: None,
            pending: BTreeMap::new(),
            retain_window: None,
            fold_filter: None,
        }
    }

    /// Bound the index to objects modified within `window` checkpoints of the
    /// head (`None` = unbounded). See [`Self::retain_window`].
    pub fn with_retain_window(mut self, window: Option<u64>) -> Self {
        self.retain_window = window;
        self
    }

    /// Fold only ids in `filter` (`None` = fold all). The filter must be a
    /// *stable* superset of the ids this node reads currency on (filtered-out
    /// ids fall back to `Unknown`). See [`Self::fold_filter`].
    pub fn with_fold_filter(mut self, filter: Option<HashSet<ObjectID>>) -> Self {
        self.fold_filter = filter;
        self
    }

    /// Highest checkpoint the contiguous frontier covers, if any.
    pub fn highest_contiguous_seq(&self) -> Option<CheckpointSequenceNumber> {
        self.contiguous_head.map(|(seq, _)| seq)
    }

    pub fn highest_seen_seq(&self) -> Option<CheckpointSequenceNumber> {
        self.highest_seen
    }

    /// Fold one checkpoint's changeset.
    ///
    /// `summary` MUST already be BLS-verified against its epoch committee (the
    /// production caller does this via `CommitteeStore::verify_summary` before
    /// absorbing). This method binds `object_states` to that verified summary
    /// (re-derives the artifacts digest and checks it against the summary's
    /// commitment), enforces forward-chain contiguity, and folds — advancing
    /// the frontier only at `head + 1` with a matching `previous_digest`,
    /// queuing gap-creating inputs, and draining the queue as gaps fill.
    pub fn absorb(
        &mut self,
        summary: &CertifiedCheckpointSummary,
        object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
    ) -> Result<AbsorbOutcome, ChangesetError> {
        let data = summary.data();
        let seq = *data.sequence_number();

        // Bind the shipped object-set to the verified summary: a relay must not
        // be able to add, drop, or alter ids in a checkpoint's changeset.
        let derived = CheckpointArtifacts::from_object_states(object_states.clone())
            .digest()
            .map_err(|e| ChangesetError::Internal(e.to_string()))?;
        let committed = data
            .checkpoint_artifacts_digest()
            .map_err(|e| ChangesetError::Internal(e.to_string()))?;
        if derived != *committed {
            return Err(ChangesetError::ArtifactsMismatch(seq));
        }

        self.highest_seen = Some(self.highest_seen.map_or(seq, |h| h.max(seq)));
        let incoming = PendingChangeset {
            digest: data.digest(),
            previous_digest: data.previous_digest,
            object_states,
        };

        match self.contiguous_head {
            // Bootstrap: the first changeset establishes the base of the range.
            None => {
                self.fold(seq, &incoming.object_states);
                self.oldest_folded = Some(seq);
                self.contiguous_head = Some((seq, incoming.digest));
                self.drain_pending();
                Ok(AbsorbOutcome::Advanced {
                    new_head: self.head_seq(),
                })
            }
            Some((head_seq, head_digest)) => {
                if seq <= head_seq {
                    Ok(AbsorbOutcome::AlreadyFolded)
                } else if seq == head_seq + 1 {
                    if incoming.previous_digest != Some(head_digest) {
                        return Err(ChangesetError::BrokenChain { seq });
                    }
                    self.fold(seq, &incoming.object_states);
                    self.contiguous_head = Some((seq, incoming.digest));
                    self.drain_pending();
                    Ok(AbsorbOutcome::Advanced {
                        new_head: self.head_seq(),
                    })
                } else if self.pending.len() >= MAX_PENDING_CHANGESETS
                    && !self.pending.contains_key(&seq)
                {
                    // Queue full — a relay is likely withholding the contiguous
                    // head while feeding higher seqs. Drop this out-of-order entry
                    // rather than grow unbounded; it is re-pulled from the
                    // contiguous head later, and the affected ids read a safe
                    // `Unknown` (per-read fallback) until the gap fills.
                    warn!(
                        seq,
                        pending = self.pending.len(),
                        "changeset pending queue at cap; dropping out-of-order entry \
                         (relay may be withholding the contiguous head)"
                    );
                    Ok(AbsorbOutcome::Queued)
                } else {
                    self.pending.insert(seq, incoming);
                    Ok(AbsorbOutcome::Queued)
                }
            }
        }
    }

    /// Verified entry point: BLS-verify `summary` against its epoch committee
    /// via `committees`, then [`Self::absorb`]. This is how the mirror node
    /// folds the gossiped stream — it discharges `absorb`'s precondition that
    /// the summary is committee-verified, so an unsigned or foreign-signed
    /// changeset is rejected and never folded. (BLS is the committee store's
    /// job; the binding + contiguity + fold are this module's.)
    pub fn absorb_verified(
        &mut self,
        committees: &CommitteeStore,
        summary: &CertifiedCheckpointSummary,
        object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
    ) -> Result<AbsorbOutcome, ChangesetError> {
        committees
            .verify_summary(summary.clone())
            .map_err(|e| ChangesetError::Unverified(e.to_string()))?;
        self.absorb(summary, object_states)
    }

    /// Is `id`, served version-anchored at its last-modifying checkpoint
    /// `anchored_seq`, the current version at the contiguous frontier?
    pub fn currency(
        &self,
        id: ObjectID,
        anchored_seq: CheckpointSequenceNumber,
    ) -> CurrencyVerdict {
        let (Some((head, _)), Some(oldest)) = (self.contiguous_head, self.oldest_folded) else {
            return CurrencyVerdict::Unknown;
        };
        // The frontier must bracket the anchor for the index to be authoritative
        // about the id's modifications since then.
        if anchored_seq > head || anchored_seq < oldest {
            return CurrencyVerdict::Unknown;
        }
        match self.index.get(&id) {
            Some(record) if record.last_seq == anchored_seq => match record.status {
                IdStatus::Modified => CurrencyVerdict::Current,
                IdStatus::Deleted | IdStatus::Wrapped => CurrencyVerdict::NotLive,
            },
            Some(record) if record.last_seq > anchored_seq => CurrencyVerdict::Stale,
            // The id isn't tracked (outside the fold filter) or its record
            // predates the anchor (can't happen for a filtered-in id with a
            // valid inclusion proof — its record always reflects its latest
            // modification). Either way the index can't speak to it: fall back.
            _ => CurrencyVerdict::Unknown,
        }
    }

    fn head_seq(&self) -> CheckpointSequenceNumber {
        self.contiguous_head.map(|(seq, _)| seq).unwrap_or_default()
    }

    fn fold(
        &mut self,
        seq: CheckpointSequenceNumber,
        object_states: &BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
    ) {
        // Folded strictly in increasing contiguous order, so `seq` only grows;
        // the last write for an id (its highest modifying checkpoint) wins.
        for (id, (_version, digest)) in object_states {
            if self
                .fold_filter
                .as_ref()
                .is_some_and(|set| !set.contains(id))
            {
                continue;
            }
            self.index.insert(
                *id,
                IdRecord {
                    last_seq: seq,
                    status: IdStatus::from_digest(digest),
                },
            );
        }
    }

    /// After advancing the head, pull in any queued successors that now chain,
    /// then prune entries that have aged out of the retain window.
    fn drain_pending(&mut self) {
        while let Some((head_seq, head_digest)) = self.contiguous_head {
            let next = head_seq + 1;
            match self.pending.get(&next) {
                Some(p) if p.previous_digest == Some(head_digest) => {
                    let p = self.pending.remove(&next).expect("just matched");
                    self.fold(next, &p.object_states);
                    self.contiguous_head = Some((next, p.digest));
                }
                // A queued successor that doesn't chain is byzantine — drop it
                // (it can never legitimately drain) and stop at the gap.
                Some(_) => {
                    self.pending.remove(&next);
                    break;
                }
                None => break,
            }
        }
        self.prune();
    }

    /// Drop entries whose last modification fell below `head - retain_window`,
    /// raising `oldest_folded` (the `Unknown` floor) to match. Sound: an object
    /// whose last modification is below the new floor has no modification at or
    /// above it, so a valid inclusion proof for it anchors below the floor →
    /// `Unknown` → per-read fallback; a forged anchor at/above the floor can't
    /// produce a valid inclusion proof. Amortized: the O(n) sweep runs only once
    /// the floor has risen by a stride, so the index over-retains by < a stride.
    fn prune(&mut self) {
        let (Some(window), Some((head, _))) = (self.retain_window, self.contiguous_head) else {
            return;
        };
        let floor = head.saturating_sub(window);
        let stride = (window / 8).max(1);
        if self
            .oldest_folded
            .is_some_and(|oldest| floor < oldest.saturating_add(stride))
        {
            return;
        }
        self.index.retain(|_id, record| record.last_seq >= floor);
        self.oldest_folded = Some(floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;
    use fastcrypto::merkle::{MerkleNonInclusionProof, Node};
    use std::sync::Arc;
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::ObjectRef;
    use sui_types::committee::Committee;
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointContentsDigest;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{CheckpointCommitment, CheckpointSummary};

    fn object_ref(id_byte: u8, version: u64) -> ObjectRef {
        (
            ObjectID::from_single_byte(id_byte),
            SequenceNumber::from(version),
            ObjectDigest::new([id_byte; 32]),
        )
    }

    fn tree_of(refs: &[ObjectRef]) -> ModifiedObjectTree {
        let object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = refs
            .iter()
            .map(|(id, version, digest)| (*id, (*version, *digest)))
            .collect();
        ModifiedObjectTree::new(&CheckpointArtifacts::from_object_states(object_states))
            .expect("modified object tree")
    }

    fn root_node(tree: &ModifiedObjectTree) -> Node {
        Node::from(tree.tree_root.into_inner())
    }

    /// THE load-bearing test for the changeset-stream design. The raw Merkle
    /// verifier *accepts* a forged non-inclusion proof for an id that is in fact
    /// present (modified): the prover passes the present leaf off as the right
    /// neighbour of the dummy `(id, 0, MIN)` target. `non_inclusion_binds_id`
    /// must reject it — a regression here silently reintroduces serving a
    /// rolled-back object as current.
    #[test]
    fn a_forged_non_inclusion_for_a_present_id_is_rejected() {
        // id 0x02 is present at version 5, sorted between 0x01 and 0x03.
        let present = object_ref(0x02, 5);
        let tree = tree_of(&[object_ref(0x01, 1), present, object_ref(0x03, 1)]);
        let target_id = present.0;
        let position = tree.object_pos_map[&target_id];

        // Forge: left neighbour is the genuine predecessor, right neighbour is
        // the PRESENT leaf for the target id itself. The dummy `(id, 0, MIN)`
        // sorts just below it, so the ordering checks pass.
        let forged = MerkleNonInclusionProof::new(
            Some((
                tree.leaves[position - 1],
                tree.tree.get_proof(position - 1).unwrap(),
            )),
            Some((
                tree.leaves[position],
                tree.tree.get_proof(position).unwrap(),
            )),
            position,
        );
        let dummy = (target_id, SequenceNumber::from(0u64), ObjectDigest::MIN);

        // The raw Merkle verifier accepts the forgery — this is the gap.
        assert!(
            forged.verify_proof(&root_node(&tree), &dummy).is_ok(),
            "merkle non-inclusion is expected to accept the forged proof (the vulnerability)"
        );

        // The id binding rejects it: the right neighbour *is* the target id.
        let forged = OCSNonInclusionProof {
            non_inclusion_proof: forged,
            tree_root: tree.tree_root,
        };
        assert!(
            !non_inclusion_binds_id(&forged, target_id),
            "must reject a non-inclusion proof whose neighbour carries the target id"
        );
    }

    /// A genuine non-inclusion proof for a truly-absent id binds that id: its
    /// neighbours necessarily carry different ids (the id isn't in the tree).
    /// Exercises the middle case — both neighbours present.
    #[test]
    fn a_genuine_non_inclusion_binds_the_absent_id() {
        let tree = tree_of(&[
            object_ref(0x01, 1),
            object_ref(0x03, 5),
            object_ref(0x05, 1),
        ]);
        let absent = ObjectID::from_single_byte(0x04); // between 0x03 and 0x05
        let dummy = (absent, SequenceNumber::from(0u64), ObjectDigest::MIN);

        let proof = tree
            .get_non_inclusion_proof(dummy)
            .expect("non-inclusion proof");
        assert!(
            proof
                .non_inclusion_proof
                .verify_proof(&root_node(&tree), &dummy)
                .is_ok(),
            "a genuine non-inclusion proof must verify"
        );
        assert!(
            non_inclusion_binds_id(&proof, absent),
            "a genuine absence proof must bind the absent id"
        );
    }

    // ---- changeset-stream fold (Blockers 2/3/4) ----

    type States = BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>;

    fn id(byte: u8) -> ObjectID {
        ObjectID::from_single_byte(byte)
    }

    fn modified(byte: u8, version: u64) -> (ObjectID, (SequenceNumber, ObjectDigest)) {
        (
            id(byte),
            (SequenceNumber::from(version), ObjectDigest::new([byte; 32])),
        )
    }

    fn deleted(byte: u8, version: u64) -> (ObjectID, (SequenceNumber, ObjectDigest)) {
        (
            id(byte),
            (
                SequenceNumber::from(version),
                ObjectDigest::OBJECT_DIGEST_DELETED,
            ),
        )
    }

    fn states(
        entries: impl IntoIterator<Item = (ObjectID, (SequenceNumber, ObjectDigest))>,
    ) -> States {
        entries.into_iter().collect()
    }

    /// A committee-signed changeset: a `CertifiedCheckpointSummary` committing
    /// (via its artifacts digest) to `object_states`, chained onto `previous`.
    /// Returns the cert and its own digest (for chaining the next).
    fn signed_changeset(
        committee: &Committee,
        keypairs: &[AuthorityKeyPair],
        seq: u64,
        previous: Option<CheckpointDigest>,
        object_states: &States,
    ) -> (CertifiedCheckpointSummary, CheckpointDigest) {
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
        let digest = summary.digest();
        let cert =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keypairs, committee);
        (cert, digest)
    }

    /// In-order changesets advance the contiguous frontier; an idle object stays
    /// current at its anchoring checkpoint.
    #[test]
    fn in_order_changesets_advance_the_frontier() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        assert_eq!(
            idx.absorb(&c10, s10).unwrap(),
            AbsorbOutcome::Advanced { new_head: 10 }
        );

        let s11 = states([modified(0xB2, 1)]);
        let (c11, _d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        assert_eq!(
            idx.absorb(&c11, s11).unwrap(),
            AbsorbOutcome::Advanced { new_head: 11 }
        );

        assert_eq!(idx.highest_contiguous_seq(), Some(11));
        // 0xA1 was last modified at 10 and not since → current there.
        assert_eq!(idx.currency(id(0xA1), 10), CurrencyVerdict::Current);
    }

    /// A gap-creating changeset is queued and drained when its predecessor
    /// arrives; the frontier never jumps the gap.
    #[test]
    fn an_out_of_order_changeset_is_queued_then_drained() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let s11 = states([modified(0xB2, 1)]);
        let s12 = states([modified(0xC3, 1)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c11, d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        let (c12, _d12) = signed_changeset(&committee, &keys, 12, Some(d11), &s12);

        idx.absorb(&c10, s10).unwrap();
        assert_eq!(idx.absorb(&c12, s12).unwrap(), AbsorbOutcome::Queued);
        assert_eq!(
            idx.highest_contiguous_seq(),
            Some(10),
            "frontier must not jump the gap"
        );
        assert_eq!(idx.highest_seen_seq(), Some(12));

        // 11 fills the gap and drains 12 in one shot.
        assert_eq!(
            idx.absorb(&c11, s11).unwrap(),
            AbsorbOutcome::Advanced { new_head: 12 }
        );
        assert_eq!(idx.highest_contiguous_seq(), Some(12));
    }

    /// A changeset whose `previous_digest` doesn't chain onto the head is
    /// rejected — a relay can't fork the stream.
    #[test]
    fn a_broken_chain_is_rejected() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let (c10, _d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        idx.absorb(&c10, s10).unwrap();

        let s11 = states([modified(0xB2, 1)]);
        let wrong_previous = CheckpointDigest::new([0x99; 32]);
        let (c11, _) = signed_changeset(&committee, &keys, 11, Some(wrong_previous), &s11);
        assert_eq!(
            idx.absorb(&c11, s11),
            Err(ChangesetError::BrokenChain { seq: 11 })
        );
    }

    /// A changeset whose shipped object-set doesn't match the summary's
    /// committed artifacts digest is rejected — a relay can't add/drop ids.
    #[test]
    fn a_forged_object_set_is_rejected() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        // Summary commits to the artifacts of `honest`, but we absorb `forged`.
        let honest = states([modified(0xA1, 1), modified(0xB2, 1)]);
        let (c10, _d10) = signed_changeset(&committee, &keys, 10, None, &honest);
        let forged = states([modified(0xA1, 1)]); // dropped 0xB2
        assert_eq!(
            idx.absorb(&c10, forged),
            Err(ChangesetError::ArtifactsMismatch(10))
        );
    }

    /// Lifecycle-aware fold: delete-then-recreate is tracked, and the read path
    /// distinguishes current / stale / deleted.
    #[test]
    fn lifecycle_and_currency_verdicts() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        // 0xA1: modified@10, deleted@11, recreated (modified)@12.
        // 0xB2: deleted@11 and never recreated.
        let s10 = states([modified(0xA1, 1), modified(0xB2, 1)]);
        let s11 = states([deleted(0xA1, 2), deleted(0xB2, 2)]);
        let s12 = states([modified(0xA1, 3)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c11, d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        let (c12, _d12) = signed_changeset(&committee, &keys, 12, Some(d11), &s12);
        idx.absorb(&c10, s10).unwrap();
        idx.absorb(&c11, s11).unwrap();
        idx.absorb(&c12, s12).unwrap();

        // 0xA1's latest modification is 12; an older anchor is rolled back.
        assert_eq!(idx.currency(id(0xA1), 12), CurrencyVerdict::Current);
        assert_eq!(idx.currency(id(0xA1), 10), CurrencyVerdict::Stale);
        assert_eq!(idx.currency(id(0xA1), 11), CurrencyVerdict::Stale);
        // 0xB2's latest is a delete@11 — not a live object to serve.
        assert_eq!(idx.currency(id(0xB2), 11), CurrencyVerdict::NotLive);
    }

    /// Currency is `Unknown` outside the folded range, and for an id the index
    /// doesn't track (anchored in-range but never folded — the inclusion proof
    /// already validated the read, so currency simply falls back).
    #[test]
    fn currency_unknown_outside_range_or_untracked() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        // Empty index: no claim either way.
        assert_eq!(idx.currency(id(0xA1), 5), CurrencyVerdict::Unknown);

        let s10 = states([modified(0xA1, 1)]);
        let s11 = states([modified(0xA1, 2)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c11, _d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        idx.absorb(&c10, s10).unwrap();
        idx.absorb(&c11, s11).unwrap();

        // Outside the folded [10, 11] range → fall back to per-read.
        assert_eq!(idx.currency(id(0xA1), 9), CurrencyVerdict::Unknown);
        assert_eq!(idx.currency(id(0xA1), 12), CurrencyVerdict::Unknown);
        // An id the index never tracked, anchored inside the range → fall back.
        assert_eq!(idx.currency(id(0xFE), 10), CurrencyVerdict::Unknown);
    }

    /// The fold filter bounds the index to a chosen id set: a filtered-in id is
    /// folded and answers currency authoritatively; a filtered-out id is never
    /// folded and falls back to `Unknown` — while the full changeset is still
    /// verified each checkpoint (the filter doesn't weaken the artifacts binding).
    #[test]
    fn the_fold_filter_restricts_what_is_indexed() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let tracked = id(0xA1);
        let untracked = id(0xB2);
        let mut idx = ChangesetIndex::new().with_fold_filter(Some(HashSet::from([tracked])));

        // Both ids are in every changeset; only the tracked one is folded.
        let s10 = states([modified(0xA1, 1), modified(0xB2, 1)]);
        let s11 = states([modified(0xA1, 2), modified(0xB2, 2)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c11, _d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        idx.absorb(&c10, s10).unwrap();
        idx.absorb(&c11, s11).unwrap();

        // Tracked: authoritative. It was modified again at 11, so a read
        // anchored at 10 is stale; the latest (11) is current.
        assert_eq!(idx.currency(tracked, 11), CurrencyVerdict::Current);
        assert_eq!(idx.currency(tracked, 10), CurrencyVerdict::Stale);
        // Untracked: never folded → fall back, never a false rejection.
        assert_eq!(idx.currency(untracked, 10), CurrencyVerdict::Unknown);
        assert_eq!(idx.currency(untracked, 11), CurrencyVerdict::Unknown);
    }

    /// A retain window ages out old entries: once the head moves a window past
    /// an object's last modification, its currency falls back to `Unknown` and
    /// the index drops it; recent objects stay `Current`.
    #[test]
    fn the_retain_window_prunes_aged_out_entries() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new().with_retain_window(Some(2));

        // Chain 10..=15, each checkpoint modifying a distinct id (its seq byte).
        let mut previous = None;
        for seq in 10u64..=15 {
            let object_states = states([modified(seq as u8, 1)]);
            let (cert, digest) = signed_changeset(&committee, &keys, seq, previous, &object_states);
            idx.absorb(&cert, object_states).unwrap();
            previous = Some(digest);
        }

        // Head 15, window 2 → floor 13: ids modified at 10..12 have aged out.
        assert_eq!(idx.currency(id(10), 10), CurrencyVerdict::Unknown);
        assert_eq!(idx.currency(id(12), 12), CurrencyVerdict::Unknown);
        // Within the window the index is still authoritative.
        assert_eq!(idx.currency(id(13), 13), CurrencyVerdict::Current);
        assert_eq!(idx.currency(id(15), 15), CurrencyVerdict::Current);
        // Without a window, nothing is pruned (the default the other tests use).
    }

    // ---- verified absorb (integration bridge to the trust anchor) ----

    fn committee_store(committee: Committee) -> (tempfile::TempDir, CommitteeStore) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store =
            CommitteeStore::open(tables, Some(CommitteeBootstrap::Genesis(committee))).unwrap();
        (dir, store)
    }

    /// A changeset signed by the store's committee is BLS-verified and folded.
    /// (`#[tokio::test]` because opening the perpetual tables spawns a
    /// DB-metrics task that needs a runtime.)
    #[tokio::test]
    async fn absorb_verified_folds_a_committee_signed_changeset() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = committee_store(committee.clone());
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let (c10, _d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        assert_eq!(
            idx.absorb_verified(&store, &c10, s10).unwrap(),
            AbsorbOutcome::Advanced { new_head: 10 }
        );
        assert_eq!(idx.currency(id(0xA1), 10), CurrencyVerdict::Current);
    }

    /// A changeset signed by a committee the node doesn't trust is rejected at
    /// the BLS gate and never folded — the index is untouched.
    #[tokio::test]
    async fn absorb_verified_rejects_a_foreign_committee_signature() {
        // Deterministically-seeded test committees diverge only by size.
        let (store_committee, _) = Committee::new_simple_test_committee_of_size(4);
        let (foreign, foreign_keys) = Committee::new_simple_test_committee_of_size(7);
        let (_dir, store) = committee_store(store_committee);
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let (c10, _d10) = signed_changeset(&foreign, &foreign_keys, 10, None, &s10);
        assert!(matches!(
            idx.absorb_verified(&store, &c10, s10),
            Err(ChangesetError::Unverified(_))
        ));
        assert_eq!(
            idx.highest_contiguous_seq(),
            None,
            "must not fold an unverified changeset"
        );
        assert_eq!(idx.currency(id(0xA1), 10), CurrencyVerdict::Unknown);
    }

    /// Re-key `keys` into a committee at `epoch` (the test constructors hardcode
    /// epoch 0). Lets a test sign a summary for a *future* epoch whose committee
    /// the store hasn't installed.
    fn committee_at_epoch(epoch: u64, keys: &[AuthorityKeyPair]) -> Committee {
        use fastcrypto::traits::KeyPair;
        use sui_types::base_types::AuthorityName;
        Committee::new_for_testing_with_normalized_voting_power(
            epoch,
            keys.iter()
                .map(|key| (AuthorityName::from(key.public()), 1))
                .collect(),
        )
    }

    /// Out-of-order absorb with large gaps grows `pending` unbounded — there is
    /// no cap on the queue. Seqs 10/100/1000 absorbed out of order: 100 and 1000
    /// queue (gaps before them), the frontier stays at 10, and nothing ever
    /// drains them because the gaps are never filled. Documents the no-cap
    /// behaviour the design flags as a follow-up (a byzantine relay streaming
    /// far-future seqs would accumulate them).
    #[test]
    fn pending_queue_grows_unbounded_on_large_gaps() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let s100 = states([modified(0xA2, 1)]);
        let s1000 = states([modified(0xA3, 1)]);
        // Each is signed with *some* valid previous_digest; the seqs are not
        // adjacent, so previous-chaining never matters — they only queue.
        let (c10, _d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c1000, _d1000) = signed_changeset(
            &committee,
            &keys,
            1000,
            Some(CheckpointDigest::new([0x99; 32])),
            &s1000,
        );
        let (c100, _d100) = signed_changeset(
            &committee,
            &keys,
            100,
            Some(CheckpointDigest::new([0x88; 32])),
            &s100,
        );

        assert_eq!(
            idx.absorb(&c10, s10).unwrap(),
            AbsorbOutcome::Advanced { new_head: 10 }
        );
        // Out of order: 1000 then 100. Both queue behind the gap at 11.
        assert_eq!(idx.absorb(&c1000, s1000).unwrap(), AbsorbOutcome::Queued);
        assert_eq!(idx.absorb(&c100, s100).unwrap(), AbsorbOutcome::Queued);

        // Frontier is still 10; the queue holds both far-future seqs with no cap.
        assert_eq!(idx.highest_contiguous_seq(), Some(10));
        assert_eq!(
            idx.pending.len(),
            2,
            "no cap: both gap-creating seqs retained"
        );
        assert!(idx.pending.contains_key(&100) && idx.pending.contains_key(&1000));
        assert_eq!(idx.highest_seen_seq(), Some(1000));

        // The gap at 11 is never filled, so the queue never drains — currency
        // for the queued ids stays Unknown (frontier never reaches them).
        assert_eq!(idx.currency(id(0xA2), 100), CurrencyVerdict::Unknown);
        assert_eq!(idx.currency(id(0xA3), 1000), CurrencyVerdict::Unknown);
        assert_eq!(idx.pending.len(), 2);
    }

    /// A queued successor whose `previous_digest` does not chain onto its
    /// predecessor is dropped at the gap when the gap fills, and the drain stops
    /// there — a relay can't smuggle a forked branch in through the pending queue.
    #[test]
    fn a_queued_non_chaining_successor_is_dropped_at_the_gap() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new();

        let s10 = states([modified(0xA1, 1)]);
        let s11 = states([modified(0xB2, 1)]);
        let s12 = states([modified(0xC3, 1)]);
        let (c10, d10) = signed_changeset(&committee, &keys, 10, None, &s10);
        let (c11, _d11) = signed_changeset(&committee, &keys, 11, Some(d10), &s11);
        // 12's previous_digest is a fork — it does NOT chain onto 11's digest.
        let forked_previous = CheckpointDigest::new([0x77; 32]);
        let (c12, _d12) = signed_changeset(&committee, &keys, 12, Some(forked_previous), &s12);

        idx.absorb(&c10, s10).unwrap();
        // 12 queues (gap at 11).
        assert_eq!(idx.absorb(&c12, s12).unwrap(), AbsorbOutcome::Queued);
        assert_eq!(idx.pending.len(), 1);

        // 11 arrives, advances to 11, then drain_pending finds queued 12 whose
        // previous_digest doesn't match 11's digest → drops it and stops.
        assert_eq!(
            idx.absorb(&c11, s11).unwrap(),
            AbsorbOutcome::Advanced { new_head: 11 }
        );
        assert_eq!(
            idx.highest_contiguous_seq(),
            Some(11),
            "drain stops at the forked gap"
        );
        assert_eq!(
            idx.pending.len(),
            0,
            "the forked successor is dropped, not retained"
        );
        // 12's id never folded.
        assert_eq!(idx.currency(id(0xC3), 12), CurrencyVerdict::Unknown);
    }

    /// The retain-window floor (`oldest_folded`) is monotone non-decreasing as
    /// the head advances, and an id that became `Current` stays consistent with
    /// the rising floor: `Current` while still in window, `Unknown` once the
    /// floor passes its anchor — never silently wrong.
    #[test]
    fn retain_window_floor_is_monotone_and_never_reverts_current() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let mut idx = ChangesetIndex::new().with_retain_window(Some(5));

        let mut previous = None;
        let mut last_floor = 0u64;
        for seq in 10u64..=20 {
            // Each checkpoint modifies a distinct id keyed by its seq byte.
            let object_states = states([modified(seq as u8, 1)]);
            let (cert, digest) = signed_changeset(&committee, &keys, seq, previous, &object_states);
            idx.absorb(&cert, object_states).unwrap();
            previous = Some(digest);

            // Floor is monotone non-decreasing.
            let floor = idx.oldest_folded.expect("folded at least one checkpoint");
            assert!(
                floor >= last_floor,
                "oldest_folded reverted: {floor} < {last_floor} at head {seq}"
            );
            last_floor = floor;

            // The id modified at this very seq is Current right now (it's the
            // head, always within window).
            assert_eq!(
                idx.currency(id(seq as u8), seq),
                CurrencyVerdict::Current,
                "head id must be Current at head {seq}"
            );
        }

        // After folding 10..=20 with window 5: head 20, floor 15. An id last
        // modified at 16 is still in window → Current; one at 12 has aged out
        // below the floor → Unknown (fallback), never a wrong Current/Stale.
        assert_eq!(idx.oldest_folded, Some(15));
        assert_eq!(idx.currency(id(16), 16), CurrencyVerdict::Current);
        assert_eq!(idx.currency(id(12), 12), CurrencyVerdict::Unknown);
    }

    /// Integration: a verified-absorb path with a committee store whose head is
    /// epoch E folds a changeset signed by `committee[E]`, but rejects one signed
    /// by `committee[E+2]` — a committee the store has not installed. The reject
    /// is `Unverified` (the store can't resolve the future committee), the
    /// changeset is not folded, and the contiguous frontier does not advance.
    #[tokio::test]
    async fn pump_rejects_a_changeset_signed_by_an_uninstalled_future_committee() {
        // Store head sits at epoch 0 (E); committee[E+2] is never installed.
        let (committee_e, keys) = Committee::new_simple_test_committee();
        let committee_future = committee_at_epoch(2, &keys);
        let (_dir, store) = committee_store(committee_e.clone());
        let mut idx = ChangesetIndex::new();

        // seq 10 signed by committee[E] folds.
        let s10 = states([modified(0xA1, 1)]);
        let (c10, d10) = signed_changeset(&committee_e, &keys, 10, None, &s10);
        assert_eq!(
            idx.absorb_verified(&store, &c10, s10).unwrap(),
            AbsorbOutcome::Advanced { new_head: 10 }
        );

        // seq 11 chains correctly but is signed by the *future*, uninstalled
        // committee[E+2]. The BLS gate can't resolve that committee → rejected
        // before any fold.
        let s11 = states([modified(0xB2, 1)]);
        let (c11, _d11) = signed_changeset(&committee_future, &keys, 11, Some(d10), &s11);
        assert!(
            matches!(
                idx.absorb_verified(&store, &c11, s11),
                Err(ChangesetError::Unverified(_))
            ),
            "a changeset signed by an uninstalled future committee must be Unverified"
        );

        // Not folded: frontier stays at 10, the future id is Unknown.
        assert_eq!(idx.highest_contiguous_seq(), Some(10));
        assert_eq!(idx.currency(id(0xB2), 11), CurrencyVerdict::Unknown);
    }
}
