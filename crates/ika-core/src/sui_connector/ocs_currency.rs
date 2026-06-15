// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Currency primitives for mirrored / peer-only validators.
//!
//! A mirrored node's OCS inclusion proof attests *authenticity* (object `X`
//! was at version `V` in some committee-signed checkpoint `M`) but not
//! *currency* (`V` is still the latest version at head `N`). The
//! changeset-stream design — see
//! [`dev-docs/plans/ocs-changeset-stream-mirror-currency.md`] — closes that gap
//! by folding a committee-signed stream of modified-object-id sets and proving
//! `X@V` current iff `X`'s id appears in no checkpoint after `M`. The audit /
//! fallback path for that "appears in no checkpoint" claim is a Merkle
//! *non-inclusion* proof against each checkpoint's `ModifiedObjectTree`.
//!
//! This module starts that subsystem with its single load-bearing primitive:
//! an **id-binding** check on non-inclusion proofs (the design's "Blocker 1").
//! Until it exists, no read path may consume a non-inclusion proof.

use std::collections::{BTreeMap, HashMap};
use sui_light_client::proof::ocs::OCSNonInclusionProof;
use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber};
use sui_types::digests::CheckpointDigest;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointArtifacts, CheckpointSequenceNumber,
};

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
    /// The frontier doesn't cover `M` yet — caller must fall back to per-read
    /// verification (no currency claim either way).
    Unknown,
    /// The proof anchors a modification of the id at `M` that the folded,
    /// committee-signed changeset for that range doesn't corroborate.
    Inconsistent,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ChangesetError {
    #[error(
        "changeset object-set at seq {0} does not match the summary's committed artifacts digest"
    )]
    ArtifactsMismatch(CheckpointSequenceNumber),
    #[error("changeset at seq {seq} does not forward-chain onto the contiguous head")]
    BrokenChain { seq: CheckpointSequenceNumber },
    #[error("internal: {0}")]
    Internal(String),
}

struct PendingChangeset {
    digest: CheckpointDigest,
    previous_digest: Option<CheckpointDigest>,
    object_states: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)>,
}

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
        }
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
                } else {
                    self.pending.insert(seq, incoming);
                    Ok(AbsorbOutcome::Queued)
                }
            }
        }
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
            // last_seq < anchored_seq, or the id never appears in the folded
            // range: the inclusion proof claims `anchored_seq` modified the id,
            // but the committee-signed changeset for that range disagrees.
            _ => CurrencyVerdict::Inconsistent,
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
            self.index.insert(
                *id,
                IdRecord {
                    last_seq: seq,
                    status: IdStatus::from_digest(digest),
                },
            );
        }
    }

    /// After advancing the head, pull in any queued successors that now chain.
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::merkle::{MerkleNonInclusionProof, Node};
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

    /// Currency is `Unknown` outside the folded range and `Inconsistent` when
    /// the anchor claims a modification the folded chain doesn't corroborate.
    #[test]
    fn currency_unknown_and_inconsistent() {
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
        // An id the folded range never modified, anchored inside it → the
        // inclusion proof contradicts the committee-signed changeset.
        assert_eq!(idx.currency(id(0xFE), 10), CurrencyVerdict::Inconsistent);
    }
}
