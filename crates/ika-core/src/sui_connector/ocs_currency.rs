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

use sui_light_client::proof::ocs::OCSNonInclusionProof;
use sui_types::base_types::ObjectID;

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

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::merkle::{MerkleNonInclusionProof, Node};
    use std::collections::BTreeMap;
    use sui_light_client::proof::ocs::ModifiedObjectTree;
    use sui_types::base_types::{ObjectDigest, ObjectRef, SequenceNumber};
    use sui_types::messages_checkpoint::CheckpointArtifacts;

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
}
