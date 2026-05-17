// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Generic epoch-handoff attestation types.
//!
//! The handoff attestation is a per-epoch cryptographic checkpoint
//! the outgoing committee produces at EndOfPublish. It pins
//! `(key, digest)` pairs the next committee needs to operate. The
//! attestation is signed by every member of the outgoing committee
//! (using their consensus / Ed25519 key) and aggregated to a
//! `CertifiedHandoffAttestation` once quorum is reached.
//!
//! Item kinds are deliberately closed for now (`HandoffItemKey` is a
//! typed enum) so non-Rust verifiers can rely on a fixed schema.
//! New kinds get added as new enum variants.

use crate::committee::EpochId;
use crate::crypto::AuthorityName;
use fastcrypto::ed25519::Ed25519Signature;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

/// Identifies a single piece of state covered by a `HandoffAttestation`.
///
/// Variant order (and the field order within each variant) determines
/// the `Ord`-derived ordering used to canonicalize the items list. The
/// canonical BCS serialization (a length-prefixed Vec sorted strictly
/// ascending by key) is what every validator's signature commits to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HandoffItemKey {
    /// Network DKG public output for a specific encryption key. Stable
    /// across an encryption key's lifetime.
    NetworkDkgOutput { key_id: ObjectID },
    /// Network reconfiguration public output for a specific encryption
    /// key, produced this epoch.
    NetworkReconfigurationOutput { key_id: ObjectID },
    /// MPC class-groups public material of a committee member, pinned
    /// to the exact version that was consumed as input by this epoch's
    /// MPC sessions.
    ValidatorMpcData { validator: AuthorityName },
}

/// What the outgoing committee at the end of `epoch` attests to: a set
/// of digests pinning the inputs and outputs the next committee needs
/// to operate.
///
/// `items` is a sorted `Vec<(HandoffItemKey, [u8; 32])>` rather than a
/// `BTreeMap` so the wire format is a plain length-prefixed list, which
/// non-Rust verifiers (Move, JS, etc.) can decode with whatever BCS
/// list support they have without needing map-aware bindings. The
/// `Ord` derive on `HandoffItemKey` defines the canonical order; the
/// list MUST be sorted by key on construction (see
/// `build_handoff_attestation` in ika-core) and verifiers SHOULD
/// reject lists that aren't strictly sorted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HandoffAttestation {
    /// The epoch the outgoing committee is handing off *from*.
    pub epoch: EpochId,
    /// Blake2b256 digest of the next committee's BLS pubkey set; binds
    /// the attestation to the specific committee receiving the handoff.
    pub next_committee_pubkey_set_hash: [u8; 32],
    /// Per-item digests, sorted strictly ascending by `HandoffItemKey`.
    pub items: Vec<(HandoffItemKey, [u8; 32])>,
}

/// Per-validator signature over a `HandoffAttestation`, signed with
/// the validator's *consensus key* (Ed25519) — not their authority /
/// protocol key. Authority/protocol keys are reserved for Sui Move-side
/// signature verification flows; cross-validator off-chain signatures
/// like this one use the consensus key, which verifiers look up in the
/// previous committee's on-chain validator info as `consensus_pubkey`.
///
/// `signer` identifies the validator (by their `AuthorityName`, i.e.
/// protocol pubkey), but the `signature` is over
/// `bcs(IntentMessage::new(Intent::ika_app(HandoffAttestation), attestation))`
/// using `signer`'s consensus key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffSignatureMessage {
    pub attestation: HandoffAttestation,
    pub signer: AuthorityName,
    pub signature: Ed25519Signature,
}

/// Aggregated handoff attestation: per-signer Ed25519 signatures
/// (consensus key) collected by every validator independently from
/// consensus-ordered `HandoffSignatureMessage`s. Verifiers iterate
/// signatures, look up each signer's `consensus_pubkey` from the
/// previous committee's on-chain validator info, verify each signature
/// over the same attestation, and check the summed
/// `committee.weight(signer)` reaches the committee's quorum
/// threshold. Ed25519 doesn't aggregate, so this is a list rather
/// than a single aggregate sig + bitmap.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertifiedHandoffAttestation {
    pub attestation: HandoffAttestation,
    pub signatures: Vec<(AuthorityName, Ed25519Signature)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_types::base_types::ObjectID;

    fn make_authority(byte: u8) -> AuthorityName {
        // BLS12381 min_pk public keys are 48 bytes. The fake bytes
        // never need to verify a real signature in the type-level
        // roundtrip tests below.
        AuthorityName::new([byte; 48])
    }

    #[test]
    fn handoff_item_key_ord_is_stable_across_variants() {
        // Variant order in the enum defines the canonical sort key
        // for items; freeze it so reordering the enum is caught
        // here.
        let key_id_a = ObjectID::random();
        let key_id_b = ObjectID::random();
        let auth = make_authority(0);
        let mut keys = vec![
            HandoffItemKey::ValidatorMpcData { validator: auth },
            HandoffItemKey::NetworkReconfigurationOutput { key_id: key_id_a },
            HandoffItemKey::NetworkDkgOutput { key_id: key_id_b },
        ];
        keys.sort();
        assert!(matches!(keys[0], HandoffItemKey::NetworkDkgOutput { .. }));
        assert!(matches!(
            keys[1],
            HandoffItemKey::NetworkReconfigurationOutput { .. }
        ));
        assert!(matches!(keys[2], HandoffItemKey::ValidatorMpcData { .. }));
    }

    #[test]
    fn handoff_attestation_bcs_roundtrip_preserves_sorted_items() {
        let key_id = ObjectID::random();
        let auth = make_authority(1);
        let attestation = HandoffAttestation {
            epoch: 7,
            next_committee_pubkey_set_hash: [0xAA; 32],
            items: vec![
                (HandoffItemKey::NetworkDkgOutput { key_id }, [0x11; 32]),
                (
                    HandoffItemKey::NetworkReconfigurationOutput { key_id },
                    [0x22; 32],
                ),
                (
                    HandoffItemKey::ValidatorMpcData { validator: auth },
                    [0x33; 32],
                ),
            ],
        };
        let bytes = bcs::to_bytes(&attestation).expect("encode");
        let decoded: HandoffAttestation = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(attestation, decoded);
    }
}
