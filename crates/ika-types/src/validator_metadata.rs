// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Off-chain validator metadata types.
//!
//! Validators publish their MPC class-groups public material via consensus
//! (and via P2P relay for next-epoch joiners) instead of relying on the
//! on-chain `mpc_data_bytes` field for validator-internal consumption.
//! The blob is referenced by `Blake2b256` hash; the blob bytes themselves
//! travel out-of-band over P2P.

use crate::committee::EpochId;
use crate::crypto::{AuthorityName, AuthoritySignInfo};
use fastcrypto::ed25519::Ed25519Signature;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

/// What a validator announces over consensus: its identity, the epoch
/// the announcement is for, a timestamp (used for the latest-by-timestamp
/// insert rule), and the Blake2b256 digest of its BCS-encoded
/// `VersionedMPCData` blob. The blob bytes themselves are out-of-band.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidatorMpcDataAnnouncement {
    pub validator: AuthorityName,
    pub epoch: EpochId,
    pub timestamp_ms: u64,
    pub blob_hash: [u8; 32],
}

/// `ValidatorMpcDataAnnouncement` plus an `AuthoritySignInfo` (BLS)
/// signature by the validator. Verifiers look up the signer's
/// protocol pubkey in the current committee (for current-epoch
/// announcements) or the `PendingActiveSet` (for cross-epoch joiner
/// announcements).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedValidatorMpcDataAnnouncement {
    pub announcement: ValidatorMpcDataAnnouncement,
    pub auth_sig: AuthoritySignInfo,
}

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

/// "I have my own `ValidatorMpcDataAnnouncement` (and any pending
/// joiner relays) submitted to consensus and am ready for the
/// epoch's MPC operations" — broadcast via consensus once per epoch
/// per validator. Once a stake quorum of these signals is observed in
/// consensus order, every honest validator snapshots the current set
/// of `(validator, blob_hash)` mpc-data digests as the *epoch-wide
/// frozen input set* used by both network DKG and reconfiguration MPC
/// sessions in this epoch.
///
/// Authentication: the consensus authority binding (sender ==
/// `authority`) is sufficient; no separate signature is needed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EpochMpcDataReadySignal {
    pub authority: AuthorityName,
    pub epoch: EpochId,
}

/// Per-network-key counterpart to `EpochMpcDataReadySignal`:
/// "I'm ready to participate in network DKG for `network_key_id`
/// this epoch." Validators may broadcast this earlier than the
/// epoch-wide signal because per-key readiness is a narrower
/// commitment (the validator has the mpc_data it needs for *this*
/// key's DKG, not necessarily all reconfig sessions).
///
/// First quorum of *either* signal kind freezes the same epoch-wide
/// `frozen_validator_mpc_data_input_set` — there is only one frozen
/// set per epoch, consumed by both genesis DKG and reconfig MPC.
/// Subsequent quorums (or per-key quorums on the same epoch) don't
/// re-freeze; `freeze_mpc_data_if_first` is idempotent.
///
/// Authentication: consensus authority binding (sender ==
/// `authority`); no payload signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NetworkKeyDKGReadySignal {
    pub authority: AuthorityName,
    pub network_key_id: ObjectID,
    pub epoch: EpochId,
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

    #[test]
    fn validator_mpc_data_announcement_roundtrip() {
        let auth = make_authority(2);
        let announcement = ValidatorMpcDataAnnouncement {
            validator: auth,
            epoch: 42,
            timestamp_ms: 1_000_000,
            blob_hash: [0xDE; 32],
        };
        let bytes = bcs::to_bytes(&announcement).expect("encode");
        let decoded: ValidatorMpcDataAnnouncement = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(announcement, decoded);
    }

    #[test]
    fn epoch_mpc_data_ready_signal_roundtrip() {
        let signal = EpochMpcDataReadySignal {
            authority: make_authority(3),
            epoch: 99,
        };
        let bytes = bcs::to_bytes(&signal).expect("encode");
        let decoded: EpochMpcDataReadySignal = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(signal, decoded);
    }
}
