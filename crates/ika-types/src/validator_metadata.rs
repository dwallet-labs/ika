// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Off-chain validator metadata types.
//!
//! Validators publish their MPC class-groups public material via consensus
//! (and via P2P relay for next-epoch joiners) instead of relying on the
//! on-chain `mpc_data_bytes` field for validator-internal consumption.
//! The blob is referenced by `Blake2b256` hash; the blob bytes themselves
//! travel out-of-band over P2P.
//!
//! The generic handoff-attestation types live in [`crate::handoff`].

use crate::committee::EpochId;
use crate::crypto::{AuthorityName, AuthoritySignInfo};
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

/// What a validator announces over consensus: its identity, a
/// timestamp (used for the latest-by-timestamp insert rule), and
/// the Blake2b256 digest of its BCS-encoded `VersionedMPCData`
/// blob. The blob bytes themselves are out-of-band over P2P.
///
/// The announcement deliberately does NOT carry the epoch in its
/// body. The signed envelope's `auth_sig.epoch` is the canonical
/// epoch binding — duplicating it inside the announcement is wire
/// bloat that doesn't add safety (the signature commits to both
/// the body and an epoch-AAD via `AuthoritySignature::new_secure`,
/// and `auth_sig.epoch` is what gets passed to `verify_secure`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidatorMpcDataAnnouncement {
    pub validator: AuthorityName,
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

/// "I have my own `ValidatorMpcDataAnnouncement` (and any pending
/// joiner relays) submitted to consensus and am ready for the
/// epoch's MPC operations" — broadcast via consensus once per epoch
/// per validator. Once a stake quorum of these signals is observed
/// in consensus order, every honest validator computes the frozen
/// mpc-data input set deterministically from per-peer attestations
/// (`validated_peers` below).
///
/// `validated_peers` is the set of authorities whose mpc_data blob
/// this signer has locally fetched, hash-verified, and structurally
/// decoded. The freeze gate uses this to decide which announcers
/// cross into `frozen_validator_mpc_data_input_set`: a validator is
/// frozen-in iff a stake-quorum of `EpochMpcDataReadySignal`s
/// attests to having a valid blob for them. Announcers that don't
/// reach that threshold are dropped from the working set — same
/// semantics as today's "validator with bad chain mpc_data is
/// ignored," made consensus-deterministic.
///
/// An honest validator should emit this signal only when its own
/// `validated_peers` (or `validated_peers ∪ {self}`) covers a stake
/// quorum of the current committee. Emitting earlier would let
/// network DKG / reconfig start before mpc_data has propagated
/// across the network.
///
/// Authentication: the consensus authority binding (sender ==
/// `authority`) is sufficient; no separate signature is needed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EpochMpcDataReadySignal {
    pub authority: AuthorityName,
    pub epoch: EpochId,
    /// Authorities whose mpc_data blob this signer has locally
    /// decode-validated. Wire-encoded as a sorted `Vec` (we sort
    /// on emit) so the BCS bytes are canonical and identical
    /// across honest validators with the same view.
    pub validated_peers: Vec<AuthorityName>,
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

    fn make_authority(byte: u8) -> AuthorityName {
        AuthorityName::new([byte; 48])
    }

    #[test]
    fn validator_mpc_data_announcement_roundtrip() {
        let auth = make_authority(2);
        let announcement = ValidatorMpcDataAnnouncement {
            validator: auth,
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
            validated_peers: vec![make_authority(1), make_authority(2)],
        };
        let bytes = bcs::to_bytes(&signal).expect("encode");
        let decoded: EpochMpcDataReadySignal = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(signal, decoded);
    }
}
