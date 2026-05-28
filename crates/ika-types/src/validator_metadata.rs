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
use crate::crypto::AuthorityName;
use fastcrypto::ed25519::Ed25519Signature;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;

/// What a validator announces over consensus: its identity, the
/// epoch it's announcing for, a timestamp (the version for the
/// latest-by-timestamp insert rule), and the Blake2b256 digest of
/// its BCS-encoded `VersionedMPCData` blob. The blob bytes
/// themselves are out-of-band over P2P.
///
/// `epoch` lives in the body because the signing key changed to the
/// Ed25519 consensus key: there's no longer an `AuthoritySignInfo`
/// envelope to carry it. For a relayed joiner announcement the
/// joiner's signature is over this whole body, so the epoch is
/// signature-bound — a sig for one epoch can't be replayed into
/// another. It's also the source of the `epoch` component of the
/// consensus dedup key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidatorMpcDataAnnouncement {
    pub validator: AuthorityName,
    pub epoch: EpochId,
    pub timestamp_ms: u64,
    pub blob_hash: [u8; 32],
}

/// A joiner's `ValidatorMpcDataAnnouncement` plus an Ed25519
/// signature by the joiner's **consensus** key. Used only on the
/// relay path: a next-epoch joiner isn't a consensus participant
/// yet, so it can't submit directly; it signs with its consensus
/// key and fans the signed announcement out to current-committee
/// peers, which verify the signature against the joiner's
/// next-epoch consensus pubkey before relaying it into consensus.
///
/// Current-committee validators submit the bare
/// `ValidatorMpcDataAnnouncement` directly (no signature — the
/// consensus block author authenticates them), so this signed
/// envelope exists only for the joiner-relay case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedValidatorMpcDataAnnouncement {
    pub announcement: ValidatorMpcDataAnnouncement,
    pub joiner_sig: Ed25519Signature,
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
/// across the network. When new peer blobs land after the first
/// emit, the producer re-emits with `sequence_number` incremented
/// (see below) — the consensus key includes the sequence number so
/// re-emits aren't dropped by the same-key dedup gate, and the
/// receive-side strict-superset rule prevents byzantine oscillation
/// between attestation sets.
///
/// Authentication: the consensus authority binding (sender ==
/// `authority`) is sufficient; no separate signature is needed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EpochMpcDataReadySignal {
    pub authority: AuthorityName,
    pub epoch: EpochId,
    /// Monotonically-increasing per-signer-per-epoch counter,
    /// starting at 0 for the first emit and bumped on every
    /// re-emit. Included in `ConsensusTransactionKey` so the
    /// generic same-key dedup at consensus verify doesn't drop
    /// re-emits — without this counter, only the first emit per
    /// (authority, epoch) would reach `record_epoch_mpc_data_ready_signal`
    /// and the strict-superset re-emit gate would never fire.
    pub sequence_number: u64,
    /// Authorities whose mpc_data blob this signer has locally
    /// decode-validated. Wire-encoded as a sorted `Vec` (we sort
    /// on emit) so the BCS bytes are canonical and identical
    /// across honest validators with the same view.
    pub validated_peers: Vec<AuthorityName>,
}

/// Per-network-key counterpart to `EpochMpcDataReadySignal`:
/// "I'm ready to participate in network DKG for `network_key_id`
/// this epoch."
///
/// Only `EpochMpcDataReadySignal` triggers the epoch-wide
/// `frozen_validator_mpc_data_input_set` freeze. This per-key
/// variant is currently recorded for future per-key DKG kickoff
/// logic but does NOT feed the freeze tally — early test runs
/// showed that letting per-key quorum drive the freeze excluded
/// late mpc_data announcers, so the freeze gate is gated only on
/// epoch-wide signals.
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
            epoch: 7,
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
            sequence_number: 7,
            validated_peers: vec![make_authority(1), make_authority(2)],
        };
        let bytes = bcs::to_bytes(&signal).expect("encode");
        let decoded: EpochMpcDataReadySignal = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(signal, decoded);
    }
}
