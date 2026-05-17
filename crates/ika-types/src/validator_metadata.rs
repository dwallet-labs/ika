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

    fn make_authority(byte: u8) -> AuthorityName {
        AuthorityName::new([byte; 48])
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
