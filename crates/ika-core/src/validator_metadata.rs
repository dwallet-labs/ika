// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Producer-side helpers for the off-chain validator-metadata flow.
//!
//! `derive_mpc_data_blob` produces the canonical BCS bytes that a
//! validator commits to (this is what gets hashed and announced; the
//! same bytes are served over P2P). `sign_validator_mpc_data_announcement`
//! builds the `SignedValidatorMpcDataAnnouncement` ready for consensus.
//!
//! These functions are deterministic given the same seed (modulo the
//! `timestamp_ms` parameter), so producer-side and any verifier
//! re-derivation will produce byte-identical blobs.

use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::{MPCDataV1, VersionedMPCData};
use dwallet_rng::RootSeed;
use ika_types::committee::EpochId;
use ika_types::crypto::{AuthorityKeyPair, AuthorityName, AuthoritySignInfo};
use ika_types::error::{IkaError, IkaResult};
use ika_types::intent::{Intent, IntentScope};
use ika_types::validator_metadata::{
    SignedValidatorMpcDataAnnouncement, ValidatorMpcDataAnnouncement,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Derives the canonical MPC data blob (BCS-encoded
/// `VersionedMPCData::V1`) from a `RootSeed` — the same encoding the
/// CLI submits on chain via `set_next_epoch_mpc_data_bytes`. Both
/// paths hashing this output produce the same digest.
pub fn derive_mpc_data_blob(seed: &RootSeed) -> IkaResult<Vec<u8>> {
    let key_and_proof = ClassGroupsKeyPairAndProof::from_seed(seed).encryption_key_and_proof();
    let inner = bcs::to_bytes(&key_and_proof)
        .map_err(|e| IkaError::Unknown(format!("bcs encode class-groups key+proof: {e}")))?;
    let mpc_data = VersionedMPCData::V1(MPCDataV1 {
        class_groups_public_key_and_proof: inner,
    });
    bcs::to_bytes(&mpc_data)
        .map_err(|e| IkaError::Unknown(format!("bcs encode versioned mpc data: {e}")))
}

/// Returns the current wall-clock time as milliseconds since the
/// Unix epoch. Used as the `timestamp_ms` field of a new
/// announcement; the latest-by-timestamp rule means later calls
/// (e.g. after a seed rotation) win.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Signs a `ValidatorMpcDataAnnouncement` with the validator's
/// authority (BLS) keypair, producing a
/// `SignedValidatorMpcDataAnnouncement` ready to submit via consensus.
pub fn sign_validator_mpc_data_announcement(
    validator: AuthorityName,
    epoch: EpochId,
    timestamp_ms: u64,
    blob_hash: [u8; 32],
    keypair: &AuthorityKeyPair,
) -> SignedValidatorMpcDataAnnouncement {
    let announcement = ValidatorMpcDataAnnouncement {
        validator,
        epoch,
        timestamp_ms,
        blob_hash,
    };
    let auth_sig = AuthoritySignInfo::new(
        epoch,
        &announcement,
        Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
        validator,
        keypair,
    );
    SignedValidatorMpcDataAnnouncement {
        announcement,
        auth_sig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::KeyPair;
    use ika_network::validator_metadata::mpc_data_blob_hash;
    use ika_types::crypto::AuthoritySignInfoTrait;
    use ika_types::crypto::random_committee_key_pairs_of_size;

    #[test]
    fn derive_mpc_data_blob_is_deterministic() {
        // Same seed → byte-identical blob (and therefore identical
        // digest). This is what guarantees the off-chain blob bytes
        // match what the CLI would have written to chain.
        let seed_bytes = [42u8; 32];
        let seed1 = RootSeed::new(seed_bytes);
        let seed2 = RootSeed::new(seed_bytes);
        let b1 = derive_mpc_data_blob(&seed1).expect("derive");
        let b2 = derive_mpc_data_blob(&seed2).expect("derive");
        assert_eq!(b1, b2);
        assert_eq!(mpc_data_blob_hash(&b1), mpc_data_blob_hash(&b2));
    }

    #[test]
    fn sign_announcement_verifies_against_signer() {
        // Construct a committee containing our signer, then verify
        // the signed announcement against it. Catches: intent
        // scope mismatches, epoch mismatches, key-derivation bugs.
        // Use the project's seeded-deterministic test keypair
        // generator to avoid the fastcrypto `AllowedRng` version
        // skew on directly-calling `KeyPair::generate`.
        let mut keypairs = random_committee_key_pairs_of_size(1);
        let kp: AuthorityKeyPair = keypairs.remove(0);
        let name: AuthorityName = (kp.public()).into();
        let voting_rights = vec![(name, 1u64)];
        let committee = ika_types::committee::Committee::new(
            5, // epoch
            voting_rights,
            std::collections::HashMap::new(),
            1,
            1,
        );

        let signed = sign_validator_mpc_data_announcement(name, 5, 1_000, [0xAB; 32], &kp);
        signed
            .auth_sig
            .verify_secure(
                &signed.announcement,
                Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
                &committee,
            )
            .expect("sig should verify");

        // Tamper the announcement → sig should fail.
        let mut tampered = signed.clone();
        tampered.announcement.timestamp_ms = 999;
        assert!(
            tampered
                .auth_sig
                .verify_secure(
                    &tampered.announcement,
                    Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
                    &committee,
                )
                .is_err()
        );
    }
}
