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
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::{
    EpochMpcDataReadySignal, SignedValidatorMpcDataAnnouncement, ValidatorMpcDataAnnouncement,
};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Look up whether a given authority is registered as a next-epoch
/// joiner — i.e., its pubkey is in the `PendingActiveSet` (and the
/// staking pool's `next_epoch_protocol_pubkey`, if set, matches that
/// pubkey). Returning `true` certifies the announcement signer; the
/// caller then verifies the signature using `authority` directly as
/// the pubkey (`AuthorityName == AuthorityPublicKeyBytes`).
///
/// The Sui-backed impl reads `validator_set.pending_active_set` plus
/// each entry's `StakingPool.validator_info`'s next-epoch pubkey,
/// hosted by a `sui_syncer` task that refreshes on a cadence (and on
/// `CommitteeSelected` events). Before the syncer task is up, an
/// empty provider is installed, which drops all joiner announcements
/// — current-committee announcements still work.
pub trait JoinerPubkeyProvider: Send + Sync + 'static {
    fn is_registered_joiner(&self, authority: &AuthorityName) -> bool;
}

/// In-memory `JoinerPubkeyProvider` over a fixed `AuthorityName` set.
/// Used as the default no-op (empty set) and by tests.
pub struct StaticJoinerPubkeyProvider {
    members: HashSet<AuthorityName>,
}

impl StaticJoinerPubkeyProvider {
    pub fn empty() -> Self {
        Self {
            members: HashSet::new(),
        }
    }

    pub fn from_iter<I: IntoIterator<Item = AuthorityName>>(members: I) -> Self {
        Self {
            members: members.into_iter().collect(),
        }
    }
}

impl JoinerPubkeyProvider for StaticJoinerPubkeyProvider {
    fn is_registered_joiner(&self, authority: &AuthorityName) -> bool {
        self.members.contains(authority)
    }
}

/// Outcome of validating a next-epoch joiner announcement, before
/// inserting it into the per-epoch store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinerAnnouncementVerdict {
    /// All checks passed; caller may proceed to apply the
    /// latest-by-timestamp insert rule.
    Accept,
    /// The provider doesn't know about this authority. Drop the
    /// announcement; it's either spam or the provider is stale.
    UnregisteredJoiner,
    /// The signature didn't verify against the claimed authority
    /// for `expected_epoch`.
    InvalidSignature,
    /// `signed.announcement.epoch != signed.auth_sig.epoch` or the
    /// announcement validator != sig authority.
    InconsistentEnvelope,
}

/// Pure verification of a next-epoch joiner announcement. Intended
/// for both unit tests and for `AuthorityPerEpochStore`'s next-epoch
/// branch — the per-epoch-store method calls this and only inserts
/// on `Accept`. Returning anything other than `Accept` is non-fatal
/// (callers should `drop and log`); these are protocol-level
/// outcomes, not unexpected errors.
pub fn verify_joiner_announcement(
    signed: &SignedValidatorMpcDataAnnouncement,
    provider: &dyn JoinerPubkeyProvider,
    expected_epoch: EpochId,
) -> JoinerAnnouncementVerdict {
    use ika_types::crypto::IkaAuthoritySignature;
    use ika_types::intent::IntentMessage;
    if signed.announcement.epoch != signed.auth_sig.epoch
        || signed.announcement.validator != signed.auth_sig.authority
        || signed.announcement.epoch != expected_epoch
    {
        return JoinerAnnouncementVerdict::InconsistentEnvelope;
    }
    if !provider.is_registered_joiner(&signed.auth_sig.authority) {
        return JoinerAnnouncementVerdict::UnregisteredJoiner;
    }
    let intent_msg = IntentMessage::new(
        Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
        signed.announcement.clone(),
    );
    match ika_types::crypto::AuthoritySignature::verify_secure(
        &signed.auth_sig.signature,
        &intent_msg,
        expected_epoch,
        signed.auth_sig.authority,
    ) {
        Ok(()) => JoinerAnnouncementVerdict::Accept,
        Err(_) => JoinerAnnouncementVerdict::InvalidSignature,
    }
}

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

/// Builds the `ConsensusTransaction` that wraps an
/// `EpochMpcDataReadySignal`. The signal carries no payload signature
/// — the consensus authority binding (sender == authority) is the
/// only authentication needed, and the consensus handler enforces it
/// at message verification time.
pub fn build_epoch_mpc_data_ready_signal_transaction(
    authority: AuthorityName,
    epoch: EpochId,
) -> ConsensusTransaction {
    let signal = EpochMpcDataReadySignal { authority, epoch };
    ConsensusTransaction::new_epoch_mpc_data_ready_signal(signal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::KeyPair;
    use ika_network::validator_metadata::mpc_data_blob_hash;
    use ika_types::crypto::AuthoritySignInfoTrait;
    use ika_types::crypto::random_committee_key_pairs_of_size;

    fn name_of(kp: &AuthorityKeyPair) -> AuthorityName {
        kp.public().into()
    }

    fn build_signed_for_epoch(
        kp: &AuthorityKeyPair,
        target_epoch: EpochId,
        blob_hash: [u8; 32],
    ) -> SignedValidatorMpcDataAnnouncement {
        sign_validator_mpc_data_announcement(name_of(kp), target_epoch, 42_000, blob_hash, kp)
    }

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

    #[test]
    fn verify_joiner_accepts_well_formed_registered_signer() {
        // Joiner produced a sig for next epoch; the provider lists
        // them as registered; bytes are byte-perfect — expect Accept.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let next_epoch: EpochId = 7;
        let signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::Accept
        );
    }

    #[test]
    fn verify_joiner_rejects_unregistered_signer() {
        // Provider doesn't know this joiner — drop.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let next_epoch: EpochId = 7;
        let signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::empty();
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::UnregisteredJoiner
        );
    }

    #[test]
    fn verify_joiner_rejects_tampered_blob_hash() {
        // Sig was over the original blob_hash; tamper post-sign and
        // the signature won't verify against the new bytes even
        // though the signer is registered.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let next_epoch: EpochId = 7;
        let mut signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        signed.announcement.blob_hash = [0x99; 32];
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::InvalidSignature
        );
    }

    #[test]
    fn verify_joiner_rejects_wrong_epoch() {
        // Joiner signed for epoch 8 but caller is processing epoch
        // 7. Reject before signature check — the envelope is
        // inconsistent with what we're processing.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let signed = build_signed_for_epoch(&kp, 8, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, 7),
            JoinerAnnouncementVerdict::InconsistentEnvelope
        );
    }

    #[test]
    fn verify_joiner_rejects_envelope_authority_mismatch() {
        // The envelope claims one validator but the auth sig was
        // produced by a different keypair (post-sign mutation of
        // the announcement.validator field).
        let mut kps = random_committee_key_pairs_of_size(2);
        let kp_signer = kps.remove(0);
        let kp_other = kps.remove(0);
        let other_name = name_of(&kp_other);
        let next_epoch: EpochId = 7;
        let mut signed = build_signed_for_epoch(&kp_signer, next_epoch, [0x77; 32]);
        signed.announcement.validator = other_name;
        let provider = StaticJoinerPubkeyProvider::from_iter([other_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::InconsistentEnvelope
        );
    }

    #[test]
    fn static_provider_round_trip() {
        // The fixture rng is seeded-deterministic, so a separate
        // `random_committee_key_pairs_of_size(N)` call returns the
        // *same* prefix. To get a non-member, allocate 4 keys and
        // hold the last one out of the provider.
        let kps = random_committee_key_pairs_of_size(4);
        let registered_names: Vec<AuthorityName> = kps[..3].iter().map(name_of).collect();
        let unknown_name = name_of(&kps[3]);
        let provider = StaticJoinerPubkeyProvider::from_iter(registered_names.iter().copied());
        for n in &registered_names {
            assert!(provider.is_registered_joiner(n));
        }
        assert!(!provider.is_registered_joiner(&unknown_name));
    }
}
