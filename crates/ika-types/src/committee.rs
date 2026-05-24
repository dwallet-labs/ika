// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::crypto::{
    AuthorityKeyPair, AuthorityName, AuthorityPublicKey, NetworkPublicKey,
    random_committee_key_pairs_of_size,
};
use crate::error::{IkaError, IkaResult};
use class_groups::CompactIbqf;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, KnowledgeOfDiscreteLogUCProof, MAX_PRIMES,
};
use fastcrypto::traits::KeyPair;
use group::PartyID;
use group::curve25519;
pub use ika_protocol_config::ProtocolVersion;
use mpc::hybrid_public_key_encryption::{
    KnowledgeOfDecryptionKeyUCProof as VssHpkeKnowledgeOfDecryptionKeyUCProof,
    parse_and_uc_verify_encryption_keys,
};
use rand::rngs::{StdRng, ThreadRng};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use sui_types::base_types::*;
use sui_types::multiaddr::Multiaddr;

pub type EpochId = u64;

// TODO: the stake and voting power of a validator can be different so
// in some places when we are actually referring to the voting power, we
// should use a different type alias, field name, etc.
pub type StakeUnit = u64;

pub type CommitteeDigest = [u8; 32];

// The voting power, quorum threshold and max voting power are defined in the `voting_power.move` module.
// We're following the very same convention in the validator binaries.

#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct Committee {
    pub epoch: EpochId,
    pub voting_rights: Vec<(AuthorityName, StakeUnit)>,
    pub class_groups_public_keys_and_proofs:
        HashMap<AuthorityName, ClassGroupsEncryptionKeyAndProof>,
    /// Per-validator PVSS HPKE encryption key + UC-secure proof of knowledge of
    /// the corresponding decryption key, parameterised for the secp256k1
    /// plaintext space. Sibling of `class_groups_public_keys_and_proofs`; new at
    /// the `cryptography-private @ 9d35fa76` bump. See
    /// `Secp256k1PvssEncryptionKeyAndProof` and `ValidatorEncryptionKeysAndProofs`
    /// for the shape and the mainnet-incompat warning.
    pub secp256k1_pvss_public_keys_and_proofs:
        HashMap<AuthorityName, Secp256k1PvssEncryptionKeyAndProof>,
    /// Per-validator PVSS HPKE encryption key + proof, secp256r1 plaintext space.
    pub secp256r1_pvss_public_keys_and_proofs:
        HashMap<AuthorityName, Secp256r1PvssEncryptionKeyAndProof>,
    /// Per-validator PVSS HPKE encryption key + proof, ristretto plaintext space.
    pub ristretto_pvss_public_keys_and_proofs:
        HashMap<AuthorityName, RistrettoPvssEncryptionKeyAndProof>,
    /// Per-party Fast Schnorr (VSS) HPKE encryption public key values
    /// (curve25519, serializable form), filtered to **only** the parties whose
    /// published UC proof of knowledge of the matching decryption key verified.
    ///
    /// Computed once at [`Self::new`] from the raw
    /// `vss_hpke_public_keys_and_proofs` input by
    /// `mpc::hybrid_public_key_encryption::parse_and_uc_verify_encryption_keys`.
    /// The raw proofs are NOT retained — we keep only the verified result so the
    /// per-presign session cost is a cheap curve-point parse, not a UC proof
    /// re-verification. Parties whose key didn't parse or whose proof didn't
    /// verify are simply absent.
    pub vss_hpke_verified_party_encryption_key_values: HashMap<PartyID, curve25519::Value>,
    pub quorum_threshold: u64,
    pub validity_threshold: u64,
    expanded_keys: HashMap<AuthorityName, AuthorityPublicKey>,
    /// AuthorityName -> to PartyID (from 0).
    index_map: HashMap<AuthorityName, usize>,
}

impl Committee {
    pub fn new(
        epoch: EpochId,
        voting_rights: Vec<(AuthorityName, StakeUnit)>,
        class_groups_public_keys_and_proofs: HashMap<
            AuthorityName,
            ClassGroupsEncryptionKeyAndProof,
        >,
        secp256k1_pvss_public_keys_and_proofs: HashMap<
            AuthorityName,
            Secp256k1PvssEncryptionKeyAndProof,
        >,
        secp256r1_pvss_public_keys_and_proofs: HashMap<
            AuthorityName,
            Secp256r1PvssEncryptionKeyAndProof,
        >,
        ristretto_pvss_public_keys_and_proofs: HashMap<
            AuthorityName,
            RistrettoPvssEncryptionKeyAndProof,
        >,
        vss_hpke_public_keys_and_proofs: HashMap<AuthorityName, VssHpkeEncryptionKeyAndProof>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        assert!(!voting_rights.is_empty());
        assert!(voting_rights.iter().any(|(_, s)| *s != 0));

        let (expanded_keys, index_map) = Self::load_inner(&voting_rights);

        // Verify the Fast Schnorr (VSS) HPKE UC proofs once, here at committee
        // construction — not per presign session. We keep only the *verified*
        // public key values; the raw proofs are dropped. Any party whose key
        // failed to parse or whose proof didn't verify is simply absent from
        // the resulting map (per upstream's per-party filter; a single
        // malformed submission excludes only that party). On a systemic
        // failure (the function itself errs), we store an empty map — no VSS
        // presign can run, but the committee is still otherwise usable.
        let vss_hpke_verified_party_encryption_key_values =
            verify_vss_hpke_keys_at_committee_construction(
                &vss_hpke_public_keys_and_proofs,
                &index_map,
            );

        Committee {
            epoch,
            voting_rights,
            class_groups_public_keys_and_proofs,
            secp256k1_pvss_public_keys_and_proofs,
            secp256r1_pvss_public_keys_and_proofs,
            ristretto_pvss_public_keys_and_proofs,
            vss_hpke_verified_party_encryption_key_values,
            expanded_keys,
            index_map,
            quorum_threshold,
            validity_threshold,
        }
    }

    /// Normalize the given weights to TOTAL_VOTING_POWER and create the committee.
    /// Used for testing only: a production system is using the voting weights
    /// of the Ika System object.
    pub fn new_for_testing_with_normalized_voting_power(
        epoch: EpochId,
        mut voting_weights: Vec<(AuthorityName, StakeUnit)>,
    ) -> Self {
        let num_nodes = voting_weights.len();
        let total_votes: StakeUnit = voting_weights.iter().map(|(_, stake)| stake).sum();

        let normalization_coef = num_nodes as f64 / total_votes as f64;
        let mut total_sum = 0;
        for (idx, (_auth, weight)) in voting_weights.iter_mut().enumerate() {
            if idx < num_nodes - 1 {
                *weight = (*weight as f64 * normalization_coef).floor() as u64; // adjust the weights following the normalization coef
                total_sum += *weight;
            } else {
                // the last element is taking all the rest
                *weight = (num_nodes as u64) - total_sum;
            }
        }

        let quorum_threshold = (2 * num_nodes as u64).div_ceil(3);
        let validity_threshold = (num_nodes as u64).div_ceil(3);

        Self::new(
            epoch,
            voting_weights.into_iter().collect(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            quorum_threshold,
            validity_threshold,
        )
    }

    // We call this if these have not yet been computed
    pub fn load_inner(
        voting_rights: &[(AuthorityName, StakeUnit)],
    ) -> (
        HashMap<AuthorityName, AuthorityPublicKey>,
        HashMap<AuthorityName, usize>,
    ) {
        let expanded_keys: HashMap<AuthorityName, AuthorityPublicKey> = voting_rights
            .iter()
            .map(|(addr, _)| {
                (
                    *addr,
                    (*addr)
                        .try_into()
                        .expect("Validator pubkey is always verified on-chain"),
                )
            })
            .collect();

        let index_map: HashMap<AuthorityName, usize> = voting_rights
            .iter()
            .enumerate()
            .map(|(index, (addr, _))| (*addr, index))
            .collect();
        (expanded_keys, index_map)
    }

    pub fn authority_index(&self, author: &AuthorityName) -> Option<u32> {
        self.index_map.get(author).map(|i| *i as u32)
    }

    pub fn authority_by_index(&self, index: u32) -> Option<&AuthorityName> {
        self.voting_rights.get(index as usize).map(|(name, _)| name)
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    pub fn public_key(&self, authority: &AuthorityName) -> IkaResult<&AuthorityPublicKey> {
        debug_assert_eq!(self.expanded_keys.len(), self.voting_rights.len());
        match self.expanded_keys.get(authority) {
            Some(v) => Ok(v),
            None => Err(IkaError::InvalidCommittee(format!(
                "Authority #{} not found, committee size {}",
                authority,
                self.expanded_keys.len()
            ))),
        }
    }

    /// Return a `HashMap` from **1-based** `PartyID` to `AuthorityName`.
    pub fn party_to_authority_map(&self) -> HashMap<PartyID, AuthorityName> {
        self.index_map
            .iter()
            .map(|(auth, &idx)| {
                // idx is 0-based in index_map, so we add 1 to match the crypto lib.
                ((idx + 1) as PartyID, *auth)
            })
            .collect()
    }

    pub fn class_groups_public_key_and_proof(
        &self,
        authority: &AuthorityName,
    ) -> IkaResult<ClassGroupsEncryptionKeyAndProof> {
        match self.class_groups_public_keys_and_proofs.get(authority) {
            Some(v) => Ok(v.clone()),
            None => Err(IkaError::InvalidCommittee(format!(
                "Authority #{} not found, committee size {}",
                authority,
                self.expanded_keys.len()
            ))),
        }
    }

    /// Samples authorities by weight
    pub fn sample(&self) -> &AuthorityName {
        // unwrap safe unless committee is empty
        Self::choose_multiple_weighted(&self.voting_rights[..], 1, &mut ThreadRng::default())
            .next()
            .unwrap()
    }

    fn choose_multiple_weighted<'a, T: Rng>(
        slice: &'a [(AuthorityName, StakeUnit)],
        count: usize,
        rng: &mut T,
    ) -> impl Iterator<Item = &'a AuthorityName> + use<'a, T> {
        // unwrap is safe because we validate the committee composition in `new` above.
        // See https://docs.rs/rand/latest/rand/distributions/weighted/enum.WeightedError.html
        // for possible errors.
        slice
            .choose_multiple_weighted(rng, count, |(_, weight)| *weight as f64)
            .unwrap()
            .map(|(a, _)| a)
    }

    pub fn choose_multiple_weighted_iter(
        &self,
        count: usize,
    ) -> impl Iterator<Item = &AuthorityName> {
        self.voting_rights
            .choose_multiple_weighted(&mut ThreadRng::default(), count, |(_, weight)| {
                *weight as f64
            })
            .unwrap()
            .map(|(a, _)| a)
    }

    pub fn total_votes(&self) -> StakeUnit {
        self.voting_rights.len() as u64
    }

    pub fn quorum_threshold(&self) -> StakeUnit {
        self.quorum_threshold
    }

    pub fn validity_threshold(&self) -> StakeUnit {
        self.validity_threshold
    }

    pub fn threshold<const STRENGTH: bool>(&self) -> StakeUnit {
        if STRENGTH {
            self.quorum_threshold
        } else {
            self.validity_threshold
        }
    }

    pub fn num_members(&self) -> usize {
        self.voting_rights.len()
    }

    pub fn members(&self) -> impl Iterator<Item = &(AuthorityName, StakeUnit)> {
        self.voting_rights.iter()
    }

    pub fn names(&self) -> impl Iterator<Item = &AuthorityName> {
        self.voting_rights.iter().map(|(name, _)| name)
    }

    pub fn stakes(&self) -> impl Iterator<Item = StakeUnit> + '_ {
        self.voting_rights.iter().map(|(_, stake)| *stake)
    }

    pub fn authority_exists(&self, name: &AuthorityName) -> bool {
        self.index_map.contains_key(name)
    }

    /// Derive a seed deterministically from the transaction digest and shuffle the validators.
    pub fn shuffle_by_stake_from_tx_digest(
        &self,
        tx_digest: &TransactionDigest,
    ) -> Vec<AuthorityName> {
        // the 32 is as requirement of the default StdRng::from_seed choice
        let digest_bytes = tx_digest.into_inner();

        // permute the validators deterministically, based on the digest
        let mut rng = StdRng::from_seed(digest_bytes);
        self.shuffle_by_stake_with_rng(None, None, &mut rng)
    }

    // ===== Testing-only methods =====
    //
    pub fn new_simple_test_committee_of_size(size: usize) -> (Self, Vec<AuthorityKeyPair>) {
        let key_pairs: Vec<_> = random_committee_key_pairs_of_size(size)
            .into_iter()
            .collect();
        let committee = Self::new_for_testing_with_normalized_voting_power(
            0,
            key_pairs
                .iter()
                .map(|key| {
                    (AuthorityName::from(key.public()), /* voting right */ 1)
                })
                .collect(),
        );
        (committee, key_pairs)
    }

    /// Generate a simple committee with 4 validators each with equal voting stake of 1.
    pub fn new_simple_test_committee() -> (Self, Vec<AuthorityKeyPair>) {
        Self::new_simple_test_committee_of_size(4)
    }

    /// Test-only: re-runs the VSS HPKE UC-proof verification on a raw input map
    /// and replaces this committee's verified-key cache with the result. Used
    /// by integration-test helpers that build the committee first and inject
    /// per-validator VSS HPKE keys afterwards. Production code lets
    /// [`Self::new`] do the verification once at construction.
    pub fn set_vss_hpke_verified_for_testing(
        &mut self,
        raw: HashMap<AuthorityName, VssHpkeEncryptionKeyAndProof>,
    ) {
        self.vss_hpke_verified_party_encryption_key_values =
            verify_vss_hpke_keys_at_committee_construction(&raw, &self.index_map);
    }
}

/// Verify per-validator VSS HPKE UC proofs once and return only the verified
/// public key values, keyed by [`PartyID`] (1-based index into voting_rights).
fn verify_vss_hpke_keys_at_committee_construction(
    raw: &HashMap<AuthorityName, VssHpkeEncryptionKeyAndProof>,
    index_map: &HashMap<AuthorityName, usize>,
) -> HashMap<PartyID, curve25519::Value> {
    let by_party_id: HashMap<PartyID, VssHpkeEncryptionKeyAndProof> = raw
        .iter()
        .filter_map(|(name, kp)| {
            let index = index_map.get(name)?;
            let party_id = u16::try_from(index.checked_add(1)?).ok()?;
            Some((party_id, kp.clone()))
        })
        .collect();
    match parse_and_uc_verify_encryption_keys(&by_party_id) {
        Ok(verified) => verified
            .into_iter()
            .map(|(pid, ek)| {
                use group::GroupElement as _;
                (pid, ek.value())
            })
            .collect(),
        Err(_) => HashMap::new(),
    }
}

impl CommitteeTrait<AuthorityName> for Committee {
    fn shuffle_by_stake_with_rng(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        rng: &mut impl Rng,
    ) -> Vec<AuthorityName> {
        let restricted = self
            .voting_rights
            .iter()
            .filter(|(name, _)| {
                if let Some(restrict_to) = restrict_to {
                    restrict_to.contains(name)
                } else {
                    true
                }
            })
            .cloned();

        let (preferred, rest): (Vec<_>, Vec<_>) = if let Some(preferences) = preferences {
            restricted.partition(|(name, _)| preferences.contains(name))
        } else {
            (Vec::new(), restricted.collect())
        };

        Self::choose_multiple_weighted(&preferred, preferred.len(), rng)
            .chain(Self::choose_multiple_weighted(&rest, rest.len(), rng))
            .cloned()
            .collect()
    }

    fn weight(&self, author: &AuthorityName) -> StakeUnit {
        let Some(index) = self.index_map.get(author) else {
            return 0;
        };

        match self.voting_rights.get(*index) {
            None => 0,
            Some((_, s)) => *s,
        }
    }
}

impl PartialEq for Committee {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.voting_rights == other.voting_rights
    }
}

impl Hash for Committee {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.epoch.hash(state);
        self.voting_rights.hash(state);
    }
}

impl Display for Committee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut voting_rights = String::new();
        for (name, vote) in &self.voting_rights {
            write!(voting_rights, "{}: {}, ", name.concise(), vote)?;
        }
        write!(
            f,
            "Committee (epoch={:?}, voting_rights=[{}])",
            self.epoch, voting_rights
        )
    }
}

pub trait CommitteeTrait<K: Ord> {
    fn shuffle_by_stake_with_rng(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<K>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<K>>,
        rng: &mut impl Rng,
    ) -> Vec<K>;

    fn shuffle_by_stake(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<K>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<K>>,
    ) -> Vec<K> {
        self.shuffle_by_stake_with_rng(preferences, restrict_to, &mut ThreadRng::default())
    }

    fn weight(&self, author: &K) -> StakeUnit;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMetadata {
    pub name: String,
    pub network_address: Multiaddr,
    pub consensus_address: Multiaddr,
    pub network_public_key: Option<NetworkPublicKey>,
    pub class_groups_public_key_and_proof: Option<ClassGroupsEncryptionKeyAndProof>,
    /// Per-validator PVSS HPKE encryption key + proof for the secp256k1
    /// plaintext space. Sibling of `class_groups_public_key_and_proof`; new at
    /// the `cryptography-private @ 9d35fa76` bump. See
    /// `Secp256k1PvssEncryptionKeyAndProof` and `ValidatorEncryptionKeysAndProofs`.
    pub secp256k1_pvss_public_key_and_proof: Option<Secp256k1PvssEncryptionKeyAndProof>,
    /// PVSS HPKE encryption key + proof, secp256r1 plaintext space.
    pub secp256r1_pvss_public_key_and_proof: Option<Secp256r1PvssEncryptionKeyAndProof>,
    /// PVSS HPKE encryption key + proof, ristretto plaintext space.
    pub ristretto_pvss_public_key_and_proof: Option<RistrettoPvssEncryptionKeyAndProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeWithNetworkMetadata {
    epoch_id: EpochId,
    validators: BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)>,
}

impl CommitteeWithNetworkMetadata {
    pub fn new(
        epoch_id: EpochId,
        validators: BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)>,
    ) -> Self {
        Self {
            epoch_id,
            validators,
        }
    }
    pub fn epoch(&self) -> EpochId {
        self.epoch_id
    }

    pub fn validators(&self) -> &BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)> {
        &self.validators
    }
}

impl Display for CommitteeWithNetworkMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CommitteeWithNetworkMetadata (epoch={}, validators={:?})",
            self.epoch_id, self.validators
        )
    }
}

pub type ClassGroupsProof = KnowledgeOfDiscreteLogUCProof;
pub type ClassGroupsEncryptionKeyAndProof = [(
    CompactIbqf<{ CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    ClassGroupsProof,
); MAX_PRIMES];

// ─────────────────────────────────────────────────────────────────────────────
// PVSS HPKE encryption keys and proofs
// ─────────────────────────────────────────────────────────────────────────────
//
// Per-curve publicly-verifiable-secret-sharing (PVSS) HPKE encryption keys plus
// UC-secure proofs of knowledge of the corresponding decryption key. Required by
// `cryptography-private @ 9d35fa76`'s decentralized DKG / reconfiguration
// `PublicInput::new` to wire the threshold_encryption_to_sharing sub-protocol;
// generated per validator at startup from the validator's `RootSeed` (mirrors
// the `class_groups_decryption_key` pattern, distinct domain-separation labels
// per curve so the 3 per-curve keys never collide with each other or with the
// existing class-groups CRT decryption key).
//
// All three curves currently use the SAME const-generic limbs
// (`SECP256K1/SECP256R1/RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS == U2048::LIMBS`,
// `*_FUNDAMENTAL_DISCRIMINANT_LIMBS == U1536::LIMBS`); the per-curve type
// aliases nonetheless stay distinct so a future divergence in upstream's curve
// parameter selection doesn't silently cross wires.

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the secp256k1 plaintext space.
pub type Secp256k1PvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the secp256r1 plaintext space.
pub type Secp256r1PvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the ristretto plaintext space.
pub type RistrettoPvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// Fast Schnorr (VSS) HPKE encryption public key (curve25519, serializable
/// `Value` form) plus the UC-secure proof of knowledge of the corresponding
/// decryption key. The proof is verified — and the holder kept only if it passes
/// — via `mpc::hybrid_public_key_encryption::
/// verify_uc_proofs_of_knowledge_of_encryption_secret_keys` when building the VSS
/// presign input; the verified set becomes the presign's
/// `parties_with_uc_verified_public_keys`.
///
/// A single curve25519 key per validator serves all VSS signing curves (the HPKE
/// transport layer is curve-independent), unlike the three class-groups `*_pvss`
/// keys which are per plaintext space.
pub type VssHpkeEncryptionKeyAndProof = (curve25519::Value, VssHpkeKnowledgeOfDecryptionKeyUCProof);

/// Combined per-validator on-chain encryption-keys-and-proofs payload.
///
/// BCS-serialized into the Move-side validator field that historically carried
/// only `ClassGroupsEncryptionKeyAndProof` (`ValidatorInfo.class_groups_public_-
/// key_and_proof` and the equivalent on `NetworkMetadata`). The Move side
/// stores opaque `vector<u8>`; the publication shape — bare class-groups vs
/// this bundle — is gated by the validator binary's `ProtocolConfig` (see the
/// publication call sites in `crates/ika/src/validator_commands.rs`).
///
/// Reading code MUST go through [`decode_validator_encryption_keys`] rather
/// than calling `bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>` directly,
/// so mainnet-v1.1.8-shape payloads (bare class-groups only) decode without
/// silently dropping the validator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorEncryptionKeysAndProofs {
    /// Existing class-groups CRT-decryption-key encryption key + proof of
    /// knowledge of discrete log (per CRT prime). Same shape as the field
    /// historically held standalone; preserved here to keep callers that only
    /// need this piece working.
    pub class_groups: ClassGroupsEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the secp256k1 plaintext space. New at this
    /// bump; required by `decentralized_party::dkg::PublicInput::new` and the
    /// reconfiguration-party constructors for the threshold-encryption-to-
    /// sharing sub-protocol.
    pub secp256k1_pvss: Secp256k1PvssEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the secp256r1 plaintext space.
    pub secp256r1_pvss: Secp256r1PvssEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the ristretto plaintext space.
    pub ristretto_pvss: RistrettoPvssEncryptionKeyAndProof,
    /// Fast Schnorr (VSS) HPKE encryption public key (curve25519) + UC proof of
    /// knowledge of the decryption key. This is the curve25519 HPKE key the VSS
    /// presign's `party_encryption_keys` requires (distinct from the three
    /// class-groups `*_pvss` keys above, which share the class-groups decryption
    /// key over the integers); one key serves all VSS signing curves.
    ///
    /// The proof is verified once at [`Committee`] construction by
    /// `mpc::hybrid_public_key_encryption::parse_and_uc_verify_encryption_keys`;
    /// only validators whose proof verifies are admitted to subsequent VSS
    /// presign / sign sessions.
    pub vss_hpke_public_key_and_proof: VssHpkeEncryptionKeyAndProof,
}

/// Result of shape-tolerant decoding of the Move-side validator encryption-key
/// bytes. The class-groups CRT key is always present (both shapes carry it);
/// the three PVSS halves are present only when the validator published the
/// post-PR-#1707 bundle shape ([`ValidatorEncryptionKeysAndProofs`]).
///
/// Validators that published under the mainnet-v1.1.8 shape (bare
/// `ClassGroupsEncryptionKeyAndProof`) come back here with PVSS halves as
/// `None`; downstream DKG / Reconfiguration dispatch picks the
/// `decentralized_party_backward_compatible` Party (which needs no PVSS keys).
///
/// TEMPORARY: only exists for the mainnet-v1.1.8 → post-PR-#1707 transition window.
/// Once every validator has republished under the new shape and the network has
/// settled at `network_encryption_key_version == 3`, delete this struct and have
/// the decode sites read [`ValidatorEncryptionKeysAndProofs`] directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedValidatorEncryptionKeys {
    pub class_groups: ClassGroupsEncryptionKeyAndProof,
    pub secp256k1_pvss: Option<Secp256k1PvssEncryptionKeyAndProof>,
    pub secp256r1_pvss: Option<Secp256r1PvssEncryptionKeyAndProof>,
    pub ristretto_pvss: Option<RistrettoPvssEncryptionKeyAndProof>,
    /// Present only for validators that published the protocol_version-5 bundle
    /// (Fast Schnorr). `None` for v4 bundles and mainnet-v1.1.8 bare class-groups.
    pub vss_hpke_public_key_and_proof: Option<VssHpkeEncryptionKeyAndProof>,
}

/// Decode the bytes from `MPCDataV1::class_groups_public_key_and_proof()`
/// accepting either publication shape:
///
/// - [`ValidatorEncryptionKeysAndProofs`] — post-PR-#1707 bundle (class-groups
///   CRT key + 3 per-curve PVSS HPKE keys). Validators publish this at
///   `ProtocolConfig::network_encryption_key_version() == 3` (protocol_version
///   `>= 5`).
/// - [`ClassGroupsEncryptionKeyAndProof`] — mainnet-v1.1.8 shape (class-groups
///   CRT key only). Validators publish this at
///   `ProtocolConfig::network_encryption_key_version() == 2` (protocol_version
///   `<= 4`, including mainnet-v1.1.8 itself).
///
/// Returns `None` only when the bytes are neither shape. BCS rejects trailing
/// bytes by default, so a new-shape payload will NOT silently parse as the old
/// shape: the old-shape parse path consumes the leading class-groups array and
/// errors on the trailing PVSS section, then the new-shape arm succeeds.
///
/// TEMPORARY: only exists for the mainnet-v1.1.8 → post-PR-#1707 transition window.
/// Delete this function (and the old-shape fallback) once the network has settled
/// at `network_encryption_key_version == 3` and every validator publishes
/// [`ValidatorEncryptionKeysAndProofs`]; decode sites can then call
/// `bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>(_)` directly.
pub fn decode_validator_encryption_keys(bytes: &[u8]) -> Option<DecodedValidatorEncryptionKeys> {
    if let Ok(bundle) = bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>(bytes) {
        return Some(DecodedValidatorEncryptionKeys {
            class_groups: bundle.class_groups,
            secp256k1_pvss: Some(bundle.secp256k1_pvss),
            secp256r1_pvss: Some(bundle.secp256r1_pvss),
            ristretto_pvss: Some(bundle.ristretto_pvss),
            vss_hpke_public_key_and_proof: Some(bundle.vss_hpke_public_key_and_proof),
        });
    }
    bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(bytes)
        .ok()
        .map(|class_groups| DecodedValidatorEncryptionKeys {
            class_groups,
            secp256k1_pvss: None,
            secp256r1_pvss: None,
            ristretto_pvss: None,
            vss_hpke_public_key_and_proof: None,
        })
}

// Tests for `decode_validator_encryption_keys` live in
// `crates/dwallet-classgroups-types/src/lib.rs`'s `mod tests`, alongside the
// existing `ValidatorMPCSecrets::from_seed` round-trip test
// — placing them here would create a circular `ika-types` ↔
// `dwallet-classgroups-types` dev-dependency.
