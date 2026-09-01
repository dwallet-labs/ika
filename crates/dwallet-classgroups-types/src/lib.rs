// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    SecretKeyShareCRTPrimeSetupParameters,
    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
    construct_setup_parameters_per_crt_prime, generate_class_groups_keypair,
    verify_knowledge_of_decryption_key_proofs,
};
use class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::generate_pvss_keypairs;
use class_groups::{
    CompactIbqf, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, EquivalenceClass,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use crypto_bigint::Uint;
use dwallet_rng::RootSeed;
use group::GroupElement as _;
use group::PartyID;
use ika_types::committee::{
    ClassGroupsEncryptionKeyAndProof, ClassGroupsProof, ValidatorEncryptionKeysAndProofs,
};
use mpc::secret_sharing::shamir::known_order::generate_and_uc_prove_encryption_keypair;

pub type ClassGroupsDecryptionKey = [Uint<{ CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS }>; MAX_PRIMES];
type AsyncProtocol = twopc_mpc::secp256k1::class_groups::ECDSAProtocol;
pub type DKGDecentralizedOutput =
    <AsyncProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput;
pub type SingleEncryptionKeyAndProof = (
    CompactIbqf<{ CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    ClassGroupsProof,
);
/// The number of primes used in the class groups key,
/// each prime corresponds to a dynamic object.
pub const NUM_OF_CLASS_GROUPS_KEY_OBJECTS: usize = MAX_PRIMES;

// Per-curve PVSS HPKE secret decryption-key aliases.
//
// These are the raw `Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>` returned as the third
// element of upstream's `generate_and_prove_encryption_keypair`. The `class_groups`
// crate's top-level `Secp256k1DecryptionKey` / `RistrettoDecryptionKey` /
// `Secp256r1DecryptionKey` are `DecryptionKey<...>` wrapper structs for the full
// FHE decryption-key API — a different type than the raw `Uint` PVSS HPKE returns.
// No upstream `*PvssDecryptionKey` alias exists, so these live ika-side.
pub type Secp256k1PvssDecryptionKey = Uint<{ SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;
pub type Secp256r1PvssDecryptionKey = Uint<{ SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;
pub type RistrettoPvssDecryptionKey = Uint<{ RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;

/// SECRET. Validator's own class-groups CRT decryption key. Holds only secret
/// material — the matching public encryption key + UC-secure proof is returned
/// alongside as [`ClassGroupsEncryptionKeyAndProof`] by [`Self::from_seed`].
///
/// Deliberately **NOT** `Serialize` / `Deserialize`: the decryption key must
/// never be written out, persisted, or transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassGroupsSecret {
    /// Class-groups CRT decryption key.
    pub decryption_key: ClassGroupsDecryptionKey,
}

impl ClassGroupsSecret {
    /// Deterministically generate the class-groups CRT decryption key and the
    /// matching encryption-key-and-proof from a root seed. Uses
    /// `class_groups_decryption_key_rng` so the same seed always reproduces
    /// the same pair.
    ///
    /// The seed must be cryptographically secure and kept confidential.
    pub fn from_seed(root_seed: &RootSeed) -> (Self, ClassGroupsEncryptionKeyAndProof) {
        let (decryption_key, encryption_key_and_proof) =
            generate_class_groups_keypair(&mut root_seed.class_groups_decryption_key_rng())
                .unwrap();

        (
            ClassGroupsSecret { decryption_key },
            encryption_key_and_proof,
        )
    }
}

/// SECRET. This validator's own private MPC key material — the class-groups CRT
/// decryption key, the three per-curve PVSS HPKE decryption keys, and the
/// Fast Schnorr (VSS) HPKE curve25519 secret key. Belongs to this validator
/// alone (never another validator's keys).
///
/// Holds only secrets. The matching public encryption keys + UC-secure proofs
/// — which depend on fresh randomness consumed during keypair generation and
/// therefore can't be re-derived from the secrets alone — live in the separate
/// [`ValidatorEncryptionKeysAndProofs`] type and are returned alongside this
/// struct by [`Self::from_seed`]; callers that need to publish the public
/// payload use the second tuple element directly.
///
/// Deliberately **NOT** `Serialize` / `Deserialize`: the private keys must
/// never be written out, persisted, or transmitted.
///
/// Generated deterministically from the validator's [`RootSeed`]; the seed must
/// be cryptographically secure and kept confidential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorMPCSecrets {
    /// Class-groups CRT decryption key. Secret-only — the matching encryption
    /// key + UC-secure proof lives in the returned [`ValidatorEncryptionKeysAndProofs`].
    pub class_groups: ClassGroupsSecret,

    /// Per-curve PVSS HPKE secret decryption keys. Never publish or transmit;
    /// used at sign time when this validator decrypts its share of the
    /// threshold-encryption-to-sharing dealing.
    pub secp256k1_pvss_decryption_key: Secp256k1PvssDecryptionKey,
    pub secp256r1_pvss_decryption_key: Secp256r1PvssDecryptionKey,
    pub ristretto_pvss_decryption_key: RistrettoPvssDecryptionKey,

    /// Fast Schnorr (VSS) HPKE secret key — a single curve25519 scalar
    /// (one keypair serves all VSS signing curves) used as the VSS presign
    /// `PrivateInput` for threshold-encryption-to-sharing.
    pub vss_hpke_secret_key: group::curve25519::Scalar,
}

impl ValidatorMPCSecrets {
    /// Deterministically generates the validator's class-groups CRT material
    /// plus the three per-curve PVSS HPKE keypairs from a single [`RootSeed`].
    ///
    /// Each derivation uses a domain-separated child RNG of the same `RootSeed`
    /// (see [`RootSeed`]'s `class_groups_decryption_key_rng`,
    /// `pvss_secp256k1_decryption_key_rng`, `pvss_secp256r1_decryption_key_rng`,
    /// `pvss_ristretto_decryption_key_rng`), so the four secret materials are
    /// independent of each other and the same root seed always reproduces the
    /// same set of keys.
    ///
    /// The class-groups and per-curve PVSS keygen (including the per-curve setup-
    /// parameter derivation) lives in the `class_groups` crate behind the
    /// `generate_class_groups_keypair` / `generate_pvss_keypairs`
    /// entry points; this only supplies the domain-separated RNGs and assembles the
    /// result into the committee types.
    ///
    /// The seed must be cryptographically secure and kept confidential.
    ///
    /// Returns the secrets alongside the matching public
    /// [`ValidatorEncryptionKeysAndProofs`] payload. The UC proofs use fresh
    /// randomness during keypair generation, so the public payload must be
    /// captured here — it can't be recomputed from the secrets alone.
    pub fn from_seed(root_seed: &RootSeed) -> (Self, ValidatorEncryptionKeysAndProofs) {
        let (class_groups, class_groups_encryption_key_and_proof) =
            ClassGroupsSecret::from_seed(root_seed);

        let (
            (secp256k1_enc, secp256k1_proof, secp256k1_dec),
            (secp256r1_enc, secp256r1_proof, secp256r1_dec),
            (ristretto_enc, ristretto_proof, ristretto_dec),
        ) = generate_pvss_keypairs(
            &mut root_seed.pvss_secp256k1_decryption_key_rng(),
            &mut root_seed.pvss_secp256r1_decryption_key_rng(),
            &mut root_seed.pvss_ristretto_decryption_key_rng(),
        )
        .unwrap();

        // Fast Schnorr (VSS) HPKE keypair: a single curve25519 keypair (not
        // class groups, not per-curve) used as the known-order
        // threshold-encryption-to-sharing transport for the VSS Schnorr
        // presign. One curve25519 keypair serves all VSS signing curves.
        let (vss_hpke_secret, vss_hpke_public, vss_hpke_proof) =
            generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                .unwrap();

        let publics = ValidatorEncryptionKeysAndProofs {
            class_groups: class_groups_encryption_key_and_proof,
            secp256k1_pvss: (secp256k1_enc, secp256k1_proof),
            secp256r1_pvss: (secp256r1_enc, secp256r1_proof),
            ristretto_pvss: (ristretto_enc, ristretto_proof),
            vss_hpke_public_key_and_proof: (vss_hpke_public.value(), vss_hpke_proof),
        };
        let secrets = ValidatorMPCSecrets {
            class_groups,
            secp256k1_pvss_decryption_key: secp256k1_dec,
            secp256r1_pvss_decryption_key: secp256r1_dec,
            ristretto_pvss_decryption_key: ristretto_dec,
            vss_hpke_secret_key: vss_hpke_secret,
        };
        (secrets, publics)
    }

    /// Thin helper: re-derive only the validator's VSS HPKE secret key from
    /// its `RootSeed`, deterministically matching the public key returned by
    /// [`Self::from_seed`]. Provided for the VSS presign hot path where
    /// rebuilding the full secrets struct would needlessly regenerate the
    /// expensive class-groups material; for everything else, hold onto the
    /// `vss_hpke_secret_key` field on a `ValidatorMPCSecrets` from
    /// [`Self::from_seed`].
    pub fn vss_hpke_secret_key_from_seed(root_seed: &RootSeed) -> group::curve25519::Scalar {
        let (secret, _public, _proof) =
            generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                .unwrap();
        secret
    }
}

/// Why a [`ClassGroupsEncryptionKeyAndProof`] failed
/// [`verify_class_groups_encryption_key_and_proof`].
#[derive(Debug, thiserror::Error)]
pub enum ClassGroupsKeyVerificationError {
    /// The class-groups CRT setup / language public parameters could not be
    /// derived. Not a property of the payload — this means the local build's
    /// class-groups parameters are unusable, which would break MPC entirely.
    #[error(
        "failed to derive the class-groups CRT public parameters needed to verify the key: {0}"
    )]
    PublicParameters(String),

    /// The bytes at CRT prime `crt_prime_index` are not a well-formed class-groups
    /// encryption key (they do not instantiate as a group element under that
    /// prime's public parameters).
    #[error("the class-groups encryption key for CRT prime #{crt_prime_index} is malformed")]
    MalformedEncryptionKey { crt_prime_index: usize },

    /// The payload is well-formed but at least one UC knowledge-of-decryption-key
    /// proof does not verify against its encryption key: the key and the proof do
    /// not belong to the same decryption key.
    #[error(
        "the class-groups knowledge-of-decryption-key proof does not verify against the encryption key"
    )]
    InvalidProof,
}

/// Party id used to address the single key-and-proof being checked. The
/// verification is per-key and stateless, so any id works; `1` matches the
/// crypto library's 1-based party numbering.
const PREFLIGHT_PARTY_ID: PartyID = 1;

/// Cryptographically verifies a validator's class-groups CRT encryption key
/// together with its UC knowledge-of-decryption-key proof, per CRT prime.
///
/// # What this protects, and what it does not
///
/// This is a **client-side pre-flight** for an *honest* operator. It catches a
/// corrupt, truncated, hand-edited or seed-mismatched `mpc_data` payload — e.g. a
/// `validator.info` regenerated against one `root-seed.key` and then registered
/// while a different seed is on the node — *before* the candidate-registration
/// transaction is built, instead of letting the operator discover it an epoch
/// later as an unexplained malicious-party conviction.
///
/// It is **NOT an on-chain guarantee**. Nothing stops a byzantine actor from
/// skipping this check and submitting arbitrary bytes: Move cannot run
/// class-groups arithmetic, so `request_add_validator_candidate` stores
/// `mpc_data_bytes` opaquely (`contracts/ika_system/sources/staking/validator_info.move:135`)
/// and verifies only the BLS proof-of-possession (`:117-125`).
///
/// The on-chain-equivalent guarantee is enforced at MPC time, by every honest
/// validator independently, against exactly the same proof: the class-groups DKG
/// and reconfiguration first rounds deal PVSS shares through
/// `class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::
/// Party::deal_and_encrypt_shares_to_valid_encryption_key_holders`, which calls
/// [`verify_knowledge_of_decryption_key_proofs`] (inkrypto `3ed95fe`,
/// `class-groups/src/publicly_verifiable_secret_sharing/chinese_remainder_theorem/deal_shares.rs:106-111`)
/// before dealing. A validator whose proof fails there is added to that round's
/// malicious set, receives no share, and is excluded — while the remaining honest
/// parties, as long as they still form an authorized subset, complete the session.
/// Party construction itself (`class_groups::dkg::PublicInput::new`) does not
/// verify: it only stores the keys and proofs.
///
/// This function deliberately calls that *same* upstream entry point, so the
/// pre-flight verdict and the MPC-time verdict cannot drift apart.
pub fn verify_class_groups_encryption_key_and_proof(
    encryption_key_and_proof: &ClassGroupsEncryptionKeyAndProof,
) -> Result<(), ClassGroupsKeyVerificationError> {
    let setup_parameters_per_crt_prime =
        construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
            .map_err(|e| ClassGroupsKeyVerificationError::PublicParameters(e.to_string()))?;

    let language_public_parameters_per_crt_prime =
        construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
            setup_parameters_per_crt_prime.each_ref(),
        )
        .map_err(|e| ClassGroupsKeyVerificationError::PublicParameters(e.to_string()))?;

    let instantiated =
        instantiate_encryption_keys(&setup_parameters_per_crt_prime, encryption_key_and_proof)?;

    let (malicious_parties, _verified_encryption_keys) = verify_knowledge_of_decryption_key_proofs(
        language_public_parameters_per_crt_prime,
        Vec::new(),
        HashMap::from([(PREFLIGHT_PARTY_ID, instantiated)]),
    )
    .map_err(|e| ClassGroupsKeyVerificationError::PublicParameters(e.to_string()))?;

    if malicious_parties.contains(&PREFLIGHT_PARTY_ID) {
        return Err(ClassGroupsKeyVerificationError::InvalidProof);
    }

    Ok(())
}

/// The per-CRT-prime encryption keys as live group elements, paired with the
/// proofs that are about to be checked against them — the input shape
/// [`verify_knowledge_of_decryption_key_proofs`] expects.
type InstantiatedEncryptionKeysAndProofs = [(
    EquivalenceClass<{ CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    ClassGroupsProof,
); MAX_PRIMES];

/// Instantiates each per-prime encryption key as a group element, exactly as
/// `instantiate_encryption_keys_per_crt_prime` does inside the PVSS party
/// constructor the DKG uses. There, a key that fails to instantiate silently
/// lands its owner in `parties_without_valid_encryption_keys`; here there is a
/// single owner and a human to tell, so name the offending prime instead.
fn instantiate_encryption_keys(
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    encryption_key_and_proof: &ClassGroupsEncryptionKeyAndProof,
) -> Result<InstantiatedEncryptionKeysAndProofs, ClassGroupsKeyVerificationError> {
    let mut instantiated = Vec::with_capacity(MAX_PRIMES);
    for (crt_prime_index, (encryption_key_value, proof)) in
        encryption_key_and_proof.iter().enumerate()
    {
        let encryption_key = EquivalenceClass::new(
            *encryption_key_value,
            setup_parameters_per_crt_prime[crt_prime_index].equivalence_class_public_parameters(),
        )
        .map_err(|_| ClassGroupsKeyVerificationError::MalformedEncryptionKey { crt_prime_index })?;

        instantiated.push((encryption_key, proof.clone()));
    }

    instantiated.try_into().map_err(|_| {
        // Unreachable: `ClassGroupsEncryptionKeyAndProof` is itself `[_; MAX_PRIMES]`.
        ClassGroupsKeyVerificationError::MalformedEncryptionKey {
            crt_prime_index: MAX_PRIMES,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_groups_and_pvss_key_pair_from_seed_is_deterministic() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let (first_secrets, first_publics) = ValidatorMPCSecrets::from_seed(&seed);
        let (second_secrets, second_publics) = ValidatorMPCSecrets::from_seed(&seed);
        assert_eq!(first_secrets, second_secrets);
        assert_eq!(first_publics, second_publics);
    }

    #[test]
    fn validator_encryption_keys_and_proofs_round_trips_through_bcs() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let (_secrets, original) = ValidatorMPCSecrets::from_seed(&seed);
        let bytes = bcs::to_bytes(&original).expect("BCS serialize");
        let decoded: ValidatorEncryptionKeysAndProofs =
            bcs::from_bytes(&bytes).expect("BCS deserialize");
        assert_eq!(original, decoded);
    }

    /// Only the class-groups half of the validator's key material — skips the
    /// three PVSS keypairs and the VSS HPKE keypair `ValidatorMPCSecrets::from_seed`
    /// would also generate, none of which reach `mpc_data_bytes` on chain.
    fn class_groups_key_and_proof(seed_byte: u8) -> ClassGroupsEncryptionKeyAndProof {
        let (_secret, key_and_proof) =
            ClassGroupsSecret::from_seed(&RootSeed::new([seed_byte; 32]));
        key_and_proof
    }

    /// Asserts the payload is exactly what `blob_decodes_to_valid_mpc_data`-style
    /// structural checks accept: it BCS round-trips at the on-chain shape. Every
    /// "invalid" payload below is invalid *cryptographically only* — the whole
    /// point of the issue.
    fn assert_structurally_valid(key_and_proof: &ClassGroupsEncryptionKeyAndProof) {
        let bytes = bcs::to_bytes(key_and_proof).expect("BCS serialize");
        let decoded: ClassGroupsEncryptionKeyAndProof =
            bcs::from_bytes(&bytes).expect("a structurally valid payload must BCS round-trip");
        assert_eq!(*key_and_proof, decoded);
    }

    #[test]
    fn preflight_accepts_a_key_and_proof_generated_from_the_same_seed() {
        let key_and_proof = class_groups_key_and_proof(0xA5);
        assert_structurally_valid(&key_and_proof);
        verify_class_groups_encryption_key_and_proof(&key_and_proof)
            .expect("a seed-generated key and proof must verify");
    }

    /// The seed-mismatch failure the pre-flight exists for: a `validator.info`
    /// carrying the encryption key of one root seed and the proof of another
    /// (an operator who regenerated one file but not the other, or restored a
    /// stale backup). Structurally perfect, cryptographically dead.
    #[test]
    fn preflight_rejects_a_proof_generated_for_a_different_key() {
        let ours = class_groups_key_and_proof(0xA5);
        let theirs = class_groups_key_and_proof(0x5A);

        let mismatched: ClassGroupsEncryptionKeyAndProof =
            std::array::from_fn(|i| (ours[i].0, theirs[i].1.clone()));

        assert_structurally_valid(&mismatched);
        assert!(
            matches!(
                verify_class_groups_encryption_key_and_proof(&mismatched),
                Err(ClassGroupsKeyVerificationError::InvalidProof)
            ),
            "a proof generated for a different key must be rejected"
        );
    }

    /// Tampering *within* one otherwise-good payload: the per-CRT-prime proofs
    /// are transposed, so every proof is checked against a key it was not made
    /// for, under that prime's own language parameters.
    #[test]
    fn preflight_rejects_proofs_transposed_across_crt_primes() {
        const {
            assert!(
                MAX_PRIMES >= 2,
                "the transposition needs at least two primes"
            );
        }

        let good = class_groups_key_and_proof(0xA5);

        let tampered: ClassGroupsEncryptionKeyAndProof = std::array::from_fn(|i| {
            let proof_from_the_next_prime = good[(i + 1) % MAX_PRIMES].1.clone();
            (good[i].0, proof_from_the_next_prime)
        });

        assert_structurally_valid(&tampered);
        assert!(
            matches!(
                verify_class_groups_encryption_key_and_proof(&tampered),
                Err(ClassGroupsKeyVerificationError::InvalidProof)
            ),
            "proofs transposed across CRT primes must be rejected"
        );
    }

    /// The compensating control from issue #488, exercised directly.
    ///
    /// This calls `verify_knowledge_of_decryption_key_proofs` the way the
    /// class-groups DKG and reconfiguration first rounds call it — inkrypto
    /// `3ed95fe`, `class-groups/src/publicly_verifiable_secret_sharing/`
    /// `chinese_remainder_theorem/deal_shares.rs:106-111`, inside
    /// `deal_and_encrypt_shares_to_valid_encryption_key_holders`, before any
    /// PVSS share is dealt — over a four-party committee in which one party
    /// registered a structurally-valid but cryptographically-invalid payload.
    ///
    /// What it establishes: the offending party alone is convicted and dropped
    /// from the set that receives shares; the three honest parties keep their
    /// keys and the session goes on. It is *not* a full DKG session (that needs
    /// a cluster) — it pins the verification and exclusion step that a
    /// byzantine registration actually runs into.
    #[test]
    fn dkg_time_verification_convicts_only_the_offending_party() {
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .expect("CRT setup parameters");
        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                setup_parameters_per_crt_prime.each_ref(),
            )
            .expect("knowledge-of-decryption-key language parameters");

        let honest_a = class_groups_key_and_proof(0x01);
        let honest_b = class_groups_key_and_proof(0x02);
        let honest_c = class_groups_key_and_proof(0x03);
        // Party 4 publishes A's encryption key with B's proof.
        let byzantine: ClassGroupsEncryptionKeyAndProof =
            std::array::from_fn(|i| (honest_a[i].0, honest_b[i].1.clone()));

        const BYZANTINE_PARTY_ID: PartyID = 4;
        let committee: HashMap<PartyID, _> = [
            (1, &honest_a),
            (2, &honest_b),
            (3, &honest_c),
            (BYZANTINE_PARTY_ID, &byzantine),
        ]
        .into_iter()
        .map(|(party_id, key_and_proof)| {
            (
                party_id,
                instantiate_encryption_keys(&setup_parameters_per_crt_prime, key_and_proof)
                    .expect("every payload here is structurally valid"),
            )
        })
        .collect();

        let (malicious_parties, surviving_encryption_keys) =
            verify_knowledge_of_decryption_key_proofs(
                language_public_parameters_per_crt_prime,
                // No party was already excluded for a malformed key.
                Vec::new(),
                committee,
            )
            .expect("verification itself must not error out");

        assert_eq!(
            malicious_parties,
            vec![BYZANTINE_PARTY_ID],
            "exactly the party with the invalid proof must be convicted"
        );
        let mut survivors: Vec<PartyID> = surviving_encryption_keys.into_keys().collect();
        survivors.sort_unstable();
        assert_eq!(
            survivors,
            vec![1, 2, 3],
            "the honest parties must keep their keys and go on dealing"
        );
    }
}
