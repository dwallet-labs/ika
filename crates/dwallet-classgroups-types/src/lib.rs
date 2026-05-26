// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_DECRYPTION_KEY_WITNESS_LIMBS, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
    construct_setup_parameters_per_crt_prime, generate_keypairs_per_crt_prime,
    generate_knowledge_of_decryption_key_proofs_per_crt_prime,
};
use class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::generate_and_prove_encryption_keypair;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    CompactIbqf, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RistrettoSetupParameters, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, Secp256k1SetupParameters,
    Secp256r1SetupParameters,
};
use crypto_bigint::Uint;
use dwallet_rng::RootSeed;
use group::GroupElement as _;
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
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                setup_parameters_per_crt_prime.each_ref(),
            )
            .unwrap();

        let mut rng = root_seed.class_groups_decryption_key_rng();
        let decryption_key =
            generate_keypairs_per_crt_prime(setup_parameters_per_crt_prime.clone(), &mut rng)
                .unwrap();

        let encryption_key_and_proof = generate_knowledge_of_decryption_key_proofs_per_crt_prime(
            language_public_parameters_per_crt_prime.clone(),
            decryption_key,
            &mut rng,
        )
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
    /// Per-curve setup parameters are derived from the curve's default scalar
    /// `PublicParameters` plus [`DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER`] — pure
    /// per-curve constants (no per-validator/per-network dependency), so
    /// deterministic derivation from `RootSeed` is sound.
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

        let secp256k1_setup =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<group::secp256k1::Scalar>(
                group::secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();
        let mut secp256k1_rng = root_seed.pvss_secp256k1_decryption_key_rng();
        let (secp256k1_enc, secp256k1_proof, secp256k1_dec) =
            generate_and_prove_encryption_keypair::<
                { group::secp256k1::SCALAR_LIMBS },
                { SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U1024::LIMBS },
                { SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U4096::LIMBS },
                { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
                group::secp256k1::GroupElement,
            >(&secp256k1_setup, &mut secp256k1_rng)
            .unwrap();

        let secp256r1_setup =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<group::secp256r1::Scalar>(
                group::secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();
        let mut secp256r1_rng = root_seed.pvss_secp256r1_decryption_key_rng();
        let (secp256r1_enc, secp256r1_proof, secp256r1_dec) =
            generate_and_prove_encryption_keypair::<
                { group::secp256r1::SCALAR_LIMBS },
                { SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U1024::LIMBS },
                { SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U4096::LIMBS },
                { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
                group::secp256r1::GroupElement,
            >(&secp256r1_setup, &mut secp256r1_rng)
            .unwrap();

        let ristretto_setup =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<group::ristretto::Scalar>(
                group::ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();
        let mut ristretto_rng = root_seed.pvss_ristretto_decryption_key_rng();
        let (ristretto_enc, ristretto_proof, ristretto_dec) =
            generate_and_prove_encryption_keypair::<
                { group::ristretto::SCALAR_LIMBS },
                { RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U1024::LIMBS },
                { RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crypto_bigint::U4096::LIMBS },
                { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
                group::ristretto::GroupElement,
            >(&ristretto_setup, &mut ristretto_rng)
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
}
