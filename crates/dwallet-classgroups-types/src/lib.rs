// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_DECRYPTION_KEY_WITNESS_LIMBS, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, SecretKeyShareCRTPrimeDecryptionKey,
    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
    construct_setup_parameters_per_crt_prime, generate_class_groups_keypair,
    generate_knowledge_of_decryption_key_proofs_per_crt_prime,
};
use class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::{
    generate_and_prove_encryption_keypair_legacy, generate_pvss_keypairs,
};
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    CompactIbqf, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RistrettoSetupParameters, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, Secp256k1SetupParameters,
    Secp256r1SetupParameters,
};
use crypto_bigint::{U1024, U4096, Uint};
use dwallet_rng::RootSeed;
use group::sampling::{LegacyCsRng, legacy_seeded_rng};
use group::{GroupElement as _, ristretto, secp256k1, secp256r1};
use ika_types::committee::{
    ClassGroupsEncryptionKeyAndProof, ClassGroupsProof, ValidatorEncryptionKeysAndProofs,
};
use mpc::secret_sharing::shamir::known_order::generate_and_uc_prove_encryption_keypair;

/// Chooses the sampler used to recover a validator's encryption keys from its seed.
/// Legacy recovery uses the original target-native word width.
// TODO: Remove validator legacy derivation in a later binary after every validator's
// new keys are certified and active. Keep the user legacy seed APIs available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorKeyDerivation {
    Current,
    Legacy,
}

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
        Self::from_seed_with_derivation(root_seed, ValidatorKeyDerivation::Current)
    }

    /// Recover the selected CRT keys and generate valid proofs for them.
    /// Legacy proof bytes need not match proofs generated before the upgrade.
    pub fn from_seed_with_derivation(
        root_seed: &RootSeed,
        derivation: ValidatorKeyDerivation,
    ) -> (Self, ClassGroupsEncryptionKeyAndProof) {
        let derivation = if cfg!(feature = "dwallet-mpc-unsafe-mock") {
            ValidatorKeyDerivation::Current
        } else {
            derivation
        };
        let (decryption_key, encryption_key_and_proof) = match derivation {
            ValidatorKeyDerivation::Current => {
                generate_class_groups_keypair(&mut root_seed.class_groups_decryption_key_rng())
                    .unwrap()
            }
            ValidatorKeyDerivation::Legacy => {
                let setup_parameters = construct_setup_parameters_per_crt_prime(
                    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                )
                .unwrap();
                let language_public_parameters =
                    construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                        setup_parameters.each_ref(),
                    )
                    .unwrap();
                let mut rng = legacy_seeded_rng(root_seed.class_groups_decryption_key_seed());
                let decryption_key = setup_parameters.map(|setup_parameters| {
                    SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters_legacy(
                        setup_parameters,
                        &mut rng,
                    )
                    .unwrap()
                    .1
                    .decryption_key
                });
                let encryption_key_and_proof =
                    generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                        language_public_parameters,
                        decryption_key,
                        &mut LegacyCsRng(&mut rng),
                    )
                    .unwrap();
                (decryption_key, encryption_key_and_proof)
            }
        };

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
        Self::from_seed_with_derivation(root_seed, ValidatorKeyDerivation::Current)
    }

    /// Recover validator keys with the selected derivation and generate valid proofs.
    /// Match their public keys against authenticated committee metadata; regenerated
    /// legacy proofs are valid but need not reproduce the original proof bytes.
    pub fn from_seed_with_derivation(
        root_seed: &RootSeed,
        derivation: ValidatorKeyDerivation,
    ) -> (Self, ValidatorEncryptionKeysAndProofs) {
        let derivation = if cfg!(feature = "dwallet-mpc-unsafe-mock") {
            ValidatorKeyDerivation::Current
        } else {
            derivation
        };
        let (class_groups, class_groups_encryption_key_and_proof) =
            ClassGroupsSecret::from_seed_with_derivation(root_seed, derivation);

        let (
            (secp256k1_enc, secp256k1_proof, secp256k1_dec),
            (secp256r1_enc, secp256r1_proof, secp256r1_dec),
            (ristretto_enc, ristretto_proof, ristretto_dec),
        ) = match derivation {
            ValidatorKeyDerivation::Current => generate_pvss_keypairs(
                &mut root_seed.pvss_secp256k1_decryption_key_rng(),
                &mut root_seed.pvss_secp256r1_decryption_key_rng(),
                &mut root_seed.pvss_ristretto_decryption_key_rng(),
            )
            .unwrap(),
            ValidatorKeyDerivation::Legacy => {
                let secp256k1_setup = Secp256k1SetupParameters::derive_from_plaintext_parameters::<
                    secp256k1::Scalar,
                >(
                    secp256k1::scalar::PublicParameters::default(),
                    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                )
                .unwrap();
                let secp256r1_setup = Secp256r1SetupParameters::derive_from_plaintext_parameters::<
                    secp256r1::Scalar,
                >(
                    secp256r1::scalar::PublicParameters::default(),
                    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                )
                .unwrap();
                let ristretto_setup = RistrettoSetupParameters::derive_from_plaintext_parameters::<
                    ristretto::Scalar,
                >(
                    ristretto::scalar::PublicParameters::default(),
                    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                )
                .unwrap();
                (
                    generate_and_prove_encryption_keypair_legacy::<
                        { secp256k1::SCALAR_LIMBS },
                        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U1024::LIMBS },
                        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U4096::LIMBS },
                        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                        secp256k1::GroupElement,
                    >(
                        &secp256k1_setup,
                        root_seed.pvss_secp256k1_decryption_key_seed(),
                    )
                    .unwrap(),
                    generate_and_prove_encryption_keypair_legacy::<
                        { secp256r1::SCALAR_LIMBS },
                        SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U1024::LIMBS },
                        SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U4096::LIMBS },
                        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                        secp256r1::GroupElement,
                    >(
                        &secp256r1_setup,
                        root_seed.pvss_secp256r1_decryption_key_seed(),
                    )
                    .unwrap(),
                    generate_and_prove_encryption_keypair_legacy::<
                        { ristretto::SCALAR_LIMBS },
                        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U1024::LIMBS },
                        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        { U4096::LIMBS },
                        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                        ristretto::GroupElement,
                    >(
                        &ristretto_setup,
                        root_seed.pvss_ristretto_decryption_key_seed(),
                    )
                    .unwrap(),
                )
            }
        };

        // Fast Schnorr (VSS) HPKE keypair: a single curve25519 keypair (not
        // class groups, not per-curve) used as the known-order
        // threshold-encryption-to-sharing transport for the VSS Schnorr
        // presign. One curve25519 keypair serves all VSS signing curves.
        let (vss_hpke_secret, vss_hpke_public, vss_hpke_proof) = match derivation {
            ValidatorKeyDerivation::Current => {
                generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                    .unwrap()
            }
            ValidatorKeyDerivation::Legacy => {
                let mut rng = legacy_seeded_rng(root_seed.vss_hpke_secret_key_seed());
                generate_and_uc_prove_encryption_keypair(&mut LegacyCsRng(&mut rng)).unwrap()
            }
        };

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
        Self::vss_hpke_secret_key_from_seed_with_derivation(
            root_seed,
            ValidatorKeyDerivation::Current,
        )
    }

    /// Recover the VSS secret using the selected validator derivation.
    pub fn vss_hpke_secret_key_from_seed_with_derivation(
        root_seed: &RootSeed,
        derivation: ValidatorKeyDerivation,
    ) -> group::curve25519::Scalar {
        let (secret, _public, _proof) = match derivation {
            ValidatorKeyDerivation::Current => {
                generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                    .unwrap()
            }
            ValidatorKeyDerivation::Legacy => {
                let mut rng = legacy_seeded_rng(root_seed.vss_hpke_secret_key_seed());
                generate_and_uc_prove_encryption_keypair(&mut LegacyCsRng(&mut rng)).unwrap()
            }
        };
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_pointer_width = "64", not(feature = "dwallet-mpc-unsafe-mock")))]
    use sha2::{Digest, Sha256};

    #[test]
    fn class_groups_and_pvss_key_pair_from_seed_is_deterministic() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let (first_secrets, first_publics) = ValidatorMPCSecrets::from_seed(&seed);
        let (second_secrets, second_publics) = ValidatorMPCSecrets::from_seed(&seed);
        assert_eq!(first_secrets, second_secrets);
        assert_eq!(first_publics, second_publics);
    }

    /// Frozen with real crypto at deployed revision 0d5046dff586258e10fc82541b625fc935893172,
    /// using the same root-seed labels. Proofs are deliberately excluded from key identity.
    #[cfg(all(target_pointer_width = "64", not(feature = "dwallet-mpc-unsafe-mock")))]
    #[test]
    fn legacy_validator_keys_match_deployed_native_fixture() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let (secrets, publics) =
            ValidatorMPCSecrets::from_seed_with_derivation(&seed, ValidatorKeyDerivation::Legacy);
        let public_keys = (
            publics.class_groups.map(|(key, _proof)| key),
            publics.secp256k1_pvss.0,
            publics.secp256r1_pvss.0,
            publics.ristretto_pvss.0,
            publics.vss_hpke_public_key_and_proof.0,
        );
        let fixture_secrets = (
            secrets.class_groups.decryption_key,
            secrets.secp256k1_pvss_decryption_key,
            secrets.secp256r1_pvss_decryption_key,
            secrets.ristretto_pvss_decryption_key,
            secrets.vss_hpke_secret_key,
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(bcs::to_bytes(&public_keys).unwrap())),
            [
                0xb4, 0xae, 0x27, 0x18, 0x31, 0xfb, 0xd7, 0x9d, 0x25, 0x0d, 0x12, 0x1a, 0xc2, 0xbd,
                0x4b, 0xda, 0x2b, 0xd7, 0x84, 0x48, 0x3e, 0x83, 0xa2, 0x86, 0x9b, 0x2b, 0x87, 0xc1,
                0x0e, 0xc1, 0x5f, 0x9e
            ]
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(bcs::to_bytes(&fixture_secrets).unwrap())),
            [
                0xa3, 0x8a, 0x1e, 0xa1, 0x77, 0x14, 0xc7, 0x6c, 0xf6, 0x22, 0xcc, 0xed, 0xb5, 0x32,
                0x15, 0xcd, 0xcd, 0x48, 0x0b, 0xf5, 0xe9, 0xd0, 0xbf, 0x4b, 0x54, 0xa9, 0x8f, 0x47,
                0x9a, 0x1e, 0xe2, 0x07
            ]
        );
        assert_ne!(
            secrets.class_groups,
            ClassGroupsSecret::from_seed_with_derivation(&seed, ValidatorKeyDerivation::Current).0,
            "the fixture must distinguish deployed sampling from current sampling"
        );
        assert_eq!(
            secrets.vss_hpke_secret_key,
            ValidatorMPCSecrets::vss_hpke_secret_key_from_seed_with_derivation(
                &seed,
                ValidatorKeyDerivation::Legacy,
            ),
        );
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
