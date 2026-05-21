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
    ClassGroupsEncryptionKeyAndProof, ClassGroupsProof, RistrettoPvssEncryptionKeyAndProof,
    Secp256k1PvssEncryptionKeyAndProof, Secp256r1PvssEncryptionKeyAndProof,
    ValidatorEncryptionKeysAndProofs, VssHpkeEncryptionKeyAndProof,
};
use mpc::secret_sharing::shamir::known_order::generate_and_uc_prove_encryption_keypair;
use serde::{Deserialize, Serialize};

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

/// Validator's class-groups CRT decryption-key + matching encryption-key + UC-secure
/// proof bundle.
///
/// Wire-format unchanged since pre-bump: callers that serialize or store this
/// struct continue to interoperate with existing keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassGroupsKeyPairAndProof {
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    decryption_key_per_crt_prime: ClassGroupsDecryptionKey,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    encryption_key_and_proof: ClassGroupsEncryptionKeyAndProof,
}

impl ClassGroupsKeyPairAndProof {
    /// Generates a [`ClassGroupsKeyPairAndProof`] from a root seed.
    ///
    /// Deterministically generates class-groups keys using ChaCha20Rng
    /// seeded with the dedicated `class_groups_decryption_key_rng` child of the
    /// provided root seed. The same seed will always produce the same key pair.
    ///
    /// The seed should be cryptographically secure and kept confidential.
    pub fn from_seed(root_seed: &RootSeed) -> Self {
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

        ClassGroupsKeyPairAndProof {
            decryption_key_per_crt_prime: decryption_key,
            encryption_key_and_proof,
        }
    }

    pub fn encryption_key_and_proof(&self) -> ClassGroupsEncryptionKeyAndProof {
        self.encryption_key_and_proof.clone()
    }

    pub fn decryption_key(&self) -> ClassGroupsDecryptionKey {
        self.decryption_key_per_crt_prime
    }
}

/// SECRET. This validator's own private MPC key material — the class-groups CRT
/// decryption key plus the three per-curve PVSS HPKE decryption keys. The matching
/// public encryption keys and UC-secure proofs are cached alongside them only so the
/// published payload can be re-derived cheaply; this struct as a whole is secret and
/// belongs to this validator alone (never another validator's keys).
///
/// Because it holds secrets it is deliberately **NOT** `Serialize`/`Deserialize`: the
/// private keys must never be written out, persisted, or transmitted. To publish the
/// validator's record, extract the public-only payload via
/// [`Self::validator_encryption_keys_and_proofs`] and serialize *that*.
///
/// Composition: the existing [`ClassGroupsKeyPairAndProof`] as a member PLUS the three
/// per-curve PVSS HPKE keypairs (private decryption key + public encryption key +
/// UC-secure proof), introduced at the `cryptography-private @ 9d35fa76` bump for
/// upstream's threshold-encryption-to-sharing sub-protocol.
///
/// Generated deterministically from the validator's [`RootSeed`]; the seed must be
/// cryptographically secure and kept confidential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorMPCSecrets {
    pub class_groups: ClassGroupsKeyPairAndProof,

    secp256k1_pvss_decryption_key: Secp256k1PvssDecryptionKey,
    secp256k1_pvss_encryption_key_and_proof: Secp256k1PvssEncryptionKeyAndProof,

    secp256r1_pvss_decryption_key: Secp256r1PvssDecryptionKey,
    secp256r1_pvss_encryption_key_and_proof: Secp256r1PvssEncryptionKeyAndProof,

    ristretto_pvss_decryption_key: RistrettoPvssDecryptionKey,
    ristretto_pvss_encryption_key_and_proof: RistrettoPvssEncryptionKeyAndProof,

    /// VSS HPKE encryption public key (curve25519) + UC proof. The matching
    /// secret key is re-derived on demand from the same `RootSeed` via
    /// [`Self::vss_hpke_secret_key_from_seed`] rather than carried as a
    /// field: it is needed only at the compute layer, where deriving the single
    /// curve25519 keypair is far cheaper than building this whole struct (which
    /// generates the expensive class-groups material). One curve25519 keypair
    /// serves all VSS signing curves.
    vss_hpke_public_key_and_proof: VssHpkeEncryptionKeyAndProof,
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
    pub fn from_seed(root_seed: &RootSeed) -> Self {
        let class_groups = ClassGroupsKeyPairAndProof::from_seed(root_seed);

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

        // Fast Schnorr (VSS) HPKE keypair: a single curve25519 keypair (not class
        // groups, not per-curve) used as the known-order threshold-encryption-to-
        // sharing transport for the VSS Schnorr presign. The secret is discarded
        // here and re-derived from the same `RootSeed` where it's needed.
        let (_vss_hpke_secret, vss_hpke_public, vss_hpke_proof) =
            generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                .unwrap();

        ValidatorMPCSecrets {
            class_groups,
            secp256k1_pvss_decryption_key: secp256k1_dec,
            secp256k1_pvss_encryption_key_and_proof: (secp256k1_enc, secp256k1_proof),
            secp256r1_pvss_decryption_key: secp256r1_dec,
            secp256r1_pvss_encryption_key_and_proof: (secp256r1_enc, secp256r1_proof),
            ristretto_pvss_decryption_key: ristretto_dec,
            ristretto_pvss_encryption_key_and_proof: (ristretto_enc, ristretto_proof),
            vss_hpke_public_key_and_proof: (vss_hpke_public.value(), vss_hpke_proof),
        }
    }

    /// Re-derives this validator's VSS HPKE *secret* key from its `RootSeed`,
    /// deterministically matching the public key published in
    /// [`Self::vss_hpke_public_key_and_proof`]. Derived standalone (rather
    /// than read off a built struct) because the secret is needed only locally as
    /// the VSS presign `PrivateInput`, and deriving the single curve25519 keypair
    /// is far cheaper than building the full struct's class-groups material.
    pub fn vss_hpke_secret_key_from_seed(root_seed: &RootSeed) -> group::curve25519::Scalar {
        let (secret, _public, _proof) =
            generate_and_uc_prove_encryption_keypair(&mut root_seed.vss_hpke_secret_key_rng())
                .unwrap();
        secret
    }

    pub fn secp256k1_pvss_encryption_key_and_proof(&self) -> Secp256k1PvssEncryptionKeyAndProof {
        self.secp256k1_pvss_encryption_key_and_proof.clone()
    }

    pub fn secp256r1_pvss_encryption_key_and_proof(&self) -> Secp256r1PvssEncryptionKeyAndProof {
        self.secp256r1_pvss_encryption_key_and_proof.clone()
    }

    pub fn ristretto_pvss_encryption_key_and_proof(&self) -> RistrettoPvssEncryptionKeyAndProof {
        self.ristretto_pvss_encryption_key_and_proof.clone()
    }

    /// Validator-private PVSS HPKE secret decryption key, secp256k1 plaintext space.
    /// NEVER publish or transmit; required at sign time when the validator decrypts
    /// its share of the threshold-encryption-to-sharing dealing.
    pub fn secp256k1_pvss_decryption_key(&self) -> Secp256k1PvssDecryptionKey {
        self.secp256k1_pvss_decryption_key
    }

    pub fn secp256r1_pvss_decryption_key(&self) -> Secp256r1PvssDecryptionKey {
        self.secp256r1_pvss_decryption_key
    }

    pub fn ristretto_pvss_decryption_key(&self) -> RistrettoPvssDecryptionKey {
        self.ristretto_pvss_decryption_key
    }

    /// Combined public payload to publish in the validator's on-chain record.
    ///
    /// Bundles the existing class-groups encryption-key + proof plus the three
    /// per-curve PVSS encryption-keys-and-proofs into the
    /// [`ValidatorEncryptionKeysAndProofs`] struct that's BCS-serialized into the
    /// Move-side `class_groups_public_key_and_proof` field. See the doc on
    /// [`ValidatorEncryptionKeysAndProofs`] for the mainnet wire-incompat warning.
    /// Fast Schnorr (VSS) HPKE encryption public key (curve25519) + UC proof.
    pub fn vss_hpke_public_key_and_proof(&self) -> VssHpkeEncryptionKeyAndProof {
        self.vss_hpke_public_key_and_proof.clone()
    }

    pub fn validator_encryption_keys_and_proofs(&self) -> ValidatorEncryptionKeysAndProofs {
        ValidatorEncryptionKeysAndProofs {
            class_groups: self.class_groups.encryption_key_and_proof(),
            secp256k1_pvss: self.secp256k1_pvss_encryption_key_and_proof.clone(),
            secp256r1_pvss: self.secp256r1_pvss_encryption_key_and_proof.clone(),
            ristretto_pvss: self.ristretto_pvss_encryption_key_and_proof.clone(),
            vss_hpke_public_key_and_proof: self.vss_hpke_public_key_and_proof.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_groups_and_pvss_key_pair_from_seed_is_deterministic() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let first = ValidatorMPCSecrets::from_seed(&seed);
        let second = ValidatorMPCSecrets::from_seed(&seed);
        assert_eq!(first, second);
    }

    #[test]
    fn validator_encryption_keys_and_proofs_round_trips_through_bcs() {
        let seed = RootSeed::new([0xA5u8; 32]);
        let original = ValidatorMPCSecrets::from_seed(&seed).validator_encryption_keys_and_proofs();
        let bytes = bcs::to_bytes(&original).expect("BCS serialize");
        let decoded: ValidatorEncryptionKeysAndProofs =
            bcs::from_bytes(&bytes).expect("BCS deserialize");
        assert_eq!(original, decoded);
    }

    /// Tests for `ika_types::committee::decode_validator_encryption_keys` —
    /// colocated here so the test can use `ValidatorMPCSecrets::from_seed`
    /// without creating a circular `ika-types` ↔ `dwallet-classgroups-types`
    /// dev-dependency.
    mod decode_validator_encryption_keys {
        use super::*;
        use ika_types::committee::decode_validator_encryption_keys;

        fn sample_bundle() -> ValidatorEncryptionKeysAndProofs {
            let seed = RootSeed::new([0xA5u8; 32]);
            ValidatorMPCSecrets::from_seed(&seed).validator_encryption_keys_and_proofs()
        }

        #[test]
        fn decodes_new_shape() {
            let bundle = sample_bundle();
            let bytes = bcs::to_bytes(&bundle).expect("encode bundle");
            let decoded = decode_validator_encryption_keys(&bytes).expect("decode new shape");
            assert_eq!(decoded.class_groups, bundle.class_groups);
            assert_eq!(decoded.secp256k1_pvss, Some(bundle.secp256k1_pvss));
            assert_eq!(decoded.secp256r1_pvss, Some(bundle.secp256r1_pvss));
            assert_eq!(decoded.ristretto_pvss, Some(bundle.ristretto_pvss));
        }

        #[test]
        fn decodes_old_shape_with_pvss_none() {
            let bundle = sample_bundle();
            let old_bytes = bcs::to_bytes(&bundle.class_groups).expect("encode old shape");
            let decoded = decode_validator_encryption_keys(&old_bytes).expect("decode old shape");
            assert_eq!(decoded.class_groups, bundle.class_groups);
            assert!(decoded.secp256k1_pvss.is_none());
            assert!(decoded.secp256r1_pvss.is_none());
            assert!(decoded.ristretto_pvss.is_none());
        }

        #[test]
        fn rejects_random_bytes() {
            assert!(decode_validator_encryption_keys(&[]).is_none());
            assert!(decode_validator_encryption_keys(&[0u8; 16]).is_none());
            assert!(decode_validator_encryption_keys(&vec![0xFFu8; 1024]).is_none());
        }

        #[test]
        fn rejects_old_shape_with_trailing_bytes() {
            let bundle = sample_bundle();
            let mut bytes = bcs::to_bytes(&bundle.class_groups).expect("encode old shape");
            bytes.push(0xAA);
            assert!(decode_validator_encryption_keys(&bytes).is_none());
        }
    }
}
