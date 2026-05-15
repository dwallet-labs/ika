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
use ika_types::committee::{
    ClassGroupsEncryptionKeyAndProof, ClassGroupsProof, RistrettoPvssEncryptionKeyAndProof,
    Secp256k1PvssEncryptionKeyAndProof, Secp256r1PvssEncryptionKeyAndProof,
    ValidatorEncryptionKeysAndProofs,
};
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

/// PVSS HPKE secret decryption key, secp256k1 plaintext space.
///
/// Sized by the secp256k1 fundamental discriminant; private to the validator
/// — never sent on the wire. Mirrored by `Secp256r1PvssDecryptionKey` and
/// `RistrettoPvssDecryptionKey` for the other two PVSS curves.
pub type Secp256k1PvssDecryptionKey = Uint<{ SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;
/// PVSS HPKE secret decryption key, secp256r1 plaintext space.
pub type Secp256r1PvssDecryptionKey = Uint<{ SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;
/// PVSS HPKE secret decryption key, ristretto plaintext space.
pub type RistrettoPvssDecryptionKey = Uint<{ RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS }>;

/// Validator's complete MPC key material: the existing class-groups CRT
/// decryption-key + proof bundle PLUS the three per-curve PVSS HPKE keypairs
/// (private decryption key + public encryption key + UC-secure proof) added
/// at the `cryptography-private @ 9d35fa76` bump for upstream's
/// threshold-encryption-to-sharing sub-protocol.
///
/// Generated deterministically from the validator's `RootSeed`. The struct
/// retains its historical name (`ClassGroupsKeyPairAndProof`) for ABI / call-
/// site stability; consumers that just need the class-groups material continue
/// to call `decryption_key()` / `encryption_key_and_proof()`. New consumers
/// that need the public payload published to the committee should use
/// `validator_encryption_keys_and_proofs()` which assembles the combined
/// `ValidatorEncryptionKeysAndProofs` ready for BCS into the Move-side field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassGroupsKeyPairAndProof {
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    decryption_key_per_crt_prime: ClassGroupsDecryptionKey,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    encryption_key_and_proof: ClassGroupsEncryptionKeyAndProof,

    secp256k1_pvss_decryption_key: Secp256k1PvssDecryptionKey,
    secp256k1_pvss_encryption_key_and_proof: Secp256k1PvssEncryptionKeyAndProof,

    secp256r1_pvss_decryption_key: Secp256r1PvssDecryptionKey,
    secp256r1_pvss_encryption_key_and_proof: Secp256r1PvssEncryptionKeyAndProof,

    ristretto_pvss_decryption_key: RistrettoPvssDecryptionKey,
    ristretto_pvss_encryption_key_and_proof: RistrettoPvssEncryptionKeyAndProof,
}

impl ClassGroupsKeyPairAndProof {
    /// Generates a [`ClassGroupsKeyPairAndProof`] from a root seed.
    ///
    /// Deterministically generates the validator's class-groups CRT
    /// decryption-key + proof bundle AND the three per-curve PVSS HPKE
    /// keypairs. Each derivation uses a domain-separated child RNG of the
    /// same `RootSeed` (see `dwallet_rng::RootSeed`'s
    /// `class_groups_decryption_key_rng`, `pvss_secp256k1_decryption_key_rng`,
    /// `pvss_secp256r1_decryption_key_rng`, `pvss_ristretto_decryption_key_rng`),
    /// so the four secret materials are independent of each other and the
    /// same root seed always reproduces the same set of keys.
    ///
    /// The seed must be cryptographically secure and kept confidential.
    pub fn from_seed(root_seed: &RootSeed) -> Self {
        // ── class-groups CRT keypair ──────────────────────────────────────
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

        // ── PVSS HPKE keypairs (one per supported plaintext-space curve) ──
        //
        // Per-curve setup parameters are derived from the curve's default
        // scalar `PublicParameters` plus `DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER`
        // — this matches upstream's example invocation in
        // `class_groups::publicly_verifiable_secret_sharing::small_prime::encryption`'s
        // module-level docs and the reference test in
        // `2pc-mpc::decentralized_party::tests::dkg_presign_signs`. They are
        // PURE per-curve constants (no per-validator/per-network dependency),
        // so deterministic derivation from `RootSeed` is sound.
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

        ClassGroupsKeyPairAndProof {
            decryption_key_per_crt_prime: decryption_key,
            encryption_key_and_proof,
            secp256k1_pvss_decryption_key: secp256k1_dec,
            secp256k1_pvss_encryption_key_and_proof: (secp256k1_enc, secp256k1_proof),
            secp256r1_pvss_decryption_key: secp256r1_dec,
            secp256r1_pvss_encryption_key_and_proof: (secp256r1_enc, secp256r1_proof),
            ristretto_pvss_decryption_key: ristretto_dec,
            ristretto_pvss_encryption_key_and_proof: (ristretto_enc, ristretto_proof),
        }
    }

    pub fn encryption_key_and_proof(&self) -> ClassGroupsEncryptionKeyAndProof {
        self.encryption_key_and_proof.clone()
    }

    pub fn decryption_key(&self) -> ClassGroupsDecryptionKey {
        self.decryption_key_per_crt_prime
    }

    /// Public PVSS encryption-key + UC-secure proof for the secp256k1 plaintext
    /// space, suitable for publishing in the validator's committee record.
    pub fn secp256k1_pvss_encryption_key_and_proof(&self) -> Secp256k1PvssEncryptionKeyAndProof {
        self.secp256k1_pvss_encryption_key_and_proof.clone()
    }

    /// Public PVSS encryption-key + UC-secure proof for the secp256r1 plaintext
    /// space.
    pub fn secp256r1_pvss_encryption_key_and_proof(&self) -> Secp256r1PvssEncryptionKeyAndProof {
        self.secp256r1_pvss_encryption_key_and_proof.clone()
    }

    /// Public PVSS encryption-key + UC-secure proof for the ristretto plaintext
    /// space.
    pub fn ristretto_pvss_encryption_key_and_proof(&self) -> RistrettoPvssEncryptionKeyAndProof {
        self.ristretto_pvss_encryption_key_and_proof.clone()
    }

    /// Validator-private PVSS HPKE secret decryption key, secp256k1 plaintext
    /// space. NEVER publish or transmit; required at sign time when the
    /// validator decrypts its share of the threshold-encryption-to-sharing
    /// dealing.
    pub fn secp256k1_pvss_decryption_key(&self) -> Secp256k1PvssDecryptionKey {
        self.secp256k1_pvss_decryption_key
    }

    /// Validator-private PVSS HPKE secret decryption key, secp256r1 plaintext
    /// space.
    pub fn secp256r1_pvss_decryption_key(&self) -> Secp256r1PvssDecryptionKey {
        self.secp256r1_pvss_decryption_key
    }

    /// Validator-private PVSS HPKE secret decryption key, ristretto plaintext
    /// space.
    pub fn ristretto_pvss_decryption_key(&self) -> RistrettoPvssDecryptionKey {
        self.ristretto_pvss_decryption_key
    }

    /// Combined public payload to publish in the validator's on-chain record.
    ///
    /// Bundles the existing `ClassGroupsEncryptionKeyAndProof` plus the three
    /// per-curve PVSS encryption-keys-and-proofs into the
    /// `ValidatorEncryptionKeysAndProofs` struct that's BCS-serialized into the
    /// Move-side `class_groups_public_key_and_proof` field. See the doc on
    /// `ValidatorEncryptionKeysAndProofs` for the mainnet wire-incompat
    /// warning.
    pub fn validator_encryption_keys_and_proofs(&self) -> ValidatorEncryptionKeysAndProofs {
        ValidatorEncryptionKeysAndProofs {
            class_groups: self.encryption_key_and_proof.clone(),
            secp256k1_pvss: self.secp256k1_pvss_encryption_key_and_proof.clone(),
            secp256r1_pvss: self.secp256r1_pvss_encryption_key_and_proof.clone(),
            ristretto_pvss: self.ristretto_pvss_encryption_key_and_proof.clone(),
        }
    }
}
