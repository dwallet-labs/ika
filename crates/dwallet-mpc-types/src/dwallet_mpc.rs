// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::mpc_protocol_configuration::try_into_curve;
use class_groups::CiphertextSpaceValue;
use crypto_bigint::{Encoding, Uint};
use enum_dispatch::enum_dispatch;
use group::HashContext;
use group::secp256k1;
use k256::elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use twopc_mpc::class_groups::{DKGCentralizedPartyOutput, DKGCentralizedPartyVersionedOutput};
use twopc_mpc::class_groups::{DKGDecentralizedPartyOutput, DKGDecentralizedPartyVersionedOutput};
use twopc_mpc::dkg::centralized_party;
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;
use twopc_mpc::{curve25519, ristretto, secp256r1};

/// Alias for an MPC message.
pub type MPCMessage = Vec<u8>;

/// Alias for an MPC public output wrapped with version.
pub type SerializedWrappedMPCPublicOutput = Vec<u8>;

/// The MPC Public Output.
pub type MPCPublicOutput = Vec<u8>;

/// Alias for MPC public input.
pub type MPCPublicInput = Vec<u8>;

/// Alias for MPC private input.
pub type MPCPrivateInput = Option<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum NetworkDecryptionKeyPublicOutputType {
    NetworkDkg,
    Reconfiguration,
}

pub type DKGDecentralizedPartyOutputSecp256k1 = DKGDecentralizedPartyOutput<
    { twopc_mpc::secp256k1::SCALAR_LIMBS },
    { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::secp256k1::GroupElement,
>;

pub type DKGDecentralizedPartyVersionedOutputSecp256k1 = DKGDecentralizedPartyVersionedOutput<
    { twopc_mpc::secp256k1::SCALAR_LIMBS },
    { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::secp256k1::GroupElement,
>;

pub type DKGDecentralizedPartyOutputRistretto = DKGDecentralizedPartyOutput<
    { twopc_mpc::ristretto::SCALAR_LIMBS },
    { twopc_mpc::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::ristretto::GroupElement,
>;

pub type DKGDecentralizedPartyVersionedOutputRistretto = DKGDecentralizedPartyVersionedOutput<
    { twopc_mpc::ristretto::SCALAR_LIMBS },
    { twopc_mpc::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::ristretto::GroupElement,
>;

pub type DKGDecentralizedPartyOutputCurve25519 = DKGDecentralizedPartyOutput<
    { twopc_mpc::curve25519::SCALAR_LIMBS },
    { twopc_mpc::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::curve25519::GroupElement,
>;

pub type DKGDecentralizedPartyVersionedOutputCurve25519 = DKGDecentralizedPartyVersionedOutput<
    { twopc_mpc::curve25519::SCALAR_LIMBS },
    { twopc_mpc::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::curve25519::GroupElement,
>;

pub type DKGDecentralizedPartyOutputSecp256r1 = DKGDecentralizedPartyOutput<
    { twopc_mpc::secp256r1::SCALAR_LIMBS },
    { twopc_mpc::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::secp256r1::GroupElement,
>;

pub type DKGDecentralizedPartyVersionedOutputSecp256r1 = DKGDecentralizedPartyVersionedOutput<
    { twopc_mpc::secp256r1::SCALAR_LIMBS },
    { twopc_mpc::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { twopc_mpc::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    group::secp256r1::GroupElement,
>;

/// The public output of the DKG and/or Reconfiguration protocols, which holds the (encrypted) decryption key shares.
/// Created for each DKG protocol and modified for each Reconfiguration Protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEncryptionKeyPublicData {
    /// The epoch of the last version update.
    pub epoch: u64,
    pub dkg_at_epoch: u64,

    pub state: NetworkDecryptionKeyPublicOutputType,
    /// The public output of the `latest` decryption key update (Reconfiguration).
    pub latest_network_reconfiguration_public_output:
        Option<VersionedDecryptionKeyReconfigurationOutput>,
    /// The public output of the `NetworkDKG` process (the first and only one).
    /// Until the first reconfiguration
    /// (`latest_network_reconfiguration_public_output` is `None`), this is the
    /// latest output.
    pub network_dkg_output: VersionedNetworkDkgOutput,
    pub secp256k1_protocol_public_parameters:
        Arc<twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters>,
    /// The public parameters of the decryption key shares,
    /// updated only after a successful network DKG or Reconfiguration.
    pub secp256k1_decryption_key_share_public_parameters:
        Arc<class_groups::Secp256k1DecryptionKeySharePublicParameters>,
    pub secp256r1_protocol_public_parameters:
        Arc<twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters>,
    pub secp256r1_decryption_key_share_public_parameters:
        Arc<class_groups::Secp256r1DecryptionKeySharePublicParameters>,
    pub ristretto_protocol_public_parameters:
        Arc<twopc_mpc::ristretto::class_groups::ProtocolPublicParameters>,
    pub ristretto_decryption_key_share_public_parameters:
        Arc<class_groups::RistrettoDecryptionKeySharePublicParameters>,
    pub curve25519_protocol_public_parameters:
        Arc<twopc_mpc::curve25519::class_groups::ProtocolPublicParameters>,
    pub curve25519_decryption_key_share_public_parameters:
        Arc<class_groups::Curve25519DecryptionKeySharePublicParameters>,

    /// Per-curve DKG outputs for network-owned-address signing.
    ///
    /// Each field holds the centralized party DKG output created using a deterministic
    /// zero-returning RNG (`ZeroRng`) to emulate the centralized party. This enables
    /// the network to perform network-owned-address signing operations
    /// without requiring an actual user.
    ///
    /// # Security Model
    ///
    /// The "user" (centralized party) key share is effectively zero/deterministic, meaning
    /// there is no user secret to protect. Security for network-owned-address signing comes entirely
    /// from the network's threshold signature scheme, not from randomness.
    ///
    /// Each output is BCS-serialized `NetworkOwnedAddressSignDKGOutput`.
    /// DKG is per-curve (4 curves), not per-algorithm (5 algorithms).
    /// Secp256k1 is shared by ECDSASecp256k1 and Taproot.
    pub secp256k1_network_owned_address_dkg_output: Vec<u8>,
    pub secp256r1_network_owned_address_dkg_output: Vec<u8>,
    pub curve25519_network_owned_address_dkg_output: Vec<u8>,
    pub ristretto_network_owned_address_dkg_output: Vec<u8>,

    /// Per-curve extracted public keys for network-owned-address signing.
    /// These are the actual group element bytes extracted from the centralized DKG output.
    pub secp256k1_network_owned_address_public_key: Vec<u8>,
    pub secp256r1_network_owned_address_public_key: Vec<u8>,
    pub curve25519_network_owned_address_public_key: Vec<u8>,
    pub ristretto_network_owned_address_public_key: Vec<u8>,
}

/// Content-derived identity of a network encryption key: the curve25519
/// network-owned-address ed25519 public key, used as the key's identity
/// in the cross-epoch handoff (replacing the Sui `ObjectID`).
///
/// It is a deterministic function of the network DKG output (the NOA DKG
/// is seeded on the class-group encryption key), so every validator
/// derives the same value; and it is invariant across reconfiguration
/// and the v2->v3 DKG-output reconstruction because that encryption key
/// is invariant. Kept Sui-free (no `ObjectID`): `dwallet-mpc-types` does
/// not depend on `sui-types`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetworkKeyId(pub [u8; 32]);

impl NetworkKeyId {
    pub const LENGTH: usize = 32;

    /// Builds a `NetworkKeyId` from raw curve25519 NOA public-key bytes,
    /// which must be exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DwalletNetworkMPCError> {
        let bytes: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| DwalletNetworkMPCError::InvalidNetworkKeyIdLength(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl NetworkEncryptionKeyPublicData {
    /// This key's content-derived [`NetworkKeyId`] — its curve25519
    /// network-owned-address ed25519 public key. curve25519 is always
    /// computed during instantiation regardless of `supported_curves`,
    /// so this is available for every instantiated key; a non-32-byte
    /// value is a hard error rather than a silent fallback.
    pub fn network_key_id(&self) -> Result<NetworkKeyId, DwalletNetworkMPCError> {
        NetworkKeyId::from_bytes(&self.curve25519_network_owned_address_public_key)
    }
}

#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    Copy,
    Ord,
    PartialOrd,
    schemars::JsonSchema,
)]
// useful to tell which protocol public parameters to use
pub enum DWalletCurve {
    #[strum(to_string = "Secp256k1")]
    Secp256k1,
    #[strum(to_string = "Secp256r1")]
    Secp256r1,
    #[strum(to_string = "Curve25519")]
    Curve25519,
    #[strum(to_string = "Ristretto")]
    Ristretto,
}

#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    Copy,
    Ord,
    PartialOrd,
    schemars::JsonSchema,
)]
pub enum DWalletSignatureAlgorithm {
    #[strum(to_string = "ECDSASecp256k1")]
    ECDSASecp256k1,
    #[strum(to_string = "ECDSASecp256r1")]
    ECDSASecp256r1,
    #[strum(to_string = "Taproot")]
    Taproot,
    #[strum(to_string = "EdDSA")]
    EdDSA,
    #[strum(to_string = "Schnorrkel")]
    Schnorrkel,
    /// Fast Schnorr (VSS) variant of Taproot on secp256k1. DKG-created keys only.
    #[strum(to_string = "TaprootVSS")]
    TaprootVSS,
    /// Fast Schnorr (VSS) variant of EdDSA on curve25519. DKG-created keys only.
    #[strum(to_string = "EdDSAVSS")]
    EdDSAVSS,
    /// Fast Schnorr (VSS) variant of Schnorrkel on ristretto. DKG-created keys only.
    #[strum(to_string = "SchnorrkelVSS")]
    SchnorrkelVSS,
}

impl DWalletSignatureAlgorithm {
    /// True for the Fast Schnorr (VSS) signature algorithms. These support
    /// DKG-created keys only (never imported), and do not support the combined
    /// DKG-and-sign fast path. They are not externally requestable — the
    /// on-chain supported-algorithm map omits them — but the internal presign
    /// pool fills them so NOA VSS sign has presigns to consume.
    pub fn is_vss(&self) -> bool {
        matches!(
            self,
            DWalletSignatureAlgorithm::TaprootVSS
                | DWalletSignatureAlgorithm::EdDSAVSS
                | DWalletSignatureAlgorithm::SchnorrkelVSS
        )
    }

    /// Returns the [`HashContext`] that pairs with this algorithm under cryptography-private
    /// PR 547's domain-separation matrix.
    ///
    /// TODO(domain-separation): Schnorrkel currently hard-codes `b"substrate"` as the
    /// signing-context bytes. Once the per-chain plumbing lands (PR 547 Part 2 / ika-private
    /// wiring), the context should be sourced from `SignRequestEvent` so each chain can
    /// supply its own. The byte literal here is byte-identical to what the crypto crate
    /// previously hard-coded inside the Schnorrkel sign path and matches the already-deployed
    /// schnorrkel domain separator — do not change without a coordinated upgrade.
    ///
    /// The VSS variants only change how the signature is computed, not its domain
    /// separation, so each pairs with the same context as its AHE sibling on the same curve.
    pub fn hash_context(&self) -> HashContext {
        match self {
            DWalletSignatureAlgorithm::Schnorrkel | DWalletSignatureAlgorithm::SchnorrkelVSS => {
                HashContext::Schnorrkel {
                    signing_context: b"substrate".to_vec(),
                }
            }
            DWalletSignatureAlgorithm::ECDSASecp256k1
            | DWalletSignatureAlgorithm::ECDSASecp256r1
            | DWalletSignatureAlgorithm::Taproot
            | DWalletSignatureAlgorithm::EdDSA
            | DWalletSignatureAlgorithm::TaprootVSS
            | DWalletSignatureAlgorithm::EdDSAVSS => HashContext::None,
        }
    }
}

#[derive(
    strum_macros::Display,
    strum_macros::EnumString,
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    Copy,
    Ord,
    PartialOrd,
    schemars::JsonSchema,
)]
pub enum DWalletHashScheme {
    #[strum(to_string = "Keccak256")]
    Keccak256,
    #[strum(to_string = "SHA256")]
    SHA256,
    #[strum(to_string = "DoubleSHA256")]
    DoubleSHA256,
    #[strum(to_string = "SHA512")]
    SHA512,
    #[strum(to_string = "Merlin")]
    Merlin,
    // Appended at the end so existing variant discriminants (0..=4) — which are
    // what bcs/bincode persists for this Serialize-derived enum — stay stable.
    // No current ika protocol maps to Blake2b256 in `try_into_hash_scheme`; it
    // exists here only so the bidirectional From conversions to `group::HashScheme`
    // remain total after cryptography-private PR 547.
    #[strum(to_string = "Blake2b256")]
    Blake2b256,
}

impl From<DWalletHashScheme> for group::HashScheme {
    fn from(scheme: DWalletHashScheme) -> Self {
        match scheme {
            DWalletHashScheme::Keccak256 => group::HashScheme::Keccak256,
            DWalletHashScheme::SHA256 => group::HashScheme::SHA256,
            DWalletHashScheme::DoubleSHA256 => group::HashScheme::DoubleSHA256,
            DWalletHashScheme::SHA512 => group::HashScheme::SHA512,
            DWalletHashScheme::Merlin => group::HashScheme::Merlin,
            DWalletHashScheme::Blake2b256 => group::HashScheme::Blake2b256,
        }
    }
}

impl From<group::HashScheme> for DWalletHashScheme {
    fn from(scheme: group::HashScheme) -> Self {
        match scheme {
            group::HashScheme::Keccak256 => DWalletHashScheme::Keccak256,
            group::HashScheme::SHA256 => DWalletHashScheme::SHA256,
            group::HashScheme::DoubleSHA256 => DWalletHashScheme::DoubleSHA256,
            group::HashScheme::SHA512 => DWalletHashScheme::SHA512,
            group::HashScheme::Merlin => DWalletHashScheme::Merlin,
            group::HashScheme::Blake2b256 => DWalletHashScheme::Blake2b256,
        }
    }
}

impl DWalletCurve {
    /// Returns the u32 representation of this curve.
    /// This is the inverse of [`try_into_curve`].
    pub fn as_u32(&self) -> u32 {
        match self {
            DWalletCurve::Secp256k1 => 0,
            DWalletCurve::Secp256r1 => 1,
            DWalletCurve::Curve25519 => 2,
            DWalletCurve::Ristretto => 3,
        }
    }
}

// We can't import ika-types here since we import this module in there.
// Therefore, we use `thiserror` `#from` to convert this error.
#[derive(Debug, Error, Clone)]
pub enum DwalletNetworkMPCError {
    #[error("invalid dwallet mpc curve value: {0}")]
    InvalidDWalletMPCCurve(u32),

    #[error("invalid dwallet mpc signature algorithm (curve: {0}) value: {1}")]
    InvalidDWalletMPCSignatureAlgorithm(u32, u32),

    #[error("invalid dwallet mpc hash scheme (curve: {0}, signature algorithm: {1}) value: {2}")]
    InvalidDWalletMPCHashScheme(u32, u32, u32),

    #[error("missing protocol public parameters for curve: {0}")]
    MissingProtocolPublicParametersForCurve(DWalletCurve),

    #[error("network key id must be 32 bytes, got {0}")]
    InvalidNetworkKeyIdLength(usize),
}

/// Opaque BCS bytes of a validator's published MPC public-key payload.
///
/// Shape depends on the propagation path:
/// - Chain reads (Move `MPCDataV1::mpc_data_bytes`) — bare
///   `ClassGroupsEncryptionKeyAndProof` (mainnet-v1.1.8).
/// - Off-chain pipeline (`derive_mpc_data_blob` → consensus + P2P) — the full
///   5-field `ValidatorEncryptionKeysAndProofs` (class-groups + per-curve PVSS
///   HPKE + Fast Schnorr VSS HPKE).
///
/// Each consumer decodes directly to its expected shape with
/// `bcs::from_bytes::<T>` — no try-then-fallback.
pub type MpcDataBytes = Vec<u8>;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedEncryptionKeyValue {
    V1(Vec<u8>),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGFirstRoundPublicOutput {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGPublicOutput {
    V1(MPCPublicOutput),
    V2 {
        public_key_bytes: Vec<u8>,
        dkg_output: MPCPublicOutput,
    },
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedPresignOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
    /// Fast Schnorr (VSS) presign. Distinct shape from V2 — the inner bytes
    /// decode to a curve-specific `schnorr::vss::Presign`, not the AHE
    /// presign decoded by V2 consumers.
    V3(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedSignOutput {
    V1(MPCPublicOutput),
}

/// Wire-tagged network-DKG public output.
///
/// - `V1` — the raw `class_groups::dkg::PublicOutput` (no decentralized-party
///   wrapper), written by a pre-1.1.8 binary. No longer PRODUCED, but the
///   deployed mainnet/testnet anchors are still V1-tagged on chain (the anchor
///   is written once at DKG and never rewritten — reconfiguration writes a
///   separate field), so this variant is still READ on every reconfiguration.
///   The variant order is also load-bearing for BCS: it keeps the `V2`/`V3`
///   variant indices stable for already-stored outputs.
/// - `V2` — bytes with the shape of
///   `twopc_mpc::decentralized_party::dkg::PublicOutputCore` (the historical
///   backward-compatible DKG party's output). No longer produced; where a
///   consumer needs only the core (e.g. the reconfiguration public-input
///   generator), the bytes still decode as `PublicOutputCore`; everywhere
///   else decode is an error.
/// - `V3` — the pre-aggregation full shape: the `PublicOutputCore` prefix
///   plus the trailing `threshold_encryption_to_sharing_output` field with
///   every dealer's full PVSS dealing. Its inkrypto type
///   (`NonAggregatedPublicOutput`) was REMOVED — V3 bytes can no longer be
///   decoded, and every decode arm errors. The variant remains only for BCS
///   variant-index stability. Persisted V3 anchors must have migrated to V4
///   (via the anchor migration, on a binary that still carried the type)
///   before this binary runs.
/// - `V4` — bytes from
///   `twopc_mpc::decentralized_party::dkg::PublicOutput`: the same
///   `PublicOutputCore` prefix, with the trailing sharing output in the
///   aggregated shape (one summed randomizer-share ciphertext per receiver
///   instead of every dealer's full PVSS dealing — O(n) instead of O(n²)).
///   The protocol aggregates at output formation, so the DKG Party's output
///   IS this shape and `advance_network_dkg_v2` tags it V4 as-is. A V4-tagged
///   anchor also arises from the anchor migration once the reconfiguration
///   output is V4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum VersionedNetworkDkgOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
    V3(MPCPublicOutput),
    V4(MPCPublicOutput),
}

impl VersionedNetworkDkgOutput {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V1(bytes) | Self::V2(bytes) | Self::V3(bytes) | Self::V4(bytes) => bytes,
        }
    }

    /// The wire version tag (1, 2, 3, or 4).
    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
            Self::V3(_) => 3,
            Self::V4(_) => 4,
        }
    }
}

/// Wire-tagged decentralized-reconfiguration public output.
///
/// - `V1` — previously-deployed shape; never produced anymore. Retained for
///   BCS variant-index stability of `V2`/`V3`.
/// - `V2` — bytes with the shape of
///   `twopc_mpc::decentralized_party::reconfiguration::PublicOutputCore` (the
///   historical backward-compatible reconfiguration party's output). No
///   longer produced; where a consumer needs only the core (e.g. as the prior
///   output for the main reconfiguration constructors), the bytes still
///   decode as `PublicOutputCore`; everywhere else decode is an error.
/// - `V3` — the pre-aggregation full shape: the `PublicOutputCore` prefix
///   plus the trailing `threshold_encryption_to_sharing_output` field
///   (every dealer's full PVSS dealing). Its inkrypto type
///   (`NonAggregatedPublicOutput`) was REMOVED — V3 bytes can no longer be
///   decoded, and every decode arm errors. The variant remains only for BCS
///   variant-index stability. A key whose LATEST reconfiguration output is
///   V3-tagged must reconfigure to V4 (on a binary that still carried the
///   type) before this binary runs.
/// - `V4` — bytes from
///   `twopc_mpc::decentralized_party::reconfiguration::PublicOutput`:
///   the same `PublicOutputCore` prefix with the trailing sharing output in
///   the aggregated shape (one summed randomizer-share ciphertext per
///   receiver). The ONLY format produced: the protocol aggregates at output
///   formation, so the reconfiguration Party's output IS this shape and the
///   finalize path tags it V4 as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum VersionedDecryptionKeyReconfigurationOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
    V3(MPCPublicOutput),
    V4(MPCPublicOutput),
}

impl VersionedDecryptionKeyReconfigurationOutput {
    /// The wire version tag (1, 2, 3, or 4).
    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
            Self::V3(_) => 3,
            Self::V4(_) => 4,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedPublicKeyShareAndProof {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedCentralizedDKGPublicOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletUserSecretShare {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedUserSignedMessage {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedCentralizedPartyImportedDWalletPublicOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedImportedSecretShare {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedImportedDwalletOutgoingMessage {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedEncryptedUserShare {
    V1(MPCPublicOutput),
}

#[enum_dispatch(MPCDataTrait)]
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub enum VersionedMPCData {
    V1(MPCDataV1),
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct MPCDataV1 {
    pub mpc_data_bytes: MpcDataBytes,
}

#[enum_dispatch]
pub trait MPCDataTrait {
    fn mpc_data_bytes(&self) -> MpcDataBytes;
}

impl MPCDataTrait for MPCDataV1 {
    fn mpc_data_bytes(&self) -> MpcDataBytes {
        self.mpc_data_bytes.clone()
    }
}

impl NetworkEncryptionKeyPublicData {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput {
        &self.network_dkg_output
    }

    pub fn state(&self) -> &NetworkDecryptionKeyPublicOutputType {
        &self.state
    }

    pub fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        self.latest_network_reconfiguration_public_output.clone()
    }

    pub fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> Arc<class_groups::Secp256k1DecryptionKeySharePublicParameters> {
        self.secp256k1_decryption_key_share_public_parameters
            .clone()
    }

    pub fn secp256k1_protocol_public_parameters(&self) -> Arc<ProtocolPublicParameters> {
        self.secp256k1_protocol_public_parameters.clone()
    }

    pub fn secp256r1_protocol_public_parameters(
        &self,
    ) -> Arc<twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters> {
        self.secp256r1_protocol_public_parameters.clone()
    }

    pub fn ristretto_protocol_public_parameters(
        &self,
    ) -> Arc<twopc_mpc::ristretto::class_groups::ProtocolPublicParameters> {
        self.ristretto_protocol_public_parameters.clone()
    }

    pub fn curve25519_protocol_public_parameters(
        &self,
    ) -> Arc<twopc_mpc::curve25519::class_groups::ProtocolPublicParameters> {
        self.curve25519_protocol_public_parameters.clone()
    }

    pub fn secp256r1_decryption_key_share_public_parameters(
        &self,
    ) -> Arc<class_groups::Secp256r1DecryptionKeySharePublicParameters> {
        self.secp256r1_decryption_key_share_public_parameters
            .clone()
    }

    pub fn ristretto_decryption_key_share_public_parameters(
        &self,
    ) -> Arc<class_groups::RistrettoDecryptionKeySharePublicParameters> {
        self.ristretto_decryption_key_share_public_parameters
            .clone()
    }

    pub fn curve25519_decryption_key_share_public_parameters(
        &self,
    ) -> Arc<class_groups::Curve25519DecryptionKeySharePublicParameters> {
        self.curve25519_decryption_key_share_public_parameters
            .clone()
    }

    /// Returns the network-owned-address DKG output for the given curve.
    pub fn network_owned_address_dkg_output(&self, curve: DWalletCurve) -> &[u8] {
        match curve {
            DWalletCurve::Secp256k1 => &self.secp256k1_network_owned_address_dkg_output,
            DWalletCurve::Secp256r1 => &self.secp256r1_network_owned_address_dkg_output,
            DWalletCurve::Curve25519 => &self.curve25519_network_owned_address_dkg_output,
            DWalletCurve::Ristretto => &self.ristretto_network_owned_address_dkg_output,
        }
    }

    /// Returns the network-owned-address public key for the given curve.
    pub fn network_owned_address_public_key(&self, curve: DWalletCurve) -> &[u8] {
        match curve {
            DWalletCurve::Secp256k1 => &self.secp256k1_network_owned_address_public_key,
            DWalletCurve::Secp256r1 => &self.secp256r1_network_owned_address_public_key,
            DWalletCurve::Curve25519 => &self.curve25519_network_owned_address_public_key,
            DWalletCurve::Ristretto => &self.ristretto_network_owned_address_public_key,
        }
    }

    /// Returns the serialized protocol public parameters for the given curve.
    ///
    /// This is useful for network-owned-address signing operations where the protocol public
    /// parameters need to be passed to emulation functions.
    pub fn serialized_protocol_public_parameters_for_curve(
        &self,
        curve: DWalletCurve,
    ) -> Result<Vec<u8>, bcs::Error> {
        match curve {
            DWalletCurve::Secp256k1 => bcs::to_bytes(&*self.secp256k1_protocol_public_parameters),
            DWalletCurve::Secp256r1 => bcs::to_bytes(&*self.secp256r1_protocol_public_parameters),
            DWalletCurve::Curve25519 => bcs::to_bytes(&*self.curve25519_protocol_public_parameters),
            DWalletCurve::Ristretto => bcs::to_bytes(&*self.ristretto_protocol_public_parameters),
        }
    }
}

pub type ReconfigurationParty = twopc_mpc::decentralized_party::reconfiguration::Party;

pub fn public_key_from_dwallet_output_by_curve(
    curve: DWalletCurve,
    dwallet_output: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let versioned_dkg_public_output: VersionedDwalletDKGPublicOutput =
        bcs::from_bytes(dwallet_output)?;

    match versioned_dkg_public_output {
        VersionedDwalletDKGPublicOutput::V1(dkg_output) => {
            let output: DKGDecentralizedPartyOutputSecp256k1 = bcs::from_bytes(&dkg_output)?;

            let public_key: k256::AffinePoint = output.public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        VersionedDwalletDKGPublicOutput::V2 { dkg_output, .. } => {
            public_key_from_decentralized_dkg_output_by_curve_v2(curve, &dkg_output)
        }
    }
}

pub fn public_key_from_centralized_dkg_output_by_curve(
    curve: u32,
    centralized_dkg_output: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match try_into_curve(curve)? {
        DWalletCurve::Secp256k1 => {
            let public_key = public_key_from_centralized_dkg_output_inner::<
                { secp256k1::SCALAR_LIMBS },
                group::secp256k1::GroupElement,
            >(centralized_dkg_output)?;

            let public_key: k256::AffinePoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Ristretto => {
            let public_key = public_key_from_centralized_dkg_output_inner::<
                { ristretto::SCALAR_LIMBS },
                group::ristretto::GroupElement,
            >(centralized_dkg_output)?;

            let public_key: curve25519_dalek::RistrettoPoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Curve25519 => {
            let public_key = public_key_from_centralized_dkg_output_inner::<
                { curve25519::SCALAR_LIMBS },
                group::curve25519::GroupElement,
            >(centralized_dkg_output)?;

            let public_key: curve25519_dalek::EdwardsPoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Secp256r1 => {
            let public_key = public_key_from_centralized_dkg_output_inner::<
                { secp256r1::SCALAR_LIMBS },
                group::secp256r1::GroupElement,
            >(centralized_dkg_output)?;

            let public_key: p256::AffinePoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
    }
}

pub fn public_key_from_decentralized_dkg_output_by_curve_v2(
    curve: DWalletCurve,
    decentralized_dkg_output: &[u8],
) -> anyhow::Result<Vec<u8>> {
    match curve {
        DWalletCurve::Secp256k1 => {
            let public_key = public_key_from_decentralized_dkg_output_inner_v2::<
                { secp256k1::SCALAR_LIMBS },
                { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                group::secp256k1::GroupElement,
            >(decentralized_dkg_output)?;

            let public_key: k256::AffinePoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Ristretto => {
            let public_key = public_key_from_decentralized_dkg_output_inner_v2::<
                { ristretto::SCALAR_LIMBS },
                { twopc_mpc::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                group::ristretto::GroupElement,
            >(decentralized_dkg_output)?;

            let public_key: curve25519_dalek::RistrettoPoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Curve25519 => {
            let public_key = public_key_from_decentralized_dkg_output_inner_v2::<
                { curve25519::SCALAR_LIMBS },
                { twopc_mpc::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                group::curve25519::GroupElement,
            >(decentralized_dkg_output)?;

            let public_key: curve25519_dalek::EdwardsPoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
        DWalletCurve::Secp256r1 => {
            let public_key = public_key_from_decentralized_dkg_output_inner_v2::<
                { secp256r1::SCALAR_LIMBS },
                { twopc_mpc::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                group::secp256r1::GroupElement,
            >(decentralized_dkg_output)?;

            let public_key: p256::AffinePoint = public_key.into();

            Ok(public_key.to_bytes().to_vec())
        }
    }
}

fn public_key_from_centralized_dkg_output_inner<
    const SCALAR_LIMBS: usize,
    GroupElement: group::GroupElement,
>(
    centralized_dkg_output: &[u8],
) -> anyhow::Result<GroupElement::Value>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    let versioned_centralized_dkg_output: VersionedCentralizedDKGPublicOutput =
        bcs::from_bytes(centralized_dkg_output)?;

    let public_key = match versioned_centralized_dkg_output {
        VersionedCentralizedDKGPublicOutput::V1(output) => {
            let dkg_output: DKGCentralizedPartyOutput<SCALAR_LIMBS, GroupElement> =
                bcs::from_bytes(output.as_slice())?;
            dkg_output.public_key
        }
        VersionedCentralizedDKGPublicOutput::V2(output) => {
            let dkg_output: DKGCentralizedPartyVersionedOutput<SCALAR_LIMBS, GroupElement> =
                bcs::from_bytes(output.as_slice())?;
            match dkg_output {
                centralized_party::VersionedOutput::TargetedPublicDKGOutput(o) => o.public_key,
                centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                    output: o, ..
                } => o.public_key,
            }
        }
    };

    Ok(public_key)
}

fn public_key_from_decentralized_dkg_output_inner_v2<
    const SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::GroupElement,
>(
    decentralized_dkg_output: &[u8],
) -> anyhow::Result<GroupElement::Value>
where
    Uint<SCALAR_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    let dkg_output: twopc_mpc::dkg::decentralized_party::VersionedOutput<
        SCALAR_LIMBS,
        GroupElement::Value,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    > = bcs::from_bytes(decentralized_dkg_output)?;
    let public_key = match dkg_output {
        twopc_mpc::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(o) => {
            o.public_key
        }
        twopc_mpc::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {
            output: o,
            ..
        } => o.public_key,
    };

    Ok(public_key)
}
