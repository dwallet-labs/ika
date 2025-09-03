// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use twopc_mpc::class_groups::{DKGDecentralizedPartyOutput, DKGDecentralizedPartyVersionedOutput};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2NetworkKeyData {
    pub secp256r1_protocol_public_parameters:
        twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters,
    pub secp256r1_decryption_key_share_public_parameters:
        class_groups::Secp256r1DecryptionKeySharePublicParameters,

    pub ristretto_decryption_key_share_public_parameters:
        class_groups::RistrettoDecryptionKeySharePublicParameters,

    pub curve25519_decryption_key_share_public_parameters:
        class_groups::Curve25519DecryptionKeySharePublicParameters,
    pub ristretto_protocol_public_parameters:
        twopc_mpc::ristretto::class_groups::ProtocolPublicParameters,
    pub curve25519_protocol_public_parameters:
        twopc_mpc::curve25519::class_groups::ProtocolPublicParameters,
}

/// The public output of the DKG and/or Reconfiguration protocols, which holds the (encrypted) decryption key shares.
/// Created for each DKG protocol and modified for each Reconfiguration Protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEncryptionKeyPublicData {
    /// The epoch of the last version update.
    pub epoch: u64,

    pub state: NetworkDecryptionKeyPublicOutputType,
    /// The public output of the `latest` decryption key update (Reconfiguration).
    pub latest_network_reconfiguration_public_output:
        Option<VersionedDecryptionKeyReconfigurationOutput>,
    /// The public parameters of the decryption key shares,
    /// updated only after a successful network DKG or Reconfiguration.
    pub secp256k1_decryption_key_share_public_parameters:
        class_groups::Secp256k1DecryptionKeySharePublicParameters,
    /// The public output of the `NetworkDKG` process (the first and only one).
    /// On first instance it will be equal to `latest_public_output`.
    pub network_dkg_output: VersionedNetworkDkgOutput,
    pub secp256k1_protocol_public_parameters:
        twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    pub v2_data: Option<V2NetworkKeyData>,
}

#[repr(u32)]
#[derive(
    strum_macros::Display,
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
)]
pub enum DWalletMPCNetworkKeyScheme {
    #[strum(to_string = "Secp256k1")]
    Secp256k1 = 0,
    #[strum(to_string = "Ristretto")]
    Ristretto = 1,
    #[strum(to_string = "Secp256r1")]
    Secp256r1 = 2,
}

#[repr(u32)]
#[derive(
    strum_macros::Display,
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
)]
pub enum SignatureAlgorithm {
    #[strum(to_string = "ECDSA")]
    ECDSA,
}

// We can't import ika-types here since we import this module in there.
// Therefore, we use `thiserror` `#from` to convert this error.
#[derive(Debug, Error, Clone)]
pub enum DwalletNetworkMPCError {
    #[error("invalid DWalletMPCNetworkKey value: {0}")]
    InvalidDWalletMPCNetworkKey(u32),

    #[error("invalid DWalletMPCSignatureAlgorithm value: {0}")]
    InvalidDWalletMPCSignatureAlgorithm(u32),
}

impl TryFrom<u32> for DWalletMPCNetworkKeyScheme {
    type Error = DwalletNetworkMPCError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DWalletMPCNetworkKeyScheme::Secp256k1),
            1 => Ok(DWalletMPCNetworkKeyScheme::Ristretto),
            v => Err(DwalletNetworkMPCError::InvalidDWalletMPCNetworkKey(v)),
        }
    }
}

impl TryFrom<u32> for SignatureAlgorithm {
    type Error = DwalletNetworkMPCError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SignatureAlgorithm::ECDSA),
            v => Err(DwalletNetworkMPCError::InvalidDWalletMPCSignatureAlgorithm(
                v,
            )),
        }
    }
}

pub type ClassGroupsPublicKeyAndProofBytes = Vec<u8>;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDWalletImportedKeyVerificationOutput {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGFirstRoundPublicOutput {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGSecondRoundPublicOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedPresignOutput {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedSignOutput {
    V1(MPCPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum VersionedNetworkDkgOutput {
    V1(MPCPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum VersionedDecryptionKeyReconfigurationOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
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
pub enum VersionedImportedDWalletPublicOutput {
    V1(MPCPublicOutput),
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
    pub class_groups_public_key_and_proof: ClassGroupsPublicKeyAndProofBytes,
}

#[enum_dispatch]
pub trait MPCDataTrait {
    fn class_groups_public_key_and_proof(&self) -> ClassGroupsPublicKeyAndProofBytes;
}

impl MPCDataTrait for MPCDataV1 {
    fn class_groups_public_key_and_proof(&self) -> ClassGroupsPublicKeyAndProofBytes {
        self.class_groups_public_key_and_proof.clone()
    }
}
