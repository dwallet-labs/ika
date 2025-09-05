// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use twopc_mpc::class_groups::{DKGDecentralizedPartyOutput, DKGDecentralizedPartyVersionedOutput};
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;

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

/// The public output of the DKG and/or Reconfiguration protocols, which holds the (encrypted) decryption key shares.
/// Created for each DKG protocol and modified for each Reconfiguration Protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEncryptionKeyPublicDataV1 {
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
}

pub trait NetworkEncryptionKeyPublicData {
    fn epoch(&self) -> u64;
    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters;
    fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput;
    fn state(&self) -> &NetworkDecryptionKeyPublicOutputType;
    fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput>;
    fn secp256k1_protocol_public_parameters(
        &self,
    ) -> twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;
}

impl NetworkEncryptionKeyPublicData for NetworkEncryptionKeyPublicDataV1 {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters {
        self.secp256k1_decryption_key_share_public_parameters
            .clone()
    }

    fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput {
        &self.network_dkg_output
    }

    fn state(&self) -> &NetworkDecryptionKeyPublicOutputType {
        &self.state
    }

    fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        self.latest_network_reconfiguration_public_output.clone()
    }

    fn secp256k1_protocol_public_parameters(&self) -> ProtocolPublicParameters {
        self.secp256k1_protocol_public_parameters.clone()
    }
}

impl NetworkEncryptionKeyPublicData for NetworkEncryptionKeyPublicDataV2 {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters {
        self.secp256k1_decryption_key_share_public_parameters
            .clone()
    }
    fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput {
        &self.network_dkg_output
    }
    fn state(&self) -> &NetworkDecryptionKeyPublicOutputType {
        &self.state
    }

    fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        self.latest_network_reconfiguration_public_output.clone()
    }

    fn secp256k1_protocol_public_parameters(&self) -> ProtocolPublicParameters {
        self.secp256k1_protocol_public_parameters.clone()
    }
}

impl NetworkEncryptionKeyPublicData for VersionedNetworkEncryptionKeyPublicData {
    fn epoch(&self) -> u64 {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => data.epoch(),
            VersionedNetworkEncryptionKeyPublicData::V2(data) => data.epoch(),
        }
    }

    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => {
                data.secp256k1_decryption_key_share_public_parameters()
            }
            VersionedNetworkEncryptionKeyPublicData::V2(data) => {
                data.secp256k1_decryption_key_share_public_parameters()
            }
        }
    }

    fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => data.network_dkg_output(),
            VersionedNetworkEncryptionKeyPublicData::V2(data) => data.network_dkg_output(),
        }
    }

    fn state(&self) -> &NetworkDecryptionKeyPublicOutputType {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => data.state(),
            VersionedNetworkEncryptionKeyPublicData::V2(data) => data.state(),
        }
    }

    fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => {
                data.latest_network_reconfiguration_public_output()
            }
            VersionedNetworkEncryptionKeyPublicData::V2(data) => {
                data.latest_network_reconfiguration_public_output()
            }
        }
    }

    fn secp256k1_protocol_public_parameters(&self) -> ProtocolPublicParameters {
        match self {
            VersionedNetworkEncryptionKeyPublicData::V1(data) => {
                data.secp256k1_protocol_public_parameters()
            }
            VersionedNetworkEncryptionKeyPublicData::V2(data) => {
                data.secp256k1_protocol_public_parameters()
            }
        }
    }
}

#[enum_dispatch(NetworkEncryptionKeyPublicData)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedNetworkEncryptionKeyPublicData {
    V1(NetworkEncryptionKeyPublicDataV1),
    V2(NetworkEncryptionKeyPublicDataV2),
}

/// The public output of the DKG and/or Reconfiguration protocols, which holds the (encrypted) decryption key shares.
/// Created for each DKG protocol and modified for each Reconfiguration Protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEncryptionKeyPublicDataV2 {
    /// The epoch of the last version update.
    pub epoch: u64,

    pub state: NetworkDecryptionKeyPublicOutputType,
    /// The public output of the `latest` decryption key update (Reconfiguration).
    pub latest_network_reconfiguration_public_output:
        Option<VersionedDecryptionKeyReconfigurationOutput>,
    /// The public output of the `NetworkDKG` process (the first and only one).
    /// On first instance it will be equal to `latest_public_output`.
    pub network_dkg_output: VersionedNetworkDkgOutput,
    pub secp256k1_protocol_public_parameters:
        twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    /// The public parameters of the decryption key shares,
    /// updated only after a successful network DKG or Reconfiguration.
    pub secp256k1_decryption_key_share_public_parameters:
        class_groups::Secp256k1DecryptionKeySharePublicParameters,
    pub secp256r1_protocol_public_parameters:
        twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters,
    pub secp256r1_decryption_key_share_public_parameters:
        class_groups::Secp256r1DecryptionKeySharePublicParameters,
    pub ristretto_protocol_public_parameters:
        twopc_mpc::ristretto::class_groups::ProtocolPublicParameters,
    pub ristretto_decryption_key_share_public_parameters:
        class_groups::RistrettoDecryptionKeySharePublicParameters,
    pub curve25519_protocol_public_parameters:
        twopc_mpc::curve25519::class_groups::ProtocolPublicParameters,
    pub curve25519_decryption_key_share_public_parameters:
        class_groups::Curve25519DecryptionKeySharePublicParameters,
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
// useful to tell which protocol public parameters to use
pub enum DWalletCurve {
    #[strum(to_string = "Secp256k1")]
    Secp256k1 = 0,
    #[strum(to_string = "Ristretto")]
    Ristretto = 1,
    #[strum(to_string = "Secp256r1")]
    Secp256r1 = 2,
    #[strum(to_string = "Curve25519")]
    Curve25519 = 3,
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
pub enum DWalletSignatureScheme {
    #[strum(to_string = "ECDSASecp256k1")]
    ECDSASecp256k1 = 0,
    #[strum(to_string = "Taproot")]
    Taproot = 1,
    #[strum(to_string = "ECDSASecp256r1")]
    ECDSASecp256r1 = 2,
    #[strum(to_string = "EdDSA")]
    EdDSA = 3,
    #[strum(to_string = "SchnorrkelSubstrate")]
    SchnorrkelSubstrate = 4,
}

// We can't import ika-types here since we import this module in there.
// Therefore, we use `thiserror` `#from` to convert this error.
#[derive(Debug, Error, Clone)]
pub enum DwalletNetworkMPCError {
    #[error("invalid DWalletMPCNetworkKey value: {0}")]
    InvalidDWalletMPCCurve(u32),

    #[error("invalid DWalletMPCSignatureAlgorithm value: {0}")]
    InvalidDWalletMPCSignatureAlgorithm(u32),
}

impl TryFrom<u32> for DWalletCurve {
    type Error = DwalletNetworkMPCError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DWalletCurve::Secp256k1),
            1 => Ok(DWalletCurve::Ristretto),
            2 => Ok(DWalletCurve::Secp256r1),
            3 => Ok(DWalletCurve::Curve25519),
            v => Err(DwalletNetworkMPCError::InvalidDWalletMPCCurve(v)),
        }
    }
}

impl TryFrom<u32> for DWalletSignatureScheme {
    type Error = DwalletNetworkMPCError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DWalletSignatureScheme::ECDSASecp256k1),
            1 => Ok(DWalletSignatureScheme::Taproot),
            2 => Ok(DWalletSignatureScheme::ECDSASecp256r1),
            3 => Ok(DWalletSignatureScheme::EdDSA),
            4 => Ok(DWalletSignatureScheme::SchnorrkelSubstrate),
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
