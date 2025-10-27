// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use class_groups::reconfiguration::Secp256k1Party;
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

#[enum_dispatch]
pub trait NetworkEncryptionKeyPublicDataTrait {
    fn epoch(&self) -> u64;
    fn network_dkg_output(&self) -> &VersionedNetworkDkgOutput;
    fn state(&self) -> &NetworkDecryptionKeyPublicOutputType;
    fn latest_network_reconfiguration_public_output(
        &self,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput>;

    // Secp256k1 parameters are available from V1, while other curve types are only available in V2.
    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters;
    fn secp256k1_protocol_public_parameters(
        &self,
    ) -> twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;

    fn secp256r1_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>;
    fn ristretto_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::ristretto::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>;
    fn curve25519_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::curve25519::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>;

    fn secp256r1_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Secp256r1DecryptionKeySharePublicParameters, DwalletNetworkMPCError>;
    fn ristretto_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::RistrettoDecryptionKeySharePublicParameters, DwalletNetworkMPCError>;
    fn curve25519_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Curve25519DecryptionKeySharePublicParameters, DwalletNetworkMPCError>;
}

#[enum_dispatch(NetworkEncryptionKeyPublicDataTrait)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum VersionedNetworkEncryptionKeyPublicData {
    V1(NetworkEncryptionKeyPublicDataV1),
    V2(NetworkEncryptionKeyPublicDataV2),
}

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
pub enum DWalletSignatureAlgorithm {
    #[strum(to_string = "ECDSASecp256k1")]
    ECDSASecp256k1,
    #[strum(to_string = "ECDSASecp256r1")]
    ECDSASecp256r1,
    #[strum(to_string = "Taproot")]
    Taproot,
    #[strum(to_string = "EdDSA")]
    EdDSA,
    #[strum(to_string = "SchnorrkelSubstrate")]
    SchnorrkelSubstrate,
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
}

pub type ClassGroupsPublicKeyAndProofBytes = Vec<u8>;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedEncryptionKeyValue {
    V1(Vec<u8>),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDWalletImportedKeyVerificationOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGFirstRoundPublicOutput {
    V1(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedDwalletDKGPublicOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedPresignOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VersionedSignOutput {
    V1(MPCPublicOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Hash)]
pub enum VersionedNetworkDkgOutput {
    V1(MPCPublicOutput),
    V2(MPCPublicOutput),
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

impl NetworkEncryptionKeyPublicDataTrait for NetworkEncryptionKeyPublicDataV1 {
    fn epoch(&self) -> u64 {
        self.epoch
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

    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters {
        self.secp256k1_decryption_key_share_public_parameters
            .clone()
    }

    fn secp256k1_protocol_public_parameters(&self) -> ProtocolPublicParameters {
        self.secp256k1_protocol_public_parameters.clone()
    }

    fn secp256r1_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Secp256r1,
            ),
        )
    }

    fn ristretto_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::ristretto::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Ristretto,
            ),
        )
    }

    fn curve25519_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::curve25519::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Curve25519,
            ),
        )
    }

    fn secp256r1_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Secp256r1DecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Secp256r1,
            ),
        )
    }

    fn ristretto_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::RistrettoDecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Ristretto,
            ),
        )
    }

    fn curve25519_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Curve25519DecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Err(
            DwalletNetworkMPCError::MissingProtocolPublicParametersForCurve(
                DWalletCurve::Curve25519,
            ),
        )
    }
}

impl NetworkEncryptionKeyPublicDataTrait for NetworkEncryptionKeyPublicDataV2 {
    fn epoch(&self) -> u64 {
        self.epoch
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

    fn secp256k1_decryption_key_share_public_parameters(
        &self,
    ) -> class_groups::Secp256k1DecryptionKeySharePublicParameters {
        self.secp256k1_decryption_key_share_public_parameters
            .clone()
    }

    fn secp256k1_protocol_public_parameters(&self) -> ProtocolPublicParameters {
        self.secp256k1_protocol_public_parameters.clone()
    }

    fn secp256r1_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Ok(self.secp256r1_protocol_public_parameters.clone())
    }

    fn ristretto_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::ristretto::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Ok(self.ristretto_protocol_public_parameters.clone())
    }

    fn curve25519_protocol_public_parameters(
        &self,
    ) -> Result<twopc_mpc::curve25519::class_groups::ProtocolPublicParameters, DwalletNetworkMPCError>
    {
        Ok(self.curve25519_protocol_public_parameters.clone())
    }

    fn secp256r1_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Secp256r1DecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Ok(self
            .secp256r1_decryption_key_share_public_parameters
            .clone())
    }

    fn ristretto_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::RistrettoDecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Ok(self
            .ristretto_decryption_key_share_public_parameters
            .clone())
    }

    fn curve25519_decryption_key_share_public_parameters(
        &self,
    ) -> Result<class_groups::Curve25519DecryptionKeySharePublicParameters, DwalletNetworkMPCError>
    {
        Ok(self
            .curve25519_decryption_key_share_public_parameters
            .clone())
    }
}

pub type ReconfigurationParty = Secp256k1Party;
pub type ReconfigurationV2Party = twopc_mpc::decentralized_party::reconfiguration::Party;
