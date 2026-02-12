// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::mpc_protocol_configuration::try_into_curve;
use class_groups::CiphertextSpaceValue;
use crypto_bigint::{Encoding, Uint};
use enum_dispatch::enum_dispatch;
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
    /// On first instance it will be equal to `latest_public_output`.
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

    /// The DKG output for internal checkpoint signing.
    ///
    /// This field holds the centralized party DKG output created using a deterministic
    /// zero-returning RNG (`ZeroRng`) to emulate the centralized party. This enables
    /// the network to perform internal signing operations (e.g., checkpoint signing)
    /// without requiring an actual user.
    ///
    /// # Security Model
    ///
    /// The "user" (centralized party) key share is effectively zero/deterministic, meaning
    /// there is no user secret to protect. Security for internal signing comes entirely
    /// from the network's threshold signature scheme, not from randomness.
    ///
    /// # Structure
    ///
    /// The output is stored as `(curve, signature_algorithm, serialized_dkg_output)`.
    /// - `curve`: The curve used for signing (e.g., Curve25519)
    /// - `signature_algorithm`: The signature algorithm (e.g., EdDSA)
    /// - `serialized_dkg_output`: BCS-serialized `VersionedDwalletDKGPublicOutput`
    pub internal_checkpoint_dkg_output: Option<(DWalletCurve, DWalletSignatureAlgorithm, Vec<u8>)>,
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
    #[strum(to_string = "SchnorrkelSubstrate")]
    SchnorrkelSubstrate,
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
}

impl From<DWalletHashScheme> for group::HashScheme {
    fn from(scheme: DWalletHashScheme) -> Self {
        match scheme {
            DWalletHashScheme::Keccak256 => group::HashScheme::Keccak256,
            DWalletHashScheme::SHA256 => group::HashScheme::SHA256,
            DWalletHashScheme::DoubleSHA256 => group::HashScheme::DoubleSHA256,
            DWalletHashScheme::SHA512 => group::HashScheme::SHA512,
            DWalletHashScheme::Merlin => group::HashScheme::Merlin,
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
}

pub type ClassGroupsPublicKeyAndProofBytes = Vec<u8>;

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

impl VersionedNetworkDkgOutput {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V1(bytes) | Self::V2(bytes) => bytes,
        }
    }
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

    /// Returns the internal checkpoint centralized DKG output if available.
    ///
    /// The output contains:
    /// - The curve used for signing
    /// - The signature algorithm
    /// - The serialized `VersionedDwalletDKGPublicOutput`
    pub fn internal_checkpoint_centralized_dkg_output(
        &self,
    ) -> Option<&(DWalletCurve, DWalletSignatureAlgorithm, Vec<u8>)> {
        self.internal_checkpoint_dkg_output.as_ref()
    }

    /// Returns the serialized protocol public parameters for the given curve.
    ///
    /// This is useful for internal signing operations where the protocol public
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
