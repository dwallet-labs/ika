// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).

use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkEncryptionKeyPublicDataTrait, SerializedWrappedMPCPublicOutput,
    VersionedDWalletImportedKeyVerificationOutput, VersionedDwalletDKGFirstRoundPublicOutput,
    VersionedDwalletDKGPublicOutput, VersionedDwalletUserSecretShare, VersionedEncryptedUserShare,
    VersionedEncryptionKeyValue, VersionedImportedDwalletOutgoingMessage,
    VersionedNetworkEncryptionKeyPublicData, VersionedPublicKeyShareAndProof,
};
use group::{CsRng, PartyID};
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, RistrettoAsyncDKGProtocol, Secp256k1AsyncDKGProtocol,
    Secp256r1AsyncDKGProtocol, UserSecretKeyShareEventType,
};
use mpc::guaranteed_output_delivery::{AdvanceRequest, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, Party,
    WeightedThresholdAccessStructure,
};
use serde::Serialize;
use std::collections::HashMap;
use twopc_mpc::dkg::{CentralizedPartyKeyShareVerification, Protocol};
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;

/// This struct represents the initial round of the DKG protocol.
pub type DWalletDKGFirstParty = twopc_mpc::secp256k1::class_groups::EncryptionOfSecretKeyShareParty;

pub(crate) type Secp256k1DWalletImportedKeyVerificationParty =
    <Secp256k1AsyncDKGProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
pub(crate) type Secp256r1DWalletImportedKeyVerificationParty =
    <Secp256r1AsyncDKGProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
pub(crate) type Curve25519DWalletImportedKeyVerificationParty =
    <Curve25519AsyncDKGProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
pub(crate) type RistrettoDWalletImportedKeyVerificationParty =
    <RistrettoAsyncDKGProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;

/// This struct represents the final round of the DKG protocol.
pub(crate) type Secp256k1DWalletDKGParty =
    <Secp256k1AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Secp256r1DWalletDKGParty =
    <Secp256r1AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Curve25519DWalletDKGParty =
    <Curve25519AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type RistrettoDWalletDKGParty =
    <RistrettoAsyncDKGProtocol as Protocol>::DKGDecentralizedParty;

#[derive(strum_macros::Display)]
pub(crate) enum DWalletImportedKeyVerificationAdvanceRequestByCurve {
    #[strum(to_string = "dWallet Imported Key Verification Advance Request for curve Secp256k1")]
    Secp256k1(
        AdvanceRequest<<Secp256k1DWalletImportedKeyVerificationParty as mpc::Party>::Message>,
    ),
    #[strum(to_string = "dWallet Imported Key Verification Advance Request for curve Secp256r1")]
    Secp256r1(
        AdvanceRequest<<Secp256r1DWalletImportedKeyVerificationParty as mpc::Party>::Message>,
    ),
    #[strum(to_string = "dWallet Imported Key Verification Advance Request for curve Curve25519")]
    Curve25519(
        AdvanceRequest<<Curve25519DWalletImportedKeyVerificationParty as mpc::Party>::Message>,
    ),
    #[strum(to_string = "dWallet Imported Key Verification Advance Request for curve Ristretto")]
    Ristretto(
        AdvanceRequest<<RistrettoDWalletImportedKeyVerificationParty as mpc::Party>::Message>,
    ),
}

impl DWalletImportedKeyVerificationAdvanceRequestByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match curve {
            DWalletCurve::Secp256k1 => {
                let advance_request = try_ready_to_advance_imported_key::<Secp256k1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletImportedKeyVerificationAdvanceRequestByCurve::Secp256k1)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request = try_ready_to_advance_imported_key::<Secp256r1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletImportedKeyVerificationAdvanceRequestByCurve::Secp256r1)
            }
            DWalletCurve::Curve25519 => {
                let advance_request =
                    try_ready_to_advance_imported_key::<Curve25519AsyncDKGProtocol>(
                        party_id,
                        access_structure,
                        consensus_round,
                        &serialized_messages_by_consensus_round,
                    )?;
                advance_request.map(DWalletImportedKeyVerificationAdvanceRequestByCurve::Curve25519)
            }
            DWalletCurve::Ristretto => {
                let advance_request = try_ready_to_advance_imported_key::<RistrettoAsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletImportedKeyVerificationAdvanceRequestByCurve::Ristretto)
            }
        };

        Ok(advance_request)
    }
}

#[derive(strum_macros::Display)]
pub(crate) enum DWalletDKGAdvanceRequestByCurve {
    #[strum(to_string = "dWallet DKG Advance Request for curve Secp256k1")]
    Secp256k1DWalletDKG(AdvanceRequest<<Secp256k1DWalletDKGParty as mpc::Party>::Message>),
    #[strum(to_string = "dWallet DKG Advance Request for curve Secp256r1")]
    Secp256r1DWalletDKG(AdvanceRequest<<Secp256r1DWalletDKGParty as mpc::Party>::Message>),
    #[strum(to_string = "dWallet DKG Advance Request for curve Curve25519")]
    Curve25519DWalletDKG(AdvanceRequest<<Curve25519DWalletDKGParty as mpc::Party>::Message>),
    #[strum(to_string = "dWallet DKG Advance Request for curve Ristretto")]
    RistrettoDWalletDKG(AdvanceRequest<<RistrettoDWalletDKGParty as mpc::Party>::Message>),
}

impl DWalletDKGAdvanceRequestByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match curve {
            DWalletCurve::Secp256k1 => {
                let advance_request = try_ready_to_advance::<Secp256k1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::Secp256k1DWalletDKG)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request = try_ready_to_advance::<Secp256r1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::Secp256r1DWalletDKG)
            }
            DWalletCurve::Curve25519 => {
                let advance_request = try_ready_to_advance::<Curve25519AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG)
            }
            DWalletCurve::Ristretto => {
                let advance_request = try_ready_to_advance::<RistrettoAsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG)
            }
        };

        Ok(advance_request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub enum DWalletImportedKeyVerificationPublicInputByCurve {
    #[strum(to_string = "dWallet Imported Key Verification Public Input for curve Secp256k1")]
    Secp256k1(<Secp256k1DWalletImportedKeyVerificationParty as Party>::PublicInput),
    #[strum(to_string = "dWallet Imported Key Verification Public Input for curve Secp256r1")]
    Secp256r1(<Secp256r1DWalletImportedKeyVerificationParty as Party>::PublicInput),
    #[strum(to_string = "dWallet Imported Key Verification Public Input for curve Curve25519")]
    Curve25519(<Curve25519DWalletImportedKeyVerificationParty as Party>::PublicInput),
    #[strum(to_string = "dWallet Imported Key Verification Public Input for curve Ristretto")]
    Ristretto(<RistrettoDWalletImportedKeyVerificationParty as Party>::PublicInput),
}

impl DWalletImportedKeyVerificationPublicInputByCurve {
    pub fn try_new(
        session_identifier: CommitmentSizedNumber,
        curve: &DWalletCurve,
        encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        centralized_party_message: &[u8],
        secret_share_verification_type: BytesCentralizedPartyKeyShareVerification,
    ) -> DwalletMPCResult<Self> {
        let public_input = match curve {
            DWalletCurve::Secp256k1 => {
                let protocol_public_parameters =
                    encryption_key_public_data.secp256k1_protocol_public_parameters();
                let centralized_party_message: VersionedImportedDwalletOutgoingMessage =
                    bcs::from_bytes(centralized_party_message)
                        .map_err(DwalletMPCError::BcsError)?;

                let VersionedImportedDwalletOutgoingMessage::V1(centralized_party_message) =
                    centralized_party_message;
                let centralized_party_message: <Secp256k1AsyncDKGProtocol as Protocol>::DealTrustedShareMessage =  bcs::from_bytes(&centralized_party_message)?;

                let public_input =
                    <Secp256k1DWalletImportedKeyVerificationParty as Party>::PublicInput::from((
                        protocol_public_parameters,
                        session_identifier,
                        centralized_party_message,
                        secret_share_verification_type.try_into()?,
                    ));

                DWalletImportedKeyVerificationPublicInputByCurve::Secp256k1(public_input)
            }
            DWalletCurve::Secp256r1 => {
                let protocol_public_parameters =
                    encryption_key_public_data.secp256r1_protocol_public_parameters()?;
                let centralized_party_message: VersionedImportedDwalletOutgoingMessage =
                    bcs::from_bytes(centralized_party_message)
                        .map_err(DwalletMPCError::BcsError)?;

                let VersionedImportedDwalletOutgoingMessage::V1(centralized_party_message) =
                    centralized_party_message;
                let centralized_party_message = bcs::from_bytes(&centralized_party_message)?;

                let public_input = (
                    protocol_public_parameters,
                    session_identifier,
                    centralized_party_message,
                    secret_share_verification_type.try_into()?,
                )
                    .into();

                DWalletImportedKeyVerificationPublicInputByCurve::Secp256r1(public_input)
            }
            DWalletCurve::Curve25519 => {
                let protocol_public_parameters =
                    encryption_key_public_data.curve25519_protocol_public_parameters()?;
                let centralized_party_message: VersionedImportedDwalletOutgoingMessage =
                    bcs::from_bytes(centralized_party_message)
                        .map_err(DwalletMPCError::BcsError)?;

                let VersionedImportedDwalletOutgoingMessage::V1(centralized_party_message) =
                    centralized_party_message;
                let centralized_party_message = bcs::from_bytes(&centralized_party_message)?;

                let public_input = (
                    protocol_public_parameters,
                    session_identifier,
                    centralized_party_message,
                    secret_share_verification_type.try_into()?,
                )
                    .into();

                DWalletImportedKeyVerificationPublicInputByCurve::Curve25519(public_input)
            }
            DWalletCurve::Ristretto => {
                let protocol_public_parameters =
                    encryption_key_public_data.ristretto_protocol_public_parameters()?;
                let centralized_party_message: VersionedImportedDwalletOutgoingMessage =
                    bcs::from_bytes(centralized_party_message)
                        .map_err(DwalletMPCError::BcsError)?;

                let VersionedImportedDwalletOutgoingMessage::V1(centralized_party_message) =
                    centralized_party_message;
                let centralized_party_message = bcs::from_bytes(&centralized_party_message)?;

                let public_input = (
                    protocol_public_parameters,
                    session_identifier,
                    centralized_party_message,
                    secret_share_verification_type.try_into()?,
                )
                    .into();

                DWalletImportedKeyVerificationPublicInputByCurve::Ristretto(public_input)
            }
        };

        Ok(public_input)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub enum DWalletDKGPublicInputByCurve {
    #[strum(to_string = "dWallet DKG Public Input for curve Secp256k1")]
    Secp256k1DWalletDKG(<Secp256k1DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Secp256r1")]
    Secp256r1DWalletDKG(<Secp256r1DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Curve25519")]
    Curve25519DWalletDKG(<Curve25519DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Ristretto")]
    RistrettoDWalletDKG(<RistrettoDWalletDKGParty as Party>::PublicInput),
}

/// Defines the verification method to be performed (if any)
/// on the centralized party's (a.k.a. the "user") key share
/// by the decentralized party (a.k.a. the "network".)
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub enum BytesCentralizedPartyKeyShareVerification {
    /// Used in the "encrypted user-share" feature,
    /// in which the centralized party (a.k.a. the "user") encrypts its secret key share under its own key,
    /// which is verified & store it as backup by the decentralized party (a.k.a. the "network".)
    Encrypted {
        encryption_key_value: Vec<u8>,
        encrypted_secret_key_share_message: Vec<u8>,
    },
    /// Used in the "public user-share" feature, in which the centralized party (a.k.a. the "user")
    /// publishes its secret key share so that anyone can emulate it.
    Public {
        centralized_party_secret_key_share: Vec<u8>,
    },
}

impl From<UserSecretKeyShareEventType> for BytesCentralizedPartyKeyShareVerification {
    fn from(value: UserSecretKeyShareEventType) -> Self {
        match value {
            UserSecretKeyShareEventType::Public {
                public_user_secret_key_share,
                ..
            } => BytesCentralizedPartyKeyShareVerification::Public {
                centralized_party_secret_key_share: public_user_secret_key_share,
            },
            UserSecretKeyShareEventType::Encrypted {
                encryption_key,
                encrypted_centralized_secret_share_and_proof,
                ..
            } => BytesCentralizedPartyKeyShareVerification::Encrypted {
                encryption_key_value: encryption_key,
                encrypted_secret_key_share_message: encrypted_centralized_secret_share_and_proof,
            },
        }
    }
}

impl<CentralizedPartySecretKeyShare, EncryptionKey, EncryptedSecretKeyShareMessage>
    TryFrom<BytesCentralizedPartyKeyShareVerification>
    for CentralizedPartyKeyShareVerification<
        CentralizedPartySecretKeyShare,
        EncryptionKey,
        EncryptedSecretKeyShareMessage,
    >
where
    CentralizedPartySecretKeyShare: serde::de::DeserializeOwned,
    EncryptionKey: serde::de::DeserializeOwned,
    EncryptedSecretKeyShareMessage: serde::de::DeserializeOwned,
{
    type Error = bcs::Error;

    fn try_from(value: BytesCentralizedPartyKeyShareVerification) -> bcs::Result<Self> {
        Ok(match value {
            BytesCentralizedPartyKeyShareVerification::Encrypted {
                encryption_key_value,
                encrypted_secret_key_share_message,
            } => {
                let VersionedEncryptedUserShare::V1(encrypted_secret_key_share_message) =
                    bcs::from_bytes(&encrypted_secret_key_share_message)?;

                let VersionedEncryptionKeyValue::V1(encryption_key_value) =
                    bcs::from_bytes(&encryption_key_value)?;

                CentralizedPartyKeyShareVerification::Encrypted {
                    encryption_key_value: bcs::from_bytes(&encryption_key_value).map_err(|_| {
                        bcs::Error::Custom("failed to deserialize encryption key value".to_string())
                    })?,
                    encrypted_secret_key_share_message: bcs::from_bytes(
                        &encrypted_secret_key_share_message,
                    )
                    .map_err(|_| {
                        bcs::Error::Custom(
                            "failed to deserialize encrypted secret key share message".to_string(),
                        )
                    })?,
                }
            }
            BytesCentralizedPartyKeyShareVerification::Public {
                centralized_party_secret_key_share,
            } => {
                let VersionedDwalletUserSecretShare::V1(centralized_party_secret_key_share) =
                    bcs::from_bytes(&centralized_party_secret_key_share)?;
                CentralizedPartyKeyShareVerification::Public {
                    centralized_party_secret_key_share: bcs::from_bytes(
                        &centralized_party_secret_key_share,
                    )
                    .map_err(|_| {
                        bcs::Error::Custom(
                            "failed to deserialize centralized party secret key share".to_string(),
                        )
                    })?,
                }
            }
        })
    }
}

impl DWalletDKGPublicInputByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
        centralized_party_key_share_verification: BytesCentralizedPartyKeyShareVerification,
    ) -> DwalletMPCResult<Self> {
        let centralized_party_public_key_share: VersionedPublicKeyShareAndProof =
            bcs::from_bytes(centralized_party_public_key_share_buf).map_err(|_| {
                bcs::Error::Custom(
                    "failed to deserialize centralized party public key share".to_string(),
                )
            })?;

        let public_input = match curve {
            DWalletCurve::Secp256k1 => {
                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share).map_err(|_| {
                            DwalletMPCError::BcsError(bcs::Error::Custom(
                                "failed to deserialize centralized party public key share"
                                    .to_string(),
                            ))
                        })?
                    }
                };
                let input = (
                    encryption_key_public_data.secp256k1_protocol_public_parameters(),
                    centralized_party_public_key_share,
                    centralized_party_key_share_verification.try_into()?,
                )
                    .into();

                DWalletDKGPublicInputByCurve::Secp256k1DWalletDKG(input)
            }
            DWalletCurve::Secp256r1 => {
                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share)
                            .map_err(DwalletMPCError::BcsError)?
                    }
                };
                let input = (
                    encryption_key_public_data.secp256r1_protocol_public_parameters()?,
                    centralized_party_public_key_share,
                    centralized_party_key_share_verification.try_into()?,
                )
                    .into();

                DWalletDKGPublicInputByCurve::Secp256r1DWalletDKG(input)
            }
            DWalletCurve::Curve25519 => {
                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share)
                            .map_err(DwalletMPCError::BcsError)?
                    }
                };
                let input = (
                    encryption_key_public_data.curve25519_protocol_public_parameters()?,
                    centralized_party_public_key_share,
                    centralized_party_key_share_verification.try_into()?,
                )
                    .into();

                DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(input)
            }
            DWalletCurve::Ristretto => {
                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share)
                            .map_err(DwalletMPCError::BcsError)?
                    }
                };
                let input = (
                    encryption_key_public_data.ristretto_protocol_public_parameters()?,
                    centralized_party_public_key_share,
                    centralized_party_key_share_verification.try_into()?,
                )
                    .into();

                DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(input)
            }
        };

        Ok(public_input)
    }
}

pub(crate) fn dwallet_dkg_first_public_input(
    protocol_public_parameters: &twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<<DWalletDKGFirstParty as mpc::Party>::PublicInput> {
    <DWalletDKGFirstParty as DWalletDKGFirstPartyPublicInputGenerator>::generate_public_input(
        protocol_public_parameters.clone(),
    )
}

pub(crate) fn dwallet_dkg_second_public_input(
    first_round_output: &SerializedWrappedMPCPublicOutput,
    centralized_public_key_share_and_proof: &SerializedWrappedMPCPublicOutput,
    protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<<Secp256k1DWalletDKGParty as mpc::Party>::PublicInput> {
    <Secp256k1DWalletDKGParty as DWalletDKGSecondPartyPublicInputGenerator>::generate_public_input(
        protocol_public_parameters,
        first_round_output,
        centralized_public_key_share_and_proof,
    )
}

/// A trait for generating the public input for the initial round of the DKG protocol.
///
/// This trait is implemented to resolve compiler type ambiguities that arise in the 2PC-MPC library
/// when accessing [`Party::PublicInput`].
/// It defines the parameters and logic
/// necessary to initiate the first round of the DKG protocol,
/// preparing the party with the essential session information and other contextual data.
pub(crate) trait DWalletDKGFirstPartyPublicInputGenerator: Party {
    /// Generates the public input required for the first round of the DKG protocol.
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    ) -> DwalletMPCResult<<DWalletDKGFirstParty as mpc::Party>::PublicInput>;
}

/// A trait for generating the public input for the last round of the DKG protocol.
///
/// This trait is implemented to resolve compiler type ambiguities that arise in the 2PC-MPC library
/// when accessing [`Party::PublicInput`].
/// It defines the parameters and logic
/// necessary to initiate the second round of the DKG protocol,
/// preparing the party with the essential session information and other contextual data.
pub(crate) trait DWalletDKGSecondPartyPublicInputGenerator: Party {
    /// Generates the public input required for the second round of the DKG protocol.
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        first_round_output: &SerializedWrappedMPCPublicOutput,
        centralized_party_public_key_share: &SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<Secp256k1DWalletDKGParty as mpc::Party>::PublicInput>;
}

impl DWalletDKGFirstPartyPublicInputGenerator for DWalletDKGFirstParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
    ) -> DwalletMPCResult<<DWalletDKGFirstParty as Party>::PublicInput> {
        let secp256k1_public_input =
            twopc_mpc::dkg::encryption_of_secret_key_share::PublicInput::new_targeted_dkg(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                protocol_public_parameters.encryption_scheme_public_parameters,
            );
        let input: Self::PublicInput = secp256k1_public_input;
        Ok(input)
    }
}

impl DWalletDKGSecondPartyPublicInputGenerator for Secp256k1DWalletDKGParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
        first_round_output_buf: &SerializedWrappedMPCPublicOutput,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<Secp256k1DWalletDKGParty as mpc::Party>::PublicInput> {
        let first_round_output_buf: VersionedDwalletDKGFirstRoundPublicOutput =
            bcs::from_bytes(first_round_output_buf).map_err(DwalletMPCError::BcsError)?;

        let centralized_party_public_key_share: VersionedPublicKeyShareAndProof =
            bcs::from_bytes(centralized_party_public_key_share_buf)
                .map_err(DwalletMPCError::BcsError)?;

        match first_round_output_buf {
            VersionedDwalletDKGFirstRoundPublicOutput::V1(first_round_output) => {
                let ([first_part, second_part], _): (
                    <DWalletDKGFirstParty as mpc::Party>::PublicOutputValue,
                    CommitmentSizedNumber,
                ) = bcs::from_bytes(&first_round_output)?;
                let (first_first_part, first_second_part) = first_part.into();
                let (second_first_part, second_second_part) = second_part.into();
                // This is a temporary hack to keep working with the existing 2-round dWallet DKG mechanism.
                // TODO (#1470): Use one network round in the dWallet DKG flow.
                let protocol_public_parameters_with_dkg_centralized_output =
                    ProtocolPublicParameters::new::<
                        { group::secp256k1::SCALAR_LIMBS },
                        { twopc_mpc::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        { twopc_mpc::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        group::secp256k1::GroupElement,
                    >(
                        first_second_part,
                        second_second_part,
                        first_first_part,
                        second_first_part,
                        protocol_public_parameters
                            .encryption_scheme_public_parameters
                            .clone(),
                    );

                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share)
                            .map_err(DwalletMPCError::BcsError)?
                    }
                };

                let input: Self::PublicInput = (
                    protocol_public_parameters_with_dkg_centralized_output,
                    centralized_party_public_key_share,
                    CentralizedPartyKeyShareVerification::None,
                )
                    .into();

                Ok(input)
            }
        }
    }
}

fn try_ready_to_advance<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    consensus_round: u64,
    serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
) -> DwalletMPCResult<Option<AdvanceRequest<<P::DKGDecentralizedParty as Party>::Message>>> {
    let advance_request_result =
        mpc::guaranteed_output_delivery::Party::<P::DKGDecentralizedParty>::ready_to_advance(
            party_id,
            access_structure,
            consensus_round,
            HashMap::new(),
            serialized_messages_by_consensus_round,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match advance_request_result {
        ReadyToAdvanceResult::ReadyToAdvance(advance_request) => Ok(Some(advance_request)),
        ReadyToAdvanceResult::WaitForMoreMessages { .. } => Ok(None),
    }
}

fn try_ready_to_advance_imported_key<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    consensus_round: u64,
    serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
) -> DwalletMPCResult<
    Option<AdvanceRequest<<P::TrustedDealerDKGDecentralizedParty as Party>::Message>>,
> {
    let advance_request_result = mpc::guaranteed_output_delivery::Party::<
        P::TrustedDealerDKGDecentralizedParty,
    >::ready_to_advance(
        party_id,
        access_structure,
        consensus_round,
        HashMap::new(),
        serialized_messages_by_consensus_round,
    )
    .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match advance_request_result {
        ReadyToAdvanceResult::ReadyToAdvance(advance_request) => Ok(Some(advance_request)),
        ReadyToAdvanceResult::WaitForMoreMessages { .. } => Ok(None),
    }
}

pub fn compute_dwallet_dkg<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<P::DKGDecentralizedParty as Party>::Message>,
    public_input: <P::DKGDecentralizedParty as Party>::PublicInput,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = mpc::guaranteed_output_delivery::Party::<P::DKGDecentralizedParty>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        None,
        &public_input.clone(),
        rng,
    ).map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let public_output_value =
                bcs::to_bytes(&VersionedDwalletDKGPublicOutput::V2(public_output_value))?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}

pub fn compute_imported_key_verification<P: Protocol>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    advance_request: AdvanceRequest<<P::TrustedDealerDKGDecentralizedParty as Party>::Message>,
    public_input: &<P::TrustedDealerDKGDecentralizedParty as Party>::PublicInput,
    protocol_version: ProtocolVersion,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = mpc::guaranteed_output_delivery::Party::<P::TrustedDealerDKGDecentralizedParty>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        None,
        public_input,
        rng,
    ).map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            // Wrap the public output with its version.
            let versioned_output = match protocol_version.as_u64() {
                1 => {
                    let decentralized_output: <Secp256k1AsyncDKGProtocol as Protocol>::DecentralizedPartyDKGOutput = bcs::from_bytes(&public_output_value)?;
                    let decentralized_output: <Secp256k1AsyncDKGProtocol as Protocol>::DecentralizedPartyTargetedDKGOutput = decentralized_output.into();

                    bcs::to_bytes(&VersionedDWalletImportedKeyVerificationOutput::V1(
                        bcs::to_bytes(&decentralized_output)?,
                    ))?
                }
                2 => bcs::to_bytes(&VersionedDWalletImportedKeyVerificationOutput::V2(
                    public_output_value,
                ))?,
                _ => {
                    return Err(DwalletMPCError::UnsupportedProtocolVersion(
                        protocol_version.as_u64(),
                    ));
                }
            };

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value: versioned_output,
                malicious_parties,
                private_output,
            })
        }
    }
}
