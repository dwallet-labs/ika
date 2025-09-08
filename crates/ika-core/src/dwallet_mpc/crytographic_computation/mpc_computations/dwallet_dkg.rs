// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).

use crate::dwallet_mpc::mpc_session::PublicInput;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkEncryptionKeyPublicData, SerializedWrappedMPCPublicOutput,
    VersionedCentralizedDKGPublicOutput, VersionedDwalletDKGFirstRoundPublicOutput,
    VersionedNetworkEncryptionKeyPublicData, VersionedPublicKeyShareAndProof,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncProtocol, Ristretto255AsyncProtocol, Secp256K1AsyncProtocol,
    Secp256R1AsyncProtocol,
};
use mpc::Party;
use twopc_mpc::BaseProtocolContext;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;

/// This struct represents the initial round of the DKG protocol.
pub type DWalletDKGFirstParty = twopc_mpc::secp256k1::class_groups::EncryptionOfSecretKeyShareParty;
pub(crate) type DWalletImportedKeyVerificationParty =
    <Secp256K1AsyncProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
/// This struct represents the final round of the DKG protocol.
pub(crate) type Secp256K1DWalletDKGParty =
    <Secp256K1AsyncProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Secp256R1DWalletDKGParty =
    <Secp256R1AsyncProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Curve25519DWalletDKGParty =
    <Curve25519AsyncProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type RistrettoDWalletDKGParty =
    <Ristretto255AsyncProtocol as Protocol>::DKGDecentralizedParty;


pub fn dwallet_dkg_generate_public_input(
    curve: &DWalletCurve,
    encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
    centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<PublicInput> {
    let centralized_party_public_key_share: VersionedPublicKeyShareAndProof =
        bcs::from_bytes(centralized_party_public_key_share_buf)
            .map_err(DwalletMPCError::BcsError)?;

    let public_input = match curve {
        DWalletCurve::Secp256k1 => {
            let centralized_party_public_key_share = match centralized_party_public_key_share {
                VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                    bcs::from_bytes(&centralized_party_public_key_share)
                        .map_err(DwalletMPCError::BcsError)?
                }
            };
            let input = (
                encryption_key_public_data.secp256k1_protocol_public_parameters(),
                centralized_party_public_key_share,
            )
                .into();

            PublicInput::Secp256K1DWalletDKG(input)
        }
        DWalletCurve::Secp256r1 => {
            let centralized_party_public_key_share = match centralized_party_public_key_share {
                VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                    bcs::from_bytes(&centralized_party_public_key_share)
                        .map_err(DwalletMPCError::BcsError)?
                }
            };
            let input = (
                encryption_key_public_data
                    .secp256r1_protocol_public_parameters()
                    .ok_or(DwalletMPCError::MissingProtocolPublicParametersForCurve(
                        DWalletCurve::Secp256r1,
                    ))?,
                centralized_party_public_key_share,
            )
                .into();

            PublicInput::Secp256R1DWalletDKG(input)
        }
        DWalletCurve::Curve25519 => {
            let centralized_party_public_key_share = match centralized_party_public_key_share {
                VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                    bcs::from_bytes(&centralized_party_public_key_share)
                        .map_err(DwalletMPCError::BcsError)?
                }
            };
            let input = (
                encryption_key_public_data
                    .curve25519_protocol_public_parameters()
                    .ok_or(DwalletMPCError::MissingProtocolPublicParametersForCurve(
                        DWalletCurve::Curve25519,
                    ))?,
                centralized_party_public_key_share,
            )
                .into();

            PublicInput::Curve25519DWalletDKG(input)
        }
        DWalletCurve::Ristretto => {
            let centralized_party_public_key_share = match centralized_party_public_key_share {
                VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                    bcs::from_bytes(&centralized_party_public_key_share)
                        .map_err(DwalletMPCError::BcsError)?
                }
            };
            let input = (
                encryption_key_public_data
                    .ristretto_protocol_public_parameters()
                    .ok_or(DwalletMPCError::MissingProtocolPublicParametersForCurve(
                        DWalletCurve::Ristretto,
                    ))?,
                centralized_party_public_key_share,
            )
                .into();

            PublicInput::RistrettoDWalletDKG(input)
        }
    };

    Ok(public_input)
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
) -> DwalletMPCResult<<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput> {
    <Secp256K1DWalletDKGParty as DWalletDKGSecondPartyPublicInputGenerator>::generate_public_input(
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
    ) -> DwalletMPCResult<<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput>;
}

impl DWalletDKGFirstPartyPublicInputGenerator for DWalletDKGFirstParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
    ) -> DwalletMPCResult<<DWalletDKGFirstParty as Party>::PublicInput> {
        let base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC DKG".to_string(),
            round_name: "1 - Encryption of Secret Key Share".to_string(),
            proof_name: "Encryption of Secret Key Share and Public Key Share Proof".to_string(),
        };
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

impl DWalletDKGSecondPartyPublicInputGenerator for Secp256K1DWalletDKGParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
        first_round_output_buf: &SerializedWrappedMPCPublicOutput,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput> {
        // TODO (#1482): Use this hack only for V1 dWallet DKG outputs
        let first_round_output_buf: VersionedDwalletDKGFirstRoundPublicOutput =
            bcs::from_bytes(first_round_output_buf).map_err(DwalletMPCError::BcsError)?;

        let centralized_party_public_key_share: VersionedPublicKeyShareAndProof =
            bcs::from_bytes(centralized_party_public_key_share_buf)
                .map_err(DwalletMPCError::BcsError)?;

        match first_round_output_buf {
            VersionedDwalletDKGFirstRoundPublicOutput::V1(first_round_output) => {
                let (first_round_output, _) =
                    bcs::from_bytes::<(Vec<u8>, CommitmentSizedNumber)>(&first_round_output)?;
                let [first_part, second_part]: <DWalletDKGFirstParty as Party>::PublicOutput =
                    bcs::from_bytes(&first_round_output).map_err(DwalletMPCError::BcsError)?;
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
                )
                    .into();

                Ok(input)
            }
        }
    }
}
