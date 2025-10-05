// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use class_groups::publicly_verifiable_secret_sharing::BaseProtocolContext;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkEncryptionKeyPublicDataTrait, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedEncryptedUserShare, VersionedNetworkEncryptionKeyPublicData,
    VersionedPublicKeyShareAndProof,
};
use group::{CsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncDKGProtocol, RistrettoAsyncDKGProtocol, Secp256K1AsyncDKGProtocol,
    Secp256R1AsyncDKGProtocol,
};
use mpc::guaranteed_output_delivery::{AdvanceRequest, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, Party,
    WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use twopc_mpc::dkg::Protocol;
use twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters;

/// This struct represents the initial round of the DKG protocol.
pub type DWalletDKGFirstParty = twopc_mpc::secp256k1::class_groups::EncryptionOfSecretKeyShareParty;
pub(crate) type DWalletImportedKeyVerificationParty =
    <Secp256K1AsyncDKGProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
/// This struct represents the final round of the DKG protocol.
pub(crate) type Secp256K1DWalletDKGParty =
    <Secp256K1AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Secp256R1DWalletDKGParty =
    <Secp256R1AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type Curve25519DWalletDKGParty =
    <Curve25519AsyncDKGProtocol as Protocol>::DKGDecentralizedParty;
pub(crate) type RistrettoDWalletDKGParty =
    <RistrettoAsyncDKGProtocol as Protocol>::DKGDecentralizedParty;

#[derive(strum_macros::Display)]
pub(crate) enum DWalletDKGAdvanceRequestByCurve {
    #[strum(to_string = "dWallet DKG Advance Request for curve Secp256k1")]
    Secp256K1DWalletDKG(AdvanceRequest<<Secp256K1DWalletDKGParty as mpc::Party>::Message>),
    #[strum(to_string = "dWallet DKG Advance Request for curve Secp256r1")]
    Secp256R1DWalletDKG(AdvanceRequest<<Secp256R1DWalletDKGParty as mpc::Party>::Message>),
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
                let advance_request = try_ready_to_advance::<Secp256K1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::Secp256K1DWalletDKG)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request = try_ready_to_advance::<Secp256R1AsyncDKGProtocol>(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;
                advance_request.map(DWalletDKGAdvanceRequestByCurve::Secp256R1DWalletDKG)
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
pub enum DWalletDKGPublicInputByCurve {
    #[strum(to_string = "dWallet DKG Public Input for curve Secp256k1")]
    Secp256K1DWalletDKG(<Secp256K1DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Secp256r1")]
    Secp256R1DWalletDKG(<Secp256R1DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Curve25519")]
    Curve25519DWalletDKG(<Curve25519DWalletDKGParty as Party>::PublicInput),
    #[strum(to_string = "dWallet DKG Public Input for curve Ristretto")]
    RistrettoDWalletDKG(<RistrettoDWalletDKGParty as Party>::PublicInput),
}

impl DWalletDKGPublicInputByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
        session_id: CommitmentSizedNumber
    ) -> DwalletMPCResult<Self> {
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
                    session_id,
                    centralized_party_public_key_share,
                )
                    .into();

                DWalletDKGPublicInputByCurve::Secp256K1DWalletDKG(input)
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
                    session_id,
                    centralized_party_public_key_share,
                )
                    .into();

                DWalletDKGPublicInputByCurve::Secp256R1DWalletDKG(input)
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
                    session_id,
                    centralized_party_public_key_share,
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
                    session_id,
                    centralized_party_public_key_share,
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
    session_id: CommitmentSizedNumber
) -> DwalletMPCResult<<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput> {
    <Secp256K1DWalletDKGParty as DWalletDKGSecondPartyPublicInputGenerator>::generate_public_input(
        protocol_public_parameters,
        first_round_output,
        centralized_public_key_share_and_proof,
        session_id
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
        session_id: CommitmentSizedNumber
    ) -> DwalletMPCResult<<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput>;
}

impl DWalletDKGFirstPartyPublicInputGenerator for DWalletDKGFirstParty {
    fn generate_public_input(
        protocol_public_parameters: ProtocolPublicParameters,
    ) -> DwalletMPCResult<<DWalletDKGFirstParty as Party>::PublicInput> {
        let base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC DKG".to_string(),
            round: 1,
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
        session_id: CommitmentSizedNumber
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
                    session_id,
                    centralized_party_public_key_share,
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
        _ => Ok(None),
    }
}

pub fn compute_dwallet_dkg<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<P::DKGDecentralizedParty as Party>::Message>,
    protocol_public_parameters: P::ProtocolPublicParameters,
    public_input: <P::DKGDecentralizedParty as Party>::PublicInput,
    encryption_key: P::EncryptionKey,
    encrypted_secret_key_share_message: &[u8],
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let encrypted_secret_key_share_message: VersionedEncryptedUserShare =
        bcs::from_bytes(encrypted_secret_key_share_message).map_err(DwalletMPCError::BcsError)?;
    let encrypted_secret_key_share_message = match encrypted_secret_key_share_message {
        VersionedEncryptedUserShare::V1(message) => message,
    };
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
            let decentralized_output: P::DecentralizedPartyDKGOutput =
                bcs::from_bytes(&public_output_value)?;
            P::verify_encryption_of_centralized_party_share_proof(
                &protocol_public_parameters,
                decentralized_output.clone(),
                encryption_key,
                bcs::from_bytes(&encrypted_secret_key_share_message)?,
                &mut group::OsCsRng,
            )
            .map_err(|e| {
                DwalletMPCError::CentralizedSecretKeyShareProofVerificationFailed(e.to_string())
            })?;

            let public_output_value =
                bcs::to_bytes(&VersionedDwalletDKGSecondRoundPublicOutput::V2(
                    bcs::to_bytes(&decentralized_output)?,
                ))?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}
