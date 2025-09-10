// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).

use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkEncryptionKeyPublicDataTrait, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGFirstRoundPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedNetworkEncryptionKeyPublicData, VersionedPublicKeyShareAndProof,
};
use group::{CsRng, PartyID};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncProtocol, RistrettoAsyncProtocol, Secp256K1AsyncProtocol, Secp256R1AsyncProtocol,
};
use mpc::guaranteed_output_delivery::{AdvanceRequest, ReadyToAdvanceResult};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, Party,
    WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
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
    <RistrettoAsyncProtocol as Protocol>::DKGDecentralizedParty;

pub(crate) enum DWalletDKGAdvanceRequestByCurve {
    Secp256K1DWalletDKG(AdvanceRequest<<Secp256K1DWalletDKGParty as mpc::Party>::Message>),
    Secp256R1DWalletDKG(AdvanceRequest<<Secp256R1DWalletDKGParty as mpc::Party>::Message>),
    Curve25519DWalletDKG(AdvanceRequest<<Curve25519DWalletDKGParty as mpc::Party>::Message>),
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
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    Secp256K1DWalletDKGParty,
                >::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };
                DWalletDKGAdvanceRequestByCurve::Secp256K1DWalletDKG(advance_request)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    Secp256R1DWalletDKGParty,
                >::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };
                DWalletDKGAdvanceRequestByCurve::Secp256R1DWalletDKG(advance_request)
            }
            DWalletCurve::Curve25519 => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    Curve25519DWalletDKGParty,
                >::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };
                DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG(advance_request)
            }
            DWalletCurve::Ristretto => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    RistrettoDWalletDKGParty,
                >::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };
                DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG(advance_request)
            }
        };

        Ok(Some(advance_request))
    }

    pub fn compute_mpc(
        self,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        session_id: CommitmentSizedNumber,
        public_input: DWalletDKGPublicInputByCurve,
        encryption_key: &[u8],
        encrypted_secret_key_share_message: &[u8],
        rng: &mut impl CsRng,
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
        match self {
            DWalletDKGAdvanceRequestByCurve::Secp256K1DWalletDKG(advance_request) => {
                let DWalletDKGPublicInputByCurve::Secp256K1DWalletDKG(public_input) = public_input
                else {
                    return Err(DwalletMPCError::PublicInputMismatch);
                };
                let encryption_key = bcs::from_bytes(encryption_key)?;
                let encrypted_secret_key_share_message =
                    bcs::from_bytes(encrypted_secret_key_share_message)?;

                compute_dwallet_dkg::<Secp256K1AsyncProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input.protocol_public_parameters.clone(),
                    public_input,
                    encryption_key,
                    encrypted_secret_key_share_message,
                    rng,
                )
            }
            DWalletDKGAdvanceRequestByCurve::Secp256R1DWalletDKG(advance_request) => {
                let DWalletDKGPublicInputByCurve::Secp256R1DWalletDKG(public_input) = public_input
                else {
                    return Err(DwalletMPCError::PublicInputMismatch);
                };
                let encryption_key = bcs::from_bytes(encryption_key)?;
                let encrypted_secret_key_share_message =
                    bcs::from_bytes(encrypted_secret_key_share_message)?;

                compute_dwallet_dkg::<Secp256R1AsyncProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input.protocol_public_parameters.clone(),
                    public_input,
                    encryption_key,
                    encrypted_secret_key_share_message,
                    rng,
                )
            }
            DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG(advance_request) => {
                let DWalletDKGPublicInputByCurve::Curve25519DWalletDKG(public_input) = public_input
                else {
                    return Err(DwalletMPCError::PublicInputMismatch);
                };
                let encryption_key = bcs::from_bytes(encryption_key)?;
                let encrypted_secret_key_share_message =
                    bcs::from_bytes(encrypted_secret_key_share_message)?;

                compute_dwallet_dkg::<Curve25519AsyncProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input.protocol_public_parameters.clone(),
                    public_input,
                    encryption_key,
                    encrypted_secret_key_share_message,
                    rng,
                )
            }
            DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG(advance_request) => {
                let DWalletDKGPublicInputByCurve::RistrettoDWalletDKG(public_input) = public_input
                else {
                    return Err(DwalletMPCError::PublicInputMismatch);
                };
                let encryption_key = bcs::from_bytes(encryption_key)?;
                let encrypted_secret_key_share_message =
                    bcs::from_bytes(encrypted_secret_key_share_message)?;

                compute_dwallet_dkg::<RistrettoAsyncProtocol>(
                    party_id,
                    access_structure,
                    session_id,
                    advance_request,
                    public_input.protocol_public_parameters.clone(),
                    public_input,
                    encryption_key,
                    encrypted_secret_key_share_message,
                    rng,
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DWalletDKGPublicInputByCurve {
    Secp256K1DWalletDKG(<Secp256K1DWalletDKGParty as Party>::PublicInput),
    Secp256R1DWalletDKG(<Secp256R1DWalletDKGParty as Party>::PublicInput),
    Curve25519DWalletDKG(<Curve25519DWalletDKGParty as Party>::PublicInput),
    RistrettoDWalletDKG(<RistrettoDWalletDKGParty as Party>::PublicInput),
}

impl DWalletDKGPublicInputByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
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

pub fn compute_dwallet_dkg<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<P::DKGDecentralizedParty as Party>::Message>,
    protocol_public_parameters: P::ProtocolPublicParameters,
    public_input: <P::DKGDecentralizedParty as Party>::PublicInput,
    encryption_key: P::EncryptionKey,
    encrypted_secret_key_share_message: P::EncryptedSecretKeyShareMessage,
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
            let decentralized_output: P::DecentralizedPartyDKGOutput =
                bcs::from_bytes(&public_output_value)?;
            P::verify_encryption_of_centralized_party_share_proof(
                &protocol_public_parameters,
                decentralized_output.clone(),
                encryption_key,
                encrypted_secret_key_share_message,
                &mut group::OsCsRng,
            )
            .map_err(|e| {
                DwalletMPCError::CentralizedSecretKeyShareProofVerificationFailed(e.to_string())
            })?;

            // Convert the decentralized output to the proper format for serialization
            // For now, we serialize the decentralized output directly since the generic type
            // doesn't have a direct conversion to Output
            let dkg_output = decentralized_output;
            let public_output_value = bcs::to_bytes(
                &VersionedDwalletDKGSecondRoundPublicOutput::V2(bcs::to_bytes(&dkg_output)?),
            )?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}
