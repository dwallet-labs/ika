// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletSignatureScheme, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGSecondRoundPublicOutput, VersionedNetworkEncryptionKeyPublicData,
};
use dwallet_mpc_types::dwallet_mpc::{NetworkEncryptionKeyPublicDataTrait, VersionedPresignOutput};
use group::{CsRng, PartyID};
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    Curve25519EdDSAProtocol, RistrettoSchnorrkelSubstrateProtocol, Secp256K1ECDSAProtocol,
    Secp256K1TaprootProtocol, Secp256R1ECDSAProtocol, SessionIdentifier,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use twopc_mpc::presign;
use twopc_mpc::presign::Protocol;

pub(crate) type PresignParty<P: Protocol> = <P as Protocol>::PresignParty;

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub(crate) enum PresignPublicInputByProtocol {
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(<PresignParty<Secp256K1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: Taproot")]
    Taproot(<PresignParty<Secp256K1TaprootProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1ECDSA(<PresignParty<Secp256R1ECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Curve25519, protocol: EdDSA")]
    EdDSA(<PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    SchnorrkelSubstrate(
        <PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput,
    ),
}

#[derive(strum_macros::Display)]
pub(crate) enum PresignAdvanceRequestByProtocol {
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1ECDSA(AdvanceRequest<<PresignParty<Secp256K1ECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: Taproot")]
    Taproot(AdvanceRequest<<PresignParty<Secp256K1TaprootProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1ECDSA(AdvanceRequest<<PresignParty<Secp256R1ECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Curve25519, protocol: EdDSA")]
    EdDSA(AdvanceRequest<<PresignParty<Curve25519EdDSAProtocol> as mpc::Party>::Message>),
    #[strum(
        to_string = "Presign Advance Request - curve: Ristretto, protocol: SchnorrkelSubstrate"
    )]
    SchnorrkelSubstrate(
        AdvanceRequest<<PresignParty<RistrettoSchnorrkelSubstrateProtocol> as mpc::Party>::Message>,
    ),
}

impl PresignAdvanceRequestByProtocol {
    pub fn try_new(
        protocol: &DWalletSignatureScheme,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match protocol {
            DWalletSignatureScheme::ECDSASecp256k1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<PresignParty<Secp256K1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Secp256k1ECDSA)
            }
            DWalletSignatureScheme::Taproot => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Secp256K1TaprootProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Taproot)
            }
            DWalletSignatureScheme::SchnorrkelSubstrate => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<RistrettoSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::SchnorrkelSubstrate)
            }
            DWalletSignatureScheme::EdDSA => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Curve25519EdDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByProtocol::EdDSA)
            }
            DWalletSignatureScheme::ECDSASecp256r1 => {
                let advance_request =
                    mpc_computations::try_ready_to_advance::<PresignParty<Secp256R1ECDSAProtocol>>(
                        party_id,
                        access_structure,
                        consensus_round,
                        &serialized_messages_by_consensus_round,
                    )?;

                advance_request.map(PresignAdvanceRequestByProtocol::Secp256r1ECDSA)
            }
        };
        Ok(advance_request)
    }
}

impl PresignPublicInputByProtocol {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        protocol: DWalletSignatureScheme,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
        protocol_version: ProtocolVersion,
    ) -> DwalletMPCResult<Self> {
        let dkg_output = dwallet_public_output
            .clone()
            .ok_or(DwalletMPCError::MPCSessionError {
                session_identifier,
                error: "presign public input cannot be None as we only support ECDSA".to_string(),
            })?;

        match protocol_version.as_u64() {
            1 => Self::try_new_v1(
                session_identifier,
                versioned_network_encryption_key_public_data,
                dkg_output,
            ),
            _ => Self::try_new_v2(
                session_identifier,
                protocol,
                versioned_network_encryption_key_public_data,
                dkg_output,
            ),
        }
    }
    pub(crate) fn try_new_v1(
        session_identifier: SessionIdentifier,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<Self> {
        let VersionedDwalletDKGSecondRoundPublicOutput::V1(decentralized_dkg_output) =
            bcs::from_bytes(dwallet_public_output.as_slice())?
        else {
            return Err(DwalletMPCError::MPCSessionError {
                    session_identifier,
                    error: "presign public input v1 only supports VersionedDwalletDKGSecondRoundPublicOutput::V1".to_string(),
                });
        };

        let decentralized_party_targeted_dkg_output =
            bcs::from_bytes::<Secp256K1ECDSAProtocol::DecentralizedPartyTargetedDKGOutput>(
                decentralized_dkg_output.as_slice(),
            )?
            .into();
        let protocol_public_parameters =
            versioned_network_encryption_key_public_data.secp256k1_protocol_public_parameters();

        let public_input: <PresignParty<Secp256K1ECDSAProtocol> as mpc::Party>::PublicInput = (
            protocol_public_parameters,
            decentralized_party_targeted_dkg_output,
        )
            .into();
        Ok(PresignPublicInputByProtocol::Secp256k1ECDSA(public_input))
    }

    pub(crate) fn try_new_v2(
        session_identifier: SessionIdentifier,
        protocol: DWalletSignatureScheme,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<Self> {
        let input = match protocol {
            DWalletSignatureScheme::ECDSASecp256k1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256k1_protocol_public_parameters();
                PresignPublicInputByProtocol::Secp256k1ECDSA(generate_presign_public_input::<
                    Secp256K1ECDSAProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletSignatureScheme::SchnorrkelSubstrate => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .ristretto_protocol_public_parameters()?;
                PresignPublicInputByProtocol::SchnorrkelSubstrate(generate_presign_public_input::<
                    RistrettoSchnorrkelSubstrateProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletSignatureScheme::EdDSA => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .curve25519_protocol_public_parameters()?;
                PresignPublicInputByProtocol::EdDSA(generate_presign_public_input::<
                    Curve25519EdDSAProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletSignatureScheme::ECDSASecp256r1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256r1_protocol_public_parameters()?;
                PresignPublicInputByProtocol::Secp256r1ECDSA(generate_presign_public_input::<
                    Secp256R1ECDSAProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletSignatureScheme::Taproot => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256k1_protocol_public_parameters();
                PresignPublicInputByProtocol::Taproot(generate_presign_public_input::<
                    Secp256K1TaprootProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
        };

        Ok(input)
    }
}

fn generate_presign_public_input<P: Protocol>(
    session_identifier: SessionIdentifier,
    protocol_public_parameters: P::ProtocolPublicParameters,
    dwallet_public_output: SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<<PresignParty<P> as mpc::Party>::PublicInput> {
    let VersionedDwalletDKGSecondRoundPublicOutput::V2(dkg_output) =
        bcs::from_bytes(dwallet_public_output.as_slice())?
    else {
        return Err(DwalletMPCError::MPCSessionError {
                session_identifier,
                error: "presign public input v2 only supports VersionedDwalletDKGSecondRoundPublicOutput::V2".to_string(),
            });
    };
    let decentralized_dkg_output =
        bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(dkg_output.as_slice())?;

    let pub_input: <PresignParty<P> as mpc::Party>::PublicInput =
        (protocol_public_parameters, decentralized_dkg_output).into();

    Ok(pub_input)
}

pub fn compute_presign<P: Protocol>(
    party_id: PartyID,
    access_structure: &WeightedThresholdAccessStructure,
    session_id: CommitmentSizedNumber,
    advance_request: AdvanceRequest<<P::PresignParty as mpc::Party>::Message>,
    public_input: <P::PresignParty as mpc::Party>::PublicInput,
    rng: &mut impl CsRng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        mpc::guaranteed_output_delivery::Party::<P::PresignParty>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            None,
            &public_input,
            rng,
        )
        .map_err(|e| DwalletMPCError::FailedToAdvanceMPC(e.into()))?;

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
            let public_output_value =
                bcs::to_bytes(&VersionedPresignOutput::V1(public_output_value))?;
            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
    }
}
