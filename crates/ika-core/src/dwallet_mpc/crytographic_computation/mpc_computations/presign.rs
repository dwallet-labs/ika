// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).

use crate::dwallet_mpc::crytographic_computation::mpc_computations;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, SerializedWrappedMPCPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
    VersionedNetworkEncryptionKeyPublicData,
};
use dwallet_mpc_types::dwallet_mpc::{NetworkEncryptionKeyPublicDataTrait, VersionedPresignOutput};
use group::{CsRng, PartyID};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    Curve25519AsyncEdDSAProtocol, RistrettoAsyncSchnorrkelSubstrateProtocol,
    Secp256K1AsyncECDSAProtocol, Secp256R1AsyncECDSAProtocol, SessionIdentifier,
};
use mpc::guaranteed_output_delivery::AdvanceRequest;
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use std::collections::HashMap;
use twopc_mpc::presign::Protocol;

pub(crate) type PresignParty<P: Protocol> = <P as Protocol>::PresignParty;

#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub(crate) enum PresignPublicInputByCurve {
    #[strum(to_string = "Presign Public Input - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1(<PresignParty<Secp256K1AsyncECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(<PresignParty<Secp256R1AsyncECDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Curve25519, protocol: EdDSA")]
    Curve25519(<PresignParty<Curve25519AsyncEdDSAProtocol> as mpc::Party>::PublicInput),
    #[strum(to_string = "Presign Public Input - curve: Ristretto, protocol: SchnorrkelSubstrate")]
    Ristretto(<PresignParty<RistrettoAsyncSchnorrkelSubstrateProtocol> as mpc::Party>::PublicInput),
}

#[derive(strum_macros::Display)]
pub(crate) enum PresignAdvanceRequestByCurve {
    #[strum(to_string = "Presign Advance Request - curve: Secp256k1, protocol: ECDSA")]
    Secp256k1(AdvanceRequest<<PresignParty<Secp256K1AsyncECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Secp256r1, protocol: ECDSA")]
    Secp256r1(AdvanceRequest<<PresignParty<Secp256R1AsyncECDSAProtocol> as mpc::Party>::Message>),
    #[strum(to_string = "Presign Advance Request - curve: Curve25519, protocol: EdDSA")]
    Curve25519(AdvanceRequest<<PresignParty<Curve25519AsyncEdDSAProtocol> as mpc::Party>::Message>),
    #[strum(
        to_string = "Presign Advance Request - curve: Ristretto, protocol: Schnorrkel Substrate"
    )]
    Ristretto(
        AdvanceRequest<
            <PresignParty<RistrettoAsyncSchnorrkelSubstrateProtocol> as mpc::Party>::Message,
        >,
    ),
}

impl PresignAdvanceRequestByCurve {
    pub fn try_new(
        curve: &DWalletCurve,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> DwalletMPCResult<Option<Self>> {
        let advance_request = match curve {
            DWalletCurve::Secp256k1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Secp256K1AsyncECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByCurve::Secp256k1)
            }
            DWalletCurve::Ristretto => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<RistrettoAsyncSchnorrkelSubstrateProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByCurve::Ristretto)
            }
            DWalletCurve::Curve25519 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Curve25519AsyncEdDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByCurve::Curve25519)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request = mpc_computations::try_ready_to_advance::<
                    PresignParty<Secp256R1AsyncECDSAProtocol>,
                >(
                    party_id,
                    access_structure,
                    consensus_round,
                    &serialized_messages_by_consensus_round,
                )?;

                advance_request.map(PresignAdvanceRequestByCurve::Secp256r1)
            }
        };

        Ok(advance_request)
    }
}

impl PresignPublicInputByCurve {
    pub(crate) fn try_new(
        session_identifier: SessionIdentifier,
        curve: DWalletCurve,
        versioned_network_encryption_key_public_data: &VersionedNetworkEncryptionKeyPublicData,
        dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
    ) -> DwalletMPCResult<Self> {
        let input = match curve {
            DWalletCurve::Secp256k1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256k1_protocol_public_parameters();
                PresignPublicInputByCurve::Secp256k1(generate_presign_public_input::<
                    Secp256K1AsyncECDSAProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Ristretto => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .ristretto_protocol_public_parameters()?;
                PresignPublicInputByCurve::Ristretto(generate_presign_public_input::<
                    RistrettoAsyncSchnorrkelSubstrateProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Curve25519 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .curve25519_protocol_public_parameters()?;
                PresignPublicInputByCurve::Curve25519(generate_presign_public_input::<
                    Curve25519AsyncEdDSAProtocol,
                >(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Secp256r1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256r1_protocol_public_parameters()?;
                PresignPublicInputByCurve::Secp256r1(generate_presign_public_input::<
                    Secp256R1AsyncECDSAProtocol,
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
    dwallet_public_output: Option<SerializedWrappedMPCPublicOutput>,
) -> DwalletMPCResult<<PresignParty<P> as mpc::Party>::PublicInput> {
    let dkg_output = dwallet_public_output
        .clone()
        .ok_or(DwalletMPCError::MPCSessionError {
            session_identifier,
            error: "presign public input cannot be None as we only support ECDSA".to_string(),
        })?;
    let dkg_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(dkg_output.as_slice())?;

    let decentralized_dkg_output = match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
            // Todo (yael): Check if we can remove the V1 V2 distinction
            bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(output.as_slice())?
        }
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => {
            bcs::from_bytes::<P::DecentralizedPartyDKGOutput>(output.as_slice())?
        }
    };
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
