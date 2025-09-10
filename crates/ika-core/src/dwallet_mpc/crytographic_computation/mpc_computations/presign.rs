// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).

use std::collections::HashMap;
use commitment::CommitmentSizedNumber;
use group::{CsRng, PartyID};
use dwallet_mpc_types::dwallet_mpc::NetworkEncryptionKeyPublicDataTrait;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, SerializedWrappedMPCPublicOutput,
    VersionedDwalletDKGSecondRoundPublicOutput, VersionedNetworkEncryptionKeyPublicData,
};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{Curve25519AsyncProtocol, RistrettoAsyncProtocol, Secp256K1AsyncProtocol, Secp256R1AsyncProtocol, SessionIdentifier};
use mpc::guaranteed_output_delivery::{AdvanceRequest, ReadyToAdvanceResult};
use mpc::{GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure};
use twopc_mpc::presign::Protocol;
use crate::dwallet_mpc::dwallet_dkg::{DWalletDKGAdvanceRequestByCurve, DWalletDKGPublicInputByCurve, Secp256K1DWalletDKGParty};

pub(crate) type PresignParty<P: Protocol> = <P as Protocol>::PresignParty;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PresignPublicInputByCurve {
    Secp256k1(<PresignParty<Secp256K1AsyncProtocol> as mpc::Party>::PublicInput),
    Secp256r1(<PresignParty<Secp256R1AsyncProtocol> as mpc::Party>::PublicInput),
    Curve25519(<PresignParty<Curve25519AsyncProtocol> as mpc::Party>::PublicInput),
    Ristretto(<PresignParty<RistrettoAsyncProtocol> as mpc::Party>::PublicInput),
}

pub(crate) enum PresignAdvanceRequestByCurve {
    Secp256k1(AdvanceRequest<<PresignParty<Secp256K1AsyncProtocol> as mpc::Party>::Message>),
    Secp256r1(AdvanceRequest<<PresignParty<Secp256R1AsyncProtocol> as mpc::Party>::Message>),
    Curve25519(AdvanceRequest<<PresignParty<Curve25519AsyncProtocol> as mpc::Party>::Message>),
    Ristretto(AdvanceRequest<<PresignParty<RistrettoAsyncProtocol> as mpc::Party>::Message>),
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
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    PresignParty<Secp256K1AsyncProtocol>,
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
                PresignAdvanceRequestByCurve::Secp256k1(advance_request)
            }
            DWalletCurve::Ristretto => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    PresignParty<RistrettoAsyncProtocol>,
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
                PresignAdvanceRequestByCurve::Ristretto(advance_request)
            }
            DWalletCurve::Curve25519 => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    PresignParty<Curve25519AsyncProtocol>,
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
                PresignAdvanceRequestByCurve::Curve25519(advance_request)
            }
            DWalletCurve::Secp256r1 => {
                let advance_request_result = mpc::guaranteed_output_delivery::Party::<
                    PresignParty<Secp256R1AsyncProtocol>,
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
                PresignAdvanceRequestByCurve::Secp256r1(advance_request)
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
    ) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {}
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
                PresignPublicInputByCurve::Secp256k1(generate_presign_public_input::<Secp256K1AsyncProtocol>(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Ristretto => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .ristretto_protocol_public_parameters()?;
                PresignPublicInputByCurve::Ristretto(generate_presign_public_input::<RistrettoAsyncProtocol>(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Curve25519 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .curve25519_protocol_public_parameters()?;
                PresignPublicInputByCurve::Curve25519(generate_presign_public_input::<Curve25519AsyncProtocol>(
                    session_identifier,
                    protocol_public_parameters,
                    dwallet_public_output,
                )?)
            }
            DWalletCurve::Secp256r1 => {
                let protocol_public_parameters = versioned_network_encryption_key_public_data
                    .secp256r1_protocol_public_parameters()?;
                PresignPublicInputByCurve::Secp256r1(generate_presign_public_input::<Secp256R1AsyncProtocol>(
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
