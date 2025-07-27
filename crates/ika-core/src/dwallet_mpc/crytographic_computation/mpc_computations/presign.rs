// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the Presign protocol from the 2PC-MPC library.
//!
//! It integrates both Presign parties (each representing a round in the Presign protocol).
use dwallet_mpc_types::dwallet_mpc::{
    SerializedWrappedMPCPublicOutput, VersionedDwalletDKGSecondRoundPublicOutput,
};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::dwallet_mpc_error::DwalletMPCResult;
use ika_types::messages_dwallet_mpc::{
    AsyncProtocol, DWalletSessionEvent, MPCRequestInput, MPCSessionRequest, PresignRequestEvent,
    SessionIdentifier,
};

pub(crate) type PresignParty = <AsyncProtocol as twopc_mpc::presign::Protocol>::PresignParty;

pub(crate) fn presign_public_input(
    session_identifier: SessionIdentifier,
    deserialized_event: PresignRequestEvent,
    protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
) -> DwalletMPCResult<<PresignParty as mpc::Party>::PublicInput> {
    <PresignParty as PresignPartyPublicInputGenerator>::generate_public_input(
        protocol_public_parameters,
        // TODO: IMPORTANT: for global presign for schnorr / eddsa signature where the presign is not per dWallet - change the code to support it.
        // The Presign Party Public Input would not take the `DKGOutput` as input in that case - probably the go-to would be to have it as an Option in the `Protocol` trait.
        deserialized_event.dwallet_public_output.clone().ok_or(
            DwalletMPCError::MPCSessionError {
                session_identifier,
                error: "presign public input cannot be None as we only support ECDSA".to_string(),
            },
        )?,
    )
}

pub(crate) fn presign_party_session_request(
    deserialized_event: DWalletSessionEvent<PresignRequestEvent>,
) -> MPCSessionRequest {
    MPCSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        epoch: deserialized_event.epoch,
        request_input: MPCRequestInput::Presign(deserialized_event),
        requires_network_key_data: true,
        requires_next_active_committee: false,
    }
}

/// A trait for generating the public input for the Presign protocol.
///
/// This trait is implemented to resolve compiler type ambiguities that arise in the 2PC-MPC library
/// when accessing `mpc::Party::PublicInput`.
pub(crate) trait PresignPartyPublicInputGenerator: mpc::Party {
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        dkg_output: SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<PresignParty as mpc::Party>::PublicInput>;
}

impl PresignPartyPublicInputGenerator for PresignParty {
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        dkg_output: SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<PresignParty as mpc::Party>::PublicInput> {
        let dkg_output = bcs::from_bytes(&dkg_output)?;
        match dkg_output {
            VersionedDwalletDKGSecondRoundPublicOutput::V1(output) => {
                let pub_input = Self::PublicInput {
                    protocol_public_parameters,
                    dkg_output: bcs::from_bytes(&output)?,
                };

                Ok(pub_input)
            }
        }
    }
}
