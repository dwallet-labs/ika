// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).
use crate::dwallet_mpc::session_request::{DWalletSessionRequest, ProtocolSpecificData};
use dwallet_mpc_types::dwallet_mpc::{
    SerializedWrappedMPCPublicOutput, VersionedCentralizedDKGPublicOutput,
    VersionedPublicKeyShareAndProof,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    AsyncProtocol, DWalletDKGFirstRoundRequestEvent, DWalletDKGSecondRoundRequestEvent,
    DWalletImportedKeyVerificationRequestEvent, DWalletSessionEvent, MPCRequestInput,
    MPCSessionRequest,
};
use mpc::Party;
use twopc_mpc::dkg::Protocol;

/// This struct represents the initial round of the DKG protocol.
pub type DWalletDKGFirstParty = <AsyncProtocol as Protocol>::EncryptionOfSecretKeyShareRoundParty;
pub(crate) type DWalletImportedKeyVerificationParty =
    <AsyncProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
/// This struct represents the final round of the DKG protocol.
pub(crate) type DWalletDKGSecondParty = <AsyncProtocol as Protocol>::ProofVerificationRoundParty;

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
) -> DwalletMPCResult<<DWalletDKGSecondParty as mpc::Party>::PublicInput> {
    <DWalletDKGSecondParty as DWalletDKGSecondPartyPublicInputGenerator>::generate_public_input(
        protocol_public_parameters,
        first_round_output,
        centralized_public_key_share_and_proof,
    )
}

pub(crate) fn dwallet_imported_key_verification_request_event_session_request(
    deserialized_event: DWalletSessionEvent<DWalletImportedKeyVerificationRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_specific_data: ProtocolSpecificData::try_new(
            MPCRequestInput::DWalletImportedKeyVerificationRequest(deserialized_event.clone()),
        )?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

pub(crate) fn dwallet_dkg_first_party_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGFirstRoundRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_specific_data: ProtocolSpecificData::try_new(MPCRequestInput::DKGFirst(
            deserialized_event.clone(),
        ))?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
}

pub(crate) fn dwallet_dkg_second_party_session_request(
    deserialized_event: DWalletSessionEvent<DWalletDKGSecondRoundRequestEvent>,
    pulled: bool,
) -> DwalletMPCResult<DWalletSessionRequest> {
    Ok(DWalletSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        protocol_specific_data: ProtocolSpecificData::try_new(MPCRequestInput::DKGSecond(
            deserialized_event.clone(),
        ))?,
        epoch: deserialized_event.epoch,
        requires_network_key_data: true,
        requires_next_active_committee: false,
        pulled,
    })
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
    ) -> DwalletMPCResult<<DWalletDKGSecondParty as mpc::Party>::PublicInput>;
}

impl DWalletDKGFirstPartyPublicInputGenerator for DWalletDKGFirstParty {
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    ) -> DwalletMPCResult<<DWalletDKGFirstParty as Party>::PublicInput> {
        let input: Self::PublicInput = protocol_public_parameters;
        Ok(input)
    }
}

impl DWalletDKGSecondPartyPublicInputGenerator for DWalletDKGSecondParty {
    fn generate_public_input(
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
        first_round_output_buf: &SerializedWrappedMPCPublicOutput,
        centralized_party_public_key_share_buf: &SerializedWrappedMPCPublicOutput,
    ) -> DwalletMPCResult<<DWalletDKGSecondParty as mpc::Party>::PublicInput> {
        let first_round_output_buf: VersionedCentralizedDKGPublicOutput =
            bcs::from_bytes(first_round_output_buf).map_err(DwalletMPCError::BcsError)?;

        let centralized_party_public_key_share: VersionedPublicKeyShareAndProof =
            bcs::from_bytes(centralized_party_public_key_share_buf)
                .map_err(DwalletMPCError::BcsError)?;

        match first_round_output_buf {
            VersionedCentralizedDKGPublicOutput::V1(first_round_output) => {
                let first_round_output: <DWalletDKGFirstParty as Party>::PublicOutput =
                    bcs::from_bytes(&first_round_output).map_err(DwalletMPCError::BcsError)?;

                let centralized_party_public_key_share = match centralized_party_public_key_share {
                    VersionedPublicKeyShareAndProof::V1(centralized_party_public_key_share) => {
                        bcs::from_bytes(&centralized_party_public_key_share)
                            .map_err(DwalletMPCError::BcsError)?
                    }
                };

                let input: Self::PublicInput = (
                    protocol_public_parameters,
                    first_round_output,
                    centralized_party_public_key_share,
                )
                    .into();

                Ok(input)
            }
        }
    }
}
