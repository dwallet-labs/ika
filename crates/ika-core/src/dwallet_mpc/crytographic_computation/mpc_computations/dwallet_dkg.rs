// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module provides a wrapper around the DKG protocol from the 2PC-MPC library.
//!
//! It integrates both DKG parties (each representing a round in the DKG protocol).
use dwallet_mpc_types::dwallet_mpc::{
    SerializedWrappedMPCPublicOutput, VersionedCentralizedDKGPublicOutput,
    VersionedPublicKeyShareAndProof,
};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::AsyncECDSAProtocol;
use mpc::Party;
use twopc_mpc::dkg::Protocol;

pub(crate) type DWalletImportedKeyVerificationParty =
    <AsyncECDSAProtocol as Protocol>::TrustedDealerDKGDecentralizedParty;
/// This struct represents the final round of the DKG protocol.
pub(crate) type DWalletDKGSecondParty =
    <AsyncECDSAProtocol as Protocol>::ProofVerificationRoundParty;

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
                // todo: (this pr): create input

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
