// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
    dwallet_dkg_first_public_input, dwallet_dkg_second_public_input,
};
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, network_dkg_public_input};
use crate::dwallet_mpc::presign::{PresignParty, presign_public_input};
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationPartyPublicInputGenerator, ReconfigurationSecp256k1Party,
};
use crate::dwallet_mpc::sign::{SignFirstParty, sign_session_public_input};
use class_groups::dkg;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, MPCPrivateInput, VersionedImportedDWalletPublicOutput,
};
use group::PartyID;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{DWalletMPCEvent, MPCRequestInput};
use mpc::WeightedThresholdAccessStructure;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PublicInput {
    DWalletImportedKeyVerificationRequest(
        <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
    ),
    DKGFirst(<DWalletDKGFirstParty as mpc::Party>::PublicInput),
    DKGSecond(<DWalletDKGSecondParty as mpc::Party>::PublicInput),
    Presign(<PresignParty as mpc::Party>::PublicInput),
    Sign(<SignFirstParty as mpc::Party>::PublicInput),
    NetworkEncryptionKeyDkg(<dkg::Secp256k1Party as mpc::Party>::PublicInput),
    EncryptedShareVerification(twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters),
    PartialSignatureVerification(twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters),
    NetworkEncryptionKeyReconfiguration(<ReconfigurationSecp256k1Party as mpc::Party>::PublicInput),
    MakeDWalletUserSecretKeySharesPublic(
        twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    ),
}

// TODO (#542): move this logic to run before writing the event to the DB, maybe include within the session info
/// Parses an [`Event`] to extract the corresponding [`MPCParty`],
/// public input, private input and session information.
///
/// Returns an error if the event type does not correspond to any known MPC rounds
/// or if deserialization fails.
pub(crate) fn session_input_from_event(
    event: DWalletMPCEvent,
    access_structure: &WeightedThresholdAccessStructure,
    committee: &Committee,
    network_keys: &DwalletMPCNetworkKeys,
    next_active_committee: Option<Committee>,
    validators_class_groups_public_keys_and_proofs: HashMap<
        PartyID,
        ClassGroupsEncryptionKeyAndProof,
    >,
) -> DwalletMPCResult<(PublicInput, MPCPrivateInput)> {
    let session_id = CommitmentSizedNumber::from_le_slice(
        event.session_request.session_identifier.to_vec().as_slice(),
    );
    match event.session_request.request_input {
        MPCRequestInput::DWalletImportedKeyVerificationRequest(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            let VersionedImportedDWalletPublicOutput::V1(centralized_party_message) =
                bcs::from_bytes(&event.event_data.centralized_party_message)?;

            let public_input = (
                protocol_public_parameters,
                session_id,
                bcs::from_bytes(&centralized_party_message)?,
            )
                .into();

            Ok((
                PublicInput::DWalletImportedKeyVerificationRequest(public_input),
                None,
            ))
        }
        MPCRequestInput::MakeDWalletUserSecretKeySharesPublicRequest(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::MakeDWalletUserSecretKeySharesPublic(protocol_public_parameters),
                None,
            ))
        }
        MPCRequestInput::NetworkEncryptionKeyDkg(_, _) => {
            let class_groups_decryption_key = network_keys
                .validator_private_dec_key_data
                .class_groups_decryption_key;

            Ok((
                PublicInput::NetworkEncryptionKeyDkg(network_dkg_public_input(
                    access_structure,
                    validators_class_groups_public_keys_and_proofs,
                    // Todo (#473): Support generic network key scheme
                    DWalletMPCNetworkKeyScheme::Secp256k1,
                )?),
                Some(bcs::to_bytes(&class_groups_decryption_key)?),
            ))
        }
        MPCRequestInput::NetworkEncryptionKeyReconfiguration(event) => {
            let class_groups_decryption_key = network_keys
                .validator_private_dec_key_data
                .class_groups_decryption_key;

            let next_active_committee = next_active_committee.ok_or(
                DwalletMPCError::MissingNextActiveCommittee(session_id.to_be_bytes().to_vec()),
            )?;

            Ok((
                    PublicInput::NetworkEncryptionKeyReconfiguration(<ReconfigurationSecp256k1Party as ReconfigurationPartyPublicInputGenerator>::generate_public_input(
                        committee,
                        next_active_committee,
                        network_keys.get_decryption_key_share_public_parameters(
                            &event
                                .event_data
                                .dwallet_network_encryption_key_id,
                        )?,
                        network_keys
                            .get_network_dkg_public_output(
                                &event
                                    .event_data
                                    .dwallet_network_encryption_key_id,
                            )?,
                    )?),
                    Some(bcs::to_bytes(
                        &class_groups_decryption_key
                    )?),
                ))
        }
        MPCRequestInput::DKGFirst(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme - take curve from event
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::DKGFirst(dwallet_dkg_first_public_input(&protocol_public_parameters)?),
                None,
            ))
        }
        MPCRequestInput::DKGSecond(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::DKGSecond(dwallet_dkg_second_public_input(
                    &event.event_data,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        MPCRequestInput::Presign(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::Presign(presign_public_input(
                    event.session_identifier_digest(),
                    event.event_data,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        MPCRequestInput::Sign(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::Sign(sign_session_public_input(
                    &event,
                    access_structure,
                    network_keys,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        MPCRequestInput::EncryptedShareVerification(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::EncryptedShareVerification(protocol_public_parameters),
                None,
            ))
        }
        MPCRequestInput::PartialSignatureVerification(event) => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                &event.event_data.dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::PartialSignatureVerification(protocol_public_parameters),
                None,
            ))
        }
    }
}
