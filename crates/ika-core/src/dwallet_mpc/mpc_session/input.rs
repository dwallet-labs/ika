// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::dwallet_dkg::{
    dwallet_dkg_first_public_input, dwallet_dkg_second_public_input,
    DWalletDKGFirstParty, DWalletDKGPublicInputByCurve
    , DWalletImportedKeyVerificationParty, Secp256K1DWalletDKGParty,
};
use crate::dwallet_mpc::network_dkg::{
    network_dkg_v1_public_input, network_dkg_v2_public_input, DwalletMPCNetworkKeys,
};
use crate::dwallet_mpc::presign::PresignPublicInputByCurve;
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationParty, ReconfigurationPartyPublicInputGenerator,
    ReconfigurationV1ToV2PartyPublicInputGenerator, ReconfigurationV1toV2Party,
    ReconfigurationV2Party, ReconfigurationV2PartyPublicInputGenerator,
};
use crate::dwallet_mpc::sign::{sign_session_public_input, SignParty};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{PresignData, ProtocolData};
use class_groups::dkg;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{MPCPrivateInput, VersionedImportedDWalletPublicOutput};
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::WeightedThresholdAccessStructure;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PublicInput {
    DWalletImportedKeyVerificationRequest(
        <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
    ),
    DWalletDKG(DWalletDKGPublicInputByCurve),
    // Used only for V1 dWallets
    DKGFirst(<DWalletDKGFirstParty as mpc::Party>::PublicInput),
    // Used only for V1 dWallets
    Secp256K1DWalletDKG(<Secp256K1DWalletDKGParty as mpc::Party>::PublicInput),
    Presign(PresignPublicInputByCurve),
    Sign(<SignParty as mpc::Party>::PublicInput),
    NetworkEncryptionKeyDkgV1(<dkg::Secp256k1Party as mpc::Party>::PublicInput),
    NetworkEncryptionKeyDkgV2(
        <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicInput,
    ),
    EncryptedShareVerification(twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters),
    PartialSignatureVerification(twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters),
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyReconfigurationV1(<ReconfigurationParty as mpc::Party>::PublicInput),
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyReconfigurationV1ToV2(
        <ReconfigurationV1toV2Party as mpc::Party>::PublicInput,
    ),
    NetworkEncryptionKeyReconfigurationV2(<ReconfigurationV2Party as mpc::Party>::PublicInput),
    MakeDWalletUserSecretKeySharesPublic(
        twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    ),
}

// TODO (#542): move this logic to run before writing the event to the DB, maybe include within the session info
/// Parses a [`DWalletSessionRequest`] to extract the corresponding [`MPCParty`],
/// public input, private input and session information.
///
/// Returns an error if the event type does not correspond to any known MPC rounds
/// or if deserialization fails.
pub(crate) fn session_input_from_request(
    request: &DWalletSessionRequest,
    access_structure: &WeightedThresholdAccessStructure,
    committee: &Committee,
    network_keys: &DwalletMPCNetworkKeys,
    next_active_committee: Option<Committee>,
    validators_class_groups_public_keys_and_proofs: HashMap<
        PartyID,
        ClassGroupsEncryptionKeyAndProof,
    >,
    protocol_config: &ProtocolConfig,
) -> DwalletMPCResult<(PublicInput, MPCPrivateInput)> {
    let session_id =
        CommitmentSizedNumber::from_le_slice(request.session_identifier.to_vec().as_slice());
    match &request.protocol_data {
        ProtocolData::DWalletDKG {
            dwallet_network_encryption_key_id,
            data,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::DWalletDKG(DWalletDKGPublicInputByCurve::try_new(
                    &data.curve,
                    encryption_key_public_data,
                    &data.centralized_public_key_share_and_proof,
                )?),
                None,
            ))
        }
        ProtocolData::ImportedKeyVerification {
            dwallet_network_encryption_key_id,
            centralized_party_message,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The request is assign with a Secp256k1 dWallet.
                // Todo (#473): Support generic network key scheme
                dwallet_network_encryption_key_id,
            )?;

            let VersionedImportedDWalletPublicOutput::V1(centralized_party_message) =
                bcs::from_bytes(&centralized_party_message)?;

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
        ProtocolData::MakeDWalletUserSecretKeySharesPublic {
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters =
                network_keys.get_protocol_public_parameters(dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::MakeDWalletUserSecretKeySharesPublic(protocol_public_parameters),
                None,
            ))
        }
        ProtocolData::NetworkEncryptionKeyDkg { .. } => {
            let class_groups_decryption_key = network_keys
                .validator_private_dec_key_data
                .class_groups_decryption_key;
            if protocol_config.network_encryption_key_version == Some(2) {
                Ok((
                    PublicInput::NetworkEncryptionKeyDkgV2(network_dkg_v2_public_input(
                        access_structure,
                        validators_class_groups_public_keys_and_proofs,
                    )?),
                    Some(bcs::to_bytes(&class_groups_decryption_key)?),
                ))
            } else {
                Ok((
                    PublicInput::NetworkEncryptionKeyDkgV1(network_dkg_v1_public_input(
                        access_structure,
                        validators_class_groups_public_keys_and_proofs,
                    )?),
                    Some(bcs::to_bytes(&class_groups_decryption_key)?),
                ))
            }
        }
        ProtocolData::NetworkEncryptionKeyReconfiguration {
            dwallet_network_encryption_key_id,
            ..
        } => {
            let class_groups_decryption_key = network_keys
                .validator_private_dec_key_data
                .class_groups_decryption_key;

            let next_active_committee = next_active_committee.ok_or(
                DwalletMPCError::MissingNextActiveCommittee(session_id.to_be_bytes().to_vec()),
            )?;
            let key_version =
                network_keys.get_network_key_version(dwallet_network_encryption_key_id)?;
            if (key_version == 1) && protocol_config.network_encryption_key_version == Some(2) {
                Ok((
                    PublicInput::NetworkEncryptionKeyReconfigurationV1ToV2(<ReconfigurationV1toV2Party as ReconfigurationV1ToV2PartyPublicInputGenerator>::generate_public_input(
                        committee,
                        next_active_committee,
                        network_keys
                            .get_network_dkg_public_output(
                                dwallet_network_encryption_key_id,
                            )?,
                        network_keys
                            .get_decryption_key_share_public_parameters(
                                dwallet_network_encryption_key_id,
                            )?,
                    )?),
                    Some(bcs::to_bytes(
                        &class_groups_decryption_key
                    )?),
                ))
            } else if protocol_config.network_encryption_key_version == Some(2) {
                Ok((
                    PublicInput::NetworkEncryptionKeyReconfigurationV2(<ReconfigurationV2Party as ReconfigurationV2PartyPublicInputGenerator>::generate_public_input(
                        committee,
                        next_active_committee,
                        network_keys
                            .get_network_dkg_public_output(
                                dwallet_network_encryption_key_id,
                            )?,
                        network_keys
                            .get_last_reconfiguration_output(
                                dwallet_network_encryption_key_id,
                            ),
                    )?),
                    Some(bcs::to_bytes(
                        &class_groups_decryption_key
                    )?),
                ))
            } else {
                Ok((
                    PublicInput::NetworkEncryptionKeyReconfigurationV1(<ReconfigurationParty as ReconfigurationPartyPublicInputGenerator>::generate_public_input(
                        committee,
                        next_active_committee,
                        network_keys.get_decryption_key_share_public_parameters(
                            dwallet_network_encryption_key_id,
                        )?,
                        network_keys
                            .get_network_dkg_public_output(
                                dwallet_network_encryption_key_id,
                            )?,
                    )?),
                    Some(bcs::to_bytes(
                        &class_groups_decryption_key
                    )?),
                ))
            }
        }
        ProtocolData::DKGFirst {
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme - take curve from event
                dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::DKGFirst(dwallet_dkg_first_public_input(&protocol_public_parameters)?),
                None,
            ))
        }
        ProtocolData::DKGSecond {
            dwallet_network_encryption_key_id,
            first_round_output,
            centralized_public_key_share_and_proof,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::Secp256K1DWalletDKG(dwallet_dkg_second_public_input(
                    first_round_output,
                    centralized_public_key_share_and_proof,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        ProtocolData::Presign {
            data: PresignData { curve, .. },
            dwallet_network_encryption_key_id,
            dwallet_public_output,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::Presign(PresignPublicInputByCurve::try_new(
                    request.session_identifier,
                    curve.clone(),
                    encryption_key_public_data,
                    dwallet_public_output.clone(),
                )?),
                None,
            ))
        }
        ProtocolData::Sign {
            data,
            dwallet_network_encryption_key_id,
            dwallet_decentralized_public_output,
            message,
            presign,
            message_centralized_signature,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::Sign(sign_session_public_input(
                    dwallet_network_encryption_key_id,
                    request.session_identifier,
                    dwallet_decentralized_public_output,
                    message.clone(),
                    presign,
                    message_centralized_signature,
                    data.hash_scheme.clone(),
                    access_structure,
                    network_keys,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        ProtocolData::EncryptedShareVerification {
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::EncryptedShareVerification(protocol_public_parameters),
                None,
            ))
        }
        ProtocolData::PartialSignatureVerification {
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys.get_protocol_public_parameters(
                // The event is assign with a Secp256k1 dwallet.
                // Todo (#473): Support generic network key scheme
                dwallet_network_encryption_key_id,
            )?;

            Ok((
                PublicInput::PartialSignatureVerification(protocol_public_parameters),
                None,
            ))
        }
    }
}
