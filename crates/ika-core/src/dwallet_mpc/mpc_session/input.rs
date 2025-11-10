// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_dkg::{
    BytesCentralizedPartyKeyShareVerification, DWalletDKGFirstParty, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationPublicInputByCurve, Secp256k1DWalletDKGParty,
    dwallet_dkg_first_public_input, dwallet_dkg_second_public_input,
};
use crate::dwallet_mpc::network_dkg::{
    DwalletMPCNetworkKeys, network_dkg_v1_public_input, network_dkg_v2_public_input,
};
use crate::dwallet_mpc::presign::PresignPublicInputByProtocol;
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationPartyPublicInputGenerator, ReconfigurationV1ToV2PartyPublicInputGenerator,
    ReconfigurationV1toV2Party, ReconfigurationV2PartyPublicInputGenerator,
};
use crate::dwallet_mpc::sign::{DKGAndSignPublicInputByProtocol, SignPublicInputByProtocol};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    EncryptedShareVerificationData, MakeDWalletUserSecretKeySharesPublicData,
    PartialSignatureVerificationData, PresignData, ProtocolData,
};
use class_groups::dkg;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    MPCPrivateInput, NetworkEncryptionKeyPublicDataTrait, ReconfigurationParty,
    ReconfigurationV2Party,
};
use group::PartyID;
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::WeightedThresholdAccessStructure;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PublicInput {
    DWalletImportedKeyVerificationRequest(DWalletImportedKeyVerificationPublicInputByCurve),
    DWalletDKG(DWalletDKGPublicInputByCurve),
    DWalletDKGAndSign(DKGAndSignPublicInputByProtocol),
    // Used only for V1 dWallets
    DKGFirst(<DWalletDKGFirstParty as mpc::Party>::PublicInput),
    // Used only for V1 dWallets
    Secp256k1DWalletDKG(<Secp256k1DWalletDKGParty as mpc::Party>::PublicInput),
    Presign(PresignPublicInputByProtocol),
    Sign(SignPublicInputByProtocol),
    NetworkEncryptionKeyDkgV1(<dkg::Secp256k1Party as mpc::Party>::PublicInput),
    NetworkEncryptionKeyDkgV2(
        <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicInput,
    ),
    EncryptedShareVerification(ProtocolPublicParametersByCurve),
    PartialSignatureVerification(ProtocolPublicParametersByCurve),
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyReconfigurationV1(<ReconfigurationParty as mpc::Party>::PublicInput),
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyReconfigurationV1ToV2(
        <ReconfigurationV1toV2Party as mpc::Party>::PublicInput,
    ),
    NetworkEncryptionKeyReconfigurationV2(<ReconfigurationV2Party as mpc::Party>::PublicInput),
    MakeDWalletUserSecretKeySharesPublic(ProtocolPublicParametersByCurve),
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
                    BytesCentralizedPartyKeyShareVerification::from(
                        data.user_secret_key_share.clone(),
                    ),
                )?),
                None,
            ))
        }
        ProtocolData::DWalletDKGAndSign {
            dwallet_network_encryption_key_id,
            data,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;
            let dwallet_dkg_public_input = DWalletDKGPublicInputByCurve::try_new(
                &data.curve,
                encryption_key_public_data,
                &data.centralized_public_key_share_and_proof,
                BytesCentralizedPartyKeyShareVerification::from(data.user_secret_key_share.clone()),
            )?;
            Ok((
                PublicInput::DWalletDKGAndSign(DKGAndSignPublicInputByProtocol::try_new(
                    request.session_identifier,
                    dwallet_dkg_public_input,
                    data.message.clone(),
                    &data.presign,
                    &data.message_centralized_signature,
                    data.hash_scheme,
                    access_structure,
                    encryption_key_public_data,
                    data.signature_algorithm,
                )?),
                None,
            ))
        }
        ProtocolData::ImportedKeyVerification {
            data,
            dwallet_network_encryption_key_id,
            centralized_party_message,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            let public_input = DWalletImportedKeyVerificationPublicInputByCurve::try_new(
                session_id,
                &data.curve,
                encryption_key_public_data,
                centralized_party_message,
                BytesCentralizedPartyKeyShareVerification::Encrypted {
                    encryption_key_value: data.encryption_key.clone(),
                    encrypted_secret_key_share_message: data
                        .encrypted_centralized_secret_share_and_proof
                        .clone(),
                },
            )?;

            Ok((
                PublicInput::DWalletImportedKeyVerificationRequest(public_input),
                None,
            ))
        }
        ProtocolData::MakeDWalletUserSecretKeySharesPublic {
            data: MakeDWalletUserSecretKeySharesPublicData { curve, .. },
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys
                .get_protocol_public_parameters(curve, dwallet_network_encryption_key_id)?
                .clone();

            Ok((
                PublicInput::MakeDWalletUserSecretKeySharesPublic(protocol_public_parameters),
                None,
            ))
        }
        ProtocolData::NetworkEncryptionKeyDkg { .. } => {
            let class_groups_decryption_key = network_keys
                .validator_private_dec_key_data
                .class_groups_decryption_key;
            if protocol_config.is_network_encryption_key_version_v2() {
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
            if (key_version == 1) && protocol_config.is_network_encryption_key_version_v2() {
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
            } else if protocol_config.is_network_encryption_key_version_v2() {
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
            let protocol_public_parameters = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?
                .secp256k1_protocol_public_parameters()
                .clone();

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
            let protocol_public_parameters = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?
                .secp256k1_protocol_public_parameters()
                .clone();

            Ok((
                PublicInput::Secp256k1DWalletDKG(dwallet_dkg_second_public_input(
                    first_round_output,
                    centralized_public_key_share_and_proof,
                    protocol_public_parameters,
                )?),
                None,
            ))
        }
        ProtocolData::Presign {
            data:
                PresignData {
                    signature_algorithm,
                    ..
                },
            dwallet_network_encryption_key_id,
            dwallet_public_output,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::Presign(PresignPublicInputByProtocol::try_new(
                    *signature_algorithm,
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
        } => Ok((
            PublicInput::Sign(SignPublicInputByProtocol::try_new(
                request.session_identifier,
                dwallet_decentralized_public_output,
                message.clone(),
                presign,
                message_centralized_signature,
                data.hash_scheme,
                access_structure,
                network_keys
                    .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?,
                data.signature_algorithm,
            )?),
            None,
        )),
        ProtocolData::EncryptedShareVerification {
            data: EncryptedShareVerificationData { curve, .. },
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys
                .get_protocol_public_parameters(curve, dwallet_network_encryption_key_id)?
                .clone();

            Ok((
                PublicInput::EncryptedShareVerification(protocol_public_parameters),
                None,
            ))
        }
        ProtocolData::PartialSignatureVerification {
            data: PartialSignatureVerificationData { curve, .. },
            dwallet_network_encryption_key_id,
            ..
        } => {
            let protocol_public_parameters = network_keys
                .get_protocol_public_parameters(curve, dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::PartialSignatureVerification(protocol_public_parameters),
                None,
            ))
        }
    }
}
