// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_dkg::{
    BytesCentralizedPartyKeyShareVerification, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationPublicInputByCurve,
};
use crate::dwallet_mpc::crytographic_computation::mpc_computations::internal_checkpoint_centralized_dkg_emulation::emulate_centralized_party_partial_signature;
use crate::dwallet_mpc::network_dkg::{DwalletMPCNetworkKeys, network_dkg_v2_public_input};
use crate::dwallet_mpc::presign::PresignPublicInputByProtocol;

use crate::dwallet_mpc::reconfiguration::ReconfigurationPartyPublicInputGenerator;
use crate::dwallet_mpc::sign::{DKGAndSignPublicInputByProtocol, SignPublicInputByProtocol};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    EncryptedShareVerificationData, InternalPresignData, MakeDWalletUserSecretKeySharesPublicData,
    PartialSignatureVerificationData, PresignData, ProtocolData,
};
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    MPCPrivateInput, ReconfigurationParty, VersionedPresignOutput,
};
use group::PartyID;
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
    Presign(PresignPublicInputByProtocol),
    Sign(SignPublicInputByProtocol),
    NetworkEncryptionKeyDkg(
        <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicInput,
    ),
    EncryptedShareVerification(ProtocolPublicParametersByCurve),
    PartialSignatureVerification(ProtocolPublicParametersByCurve),
    NetworkEncryptionKeyReconfiguration(<ReconfigurationParty as mpc::Party>::PublicInput),
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
            Ok((
                PublicInput::NetworkEncryptionKeyDkg(network_dkg_v2_public_input(
                    access_structure,
                    validators_class_groups_public_keys_and_proofs,
                )?),
                Some(bcs::to_bytes(&class_groups_decryption_key)?),
            ))
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
            Ok((
                    PublicInput::NetworkEncryptionKeyReconfiguration(<ReconfigurationParty as ReconfigurationPartyPublicInputGenerator>::generate_public_input(
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
        }
        ProtocolData::InternalPresign {
            data:
                InternalPresignData {
                    signature_algorithm,
                    ..
                },
            dwallet_network_encryption_key_id,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            Ok((
                PublicInput::Presign(PresignPublicInputByProtocol::try_new(
                    *signature_algorithm,
                    encryption_key_public_data,
                    None,
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
        ProtocolData::InternalSign {
            data,
            dwallet_network_encryption_key_id,
            message,
            presign,
            ..
        } => {
            use crate::dwallet_mpc::crytographic_computation::mpc_computations::internal_checkpoint_centralized_dkg_emulation::InternalCheckpointDKGOutput;
            use crate::dwallet_mpc::sign::SignPublicInputByProtocol;

            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            // Get the stored internal checkpoint DKG output (contains both centralized and decentralized DKG).
            // This is pre-computed during network key construction.
            let (stored_curve, stored_algorithm, stored_dkg_output_bytes) =
                encryption_key_public_data
                    .internal_checkpoint_centralized_dkg_output()
                    .ok_or_else(|| {
                        DwalletMPCError::InternalError(
                            "Internal checkpoint DKG output not found in network key public data during internal sign".to_string(),
                        )
                    })?;

            // Verify the stored curve and algorithm match the requested ones
            if *stored_curve != data.curve || *stored_algorithm != data.signature_algorithm {
                return Err(DwalletMPCError::InternalError(format!(
                    "Internal checkpoint DKG was created for {:?}/{:?}, but signing requested {:?}/{:?}",
                    stored_curve, stored_algorithm, data.curve, data.signature_algorithm
                )));
            }

            // Deserialize the stored internal checkpoint DKG output.
            let internal_checkpoint_dkg_output: InternalCheckpointDKGOutput =
                bcs::from_bytes(stored_dkg_output_bytes).map_err(DwalletMPCError::BcsError)?;

            // Get the serialized protocol public parameters for the curve
            let protocol_pp_bytes = encryption_key_public_data
                .serialized_protocol_public_parameters_for_curve(data.curve)
                .map_err(DwalletMPCError::BcsError)?;

            // Extract the presign bytes from the versioned presign output
            let presign_bytes = match bcs::from_bytes::<VersionedPresignOutput>(presign)
                .map_err(DwalletMPCError::BcsError)?
            {
                VersionedPresignOutput::V1(bytes) | VersionedPresignOutput::V2(bytes) => bytes,
            };

            // Emulate the centralized party's partial signature using ZeroRng.
            // All validators will produce identical output.
            // NOTE: this is a cryptographic computation done outside of a Rayon context; it could be expensive.
            // Currently, we are using schnorr signatures for which it is cheap;
            // if in the future we should support other signature algorithms for internal sign, e.g. ECDSA, we would have to add an option to the Sign protocol to emulate the message internally, or compute it separately within a rayon context.
            let message_centralized_signature = emulate_centralized_party_partial_signature(
                data.signature_algorithm,
                &internal_checkpoint_dkg_output.centralized_dkg_result,
                message.clone(),
                data.hash_scheme,
                &presign_bytes,
                &protocol_pp_bytes,
            )?;

            // Use Sign protocol with the pre-computed decentralized DKG output.
            // The DKG was computed during network key construction.
            Ok((
                PublicInput::Sign(SignPublicInputByProtocol::try_new(
                    request.session_identifier,
                    &internal_checkpoint_dkg_output.decentralized_dkg_public_output,
                    message.clone(),
                    presign,
                    &message_centralized_signature,
                    data.hash_scheme,
                    access_structure,
                    encryption_key_public_data,
                    data.signature_algorithm,
                )?),
                None,
            ))
        }
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
