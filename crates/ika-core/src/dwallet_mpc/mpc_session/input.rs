// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::dwallet_dkg::{
    BytesCentralizedPartyKeyShareVerification, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationPublicInputByCurve,
};
use crate::dwallet_mpc::network_dkg::{
    DwalletMPCNetworkKeys, network_dkg_bwd_compat_public_input, network_dkg_v2_public_input,
};
use crate::dwallet_mpc::presign::PresignPublicInputByProtocol;

use crate::dwallet_mpc::ValidatorMpcKeysByPartyId;
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationPartyPublicInputGenerator, reconfiguration_bwd_compat_public_input,
};
use crate::dwallet_mpc::sign::{DKGAndSignPublicInputByProtocol, SignPublicInputByProtocol};
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::request_protocol_data::{
    EncryptedShareVerificationData, InternalPresignData, MakeDWalletUserSecretKeySharesPublicData,
    PartialSignatureVerificationData, PresignData, ProtocolData,
};
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{MPCPrivateInput, ReconfigurationParty};
use ika_protocol_config::ProtocolConfig;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::WeightedThresholdAccessStructure;
use twopc_mpc::decentralized_party_backward_compatible::dkg as bwd_compat_dkg;
use twopc_mpc::decentralized_party_backward_compatible::reconfiguration as bwd_compat_reconfig;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PublicInput {
    DWalletImportedKeyVerificationRequest(DWalletImportedKeyVerificationPublicInputByCurve),
    DWalletDKG(DWalletDKGPublicInputByCurve),
    DWalletDKGAndSign(DKGAndSignPublicInputByProtocol),
    Presign(PresignPublicInputByProtocol),
    Sign(SignPublicInputByProtocol),
    /// Backward-compatible network DKG public input
    /// (`twopc_mpc::decentralized_party_backward_compatible::dkg::Party::PublicInput`).
    /// Selected when `ProtocolConfig::is_network_encryption_key_version_v3()` is
    /// `false` — peers may still publish bare `ClassGroupsEncryptionKeyAndProof`
    /// without PVSS HPKE keys.
    NetworkEncryptionKeyDkgBwdCompat(<bwd_compat_dkg::Party as mpc::Party>::PublicInput),
    /// Main network DKG public input
    /// (`twopc_mpc::decentralized_party::dkg::Party::PublicInput`). Selected when
    /// `ProtocolConfig::is_network_encryption_key_version_v3()` is `true`.
    NetworkEncryptionKeyDkg(
        <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicInput,
    ),
    EncryptedShareVerification(ProtocolPublicParametersByCurve),
    PartialSignatureVerification(ProtocolPublicParametersByCurve),
    /// Backward-compatible network Reconfiguration public input
    /// (`twopc_mpc::decentralized_party_backward_compatible::reconfiguration::Party::PublicInput`).
    /// Selected when `ProtocolConfig::is_reconfiguration_message_version_v3()` is
    /// `false`.
    NetworkEncryptionKeyReconfigurationBwdCompat(
        <bwd_compat_reconfig::Party as mpc::Party>::PublicInput,
    ),
    /// Main network Reconfiguration public input
    /// (`ReconfigurationParty::PublicInput`). Selected when
    /// `ProtocolConfig::is_reconfiguration_message_version_v3()` is `true`.
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
    validator_mpc_keys_by_party_id: ValidatorMpcKeysByPartyId,
    protocol_config: &ProtocolConfig,
) -> DwalletMPCResult<(PublicInput, MPCPrivateInput)> {
    let session_id =
        CommitmentSizedNumber::from_le_slice(request.session_identifier.to_vec().as_slice());

    // Defense-in-depth protocol-version gate for Fast Schnorr (VSS): the primary
    // enforcement is the on-chain supported-algorithm map population, but reject
    // any VSS presign/sign request here too if the active protocol version does
    // not enable it. (Move has no version gate; this is the Rust-side gate.)
    if let Some(signature_algorithm) = request.protocol_data.signature_algorithm()
        && signature_algorithm.is_vss()
        && !protocol_config.fast_schnorr_supported()
    {
        return Err(DwalletMPCError::InvalidInput(format!(
            "Fast Schnorr (VSS) algorithm {signature_algorithm} requested but \
             fast_schnorr_supported is disabled at this protocol version"
        )));
    }

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
            // Pick the network DKG public-input shape that matches the active
            // protocol_version. At `_version == 2` (mainnet-v1.1.8 era) peers
            // publish bare `ClassGroupsEncryptionKeyAndProof` and the
            // bwd-compat DKG `PublicInput::new` takes only the class-groups
            // CRT map. At `_version == 3` (post-PR-#1707) we have per-curve
            // PVSS HPKE keys too and call the main DKG `PublicInput::new`.
            let dkg_public_input = if protocol_config.is_network_encryption_key_version_v3() {
                // At `_version == 3` every committee member MUST publish the post-PR-#1707
                // bundle shape (class-groups + per-curve PVSS HPKE). The shape-tolerant
                // decoder accepts old-shape submissions silently, so a validator that
                // hasn't migrated would land here with empty PVSS entries while their
                // class-groups entry is present — fail loudly rather than running DKG
                // on a partial map.
                let expected = committee.voting_rights.len();
                let class_groups_count = validator_mpc_keys_by_party_id.class_groups.len();
                let secp256k1_pvss_count = validator_mpc_keys_by_party_id.secp256k1_pvss.len();
                let secp256r1_pvss_count = validator_mpc_keys_by_party_id.secp256r1_pvss.len();
                let ristretto_pvss_count = validator_mpc_keys_by_party_id.ristretto_pvss.len();
                if class_groups_count != expected
                    || secp256k1_pvss_count != expected
                    || secp256r1_pvss_count != expected
                    || ristretto_pvss_count != expected
                {
                    return Err(DwalletMPCError::InvalidMPCPartyType(format!(
                        "at network_encryption_key_version == 3 every committee member \
                         must publish the post-PR-#1707 bundle shape, but only \
                         {class_groups_count}/{expected} class-groups, \
                         {secp256k1_pvss_count}/{expected} secp256k1 PVSS, \
                         {secp256r1_pvss_count}/{expected} secp256r1 PVSS, \
                         {ristretto_pvss_count}/{expected} ristretto PVSS keys decoded",
                    )));
                }
                PublicInput::NetworkEncryptionKeyDkg(network_dkg_v2_public_input(
                    access_structure,
                    validator_mpc_keys_by_party_id.class_groups,
                    validator_mpc_keys_by_party_id.secp256k1_pvss,
                    validator_mpc_keys_by_party_id.secp256r1_pvss,
                    validator_mpc_keys_by_party_id.ristretto_pvss,
                )?)
            } else {
                PublicInput::NetworkEncryptionKeyDkgBwdCompat(network_dkg_bwd_compat_public_input(
                    access_structure,
                    validator_mpc_keys_by_party_id.class_groups,
                )?)
            };
            Ok((
                dkg_public_input,
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
            let network_dkg_public_output =
                network_keys.get_network_dkg_public_output(dwallet_network_encryption_key_id)?;
            let latest_reconfiguration_public_output =
                network_keys.get_last_reconfiguration_output(dwallet_network_encryption_key_id);

            let reconfig_public_input = if protocol_config.is_reconfiguration_message_version_v3() {
                PublicInput::NetworkEncryptionKeyReconfiguration(
                    <ReconfigurationParty as ReconfigurationPartyPublicInputGenerator>::generate_public_input(
                        committee,
                        next_active_committee,
                        network_dkg_public_output,
                        latest_reconfiguration_public_output,
                    )?,
                )
            } else {
                PublicInput::NetworkEncryptionKeyReconfigurationBwdCompat(
                    reconfiguration_bwd_compat_public_input(
                        committee,
                        next_active_committee,
                        network_dkg_public_output,
                        latest_reconfiguration_public_output,
                    )?,
                )
            };
            Ok((
                reconfig_public_input,
                Some(bcs::to_bytes(&class_groups_decryption_key)?),
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
                    &validator_mpc_keys_by_party_id,
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
                    &validator_mpc_keys_by_party_id,
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
        ProtocolData::NetworkOwnedAddressSign {
            data,
            dwallet_network_encryption_key_id,
            message,
            presign,
            ..
        } => {
            let encryption_key_public_data = network_keys
                .get_network_encryption_key_public_data(dwallet_network_encryption_key_id)?;

            // Pass an empty `message_centralized_signature` so `SignPublicInputByProtocol`
            // dispatches `SignData::ToBeEmulated` — the upstream sign protocol then emulates
            // the centralized party's partial signature inside its Rayon-scheduled advance.
            let stored_dkg_output_bytes =
                encryption_key_public_data.network_owned_address_dkg_output(data.curve);

            let stored_dkg_output_bytes = stored_dkg_output_bytes.to_vec();
            Ok((
                PublicInput::Sign(SignPublicInputByProtocol::try_new(
                    request.session_identifier,
                    &stored_dkg_output_bytes,
                    message.clone(),
                    presign,
                    &Vec::<u8>::new(),
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
