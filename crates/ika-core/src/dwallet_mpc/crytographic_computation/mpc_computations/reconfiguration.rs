// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
};
use class_groups::reconfiguration::{PublicInput, Secp256k1Party};
use class_groups::{
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, Secp256k1DecryptionKeySharePublicParameters, dkg,
};
use dwallet_mpc_types::dwallet_mpc::{
    NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicData,
    SerializedWrappedMPCPublicOutput, V2NetworkKeyData,
    VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
};
use group::{GroupElement, PartyID, secp256k1};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::{Party, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use twopc_mpc::ProtocolPublicParameters;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};

pub(crate) type ReconfigurationSecp256k1Party = Secp256k1Party;
pub(crate) type ReconfigurationV1toV2Secp256k1Party = twopc_mpc::reconfiguration_v1_to_v2::Party;
pub(crate) type ReconfigurationV2Secp256k1Party = twopc_mpc::reconfiguration::Party;

pub(crate) trait ReconfigurationPartyPublicInputGenerator: Party {
    /// Generates the public input required for the reconfiguration protocol.
    fn generate_public_input(
        committee: &Committee,
        new_committee: Committee,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
        network_dkg_public_output: VersionedNetworkDkgOutput,
    ) -> DwalletMPCResult<<ReconfigurationSecp256k1Party as mpc::Party>::PublicInput>;
}

pub(crate) trait ReconfigurationV2PartyPublicInputGenerator: Party {
    /// Generates the public input required for the reconfiguration protocol.
    fn generate_public_input(
        committee: &Committee,
        new_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: VersionedDecryptionKeyReconfigurationOutput,
    ) -> DwalletMPCResult<<ReconfigurationV2Secp256k1Party as mpc::Party>::PublicInput>;
}

impl ReconfigurationV2PartyPublicInputGenerator for ReconfigurationV2Secp256k1Party {
    fn generate_public_input(
        current_committee: &Committee,
        upcoming_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: VersionedDecryptionKeyReconfigurationOutput,
    ) -> DwalletMPCResult<<ReconfigurationV2Secp256k1Party as mpc::Party>::PublicInput> {
        let VersionedNetworkDkgOutput::V1(network_dkg_public_output) = network_dkg_public_output;
        let VersionedDecryptionKeyReconfigurationOutput::V2(latest_reconfiguration_public_output) =
            latest_reconfiguration_public_output
        else {
            return Err(DwalletMPCError::InternalError(
                "Reconfiguration to V2 only supports reconfiguration public output of version V2"
                    .to_string(),
            ));
        };
        let current_committee = current_committee.clone();

        let current_access_structure =
            generate_access_structure_from_committee(&current_committee)?;
        let upcoming_access_structure =
            generate_access_structure_from_committee(&upcoming_committee)?;

        let current_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&current_committee)?;

        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&upcoming_committee)?;

        let public_input: <ReconfigurationV2Secp256k1Party as Party>::PublicInput =
            <twopc_mpc::reconfiguration::Party as mpc::Party>::PublicInput::new(
                &current_access_structure,
                upcoming_access_structure,
                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                current_tangible_party_id_to_upcoming(current_committee, upcoming_committee)
                    .clone(),
                bcs::from_bytes(&network_dkg_public_output)?,
                bcs::from_bytes(&latest_reconfiguration_public_output)?,
            )
            .map_err(DwalletMPCError::from)?;

        Ok(public_input)
    }
}

pub(crate) trait ReconfigurationV1ToV2PartyPublicInputGenerator: Party {
    /// Generates the public input required for the reconfiguration protocol.
    fn generate_public_input(
        committee: &Committee,
        new_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
    ) -> DwalletMPCResult<<ReconfigurationV1toV2Secp256k1Party as mpc::Party>::PublicInput>;
}

impl ReconfigurationV1ToV2PartyPublicInputGenerator for ReconfigurationV1toV2Secp256k1Party {
    fn generate_public_input(
        current_committee: &Committee,
        upcoming_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
    ) -> DwalletMPCResult<<ReconfigurationV1toV2Secp256k1Party as mpc::Party>::PublicInput> {
        let VersionedNetworkDkgOutput::V1(network_dkg_public_output) = network_dkg_public_output;
        let current_committee = current_committee.clone();

        let current_access_structure =
            generate_access_structure_from_committee(&current_committee)?;
        let upcoming_access_structure =
            generate_access_structure_from_committee(&upcoming_committee)?;

        let current_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&current_committee)?;

        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&upcoming_committee)?;

        let public_input: <ReconfigurationV1toV2Secp256k1Party as Party>::PublicInput =
            <ReconfigurationV1toV2Secp256k1Party as Party>::PublicInput::new(
                &current_access_structure,
                upcoming_access_structure,
                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                current_tangible_party_id_to_upcoming(current_committee, upcoming_committee)
                    .clone(),
                decryption_key_share_public_parameters,
                bcs::from_bytes(&network_dkg_public_output)?,
            )
            .map_err(DwalletMPCError::from)?;

        Ok(public_input)
    }
}

fn current_tangible_party_id_to_upcoming(
    current_committee: Committee,
    upcoming_committee: Committee,
) -> HashMap<PartyID, Option<PartyID>> {
    current_committee
        .voting_rights
        .iter()
        .map(|(name, _)| {
            // Todo (#972): Authority name can change, we need to use real const value for the committee - validator ID
            // Safe to unwrap because we know the name is in the current committee.
            let current_party_id =
                authority_name_to_party_id_from_committee(&current_committee, name).unwrap();

            let upcoming_party_id =
                authority_name_to_party_id_from_committee(&upcoming_committee, name).ok();

            (current_party_id, upcoming_party_id)
        })
        .collect()
}

impl ReconfigurationPartyPublicInputGenerator for ReconfigurationSecp256k1Party {
    fn generate_public_input(
        current_committee: &Committee,
        upcoming_committee: Committee,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
        network_dkg_public_output: VersionedNetworkDkgOutput,
    ) -> DwalletMPCResult<<ReconfigurationSecp256k1Party as mpc::Party>::PublicInput> {
        let VersionedNetworkDkgOutput::V1(network_dkg_public_output) = network_dkg_public_output;
        let current_committee = current_committee.clone();

        let current_access_structure =
            generate_access_structure_from_committee(&current_committee)?;
        let upcoming_access_structure =
            generate_access_structure_from_committee(&upcoming_committee)?;

        let plaintext_space_public_parameters = secp256k1::scalar::PublicParameters::default();

        let current_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&current_committee)?;

        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&upcoming_committee)?;

        let public_input: <ReconfigurationSecp256k1Party as Party>::PublicInput =
            PublicInput::new::<secp256k1::GroupElement>(
                &current_access_structure,
                upcoming_access_structure,
                plaintext_space_public_parameters.clone(),
                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                decryption_key_share_public_parameters,
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                current_tangible_party_id_to_upcoming(current_committee, upcoming_committee)
                    .clone(),
                bcs::from_bytes(&network_dkg_public_output)?,
            )
            .map_err(DwalletMPCError::from)?;

        Ok(public_input)
    }
}

fn extract_encryption_keys_from_committee(
    committee: &Committee,
) -> DwalletMPCResult<HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>> {
    committee
        .class_groups_public_keys_and_proofs
        .iter()
        .map(|(name, key)| {
            let party_id = authority_name_to_party_id_from_committee(committee, name)?;
            let key = key.clone();

            Ok((party_id, key))
        })
        .collect::<DwalletMPCResult<HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>>>()
}

pub(crate) fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output(
    epoch: u64,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
    network_dkg_public_output: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    match &mpc_public_output {
        VersionedDecryptionKeyReconfigurationOutput::V1(public_output_bytes) => {
            let public_output: <ReconfigurationSecp256k1Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;

            let decryption_key_share_public_parameters = public_output
                .default_decryption_key_share_public_parameters::<secp256k1::GroupElement>(
                    access_structure,
                )
                .map_err(DwalletMPCError::from)?;
            let encryption_scheme_public_parameters = decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .clone();

            let neutral_group_value =
                group::secp256k1::GroupElement::neutral_from_public_parameters(
                    &group::secp256k1::group_element::PublicParameters::default(),
                )
                .map_err(twopc_mpc::Error::from)?
                .value();
            let neutral_ciphertext_value =
                ::class_groups::CiphertextSpaceGroupElement::neutral_from_public_parameters(
                    encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                )
                .map_err(twopc_mpc::Error::from)?
                .value();

            let protocol_public_parameters = ProtocolPublicParameters::new::<
                { secp256k1::SCALAR_LIMBS },
                { FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >(
                neutral_group_value,
                neutral_group_value,
                neutral_ciphertext_value,
                neutral_ciphertext_value,
                decryption_key_share_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
            );

            Ok(NetworkEncryptionKeyPublicData {
                epoch,
                state: NetworkDecryptionKeyPublicOutputType::Reconfiguration,
                secp256k1_decryption_key_share_public_parameters:
                    decryption_key_share_public_parameters,
                secp256k1_protocol_public_parameters: protocol_public_parameters,
                network_dkg_output: bcs::from_bytes(network_dkg_public_output)?,
                latest_network_reconfiguration_public_output: Some(mpc_public_output),
                v2_data: None,
            })
        }
        VersionedDecryptionKeyReconfigurationOutput::V2(public_output_bytes) => {
            let public_output: <twopc_mpc::reconfiguration::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            let secp256k1_protocol_public_parameters =
                twopc_mpc::reconfiguration::PublicOutput::secp256k1_protocol_public_parameters(
                    &public_output,
                )
                .map_err(DwalletMPCError::from)?;
            let secp256r1_protocol_public_parameters =
                twopc_mpc::reconfiguration::PublicOutput::secp256r1_protocol_public_parameters(
                    &public_output,
                )
                .map_err(DwalletMPCError::from)?;
            let ristretto_protocol_public_parameters =
                twopc_mpc::reconfiguration::PublicOutput::ristretto_protocol_public_parameters(
                    &public_output,
                )
                .map_err(DwalletMPCError::from)?;
            let curve25519_protocol_public_parameters =
                twopc_mpc::reconfiguration::PublicOutput::curve25519_protocol_public_parameters(
                    &public_output,
                )
                .map_err(DwalletMPCError::from)?;
            let secp256k1_decryption_key_share_public_parameters = public_output
                .secp256k1_decryption_key_share_public_parameters(access_structure)
                .map_err(DwalletMPCError::from)?;
            let secp256r1_decryption_key_share_public_parameters = public_output
                .secp256r1_decryption_key_share_public_parameters(access_structure)
                .map_err(DwalletMPCError::from)?;
            let ristretto_decryption_key_share_public_parameters = public_output
                .ristretto_decryption_key_share_public_parameters(access_structure)
                .map_err(DwalletMPCError::from)?;
            let curve25519_decryption_key_share_public_parameters = public_output
                .curve25519_decryption_key_share_public_parameters(access_structure)
                .map_err(DwalletMPCError::from)?;

            Ok(NetworkEncryptionKeyPublicData {
                epoch,
                state: NetworkDecryptionKeyPublicOutputType::Reconfiguration,
                latest_network_reconfiguration_public_output: Some(mpc_public_output),
                secp256k1_decryption_key_share_public_parameters,
                secp256k1_protocol_public_parameters,
                network_dkg_output: bcs::from_bytes(network_dkg_public_output)?,
                v2_data: Some(V2NetworkKeyData {
                    secp256r1_decryption_key_share_public_parameters,
                    ristretto_decryption_key_share_public_parameters,
                    secp256r1_protocol_public_parameters,
                    ristretto_protocol_public_parameters,
                    curve25519_protocol_public_parameters,
                    curve25519_decryption_key_share_public_parameters,
                }),
            });
        }
    }
}
