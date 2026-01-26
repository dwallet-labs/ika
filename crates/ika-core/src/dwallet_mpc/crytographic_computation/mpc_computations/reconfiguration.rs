// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::debug_variable_chunks;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::internal_checkpoint_dkg_emulation::compute_internal_checkpoint_dkg_output;
use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
};
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, DWalletSignatureAlgorithm, NetworkDecryptionKeyPublicOutputType,
    NetworkEncryptionKeyPublicData, ReconfigurationParty, SerializedWrappedMPCPublicOutput,
    VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
};
use group::PartyID;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::{Party, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use tracing::error;

pub(crate) trait ReconfigurationPartyPublicInputGenerator: Party {
    /// Generates the public input required for the reconfiguration protocol.
    fn generate_public_input(
        committee: &Committee,
        new_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: Option<VersionedDecryptionKeyReconfigurationOutput>,
    ) -> DwalletMPCResult<<ReconfigurationParty as mpc::Party>::PublicInput>;
}

impl ReconfigurationPartyPublicInputGenerator for ReconfigurationParty {
    fn generate_public_input(
        current_committee: &Committee,
        upcoming_committee: Committee,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: Option<VersionedDecryptionKeyReconfigurationOutput>,
    ) -> DwalletMPCResult<<ReconfigurationParty as Party>::PublicInput> {
        let current_committee = current_committee.clone();
        let current_access_structure =
            generate_access_structure_from_committee(&current_committee)?;
        let upcoming_access_structure =
            generate_access_structure_from_committee(&upcoming_committee)?;

        let current_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&current_committee)?;

        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            extract_encryption_keys_from_committee(&upcoming_committee)?;

        let current_tangible_party_id_to_upcoming =
            current_tangible_party_id_to_upcoming(current_committee, upcoming_committee);

        if let Ok(current_access_structure_bcs) = bcs::to_bytes(&current_access_structure) {
            debug!(
                current_access_structure=?current_access_structure,
                current_access_structure_bcs=%hex::encode(&current_access_structure_bcs),
                "Instantiating public input for reconfiguration v2 [current_access_structure]"
            );
        }

        if let Ok(upcoming_access_structure_bcs) = bcs::to_bytes(&upcoming_access_structure) {
            debug!(
                upcoming_access_structure=?upcoming_access_structure,
                upcoming_access_structure_bcs=%hex::encode(&upcoming_access_structure_bcs),
                "Instantiating public input for reconfiguration v2 [upcoming_access_structure]"
            );
        }

        if let Ok(current_tangible_party_id_to_upcoming_bcs) =
            bcs::to_bytes(&current_tangible_party_id_to_upcoming)
        {
            debug!(
                current_tangible_party_id_to_upcoming=?current_tangible_party_id_to_upcoming,
                current_tangible_party_id_to_upcoming_bcs=%hex::encode(&current_tangible_party_id_to_upcoming_bcs),
                "Instantiating public input for reconfiguration v2 [current_tangible_party_id_to_upcoming]"
            );
        }

        if let Ok(current_encryption_keys_per_crt_prime_and_proofs_bcs) =
            bcs::to_bytes(&current_encryption_keys_per_crt_prime_and_proofs)
        {
            debug_variable_chunks(
                "Instantiating public input for reconfiguration v2 [current_encryption_keys_per_crt_prime_and_proofs]",
                "current_encryption_keys_per_crt_prime_and_proofs",
                &current_encryption_keys_per_crt_prime_and_proofs_bcs,
            );
        }

        if let Ok(upcoming_encryption_keys_per_crt_prime_and_proofs_bcs) =
            bcs::to_bytes(&upcoming_encryption_keys_per_crt_prime_and_proofs)
        {
            debug_variable_chunks(
                "Instantiating public input for reconfiguration v2 [upcoming_encryption_keys_per_crt_prime_and_proofs]",
                "upcoming_encryption_keys_per_crt_prime_and_proofs",
                &upcoming_encryption_keys_per_crt_prime_and_proofs_bcs,
            );
        }

        match network_dkg_public_output {
            VersionedNetworkDkgOutput::V1(network_dkg_public_output) => {
                match latest_reconfiguration_public_output {
                    None => {
                        Err(DwalletMPCError::InternalError(
                            "The Reconfiguration v2 protocol can only be executed after a v1-to-v2 protocol, or after another reconfiguration v2 protocol."
                                .to_string(),
                        ))
                    }
                    Some(latest_reconfiguration_public_output) => {
                        let VersionedDecryptionKeyReconfigurationOutput::V2(
                            latest_reconfiguration_public_output,
                        ) = latest_reconfiguration_public_output
                        else {
                            return Err(DwalletMPCError::InternalError(
                                "The Reconfiguration v2 protocol can only be executed after a v1-to-v2 protocol, or after another reconfiguration v2 protocol."
                                    .to_string(),
                            ));
                        };

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v2 [network_dkg_public_output (v1)]",
                            "network_dkg_public_output",
                            &network_dkg_public_output
                        );

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v2 [latest_reconfiguration_public_output]",
                            "latest_reconfiguration_public_output",
                            &latest_reconfiguration_public_output
                        );


                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_reconfiguration_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                bcs::from_bytes(&network_dkg_public_output)?,
                                bcs::from_bytes(&latest_reconfiguration_public_output)?,
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                }
            }
            VersionedNetworkDkgOutput::V2(network_dkg_public_output) => {
                match latest_reconfiguration_public_output {
                    None => {
                        let public_output: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                            bcs::from_bytes(&network_dkg_public_output)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v2 [network_dkg_public_output (v2)]",
                            "network_dkg_public_output",
                            &network_dkg_public_output
                        );

                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_dkg_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                public_output,
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                    Some(latest_reconfiguration_public_output) => {
                        let VersionedDecryptionKeyReconfigurationOutput::V2(
                            latest_reconfiguration_public_output,
                        ) = latest_reconfiguration_public_output
                        else {
                            return Err(DwalletMPCError::InternalError(
                                "The Reconfiguration v2 protocol can only be executed after a v1-to-v2 protocol, or after another reconfiguration v2 protocol."
                                    .to_string(),
                            ));
                        };

                        let public_output: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                            bcs::from_bytes(&network_dkg_public_output)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v2 [network_dkg_public_output (v2)]",
                            "network_dkg_public_output",
                            &network_dkg_public_output
                        );

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v2 [latest_reconfiguration_public_output]",
                            "latest_reconfiguration_public_output",
                            &latest_reconfiguration_public_output
                        );

                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_reconfiguration_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                public_output.into(),
                                bcs::from_bytes(&latest_reconfiguration_public_output)?,
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                }
            }
        }
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
    dkg_at_epoch: u64,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
    network_dkg_public_output: &SerializedWrappedMPCPublicOutput,
    network_key_id: [u8; 32],
    checkpoint_signing_curve: DWalletCurve,
    checkpoint_signing_algorithm: DWalletSignatureAlgorithm,
    party_id: group::PartyID,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    match &mpc_public_output {
        VersionedDecryptionKeyReconfigurationOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "V1 Network keys no longer supported".to_string(),
        )),
        VersionedDecryptionKeyReconfigurationOutput::V2(public_output_bytes) => {
            let public_output: <twopc_mpc::decentralized_party::reconfiguration::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            let secp256k1_protocol_public_parameters =
                Arc::new(public_output.secp256k1_protocol_public_parameters()?);

            let secp256k1_decryption_key_share_public_parameters = Arc::new(
                public_output
                    .secp256k1_decryption_key_share_public_parameters(access_structure)
                    .map_err(DwalletMPCError::from)?,
            );

            let secp256r1_protocol_public_parameters =
                Arc::new(public_output.secp256r1_protocol_public_parameters()?);
            let secp256r1_decryption_key_share_public_parameters = Arc::new(
                public_output.secp256r1_decryption_key_share_public_parameters(access_structure)?,
            );

            let ristretto_protocol_public_parameters =
                Arc::new(public_output.ristretto_protocol_public_parameters()?);
            let ristretto_decryption_key_share_public_parameters = Arc::new(
                public_output.ristretto_decryption_key_share_public_parameters(access_structure)?,
            );

            let curve25519_protocol_public_parameters =
                Arc::new(public_output.curve25519_protocol_public_parameters()?);

            let curve25519_decryption_key_share_public_parameters = Arc::new(
                public_output
                    .curve25519_decryption_key_share_public_parameters(access_structure)?,
            );

            // Compute the internal checkpoint DKG output for checkpoint signing
            // Select the protocol PP for the checkpoint signing curve
            let internal_checkpoint_dkg_output = match checkpoint_signing_curve {
                DWalletCurve::Secp256k1 => {
                    bcs::to_bytes(&*secp256k1_protocol_public_parameters).ok()
                }
                DWalletCurve::Secp256r1 => {
                    bcs::to_bytes(&*secp256r1_protocol_public_parameters).ok()
                }
                DWalletCurve::Ristretto => {
                    bcs::to_bytes(&*ristretto_protocol_public_parameters).ok()
                }
                DWalletCurve::Curve25519 => {
                    bcs::to_bytes(&*curve25519_protocol_public_parameters).ok()
                }
            }
            .and_then(|protocol_pp| {
                compute_internal_checkpoint_dkg_output(
                    &network_key_id,
                    checkpoint_signing_curve,
                    checkpoint_signing_algorithm,
                    &protocol_pp,
                    access_structure,
                    party_id,
                )
            });

            Ok(NetworkEncryptionKeyPublicData {
                epoch,
                dkg_at_epoch,
                state: NetworkDecryptionKeyPublicOutputType::Reconfiguration,
                latest_network_reconfiguration_public_output: Some(mpc_public_output),
                secp256k1_decryption_key_share_public_parameters,
                secp256k1_protocol_public_parameters,
                network_dkg_output: bcs::from_bytes(network_dkg_public_output)?,
                secp256r1_decryption_key_share_public_parameters,
                ristretto_decryption_key_share_public_parameters,
                secp256r1_protocol_public_parameters,
                ristretto_protocol_public_parameters,
                curve25519_protocol_public_parameters,
                curve25519_decryption_key_share_public_parameters,
                internal_checkpoint_dkg_output,
            })
        }
    }
}
