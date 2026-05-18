// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::debug_variable_chunks;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::{
    build_network_encryption_key_public_data, compute_all_network_owned_address_dkg_outputs,
};
use crate::dwallet_mpc::{
    authority_name_to_party_id_from_committee, generate_access_structure_from_committee,
};
use class_groups::SecretKeyShareSizedInteger;
use commitment::CommitmentSizedNumber;
use dwallet_mpc_types::dwallet_mpc::{
    NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicData, ReconfigurationParty,
    SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedNetworkDkgOutput,
};
use group::PartyID;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party as GuaranteedOutputParty};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, Party,
    WeightedThresholdAccessStructure,
};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use twopc_mpc::decentralized_party_backward_compatible::reconfiguration as bwd_compat_reconfig;

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
            extract_class_groups_encryption_keys_from_committee(&current_committee)?;

        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            extract_class_groups_encryption_keys_from_committee(&upcoming_committee)?;

        // Per-curve PVSS HPKE encryption keys + proofs. Upstream's
        // `new_from_dkg_output` / `new_from_reconfiguration_output` accept a
        // single set of PVSS HashMaps keyed by `PartyID`; their internal use
        // (`participating_parties_access_structure: upcoming_access_structure`
        // in `2pc-mpc/src/decentralized_party/reconfiguration.rs:401, 689`)
        // shows they correspond to the UPCOMING committee — the dealers send
        // ciphertexts encrypted under each upcoming participating party's PVSS
        // public key.
        let upcoming_validators_pvss_hpke_keys_by_party_id =
            crate::dwallet_mpc::get_validator_mpc_keys_by_party_id(&upcoming_committee)?;

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


                        // 3 trailing PVSS HPKE encryption-keys-and-proofs args (per-curve,
                        // for upstream's threshold-encryption-to-sharing sub-protocol) sourced
                        // from the UPCOMING committee.
                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_reconfiguration_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                bcs::from_bytes(&network_dkg_public_output)?,
                                bcs::from_bytes(&latest_reconfiguration_public_output)?,
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                }
            }
            VersionedNetworkDkgOutput::V2(_) => {
                // Main `ReconfigurationParty::generate_public_input` is only called when
                // `protocol_config.is_reconfiguration_message_version_v3() == true` — but
                // a V2-tagged DKG output means the network was DKG'd under the bwd-compat
                // Party. Converting bwd-compat `dkg::PublicOutput` to main shape requires
                // an upstream `From` impl on `decentralized_party_backward_compatible::dkg::PublicOutput`
                // for `decentralized_party::dkg::PublicOutput`; that conversion is not yet
                // shipped in cryptography-private. Until it is, treat the v2→v3 migration
                // explicitly as unsupported.
                Err(DwalletMPCError::InternalError(
                    "v2→v3 reconfig migration requires upstream `bwd_compat_dkg::PublicOutput → \
                     dkg::PublicOutput` conversion; not yet available in cryptography-private."
                        .to_string(),
                ))
            }
            VersionedNetworkDkgOutput::V3(network_dkg_public_output) => {
                match latest_reconfiguration_public_output {
                    None => {
                        let public_output: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                            bcs::from_bytes(&network_dkg_public_output)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v3 [network_dkg_public_output (v3)]",
                            "network_dkg_public_output",
                            &network_dkg_public_output,
                        );

                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_dkg_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                public_output,
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                    Some(VersionedDecryptionKeyReconfigurationOutput::V3(
                        latest_reconfiguration_public_output,
                    )) => {
                        let public_output: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicOutput =
                            bcs::from_bytes(&network_dkg_public_output)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v3 [network_dkg_public_output (v3)]",
                            "network_dkg_public_output",
                            &network_dkg_public_output,
                        );
                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v3 [latest_reconfiguration_public_output (v3)]",
                            "latest_reconfiguration_public_output",
                            &latest_reconfiguration_public_output,
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
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                    Some(VersionedDecryptionKeyReconfigurationOutput::V1(_))
                    | Some(VersionedDecryptionKeyReconfigurationOutput::V2(_)) => {
                        // The DKG ran under main (V3) but a prior reconfig is V1/V2-tagged.
                        // V1 is unsupported globally; a V2 prior under a V3 DKG is the
                        // mid-migration case (see V2 dkg arm above for the same upstream gap).
                        Err(DwalletMPCError::InternalError(
                            "Main Reconfig expects V3 prior reconfig output; cross-version not yet supported."
                                .to_string(),
                        ))
                    }
                }
            }
        }
    }
}

/// Builds the bwd-compat reconfiguration public input via
/// `cryptography-private @ 7795eb45`'s new
/// `decentralized_party_backward_compatible::reconfiguration::PublicInput::new_from_*`
/// constructors. Mirrors the main path's `(VersionedNetworkDkgOutput,
/// Option<VersionedDecryptionKeyReconfigurationOutput>)` dispatcher but produces
/// the bwd-compat `PublicInput` shape (no PVSS HPKE keys — bwd-compat
/// reconfig predates the threshold-encryption-to-sharing sub-protocol).
///
/// Used at `ProtocolConfig::is_reconfiguration_message_version_v3() == false`
/// (protocol_version ≤ 4); paired with [`advance_network_reconfiguration_bwd_compat`].
pub(crate) fn reconfiguration_bwd_compat_public_input(
    current_committee: &Committee,
    upcoming_committee: Committee,
    network_dkg_public_output: VersionedNetworkDkgOutput,
    latest_reconfiguration_public_output: Option<VersionedDecryptionKeyReconfigurationOutput>,
) -> DwalletMPCResult<<bwd_compat_reconfig::Party as mpc::Party>::PublicInput> {
    let _ = latest_reconfiguration_public_output;
    let current_committee = current_committee.clone();
    let _current_access_structure = generate_access_structure_from_committee(&current_committee)?;
    let _upcoming_access_structure = generate_access_structure_from_committee(&upcoming_committee)?;

    let _current_encryption_keys_per_crt_prime_and_proofs =
        extract_class_groups_encryption_keys_from_committee(&current_committee)?;

    let _upcoming_encryption_keys_per_crt_prime_and_proofs =
        extract_class_groups_encryption_keys_from_committee(&upcoming_committee)?;

    let _current_tangible_party_id_to_upcoming =
        current_tangible_party_id_to_upcoming(current_committee, upcoming_committee);

    match network_dkg_public_output {
        VersionedNetworkDkgOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "V1 Network keys no longer supported".to_string(),
        )),
        VersionedNetworkDkgOutput::V2(_) => {
            // Bwd-compat DKG output (`bwd_compat_dkg::Party::PublicOutput`) is
            // structurally a subset of post-bump main `dkg::Party::PublicOutput`
            // — same legacy fields, no trailing `threshold_encryption_to_sharing_output`.
            // Upstream's `bwd_compat_reconfig::PublicInput::new_from_{dkg,
            // reconfiguration}_output` takes `universal_public_output: decentralized_party::dkg::PublicOutput`
            // (the post-bump main type), reading only the legacy fields. So
            // building the bwd-compat reconfig PublicInput from bwd-compat DKG
            // bytes needs one of:
            //   - upstream `From<bwd_compat::dkg::PublicOutput> for decentralized_party::dkg::PublicOutput`,
            //     or
            //   - upstream `bwd_compat_reconfig::PublicInput::new_from_bwd_compat_dkg_output`.
            // Neither ships in `cryptography-private @ 7795eb45`. Until one
            // lands, bwd-compat Reconfig (item 7 end-to-end) is blocked at this
            // call site; bwd-compat DKG itself works.
            Err(DwalletMPCError::InternalError(
                "Bwd-compat Reconfig blocked on upstream: needs `From<bwd_compat::dkg::PublicOutput> \
                 for decentralized_party::dkg::PublicOutput` or `bwd_compat_reconfig::PublicInput::\
                 new_from_bwd_compat_dkg_output` in cryptography-private.".to_string(),
            ))
        }
        VersionedNetworkDkgOutput::V3(_) => {
            // V3 means main-shape DKG output. The bwd-compat reconfig path is
            // only reached when `_version == 2`; a V3-tagged DKG output in
            // that case is a config error (the network produced post-bump
            // output but is still running bwd-compat reconfig).
            Err(DwalletMPCError::InternalError(
                "Bwd-compat Reconfig dispatch saw a V3 DKG output — protocol_config / wire-tag mismatch."
                    .to_string(),
            ))
        }
    }
}

/// Advances the network Reconfiguration protocol using the mainnet-v1.1.8-shape
/// decentralized party
/// (`twopc_mpc::decentralized_party_backward_compatible::reconfiguration::Party`).
///
/// Used when the active `ProtocolConfig` reports
/// `reconfiguration_message_version() == 2` (protocol_version ≤ 4). The
/// finalized public output is wrapped as
/// `VersionedDecryptionKeyReconfigurationOutput::V2`; bytes are wire-compatible
/// with mainnet-v1.1.8 peers per audit §4 (reconfig `PublicOutput` wire-stable).
pub(crate) fn advance_network_reconfiguration_bwd_compat(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <bwd_compat_reconfig::Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<bwd_compat_reconfig::Party as mpc::Party>::Message>,
    decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result =
        GuaranteedOutputParty::<bwd_compat_reconfig::Party>::advance_with_guaranteed_output(
            session_id,
            party_id,
            access_structure,
            advance_request,
            Some(decryption_key_shares),
            &public_input,
            rng,
        )?;

    match result {
        GuaranteedOutputDeliveryRoundResult::Advance { message } => {
            Ok(GuaranteedOutputDeliveryRoundResult::Advance { message })
        }
        GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        } => {
            let public_output_value = bcs::to_bytes(
                &VersionedDecryptionKeyReconfigurationOutput::V2(public_output_value),
            )?;
            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
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

fn extract_class_groups_encryption_keys_from_committee(
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
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    // Macro extracts the 8 protocol+decryption-key-share Arcs from a decoded
    // reconfiguration `PublicOutput` (either bwd-compat or main; both expose
    // the same per-curve accessor API).
    macro_rules! build_from_reconfig_output {
        ($public_output:expr) => {{
            let public_output = $public_output;
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

            let noa_dkg_data = compute_all_network_owned_address_dkg_outputs(
                &network_key_id,
                &secp256k1_protocol_public_parameters,
                &secp256r1_protocol_public_parameters,
                &ristretto_protocol_public_parameters,
                &curve25519_protocol_public_parameters,
            )?;

            Ok::<NetworkEncryptionKeyPublicData, DwalletMPCError>(
                build_network_encryption_key_public_data(
                    epoch,
                    dkg_at_epoch,
                    NetworkDecryptionKeyPublicOutputType::Reconfiguration,
                    Some(mpc_public_output.clone()),
                    bcs::from_bytes(network_dkg_public_output)?,
                    secp256k1_protocol_public_parameters,
                    secp256k1_decryption_key_share_public_parameters,
                    secp256r1_protocol_public_parameters,
                    secp256r1_decryption_key_share_public_parameters,
                    ristretto_protocol_public_parameters,
                    ristretto_decryption_key_share_public_parameters,
                    curve25519_protocol_public_parameters,
                    curve25519_decryption_key_share_public_parameters,
                    &noa_dkg_data,
                ),
            )
        }};
    }

    match &mpc_public_output {
        VersionedDecryptionKeyReconfigurationOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "V1 Network keys no longer supported".to_string(),
        )),
        VersionedDecryptionKeyReconfigurationOutput::V2(public_output_bytes) => {
            // bwd-compat reconfig PublicOutput shape.
            let public_output: <bwd_compat_reconfig::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_reconfig_output!(public_output)
        }
        VersionedDecryptionKeyReconfigurationOutput::V3(public_output_bytes) => {
            let public_output: <twopc_mpc::decentralized_party::reconfiguration::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_reconfig_output!(public_output)
        }
    }
}
