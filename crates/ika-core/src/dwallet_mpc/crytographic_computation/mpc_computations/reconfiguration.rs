// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::debug_variable_chunks;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::{
    build_network_encryption_key_public_data, compute_all_network_owned_address_dkg_outputs,
    timed_sub_call,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::dwallet_mpc::{
    ValidatorMpcKeysByPartyId, authority_name_to_party_id_from_committee,
    generate_access_structure_from_committee,
};
use dwallet_mpc_types::dwallet_mpc::{
    NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicData, ReconfigurationParty,
    SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedNetworkDkgOutput,
};
use group::PartyID;
use ika_types::committee::Committee;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::{Party, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

pub(crate) trait ReconfigurationPartyPublicInputGenerator: Party {
    /// Generates the public input required for the reconfiguration protocol.
    ///
    /// `current_validator_mpc_keys` / `upcoming_validator_mpc_keys` are the
    /// current and upcoming committees' off-chain consensus-agreed key sets
    /// (class groups + per-curve PVSS HPKE + verified VSS), keyed by their
    /// respective committee's party ids. This is the MAIN reconfig party, which
    /// only runs at `network_encryption_key_version == 3` — so ALL validator
    /// keys come from these agreed sets, never from Sui; the committees supply
    /// only the access structures. Each agreed set may cover a subset of its
    /// committee (offline/withholding validators are undealt but stay committee
    /// members for consensus).
    fn generate_public_input(
        committee: &Committee,
        new_committee: Committee,
        current_validator_mpc_keys: ValidatorMpcKeysByPartyId,
        upcoming_validator_mpc_keys: ValidatorMpcKeysByPartyId,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: Option<VersionedDecryptionKeyReconfigurationOutput>,
    ) -> DwalletMPCResult<<ReconfigurationParty as mpc::Party>::PublicInput>;
}

impl ReconfigurationPartyPublicInputGenerator for ReconfigurationParty {
    fn generate_public_input(
        current_committee: &Committee,
        upcoming_committee: Committee,
        current_validator_mpc_keys: ValidatorMpcKeysByPartyId,
        upcoming_validator_mpc_keys: ValidatorMpcKeysByPartyId,
        network_dkg_public_output: VersionedNetworkDkgOutput,
        latest_reconfiguration_public_output: Option<VersionedDecryptionKeyReconfigurationOutput>,
    ) -> DwalletMPCResult<<ReconfigurationParty as Party>::PublicInput> {
        let current_committee = current_committee.clone();
        // Committees supply ONLY the access structures (voting weights /
        // threshold over the full committee).
        let current_access_structure =
            generate_access_structure_from_committee(&current_committee)?;
        let upcoming_access_structure =
            generate_access_structure_from_committee(&upcoming_committee)?;

        // class_groups (and PVSS, below) come from the off-chain consensus-agreed
        // key sets — NOT from Sui; the validator keys live off-chain.
        // The current set is the parties that actually hold shares from the
        // current DKG; the upcoming set is the reshare targets. Either may be a
        // subset of its committee — the reshare deals only to parties with keys.
        let current_encryption_keys_per_crt_prime_and_proofs =
            current_validator_mpc_keys.class_groups;

        // Per-curve PVSS HPKE encryption keys + proofs. Upstream's
        // `new_from_dkg_output` / `new_from_reconfiguration_output` accept a
        // single set of PVSS HashMaps keyed by `PartyID`; their internal use
        // (`participating_parties_access_structure: upcoming_access_structure`
        // in `2pc-mpc/src/decentralized_party/reconfiguration.rs:401, 689`)
        // shows they correspond to the UPCOMING committee — the dealers send
        // ciphertexts encrypted under each upcoming participating party's PVSS
        // public key.
        let upcoming_validators_pvss_hpke_keys_by_party_id = upcoming_validator_mpc_keys;
        let upcoming_encryption_keys_per_crt_prime_and_proofs =
            upcoming_validators_pvss_hpke_keys_by_party_id
                .class_groups
                .clone();

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
            // A V1 anchor is the raw `class_groups::dkg::PublicOutput`,
            // written once by the original (pre-1.1.8) DKG and never
            // rewritten on chain. The deployed keys have since migrated their
            // canonical anchor to V4, but this arm stays because a V1 anchor
            // must remain decodable — a node has to keep reading its own
            // history. The V1 bytes decode directly to the
            // `class_groups::dkg::PublicOutput` the constructor takes — the
            // same value the V2/V4 arm reaches via
            // `dkg_public_output_core.into()`.
            VersionedNetworkDkgOutput::V1(network_dkg_public_output_bytes) => {
                match latest_reconfiguration_public_output {
                    // A V1 anchor with no prior reconfiguration output cannot
                    // bootstrap: `new_from_dkg_output` needs the multi-curve
                    // `PublicOutputCore`, which a V1 anchor does not carry. No
                    // deployed key is in this state (they have all
                    // reconfigured).
                    None => Err(DwalletMPCError::InternalError(
                        "Main Reconfig with a V1 network DKG anchor requires a prior V2 or \
                         V4 reconfiguration output; a V1 anchor with no reconfiguration \
                         output is unsupported."
                            .to_string(),
                    )),
                    Some(prior) => {
                        let prior_reconfig_core = decode_prior_reconfiguration_output_core(&prior)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v3 [prior_reconfig_core]",
                            "prior_reconfig_core",
                            &bcs::to_bytes(&prior_reconfig_core)?,
                        );

                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_reconfiguration_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                bcs::from_bytes(&network_dkg_public_output_bytes)?,
                                prior_reconfig_core,
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                }
            }
            // A pre-aggregation (V3) anchor can no longer be decoded — its
            // inkrypto type was removed; such state must have migrated to V4
            // before this binary runs.
            VersionedNetworkDkgOutput::V3(_) => Err(DwalletMPCError::InternalError(
                "pre-aggregation (V3) network DKG anchors are no longer supported".to_string(),
            )),
            // V2 and V4 DKG outputs differ only in the trailing Protocol-0.1
            // `threshold_encryption_to_sharing_output` (absent / aggregated).
            // Decode either shape to a `dkg::PublicOutputCore` (their shared
            // bcs prefix) and feed it into the same main constructor —
            // including the epoch-1 edge case where there is no prior
            // reconfig output yet.
            versioned @ (VersionedNetworkDkgOutput::V2(_) | VersionedNetworkDkgOutput::V4(_)) => {
                let dkg_public_output_core: twopc_mpc::decentralized_party::dkg::PublicOutputCore =
                    match &versioned {
                        VersionedNetworkDkgOutput::V2(bytes) => bcs::from_bytes(bytes)?,
                        VersionedNetworkDkgOutput::V4(bytes) => {
                            let full: twopc_mpc::decentralized_party::dkg::PublicOutput =
                                bcs::from_bytes(bytes)?;
                            full.core
                        }
                        VersionedNetworkDkgOutput::V1(_) | VersionedNetworkDkgOutput::V3(_) => {
                            unreachable!()
                        }
                    };

                debug_variable_chunks(
                    "Instantiating public input for reconfiguration v3 [dkg_public_output_core]",
                    "dkg_public_output_core",
                    &bcs::to_bytes(&dkg_public_output_core)?,
                );

                match latest_reconfiguration_public_output {
                    None => {
                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_dkg_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                dkg_public_output_core,
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                    Some(prior) => {
                        let prior_reconfig_core = decode_prior_reconfiguration_output_core(&prior)?;

                        debug_variable_chunks(
                            "Instantiating public input for reconfiguration v3 [prior_reconfig_core]",
                            "prior_reconfig_core",
                            &bcs::to_bytes(&prior_reconfig_core)?,
                        );

                        let public_input: <ReconfigurationParty as Party>::PublicInput =
                            <twopc_mpc::decentralized_party::reconfiguration::Party as Party>::PublicInput::new_from_reconfiguration_output(
                                &current_access_structure,
                                upcoming_access_structure,
                                current_encryption_keys_per_crt_prime_and_proofs.clone(),
                                upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
                                current_tangible_party_id_to_upcoming,
                                dkg_public_output_core.into(),
                                prior_reconfig_core,
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256k1_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.ristretto_pvss.clone(),
                                upcoming_validators_pvss_hpke_keys_by_party_id.secp256r1_pvss.clone(),
                            )
                                .map_err(DwalletMPCError::from)?;

                        Ok(public_input)
                    }
                }
            }
        }
    }
}

/// Decodes a prior (V2 or V4) reconfiguration output to its
/// `reconfiguration::PublicOutputCore` for the main reconfiguration
/// constructors. V2 bytes are the core itself; V4 (aggregated) bytes are full
/// outputs, whose trailing threshold-encryption-to-sharing field the
/// constructor re-derives. V1 outputs predate the core shape and are
/// unsupported; V3 (pre-aggregation) outputs can no longer be decoded — their
/// inkrypto type was removed.
fn decode_prior_reconfiguration_output_core(
    prior: &VersionedDecryptionKeyReconfigurationOutput,
) -> DwalletMPCResult<twopc_mpc::decentralized_party::reconfiguration::PublicOutputCore> {
    match prior {
        VersionedDecryptionKeyReconfigurationOutput::V2(bytes) => Ok(bcs::from_bytes(bytes)?),
        VersionedDecryptionKeyReconfigurationOutput::V3(_) => Err(DwalletMPCError::InternalError(
            "pre-aggregation (V3) reconfiguration outputs are no longer supported".to_string(),
        )),
        VersionedDecryptionKeyReconfigurationOutput::V4(bytes) => {
            let full: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
                bcs::from_bytes(bytes)?;
            Ok(full.core)
        }
        VersionedDecryptionKeyReconfigurationOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "Main Reconfig expects a V2 or V4 prior reconfig output; V1 is unsupported."
                .to_string(),
        )),
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

pub(crate) fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output(
    epoch: u64,
    dkg_at_epoch: u64,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
    network_dkg_public_output: &SerializedWrappedMPCPublicOutput,
    metrics: &DWalletMPCMetrics,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    // Macro extracts the 8 protocol+decryption-key-share Arcs from a decoded
    // reconfiguration `PublicOutput`. Each sub-call is individually timed
    // (log + histogram) — this is the steady-state per-epoch instantiation
    // path, so it needs the same cost breakdown as the DKG path.
    macro_rules! build_from_reconfig_output {
        ($public_output:expr) => {{
            let public_output = $public_output;
            let secp256k1_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256k1_protocol_public_parameters",
                || public_output.secp256k1_protocol_public_parameters(),
            )?);
            let secp256k1_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256k1_decryption_key_share",
                || {
                    public_output
                        .secp256k1_decryption_key_share_public_parameters(access_structure)
                        .map_err(DwalletMPCError::from)
                },
            )?);
            let secp256r1_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256r1_protocol_public_parameters",
                || public_output.secp256r1_protocol_public_parameters(),
            )?);
            let secp256r1_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "secp256r1_decryption_key_share",
                || public_output.secp256r1_decryption_key_share_public_parameters(access_structure),
            )?);
            let ristretto_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "ristretto_protocol_public_parameters",
                || public_output.ristretto_protocol_public_parameters(),
            )?);
            let ristretto_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "ristretto_decryption_key_share",
                || public_output.ristretto_decryption_key_share_public_parameters(access_structure),
            )?);
            let curve25519_protocol_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "curve25519_protocol_public_parameters",
                || public_output.curve25519_protocol_public_parameters(),
            )?);
            let curve25519_decryption_key_share_public_parameters = Arc::new(timed_sub_call(
                metrics,
                "curve25519_decryption_key_share",
                || {
                    public_output
                        .curve25519_decryption_key_share_public_parameters(access_structure)
                },
            )?);

            let noa_dkg_data = timed_sub_call(metrics, "noa_dkg_outputs", || {
                compute_all_network_owned_address_dkg_outputs(
                    &secp256k1_protocol_public_parameters,
                    &secp256r1_protocol_public_parameters,
                    &ristretto_protocol_public_parameters,
                    &curve25519_protocol_public_parameters,
                )
            })?;

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
            )
        }};
    }

    match &mpc_public_output {
        VersionedDecryptionKeyReconfigurationOutput::V1(_) => Err(DwalletMPCError::InternalError(
            "V1 network keys are no longer supported for instantiation.".to_string(),
        )),
        // The crypto types for the V2 (bwd-compat) and V3 (pre-aggregation)
        // shapes were removed from inkrypto; the variants remain only for BCS
        // variant-index stability.
        VersionedDecryptionKeyReconfigurationOutput::V2(_)
        | VersionedDecryptionKeyReconfigurationOutput::V3(_) => {
            Err(DwalletMPCError::InternalError(
                "pre-aggregation (V2/V3) reconfiguration outputs are no longer supported for instantiation."
                    .to_string(),
            ))
        }
        VersionedDecryptionKeyReconfigurationOutput::V4(public_output_bytes) => {
            let public_output: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;
            build_from_reconfig_output!(public_output)
        }
    }
}
