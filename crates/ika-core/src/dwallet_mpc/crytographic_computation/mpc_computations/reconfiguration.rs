// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::debug_variable_chunks;
use crate::dwallet_mpc::crytographic_computation::mpc_computations::network_dkg::{
    build_network_encryption_key_public_data, compute_all_network_owned_address_dkg_outputs,
    timed_sub_call,
};
use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
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

        // At main Reconfig (callable only from `_version == 3`) every upcoming
        // committee member MUST publish the post-PR-#1707 bundle shape. The
        // shape-tolerant decoder accepts old-shape submissions silently, so a
        // not-yet-migrated validator in the upcoming committee would land here
        // with empty PVSS entries while their class-groups entry is present.
        // Fail loudly rather than running reconfig on a partial map.
        let expected = upcoming_committee.voting_rights.len();
        let class_groups_count = upcoming_validators_pvss_hpke_keys_by_party_id
            .class_groups
            .len();
        let secp256k1_pvss_count = upcoming_validators_pvss_hpke_keys_by_party_id
            .secp256k1_pvss
            .len();
        let secp256r1_pvss_count = upcoming_validators_pvss_hpke_keys_by_party_id
            .secp256r1_pvss
            .len();
        let ristretto_pvss_count = upcoming_validators_pvss_hpke_keys_by_party_id
            .ristretto_pvss
            .len();
        if class_groups_count != expected
            || secp256k1_pvss_count != expected
            || secp256r1_pvss_count != expected
            || ristretto_pvss_count != expected
        {
            return Err(DwalletMPCError::InvalidMPCPartyType(format!(
                "at reconfiguration_message_version == 3 every upcoming committee \
                 member must publish the post-PR-#1707 bundle shape, but only \
                 {class_groups_count}/{expected} class-groups, \
                 {secp256k1_pvss_count}/{expected} secp256k1 PVSS, \
                 {secp256r1_pvss_count}/{expected} secp256r1 PVSS, \
                 {ristretto_pvss_count}/{expected} ristretto PVSS keys decoded",
            )));
        }

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
            VersionedNetworkDkgOutput::V1(_) => {
                unreachable!("V1 network DKG outputs are no longer produced")
            }
            // V2 and V3 DKG outputs differ only in whether the trailing Protocol-0.1
            // `threshold_encryption_to_sharing_output` is present. Decode either shape to a
            // `dkg::PublicOutputCore` and feed it into the same main constructor — covers
            // both the steady-state v3-DKG path and the v2→v3 migration path (including the
            // epoch-1 edge case where there is no prior reconfig output yet).
            v2_or_v3 @ (VersionedNetworkDkgOutput::V2(_) | VersionedNetworkDkgOutput::V3(_)) => {
                let dkg_public_output_core: twopc_mpc::decentralized_party::dkg::PublicOutputCore =
                    match &v2_or_v3 {
                        VersionedNetworkDkgOutput::V2(bytes) => bcs::from_bytes(bytes)?,
                        VersionedNetworkDkgOutput::V3(bytes) => {
                            let full: twopc_mpc::decentralized_party::dkg::PublicOutput =
                                bcs::from_bytes(bytes)?;
                            full.core
                        }
                        VersionedNetworkDkgOutput::V1(_) => unreachable!(),
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
                    Some(prior @ (VersionedDecryptionKeyReconfigurationOutput::V2(_)
                    | VersionedDecryptionKeyReconfigurationOutput::V3(_))) => {
                        let prior_reconfig_core: twopc_mpc::decentralized_party::reconfiguration::PublicOutputCore =
                            match &prior {
                                VersionedDecryptionKeyReconfigurationOutput::V2(bytes) => {
                                    bcs::from_bytes(bytes)?
                                }
                                VersionedDecryptionKeyReconfigurationOutput::V3(bytes) => {
                                    let full: twopc_mpc::decentralized_party::reconfiguration::PublicOutput =
                                        bcs::from_bytes(bytes)?;
                                    full.core
                                }
                                VersionedDecryptionKeyReconfigurationOutput::V1(_) => unreachable!(),
                            };

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
                    Some(VersionedDecryptionKeyReconfigurationOutput::V1(_)) => Err(
                        DwalletMPCError::InternalError(
                            "Main Reconfig expects V2 or V3 prior reconfig output; V1 is unsupported."
                                .to_string(),
                        ),
                    ),
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
    let current_committee = current_committee.clone();
    let current_access_structure = generate_access_structure_from_committee(&current_committee)?;
    let upcoming_access_structure = generate_access_structure_from_committee(&upcoming_committee)?;

    let current_encryption_keys_per_crt_prime_and_proofs =
        extract_class_groups_encryption_keys_from_committee(&current_committee)?;

    let upcoming_encryption_keys_per_crt_prime_and_proofs =
        extract_class_groups_encryption_keys_from_committee(&upcoming_committee)?;

    let current_tangible_party_id_to_upcoming =
        current_tangible_party_id_to_upcoming(current_committee, upcoming_committee);

    match network_dkg_public_output {
        VersionedNetworkDkgOutput::V1(_) => {
            unreachable!("V1 network DKG outputs are no longer produced")
        }
        VersionedNetworkDkgOutput::V2(network_dkg_public_output_bytes) => {
            let bwd_compat_dkg_public_output: <twopc_mpc::decentralized_party_backward_compatible::dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(&network_dkg_public_output_bytes)?;

            match latest_reconfiguration_public_output {
                None => bwd_compat_reconfig::PublicInput::new_from_dkg_output(
                    &current_access_structure,
                    upcoming_access_structure,
                    current_encryption_keys_per_crt_prime_and_proofs,
                    upcoming_encryption_keys_per_crt_prime_and_proofs,
                    current_tangible_party_id_to_upcoming,
                    bwd_compat_dkg_public_output,
                )
                .map_err(DwalletMPCError::from),
                Some(VersionedDecryptionKeyReconfigurationOutput::V2(
                    latest_reconfiguration_public_output_bytes,
                )) => {
                    let public_output: <bwd_compat_reconfig::Party as mpc::Party>::PublicOutput =
                        bcs::from_bytes(&latest_reconfiguration_public_output_bytes)?;
                    bwd_compat_reconfig::PublicInput::new_from_reconfiguration_output(
                        &current_access_structure,
                        upcoming_access_structure,
                        current_encryption_keys_per_crt_prime_and_proofs,
                        upcoming_encryption_keys_per_crt_prime_and_proofs,
                        current_tangible_party_id_to_upcoming,
                        bwd_compat_dkg_public_output.into(),
                        public_output,
                    )
                    .map_err(DwalletMPCError::from)
                }
                Some(VersionedDecryptionKeyReconfigurationOutput::V1(_)) => {
                    unreachable!("V1 reconfiguration outputs are no longer produced")
                }
                Some(VersionedDecryptionKeyReconfigurationOutput::V3(_)) => Err(
                    DwalletMPCError::InternalError(
                        "Bwd-compat reconfig requires a prior V2-tagged reconfiguration output."
                            .to_string(),
                    ),
                ),
            }
        }
        VersionedNetworkDkgOutput::V3(_) => Err(DwalletMPCError::InternalError(
            "Bwd-compat Reconfig dispatch saw a V3 DKG output — protocol_config / wire-tag mismatch."
                .to_string(),
        )),
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
    metrics: &DWalletMPCMetrics,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedDecryptionKeyReconfigurationOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    // Macro extracts the 8 protocol+decryption-key-share Arcs from a decoded
    // reconfiguration `PublicOutput` (either bwd-compat or main; both expose
    // the same per-curve accessor API). Each sub-call is individually timed
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
                    &network_key_id,
                    &secp256k1_protocol_public_parameters,
                    &secp256r1_protocol_public_parameters,
                    &ristretto_protocol_public_parameters,
                    &curve25519_protocol_public_parameters,
                )
            })?;

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
        VersionedDecryptionKeyReconfigurationOutput::V1(_) => {
            unreachable!("V1 reconfiguration outputs are no longer produced")
        }
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
