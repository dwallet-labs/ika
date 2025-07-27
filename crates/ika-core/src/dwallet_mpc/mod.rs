// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::PartyID;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::{Weight, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use std::vec::Vec;
use sui_types::base_types::EpochId;
use tracing::error;

pub mod dwallet_mpc_service;
pub mod mpc_manager;
pub mod mpc_session;

mod crytographic_computation;
pub mod dwallet_mpc_metrics;
mod mpc_event;

pub(crate) use crytographic_computation::mpc_computations::{
    dwallet_dkg, network_dkg, presign, reconfiguration, sign,
};
pub(crate) use crytographic_computation::native_computations::{
    encrypt_user_share, make_dwallet_user_secret_key_shares_public,
};

pub const FIRST_EPOCH_ID: EpochId = 0;

/// Convert an `authority_name` to the tangible party ID (`PartyID`) in the `committee`.
pub(crate) fn authority_name_to_party_id_from_committee(
    committee: &Committee,
    authority_name: &AuthorityName,
) -> DwalletMPCResult<PartyID> {
    // The index of the authority `authority_name` in the `committee`.
    // This value is in the range `0..number_of_tangible_parties`,
    // and represents a unique index to the set of authority names.
    let authority_index = committee
        .authority_index(authority_name)
        .ok_or(DwalletMPCError::AuthorityNameNotFound(*authority_name))?;

    // A tangible party ID is of type `PartyID` and in the range `1..=number_of_tangible_parties`.
    // Increment the index to transform it from 0-based to 1-based.
    let tangible_party_id: u32 = authority_index
        .checked_add(1)
        .expect("should never have more than 2^32 parties");
    let tangible_party_id: u16 = tangible_party_id
        .try_into()
        .expect("should never have more than 2^16 parties");

    Ok(tangible_party_id)
}

pub(crate) fn get_validators_class_groups_public_keys_and_proofs(
    committee: &Committee,
) -> DwalletMPCResult<HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>> {
    let mut validators_class_groups_public_keys_and_proofs = HashMap::new();
    for (name, _) in committee.voting_rights.iter() {
        let party_id = authority_name_to_party_id_from_committee(committee, name)?;
        if let Ok(public_key) = committee.class_groups_public_key_and_proof(name) {
            validators_class_groups_public_keys_and_proofs.insert(party_id, public_key);
        }
    }

    Ok(validators_class_groups_public_keys_and_proofs)
}

/// Convert a `committee` to a `WeightedThresholdAccessStructure` that is used by the cryptographic library.
pub(crate) fn generate_access_structure_from_committee(
    committee: &Committee,
) -> DwalletMPCResult<WeightedThresholdAccessStructure> {
    let party_to_weight: HashMap<PartyID, Weight> = committee
        .voting_rights
        .iter()
        .map(|(name, stake)| {
            let tangible_party_id = authority_name_to_party_id_from_committee(committee, name)?;
            let weight: Weight = (*stake)
                .try_into()
                .expect("should never have more than 2^16 stake units");

            Ok((tangible_party_id, weight))
        })
        .collect::<DwalletMPCResult<HashMap<PartyID, Weight>>>()?;
    let threshold: PartyID = committee
        .quorum_threshold()
        .try_into()
        .expect("should never have more than 2^16 parties");

    // TODO: use error directly
    WeightedThresholdAccessStructure::new(threshold, party_to_weight).map_err(DwalletMPCError::from)
}

/// Convert a given `party_id` to it's corresponding authority name (address).
pub(crate) fn party_id_to_authority_name(
    party_id: PartyID,
    committee: &Committee,
) -> Option<AuthorityName> {
    // A tangible party ID is of type `PartyID` and in the range `1..=number_of_tangible_parties`.
    // Convert it to an index to the committee authority names, which is in the range `0..number_of_tangible_parties`,
    // Decrement the index to transform it from 1-based to 0-based.
    // Safe to decrement as `PartyID` is `u16`, will never overflow.
    let index = u32::from(party_id) - 1;

    committee.authority_by_index(index).copied()
}

/// Convert a given [`Vec<PartyID>`] to the corresponding [`Vec<AuthorityName>`].
pub(crate) fn party_ids_to_authority_names(
    party_ids: &[PartyID],
    committee: &Committee,
) -> Vec<AuthorityName> {
    party_ids
        .iter()
        .flat_map(|party_id| {
            let authority_name = party_id_to_authority_name(*party_id, committee);

            if authority_name.is_none() {
                error!(
                    party_id=?party_id,
                    "failed to find matching authority name for party ID"
                );
            }

            authority_name
        })
        .collect()
}
