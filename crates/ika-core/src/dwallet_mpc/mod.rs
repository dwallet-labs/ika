// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm};
use group::PartyID;
use group::curve25519;
use ika_types::committee::{
    ClassGroupsEncryptionKeyAndProof, Committee, RistrettoPvssEncryptionKeyAndProof,
    Secp256k1PvssEncryptionKeyAndProof, Secp256r1PvssEncryptionKeyAndProof,
};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use mpc::{Weight, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use std::vec::Vec;
use sui_types::base_types::EpochId;
use tracing::error;

/// Request to trigger an internal MPC signing session.
/// Sent to the MPC service to initiate a sign session using the internal presign pool.
#[derive(Debug, Clone)]
pub struct NetworkOwnedAddressSignRequest {
    pub message: Vec<u8>,
    pub curve: DWalletCurve,
    pub hash_scheme: DWalletHashScheme,
    /// Network-uniform identity of this sign demand. Announced through
    /// consensus so every validator assigns it the same presign in
    /// consensus-delivery order (see `dwallet_mpc_service`'s NOA presign-demand
    /// drain).
    ///
    /// The signature algorithm is NOT carried beside this: it is derived from
    /// the identity (`expected_signature_algorithm`), so the pool a demand
    /// pops from and the session it instantiates cannot disagree.
    pub demand_id: ika_types::noa_checkpoint::NOAPresignDemandId,
}

/// Output from a completed internal MPC signing session.
/// Sent to the network-owned-address sign output channel for consumers.
#[derive(Debug, Clone)]
pub struct NetworkOwnedAddressSignOutput {
    pub session_identifier: ika_types::messages_dwallet_mpc::SessionIdentifier,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub curve: DWalletCurve,
    pub signature_algorithm: DWalletSignatureAlgorithm,
    pub hash_scheme: DWalletHashScheme,
}

mod catchup_gate;
pub mod dwallet_mpc_service;
mod mpc_diagnostics;
pub mod mpc_manager;
pub mod mpc_session;

mod crytographic_computation;
pub mod dwallet_mpc_metrics;

pub use crytographic_computation::protocol_cryptographic_data;

#[cfg(test)]
mod integration_tests;

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

/// Per-validator public MPC keys, indexed by `PartyID`. Holds the class-groups
/// CRT encryption-key map alongside the three per-curve PVSS HPKE encryption-key
/// maps that `decentralized_party::dkg::PublicInput::new` and the
/// reconfiguration-party constructors require since inkrypto introduced
/// per-curve PVSS keys.
///
/// Exists so that `network_dkg_v2_public_input` and the three reconfiguration
/// `generate_public_input` constructors take one parameter instead of four
/// separate `HashMap` arguments. Adding a fifth PVSS curve in the future becomes
/// a one-field change to this struct + its extractor rather than threading a new
/// `HashMap` through every helper signature on the call path.
#[derive(Clone, Debug)]
pub(crate) struct ValidatorMpcKeysByPartyId {
    pub class_groups: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
    pub secp256k1_pvss: HashMap<PartyID, Secp256k1PvssEncryptionKeyAndProof>,
    pub secp256r1_pvss: HashMap<PartyID, Secp256r1PvssEncryptionKeyAndProof>,
    pub ristretto_pvss: HashMap<PartyID, RistrettoPvssEncryptionKeyAndProof>,
    /// Fast Schnorr (VSS) HPKE encryption public **key values** (curve25519,
    /// serializable form), already filtered to the parties whose UC proof of
    /// knowledge verified at [`Committee::new`]. Read sites rebuild
    /// `EncryptionPublicKey` via `EncryptionPublicKey::new(value, &pp)` — a
    /// cheap curve-point parse — without re-running the UC proof verification.
    pub vss_hpke_verified_party_encryption_key_values: HashMap<PartyID, curve25519::Value>,
}

/// Re-key an epoch's off-chain validator MPC keys from `AuthorityName` to the
/// committee's 1-based `PartyID`, producing the form the crypto library
/// consumes.
///
/// All key material — class-groups + the three per-curve PVSS HPKE keys + the
/// Fast Schnorr (VSS) HPKE key — comes from the single atomic off-chain
/// `bundles` (the consensus-agreed set delivered per-epoch). `committee` is used
/// only for the `AuthorityName → PartyID` mapping and to verify the VSS UC
/// proofs (once). A validator absent from `bundles` (offline/withholding) is
/// absent from every map — the DKG/reconfig then deal only to the parties that
/// are present, and the committee stays full for consensus.
pub(crate) fn get_validator_mpc_keys_by_party_id(
    committee: &Committee,
    bundles: &crate::validator_metadata::OffChainCommitteeBundles,
) -> DwalletMPCResult<ValidatorMpcKeysByPartyId> {
    let mut class_groups = HashMap::new();
    let mut secp256k1_pvss = HashMap::new();
    let mut secp256r1_pvss = HashMap::new();
    let mut ristretto_pvss = HashMap::new();
    for (name, _) in committee.voting_rights.iter() {
        let party_id = authority_name_to_party_id_from_committee(committee, name)?;
        // All four maps come from the same atomic off-chain bundle, so a
        // validator that withheld its bundle is absent from ALL of them (rather
        // than appearing in class_groups but not PVSS). This keeps the dealt set
        // consistent across class-groups + PVSS + VSS — the DKG/reconfig deal to
        // exactly the parties present in the agreed bundle.
        if let Some(k) = bundles.class_groups.get(name).cloned() {
            class_groups.insert(party_id, k);
        }
        if let Some(k) = bundles.secp256k1_pvss.get(name).cloned() {
            secp256k1_pvss.insert(party_id, k);
        }
        if let Some(k) = bundles.secp256r1_pvss.get(name).cloned() {
            secp256r1_pvss.insert(party_id, k);
        }
        if let Some(k) = bundles.ristretto_pvss.get(name).cloned() {
            ristretto_pvss.insert(party_id, k);
        }
    }
    Ok(ValidatorMpcKeysByPartyId {
        class_groups,
        secp256k1_pvss,
        secp256r1_pvss,
        ristretto_pvss,
        // Verify the VSS HPKE UC proofs once, keyed by this committee's party ids.
        vss_hpke_verified_party_encryption_key_values: committee
            .verified_vss_hpke_party_encryption_key_values(&bundles.vss_hpke),
    })
}

impl ValidatorMpcKeysByPartyId {
    /// An empty key set — the manager's starting point at network key version 3,
    /// where every key (class_groups included) is supplied by the off-chain
    /// consensus-agreed set via `ingest_offchain_mpc_keys`, never from Sui.
    pub(crate) fn empty() -> Self {
        Self {
            class_groups: HashMap::new(),
            secp256k1_pvss: HashMap::new(),
            secp256r1_pvss: HashMap::new(),
            ristretto_pvss: HashMap::new(),
            vss_hpke_verified_party_encryption_key_values: HashMap::new(),
        }
    }
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
    if party_id == 0 {
        // Party IDs are 1-based, so 0 is not a valid party ID.
        return None;
    }
    // A tangible party ID is of type `PartyID` and in the range `1..=number_of_tangible_parties`.
    // Convert it to an index to the committee authority names, which is in the range `0..number_of_tangible_parties`,
    // Decrement the index to transform it from 1-based to 0-based.
    // Safe to decrement as `PartyID` is `u16`, will never overflow.
    let index = u32::from(party_id) - 1;

    committee.authority_by_index(index).copied()
}

/// Convert a given [`Vec<PartyID>`] to the corresponding [`Vec<AuthorityName>`].
///
/// Returns the authority names for the given party IDs that are part of the committee, and ignores any
/// party IDs that do not have a corresponding authority name in the committee.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_id_to_authority_name() {
        let (committee, _keypairs) = Committee::new_simple_test_committee();

        // Party ids are 1-based positions in the committee's own
        // `voting_rights` order. The expectation comes from the committee, not
        // from the BLS keypairs: a name is a consensus key and cannot be
        // derived from the BLS keypair used for signing.
        for (index, (expected_name, _)) in committee.voting_rights.iter().enumerate() {
            assert_eq!(
                party_id_to_authority_name(index as PartyID + 1, &committee),
                Some(*expected_name),
            );
        }
    }

    #[test]
    fn test_party_id_to_authority_name_zero_party() {
        let (committee, _keypairs) = Committee::new_simple_test_committee();

        assert_eq!(party_id_to_authority_name(0, &committee), None);
    }

    #[test]
    fn test_party_id_to_authority_name_not_existing_party() {
        let (committee, _keypairs) = Committee::new_simple_test_committee();

        assert_eq!(party_id_to_authority_name(0, &committee), None);
    }

    #[test]
    fn test_party_ids_to_authority_names() {
        let (committee, _keypairs) = Committee::new_simple_test_committee();
        assert_eq!(
            party_ids_to_authority_names(&[1, 2, 3, 4], &committee),
            vec![
                committee.voting_rights[0].0,
                committee.voting_rights[1].0,
                committee.voting_rights[2].0,
                committee.voting_rights[3].0,
            ]
        );
    }

    #[test]
    fn test_party_ids_to_authority_names_some_absent_authorities() {
        let (committee, _keypairs) = Committee::new_simple_test_committee();
        assert_eq!(
            party_ids_to_authority_names(&[1, 2, 3, 40], &committee),
            vec![
                committee.voting_rights[0].0,
                committee.voting_rights[1].0,
                committee.voting_rights[2].0,
            ]
        );
    }
}
