// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use enum_dispatch::enum_dispatch;
use std::collections::HashMap;

use crate::committee::{Committee, CommitteeWithNetworkMetadata, NetworkMetadata, StakeUnit};
use crate::crypto::{AuthorityName, AuthorityPublicKey, AuthorityPublicKeyBytes, NetworkPublicKey};
use anemo::PeerId;
use anemo::types::{PeerAffinity, PeerInfo};
use consensus_config::{Authority, Committee as ConsensusCommittee};
use dwallet_mpc_types::dwallet_mpc::VersionedMPCData;
use ika_protocol_config::ProtocolVersion;
use serde::{Deserialize, Serialize};
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::multiaddr::Multiaddr;
use tracing::{error, warn};

#[enum_dispatch]
pub trait EpochStartSystemTrait {
    fn epoch(&self) -> EpochId;
    fn protocol_version(&self) -> ProtocolVersion;
    fn epoch_start_timestamp_ms(&self) -> u64;
    fn epoch_duration_ms(&self) -> u64;
    fn get_ika_committee_with_network_metadata(&self) -> CommitteeWithNetworkMetadata;
    fn get_ika_committee(&self) -> Committee;
    fn get_consensus_committee(&self) -> ConsensusCommittee;
    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo>;
    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId>;
    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String>;
    fn get_ika_validators(&self) -> Vec<EpochStartValidatorInfo>;
}

/// This type captures the minimum amount of information from `System` needed by a validator
/// to run the protocol. This allows us to decouple from the actual `System` type, and hence
/// do not need to evolve it when we upgrade the `System` type.
/// Evolving EpochStartSystem is also a lot easier in that we could add optional fields
/// and fill them with None for older versions. When we absolutely must delete fields, we could
/// also add new db tables to store the new version. This is OK because we only store one copy of
/// this as part of EpochStartConfiguration for the most recent epoch in the db.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[enum_dispatch(EpochStartSystemTrait)]
pub enum EpochStartSystem {
    V1(EpochStartSystemV1),
    V2(EpochStartSystemV2),
}

impl EpochStartSystem {
    pub fn new_v1(
        epoch: EpochId,
        protocol_version: u64,
        epoch_start_timestamp_ms: u64,
        epoch_duration_ms: u64,
        active_validators: Vec<EpochStartValidatorInfoV1>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        Self::V1(EpochStartSystemV1 {
            epoch,
            protocol_version,
            epoch_start_timestamp_ms,
            epoch_duration_ms,
            active_validators,
            quorum_threshold,
            validity_threshold,
        })
    }

    /// V2 additionally records that this epoch's committee uses
    /// consensus-basis authority names.
    pub fn new_v2(
        epoch: EpochId,
        protocol_version: u64,
        epoch_start_timestamp_ms: u64,
        epoch_duration_ms: u64,
        active_validators: Vec<EpochStartValidatorInfoV1>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        Self::V2(EpochStartSystemV2 {
            epoch,
            protocol_version,
            epoch_start_timestamp_ms,
            epoch_duration_ms,
            active_validators,
            quorum_threshold,
            validity_threshold,
            consensus_key_identity: true,
        })
    }

    pub fn new_for_testing_with_epoch(epoch: EpochId) -> Self {
        Self::V1(EpochStartSystemV1::new_for_testing_with_epoch(epoch))
    }

    pub fn new_at_next_epoch_for_testing(&self) -> Self {
        // Only need to support the latest version for testing.
        match self {
            Self::V1(state) => Self::V1(EpochStartSystemV1 {
                epoch: state.epoch + 1,
                protocol_version: state.protocol_version,
                epoch_start_timestamp_ms: state.epoch_start_timestamp_ms,
                epoch_duration_ms: state.epoch_duration_ms,
                active_validators: state.active_validators.clone(),
                quorum_threshold: 0,
                validity_threshold: 0,
            }),
            Self::V2(state) => Self::V2(EpochStartSystemV2 {
                epoch: state.epoch + 1,
                protocol_version: state.protocol_version,
                epoch_start_timestamp_ms: state.epoch_start_timestamp_ms,
                epoch_duration_ms: state.epoch_duration_ms,
                active_validators: state.active_validators.clone(),
                quorum_threshold: 0,
                validity_threshold: 0,
                consensus_key_identity: state.consensus_key_identity,
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct EpochStartSystemV1 {
    epoch: EpochId,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    active_validators: Vec<EpochStartValidatorInfoV1>,
    quorum_threshold: u64,
    validity_threshold: u64,
}

/// V1 plus the epoch's authority-name identity basis.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct EpochStartSystemV2 {
    epoch: EpochId,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    active_validators: Vec<EpochStartValidatorInfoV1>,
    quorum_threshold: u64,
    validity_threshold: u64,
    /// Whether this epoch's committee derives members' `AuthorityName` from
    /// the consensus key. Always `true` in records this binary writes —
    /// the basis it distinguished flipped at protocol version 6, below this
    /// binary's minimum. Kept because it is part of the persisted BCS shape
    /// a v1.2.7 binary reads back after a downgrade.
    consensus_key_identity: bool,
}

impl EpochStartSystemV1 {
    pub fn new_for_testing() -> Self {
        Self::new_for_testing_with_epoch(0)
    }

    pub fn new_for_testing_with_epoch(epoch: EpochId) -> Self {
        Self {
            epoch,
            protocol_version: ProtocolVersion::MAX.as_u64(),
            epoch_start_timestamp_ms: 0,
            epoch_duration_ms: 1000,
            active_validators: vec![],
            quorum_threshold: 0,
            validity_threshold: 0,
        }
    }
}

/// A validator's `AuthorityName`: its consensus Ed25519 key, the raw 32 bytes.
/// The BLS protocol key was the identity basis through protocol version 5 and
/// is below this binary's minimum, so the consensus key is the only basis a
/// supported epoch uses. The BLS key stays on `Committee` for
/// aggregate-certificate (checkpoint) verification.
pub fn validator_authority_name(validator: &EpochStartValidatorInfoV1) -> AuthorityName {
    AuthorityName::from_consensus_key(&validator.consensus_pubkey)
}

fn build_committee_with_network_metadata(
    epoch: EpochId,
    active_validators: &[EpochStartValidatorInfoV1],
) -> CommitteeWithNetworkMetadata {
    let validators = active_validators
        .iter()
        .map(|validator| {
            // No validator MPC key material is carried here. The
            // `class_groups_public_key_and_proof` field this used to decode
            // out of the on-chain `mpc_data_bytes` had no reader anywhere in
            // the workspace, and that field is deprecated (#2119) — a
            // validator may register with placeholder bytes. Every consumer
            // of validator key material takes it from the off-chain
            // announcement pipeline instead.
            let name = validator_authority_name(validator);

            (
                name,
                (
                    validator.voting_power,
                    NetworkMetadata {
                        name: validator.name.clone(),
                        network_address: validator.network_address.clone(),
                        consensus_address: validator.consensus_address.clone(),
                        network_public_key: Some(validator.network_pubkey.clone()),
                    },
                ),
            )
        })
        .collect();

    CommitteeWithNetworkMetadata::new(epoch, validators)
}

fn build_ika_committee(
    epoch: EpochId,
    active_validators: &[EpochStartValidatorInfoV1],
    quorum_threshold: u64,
    validity_threshold: u64,
) -> Committee {
    let voting_rights = active_validators
        .iter()
        .map(|validator| (validator_authority_name(validator), validator.voting_power))
        .collect();

    // EMPTY, deliberately. `Committee.class_groups_public_keys_and_proofs`
    // used to be filled here by decoding every active member's on-chain
    // `mpc_data_bytes`. That field is deprecated (#2119) — a validator may
    // register with placeholder bytes — and the map has no production reader:
    //   * the MPC manager starts from `ValidatorMpcKeysByPartyId::empty()` and
    //     takes ALL validator key material, class-groups included, from the
    //     off-chain bundles (`ika-core/src/dwallet_mpc/mpc_manager.rs`,
    //     `get_validator_mpc_keys_by_party_id`);
    //   * the reconfiguration public input reads a `Committee` only for its
    //     access structure — voting weights and thresholds
    //     (`mpc_computations/reconfiguration.rs::generate_public_input`);
    //   * `Committee::class_groups_public_key_and_proof` has no caller.
    // Decoding a placeholder would have logged a decode error per member per
    // epoch on every node — a chain-read defect that isn't one.
    //
    // The field itself stays: `Committee` is persisted in `committee_map` and
    // mirrored positionally by `LegacyCommittee`, so removing it is a storage
    // format change, not a cleanup. See the PR for #2119.
    let class_groups_public_keys_and_proofs = HashMap::new();

    // Carry each validator's consensus Ed25519 key as committee data so
    // consensus-key-signed messages (handoff certs) can be verified by name
    // without a side provider.
    let consensus_keys = active_validators
        .iter()
        .map(|validator| {
            (
                validator_authority_name(validator),
                validator.consensus_pubkey.clone(),
            )
        })
        .collect();

    // The BLS protocol keys are carried explicitly from the chain read
    // rather than decoded from the names: a consensus-basis name does not
    // contain the BLS key.
    let protocol_keys = active_validators
        .iter()
        .map(|validator| {
            (
                validator_authority_name(validator),
                validator.protocol_pubkey.clone(),
            )
        })
        .collect();

    Committee::new_with_protocol_keys(
        epoch,
        voting_rights,
        class_groups_public_keys_and_proofs,
        consensus_keys,
        protocol_keys,
        quorum_threshold,
        validity_threshold,
    )
}

fn build_consensus_committee(
    epoch: EpochId,
    active_validators: &[EpochStartValidatorInfoV1],
    quorum_threshold: u64,
    validity_threshold: u64,
) -> ConsensusCommittee {
    let ika_committee = build_ika_committee(
        epoch,
        active_validators,
        quorum_threshold,
        validity_threshold,
    );
    let mut authorities = vec![];
    for (i, (name, stake)) in ika_committee.members().enumerate() {
        let active_validator = &active_validators[i];
        let expected_name = validator_authority_name(active_validator);
        if *name != expected_name {
            error!(
                "Mismatched authority order between Ika and Mysticeti! Index {}, Mysticeti authority {:?}\nIka authority name {:?}",
                i, name, expected_name
            );
        }
        authorities.push(Authority {
            stake: *stake as consensus_config::Stake,
            address: active_validator.consensus_address.clone(),
            hostname: active_validator.hostname.clone(),
            // Mysticeti's own authority label stays derived from the BLS
            // protocol key — it is Sui's consensus-config
            // namespace, not ika's `AuthorityName`, and the consensus layer
            // authenticates via `protocol_key` (the Ed25519 consensus key)
            // regardless.
            authority_name: consensus_config::AuthorityName::from_bytes(
                &[
                    [0u8; 48],
                    active_validator.protocol_pubkey.pubkey.to_bytes(),
                ]
                .concat(),
            ),
            protocol_key: consensus_config::ProtocolPublicKey::new(
                active_validator.consensus_pubkey.clone(),
            ),
            network_key: consensus_config::NetworkPublicKey::new(
                active_validator.network_pubkey.clone(),
            ),
        });
    }

    ConsensusCommittee::new(epoch as consensus_config::Epoch, authorities)
}

fn build_validator_p2p_peers(
    active_validators: &[EpochStartValidatorInfoV1],
    excluding_self: AuthorityName,
) -> Vec<PeerInfo> {
    active_validators
        .iter()
        .filter(|validator| validator_authority_name(validator) != excluding_self)
        .map(|validator| {
            let address = validator
                .p2p_address
                .to_anemo_address()
                .into_iter()
                .collect::<Vec<_>>();
            let peer_id = PeerId(validator.network_pubkey.0.to_bytes());
            if address.is_empty() {
                warn!(
                    ?peer_id,
                    "Peer has invalid p2p address: {}", &validator.p2p_address
                );
            }
            PeerInfo {
                peer_id,
                affinity: PeerAffinity::High,
                address,
            }
        })
        .collect()
}

fn build_authority_names_to_peer_ids(
    active_validators: &[EpochStartValidatorInfoV1],
) -> HashMap<AuthorityName, PeerId> {
    active_validators
        .iter()
        .map(|validator| {
            let name = validator_authority_name(validator);
            let peer_id = PeerId(validator.network_pubkey.0.to_bytes());

            (name, peer_id)
        })
        .collect()
}

fn build_authority_names_to_hostnames(
    active_validators: &[EpochStartValidatorInfoV1],
) -> HashMap<AuthorityName, String> {
    active_validators
        .iter()
        .map(|validator| {
            let name = validator_authority_name(validator);
            let hostname = validator.hostname.clone();

            (name, hostname)
        })
        .collect()
}

impl EpochStartSystemTrait for EpochStartSystemV1 {
    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::new(self.protocol_version)
    }

    fn epoch_start_timestamp_ms(&self) -> u64 {
        self.epoch_start_timestamp_ms
    }

    fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    fn get_ika_committee_with_network_metadata(&self) -> CommitteeWithNetworkMetadata {
        build_committee_with_network_metadata(self.epoch, &self.active_validators)
    }

    fn get_ika_committee(&self) -> Committee {
        build_ika_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
        )
    }

    fn get_consensus_committee(&self) -> ConsensusCommittee {
        build_consensus_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
        )
    }

    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo> {
        build_validator_p2p_peers(&self.active_validators, excluding_self)
    }

    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId> {
        build_authority_names_to_peer_ids(&self.active_validators)
    }

    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String> {
        build_authority_names_to_hostnames(&self.active_validators)
    }

    fn get_ika_validators(&self) -> Vec<EpochStartValidatorInfo> {
        self.active_validators
            .iter()
            .map(|validator| EpochStartValidatorInfo::V1(validator.clone()))
            .collect()
    }
}

impl EpochStartSystemTrait for EpochStartSystemV2 {
    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::new(self.protocol_version)
    }

    fn epoch_start_timestamp_ms(&self) -> u64 {
        self.epoch_start_timestamp_ms
    }

    fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    fn get_ika_committee_with_network_metadata(&self) -> CommitteeWithNetworkMetadata {
        build_committee_with_network_metadata(self.epoch, &self.active_validators)
    }

    fn get_ika_committee(&self) -> Committee {
        build_ika_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
        )
    }

    fn get_consensus_committee(&self) -> ConsensusCommittee {
        build_consensus_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
        )
    }

    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo> {
        build_validator_p2p_peers(&self.active_validators, excluding_self)
    }

    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId> {
        build_authority_names_to_peer_ids(&self.active_validators)
    }

    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String> {
        build_authority_names_to_hostnames(&self.active_validators)
    }

    fn get_ika_validators(&self) -> Vec<EpochStartValidatorInfo> {
        self.active_validators
            .iter()
            .map(|validator| EpochStartValidatorInfo::V1(validator.clone()))
            .collect()
    }
}

#[enum_dispatch]
pub trait EpochStartValidatorInfoTrait {
    /// The validator's BLS protocol key. This is NOT the committee identity —
    /// that is [`AuthorityName`], the Ed25519 consensus key. The raw validator
    /// records are a separate name space, keyed by the BLS key, and conflating
    /// the two is how a lookup silently finds nobody.
    fn protocol_pubkey_bytes(&self) -> AuthorityPublicKeyBytes;
    fn get_name(&self) -> String;
    fn get_network_pubkey(&self) -> NetworkPublicKey;
    fn get_consensus_pubkey(&self) -> NetworkPublicKey;
    fn get_mpc_data(&self) -> Option<VersionedMPCData>;
}

#[enum_dispatch(EpochStartValidatorInfoTrait)]
pub enum EpochStartValidatorInfo {
    V1(EpochStartValidatorInfoV1),
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct EpochStartValidatorInfoV1 {
    pub validator_id: ObjectID,
    pub protocol_pubkey: AuthorityPublicKey,
    pub network_pubkey: NetworkPublicKey,
    pub consensus_pubkey: NetworkPublicKey,
    pub mpc_data: Option<VersionedMPCData>,
    pub network_address: Multiaddr,
    pub p2p_address: Multiaddr,
    pub consensus_address: Multiaddr,
    pub voting_power: StakeUnit,
    pub hostname: String,
    pub name: String,
}

impl EpochStartValidatorInfoTrait for EpochStartValidatorInfoV1 {
    fn protocol_pubkey_bytes(&self) -> AuthorityPublicKeyBytes {
        (&self.protocol_pubkey).into()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_network_pubkey(&self) -> NetworkPublicKey {
        self.network_pubkey.clone()
    }

    fn get_consensus_pubkey(&self) -> NetworkPublicKey {
        self.consensus_pubkey.clone()
    }

    fn get_mpc_data(&self) -> Option<VersionedMPCData> {
        self.mpc_data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_with(epoch: EpochId) -> EpochStartSystem {
        EpochStartSystem::new_v2(epoch, 6, 0, 1000, vec![], 0, 0)
    }

    /// A V1 record's BCS bytes must keep decoding after the V2 variant was
    /// added (old persisted EpochStartConfiguration records).
    #[test]
    fn v1_bcs_round_trip_survives_v2_addition() {
        let v1 = EpochStartSystem::new_for_testing_with_epoch(7);
        let bytes = bcs::to_bytes(&v1).unwrap();
        let decoded: EpochStartSystem = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, v1);
        assert_eq!(decoded.epoch(), 7);
    }

    #[test]
    fn v2_bcs_round_trip() {
        let v2 = v2_with(9);
        let bytes = bcs::to_bytes(&v2).unwrap();
        let decoded: EpochStartSystem = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, v2);
    }

    fn validator_with_mpc_data(
        index: u8,
        mpc_data: Option<VersionedMPCData>,
    ) -> EpochStartValidatorInfoV1 {
        use crate::crypto::{AuthorityKeyPair, NetworkKeyPair, get_key_pair_from_rng};
        use fastcrypto::traits::KeyPair;
        let protocol: AuthorityKeyPair = get_key_pair_from_rng(&mut rand::rngs::OsRng).1;
        let network: NetworkKeyPair = get_key_pair_from_rng(&mut rand::rngs::OsRng).1;
        let consensus: NetworkKeyPair = get_key_pair_from_rng(&mut rand::rngs::OsRng).1;
        let address: Multiaddr = "/ip4/127.0.0.1/udp/8080".parse().unwrap();
        EpochStartValidatorInfoV1 {
            validator_id: ObjectID::random(),
            protocol_pubkey: protocol.public().clone(),
            network_pubkey: network.public().clone(),
            consensus_pubkey: consensus.public().clone(),
            mpc_data,
            network_address: address.clone(),
            p2p_address: address.clone(),
            consensus_address: address,
            voting_power: 2_500,
            hostname: format!("validator-{index}"),
            name: format!("validator-{index}"),
        }
    }

    /// #2119: the on-chain `mpc_data_bytes` field is deprecated, and a
    /// validator may register with placeholder bytes. Building the epoch's
    /// committee from an `EpochStartSystem` must not depend on it — not for
    /// its own liveness, and not by logging a per-member decode error every
    /// epoch on every node for what is a legitimate registration.
    ///
    /// Membership, stake and thresholds stay chain-true; the class-groups
    /// map is empty because ALL validator key material now comes from the
    /// off-chain announcement pipeline.
    #[test]
    fn committee_build_ignores_placeholder_on_chain_mpc_data() {
        let placeholder = VersionedMPCData::V1(dwallet_mpc_types::dwallet_mpc::MPCDataV1 {
            mpc_data_bytes: b"ika-placeholder-mpc-data".to_vec(),
        });
        let validators = vec![
            // A placeholder registration — the post-#2119 shape.
            validator_with_mpc_data(0, Some(placeholder)),
            // Empty bytes: the other plausible placeholder (an empty TableVec).
            validator_with_mpc_data(
                1,
                Some(VersionedMPCData::V1(
                    dwallet_mpc_types::dwallet_mpc::MPCDataV1 {
                        mpc_data_bytes: Vec::new(),
                    },
                )),
            ),
            // No record at all.
            validator_with_mpc_data(2, None),
        ];
        let expected_names: Vec<_> = validators.iter().map(validator_authority_name).collect();

        let system = EpochStartSystem::new_v2(4, 7, 0, 1000, validators, 6_667, 3_334);
        let committee = system.get_ika_committee();

        assert_eq!(committee.epoch, 4);
        assert_eq!(committee.quorum_threshold, 6_667);
        assert_eq!(committee.validity_threshold, 3_334);
        for name in &expected_names {
            assert!(
                committee.voting_rights.iter().any(|(n, _)| n == name),
                "every active validator keeps its seat and stake regardless of \
                 what its deprecated on-chain mpc_data record contains"
            );
        }
        assert!(
            committee.class_groups_public_keys_and_proofs.is_empty(),
            "no validator key material is sourced from the deprecated chain field"
        );
        // The chain-derived network metadata carries no key material either.
        let with_metadata = system.get_ika_committee_with_network_metadata();
        assert_eq!(with_metadata.validators().len(), expected_names.len());
    }
}
