// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use enum_dispatch::enum_dispatch;
use std::collections::HashMap;

use crate::committee::{
    Committee, CommitteeWithNetworkMetadata, NetworkMetadata, StakeUnit,
    decode_validator_encryption_keys,
};
use crate::crypto::{AuthorityName, AuthorityPublicKey, NetworkPublicKey};
use anemo::PeerId;
use anemo::types::{PeerAffinity, PeerInfo};
use consensus_config::{Authority, Committee as ConsensusCommittee};
use dwallet_mpc_types::dwallet_mpc::{MPCDataTrait, VersionedMPCData};
use fastcrypto::traits::ToFromBytes;
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
        let validators = self
            .active_validators
            .iter()
            .map(|validator| {
                // Shape-tolerant decode: accepts both the mainnet-v1.1.8
                // bare-class-groups payload and the post-PR-#1707 bundle. PVSS
                // halves come back as `None` for validators publishing the old
                // shape; downstream DKG/Reconfig dispatch picks the bwd-compat
                // Party in that case.
                let (
                    class_groups_public_key_and_proof,
                    secp256k1_pvss_public_key_and_proof,
                    secp256r1_pvss_public_key_and_proof,
                    ristretto_pvss_public_key_and_proof,
                ) = match validator.mpc_data.as_ref().and_then(|mpc_data| {
                    decode_validator_encryption_keys(&mpc_data.class_groups_public_key_and_proof())
                }) {
                    Some(v) => (
                        Some(v.class_groups),
                        v.secp256k1_pvss,
                        v.secp256r1_pvss,
                        v.ristretto_pvss,
                    ),
                    None => (None, None, None, None),
                };

                (
                    validator.authority_name(),
                    (
                        validator.voting_power,
                        NetworkMetadata {
                            name: validator.name.clone(),
                            network_address: validator.network_address.clone(),
                            consensus_address: validator.consensus_address.clone(),
                            network_public_key: Some(validator.network_pubkey.clone()),
                            class_groups_public_key_and_proof,
                            secp256k1_pvss_public_key_and_proof,
                            secp256r1_pvss_public_key_and_proof,
                            ristretto_pvss_public_key_and_proof,
                        },
                    ),
                )
            })
            .collect();

        CommitteeWithNetworkMetadata::new(self.epoch, validators)
    }

    fn get_ika_committee(&self) -> Committee {
        let voting_rights = self
            .active_validators
            .iter()
            .map(|validator| (validator.authority_name(), validator.voting_power))
            .collect();

        // Shape-tolerant decode per validator. Mainnet-v1.1.8-shape payloads
        // (bare class-groups) populate only the class-groups HashMap; PVSS
        // HashMaps gain an entry only when the validator published the
        // post-PR-#1707 bundle shape.
        let decoded_per_validator: Vec<_> = self
            .active_validators
            .iter()
            .filter_map(|validator| {
                let mpc_data = validator.mpc_data.as_ref()?;
                let decoded = decode_validator_encryption_keys(
                    &mpc_data.class_groups_public_key_and_proof(),
                );
                if decoded.is_none() {
                    error!(
                        authority = ?validator.authority_name(),
                        "Failed to decode validator encryption keys (neither mainnet-v1.1.8 nor post-PR-#1707 shape)"
                    );
                }
                decoded.map(|d| (validator.authority_name(), d))
            })
            .collect();

        let class_groups_public_keys_and_proofs = decoded_per_validator
            .iter()
            .map(|(name, v)| (*name, v.class_groups.clone()))
            .collect();
        let secp256k1_pvss_public_keys_and_proofs = decoded_per_validator
            .iter()
            .filter_map(|(name, v)| v.secp256k1_pvss.clone().map(|k| (*name, k)))
            .collect();
        let secp256r1_pvss_public_keys_and_proofs = decoded_per_validator
            .iter()
            .filter_map(|(name, v)| v.secp256r1_pvss.clone().map(|k| (*name, k)))
            .collect();
        let ristretto_pvss_public_keys_and_proofs = decoded_per_validator
            .iter()
            .filter_map(|(name, v)| v.ristretto_pvss.clone().map(|k| (*name, k)))
            .collect();
        let vss_hpke_public_keys_and_proofs = decoded_per_validator
            .iter()
            .filter_map(|(name, v)| v.vss_hpke_public_key_and_proof.clone().map(|k| (*name, k)))
            .collect();

        Committee::new(
            self.epoch,
            voting_rights,
            class_groups_public_keys_and_proofs,
            secp256k1_pvss_public_keys_and_proofs,
            secp256r1_pvss_public_keys_and_proofs,
            ristretto_pvss_public_keys_and_proofs,
            vss_hpke_public_keys_and_proofs,
            self.quorum_threshold,
            self.validity_threshold,
        )
    }

    fn get_consensus_committee(&self) -> ConsensusCommittee {
        let ika_committee = self.get_ika_committee();
        let mut authorities = vec![];
        for (i, (name, stake)) in ika_committee.members().enumerate() {
            let active_validator = &self.active_validators[i];
            if name.0 != active_validator.protocol_pubkey.as_bytes() {
                error!(
                    "Mismatched authority order between Ika and Mysticeti! Index {}, Mysticeti authority {:?}\nIka authority name {:?}",
                    i,
                    name,
                    active_validator.protocol_pubkey.as_bytes()
                );
            }
            authorities.push(Authority {
                stake: *stake as consensus_config::Stake,
                address: active_validator.consensus_address.clone(),
                hostname: active_validator.hostname.clone(),
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

        ConsensusCommittee::new(self.epoch as consensus_config::Epoch, authorities)
    }

    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo> {
        self.active_validators
            .iter()
            .filter(|validator| validator.authority_name() != excluding_self)
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

    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId> {
        self.active_validators
            .iter()
            .map(|validator| {
                let name = validator.authority_name();
                let peer_id = PeerId(validator.network_pubkey.0.to_bytes());

                (name, peer_id)
            })
            .collect()
    }

    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String> {
        self.active_validators
            .iter()
            .map(|validator| {
                let name = validator.authority_name();
                let hostname = validator.hostname.clone();

                (name, hostname)
            })
            .collect()
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
    fn authority_name(&self) -> AuthorityName;
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
    fn authority_name(&self) -> AuthorityName {
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
