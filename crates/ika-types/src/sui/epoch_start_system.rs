// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use enum_dispatch::enum_dispatch;
use std::collections::HashMap;

use crate::committee::{
    ClassGroupsEncryptionKeyAndProof, Committee, CommitteeWithNetworkMetadata, NetworkMetadata,
    StakeUnit,
};
use crate::crypto::{AuthorityName, AuthorityPublicKey, NetworkPublicKey};
use anemo::PeerId;
use anemo::types::{PeerAffinity, PeerInfo};
use consensus_config::{Authority, Committee as ConsensusCommittee};
use dwallet_mpc_types::dwallet_mpc::{MPCDataTrait, VersionedMPCData};
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
    /// The on-chain authority-name flip epoch this record was built with
    /// (`None` for V1 records and unarmed networks). Committees OF epochs
    /// `>=` this value use consensus-basis authority names.
    fn authority_name_flip_epoch(&self) -> Option<EpochId>;
    /// Whether THIS epoch's committee uses consensus-basis authority names.
    fn consensus_key_identity(&self) -> bool;
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

    /// V2 additionally carries the on-chain authority-name flip epoch, from
    /// which the epoch's identity basis is decided (see
    /// [`EpochStartSystemV2::consensus_key_identity`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new_v2(
        epoch: EpochId,
        protocol_version: u64,
        epoch_start_timestamp_ms: u64,
        epoch_duration_ms: u64,
        active_validators: Vec<EpochStartValidatorInfoV1>,
        quorum_threshold: u64,
        validity_threshold: u64,
        authority_name_flip_epoch: Option<EpochId>,
    ) -> Self {
        Self::V2(EpochStartSystemV2 {
            epoch,
            protocol_version,
            epoch_start_timestamp_ms,
            epoch_duration_ms,
            active_validators,
            quorum_threshold,
            validity_threshold,
            authority_name_flip_epoch,
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
                authority_name_flip_epoch: state.authority_name_flip_epoch,
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

/// V1 plus the on-chain authority-name flip epoch. Persisted V1 records
/// (written by pre-flip binaries) always describe pre-flip epochs, so V1's
/// trait impl keeps the BLS identity basis unconditionally.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct EpochStartSystemV2 {
    epoch: EpochId,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    active_validators: Vec<EpochStartValidatorInfoV1>,
    quorum_threshold: u64,
    validity_threshold: u64,
    /// The on-chain marker (`ika_system::system_inner`, `extra_fields`):
    /// committees OF epochs `>=` this value derive members' `AuthorityName`
    /// from the consensus key. `None` while the network has not reached the
    /// arming protocol version.
    authority_name_flip_epoch: Option<EpochId>,
}

impl EpochStartSystemV2 {
    /// Whether THIS epoch's committee uses consensus-basis authority names.
    /// Decided solely by the persisted on-chain marker — never by the
    /// protocol version, which the producing and consuming sides of an
    /// epoch boundary can see differently.
    fn consensus_key_identity(&self) -> bool {
        self.authority_name_flip_epoch
            .is_some_and(|flip_epoch| self.epoch >= flip_epoch)
    }
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

/// A validator's `AuthorityName` under the given identity basis: the
/// zero-padded consensus Ed25519 key when `consensus_key_identity`, the BLS
/// protocol key otherwise. The basis is decided per epoch from the on-chain
/// flip marker (see [`EpochStartSystemV2::consensus_key_identity`]).
pub fn validator_authority_name(
    validator: &EpochStartValidatorInfoV1,
    consensus_key_identity: bool,
) -> AuthorityName {
    if consensus_key_identity {
        AuthorityName::from_consensus_key(&validator.consensus_pubkey)
    } else {
        (&validator.protocol_pubkey).into()
    }
}

fn build_committee_with_network_metadata(
    epoch: EpochId,
    active_validators: &[EpochStartValidatorInfoV1],
    consensus_key_identity: bool,
) -> CommitteeWithNetworkMetadata {
    let validators = active_validators
        .iter()
        .map(|validator| {
            // Chain reads decode the mainnet-v1.1.8 bare
            // `ClassGroupsEncryptionKeyAndProof` shape exclusively. The
            // off-chain-only PVSS / VSS HPKE keys are not carried on the
            // chain-derived metadata; they reach the MPC manager via the
            // off-chain key channels.
            let name = validator_authority_name(validator, consensus_key_identity);
            let class_groups_public_key_and_proof =
                validator.mpc_data.as_ref().and_then(|mpc_data| {
                    bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(&mpc_data.mpc_data_bytes())
                        .map_err(|e| {
                            error!(
                                authority = ?name,
                                error = ?e,
                                "Failed to decode mainnet-v1.1.8 ClassGroupsEncryptionKeyAndProof \
                                 from Move-side mpc_data"
                            );
                        })
                        .ok()
                });

            (
                name,
                (
                    validator.voting_power,
                    NetworkMetadata {
                        name: validator.name.clone(),
                        network_address: validator.network_address.clone(),
                        consensus_address: validator.consensus_address.clone(),
                        network_public_key: Some(validator.network_pubkey.clone()),
                        class_groups_public_key_and_proof,
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
    consensus_key_identity: bool,
) -> Committee {
    let voting_rights = active_validators
        .iter()
        .map(|validator| {
            (
                validator_authority_name(validator, consensus_key_identity),
                validator.voting_power,
            )
        })
        .collect();

    // Chain reads decode the mainnet-v1.1.8 bare
    // `ClassGroupsEncryptionKeyAndProof` shape exclusively — the only
    // validator MPC key on `Committee`. The off-chain-only PVSS / VSS HPKE
    // keys reach the MPC manager via the off-chain key channels, not here.
    let class_groups_public_keys_and_proofs = active_validators
        .iter()
        .filter_map(|validator| {
            let name = validator_authority_name(validator, consensus_key_identity);
            let Some(mpc_data) = validator.mpc_data.as_ref() else {
                // The fetch (`get_epoch_start_system`) fails the whole read
                // when an active member's record is missing, so this arm is
                // reachable only from a degraded `EpochStartSystem` persisted
                // before that gate existed. Loud because the built committee
                // then silently drops this member from every MPC public input
                // seeded from it (the class-groups map must never be partial
                // for a non-excluded member).
                error!(
                    should_never_happen = true,
                    authority = ?name,
                    "active committee member has no mpc_data record in the \
                     persisted EpochStartSystem; its class-groups key is \
                     missing from the committee"
                );
                return None;
            };
            match bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(&mpc_data.mpc_data_bytes()) {
                Ok(k) => Some((name, k)),
                Err(e) => {
                    error!(
                        authority = ?name,
                        error = ?e,
                        "Failed to decode mainnet-v1.1.8 ClassGroupsEncryptionKeyAndProof from Move-side mpc_data"
                    );
                    None
                }
            }
        })
        .collect();

    // Carry each validator's consensus Ed25519 key as committee data so
    // consensus-key-signed messages (handoff certs) can be verified by name
    // without a side provider.
    let consensus_keys = active_validators
        .iter()
        .map(|validator| {
            (
                validator_authority_name(validator, consensus_key_identity),
                validator.consensus_pubkey.clone(),
            )
        })
        .collect();

    // The BLS protocol keys are carried explicitly from the chain read
    // rather than decoded from the names: a consensus-basis name does not
    // contain the BLS key. Under the BLS basis the carried map is identical
    // to what decoding the names would produce.
    let protocol_keys = active_validators
        .iter()
        .map(|validator| {
            (
                validator_authority_name(validator, consensus_key_identity),
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
    consensus_key_identity: bool,
) -> ConsensusCommittee {
    let ika_committee = build_ika_committee(
        epoch,
        active_validators,
        quorum_threshold,
        validity_threshold,
        consensus_key_identity,
    );
    let mut authorities = vec![];
    for (i, (name, stake)) in ika_committee.members().enumerate() {
        let active_validator = &active_validators[i];
        let expected_name = validator_authority_name(active_validator, consensus_key_identity);
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
            // protocol key in both bases — it is Sui's consensus-config
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
    consensus_key_identity: bool,
) -> Vec<PeerInfo> {
    active_validators
        .iter()
        .filter(|validator| {
            validator_authority_name(validator, consensus_key_identity) != excluding_self
        })
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
    consensus_key_identity: bool,
) -> HashMap<AuthorityName, PeerId> {
    active_validators
        .iter()
        .map(|validator| {
            let name = validator_authority_name(validator, consensus_key_identity);
            let peer_id = PeerId(validator.network_pubkey.0.to_bytes());

            (name, peer_id)
        })
        .collect()
}

fn build_authority_names_to_hostnames(
    active_validators: &[EpochStartValidatorInfoV1],
    consensus_key_identity: bool,
) -> HashMap<AuthorityName, String> {
    active_validators
        .iter()
        .map(|validator| {
            let name = validator_authority_name(validator, consensus_key_identity);
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
        build_committee_with_network_metadata(self.epoch, &self.active_validators, false)
    }

    fn get_ika_committee(&self) -> Committee {
        build_ika_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
            false,
        )
    }

    fn get_consensus_committee(&self) -> ConsensusCommittee {
        build_consensus_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
            false,
        )
    }

    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo> {
        build_validator_p2p_peers(&self.active_validators, excluding_self, false)
    }

    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId> {
        build_authority_names_to_peer_ids(&self.active_validators, false)
    }

    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String> {
        build_authority_names_to_hostnames(&self.active_validators, false)
    }

    fn get_ika_validators(&self) -> Vec<EpochStartValidatorInfo> {
        self.active_validators
            .iter()
            .map(|validator| EpochStartValidatorInfo::V1(validator.clone()))
            .collect()
    }

    fn authority_name_flip_epoch(&self) -> Option<EpochId> {
        // V1 records were written by binaries that predate the flip; they
        // always describe pre-flip epochs.
        None
    }

    fn consensus_key_identity(&self) -> bool {
        false
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
        build_committee_with_network_metadata(
            self.epoch,
            &self.active_validators,
            self.consensus_key_identity(),
        )
    }

    fn get_ika_committee(&self) -> Committee {
        build_ika_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
            self.consensus_key_identity(),
        )
    }

    fn get_consensus_committee(&self) -> ConsensusCommittee {
        build_consensus_committee(
            self.epoch,
            &self.active_validators,
            self.quorum_threshold,
            self.validity_threshold,
            self.consensus_key_identity(),
        )
    }

    fn get_validator_as_p2p_peers(&self, excluding_self: AuthorityName) -> Vec<PeerInfo> {
        build_validator_p2p_peers(
            &self.active_validators,
            excluding_self,
            self.consensus_key_identity(),
        )
    }

    fn get_authority_names_to_peer_ids(&self) -> HashMap<AuthorityName, PeerId> {
        build_authority_names_to_peer_ids(&self.active_validators, self.consensus_key_identity())
    }

    fn get_authority_names_to_hostnames(&self) -> HashMap<AuthorityName, String> {
        build_authority_names_to_hostnames(&self.active_validators, self.consensus_key_identity())
    }

    fn get_ika_validators(&self) -> Vec<EpochStartValidatorInfo> {
        self.active_validators
            .iter()
            .map(|validator| EpochStartValidatorInfo::V1(validator.clone()))
            .collect()
    }

    fn authority_name_flip_epoch(&self) -> Option<EpochId> {
        self.authority_name_flip_epoch
    }

    fn consensus_key_identity(&self) -> bool {
        EpochStartSystemV2::consensus_key_identity(self)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_with(epoch: EpochId, flip_epoch: Option<EpochId>) -> EpochStartSystem {
        EpochStartSystem::new_v2(epoch, 6, 0, 1000, vec![], 0, 0, flip_epoch)
    }

    /// The basis rule: consensus-key identity iff the marker is set and the
    /// record's epoch has reached it — never a protocol-version comparison.
    #[test]
    fn consensus_key_identity_follows_the_marker() {
        assert!(!v2_with(10, None).consensus_key_identity());
        assert!(!v2_with(4, Some(5)).consensus_key_identity());
        assert!(v2_with(5, Some(5)).consensus_key_identity());
        assert!(v2_with(9, Some(5)).consensus_key_identity());
    }

    /// V1 records were written by pre-flip binaries and always describe
    /// pre-flip epochs.
    #[test]
    fn v1_records_are_always_bls_basis() {
        let v1 = EpochStartSystem::new_for_testing_with_epoch(42);
        assert!(!v1.consensus_key_identity());
        assert_eq!(v1.authority_name_flip_epoch(), None);
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
        let v2 = v2_with(9, Some(5));
        let bytes = bcs::to_bytes(&v2).unwrap();
        let decoded: EpochStartSystem = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, v2);
        assert!(decoded.consensus_key_identity());
    }
}
