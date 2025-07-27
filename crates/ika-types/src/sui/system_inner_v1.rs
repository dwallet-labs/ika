// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::{Element, ExtendedField, SystemInnerTrait};
use crate::committee::StakeUnit;
use crate::crypto::{AuthorityName, AuthorityPublicKey};
use fastcrypto::traits::ToFromBytes;
use serde::{Deserialize, Serialize};
use sui_types::balance::Balance;
use sui_types::base_types::ObjectID;
use sui_types::coin::TreasuryCap;
use sui_types::collection_types::{Bag, Table, VecMap, VecSet};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct BlsCommitteeMember {
    pub validator_id: ObjectID,
    pub protocol_pubkey: Element,
}

/// Represents the current committee in the system.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct BlsCommittee {
    pub members: Vec<BlsCommitteeMember>,
    pub aggregated_protocol_pubkey: Element,
    pub quorum_threshold: u64,
    pub validity_threshold: u64,
}

pub type ObjectTable = Table;

/// Rust version of the Move ika_system::validator_set::ValidatorSet type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorSetV1 {
    pub total_stake: u64,
    pub reward_slashing_rate: u16,
    pub validators: ObjectTable, // This now holds StakingPool objects
    pub active_committee: BlsCommittee,
    pub next_epoch_committee: Option<BlsCommittee>,
    pub previous_committee: BlsCommittee,
    pub pending_active_set: ExtendedField,
    pub validator_report_records: VecMap<ObjectID, VecSet<ObjectID>>,
    pub extra_fields: Bag,
}

/// Rust version of the Move sui::package::UpgradeCap.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct UpgradeCap {
    pub id: ObjectID,
    pub package: ObjectID,
    pub version: u64,
    pub policy: u8,
}
/// Rust version of the Move ika_common::system_object_cap::SystemObjectCap.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SystemObjectCap {
    pub id: ObjectID,
}

/// Rust version of the Move ika::ika_system::SystemInner type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SystemInnerV1 {
    pub epoch: u64,
    pub epoch_start_tx_digest: Vec<u8>,
    pub system_object_cap: SystemObjectCap,
    pub protocol_version: u64,
    pub next_protocol_version: Option<u64>,
    pub upgrade_caps: Vec<UpgradeCap>,
    pub approved_upgrades: VecMap<ObjectID, Vec<u8>>,
    pub validator_set: ValidatorSetV1,
    pub epoch_duration_ms: u64,
    pub stake_subsidy_start_epoch: u64,
    pub protocol_treasury: ProtocolTreasuryV1,
    pub epoch_start_timestamp_ms: u64,
    pub last_processed_checkpoint_sequence_number: u64,
    pub previous_epoch_last_checkpoint_sequence_number: u64,
    pub total_messages_processed: u64,
    pub remaining_rewards: Balance,
    pub authorized_protocol_cap_ids: Vec<ObjectID>,
    pub witness_approving_advance_epoch: Vec<String>,
    pub received_end_of_publish: bool,
    pub extra_fields: Bag,
    // TODO: Use getters instead of all pub.
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfo {
    pub pricing_map: VecMap<PricingInfoKey, PricingInfoValue>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoKey {
    pub curve: u32,
    pub signature_algorithm: Option<u32>,
    pub protocol: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoValue {
    pub fee_ika: u64,
    pub gas_fee_reimbursement_sui: u64,
    pub gas_fee_reimbursement_sui_for_system_calls: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingInfoCalculationVotes {
    pub bls_committee: BlsCommittee,
    pub default_pricing: PricingInfo,
    pub working_pricing: PricingInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SessionsKeeper {
    pub sessions: ObjectTable,
    pub session_events: Bag,
    pub started_sessions_count: u64,
    pub completed_sessions_count: u64,
    pub next_session_sequence_number: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SessionsManager {
    pub registered_user_session_identifiers: Table,
    pub user_sessions_keeper: SessionsKeeper,
    pub system_sessions_keeper: SessionsKeeper,
    pub last_user_initiated_session_to_complete_in_current_epoch: u64,
    pub locked_last_user_initiated_session_to_complete_in_current_epoch: bool,
    pub max_active_sessions_buffer: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SupportConfig {
    pub supported_curves_to_signature_algorithms_to_hash_schemes:
        VecMap<u32, VecMap<u32, Vec<u32>>>,
    pub paused_curves: Vec<u32>,
    pub paused_signature_algorithms: Vec<u32>,
    pub paused_hash_schemes: Vec<u32>,
    pub signature_algorithms_allowed_global_presign: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PricingAndFeeManagement {
    pub current: PricingInfo,
    pub default: PricingInfo,
    pub validator_votes: Table,
    pub calculation_votes: Option<PricingInfoCalculationVotes>,
    pub gas_fee_reimbursement_sui_system_call_value: u64,
    pub gas_fee_reimbursement_sui_system_call_balance: Balance,
    pub fee_charged_ika: Balance,
}

/// Rust version of the Move DWalletCoordinatorInner type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct DWalletCoordinatorInnerV1 {
    pub current_epoch: u64,
    pub sessions_manager: SessionsManager,
    pub dwallets: ObjectTable,
    pub dwallet_network_encryption_keys: ObjectTable,
    pub epoch_dwallet_network_encryption_keys_reconfiguration_completed: u64,
    pub encryption_keys: ObjectTable,
    pub presigns: ObjectTable,
    pub partial_centralized_signed_messages: ObjectTable,
    pub pricing_and_fee_management: PricingAndFeeManagement,
    pub active_committee: BlsCommittee,
    pub next_epoch_active_committee: Option<BlsCommittee>,
    pub total_messages_processed: u64,
    pub last_processed_checkpoint_sequence_number: u64,
    pub previous_epoch_last_checkpoint_sequence_number: u64,
    pub support_config: SupportConfig,
    pub received_end_of_publish: bool,
    pub extra_fields: Bag,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ProtocolTreasuryV1 {
    /// TreasuryCap of IKA tokens.
    pub treasury_cap: TreasuryCap,

    /// Count of the number of times stake subsidies have been distributed.
    pub stake_subsidy_distribution_counter: u64,

    /// The rate at which the amount per distribution is calculated based on
    /// period nad total supply. Expressed in basis points.
    pub stake_subsidy_rate: u16,

    /// The amount of stake subsidy to be destructured per distribution.
    /// This amount changes based on `stake_subsidy_rate`.
    pub stake_subsidy_amount_per_distribution: u64,

    /// Number of distributions to occur before the amount per distribution will be recalculated.
    pub stake_subsidy_period_length: u64,

    /// The total supply of IKA tokens at the start of the current period.
    pub total_supply_at_period_start: u64,

    /// Any extra fields that's not defined statically.
    pub extra_fields: Bag,
}

impl SystemInnerTrait for SystemInnerV1 {
    fn epoch(&self) -> u64 {
        self.epoch
    }
    fn epoch_start_tx_digest(&self) -> Vec<u8> {
        self.epoch_start_tx_digest.clone()
    }
    fn protocol_version(&self) -> u64 {
        self.protocol_version
    }

    fn next_protocol_version(&self) -> Option<u64> {
        self.next_protocol_version
    }

    fn last_processed_checkpoint_sequence_number(&self) -> u64 {
        self.last_processed_checkpoint_sequence_number
    }

    fn previous_epoch_last_checkpoint_sequence_number(&self) -> u64 {
        self.previous_epoch_last_checkpoint_sequence_number
    }

    fn upgrade_caps(&self) -> &Vec<UpgradeCap> {
        &self.upgrade_caps
    }

    fn epoch_start_timestamp_ms(&self) -> u64 {
        self.epoch_start_timestamp_ms
    }

    fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    fn get_ika_next_epoch_committee(&self) -> Option<BlsCommittee> {
        self.validator_set.next_epoch_committee.clone()
    }

    fn get_ika_active_committee(&self) -> BlsCommittee {
        self.validator_set.active_committee.clone()
    }

    fn read_bls_committee(
        &self,
        bls_committee: &BlsCommittee,
    ) -> Vec<(ObjectID, (AuthorityName, StakeUnit))> {
        bls_committee
            .members
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    (
                        // AuthorityName is derived from the protocol public key;
                        // therefore, it is safe to unwrap.
                        (&AuthorityPublicKey::from_bytes(v.protocol_pubkey.clone().bytes.as_ref())
                            .unwrap())
                            .into(),
                        1,
                    ),
                )
            })
            .collect()
    }

    fn validator_set(&self) -> &ValidatorSetV1 {
        &self.validator_set
    }
}

/// Rust version of the Move ika_system::validator_cap::ValidatorCap type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorCapV1 {
    pub id: ObjectID,
    pub validator_id: ObjectID,
}

/// Rust version of the Move ika_system::validator_cap::ValidatorOperationCap type
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ValidatorOperationCapV1 {
    pub id: ObjectID,
    pub validator_id: ObjectID,
}
