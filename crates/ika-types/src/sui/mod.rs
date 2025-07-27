// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::StakeUnit;
use crate::crypto::AuthorityName;
use enum_dispatch::enum_dispatch;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::TypeTag;
use move_core_types::{ident_str, identifier::IdentStr, language_storage::StructTag};
use serde::{Deserialize, Serialize};
use sui_types::base_types::ObjectID;
use sui_types::collection_types::VecMap;
use sui_types::versioned::Versioned;

pub mod epoch_start_system;
pub mod staking;
pub mod system_inner_v1;

pub use epoch_start_system::*;
pub use staking::*;
pub use system_inner_v1::*;

#[cfg(msim)]
use self::simtest_ika_system_state_inner::{
    SimTestIkaSystemStateInnerDeepV2, SimTestIkaSystemStateInnerShallowV2,
    SimTestIkaSystemStateInnerV1, SimTestValidatorDeepV2, SimTestValidatorV1,
};

/// Default computation price of 1000 NIka
pub const DEFAULT_VALIDATOR_COMPUTATION_PRICE: u64 = 1000;
/// Default commission rate of 10%
pub const DEFAULT_COMMISSION_RATE: u16 = 1000;

pub const INIT_CAP_STRUCT_NAME: &IdentStr = ident_str!("InitCap");
pub const SYSTEM_STRUCT_NAME: &IdentStr = ident_str!("System");
pub const VALIDATOR_CAP_STRUCT_NAME: &IdentStr = ident_str!("ValidatorCap");
pub const VALIDATOR_OPERATION_STRUCT_NAME: &IdentStr = ident_str!("ValidatorOperationCap");
pub const VALIDATOR_COMMISSION_STRUCT_NAME: &IdentStr = ident_str!("ValidatorCommissionCap");
pub const PROTOCOL_CAP_STRUCT_NAME: &IdentStr = ident_str!("ProtocolCap");
pub const DWALLET_COORDINATOR_STRUCT_NAME: &IdentStr = ident_str!("DWalletCoordinator");

pub const SYSTEM_MODULE_NAME: &IdentStr = ident_str!("system");
pub const INIT_MODULE_NAME: &IdentStr = ident_str!("init");
pub const VALIDATOR_CAP_MODULE_NAME: &IdentStr = ident_str!("validator_cap");
pub const PROTOCOL_CAP_MODULE_NAME: &IdentStr = ident_str!("protocol_cap");
pub const VALIDATOR_METADATA_MODULE_NAME: &IdentStr = ident_str!("validator_metadata");
pub const SYSTEM_INNER_MODULE_NAME: &IdentStr = ident_str!("system_inner");
pub const DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME: &IdentStr = ident_str!("coordinator");

pub const INITIALIZE_FUNCTION_NAME: &IdentStr = ident_str!("initialize");
pub const REQUEST_ADD_VALIDATOR_CANDIDATE_FUNCTION_NAME: &IdentStr =
    ident_str!("request_add_validator_candidate");
pub const REQUEST_ADD_VALIDATOR_FUNCTION_NAME: &IdentStr = ident_str!("request_add_validator");
pub const REQUEST_REMOVE_VALIDATOR_CANDIDATE_FUNCTION_NAME: &IdentStr =
    ident_str!("request_remove_validator_candidate");
pub const REQUEST_ADD_STAKE_FUNCTION_NAME: &IdentStr = ident_str!("request_add_stake");
pub const REQUEST_REMOVE_VALIDATOR_FUNCTION_NAME: &IdentStr =
    ident_str!("request_remove_validator");
pub const SET_NEXT_COMMISSION_FUNCTION_NAME: &IdentStr = ident_str!("set_next_commission");
pub const WITHDRAW_STAKE_FUNCTION_NAME: &IdentStr = ident_str!("withdraw_stake");
pub const REQUEST_WITHDRAW_STAKE_FUNCTION_NAME: &IdentStr = ident_str!("request_withdraw_stake");
pub const REPORT_VALIDATOR_FUNCTION_NAME: &IdentStr = ident_str!("report_validator");
pub const UNDO_REPORT_VALIDATOR_FUNCTION_NAME: &IdentStr = ident_str!("undo_report_validator");
pub const ROTATE_OPERATION_CAP_FUNCTION_NAME: &IdentStr = ident_str!("rotate_operation_cap");
pub const ROTATE_COMMISSION_CAP_FUNCTION_NAME: &IdentStr = ident_str!("rotate_commission_cap");
pub const COLLECT_COMMISSION_FUNCTION_NAME: &IdentStr = ident_str!("collect_commission");
pub const SET_VALIDATOR_NAME_FUNCTION_NAME: &IdentStr = ident_str!("set_validator_name");
pub const VALIDATOR_METADATA_FUNCTION_NAME: &IdentStr = ident_str!("validator_metadata");
pub const SET_VALIDATOR_METADATA_FUNCTION_NAME: &IdentStr = ident_str!("set_validator_metadata");
pub const SET_NEXT_EPOCH_NETWORK_ADDRESS_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_network_address");
pub const SET_NEXT_EPOCH_P2P_ADDRESS_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_p2p_address");
pub const SET_NEXT_EPOCH_CONSENSUS_ADDRESS_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_consensus_address");
pub const SET_NEXT_EPOCH_PROTOCOL_PUBKEY_BYTES_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_protocol_pubkey_bytes");
pub const SET_NEXT_EPOCH_NETWORK_PUBKEY_BYTES_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_network_pubkey_bytes");
pub const SET_NEXT_EPOCH_CONSENSUS_PUBKEY_BYTES_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_consensus_pubkey_bytes");
pub const VERIFY_VALIDATOR_CAP_FUNCTION_NAME: &IdentStr = ident_str!("verify_validator_cap");
pub const VERIFY_OPERATION_CAP_FUNCTION_NAME: &IdentStr = ident_str!("verify_operation_cap");
pub const VERIFY_COMMISSION_CAP_FUNCTION_NAME: &IdentStr = ident_str!("verify_commission_cap");
pub const PROCESS_CHECKPOINT_MESSAGE_BY_QUORUM_FUNCTION_NAME: &IdentStr =
    ident_str!("process_checkpoint_message_by_quorum");
pub const INITIATE_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME: &IdentStr =
    ident_str!("initiate_mid_epoch_reconfiguration");
pub const REQUEST_NETWORK_ENCRYPTION_KEY_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME: &IdentStr =
    ident_str!("request_network_encryption_key_mid_epoch_reconfiguration");
pub const CREATE_SYSTEM_CURRENT_STATUS_INFO_FUNCTION_NAME: &IdentStr =
    ident_str!("create_system_current_status_info");
pub const REQUEST_LOCK_EPOCH_SESSIONS_FUNCTION_NAME: &IdentStr =
    ident_str!("request_lock_epoch_sessions");
pub const INITIATE_ADVANCE_EPOCH_FUNCTION_NAME: &IdentStr = ident_str!("initiate_advance_epoch");
pub const ADVANCE_EPOCH_FUNCTION_NAME: &IdentStr = ident_str!("advance_epoch");
pub const REQUEST_DWALLET_NETWORK_DECRYPTION_KEY_DKG_BY_CAP_FUNCTION_NAME: &IdentStr =
    ident_str!("request_dwallet_network_encryption_key_dkg_by_cap");
pub const SET_SUPPORTED_AND_PRICING: &IdentStr = ident_str!("set_supported_and_pricing");
pub const SET_PRICING_VOTE_FUNCTION_NAME: &IdentStr = ident_str!("set_pricing_vote");
pub const SET_NEXT_EPOCH_MPC_DATA_BYTES_FUNCTION_NAME: &IdentStr =
    ident_str!("set_next_epoch_mpc_data_bytes");

pub const NEW_VALIDATOR_METADATA_FUNCTION_NAME: &IdentStr = ident_str!("new");

pub const TABLE_VEC_MODULE_NAME: &IdentStr = ident_str!("table_vec");
pub const TABLE_VEC_STRUCT_NAME: &IdentStr = ident_str!("TableVec");
pub const CREATE_BYTES_TABLE_VEC_FUNCTION_NAME: &IdentStr = ident_str!("empty");
pub const PUSH_BACK_TO_TABLE_VEC_FUNCTION_NAME: &IdentStr = ident_str!("push_back");
pub const DROP_TABLE_VEC_FUNCTION_NAME: &IdentStr = ident_str!("drop");

pub const VECTOR_MODULE_NAME: &IdentStr = ident_str!("vector");
pub const APPEND_VECTOR_FUNCTION_NAME: &IdentStr = ident_str!("append");

pub const OPTION_MODULE_NAME: &IdentStr = ident_str!("option");
pub const OPTION_DESTROY_NONE_FUNCTION_NAME: &IdentStr = ident_str!("destroy_none");
pub const OPTION_DESTROY_SOME_FUNCTION_NAME: &IdentStr = ident_str!("destroy_some");

pub const PRICING_MODULE_NAME: &IdentStr = ident_str!("pricing");
pub const INSERT_OR_UPDATE_PRICING_FUNCTION_NAME: &IdentStr =
    ident_str!("insert_or_update_pricing");

pub const VEC_MAP_MODULE_NAME: &IdentStr = ident_str!("vec_map");
pub const VEC_MAP_STRUCT_NAME: &IdentStr = ident_str!("VecMap");
pub const VEC_MAP_NEW_FUNCTION_NAME: &IdentStr = ident_str!("empty");
pub const VEC_MAP_INSERT_FUNCTION_NAME: &IdentStr = ident_str!("insert");
pub const VEC_MAP_FROM_KEYS_VALUES_FUNCTION_NAME: &IdentStr = ident_str!("from_keys_values");

#[cfg(msim)]
pub const IKA_SYSTEM_STATE_SIM_TEST_V1: u64 = 18446744073709551605; // u64::MAX - 10
#[cfg(msim)]
pub const IKA_SYSTEM_STATE_SIM_TEST_SHALLOW_V2: u64 = 18446744073709551606; // u64::MAX - 9
#[cfg(msim)]
pub const IKA_SYSTEM_STATE_SIM_TEST_DEEP_V2: u64 = 18446744073709551607; // u64::MAX - 8

/// Rust version of the Move ika::ika_system::IkaSystemState type
/// In Rust, this type should rarely be used since it's just a thin
/// wrapper used to access the inner object.
/// Within this module, we use it to determine the current version of the system state inner object type,
/// so that we could deserialize the inner object correctly.
/// Outside of this module, we only use it in testing.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct System {
    pub id: ObjectID,
    pub version: u64,
    pub package_id: ObjectID,
    pub new_package_id: Option<ObjectID>,
    pub migration_epoch: Option<u64>,
}

/// Rust version of the Move DWalletCoordinator type
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DWalletCoordinator {
    pub id: ObjectID,
    pub version: u64,
    pub package_id: ObjectID,
    pub new_package_id: Option<ObjectID>,
    pub migration_epoch: Option<u64>,
}

impl System {
    pub fn type_(ika_system_package_address: AccountAddress) -> StructTag {
        StructTag {
            address: ika_system_package_address,
            name: SYSTEM_STRUCT_NAME.to_owned(),
            module: SYSTEM_MODULE_NAME.to_owned(),
            type_params: vec![],
        }
    }

    pub fn type_tag(ika_system_package_address: AccountAddress) -> TypeTag {
        TypeTag::Struct(Box::new(Self::type_(ika_system_package_address)))
    }
}

/// This is the standard API that all inner system state object type should implement.
#[enum_dispatch]
pub trait SystemInnerTrait {
    fn epoch(&self) -> u64;
    fn epoch_start_tx_digest(&self) -> Vec<u8>;
    fn protocol_version(&self) -> u64;
    fn next_protocol_version(&self) -> Option<u64>;
    fn last_processed_checkpoint_sequence_number(&self) -> u64;
    fn previous_epoch_last_checkpoint_sequence_number(&self) -> u64;
    fn upgrade_caps(&self) -> &Vec<UpgradeCap>;
    fn epoch_start_timestamp_ms(&self) -> u64;
    fn epoch_duration_ms(&self) -> u64;
    fn get_ika_next_epoch_committee(&self) -> Option<BlsCommittee>;
    fn get_ika_active_committee(&self) -> BlsCommittee;
    fn read_bls_committee(
        &self,
        committee: &BlsCommittee,
    ) -> Vec<(ObjectID, (AuthorityName, StakeUnit))>;
    fn validator_set(&self) -> &ValidatorSetV1;
}

/// [`SystemInner`] provides an abstraction over multiple versions of
/// the inner [`IkaSystemStateInner`] object.
/// This should be the primary interface to the system state object in Rust.
/// We use enum dispatch to dispatch all methods defined in [`SystemInnerTrait`] to the actual
/// implementation in the inner types.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[enum_dispatch(SystemInnerTrait)]
pub enum SystemInner {
    V1(SystemInnerV1),
}

/// A wrapper around the different versions of the DWalletCoordinator.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum DWalletCoordinatorInner {
    V1(DWalletCoordinatorInnerV1),
}

/// This is the fixed type used by init.
pub type SystemInnerInit = SystemInnerV1;

impl SystemInner {
    /// Always return the version that we will be using for init.
    /// Init always uses this version regardless of the current version.
    /// Note that since it's possible for the actual init of the network to diverge from the
    /// init of the latest Rust code, it's important that we only use this for tooling purposes.
    pub fn into_init_version_for_tooling(self) -> SystemInnerInit {
        match self {
            SystemInner::V1(inner) => inner,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Element {
    bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Validator {
    pub id: ObjectID,
    pub inner: Versioned,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ExtendedField {
    pub id: ObjectID,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PendingValues {
    pub values: VecMap<u64, u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum TokenExchangeRate {
    Flat,
    Variable {
        ika_amount: u128,
        share_amount: u128,
    },
}

impl TokenExchangeRate {
    /// Rate of the staking pool, share amount: Ika amount
    pub fn rate(&self) -> f64 {
        match self {
            TokenExchangeRate::Flat => 1_f64,
            TokenExchangeRate::Variable {
                ika_amount,
                share_amount,
            } => {
                if *ika_amount == 0 {
                    1_f64
                } else {
                    *share_amount as f64 / *ika_amount as f64
                }
            }
        }
    }

    /// Create a new exchange rate with the given amounts.
    /// If both amounts are 0 or share_amount <= ika_amount, returns Flat rate.
    /// Otherwise, returns Variable rate.
    pub fn new(ika_amount: u64, share_amount: u64) -> Self {
        if ika_amount == 0 || share_amount == 0 || share_amount <= ika_amount {
            TokenExchangeRate::Flat
        } else {
            TokenExchangeRate::Variable {
                ika_amount: ika_amount as u128,
                share_amount: share_amount as u128,
            }
        }
    }
}
