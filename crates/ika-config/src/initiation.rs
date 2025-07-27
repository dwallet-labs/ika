// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::committee::ProtocolVersion;
use ika_types::ika_coin::INKU_PER_IKA;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Minimum number of active validators at any moment.
/// We do not allow the number of validators in any epoch to go below this.
pub const MIN_VALIDATOR_COUNT: u64 = 4;

/// Maximum number of active validators at any moment.
/// We do not allow the number of validators in any epoch to go above this.
pub const MAX_VALIDATOR_COUNT: u64 = 102;

/// Lower-bound on the amount of stake required to become a validator.
/// 30 million IKA.
pub const MIN_VALIDATOR_JOINING_STAKE_INKU: u64 = 30_000_000 * INKU_PER_IKA;

/// Maximum number of validator changes allowed in an epoch (be added or removed).
pub const MAX_VALIDATOR_CHANGE_COUNT: u64 = 10;

/// How many rewards are slashed to punish a validator, in BPS (Basis Points).
pub const REWARD_SLASHING_RATE: u16 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InitiationParameters {
    /// Protocol version that the chain starts at.
    #[serde(default = "InitiationParameters::default_protocol_version")]
    pub protocol_version: u64,

    #[serde(default = "InitiationParameters::default_chain_start_timestamp_ms")]
    pub chain_start_timestamp_ms: u64,

    /// The duration of an epoch, in milliseconds.
    #[serde(default = "InitiationParameters::default_epoch_duration_ms")]
    pub epoch_duration_ms: u64,

    // Stake Subsidy parameters
    /// The starting epoch in which stake subsidies start being paid out.
    #[serde(default = "InitiationParameters::default_stake_subsidy_start_epoch")]
    pub stake_subsidy_start_epoch: u64,

    /// The rate at which the amount per distribution is calculated based on
    /// period nad total supply. Expressed in basis points.
    #[serde(default = "InitiationParameters::default_stake_subsidy_rate")]
    pub stake_subsidy_rate: u16,

    /// The Number of distributions to occur before the amount per distribution will be recalculated.
    #[serde(default = "InitiationParameters::default_stake_subsidy_period_length")]
    pub stake_subsidy_period_length: u64,

    // Validator committee parameters
    /// Minimum number of active validators at any moment.
    #[serde(default = "InitiationParameters::default_min_validator_count")]
    pub min_validator_count: u64,

    /// Maximum number of active validators at any moment.
    /// We do not allow the number of validators in any epoch to go above this.
    #[serde(default = "InitiationParameters::default_max_validator_count")]
    pub max_validator_count: u64,

    /// Lower-bound on the amount of stake required to become a validator.
    #[serde(default = "InitiationParameters::default_min_validator_joining_stake")]
    pub min_validator_joining_stake: u64,

    /// Maximum number of validator changes allowed in an epoch (be added or removed).
    #[serde(default = "InitiationParameters::default_max_validator_change_count")]
    pub max_validator_change_count: u64,

    /// How many rewards are slashed to punish a validator, in BPS (Basis Points).
    #[serde(default = "InitiationParameters::default_reward_slashing_rate")]
    pub reward_slashing_rate: u16,
}

impl InitiationParameters {
    pub fn new() -> Self {
        Self {
            protocol_version: Self::default_protocol_version(),
            chain_start_timestamp_ms: Self::default_chain_start_timestamp_ms(),
            epoch_duration_ms: Self::default_epoch_duration_ms(),
            stake_subsidy_start_epoch: Self::default_stake_subsidy_start_epoch(),
            stake_subsidy_rate: Self::default_stake_subsidy_rate(),
            stake_subsidy_period_length: Self::default_stake_subsidy_period_length(),
            min_validator_count: Self::default_min_validator_count(),
            max_validator_count: Self::default_max_validator_count(),
            min_validator_joining_stake: Self::default_min_validator_joining_stake(),
            max_validator_change_count: Self::default_max_validator_change_count(),
            reward_slashing_rate: Self::default_reward_slashing_rate(),
        }
    }

    fn default_protocol_version() -> u64 {
        ProtocolVersion::MAX.as_u64()
    }

    fn default_chain_start_timestamp_ms() -> u64 {
        std::time::SystemTime::now()
            // Subtract 24 hours.
            .checked_sub(Duration::from_secs(24 * 60 * 60))
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn default_epoch_duration_ms() -> u64 {
        // 24 hrs
        24 * 60 * 60 * 1000
    }

    fn default_stake_subsidy_start_epoch() -> u64 {
        1
    }

    fn default_stake_subsidy_rate() -> u16 {
        // 10%
        1000
    }

    fn default_stake_subsidy_period_length() -> u64 {
        // 1 year
        365
    }

    fn default_min_validator_count() -> u64 {
        MIN_VALIDATOR_COUNT
    }

    fn default_max_validator_count() -> u64 {
        MAX_VALIDATOR_COUNT
    }

    fn default_min_validator_joining_stake() -> u64 {
        MIN_VALIDATOR_JOINING_STAKE_INKU
    }

    fn default_max_validator_change_count() -> u64 {
        MAX_VALIDATOR_CHANGE_COUNT
    }

    fn default_reward_slashing_rate() -> u16 {
        REWARD_SLASHING_RATE
    }
}

impl Default for InitiationParameters {
    fn default() -> Self {
        Self::new()
    }
}
