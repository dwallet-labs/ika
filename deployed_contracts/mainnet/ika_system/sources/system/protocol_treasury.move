// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::protocol_treasury;

use ika::ika::IKA;
use sui::bag::{Self, Bag};
use sui::balance::Balance;
use sui::coin::TreasuryCap;

// === Errors ===

/// The stake subsidy rate is too large.
const ESubsidyDecreaseRateTooLarge: u64 = 0;

// === Constants ===

const BASIS_POINT_DENOMINATOR: u128 = 10_000;

// === Structs ===

public struct ProtocolTreasury has store {
    /// TreasuryCap of IKA tokens.
    treasury_cap: TreasuryCap<IKA>,
    /// Count of the number of times stake subsidies have been distributed.
    stake_subsidy_distribution_counter: u64,
    /// The rate at which the amount per distribution is calculated based on
    /// period nad total supply. Expressed in basis points.
    stake_subsidy_rate: u16,
    /// The amount of stake subsidy to be destructured per distribution.
    /// This amount changes based on `stake_subsidy_rate`.
    stake_subsidy_amount_per_distribution: u64,
    /// Number of distributions to occur before the amount per distribution will be recalculated.
    stake_subsidy_period_length: u64,
    /// The total supply of IKA tokens at the start of the current period.
    total_supply_at_period_start: u64,
    /// Any extra fields that's not defined statically.
    extra_fields: Bag,
}

// === Public Functions ===

public(package) fun create(
    treasury_cap: TreasuryCap<IKA>,
    stake_subsidy_rate: u16,
    stake_subsidy_period_length: u64,
    ctx: &mut TxContext,
): ProtocolTreasury {
    // Rate can't be higher than 100%.
    assert!(stake_subsidy_rate <= BASIS_POINT_DENOMINATOR as u16, ESubsidyDecreaseRateTooLarge);

    let total_supply_at_period_start = treasury_cap.total_supply();

    let stake_subsidy_amount_per_distribution = calculate_stake_subsidy_amount_per_distribution(
        total_supply_at_period_start,
        stake_subsidy_rate,
        stake_subsidy_period_length,
    );

    ProtocolTreasury {
        treasury_cap,
        stake_subsidy_distribution_counter: 0,
        stake_subsidy_rate,
        stake_subsidy_amount_per_distribution,
        stake_subsidy_period_length,
        total_supply_at_period_start,
        extra_fields: bag::new(ctx),
    }
}

/// Advance the distribution counter and return the stake subsidy.
public(package) fun stake_subsidy_for_distribution(
    self: &mut ProtocolTreasury,
    ctx: &mut TxContext,
): Balance<IKA> {
    // Mint the reward amount for this stake subsidy
    let stake_subsidy = self.treasury_cap.mint(self.stake_subsidy_amount_per_distribution, ctx);

    self.stake_subsidy_distribution_counter = self.stake_subsidy_distribution_counter + 1;

    // Recalculate subsidy amount per distribution only when the current period ends.
    if (self.stake_subsidy_distribution_counter % self.stake_subsidy_period_length == 0) {
        let total_supply_at_period_start = self.treasury_cap.total_supply();

        self.stake_subsidy_amount_per_distribution =
            calculate_stake_subsidy_amount_per_distribution(
                total_supply_at_period_start,
                self.stake_subsidy_rate,
                self.stake_subsidy_period_length,
            );
        self.total_supply_at_period_start = total_supply_at_period_start;
    };

    stake_subsidy.into_balance()
}

public(package) fun set_stake_subsidy_rate(self: &mut ProtocolTreasury, stake_subsidy_rate: u16) {
    // Rate can't be higher than 100%.
    assert!(stake_subsidy_rate <= BASIS_POINT_DENOMINATOR as u16, ESubsidyDecreaseRateTooLarge);

    // Update the stored rate
    self.stake_subsidy_rate = stake_subsidy_rate;

    // Recalculate the stake subsidy amount per distribution with the new rate
    self.stake_subsidy_amount_per_distribution =
        calculate_stake_subsidy_amount_per_distribution(
            self.total_supply_at_period_start,
            stake_subsidy_rate,
            self.stake_subsidy_period_length,
        );
}

public(package) fun set_stake_subsidy_period_length(
    self: &mut ProtocolTreasury,
    stake_subsidy_period_length: u64,
) {
    self.stake_subsidy_period_length = stake_subsidy_period_length;

    // Recalculate the stake subsidy amount per distribution with the new period length
    self.stake_subsidy_amount_per_distribution =
        calculate_stake_subsidy_amount_per_distribution(
            self.total_supply_at_period_start,
            self.stake_subsidy_rate,
            stake_subsidy_period_length,
        );
}

/// Returns the stake subsidy amount per distribution.
public fun stake_subsidy_amount_per_distribution(self: &ProtocolTreasury): u64 {
    self.stake_subsidy_amount_per_distribution
}

/// Returns the number of distributions that have occurred.
public(package) fun get_stake_subsidy_distribution_counter(self: &ProtocolTreasury): u64 {
    self.stake_subsidy_distribution_counter
}

#[test_only]
public(package) fun set_stake_subsidy_distribution_counter(
    self: &mut ProtocolTreasury,
    stake_subsidy_distribution_counter: u64,
) {
    self.stake_subsidy_distribution_counter = stake_subsidy_distribution_counter;
}

// === Private Functions ===

fun calculate_stake_subsidy_amount_per_distribution(
    total_supply_at_period_start: u64,
    stake_subsidy_rate: u16,
    stake_subsidy_period_length: u64,
): u64 {
    let stake_subsidy_total_period_distribution_amount =
        total_supply_at_period_start as u128
                * (stake_subsidy_rate as u128) / BASIS_POINT_DENOMINATOR;
    let stake_subsidy_amount_per_distribution =
        stake_subsidy_total_period_distribution_amount / (stake_subsidy_period_length as u128);
    stake_subsidy_amount_per_distribution as u64
}
