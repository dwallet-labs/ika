// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Implements the `StakedIka` functionality - a staked IKA is an object that
/// represents a staked amount of IKAs in a staking pool. It is created in the
/// `staking_pool` on staking and can be split, joined, and burned. The burning
/// is performed via the `withdraw_stake` method in the `staking_pool`.
module ika_system::staked_ika;

use ika::ika::IKA;
use sui::balance::Balance;

// === Constants ===

/// StakedIka objects must have a principal with at least this amount.
const MIN_STAKING_THRESHOLD: u64 = 1_000_000_000; // 1 IKA

// === Errors ===

/// The `StakedIka` is not in `Withdrawing` state.
const ENotWithdrawing: u64 = 0;
/// The metadata of two `StakedIka` objects does not match.
const EMetadataMismatch: u64 = 1;
/// The amount for the split is invalid.
const EInvalidAmount: u64 = 2;
/// Trying to mark stake as withdrawing when it is already marked as withdrawing.
const EAlreadyWithdrawing: u64 = 3;
/// Stake is below the minimum staking threshold.
const EStakeBelowThreshold: u64 = 4;

// === Structs ===

/// The state of the staked IKA. It can be either `Staked` or `Withdrawing`.
/// The `Withdrawing` state contains the epoch when the staked IKA can be
/// withdrawn.
public enum StakedIkaState has copy, drop, store {
    // Default state of the staked IKA - it is staked in the staking pool.
    Staked,
    // The staked IKA is in the process of withdrawing. The value inside the
    // variant is the epoch when the staked IKA can be withdrawn.
    Withdrawing { withdraw_epoch: u64 },
}

/// Represents a staked IKA, does not store the `Balance` inside, but uses
/// `u64` to represent the staked amount. Behaves similarly to `Balance` and
/// `Coin` providing methods to `split` and `join`.
public struct StakedIka has key, store {
    id: UID,
    /// Whether the staked IKA is active or withdrawing.
    state: StakedIkaState,
    /// ID of the staking pool.
    validator_id: ID,
    /// The staked amount.
    principal: Balance<IKA>,
    /// The Ikarus epoch when the staked IKA was activated.
    activation_epoch: u64,
}

// === Package Functions ===

/// Protected method to create a new staked IKA.
public(package) fun mint(
    validator_id: ID,
    principal: Balance<IKA>,
    activation_epoch: u64,
    ctx: &mut TxContext,
): StakedIka {
    assert!(principal.value() >= MIN_STAKING_THRESHOLD, EStakeBelowThreshold);
    StakedIka {
        id: object::new(ctx),
        state: StakedIkaState::Staked,
        validator_id,
        principal,
        activation_epoch,
    }
}

/// Burns the staked IKA and returns the `principal`.
public(package) fun into_balance(sw: StakedIka): Balance<IKA> {
    let StakedIka { id, principal, .. } = sw;
    id.delete();
    principal
}

/// Sets the staked IKA state to `Withdrawing`
public(package) fun set_withdrawing(sw: &mut StakedIka, withdraw_epoch: u64) {
    assert!(sw.is_staked(), EAlreadyWithdrawing);
    sw.state = StakedIkaState::Withdrawing { withdraw_epoch };
}

/// Checks if the staked IKA can be withdrawn directly.
///
/// The staked IKA can be withdrawn early if:
/// - activation epoch is current epoch + 2
/// - activation epoch is current epoch + 1 and !node_in_next_committee
///   (or committee not selected yet)
public(package) fun can_withdraw_early(
    sw: &StakedIka,
    node_in_next_committee: bool,
    current_epoch: u64,
): bool {
    if (sw.is_withdrawing()) {
        return false
    };

    let activation_epoch = sw.activation_epoch;

    activation_epoch == current_epoch + 2 ||
    (sw.activation_epoch == current_epoch + 1 && !node_in_next_committee)
}

// === Accessors ===

/// Returns the `validator_id` of the staked IKA.
public fun validator_id(sw: &StakedIka): ID { sw.validator_id }

/// Returns the `principal` of the staked IKA. Called `value` to be consistent
/// with `Coin`.
public fun value(sw: &StakedIka): u64 { sw.principal.value() }

/// Returns the `activation_epoch` of the staked IKA.
public fun activation_epoch(sw: &StakedIka): u64 { sw.activation_epoch }

/// Returns true if the staked IKA is in the `Staked` state.
public fun is_staked(sw: &StakedIka): bool { sw.state == StakedIkaState::Staked }

/// Checks whether the staked IKA is in the `Withdrawing` state.
public fun is_withdrawing(sw: &StakedIka): bool {
    match (sw.state) {
        StakedIkaState::Withdrawing { .. } => true,
        _ => false,
    }
}

/// Returns the `withdraw_epoch` of the staked IKA if it is in the `Withdrawing`.
/// Aborts otherwise.
public fun withdraw_epoch(sw: &StakedIka): u64 {
    match (sw.state) {
        StakedIkaState::Withdrawing { withdraw_epoch, .. } => withdraw_epoch,
        _ => abort ENotWithdrawing,
    }
}

// === Public APIs ===

/// Joins the staked IKA with another staked IKA, adding the `principal` of the
/// `other` staked IKA to the current staked IKA.
///
/// Aborts if the `validator_id` or `activation_epoch` of the staked IKAs do not match.
public fun join(sw: &mut StakedIka, other: StakedIka) {
    assert!(sw.validator_id == other.validator_id, EMetadataMismatch);
    assert!(sw.activation_epoch == other.activation_epoch, EMetadataMismatch);

    // Simple scenario - staked ika is in `Staked` state. We guarantee that the
    // metadata is identical: same activation epoch and both are in the same state.
    if (sw.is_staked()) {
        assert!(other.is_staked(), EMetadataMismatch);

        let StakedIka { id, principal, .. } = other;
        sw.principal.join(principal);
        id.delete();
        return
    };

    // Withdrawing scenario - we no longer check that the activation epoch is
    // the same, as the staked IKA is in the process of withdrawing. Instead,
    // we make sure that the withdraw epoch is the same.
    assert!(sw.is_withdrawing() && other.is_withdrawing(), EMetadataMismatch);
    assert!(sw.withdraw_epoch() == other.withdraw_epoch(), EMetadataMismatch);

    let StakedIka { id, principal, .. } = other;
    sw.principal.join(principal);
    id.delete();
}

/// Splits the staked IKA into two parts, one with the `amount` and the other
/// with the remaining `principal`. The `validator_id`, `activation_epoch` are the
/// same for both the staked IKAs.
///
/// Aborts if the `amount` is greater than the `principal` of the staked IKA.
/// Aborts if the `amount` is zero.
public fun split(sw: &mut StakedIka, amount: u64, ctx: &mut TxContext): StakedIka {
    assert!(sw.principal.value() > amount, EInvalidAmount);

    // Both parts after the split must have a principal of at least MIN_STAKING_THRESHOLD.
    assert!(amount >= MIN_STAKING_THRESHOLD, EStakeBelowThreshold);
    assert!(sw.principal.value() - amount >= MIN_STAKING_THRESHOLD, EStakeBelowThreshold);

    StakedIka {
        id: object::new(ctx),
        state: sw.state, // state is preserved
        validator_id: sw.validator_id,
        principal: sw.principal.split(amount),
        activation_epoch: sw.activation_epoch,
    }
}

// === Test Functions ===

#[test_only]
public fun destroy_for_testing(sw: StakedIka) {
    let StakedIka { id, principal, .. } = sw;
    principal.destroy_for_testing();
    id.delete();
}
