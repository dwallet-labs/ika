// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Contains an active set of validators. The active set is a smart collection
/// that only stores up to a max size of validators. The active set tracks the total amount of staked
/// IKA to make the calculation of the rewards and voting power distribution easier.
module ika_system::pending_active_set;

use sui::vec_set::{Self, VecSet};

// === Errors ===

/// The maximum size of an ActiveSet must be strictly larger than zero.
const EZeroMaxSize: u64 = 0;
/// The validator is already part of the active set.
const EDuplicateInsertion: u64 = 1;
/// The minimum active set size must be maintained.
const EBelowMinValidatorCount: u64 = 3;
/// The maximum number of validator changes has been reached.
const EMaxValidatorChangeReached: u64 = 4;

// === Structs ===

/// Represents a single validator entry in the active set
public struct PendingActiveSetEntry has copy, drop, store {
    /// The ID of the validator
    validator_id: ID,
    /// The amount of IKA staked by this validator
    staked_amount: u64,
}

/// The active set of validators, a smart collection that only stores up
/// to a max size of validators.
/// Additionally, the active set tracks the total amount of staked IKA to make
/// the calculation of the rewards and voting power distribution easier.
public struct PendingActiveSet has copy, drop, store {
    /// The minimum number of validators required in the active set
    min_validator_count: u64,
    /// The maximum number of validators in the active set
    max_validator_count: u64,
    /// The minimum amount of staked IKA needed to enter the active set. This is used to
    /// determine if a storage validator can be added to the active set
    min_validator_joining_stake: u64,
    /// The maximum number of validators that can be added or removed to the active set in an epoch
    max_validator_change_count: u64,
    /// The list of validators in the active set and their stake
    validators: vector<PendingActiveSetEntry>,
    /// The total amount of staked IKA in the active set
    total_stake: u64,
    /// The list of validators that have been added or removed to the active set in the current epoch
    validator_changes: VecSet<ID>,
}

// === Package Functions ===

/// Creates a new pending active set with the specified configuration parameters.
///
/// The `min_validator_joining_stake` is used to filter out validators that do not have enough staked
/// IKA to be included in the active set initially. The `max_validator_change_count` limits the number
/// of validator additions/removals per epoch.
///
/// # Arguments
/// * `min_validator_count` - The minimum number of validators required in the active set
/// * `max_validator_count` - The maximum number of validators allowed in the active set
/// * `min_validator_joining_stake` - The minimum stake required for a validator to join
/// * `max_validator_change_count` - The maximum number of validator changes allowed per epoch
///
/// # Aborts
/// * `EZeroMaxSize` - If `max_validator_count` is zero
/// * `EBelowMinValidatorCount` - If `min_validator_count` > `max_validator_count`
public(package) fun new(
    min_validator_count: u64,
    max_validator_count: u64,
    min_validator_joining_stake: u64,
    max_validator_change_count: u64,
): PendingActiveSet {
    assert!(max_validator_count > 0, EZeroMaxSize);
    assert!(min_validator_count <= max_validator_count, EBelowMinValidatorCount);

    PendingActiveSet {
        min_validator_count,
        max_validator_count,
        min_validator_joining_stake,
        max_validator_change_count,
        validators: vector[],
        total_stake: 0,
        validator_changes: vec_set::empty(),
    }
}

/// Inserts, updates, or removes a validator based on their stake amount.
///
/// This function handles the complete lifecycle of a validator in the active set:
/// - If stake is below threshold: attempts to remove the validator
/// - If validator exists: updates their stake
/// - If validator doesn't exist and has sufficient stake: inserts them
///
/// # Arguments
/// * `set` - The pending active set to modify
/// * `validator_id` - The ID of the validator to process
/// * `staked_amount` - The new stake amount for the validator
///
/// # Returns
/// * `bool` - Whether the validator is in the set after the operation
/// * `Option<ID>` - The ID of any validator that was removed, or None
public(package) fun insert_or_update_or_remove(
    set: &mut PendingActiveSet,
    validator_id: ID,
    staked_amount: u64,
): (bool, Option<ID>) {
    // Currently, the `min_validator_joining_stake` is set to `0`, so we need to account for that.
    if (staked_amount == 0 || staked_amount < set.min_validator_joining_stake) {
        if (set.remove(validator_id)) {
            (false, option::some(validator_id))
        } else {
            (false, option::none())
        }
    } else if (set.update(validator_id, staked_amount)) {
        (true, option::none())
    } else {
        set.insert(validator_id, staked_amount)
    }
}

/// Updates an existing validator's stake or removes them if stake is insufficient.
///
/// # Arguments
/// * `set` - The pending active set to modify
/// * `validator_id` - The ID of the validator to update
/// * `staked_amount` - The new stake amount for the validator
///
/// # Returns
/// * `bool` - Whether the validator remains in the set after the operation
/// * `Option<ID>` - The ID of the validator if it was removed, or None
public(package) fun update_or_remove(
    set: &mut PendingActiveSet,
    validator_id: ID,
    staked_amount: u64,
): (bool, Option<ID>) {
    if (staked_amount == 0 || staked_amount < set.min_validator_joining_stake) {
        if (set.remove(validator_id)) {
            (false, option::some(validator_id))
        } else {
            (false, option::none())
        }
    } else {
        (set.update(validator_id, staked_amount), option::none())
    }
}

/// Updates the stake amount of an existing validator in the active set.
///
/// # Arguments
/// * `set` - The pending active set to modify
/// * `validator_id` - The ID of the validator to update
/// * `staked_amount` - The new stake amount for the validator
///
/// # Returns
/// * `bool` - Whether the validator was found and updated
public(package) fun update(set: &mut PendingActiveSet, validator_id: ID, staked_amount: u64): bool {
    let index = set.find_validator_index(validator_id);
    if (index.is_none()) {
        return false
    };
    index.do!(|idx| {
        set.total_stake = set.total_stake + staked_amount - set.validators[idx].staked_amount;
        set.validators[idx].staked_amount = staked_amount;
        // Re-sort the validator in its new position
        set.reposition_validator(idx);
    });
    true
}

/// Removes a validator from the active set.
///
/// # Arguments
/// * `set` - The pending active set to modify
/// * `validator_id` - The ID of the validator to remove
///
/// # Returns
/// * `bool` - Whether the validator was found and removed
///
/// # Aborts
/// * `EBelowMinValidatorCount` - If removal would violate the minimum validator count
public(package) fun remove(set: &mut PendingActiveSet, validator_id: ID): bool {
    let is_under_min_validator_count = set.validators.length() < set.min_validator_count;
    let index = set.find_validator_index(validator_id);
    let removed = index.is_some();
    index.do!(|idx| {
        let entry = set.validators.remove(idx);
        set.total_stake = set.total_stake - entry.staked_amount;
    });

    // Abort if removal would violate the minimum validator count
    assert!(
        is_under_min_validator_count || set.validators.length() >= set.min_validator_count,
        EBelowMinValidatorCount,
    );

    // Only track the change if the validator was actually removed
    if (removed) {
        if (!set.validator_changes.contains(&validator_id)) {
            set.validator_changes.insert(validator_id);
        };
        assert!(
            set.validator_changes.size() <= set.max_validator_change_count,
            EMaxValidatorChangeReached,
        );
    };
    removed
}

// === View Functions ===

/// Finds the index of a validator in the active set using linear search.
///
/// # Arguments
/// * `set` - The pending active set to search
/// * `validator_id` - The ID of the validator to find
///
/// # Returns
/// * `Option<u64>` - The index of the validator, or None if not found
public(package) fun find_validator_index(set: &PendingActiveSet, validator_id: ID): Option<u64> {
    let len = set.validators.length();
    let mut i = 0;
    while (i < len) {
        if (set.validators[i].validator_id == validator_id) {
            return option::some(i)
        };
        i = i + 1;
    };
    option::none()
}

// === Admin Functions ===

/// Sets the maximum size of the active set.
public(package) fun set_max_validator_count(set: &mut PendingActiveSet, max_validator_count: u64) {
    set.max_validator_count = max_validator_count;
}

/// Sets the minimum number of validators required in the active set.
public(package) fun set_min_validator_count(set: &mut PendingActiveSet, min_validator_count: u64) {
    set.min_validator_count = min_validator_count;
}

/// Sets the maximum number of validator changes allowed per epoch.
public(package) fun set_max_validator_change_count(
    set: &mut PendingActiveSet,
    max_validator_change_count: u64,
) {
    set.max_validator_change_count = max_validator_change_count;
}

/// Resets the validator changes count (typically called at the start of a new epoch).
public(package) fun reset_validator_changes(set: &mut PendingActiveSet) {
    set.validator_changes = vec_set::empty();
}

/// Sets the minimum amount of staked IKA required to join the active set.
public(package) fun set_min_validator_joining_stake(
    set: &mut PendingActiveSet,
    min_validator_joining_stake: u64,
) {
    set.min_validator_joining_stake = min_validator_joining_stake;
}

// === Getter Functions ===

/// Returns the maximum size of the active set.
public(package) fun max_validator_count(set: &PendingActiveSet): u64 {
    set.max_validator_count
}

/// Returns the minimum number of validators required in the active set.
public(package) fun min_validator_count(set: &PendingActiveSet): u64 {
    set.min_validator_count
}

/// Returns the maximum number of validator changes allowed per epoch.
public(package) fun max_validator_change_count(set: &PendingActiveSet): u64 {
    set.max_validator_change_count
}

/// Returns the current size of the active set.
public(package) fun size(set: &PendingActiveSet): u64 {
    set.validators.length()
}

/// Returns the minimum amount of staked IKA required to join the active set.
public(package) fun min_validator_joining_stake(set: &PendingActiveSet): u64 {
    set.min_validator_joining_stake
}

/// Returns the total amount of staked IKA in the active set.
public(package) fun total_stake(set: &PendingActiveSet): u64 {
    set.total_stake
}

/// Returns the IDs of all validators in the active set.
public(package) fun active_ids(set: &PendingActiveSet): vector<ID> {
    set.validators.map_ref!(|validator| validator.validator_id)
}

/// Returns the IDs and stake amounts of all validators in the active set.
public(package) fun active_ids_and_stake(set: &PendingActiveSet): (vector<ID>, vector<u64>) {
    let mut active_ids = vector[];
    let mut stake = vector[];
    set.validators.do_ref!(|entry| {
        active_ids.push_back(entry.validator_id);
        stake.push_back(entry.staked_amount);
    });
    (active_ids, stake)
}

// === Private Functions ===

/// Inserts a validator into the active set with smart capacity management.
///
/// If the set is full, the validator with the smallest stake is removed to make space
/// for the new validator (if the new validator has higher stake).
///
/// # Arguments
/// * `set` - The pending active set to modify
/// * `validator_id` - The ID of the validator to insert
/// * `staked_amount` - The stake amount for the validator
///
/// # Returns
/// * `bool` - Whether the validator was successfully inserted
/// * `Option<ID>` - The ID of any validator that was removed, or None
///
/// # Aborts
/// * `EDuplicateInsertion` - If the validator is already in the set
/// * `EMaxValidatorChangeReached` - If the change would exceed the epoch limit
fun insert(set: &mut PendingActiveSet, validator_id: ID, staked_amount: u64): (bool, Option<ID>) {
    assert!(set.find_validator_index(validator_id).is_none(), EDuplicateInsertion);

    // If the validators are less than the max size, insert the validator.
    if (set.validators.length() < set.max_validator_count) {
        set.total_stake = set.total_stake + staked_amount;
        let new_entry = PendingActiveSetEntry { validator_id, staked_amount };
        set.insert_sorted(new_entry);
        if (!set.validator_changes.contains(&validator_id)) {
            set.validator_changes.insert(validator_id);
        };
        assert!(
            set.validator_changes.size() <= set.max_validator_change_count,
            EMaxValidatorChangeReached,
        );

        return (true, option::none())
    };

    // If the new validator's stake is less than the smallest stake in the set, don't insert
    if (staked_amount <= set.validators[0].staked_amount) {
        return (false, option::none())
    };

    // Remove the validator with smallest stake and insert the new one
    let removed_validator_id = set.validators[0].validator_id;
    let removed_stake = set.validators[0].staked_amount;
    set.total_stake = set.total_stake - removed_stake + staked_amount;
    set.validators.remove(0);
    let new_entry = PendingActiveSetEntry { validator_id, staked_amount };
    set.insert_sorted(new_entry);
    if (!set.validator_changes.contains(&validator_id)) {
        set.validator_changes.insert(validator_id);
    };
    assert!(
        set.validator_changes.size() <= set.max_validator_change_count,
        EMaxValidatorChangeReached,
    );
    (true, option::some(removed_validator_id))
}

/// Inserts a validator entry into the sorted vector maintaining ascending order by stake.
fun insert_sorted(set: &mut PendingActiveSet, entry: PendingActiveSetEntry) {
    let mut left = 0u64;
    let mut right = set.validators.length();
    while (left < right) {
        let mid = (left + right) / 2;
        if (set.validators[mid].staked_amount < entry.staked_amount) {
            left = mid + 1
        } else {
            right = mid
        }
    };

    // Manual insert implementation: push to end, then shift elements to the correct position
    vector::push_back(&mut set.validators, entry); // Temporarily add to end
    let len = set.validators.length();
    if (len > 1) {
        let mut i = len - 1;
        while (i > left) {
            vector::swap(&mut set.validators, i, i - 1);
            i = i - 1;
        }
    }
}

/// Repositions a validator in the sorted vector after its stake has been updated.
/// This maintains the ascending order by stake amount.
fun reposition_validator(set: &mut PendingActiveSet, index: u64) {
    let entry = vector::remove(&mut set.validators, index);
    set.insert_sorted(entry)
}

// === Test Functions ===

/// Returns the current minimum stake needed to be in the active set.
///
/// If the active set is full, returns the stake of the validator with the smallest stake.
/// Otherwise, returns the threshold stake.
///
/// Note: Test only to discourage using this since it iterates over all validators.
/// When `min_validator_joining_stake` is needed within `PendingActiveSet`,
/// prefer inlining/integrating it in other loops.
#[test_only]
public(package) fun current_min_validator_joining_stake(set: &PendingActiveSet): u64 {
    if (set.validators.length() == set.max_validator_count as u64) {
        set.validators[0].staked_amount
    } else {
        set.min_validator_joining_stake
    }
}

/// Returns the stake amount for a specific validator in the active set.
/// Returns 0 if the validator is not found.
#[test_only]
public fun stake_for_validator(set: &PendingActiveSet, validator_id: ID): u64 {
    set
        .validators
        .find_index!(|entry| entry.validator_id == validator_id)
        .map!(|index| set.validators[index].staked_amount)
        .destroy_or!(0)
}

// === Tests ===

#[test]
fun test_evict_correct_validator_simple() {
    let mut set = new(1, 5, 0, 10); // Allow sufficient changes for the test
    let (inserted, _) = set.insert_or_update_or_remove(object::id_from_address(@0x1), 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(object::id_from_address(@0x2), 9);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(object::id_from_address(@0x3), 8);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(object::id_from_address(@0x4), 7);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(object::id_from_address(@0x5), 6);
    assert!(inserted);

    let mut total_stake = 10 + 9 + 8 + 7 + 6;

    assert!(set.total_stake == total_stake);

    // insert another validator which should eject validator 5
    let (inserted, removed_id) = set.insert_or_update_or_remove(object::id_from_address(@0x6), 11);
    assert!(inserted);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == object::id_from_address(@0x5));

    // check if total stake was updated correctly
    total_stake = total_stake - 6 + 11;
    assert!(set.total_stake == total_stake);

    let active_ids = set.active_ids();

    // validator 5 should not be part of the set
    assert!(!active_ids.contains(&object::id_from_address(@0x5)));

    // all other validators should be
    assert!(active_ids.contains(&object::id_from_address(@0x1)));
    assert!(active_ids.contains(&object::id_from_address(@0x2)));
    assert!(active_ids.contains(&object::id_from_address(@0x3)));
    assert!(active_ids.contains(&object::id_from_address(@0x4)));
    assert!(active_ids.contains(&object::id_from_address(@0x6)));
}

#[test]
fun test_evict_correct_validator_with_updates() {
    let validators = vector[
        object::id_from_address(@0x1),
        object::id_from_address(@0x2),
        object::id_from_address(@0x3),
        object::id_from_address(@0x4),
        object::id_from_address(@0x5),
        object::id_from_address(@0x6),
    ];

    let mut set = new(1, 5, 0, 10); // Allow sufficient changes for the test
    let (inserted, _) = set.insert_or_update_or_remove(validators[3], 7);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(validators[0], 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(validators[2], 8);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(validators[1], 9);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(validators[4], 6);
    assert!(inserted);

    let mut total_stake = 10 + 9 + 8 + 7 + 6;

    assert!(set.total_stake == total_stake);

    // update validators again
    let (updated, _) = set.insert_or_update_or_remove(validators[0], 12);
    assert!(updated);
    // check if total stake was updated correctly
    total_stake = total_stake - 10 + 12;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[0]) == 12);

    let (updated, _) = set.insert_or_update_or_remove(validators[2], 13);
    assert!(updated);
    // check if total stake was updated correctly
    total_stake = total_stake - 8 + 13;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[2]) == 13);

    let (updated, _) = set.insert_or_update_or_remove(validators[3], 9);
    assert!(updated);
    // check if total stake was updated correctly
    total_stake = total_stake - 7 + 9;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[3]) == 9);

    let (updated, _) = set.insert_or_update_or_remove(validators[1], 10);
    assert!(updated);
    // check if total stake was updated correctly
    total_stake = total_stake - 9 + 10;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[1]) == 10);

    let (updated, _) = set.insert_or_update_or_remove(validators[4], 7);
    assert!(updated);
    // check if total stake was updated correctly
    total_stake = total_stake - 6 + 7;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[4]) == 7);

    // insert another validator which should eject validators[4] (address @5)
    let (inserted, removed_id) = set.insert_or_update_or_remove(validators[5], 11);
    assert!(inserted);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == validators[4]);
    // check if total stake was updated correctly
    total_stake = total_stake - 7 + 11;
    assert!(set.total_stake == total_stake);
    // check if the stake of the validator was updated correctly
    assert!(set.stake_for_validator(validators[5]) == 11);

    let active_ids = set.active_ids();

    // validator 5 should not be part of the set
    assert!(!active_ids.contains(&validators[4]));

    // all other validators should be
    assert!(active_ids.contains(&validators[0]));
    assert!(active_ids.contains(&validators[1]));
    assert!(active_ids.contains(&validators[2]));
    assert!(active_ids.contains(&validators[3]));
    assert!(active_ids.contains(&validators[5]));
}

#[test]
fun test_empty_set() {
    let set = new(0, 10, 100, 0); // min_validator_count = 0, max_validator_count = 10, min_validator_joining_stake = 100, max_validator_change_count = 0
    assert!(set.size() == 0);
    assert!(set.total_stake() == 0);
    assert!(set.min_validator_joining_stake() == 100);
    assert!(set.current_min_validator_joining_stake() == 100); // Not full, should return threshold
    assert!(set.active_ids().is_empty());
    assert!(set.stake_for_validator(object::id_from_address(@0x1)) == 0);
}

#[test]
fun test_removal() {
    let mut set = new(0, 5, 0, 10); // min_validator_count = 0 to allow removing all validators
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);
    let v4 = object::id_from_address(@0x4);
    let v5 = object::id_from_address(@0x5);

    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v4, 40);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v5, 50);
    assert!(inserted);

    assert!(set.size() == 5);
    assert!(set.total_stake() == 150);

    // Remove middle
    set.remove(v3);
    assert!(set.size() == 4);
    assert!(set.total_stake() == 120);
    assert!(set.stake_for_validator(v3) == 0);
    assert!(!set.active_ids().contains(&v3));

    // Remove min (v1)
    set.remove(v1);
    assert!(set.size() == 3);
    assert!(set.total_stake() == 110);
    assert!(set.stake_for_validator(v1) == 0);
    assert!(!set.active_ids().contains(&v1));

    // Remove max (v5)
    set.remove(v5);
    assert!(set.size() == 2);
    assert!(set.total_stake() == 60);
    assert!(set.stake_for_validator(v5) == 0);
    assert!(!set.active_ids().contains(&v5));

    // Remove non-existent
    set.remove(object::id_from_address(@0x6));
    assert!(set.size() == 2);
    assert!(set.total_stake() == 60);

    // Remove remaining
    set.remove(v2);
    set.remove(v4);
    assert!(set.size() == 0);
    assert!(set.total_stake() == 0);
}

#[test]
fun test_min_validator_count() {
    let mut set = new(2, 5, 0, 10); // min_validator_count = 2, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 10
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // Add three validators
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);
    assert!(set.size() == 3);

    // Should be able to remove one (leaving 2)
    set.remove(v1);
    assert!(set.size() == 2);

    // Should not be able to remove more (would go below min of 2)
    // Attempting to remove should abort, so we don't test it here

    // Re-add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 15);
    assert!(inserted);
    assert!(set.size() == 3);

    // Now should be able to remove v2
    set.remove(v2);
    assert!(set.size() == 2);
    assert!(!set.active_ids().contains(&v2));
}

#[test]
#[expected_failure(abort_code = EBelowMinValidatorCount)]
fun test_remove_below_min_aborts() {
    let mut set = new(2, 5, 0, 10); // min_validator_count = 2, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 10
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);

    // Add two validators (exactly at min)
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    assert!(set.size() == 2);

    // This should abort since we're at the minimum
    set.remove(v1);
}

#[test]
#[expected_failure(abort_code = EBelowMinValidatorCount)]
fun test_min_validator_count_aborts() {
    let mut set = new(1, 3, 100, 10); // min_validator_count = 1, max_validator_count = 3, min_validator_joining_stake = 100, max_validator_change_count = 10
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // Insert below threshold - should fail
    let (inserted, _) = set.insert_or_update_or_remove(v1, 50);
    assert!(!inserted);
    assert!(set.size() == 0);

    // Insert at/above threshold
    let (inserted, _) = set.insert_or_update_or_remove(v2, 100);
    assert!(inserted);
    assert!(set.size() == 1);
    assert!(set.total_stake() == 100);
    let (inserted, _) = set.insert_or_update_or_remove(v3, 150);
    assert!(inserted);
    assert!(set.size() == 2);
    assert!(set.total_stake() == 250);

    // Update below threshold - this is different now
    // Since min_validator_count = 1 and we have 2 validators,
    // we should still be able to remove v2
    let (updated, removed_id) = set.insert_or_update_or_remove(v2, 90);
    assert!(!updated);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == v2);
    assert!(set.size() == 1);
    assert!(set.total_stake() == 150);
    assert!(set.stake_for_validator(v2) == 0);
    assert!(!set.active_ids().contains(&v2));

    // Now we're at min_validator_count=1, trying to update below threshold
    // should keep the validator since we can't remove it
    let (updated, _) = set.insert_or_update_or_remove(v3, 90);
    assert!(updated);
}

#[test]
fun test_min_validator_count2() {
    let mut set = new(1, 3, 100, 10); // min_validator_count = 1, max_validator_count = 3, min_validator_joining_stake = 100, max_validator_change_count = 10
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);
    let v4 = object::id_from_address(@0x4);

    // Insert below threshold - should fail
    let (inserted, _) = set.insert_or_update_or_remove(v1, 50);
    assert!(!inserted);
    assert!(set.size() == 0);

    // Insert at/above threshold
    let (inserted, _) = set.insert_or_update_or_remove(v2, 100);
    assert!(inserted);
    assert!(set.size() == 1);
    assert!(set.total_stake() == 100);
    let (inserted, _) = set.insert_or_update_or_remove(v3, 150);
    assert!(inserted);
    assert!(set.size() == 2);
    assert!(set.total_stake() == 250);

    // Update below threshold - this is different now
    // Since min_validator_count = 1 and we have 2 validators,
    // we should still be able to remove v2
    let (updated, removed_id) = set.insert_or_update_or_remove(v2, 90);
    assert!(!updated);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == v2);
    assert!(set.size() == 1);
    assert!(set.total_stake() == 150);
    assert!(set.stake_for_validator(v2) == 0);
    assert!(!set.active_ids().contains(&v2));

    // Refill set
    let (inserted, _) = set.insert_or_update_or_remove(v2, 120); // v2 re-enters
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v4, 110); // v4 enters
    assert!(inserted);
    assert!(set.size() == 3);
    assert!(set.total_stake() == 150 + 120 + 110);
    // Validators: v4(110), v2(120), v3(150)

    // Test cur_min_stake
    assert!(set.current_min_validator_joining_stake() == 110); // Full set, should return actual min

    // Insert another validator - should eject v4
    let (inserted, removed_id) = set.insert_or_update_or_remove(v1, 130);
    assert!(inserted);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == v4);
    assert!(set.size() == 3);
    assert!(set.total_stake() == 120 + 150 + 130);
    let active_ids = set.active_ids();
    assert!(!active_ids.contains(&v4));
    assert!(active_ids.contains(&v1));
    assert!(active_ids.contains(&v2));
    assert!(active_ids.contains(&v3));
    assert!(set.current_min_validator_joining_stake() == 120);
}

#[test]
fun test_removal_reporting() {
    let mut set = new(0, 5, 100, 10); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 100, max_validator_change_count = 10
    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);

    // Try to remove validator not in set using update_or_remove
    let (in_set, removed_id) = set.update_or_remove(v1, 50);
    assert!(!in_set); // Should not be in set
    assert!(option::is_none(&removed_id)); // Should not report removal since validator wasn't in set

    // Try to remove validator not in set using insert_or_update_or_remove
    let (in_set, removed_id) = set.insert_or_update_or_remove(v2, 50);
    assert!(!in_set); // Should not be in set
    assert!(option::is_none(&removed_id)); // Should not report removal since validator wasn't in set

    // Add a validator to the set
    let (inserted, _) = set.insert_or_update_or_remove(v1, 150);
    assert!(inserted);
    assert!(set.size() == 1);

    // Now remove validator that is in set using update_or_remove with stake below threshold
    let (in_set, removed_id) = set.update_or_remove(v1, 50);
    assert!(!in_set); // Should not be in set after removal
    assert!(option::is_some(&removed_id)); // Should report removal
    assert!(*option::borrow(&removed_id) == v1); // Should remove the correct validator
    assert!(set.size() == 0);

    // Add validators back to set
    let (inserted, _) = set.insert_or_update_or_remove(v1, 150);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 200);
    assert!(inserted);
    assert!(set.size() == 2);

    // Remove validator that is in set using insert_or_update_or_remove with stake below threshold
    let (in_set, removed_id) = set.insert_or_update_or_remove(v1, 50);
    assert!(!in_set); // Should not be in set after removal
    assert!(option::is_some(&removed_id)); // Should report removal
    assert!(*option::borrow(&removed_id) == v1); // Should remove the correct validator
    assert!(set.size() == 1);
}

#[test]
fun test_max_validator_change_count_basic() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    assert!(set.size() == 1);

    // Second change: add v2
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    assert!(set.size() == 2);

    // Third change should fail - exceeds max_validator_change_count
    // This will be tested in the abort test below
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_insert_exceeds_limit() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Second change: add v2
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);

    // Third change should abort - exceeds max_validator_change_count
    set.insert_or_update_or_remove(v3, 30);
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_remove_exceeds_limit() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // Add validators first (without change count limit)
    set.set_max_validator_change_count(10); // Temporarily increase limit
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);

    // Reset changes and set limit back to 2
    set.reset_validator_changes();
    set.set_max_validator_change_count(2);

    // First change: remove v1
    set.remove(v1);
    assert!(set.size() == 2);

    // Second change: remove v2
    set.remove(v2);
    assert!(set.size() == 1);

    // Third change should abort - exceeds max_validator_change_count
    set.remove(v3);
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_mixed_operations_exceeds_limit() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2
    set.set_max_validator_change_count(3); // Allow only 3 changes per epoch

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Second change: add v2
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);

    // Third change: add v3
    let (inserted, _) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);

    // Fourth change should abort - exceeds max_validator_change_count
    set.insert_or_update_or_remove(object::id_from_address(@0x4), 40);
}

#[test]
fun test_max_validator_change_count_updates_dont_count() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Second change: add v2
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);

    // Updates should not count towards the change limit
    let (updated, _) = set.insert_or_update_or_remove(v1, 15);
    assert!(updated);
    assert!(set.stake_for_validator(v1) == 15);

    let (updated, _) = set.insert_or_update_or_remove(v2, 25);
    assert!(updated);
    assert!(set.stake_for_validator(v2) == 25);

    // Multiple updates should still work
    let (updated, _) = set.insert_or_update_or_remove(v1, 12);
    assert!(updated);
    assert!(set.stake_for_validator(v1) == 12);
}

#[test]
fun test_max_validator_change_count_reset() {
    let mut set = new(0, 5, 0, 2); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 2

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);
    let v4 = object::id_from_address(@0x4);

    // Use up the change limit
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);

    // Reset changes (simulating new epoch)
    set.reset_validator_changes();

    // Should be able to make changes again
    let (inserted, _) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);
    let (inserted, _) = set.insert_or_update_or_remove(v4, 40);
    assert!(inserted);

    assert!(set.size() == 4);
}

#[test]
fun test_max_validator_change_count_eviction_counts() {
    let mut set = new(0, 2, 0, 3); // min_validator_count = 0, max_validator_count = 2, min_validator_joining_stake = 0, max_validator_change_count = 3

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Second change: add v2 (fills the set)
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);
    assert!(set.size() == 2);

    // Third change: add v3 with higher stake (should evict v1 and count as one change for v3)
    let (inserted, removed_id) = set.insert_or_update_or_remove(v3, 30);
    assert!(inserted);
    assert!(option::is_some(&removed_id));
    assert!(*option::borrow(&removed_id) == v1);
    assert!(set.size() == 2);

    // We should have used 3 changes now (v1 add, v2 add, v3 add)
    // The eviction of v1 doesn't count as a separate change
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_eviction_exceeds_limit() {
    let mut set = new(0, 2, 0, 3); // min_validator_count = 0, max_validator_count = 2, min_validator_joining_stake = 0, max_validator_change_count = 3
    set.set_max_validator_change_count(2); // Allow only 2 changes per epoch

    let v1 = object::id_from_address(@0x1);
    let v2 = object::id_from_address(@0x2);
    let v3 = object::id_from_address(@0x3);

    // First change: add v1
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Second change: add v2 (fills the set)
    let (inserted, _) = set.insert_or_update_or_remove(v2, 20);
    assert!(inserted);

    // Third change should abort - adding v3 would exceed the limit
    set.insert_or_update_or_remove(v3, 30);
}

#[test]
fun test_max_validator_change_count_zero_allows_no_changes() {
    let mut set = new(0, 5, 0, 0); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 0
    // max_validator_change_count is 0 by default
    assert!(set.max_validator_change_count() == 0);

    let v1 = object::id_from_address(@0x1);

    // Updates should work even with zero change limit (since they don't count as changes)
    // But first we need to add a validator when the limit is higher
    set.set_max_validator_change_count(1);
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Reset and set limit back to 0
    set.reset_validator_changes();
    set.set_max_validator_change_count(0);

    // Updates should still work
    let (updated, _) = set.insert_or_update_or_remove(v1, 15);
    assert!(updated);
    assert!(set.stake_for_validator(v1) == 15);
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_zero_blocks_additions() {
    let mut set = new(0, 5, 0, 0); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 0
    // max_validator_change_count is 0 by default
    assert!(set.max_validator_change_count() == 0);

    let v1 = object::id_from_address(@0x1);

    // Should abort when trying to add a validator with zero change limit
    set.insert_or_update_or_remove(v1, 10);
}

#[test]
#[expected_failure(abort_code = EMaxValidatorChangeReached)]
fun test_max_validator_change_count_zero_blocks_removals() {
    let mut set = new(0, 5, 0, 0); // min_validator_count = 0, max_validator_count = 5, min_validator_joining_stake = 0, max_validator_change_count = 0
    let v1 = object::id_from_address(@0x1);

    // Add a validator first (with higher limit)
    set.set_max_validator_change_count(1);
    let (inserted, _) = set.insert_or_update_or_remove(v1, 10);
    assert!(inserted);

    // Reset and set limit to 0
    set.reset_validator_changes();
    set.set_max_validator_change_count(0);

    // Should abort when trying to remove with zero change limit
    set.remove(v1);
}
