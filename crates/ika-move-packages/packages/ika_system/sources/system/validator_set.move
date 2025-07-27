// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::validator_set;

use ika::ika::IKA;
use ika_common::bls_committee::{Self, BlsCommittee, new_bls_committee, new_bls_committee_member};
use ika_common::extended_field::{Self, ExtendedField};
use ika_common::system_object_cap::SystemObjectCap;
use ika_common::validator_cap::{ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap};
use ika_system::pending_active_set::{Self, PendingActiveSet};
use ika_system::staked_ika::StakedIka;
use ika_system::token_exchange_rate::TokenExchangeRate;
use ika_system::validator::{Self, Validator};
use ika_system::validator_metadata::ValidatorMetadata;
use std::string::String;
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::coin::Coin;
use sui::event;
use sui::object_table::{Self, ObjectTable};
use sui::table::Table;
use sui::vec_map::{Self, VecMap};
use sui::vec_set::{Self, VecSet};
use sui::table_vec::TableVec;

// === Constants ===

const BASIS_POINT_DENOMINATOR: u16 = 10_000;
const BASIS_POINT_DENOMINATOR_U128: u128 = 10_000;
const MIN_STAKING_THRESHOLD: u64 = 1_000_000_000; // 1 IKA

// === Errors ===

/// The validator is not in the report records.
const ENonValidatorInReportRecords: u64 = 0;
/// The validator is already in the validator set.
const EDuplicateValidator: u64 = 1;
/// The validator is not a validator.
const ENotAValidator: u64 = 2;
/// The validator is not a candidate.
const EValidatorNotCandidate: u64 = 3;
/// The validator is not staking below the threshold.
const EStakingBelowThreshold: u64 = 4;
/// The validator is already removed.
const EValidatorAlreadyRemoved: u64 = 5;
/// The validator cannot report on itself.
const ECannotReportOneself: u64 = 6;
/// The report record is not found.
const EReportRecordNotFound: u64 = 7;
/// The validator cannot join the active set.
const ECannotJoinActiveSet: u64 = 8;
/// The bps is too large.
const EBpsTooLarge: u64 = 9;
/// The cap is invalid.
const EInvalidCap: u64 = 10;
/// Process mid epoch can be called only after advance epoch.
const EProcessMidEpochOnlyAfterAdvanceEpoch: u64 = 11;
/// Advance epoch can be called only after process mid epoch.
const EAdvanceEpochOnlyAfterProcessMidEpoch: u64 = 12;
/// Cannot set validator new info before next epoch if validator is in next epoch committee.
const ECannotSetBeforeNextEpoch: u64 = 13;

// === Structs ===

public struct ValidatorSet has store {
    /// Total amount of stake from all active validators at the beginning of the epoch.
    total_stake: u64,
    /// How many reward are slashed to punish a validator, in bps.
    reward_slashing_rate: u16,
    /// A table that contains all validators
    validators: ObjectTable<ID, Validator>,
    /// The current list of active committee of validators.
    active_committee: BlsCommittee,
    /// The next list of active committee of validators.
    /// It will become the active_committee at the end of the epoch.
    next_epoch_active_committee: Option<BlsCommittee>,
    /// The current list of previous committee of validators.
    previous_committee: BlsCommittee,
    /// The next list of pending active set of validators to be next_epoch_active_committee.
    /// It will start from the last next_epoch_active_committee and will be
    /// process between middle of the epochs and will be finalize
    /// at the middle of the epoch.
    pending_active_set: ExtendedField<PendingActiveSet>,
    /// A map storing the records of validator reporting each other.
    /// There is an entry in the map for each validator that has been reported
    /// at least once. The entry VecSet contains all the validators that reported
    /// them. If a validator has never been reported they don't have an entry in this map.
    /// This map persists across epoch: a peer continues being in a reported state until the
    /// reporter doesn't explicitly remove their report.
    /// Note that in case we want to support validator address change in future,
    /// the reports should be based on validator ids
    validator_report_records: VecMap<ID, VecSet<ID>>,
    /// Any extra fields that's not defined statically.
    extra_fields: Bag,
}

/// Event containing staking and rewards related information of
/// each validator, emitted during epoch advancement.
public struct ValidatorEpochInfoEventV1 has copy, drop {
    epoch: u64,
    validator_id: ID,
    stake: u64,
    commission_rate: u16,
    staking_rewards: u64,
    token_exchange_rate: TokenExchangeRate,
    tallying_rule_reporters: vector<ID>,
    tallying_rule_global_score: u64,
}

/// Event emitted every time a new validator joins the committee.
/// The epoch value corresponds to the first epoch this change takes place.
public struct ValidatorJoinEvent has copy, drop {
    epoch: u64,
    validator_id: ID,
}

/// Event emitted every time a validator leaves the committee.
/// The epoch value corresponds to the first epoch this change takes place.
public struct ValidatorLeaveEvent has copy, drop {
    withdrawing_epoch: u64,
    validator_id: ID,
    is_voluntary: bool,
}

// === Package Functions ===

// ==== initialization ====

public(package) fun new(
    min_validator_count: u64,
    max_validator_count: u64,
    min_validator_joining_stake: u64,
    max_validator_change_count: u64,
    reward_slashing_rate: u16,
    ctx: &mut TxContext,
): ValidatorSet {
    // Rates can't be higher than 100%.
    assert!(reward_slashing_rate <= BASIS_POINT_DENOMINATOR, EBpsTooLarge);
    ValidatorSet {
        total_stake: 0,
        reward_slashing_rate,
        validators: object_table::new(ctx),
        active_committee: bls_committee::empty(),
        next_epoch_active_committee: option::none(),
        previous_committee: bls_committee::empty(),
        pending_active_set: extended_field::new(
            pending_active_set::new(
                min_validator_count,
                max_validator_count,
                min_validator_joining_stake,
                max_validator_change_count,
            ),
            ctx,
        ),
        validator_report_records: vec_map::empty(),
        extra_fields: bag::new(ctx),
    }
}

// ==== functions to add or remove validators ====

/// Called by `ika_system` to add a new validator candidate.
public(package) fun request_add_validator_candidate(
    self: &mut ValidatorSet,
    current_epoch: u64,
    name: String,
    protocol_pubkey_bytes: vector<u8>,
    network_pubkey_bytes: vector<u8>,
    consensus_pubkey_bytes: vector<u8>,
    mpc_data_bytes: TableVec<vector<u8>>,
    proof_of_possession_bytes: vector<u8>,
    network_address: String,
    p2p_address: String,
    consensus_address: String,
    commission_rate: u16,
    metadata: ValidatorMetadata,
    system_object_cap: &SystemObjectCap,
    ctx: &mut TxContext,
): (ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap) {
    let (validator, cap, operation_cap, commission_cap) = validator::new(
        current_epoch,
        name,
        protocol_pubkey_bytes,
        network_pubkey_bytes,
        consensus_pubkey_bytes,
        mpc_data_bytes,
        proof_of_possession_bytes,
        network_address,
        p2p_address,
        consensus_address,
        commission_rate,
        metadata,
        system_object_cap,
        ctx,
    );

    let validator_id = validator.validator_id();

    // The next assertions are not critical for the protocol, but they are here to catch problematic configs earlier.
    assert!(!is_duplicate_with_pending_validator(self, &validator), EDuplicateValidator);

    assert!(!self.validators.contains(validator_id), EDuplicateValidator);

    assert!(validator.is_preactive(), EValidatorNotCandidate);
    self.validators.add(validator_id, validator);

    (cap, operation_cap, commission_cap)
}

/// Called by `ika_system` to remove a validator candidate, and move them to `inactive_committee`.
public(package) fun request_remove_validator_candidate(
    self: &mut ValidatorSet,
    epoch: u64,
    cap: &ValidatorCap,
) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator_mut(validator_id);
    assert!(validator.is_preactive(), EValidatorNotCandidate);

    // Set the validator to withdrawing state
    validator.set_withdrawing(cap, epoch);
}

public(package) fun update_pending_active_set(
    self: &mut ValidatorSet,
    validator_id: ID,
    current_epoch: u64,
    committee_selected: bool,
    insert_if_not_in_set: bool,
): bool {
    let validator = self.get_validator_mut(validator_id);
    let balance = if (committee_selected) {
        validator.ika_balance_at_epoch(current_epoch + 2)
    } else {
        validator.ika_balance_at_epoch(current_epoch + 1)
    };
    let (in_set, mut removed_validator_id) = if (insert_if_not_in_set) {
        self.pending_active_set.borrow_mut().insert_or_update_or_remove(validator_id, balance)
    } else {
        self.pending_active_set.borrow_mut().update_or_remove(validator_id, balance)
    };

    if (removed_validator_id.is_some()) {
        let removed_validator = self.get_validator_mut(removed_validator_id.extract());
        let new_epoch = current_epoch + 1;
        removed_validator.deactivate(new_epoch);
        event::emit(ValidatorLeaveEvent {
            withdrawing_epoch: new_epoch,
            validator_id,
            is_voluntary: false,
        });
    };
    in_set
}

/// Called by `ika_system` to add a new validator to `pending_active_validators`
public(package) fun request_add_validator(
    self: &mut ValidatorSet,
    current_epoch: u64,
    cap: &ValidatorCap,
) {
    let validator_id = cap.validator_id();
    assert!(self.validators.contains(validator_id), EValidatorNotCandidate);
    let committee_selected = self.next_epoch_active_committee.is_some();
    // We have to remove and to add again because we can have 2 refs to self
    let mut validator = self.validators.remove(validator_id);
    assert!(!self.is_duplicate_with_pending_validator(&validator), EDuplicateValidator);

    assert!(validator.is_preactive(), EValidatorNotCandidate);

    validator.activate(cap, current_epoch, committee_selected);

    self.validators.add(validator_id, validator);

    let in_set = self.update_pending_active_set(
        validator_id,
        current_epoch,
        committee_selected,
        true,
    );
    assert!(in_set, ECannotJoinActiveSet);
}

public(package) fun assert_no_pending_or_active_duplicates(
    self: &mut ValidatorSet,
    validator_id: ID,
) {
    assert!(self.validators.contains(validator_id), ENotAValidator);
    // We have to remove and to add again because we can have 2 refs to self
    let validator = self.validators.remove(validator_id);

    assert!(!self.is_duplicate_with_pending_validator(&validator), EDuplicateValidator);

    self.validators.add(validator_id, validator);
}

public(package) fun assert_validator_can_set_for_next_epoch(
    self: &ValidatorSet,
    validator_id: ID,
) {
    assert!(
        !self.next_epoch_active_committee.is_some_and!(|c| c.contains(&validator_id)),
        ECannotSetBeforeNextEpoch
    );
}

/// Called by `ika_system`, to remove a validator.
/// The index of the validator is added to `pending_removals` and
/// will be processed at the end of epoch.
/// Only an active validator can request to be removed.
public(package) fun request_remove_validator(
    self: &mut ValidatorSet,
    current_epoch: u64,
    cap: &ValidatorCap,
) {
    let validator_id = cap.validator_id();
    let committee_selected = self.next_epoch_active_committee.is_some();

    let validator = self.get_validator_mut(validator_id);
    assert!(!validator.is_withdrawing(), EValidatorAlreadyRemoved);

    let withdrawing_epoch = if (committee_selected) {
        current_epoch + 2
    } else {
        current_epoch + 1
    };
    validator.set_withdrawing(cap, withdrawing_epoch);
    self.pending_active_set.borrow_mut().remove(validator_id);
    event::emit(ValidatorLeaveEvent {
        withdrawing_epoch,
        validator_id,
        is_voluntary: true,
    });
}

// ==== staking related functions ====

/// Called by `ika_system`, to add a new stake to the validator.
/// This request is added to the validator's validator's pending stake entries, processed at the end
/// of the epoch.
/// Aborts in case the staking amount is smaller than MIN_STAKING_THRESHOLD
public(package) fun request_add_stake(
    self: &mut ValidatorSet,
    epoch: u64,
    validator_id: ID,
    stake: Balance<IKA>,
    ctx: &mut TxContext,
): StakedIka {
    let committee_selected = self.next_epoch_active_committee.is_some();
    let ika_amount = stake.value();
    assert!(ika_amount >= MIN_STAKING_THRESHOLD, EStakingBelowThreshold);
    let validator = self.get_validator_mut(validator_id);
    let staked_ika = validator.request_add_stake(
        stake,
        epoch,
        committee_selected,
        ctx,
    );
    self.update_pending_active_set(validator_id, epoch, committee_selected, false);
    staked_ika
}

/// Requests withdrawal of the given amount from the `StakedIKA`, marking it as
/// `Withdrawing`. Once the epoch is greater than the `withdraw_epoch`, the
/// withdrawal can be performed.
public(package) fun request_withdraw_stake(
    self: &mut ValidatorSet,
    staked_ika: &mut StakedIka,
    current_epoch: u64,
) {
    let validator_id = staked_ika.validator_id();
    let committee_selected = self.next_epoch_active_committee.is_some();
    let is_current_committee = self.active_committee.contains(&validator_id);
    let is_next_committee = self
        .next_epoch_active_committee
        .is_some_and!(|c| c.contains(&validator_id));
    let validator = self.get_validator_mut(validator_id);
    validator.request_withdraw_stake(
        staked_ika,
        is_current_committee,
        is_next_committee,
        current_epoch,
    );
    self.update_pending_active_set(validator_id, current_epoch, committee_selected, false);
}

/// Perform the withdrawal of the staked WAL, returning the amount to the caller.
/// The `StakedWal` must be in the `Withdrawing` state, and the epoch must be
/// greater than the `withdraw_epoch`.
public(package) fun withdraw_stake(
    self: &mut ValidatorSet,
    staked_ika: StakedIka,
    current_epoch: u64,
    ctx: &mut TxContext,
): Coin<IKA> {
    let validator_id = staked_ika.validator_id();
    let committee_selected = self.next_epoch_active_committee.is_some();
    let is_current_committee = self.active_committee.contains(&validator_id);
    let is_next_committee = self
        .next_epoch_active_committee
        .is_some_and!(|c| c.contains(&validator_id));

    let validator = self.get_validator_mut(validator_id);
    let ika_balance = validator.withdraw_stake(
        staked_ika,
        is_current_committee,
        is_next_committee,
        current_epoch,
    );
    self.update_pending_active_set(validator_id, current_epoch, committee_selected, false);
    ika_balance.into_coin(ctx)
}

// ==== validator config setting functions ====

/// Create a new `ValidatorOperationCap` and registers it.
/// The original object is thus revoked.
public(package) fun rotate_operation_cap(
    self: &mut ValidatorSet,
    cap: &ValidatorCap,
    system_object_cap: &SystemObjectCap,
    ctx: &mut TxContext,
): ValidatorOperationCap {
    let validator = self.get_validator_mut(cap.validator_id());
    validator.rotate_operation_cap(cap, system_object_cap, ctx)
}

/// Create a new `ValidatorCommissionCap` and registers it.
/// The original object is thus revoked.
public(package) fun rotate_commission_cap(
    self: &mut ValidatorSet,
    cap: &ValidatorCap,
    system_object_cap: &SystemObjectCap,
    ctx: &mut TxContext,
): ValidatorCommissionCap {
    let validator = self.get_validator_mut(cap.validator_id());
    validator.rotate_commission_cap(cap, system_object_cap, ctx)
}

public(package) fun collect_commission(
    self: &mut ValidatorSet,
    cap: &ValidatorCommissionCap,
    amount: Option<u64>,
): Balance<IKA> {
    let validator_id = cap.validator_id();
    let validator = self.get_validator_mut(validator_id);
    validator.collect_commission(cap, amount)
}

public(package) fun set_validator_name(
    self: &mut ValidatorSet,
    name: String,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator_mut(validator_id);
    validator.set_name(name, cap);
}

public(package) fun validator_metadata(self: &ValidatorSet, validator_id: ID): ValidatorMetadata {
    let validator = self.get_validator(validator_id);
    validator.validator_info().metadata()
}

public(package) fun set_validator_metadata(
    self: &mut ValidatorSet,
    cap: &ValidatorOperationCap,
    metadata: ValidatorMetadata,
) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator_mut(validator_id);
    validator.set_validator_metadata(cap, metadata);
}

/// Request to set commission rate for the validator.
public(package) fun set_next_commission(
    self: &mut ValidatorSet,
    new_commission_rate: u16,
    cap: &ValidatorOperationCap,
    current_epoch: u64,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_commission(new_commission_rate, current_epoch, cap);
}

public(package) fun set_next_epoch_network_address(
    self: &mut ValidatorSet,
    network_address: String,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_network_address(network_address, cap);
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_p2p_address(
    self: &mut ValidatorSet,
    p2p_address: String,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_p2p_address(p2p_address, cap);
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_consensus_address(
    self: &mut ValidatorSet,
    consensus_address: String,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_consensus_address(consensus_address, cap);
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_protocol_pubkey_bytes(
    self: &mut ValidatorSet,
    protocol_pubkey_bytes: vector<u8>,
    proof_of_possession: vector<u8>,
    cap: &ValidatorOperationCap,
    ctx: &TxContext,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_protocol_pubkey_bytes(
        protocol_pubkey_bytes,
        proof_of_possession,
        cap,
        ctx,
    );
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_network_pubkey_bytes(
    self: &mut ValidatorSet,
    network_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_network_pubkey_bytes(network_pubkey_bytes, cap);
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_consensus_pubkey_bytes(
    self: &mut ValidatorSet,
    consensus_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    validator.set_next_epoch_consensus_pubkey_bytes(consensus_pubkey_bytes, cap);
    self.assert_no_pending_or_active_duplicates(validator_id);
}

public(package) fun set_next_epoch_mpc_data_bytes(
    self: &mut ValidatorSet,
    mpc_data_bytes: TableVec<vector<u8>>,
    cap: &ValidatorOperationCap,
): Option<TableVec<vector<u8>>> {
    let validator_id = cap.validator_id();
    self.assert_validator_can_set_for_next_epoch(validator_id);
    let validator = self.get_validator_mut(validator_id);
    let previous_mpc_data_key = validator.set_next_epoch_mpc_data_bytes(
        mpc_data_bytes,
        cap,
    );
    self.assert_no_pending_or_active_duplicates(validator_id);
    previous_mpc_data_key

}

// ==== epoch change functions ====

/// Process the pending validator changes at mid epoch
public(package) fun initiate_mid_epoch_reconfiguration(self: &mut ValidatorSet) {
    assert!(self.next_epoch_active_committee.is_none(), EProcessMidEpochOnlyAfterAdvanceEpoch);

    self.process_pending_validators();
}

/// Update the validator set at the end of epoch.
/// It does the following things:
///   1. Distribute stake award.
///   2. Process pending stake deposits and withdraws for each validator (`adjust_stake`).
///   3. Process pending stake deposits, and withdraws.
///   4. Process pending validator application and withdraws.
///   5. At the end, we calculate the total stake for the new epoch.
public(package) fun advance_epoch(
    self: &mut ValidatorSet,
    new_epoch: u64,
    total_rewards: &mut Balance<IKA>,
) {
    assert!(self.next_epoch_active_committee.is_some(), EAdvanceEpochOnlyAfterProcessMidEpoch);

    let total_voting_power = self.active_committee.total_voting_power();

    // Compute the reward distribution without taking into account the tallying rule slashing.
    let unadjusted_staking_reward_amounts = self.compute_unadjusted_reward_distribution(
        total_voting_power,
        total_rewards.value(),
    );

    // Use the tallying rule report records for the epoch to compute validators that will be
    // punished.
    let slashed_validators = self.compute_slashed_validators();

    // let total_slashed_validator_voting_power = self.sum_voting_power_by_validator_indices(
    //     slashed_validators,
    // );

    let total_slashed_validator_voting_power = slashed_validators.length();

    let slashed_validator_indices = self.get_validator_indices(&slashed_validators);

    // Compute the reward adjustments of slashed validators, to be taken into
    // account in adjusted reward computation.
    let (
        total_staking_reward_adjustment,
        individual_staking_reward_adjustments,
    ) = compute_reward_adjustments(
        slashed_validator_indices,
        self.reward_slashing_rate,
        &unadjusted_staking_reward_amounts,
    );

    // Compute the adjusted amounts of stake each validator should get given the tallying rule
    // reward adjustments we computed before.
    // `compute_adjusted_reward_distribution` must be called before `distribute_reward` and `adjust_stake_and_computation_price` to
    // make sure we are using the current epoch's stake information to compute reward distribution.
    let (adjusted_staking_reward_amounts) = self.compute_adjusted_reward_distribution(
        total_voting_power,
        total_slashed_validator_voting_power,
        unadjusted_staking_reward_amounts,
        total_staking_reward_adjustment,
        individual_staking_reward_adjustments,
    );

    // Distribute the rewards before adjusting stake so that we immediately start compounding
    // the rewards for validators and stakers.
    self.distribute_reward(
        new_epoch,
        &adjusted_staking_reward_amounts,
        total_rewards,
    );

    self.previous_committee = self.active_committee;

    // Change to the next validator committee
    self.active_committee = self.next_epoch_active_committee.extract();

    // Activate validators that were added during `process_mid_epoch`
    self.activate_added_validators(new_epoch);

    self.pending_active_set.borrow_mut().reset_validator_changes();

    // Emit events after we have processed all the rewards distribution and pending stakes.
    self.emit_validator_epoch_events(
        new_epoch,
        &adjusted_staking_reward_amounts,
        &slashed_validators,
    );

    self.total_stake = self.calculate_total_stakes();
}

// Activate validators added during `process_mid_epoch` and kept in `next_epoch_active_committee`.
fun activate_added_validators(self: &mut ValidatorSet, new_epoch: u64) {
    let members = *self.active_committee.members();
    members.do!(|member| {
        let validator = self.get_validator_mut(member.validator_id());
        if (validator.activation_epoch().is_some_and!(|epoch| epoch == new_epoch)) {
            validator.advance_epoch(balance::zero(), new_epoch);
            event::emit(ValidatorJoinEvent {
                epoch: new_epoch,
                validator_id: validator.validator_id(),
            });
        };
    });
}

public(package) fun set_min_validator_count(self: &mut ValidatorSet, min_validator_count: u64) {
    self.pending_active_set.borrow_mut().set_min_validator_count(min_validator_count);
}

public(package) fun set_max_validator_count(self: &mut ValidatorSet, max_validator_count: u64) {
    self.pending_active_set.borrow_mut().set_max_validator_count(max_validator_count);
}

public(package) fun set_min_validator_joining_stake(
    self: &mut ValidatorSet,
    min_validator_joining_stake: u64,
) {
    self
        .pending_active_set
        .borrow_mut()
        .set_min_validator_joining_stake(min_validator_joining_stake);
}

public(package) fun set_max_validator_change_count(
    self: &mut ValidatorSet,
    max_validator_change_count: u64,
) {
    self.pending_active_set.borrow_mut().set_max_validator_change_count(max_validator_change_count);
}

public(package) fun set_reward_slashing_rate(self: &mut ValidatorSet, reward_slashing_rate: u16) {
    self.reward_slashing_rate = reward_slashing_rate;
}

// ==== getter functions ====

public fun total_stake(self: &ValidatorSet): u64 {
    self.total_stake
}

public fun validator_total_stake_amount(self: &mut ValidatorSet, validator_id: ID): u64 {
    let validator = get_validator(self, validator_id);
    validator.ika_balance()
}

public(package) fun token_exchange_rates(
    self: &ValidatorSet,
    validator_id: ID,
): &Table<u64, TokenExchangeRate> {
    let validator = self.get_validator(validator_id);
    validator.exchange_rates()
}

/// Get the total number of pending validators.
public(package) fun pending_active_validators_count(self: &ValidatorSet): u64 {
    self.pending_active_set.borrow().size()
}

/// Returns true if exists in active validators.
public(package) fun is_active_validator(self: &ValidatorSet, validator_id: ID): bool {
    self.active_committee.contains(&validator_id)
}

/// Returns all the validators who are currently reporting `validator_id`
public(package) fun get_reporters_of(self: &ValidatorSet, validator_id: ID): VecSet<ID> {
    if (self.validator_report_records.contains(&validator_id)) {
        self.validator_report_records[&validator_id]
    } else {
        vec_set::empty()
    }
}
// ==== private helpers ====

/// Checks whether `new_validator` is duplicate with any currently pending validators in the pending active set.
fun is_duplicate_with_pending_validator(self: &ValidatorSet, new_validator: &Validator): bool {
    let pending_active_validator_ids = self.pending_active_set.borrow().active_ids();
    pending_active_validator_ids.any!(|id| {
        if (new_validator.validator_id() == *id) {
            false
        } else {
            let validator = self.get_validator(*id);
            validator.validator_info().is_duplicate(new_validator.validator_info())
        }
    })
}

/// Get mutable reference to a validator by id.
public(package) fun get_validator_mut(self: &mut ValidatorSet, validator_id: ID): &mut Validator {
    assert!(self.validators.contains(validator_id), ENotAValidator);
    self.validators.borrow_mut(validator_id)
}

/// Get reference to a validator by id.
public fun get_validator(self: &ValidatorSet, validator_id: ID): &Validator {
    assert!(self.validators.contains(validator_id), ENotAValidator);
    self.validators.borrow(validator_id)
}

/// Given a vector of validator ids to look for, return their indices in the validator vector.
/// Aborts if any id isn't in the given validator vector.
fun get_validator_indices(self: &ValidatorSet, look_for_indices_ids: &vector<ID>): vector<u64> {
    let validators = self.active_committee.validator_ids();
    let length = look_for_indices_ids.length();
    let mut i = 0;
    let mut res = vector[];
    while (i < length) {
        let validator_id = look_for_indices_ids[i];
        let (found, index_opt) = validators.index_of(&validator_id);
        assert!(found, ENotAValidator);
        res.push_back(index_opt);
        i = i + 1;
    };
    res
}

/// Verify the validator capability is valid for a Validator.
public(package) fun verify_validator_cap(self: &ValidatorSet, cap: &ValidatorCap) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator(validator_id);
    assert!(validator.validator_cap_id() == &object::id(cap), EInvalidCap);
}

/// Verify the operation capability is valid for a Validator.
public(package) fun verify_operation_cap(self: &ValidatorSet, cap: &ValidatorOperationCap) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator(validator_id);
    assert!(validator.operation_cap_id() == &object::id(cap), EInvalidCap);
}

/// Verify the commission capability is valid for a Validator.
public(package) fun verify_commission_cap(self: &ValidatorSet, cap: &ValidatorCommissionCap) {
    let validator_id = cap.validator_id();
    let validator = self.get_validator(validator_id);
    assert!(validator.commission_cap_id() == &object::id(cap), EInvalidCap);
}

/// Process the pending new validators. They will be `next_epoch_active_committee` and activated during `advance_epoch`.
fun process_pending_validators(self: &mut ValidatorSet) {
    let mut next_epoch_active_members = vector[];
    let mut i = 0;
    let pending_active_validator_ids = self.pending_active_set.borrow().active_ids();
    let length = pending_active_validator_ids.length();
    while (i < length) {
        let validator_id = pending_active_validator_ids[i];
        let validator = self.get_validator_mut(validator_id);
        next_epoch_active_members.push_back(
            new_bls_committee_member(validator_id, *validator.validator_info().protocol_pubkey()),
        );
        i = i + 1;
    };
    let next_epoch_active_committee = new_bls_committee(next_epoch_active_members);
    self.next_epoch_active_committee.fill(next_epoch_active_committee);
}

/// Calculate the total active validator stake.
fun calculate_total_stakes(self: &mut ValidatorSet): u64 {
    let mut stake = 0;
    let members = *self.active_committee.members();
    members.do!(|member| {
        let validator_id = member.validator_id();
        let validator = self.get_validator_mut(validator_id);
        stake = stake + validator.ika_balance();
    });

    stake
}

/// Compute both the individual reward adjustments and total reward adjustment for staking rewards
/// as well as storage fund rewards.
fun compute_reward_adjustments(
    mut slashed_validator_indices: vector<u64>,
    reward_slashing_rate: u16,
    unadjusted_staking_reward_amounts: &vector<u64>,
): (
    u64, // sum of staking reward adjustments
    VecMap<u64, u64>, // mapping of individual validator's staking reward adjustment from index -> amount
) {
    let mut total_staking_reward_adjustment = 0;
    let mut individual_staking_reward_adjustments = vec_map::empty();

    while (!slashed_validator_indices.is_empty()) {
        let validator_index = slashed_validator_indices.pop_back();

        // Use the slashing rate to compute the amount of staking rewards slashed from this punished validator.
        let unadjusted_staking_reward = unadjusted_staking_reward_amounts[validator_index];
        let staking_reward_adjustment_u128 =
            unadjusted_staking_reward as u128 * (reward_slashing_rate as u128)
                / BASIS_POINT_DENOMINATOR_U128;

        // Insert into individual mapping and record into the total adjustment sum.
        individual_staking_reward_adjustments.insert(
            validator_index,
            staking_reward_adjustment_u128 as u64,
        );
        total_staking_reward_adjustment =
            total_staking_reward_adjustment + (staking_reward_adjustment_u128 as u64);
    };

    (total_staking_reward_adjustment, individual_staking_reward_adjustments)
}

/// Process the validator report records of the epoch and return the ids of the
/// non-performant validators according to the input threshold.
fun compute_slashed_validators(self: &mut ValidatorSet): vector<ID> {
    let mut slashed_validators = vector[];
    while (!self.validator_report_records.is_empty()) {
        let (validator_id, reporters) = self.validator_report_records.pop();
        assert!(is_active_validator(self, validator_id), ENonValidatorInReportRecords);
        // Sum up the voting power of validators that have reported this validator and check if it has
        // passed the slashing threshold.
        // let reporter_votes = sum_voting_power_by_validator_indices(
        //     self,
        //     reporters.into_keys(),
        // );
        let reporter_votes = reporters.size();
        //if (reporter_votes >= quorum_threshold()) {
        if (self.active_committee.is_quorum_threshold(reporter_votes)) {
            slashed_validators.push_back(validator_id);
        }
    };
    slashed_validators
}

/// Given the current list of active validators, the total stake and total reward,
/// calculate the amount of reward each validator should get, without taking into
/// account the tallying rule results.
/// Returns the unadjusted amounts of staking reward for each validator.
fun compute_unadjusted_reward_distribution(
    self: &ValidatorSet,
    total_voting_power: u64,
    total_rewards: u64,
): vector<u64> {
    let members = self.active_committee.members();
    let reward_amounts = members.map_ref!(|_| {
        // Integer divisions will truncate the results. Because of this, we expect that at the end
        // there will be some reward remaining in `total_rewards`.
        // Use u128 to avoid multiplication overflow.
        let reward_amount = (total_rewards as u128) / (total_voting_power as u128);
        reward_amount as u64
    });
    reward_amounts
}

/// Use the reward adjustment info to compute the adjusted rewards each validator should get.
/// Returns the staking rewards each validator gets.
/// The staking rewards are shared with the stakers.
fun compute_adjusted_reward_distribution(
    self: &ValidatorSet,
    total_voting_power: u64,
    total_slashed_validator_voting_power: u64,
    unadjusted_staking_reward_amounts: vector<u64>,
    total_staking_reward_adjustment: u64,
    individual_staking_reward_adjustments: VecMap<u64, u64>,
): vector<u64> {
    let total_unslashed_validator_voting_power =
        total_voting_power - total_slashed_validator_voting_power;
    let mut adjusted_staking_reward_amounts = vector[];
    let members = self.active_committee.members();
    let mut i = 0;
    let length = members.length();

    while (i < length) {
        // Integer divisions will truncate the results. Because of this, we expect that at the end
        // there will be some reward remaining in `total_reward`.
        // Use u128 to avoid multiplication overflow.

        // Compute adjusted staking reward.
        let unadjusted_staking_reward_amount = unadjusted_staking_reward_amounts[i];
        let adjusted_staking_reward_amount // If the validator is one of the slashed ones, then subtract the adjustment.
         = if (individual_staking_reward_adjustments.contains(&i)) {
            let adjustment = individual_staking_reward_adjustments[&i];
            unadjusted_staking_reward_amount - adjustment
        } else {
            // Otherwise the slashed rewards should be distributed among the unslashed
            // validators so add the corresponding adjustment.
            let adjustment =
                total_staking_reward_adjustment as u128
                                   / (total_unslashed_validator_voting_power as u128);
            unadjusted_staking_reward_amount + (adjustment as u64)
        };
        adjusted_staking_reward_amounts.push_back(adjusted_staking_reward_amount);
        i = i + 1;
    };
    adjusted_staking_reward_amounts
}

/// Distribute rewards to validators and stakers
fun distribute_reward(
    self: &mut ValidatorSet,
    new_epoch: u64,
    adjusted_staking_reward_amounts: &vector<u64>,
    staking_rewards: &mut Balance<IKA>,
) {
    let pending_active_set = self.pending_active_set.borrow_mut();
    let members = *self.active_committee.members();
    let length = members.length();
    let mut i = 0;
    while (i < length) {
        let validator_id = members[i].validator_id();
        let validator = &mut self.validators[validator_id];
        let staking_reward_amount = adjusted_staking_reward_amounts[i];
        let validator_rewards = staking_rewards.split(staking_reward_amount);

        validator.advance_epoch(validator_rewards, new_epoch);
        pending_active_set.update(validator_id, validator.ika_balance_at_epoch(new_epoch));
        i = i + 1;
    }
}

/// Emit events containing information of each validator for the epoch,
/// including stakes, rewards, performance, etc.
fun emit_validator_epoch_events(
    self: &ValidatorSet,
    new_epoch: u64,
    staking_rewards_amounts: &vector<u64>,
    slashed_validators: &vector<ID>,
) {
    let members = *self.previous_committee.members();
    let num_validators = members.length();
    let mut i = 0;
    while (i < num_validators) {
        let member = members[i];
        let validator_id = member.validator_id();
        let validator = self.get_validator(validator_id);
        let tallying_rule_reporters = if (self.validator_report_records.contains(&validator_id)) {
            self.validator_report_records[&validator_id].into_keys()
        } else {
            vector[]
        };
        let tallying_rule_global_score = if (slashed_validators.contains(&validator_id)) 0 else 1;
        event::emit(ValidatorEpochInfoEventV1 {
            epoch: new_epoch,
            validator_id,
            //reference_gas_survey_quote: validator.computation_price(),
            stake: validator.ika_balance(),
            commission_rate: validator.commission_rate(),
            staking_rewards: staking_rewards_amounts[i],
            token_exchange_rate: validator.exchange_rate_at_epoch(new_epoch),
            tallying_rule_reporters,
            tallying_rule_global_score,
        });
        i = i + 1;
    }
}

// /// Sum up the total stake of a given list of validator indices.
// public fun sum_voting_power_by_validator_indices(self: &mut ValidatorSet, validator_ids: vector<ID>): u64 {
//     let validator_indices = get_validator_indices(self, &validator_ids);
//     //let members = self.active_committee.members();
//     let sum = validator_indices.fold!(0, |s, i|  {
//         s + 1 //members[i].voting_power()
//     });
//     sum
// }

/// Report a validator as a bad or non-performant actor in the system.
/// Succeeds if all the following are satisfied:
/// 1. both the reporter in `cap` and the input `reportee_id` are active validators.
/// 2. reporter and reportee not the same address.
/// 3. the cap object is still valid.
/// This function is idempotent.
public(package) fun report_validator(
    self: &mut ValidatorSet,
    operation_cap: &ValidatorOperationCap,
    reportee_id: ID,
) {
    // Reportee needs to be an active validator
    assert!(self.is_active_validator(reportee_id), ENotAValidator);
    // Verify the represented reporter address is an active validator, and the capability is still valid.
    assert!(self.is_active_validator(operation_cap.validator_id()), ENotAValidator);
    self.verify_operation_cap(operation_cap);
    report_validator_impl(operation_cap, reportee_id, &mut self.validator_report_records);
}

/// Undo a `report_validator` action. Aborts if
/// 1. the reportee is not a currently active validator or
/// 2. the sender has not previously reported the `reportee_id`, or
/// 3. the cap is not valid
public(package) fun undo_report_validator(
    self: &mut ValidatorSet,
    operation_cap: &ValidatorOperationCap,
    reportee_id: ID,
) {
    // Verify the represented reporter address is an active validator, and the capability is still valid.
    assert!(self.is_active_validator(operation_cap.validator_id()), ENotAValidator);
    self.verify_operation_cap(operation_cap);
    undo_report_validator_impl(operation_cap, reportee_id, &mut self.validator_report_records);
}

fun report_validator_impl(
    operation_cap: &ValidatorOperationCap,
    reportee_id: ID,
    validator_report_records: &mut VecMap<ID, VecSet<ID>>,
) {
    let reporter_id = operation_cap.validator_id();
    assert!(reporter_id != reportee_id, ECannotReportOneself);
    if (!validator_report_records.contains(&reportee_id)) {
        validator_report_records.insert(reportee_id, vec_set::singleton(reporter_id));
    } else {
        let reporters = validator_report_records.get_mut(&reportee_id);
        if (!reporters.contains(&reporter_id)) {
            reporters.insert(reporter_id);
        }
    }
}

fun undo_report_validator_impl(
    operation_cap: &ValidatorOperationCap,
    reportee_id: ID,
    validator_report_records: &mut VecMap<ID, VecSet<ID>>,
) {
    assert!(validator_report_records.contains(&reportee_id), EReportRecordNotFound);
    let reporters = validator_report_records.get_mut(&reportee_id);

    let reporter_id = operation_cap.validator_id();
    assert!(reporters.contains(&reporter_id), EReportRecordNotFound);

    reporters.remove(&reporter_id);
    if (reporters.is_empty()) {
        validator_report_records.remove(&reportee_id);
    }
}

/// Return the active validators in `self`
public fun active_committee(self: &ValidatorSet): BlsCommittee {
    self.active_committee
}

/// Return the next epoch active committee in `self`
public fun next_epoch_active_committee(self: &ValidatorSet): Option<BlsCommittee> {
    self.next_epoch_active_committee
}

/// Return the pending active set in `self`
public fun pending_active_set(self: &ValidatorSet): &PendingActiveSet {
    self.pending_active_set.borrow()
}

/// Returns true if the `validator_id` is a validator candidate.
public fun is_validator_candidate(self: &mut ValidatorSet, validator_id: ID): bool {
    let validator = self.get_validator(validator_id);
    validator.is_preactive()
}

/// Returns true if the validator identified by `validator_id` is of an inactive validator.
public fun is_inactive_validator(self: &mut ValidatorSet, validator_id: ID): bool {
    let validator = self.get_validator(validator_id);
    validator.is_withdrawing()
}

// === Utility functions ===

/// Calculate the rewards for an amount with value `staked_principal`, staked in the validator with
/// the given `validator_id` between `activation_epoch` and `withdraw_epoch`.
public(package) fun calculate_rewards(
    self: &ValidatorSet,
    validator_id: ID,
    staked_principal: u64,
    activation_epoch: u64,
    withdraw_epoch: u64,
): u64 {
    let validator = self.get_validator(validator_id);
    validator.calculate_rewards(staked_principal, activation_epoch, withdraw_epoch)
}

/// Check whether StakedIka can be withdrawn directly.
public(package) fun can_withdraw_staked_ika_early(
    self: &ValidatorSet,
    staked_ika: &StakedIka,
    current_epoch: u64,
): bool {
    let validator_id = staked_ika.validator_id();
    let is_next_committee = self
        .next_epoch_active_committee
        .is_some_and!(|c| c.contains(&validator_id));
    staked_ika.can_withdraw_early(is_next_committee, current_epoch)
}
