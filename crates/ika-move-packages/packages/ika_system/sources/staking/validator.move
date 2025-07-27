// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::validator;

use ika::ika::IKA;
use ika_common::system_object_cap::SystemObjectCap;
use ika_common::validator_cap::{Self, ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap};
use ika_system::pending_values::{Self, PendingValues};
use ika_system::staked_ika::{Self, StakedIka};
use ika_system::token_exchange_rate::{Self, TokenExchangeRate};
use ika_system::validator_info::{Self, ValidatorInfo};
use ika_system::validator_metadata::ValidatorMetadata;
use std::string::String;
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::table::{Self, Table};
use sui::table_vec::TableVec;

// === Constants ===

/// The number of basis points in 100%.
const BASIS_POINT_DENOMINATOR: u16 = 10_000;

// === Errors ===

/// The epoch of the validator has already been advanced.
const EValidatorAlreadyUpdated: u64 = 0;
/// Error in a calculation. Indicates that a sanity check failed.
const ECalculationError: u64 = 1;
/// The state of the validator and the parameters to advance the epoch are not consistent.
const EIncorrectEpochAdvance: u64 = 2;
/// Trying to destroy a non-empty validator.
const EValidatorNotEmpty: u64 = 3;
/// Validator is not in `PreActive` state.
const EValidatorIsNotPreActive: u64 = 4;
/// Trying to set the validator to withdrawing state when it is already withdrawing.
const EValidatorAlreadyWithdrawing: u64 = 5;
/// Validator is not in `Active` state.
const EValidatorIsNotActive: u64 = 6;
/// Trying to stake zero amount.
const EZeroStake: u64 = 7;
/// StakedIka is already in `Withdrawing` state.
const ENotStaked: u64 = 8;
/// Trying to withdraw stake from the incorrect validator.
const EIncorrectValidatorId: u64 = 9;
/// Trying to withdraw active stake.
const ENotWithdrawing: u64 = 10;
/// Attempt to withdraw before `withdraw_epoch`.
const EWithdrawEpochNotReached: u64 = 11;
/// Attempt to withdraw before `activation_epoch`.
const EActivationEpochNotReached: u64 = 12;
/// Requesting withdrawal for the stake that can be withdrawn directly.
const EWithdrawDirectly: u64 = 13;
/// Incorrect commission rate.
const EIncorrectCommissionRate: u64 = 14;
/// Trying to collect commission or change receiver without authorization.
const EAuthorizationFailure: u64 = 15;
/// The number of shares for the staked IKA are zero.
const EZeroShares: u64 = 16;

// === Structs ===

/// Represents the state of the validator.
public enum ValidatorState has copy, drop, store {
    /// The validator is not active yet but can accept stakes.
    PreActive,
    /// The validator is active and can accept stakes.
    Active,
    /// The validator awaits the stake to be withdrawn. The value inside the
    /// variant is the epoch in which the validator will be withdrawn.
    Withdrawing(u64),
}

/// Represents a single validator. Even though it is never
/// transferred or shared, the `key` ability is added for discoverability
/// in the `ObjectTable`.
///
/// High level overview of the validator:
/// The validator maintains a balance of IKA 'ika_balance' that is increased
/// when stakes/rewards are added to the validator, and is decreased when
/// stakes are withdrawn.
/// To track the users' portion of the validator, we associate shares to the
/// staked IKA. Initially, the share price is 1 IKA per share.
/// When a new stake is added to the validator, the total number of shares
/// increases by an amount that corresponds to the share price at that
/// time. E.g., if the share price is 2 IKA per share, and 10 IKA are
/// added to the validator, the total number of shares is increased by 5
/// shares. The total number of shares is stored in 'num_shares'.
///
/// As stakes are added/withdrawn only in the granularity of epochs, we
/// maintain a share price per epoch in 'exchange_rates'.
/// StakedIka objects only need to store the epoch when they are created,
/// and the amount of IKA they locked. Whenever a settlement is performed
/// for a StakedIka, we calculate the number of shares that correspond to
/// the amount of IKA that was locked using the exchange rate at the time
/// of the lock, and then convert it to the amount of IKA that corresponds
/// to the current share price.
public struct Validator has key, store {
    id: UID,
    /// The validator info for the validator.
    validator_info: ValidatorInfo,
    /// The current state of the validator.
    state: ValidatorState,
    /// The epoch when the validator is / will be activated.
    /// Serves information purposes only, the checks are performed in the `state`
    /// property.
    activation_epoch: Option<u64>,
    /// Epoch when the validator was last updated.
    latest_epoch: u64,
    /// Currently staked IKA in the validator + rewards validator.
    ika_balance: u64,
    /// The total number of shares in the current epoch.
    num_shares: u64,
    /// The amount of the shares that will be withdrawn in E+1 or E+2.
    /// We use this amount to calculate the IKA withdrawal in the
    /// `process_pending_stake`.
    pending_shares_withdraw: PendingValues,
    /// The amount of the stake requested for withdrawal for a node that may
    /// part of the next committee. Stores principals of not yet active stakes.
    /// In practice, those tokens are staked for exactly one epoch.
    pre_active_withdrawals: PendingValues,
    /// The pending commission rate for the validator. Commission rate is applied in
    /// E+2, so we store the value for the matching epoch and apply it in the
    /// `advance_epoch` function.
    pending_commission_rate: PendingValues,
    /// The commission rate for the validator, in basis points.
    commission_rate: u16,
    /// Historical exchange rates for the validator. The key is the epoch when the
    /// exchange rate was set, and the value is the exchange rate (the ratio of
    /// the amount of IKA tokens for the validator shares).
    exchange_rates: Table<u64, TokenExchangeRate>,
    /// The amount of stake that will be added to the `ika_balance`. Can hold
    /// up to two keys: E+1 and E+2, due to the differences in the activation
    /// epoch.
    ///
    /// ```
    /// E+1 -> Balance
    /// E+2 -> Balance
    /// ```
    ///
    /// Single key is cleared in the `advance_epoch` function, leaving only the
    /// next epoch's stake.
    pending_stake: PendingValues,
    /// The rewards that the validator has received from being in the committee.
    rewards_pool: Balance<IKA>,
    /// The commission that the validator has received from the rewards.
    commission: Balance<IKA>,
    /// The ID of this validator's `ValidatorCap`
    validator_cap_id: ID,
    /// The ID of this validator's current valid `ValidatorOperationCap`
    operation_cap_id: ID,
    /// The ID of this validator's current valid `ValidatorCommissionCap`
    commission_cap_id: ID,
    /// Reserved for future use and migrations.
    extra_fields: Bag,
}

// === Package Functions ===

/// Create a new `Validator` object.
/// If committee is selected, the validator will be activated in the next epoch.
/// Otherwise, it will be activated in the current epoch.
public(package) fun new(
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
): (Validator, ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap) {
    let id = object::new(ctx);
    let validator_id = id.to_inner();

    let validator_cap = validator_cap::new_validator_cap(validator_id, ctx, system_object_cap);
    let validator_operation_cap = validator_cap::new_validator_operation_cap(
        validator_id,
        ctx,
        system_object_cap,
    );
    let validator_commission_cap = validator_cap::new_validator_commission_cap(
        validator_id,
        ctx,
        system_object_cap,
    );
    let validator = Validator {
        id,
        validator_info: validator_info::new(
            name,
            validator_id,
            protocol_pubkey_bytes,
            network_pubkey_bytes,
            consensus_pubkey_bytes,
            mpc_data_bytes,
            proof_of_possession_bytes,
            network_address,
            p2p_address,
            consensus_address,
            metadata,
            ctx,
        ),
        state: ValidatorState::PreActive,
        exchange_rates: table::new(ctx),
        commission_rate,
        activation_epoch: option::none(),
        latest_epoch: current_epoch,
        pending_stake: pending_values::empty(),
        pending_shares_withdraw: pending_values::empty(),
        pre_active_withdrawals: pending_values::empty(),
        pending_commission_rate: pending_values::empty(),
        ika_balance: 0,
        num_shares: 0,
        rewards_pool: balance::zero(),
        commission: balance::zero(),
        validator_cap_id: object::id(&validator_cap),
        operation_cap_id: object::id(&validator_operation_cap),
        commission_cap_id: object::id(&validator_commission_cap),
        extra_fields: bag::new(ctx),
    };
    (validator, validator_cap, validator_operation_cap, validator_commission_cap)
}

/// Activate the validator for participation in the network.
public(package) fun activate(
    validator: &mut Validator,
    validator_cap: &ValidatorCap,
    current_epoch: u64,
    committee_selected: bool,
) {
    assert!(validator_cap.validator_id() == validator.validator_id(), EAuthorizationFailure);
    assert!(object::id(validator_cap) == validator.validator_cap_id, EAuthorizationFailure);
    assert!(validator.state == ValidatorState::PreActive, EValidatorIsNotPreActive);
    let activation_epoch = if (committee_selected) {
        current_epoch + 2
    } else {
        current_epoch + 1
    };

    // // Add the initial exchange rate to the table.
    // validator.exchange_rates.add(activation_epoch, token_exchange_rate::flat());

    validator.state = ValidatorState::Active;
    validator.activation_epoch.fill(activation_epoch);
}

/// Set the state of the validator to `Withdrawing`.
public(package) fun set_withdrawing(
    validator: &mut Validator,
    validator_cap: &ValidatorCap,
    current_epoch: u64,
) {
    assert!(validator_cap.validator_id() == validator.validator_id(), EAuthorizationFailure);
    assert!(object::id(validator_cap) == validator.validator_cap_id, EAuthorizationFailure);
    assert!(!validator.is_withdrawing(), EValidatorAlreadyWithdrawing);
    validator.state = ValidatorState::Withdrawing(current_epoch);
}

/// Deactivate the validator from network participation by setting the state to `Withdrawing`.
/// This is a function to deactivate the validator from the network participation without validator cap.
public(package) fun deactivate(validator: &mut Validator, deactivation_epoch: u64) {
    validator.state = ValidatorState::Withdrawing(deactivation_epoch);
}

/// Stake the given amount of IKA in the validator.
public(package) fun request_add_stake(
    validator: &mut Validator,
    to_stake: Balance<IKA>,
    current_epoch: u64,
    committee_selected: bool,
    ctx: &mut TxContext,
): StakedIka {
    assert!(validator.is_preactive() || validator.is_active(), EValidatorIsNotActive);
    assert!(to_stake.value() > 0, EZeroStake);

    let activation_epoch = if (committee_selected) {
        current_epoch + 2
    } else {
        current_epoch + 1
    };

    let staked_amount = to_stake.value();
    let staked_ika = staked_ika::mint(
        validator.validator_id(),
        to_stake,
        activation_epoch,
        ctx,
    );

    // Add the stake to the pending stake either for E+1 or E+2.
    validator.pending_stake.insert_or_add(activation_epoch, staked_amount);
    staked_ika
}

/// Request withdrawal of the given amount from the staked IKA.
/// Marks the `StakedIka` as withdrawing and updates the activation epoch.
public(package) fun request_withdraw_stake(
    validator: &mut Validator,
    staked_ika: &mut StakedIka,
    in_current_committee: bool,
    in_next_committee: bool,
    current_epoch: u64,
) {
    assert!(staked_ika.value() > 0, EZeroStake);
    assert!(staked_ika.validator_id() == validator.validator_id(), EIncorrectValidatorId);
    assert!(staked_ika.is_staked(), ENotStaked);

    // Only allow requesting if the stake cannot be withdrawn directly.
    assert!(!staked_ika.can_withdraw_early(in_next_committee, current_epoch), EWithdrawDirectly);

    // Early withdrawal request: only possible if activation epoch has not been
    // reached, and the stake is already counted for the next committee selection.
    if (staked_ika.activation_epoch() == current_epoch + 1) {
        let withdraw_epoch = staked_ika.activation_epoch() + 1;
        // register principal in the early withdrawals, the value will get converted to
        // the token amount in the `process_pending_stake` function
        validator.pre_active_withdrawals.insert_or_add(withdraw_epoch, staked_ika.value());
        staked_ika.set_withdrawing(withdraw_epoch);
        return
    };

    assert!(staked_ika.activation_epoch() <= current_epoch, EActivationEpochNotReached);

    // If the node is in the committee, the stake will be withdrawn in E+2,
    // otherwise in E+1.
    let withdraw_epoch = if (in_next_committee) {
        current_epoch + 2
    } else if (in_current_committee) {
        current_epoch + 1
    } else {
        abort EWithdrawDirectly
    };

    let principal_amount = staked_ika.value();
    let share_amount = validator
        .exchange_rate_at_epoch(staked_ika.activation_epoch())
        .convert_to_share_amount(principal_amount);

    assert!(share_amount != 0, EZeroShares);

    validator.pending_shares_withdraw.insert_or_add(withdraw_epoch, share_amount);
    staked_ika.set_withdrawing(withdraw_epoch);
}

/// Perform the withdrawal of the staked IKA, returning the amount to the caller.
public(package) fun withdraw_stake(
    validator: &mut Validator,
    staked_ika: StakedIka,
    in_current_committee: bool,
    in_next_committee: bool,
    current_epoch: u64,
): Balance<IKA> {
    assert!(staked_ika.value() > 0, EZeroStake);
    assert!(staked_ika.validator_id() == validator.validator_id(), EIncorrectValidatorId);

    let activation_epoch = staked_ika.activation_epoch();

    // One step, early withdrawal in the case when committee before
    // activation epoch hasn't been selected. covers both E+1 and E+2 cases.
    if (staked_ika.can_withdraw_early(in_next_committee, current_epoch)) {
        validator.pending_stake.reduce(activation_epoch, staked_ika.value());
        return staked_ika.into_balance()
    };

    let rewards_amount = if (
        !in_current_committee && !in_next_committee && staked_ika.is_staked()
    ) {
        // One step withdrawal for an inactive node.
        if (activation_epoch > current_epoch) {
            // Not even active stake yet, remove from pending stake.
            validator.pending_stake.reduce(activation_epoch, staked_ika.value());
            0
        } else {
            // Active stake, remove it with the current epoch as the withdraw epoch.
            let share_amount = validator
                .exchange_rate_at_epoch(activation_epoch)
                .convert_to_share_amount(staked_ika.value());
            validator.pending_shares_withdraw.insert_or_add(current_epoch, share_amount);
            validator.calculate_rewards(staked_ika.value(), activation_epoch, current_epoch)
        }
        // Note that if the stake is in state Withdrawing, it can either be
        // from a pre-active withdrawal, but then
        // (in_current_committee || in_next_committee) is true since it was
        // an early withdrawal, or from a standard two step withdrawal,
        // which is handled below.
    } else {
        // Normal two-step withdrawals.
        assert!(staked_ika.is_withdrawing(), ENotWithdrawing);
        assert!(staked_ika.withdraw_epoch() <= current_epoch, EWithdrawEpochNotReached);
        assert!(activation_epoch <= current_epoch, EActivationEpochNotReached);
        validator.calculate_rewards(
            staked_ika.value(),
            activation_epoch,
            staked_ika.withdraw_epoch(),
        )
    };

    let principal = staked_ika.into_balance();

    // Withdraw rewards. Due to rounding errors, there's a chance that the
    // rewards amount is higher than the rewards validator, in this case, we
    // withdraw the maximum amount possible.
    let rewards_amount = rewards_amount.min(validator.rewards_pool.value());
    let mut to_withdraw = validator.rewards_pool.split(rewards_amount);
    to_withdraw.join(principal);
    to_withdraw
}

/// Advance epoch for the `Validator`.
public(package) fun advance_epoch(
    validator: &mut Validator,
    mut rewards: Balance<IKA>,
    current_epoch: u64,
) {
    assert!(current_epoch > validator.latest_epoch, EValidatorAlreadyUpdated);
    // Sanity check.
    assert!(rewards.value() == 0 || validator.ika_balance > 0, EIncorrectEpochAdvance);

    // Split the commission from the rewards.
    let total_rewards = rewards.value();
    let commission = rewards.split(
        total_rewards * (validator.commission_rate as u64) / (BASIS_POINT_DENOMINATOR as u64),
    );
    validator.commission.join(commission);

    // Update the commission_rate for the new epoch if there's a pending value.
    // Note that pending commission rates are set 2 epochs ahead, so users are
    // aware of the rate change in advance.
    validator.pending_commission_rate.inner().try_get(&current_epoch).do!(|commission_rate| {
        validator.commission_rate = commission_rate as u16;
        validator.pending_commission_rate.flush(current_epoch);
    });

    // Add rewards to the validator and update the `ika_balance`.
    let rewards_amount = rewards.value();
    validator.rewards_pool.join(rewards);
    validator.ika_balance = validator.ika_balance + rewards_amount;
    validator.latest_epoch = current_epoch;
    validator.validator_info.rotate_next_epoch_info();

    // Perform stake deduction / addition for the current epoch.
    validator.process_pending_stake(current_epoch);
}

/// Process the pending stake and withdrawal requests for the validator. Called in the
/// `advance_epoch` function in case the validator is in the committee and receives the
/// rewards. And may be called in user-facing functions to update the validator state,
/// if the validator is not in the committee.
public(package) fun process_pending_stake(validator: &mut Validator, current_epoch: u64) {
    // Set the exchange rate for the current epoch.
    let exchange_rate = token_exchange_rate::new(
        validator.ika_balance,
        validator.num_shares,
    );
    validator.exchange_rates.add(current_epoch, exchange_rate);

    // Process additions.
    validator.ika_balance = validator.ika_balance + validator.pending_stake.flush(current_epoch);

    // Process withdrawals.

    // each value in pending withdrawals contains the principal which became
    // active in the previous epoch. so unlike other pending values, we need to
    // flush it one by one, recalculating the exchange rate and validator share amount
    // for each early withdrawal epoch.
    let mut pre_active_shares_withdraw = 0;
    let mut pre_active_withdrawals = validator.pre_active_withdrawals.unwrap();
    pre_active_withdrawals.keys().do!(|epoch| if (epoch <= current_epoch) {
        let (_, epoch_value) = pre_active_withdrawals.remove(&epoch);
        // recall that pre_active_withdrawals contains stakes that were
        // active for exactly 1 epoch.
        let activation_epoch = epoch - 1;
        let shares_for_epoch = validator
            .exchange_rate_at_epoch(activation_epoch)
            .convert_to_share_amount(epoch_value);

        pre_active_shares_withdraw = pre_active_shares_withdraw + shares_for_epoch;
    });
    // don't forget to flush the early withdrawals since we worked on a copy
    let _ = validator.pre_active_withdrawals.flush(current_epoch);

    let shares_withdraw = validator.pending_shares_withdraw.flush(current_epoch);
    let pending_withdrawal = exchange_rate.convert_to_ika_amount(
        shares_withdraw + pre_active_shares_withdraw,
    );

    // Sanity check that the amount is not higher than the validator balance.
    assert!(validator.ika_balance >= pending_withdrawal, ECalculationError);
    validator.ika_balance = validator.ika_balance - pending_withdrawal;

    // Recalculate the total number of shares according to the exchange rate.
    validator.num_shares = exchange_rate.convert_to_share_amount(validator.ika_balance);
}

public(package) fun verify_validator_cap(self: &Validator, cap: &ValidatorCap) {
    assert!(cap.validator_id() == self.id.to_inner(), EAuthorizationFailure);
    assert!(object::id(cap) == self.validator_cap_id, EAuthorizationFailure);
}

public(package) fun verify_operation_cap(self: &Validator, cap: &ValidatorOperationCap) {
    assert!(cap.validator_id() == self.id.to_inner(), EAuthorizationFailure);
    assert!(object::id(cap) == self.operation_cap_id, EAuthorizationFailure);
}

public(package) fun verify_commission_cap(self: &Validator, cap: &ValidatorCommissionCap) {
    assert!(cap.validator_id() == self.id.to_inner(), EAuthorizationFailure);
    assert!(object::id(cap) == self.commission_cap_id, EAuthorizationFailure);
}

// === Validator parameters ===

/// Sets the name of the validator.
public(package) fun set_name(self: &mut Validator, name: String, cap: &ValidatorOperationCap) {
    self.verify_operation_cap(cap);

    self.validator_info.set_name(name);
}

/// Sets the node metadata.
public(package) fun set_validator_metadata(
    self: &mut Validator,
    cap: &ValidatorOperationCap,
    metadata: ValidatorMetadata,
) {
    self.verify_operation_cap(cap);

    self.validator_info.set_validator_metadata(metadata);
}

/// Sets the next commission rate for the validator.
public(package) fun set_next_commission(
    validator: &mut Validator,
    commission_rate: u16,
    current_epoch: u64,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    assert!(commission_rate <= BASIS_POINT_DENOMINATOR, EIncorrectCommissionRate);
    validator.pending_commission_rate.insert_or_replace(current_epoch + 2, commission_rate as u64);
}

public(package) fun set_next_epoch_network_address(
    validator: &mut Validator,
    network_address: String,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    validator.validator_info.set_next_epoch_network_address(network_address);
}

public(package) fun set_next_epoch_p2p_address(
    validator: &mut Validator,
    p2p_address: String,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    validator.validator_info.set_next_epoch_p2p_address(p2p_address);
}

public(package) fun set_next_epoch_consensus_address(
    validator: &mut Validator,
    consensus_address: String,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    validator.validator_info.set_next_epoch_consensus_address(consensus_address);
}

public(package) fun set_next_epoch_protocol_pubkey_bytes(
    validator: &mut Validator,
    protocol_pubkey_bytes: vector<u8>,
    proof_of_possession: vector<u8>,
    cap: &ValidatorOperationCap,
    ctx: &TxContext,
) {
    validator.verify_operation_cap(cap);

    validator
        .validator_info
        .set_next_epoch_protocol_pubkey_bytes(protocol_pubkey_bytes, proof_of_possession, ctx);
}

public(package) fun set_next_epoch_network_pubkey_bytes(
    validator: &mut Validator,
    network_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    validator.validator_info.set_next_epoch_network_pubkey_bytes(network_pubkey_bytes);
}

public(package) fun set_next_epoch_consensus_pubkey_bytes(
    validator: &mut Validator,
    consensus_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    validator.verify_operation_cap(cap);

    validator.validator_info.set_next_epoch_consensus_pubkey_bytes(consensus_pubkey_bytes);
}

public(package) fun set_next_epoch_mpc_data_bytes(
    validator: &mut Validator,
    mpc_data_bytes: TableVec<vector<u8>>,
    cap: &ValidatorOperationCap,
): Option<TableVec<vector<u8>>> {
    validator.verify_operation_cap(cap);

    validator
        .validator_info
        .set_next_epoch_mpc_data_bytes(mpc_data_bytes)
}

/// Destroy the validator if it is empty.
public(package) fun destroy_empty(validator: Validator) {
    assert!(validator.is_empty(), EValidatorNotEmpty);

    let Validator {
        id,
        validator_info,
        exchange_rates,
        rewards_pool,
        commission,
        extra_fields,
        ..,
    } = validator;

    id.delete();
    validator_info.destroy();
    exchange_rates.drop();
    commission.destroy_zero();
    rewards_pool.destroy_zero();
    extra_fields.destroy_empty();
}

/// Returns the exchange rate for the given current or future epoch. If there
/// isn't a value for the specified epoch, it will look for the most recent
/// value down to the validator activation epoch.
/// Note that exchange rates are only set for epochs in which the node is in
/// the committee, and otherwise the rate remains static.
public(package) fun exchange_rate_at_epoch(validator: &Validator, epoch: u64): TokenExchangeRate {
    // If the validator is preactive then the exchange rate is always 1:1.
    if (validator.is_preactive_at_epoch(epoch)) {
        return token_exchange_rate::flat()
    };
    let clamped_epoch = validator.withdrawing_epoch().get_with_default(epoch);
    let mut epoch = clamped_epoch.min(epoch);
    let activation_epoch = *validator.activation_epoch.borrow();

    while (epoch >= activation_epoch) {
        if (validator.exchange_rates.contains(epoch)) {
            return validator.exchange_rates[epoch]
        };
        epoch = epoch - 1;
    };

    token_exchange_rate::flat()
}

/// Returns the expected active stake for current or future epoch `E` for the validator.
/// It processes the pending stake and withdrawal requests from the current epoch
/// to `E`.
///
/// Should be the main function to calculate the active stake for the validator at
/// the given epoch, due to the complexity of the pending stake and withdrawal
/// requests, and lack of immediate updates.
public(package) fun ika_balance_at_epoch(validator: &Validator, epoch: u64): u64 {
    let exchange_rate = token_exchange_rate::new(validator.ika_balance, validator.num_shares);

    let mut pre_active_shares_withdraw = 0;
    let pre_active_withdrawals = validator.pre_active_withdrawals.unwrap();
    pre_active_withdrawals.keys().do_ref!(|old_epoch| if (*old_epoch <= epoch) {
        let ika_value = pre_active_withdrawals.get(old_epoch);
        // recall that pre_active_withdrawals contains stakes that were
        // active for exactly 1 epoch. since the node might have been
        // inactive, this list may contain more than one value
        // (although exchange_rate_at_epoch will return the same value).
        let activation_epoch = *old_epoch - 1;
        let shares_for_epoch = validator
            .exchange_rate_at_epoch(activation_epoch)
            .convert_to_share_amount(*ika_value);

        pre_active_shares_withdraw = pre_active_shares_withdraw + shares_for_epoch;
    });
    let shares_withdraw = validator.pending_shares_withdraw.value_at(epoch);
    let pending_withdrawal = exchange_rate.convert_to_ika_amount(
        shares_withdraw + pre_active_shares_withdraw,
    );

    validator.ika_balance + validator.pending_stake.value_at(epoch) - pending_withdrawal
}

// === Cap Management ===

/// Create a new `ValidatorOperationCap`, and registers it,
/// thus revoking the previous cap's permission.
public(package) fun rotate_operation_cap(
    self: &mut Validator,
    cap: &ValidatorCap,
    system_object_cap: &SystemObjectCap,
    ctx: &mut TxContext,
): ValidatorOperationCap {
    let validator_id = cap.validator_id();
    self.verify_validator_cap(cap);
    let operation_cap = validator_cap::new_validator_operation_cap(
        validator_id,
        ctx,
        system_object_cap,
    );
    self.operation_cap_id = object::id(&operation_cap);
    operation_cap
}

/// Create a new `ValidatorCommissionCap`, and registers it,
/// thus revoking the previous cap's permission.
public(package) fun rotate_commission_cap(
    self: &mut Validator,
    cap: &ValidatorCap,
    system_object_cap: &SystemObjectCap,
    ctx: &mut TxContext,
): ValidatorCommissionCap {
    let validator_id = cap.validator_id();
    self.verify_validator_cap(cap);
    let commission_cap = validator_cap::new_validator_commission_cap(
        validator_id,
        ctx,
        system_object_cap,
    );
    self.commission_cap_id = object::id(&commission_cap);
    commission_cap
}

/// Withdraws the commission from the validator. Amount is optional, if not provided,
/// the full commission is withdrawn.
public(package) fun collect_commission(
    validator: &mut Validator,
    cap: &ValidatorCommissionCap,
    amount: Option<u64>,
): Balance<IKA> {
    validator.verify_commission_cap(cap);
    if (amount.is_some()) {
        validator.commission.split(*amount.borrow())
    } else {
        validator.commission.withdraw_all()
    }
}

// === Accessors ===

/// Returns the validator id for the validator.
public(package) fun validator_id(validator: &Validator): ID { validator.id.to_inner() }

/// Returns the validator cap for the validator.
public(package) fun validator_cap_id(validator: &Validator): ID { validator.validator_cap_id }

/// Returns the operation cap id for the validator.
public(package) fun operation_cap_id(validator: &Validator): ID { validator.operation_cap_id }

/// Returns the commission cap id for the validator.
public(package) fun commission_cap_id(validator: &Validator): ID { validator.commission_cap_id }

/// Returns the commission rate for the validator.
public(package) fun commission_rate(validator: &Validator): u16 { validator.commission_rate }

/// Returns the commission amount for the validator.
public(package) fun commission_amount(validator: &Validator): u64 { validator.commission.value() }

/// Returns the rewards amount for the validator.
public(package) fun rewards_amount(validator: &Validator): u64 { validator.rewards_pool.value() }

/// Returns the rewards for the validator.
public(package) fun ika_balance(validator: &Validator): u64 { validator.ika_balance }

/// Returns the activation epoch for the validator.
public(package) fun activation_epoch(validator: &Validator): Option<u64> {
    validator.activation_epoch
}

/// Returns the validator info for the validator.
public(package) fun validator_info(validator: &Validator): &ValidatorInfo {
    &validator.validator_info
}

/// Returns `true` if the validator is preactive.
public(package) fun is_preactive(validator: &Validator): bool {
    validator.state == ValidatorState::PreActive
}

/// Returns `true` if the validator is active.
public(package) fun is_active(validator: &Validator): bool {
    validator.state == ValidatorState::Active
}

/// Returns `true` if the validator is withdrawing.
public(package) fun is_withdrawing(validator: &Validator): bool {
    match (validator.state) {
        ValidatorState::Withdrawing(_) => true,
        _ => false,
    }
}

/// Returns the epoch in which the validator is withdrawing.
public(package) fun withdrawing_epoch(validator: &Validator): Option<u64> {
    match (validator.state) {
        ValidatorState::Withdrawing(epoch) => option::some(epoch),
        _ => option::none(),
    }
}

public(package) fun exchange_rates(validator: &Validator): &Table<u64, TokenExchangeRate> {
    &validator.exchange_rates
}

/// Returns `true` if the validator is empty.
public(package) fun is_empty(validator: &Validator): bool {
    let pending_stake = validator.pending_stake.unwrap();
    let non_empty = pending_stake.keys().count!(|epoch| pending_stake[epoch] != 0);

    validator.rewards_pool.value() == 0 &&
    validator.num_shares == 0 &&
    validator.commission.value() == 0 &&
    validator.ika_balance == 0 &&
    non_empty == 0
}

/// Calculate the rewards for an amount with value `staked_principal`, staked in the validator between
/// `activation_epoch` and `withdraw_epoch`.
public(package) fun calculate_rewards(
    validator: &Validator,
    staked_principal: u64,
    activation_epoch: u64,
    withdraw_epoch: u64,
): u64 {
    let shares = validator
        .exchange_rate_at_epoch(activation_epoch)
        .convert_to_share_amount(staked_principal);
    let ika_amount = validator.exchange_rate_at_epoch(withdraw_epoch).convert_to_ika_amount(shares);
    if (ika_amount >= staked_principal) {
        ika_amount - staked_principal
    } else 0
}

// === Private Functions ===

/// Returns true if the provided validator is preactive at the provided epoch.
fun is_preactive_at_epoch(validator: &Validator, epoch: u64): bool {
    // Either the validator is currently preactive or the validator's starting epoch is later than the provided epoch.
    validator.is_preactive() || (*validator.activation_epoch.borrow() > epoch)
}

// === Test Functions ===

#[test_only]
public(package) fun num_shares(validator: &Validator): u64 { validator.num_shares }

#[test_only]
public(package) fun latest_epoch(validator: &Validator): u64 { validator.latest_epoch }
