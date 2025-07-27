// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::system_inner;

use ika::ika::IKA;
use ika_common::advance_epoch_approver::{Self, AdvanceEpochApprover};
use ika_common::bls_committee::BlsCommittee;
use ika_common::protocol_cap::{Self, ProtocolCap, VerifiedProtocolCap};
use ika_common::system_current_status_info::{Self, SystemCurrentStatusInfo};
use ika_common::system_object_cap::SystemObjectCap;
use ika_common::upgrade_package_approver::{Self, UpgradePackageApprover};
use ika_common::validator_cap::{
    ValidatorCap,
    ValidatorOperationCap,
    ValidatorCommissionCap,
    VerifiedValidatorCap,
    VerifiedValidatorOperationCap,
    VerifiedValidatorCommissionCap
};
use ika_system::protocol_treasury::ProtocolTreasury;
use ika_system::staked_ika::StakedIka;
use ika_system::token_exchange_rate::TokenExchangeRate;
use ika_system::validator_metadata::ValidatorMetadata;
use ika_system::validator_set::ValidatorSet;
use std::string::String;
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::bcs;
use sui::clock::Clock;
use sui::coin::Coin;
use sui::event;
use sui::package::{UpgradeCap, UpgradeTicket, UpgradeReceipt};
use sui::table::Table;
use sui::table_vec::TableVec;
use sui::vec_map::{Self, VecMap};
use sui::vec_set::VecSet;

// === Constants ===

const PARAMS_MESSAGE_INTENT: vector<u8> = vector[2, 0, 0];

// System checkpoint message data type constants corresponding to system parameters
// Note: the order of these fields, and the number must correspond to the Rust code in
// `crates/ika-types/src/messages_system_checkpoints.rs`.
const SET_NEXT_PROTOCOL_VERSION_MESSAGE_TYPE: u32 = 0;
const SET_EPOCH_DURATION_MS_MESSAGE_TYPE: u32 = 1;
const SET_STAKE_SUBSIDY_START_EPOCH_MESSAGE_TYPE: u32 = 2;
const SET_STAKE_SUBSIDY_RATE_MESSAGE_TYPE: u32 = 3;
const SET_STAKE_SUBSIDY_PERIOD_LENGTH_MESSAGE_TYPE: u32 = 4;
const SET_MIN_VALIDATOR_COUNT_MESSAGE_TYPE: u32 = 5;
const SET_MAX_VALIDATOR_COUNT_MESSAGE_TYPE: u32 = 6;
const SET_MIN_VALIDATOR_JOINING_STAKE_MESSAGE_TYPE: u32 = 7;
const SET_MAX_VALIDATOR_CHANGE_COUNT_MESSAGE_TYPE: u32 = 8;
const SET_REWARD_SLASHING_RATE_MESSAGE_TYPE: u32 = 9;
const END_OF_PUBLISH_MESSAGE_TYPE: u32 = 10;
const SET_APPROVED_UPGRADE_MESSAGE_TYPE: u32 = 11;
const SetOrRemoveWitnessApprovingAdvanceEpochMessageType: u32 = 12;

// === Errors ===

/// The system has not reached the end epoch time.
const EHaveNotReachedEndEpochTime: u64 = 0;
/// The active BLS committee must be initialized.
const EActiveBlsCommitteeMustInitialize: u64 = 1;
/// The epoch in the system checkpoint is incorrect.
const EIncorrectEpochInSystemCheckpoint: u64 = 2;
/// The sequence number in the system checkpoint is incorrect.
const EWrongSystemCheckpointSequenceNumber: u64 = 3;
/// The approved upgrade is not found.
const EApprovedUpgradeNotFound: u64 = 4;
/// The protocol cap is unauthorized.
const EUnauthorizedProtocolCap: u64 = 5;
/// Too early for initialization time or already initialized.
const ECannotInitialize: u64 = 6;
/// The system has not reached the mid epoch time.
const EHaveNotReachedMidEpochTime: u64 = 7;

// === Structs ===

/// Uses SystemParametersV1 as the parameters.
public struct SystemInner has store {
    /// The current epoch ID, starting from 0.
    epoch: u64,
    epoch_start_tx_digest: vector<u8>,
    /// The system object cap for common modules.
    system_object_cap: SystemObjectCap,
    /// The current protocol version, starting from 1.
    protocol_version: u64,
    next_protocol_version: Option<u64>,
    /// Upgrade caps for this package and others like ika coin of the ika protocol.
    upgrade_caps: vector<UpgradeCap>,
    /// Approved upgrade for package id to its approved digest.
    approved_upgrades: VecMap<ID, vector<u8>>,
    /// Contains all information about the validators.
    validator_set: ValidatorSet,
    /// The duration of an epoch, in milliseconds.
    epoch_duration_ms: u64,
    /// The starting epoch in which stake subsidies start being paid out
    stake_subsidy_start_epoch: u64,
    /// Schedule of stake subsidies given out each epoch.
    protocol_treasury: ProtocolTreasury,
    /// Unix timestamp of the current epoch start.
    epoch_start_timestamp_ms: u64,
    /// The last processed checkpoint sequence number.
    last_processed_checkpoint_sequence_number: u64,
    /// The last checkpoint sequence number of the previous epoch.
    previous_epoch_last_checkpoint_sequence_number: u64,
    /// The total messages processed.
    total_messages_processed: u64,
    /// The fees paid for computation.
    remaining_rewards: Balance<IKA>,
    /// List of authorized protocol cap ids.
    authorized_protocol_cap_ids: vector<ID>,
    /// List of witnesses approving advance epoch.
    /// as part of the epoch advancement, we have to collect approval from all witnesses.
    witnesses_approving_advance_epoch: vector<String>,
    /// Whether the system has received the end of publish message.
    received_end_of_publish: bool,
    /// Any extra fields that's not defined statically.
    extra_fields: Bag,
}

// === Events ===

/// Event containing system-level epoch information, emitted during
/// the epoch advancement message.
public struct SystemEpochInfoEvent has copy, drop {
    epoch: u64,
    protocol_version: u64,
    total_stake: u64,
    stake_subsidy_amount: u64,
    total_computation_fees: u64,
    total_stake_rewards_distributed: u64,
}

/// Event containing system-level checkpoint information, emitted during
/// the system checkpoint submission message.
public struct SystemCheckpointInfoEvent has copy, drop {
    epoch: u64,
    sequence_number: u64,
}

/// Event emitted when protocol version is set via checkpoint message.
public struct SetNextProtocolVersionEvent has copy, drop {
    epoch: u64,
    next_protocol_version: u64,
}

/// Event emitted when epoch duration is set via checkpoint message.
public struct SetEpochDurationMsEvent has copy, drop {
    epoch: u64,
    epoch_duration_ms: u64,
}

/// Event emitted when stake subsidy start epoch is set via checkpoint message.
public struct SetStakeSubsidyStartEpochEvent has copy, drop {
    epoch: u64,
    stake_subsidy_start_epoch: u64,
}

/// Event emitted when stake subsidy rate is set via checkpoint message.
public struct SetStakeSubsidyRateEvent has copy, drop {
    epoch: u64,
    stake_subsidy_rate: u16,
}

/// Event emitted when stake subsidy period length is set via checkpoint message.
public struct SetStakeSubsidyPeriodLengthEvent has copy, drop {
    epoch: u64,
    stake_subsidy_period_length: u64,
}

/// Event emitted when minimum validator count is set via checkpoint message.
public struct SetMinValidatorCountEvent has copy, drop {
    epoch: u64,
    min_validator_count: u64,
}

/// Event emitted when maximum validator count is set via checkpoint message.
public struct SetMaxValidatorCountEvent has copy, drop {
    epoch: u64,
    max_validator_count: u64,
}

/// Event emitted when minimum validator joining stake is set via checkpoint message.
public struct SetMinValidatorJoiningStakeEvent has copy, drop {
    epoch: u64,
    min_validator_joining_stake: u64,
}

/// Event emitted when maximum validator change count is set via checkpoint message.
public struct SetMaxValidatorChangeCountEvent has copy, drop {
    epoch: u64,
    max_validator_change_count: u64,
}

/// Event emitted when reward slashing rate is set via checkpoint message.
public struct SetRewardSlashingRateEvent has copy, drop {
    epoch: u64,
    reward_slashing_rate: u16,
}

/// Event emitted when approved upgrade is set via checkpoint message.
public struct SetApprovedUpgradeEvent has copy, drop {
    epoch: u64,
    package_id: ID,
    digest: Option<vector<u8>>,
}

/// Event emitted when the epoch ends.
public struct EndOfPublishEvent has copy, drop {
    epoch: u64,
}

/// Event emitted when witness approving advance epoch is set or removed via checkpoint message.
public struct SetOrRemoveWitnessApprovingAdvanceEpochEvent has copy, drop {
    epoch: u64,
    witness_type: String,
    remove: bool,
}

// ==== functions that can only be called by init ====

/// Create a new IkaSystemState object and make it shared.
/// This function will be called only once in init.
public(package) fun create(
    system_object_cap: SystemObjectCap,
    upgrade_caps: vector<UpgradeCap>,
    validator_set: ValidatorSet,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    stake_subsidy_start_epoch: u64,
    protocol_treasury: ProtocolTreasury,
    ctx: &mut TxContext,
): (SystemInner, ProtocolCap) {
    let protocol_cap = protocol_cap::create(ctx, &system_object_cap);
    let protocol_cap_id = object::id(&protocol_cap);

    let authorized_protocol_cap_ids = vector[protocol_cap_id];
    // This type is fixed as it's created at init. It should not be updated during type upgrade.
    let system_state = SystemInner {
        epoch: 0,
        epoch_start_tx_digest: *ctx.digest(),
        system_object_cap,
        protocol_version,
        next_protocol_version: option::none(),
        upgrade_caps,
        approved_upgrades: vec_map::empty(),
        validator_set,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        protocol_treasury,
        epoch_start_timestamp_ms,
        last_processed_checkpoint_sequence_number: 0,
        previous_epoch_last_checkpoint_sequence_number: 0,
        total_messages_processed: 0,
        remaining_rewards: balance::zero(),
        authorized_protocol_cap_ids,
        witnesses_approving_advance_epoch: vector[],
        // We advance epoch `0` immediately, and so the network doesn't participate in it and won't
        // send `END_OF_PUBLISH` - so we shouldn't expect one, and we set `received_end_of_publish`
        // to overcome the check in `advance_epoch()`.
        received_end_of_publish: true,
        extra_fields: bag::new(ctx),
    };
    (system_state, protocol_cap)
}

// === Package Functions ===

public(package) fun initialize(
    self: &mut SystemInner,
    max_validator_change_count: u64,
    cap: &ProtocolCap,
    clock: &Clock,
): AdvanceEpochApprover {
    self.verify_protocol_cap_impl(cap);
    let now = clock.timestamp_ms();
    assert!(self.epoch == 0 && now >= self.epoch_start_timestamp_ms, ECannotInitialize);
    assert!(self.active_committee().members().is_empty(), ECannotInitialize);
    let pending_active_set = self.validator_set.pending_active_set();
    assert!(
        pending_active_set.size() >= pending_active_set.min_validator_count(),
        ECannotInitialize,
    );
    self.validator_set.set_max_validator_change_count(max_validator_change_count);

    self.validator_set.initiate_mid_epoch_reconfiguration();

    // Create for the first time the advance epoch approver for epoch 0.
    // This is done to avoid the case where the epoch 0 is advanced before the
    // committee is initialized.
    advance_epoch_approver::create(
        self.epoch + 1,
        self.witnesses_approving_advance_epoch,
        balance::zero(),
        &self.system_object_cap,
    )
}

/// Can be called by anyone who wishes to become a validator candidate and starts accusing delegated
/// stakes in their staking pool. Once they have at least `MIN_VALIDATOR_JOINING_STAKE` amount of stake they
/// can call `request_add_validator` to officially become an active validator at the next epoch.
/// Aborts if the caller is already a pending or active validator, or a validator candidate.
/// Note: `proof_of_possession_bytes` MUST be a valid signature using proof_of_possession_sender and protocol_pubkey_bytes.
/// To produce a valid PoP, run [fn test_proof_of_possession_bytes].
public(package) fun request_add_validator_candidate(
    self: &mut SystemInner,
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
    ctx: &mut TxContext,
): (ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap) {
    self
        .validator_set
        .request_add_validator_candidate(
            self.epoch,
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
            &self.system_object_cap,
            ctx,
        )
}

/// Called by a validator candidate to remove themselves from the candidacy. After this call
/// their staking pool becomes deactivate.
public(package) fun request_remove_validator_candidate(self: &mut SystemInner, cap: &ValidatorCap) {
    self.validator_set.request_remove_validator_candidate(self.epoch, cap);
}

/// Called by a validator candidate to add themselves to the active validator set beginning next epoch.
/// Aborts if the validator is a duplicate with one of the pending or active validators, or if the amount of
/// stake the validator has doesn't meet the min threshold, or if the number of new validators for the next
/// epoch has already reached the maximum.
public(package) fun request_add_validator(self: &mut SystemInner, cap: &ValidatorCap) {
    self.validator_set.request_add_validator(self.epoch, cap);
}

/// A validator can call this function to request a removal in the next epoch.
/// We use the sender of `ctx` to look up the validator
/// (i.e. sender must match the sui_address in the validator).
/// At the end of the epoch, the `validator` object will be returned to the sui_address
/// of the validator.
public(package) fun request_remove_validator(self: &mut SystemInner, cap: &ValidatorCap) {
    self.validator_set.request_remove_validator(self.epoch, cap);
}

public(package) fun validator_metadata(self: &SystemInner, validator_id: ID): ValidatorMetadata {
    self.validator_set.validator_metadata(validator_id)
}

public(package) fun set_validator_metadata(
    self: &mut SystemInner,
    cap: &ValidatorOperationCap,
    metadata: ValidatorMetadata,
) {
    self.validator_set.set_validator_metadata(cap, metadata);
}

/// A validator can call this function to set a new commission rate, updated at the end of
/// the epoch.
public(package) fun set_next_commission(
    self: &mut SystemInner,
    new_commission_rate: u16,
    cap: &ValidatorOperationCap,
) {
    self
        .validator_set
        .set_next_commission(
            new_commission_rate,
            cap,
            self.epoch,
        );
}

/// Add stake to a validator's staking pool.
public(package) fun request_add_stake(
    self: &mut SystemInner,
    stake: Coin<IKA>,
    validator_id: ID,
    ctx: &mut TxContext,
): StakedIka {
    self
        .validator_set
        .request_add_stake(
            self.epoch,
            validator_id,
            stake.into_balance(),
            ctx,
        )
}

/// Withdraw some portion of a stake from a validator's staking pool.
public(package) fun request_withdraw_stake(self: &mut SystemInner, staked_ika: &mut StakedIka) {
    self.validator_set.request_withdraw_stake(staked_ika, self.epoch);
}

public(package) fun withdraw_stake(
    self: &mut SystemInner,
    staked_ika: StakedIka,
    ctx: &mut TxContext,
): Coin<IKA> {
    self.validator_set.withdraw_stake(staked_ika, self.epoch, ctx)
}

public(package) fun report_validator(
    self: &mut SystemInner,
    cap: &ValidatorOperationCap,
    reportee_id: ID,
) {
    self.validator_set.report_validator(cap, reportee_id);
}

public(package) fun undo_report_validator(
    self: &mut SystemInner,
    cap: &ValidatorOperationCap,
    reportee_id: ID,
) {
    self.validator_set.undo_report_validator(cap, reportee_id);
}

// ==== validator metadata management functions ====

/// Create a new `ValidatorOperationCap` and registers it.
/// The original object is thus revoked.
public(package) fun rotate_operation_cap(
    self: &mut SystemInner,
    cap: &ValidatorCap,
    ctx: &mut TxContext,
): ValidatorOperationCap {
    self.validator_set.rotate_operation_cap(cap, &self.system_object_cap, ctx)
}

public(package) fun rotate_commission_cap(
    self: &mut SystemInner,
    cap: &ValidatorCap,
    ctx: &mut TxContext,
): ValidatorCommissionCap {
    self.validator_set.rotate_commission_cap(cap, &self.system_object_cap, ctx)
}

public(package) fun collect_commission(
    self: &mut SystemInner,
    cap: &ValidatorCommissionCap,
    amount: Option<u64>,
    ctx: &mut TxContext,
): Coin<IKA> {
    self.validator_set.collect_commission(cap, amount).into_coin(ctx)
}

/// Sets a validator's name.
public(package) fun set_validator_name(
    self: &mut SystemInner,
    name: String,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_validator_name(name, cap);
}

/// Sets a validator's network address.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_network_address(
    self: &mut SystemInner,
    network_address: String,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_next_epoch_network_address(network_address, cap);
}

/// Sets a validator's p2p address.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_p2p_address(
    self: &mut SystemInner,
    p2p_address: String,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_next_epoch_p2p_address(p2p_address, cap);
}

/// Sets a validator's consensus address.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_consensus_address(
    self: &mut SystemInner,
    consensus_address: String,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_next_epoch_consensus_address(consensus_address, cap);
}

/// Sets a validator's public key of protocol key and proof of possession.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_protocol_pubkey_bytes(
    self: &mut SystemInner,
    protocol_pubkey_bytes: vector<u8>,
    proof_of_possession_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
    ctx: &TxContext,
) {
    self
        .validator_set
        .set_next_epoch_protocol_pubkey_bytes(
            protocol_pubkey_bytes,
            proof_of_possession_bytes,
            cap,
            ctx,
        );
}

/// Sets a validator's public key of network key.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_network_pubkey_bytes(
    self: &mut SystemInner,
    network_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_next_epoch_network_pubkey_bytes(network_pubkey_bytes, cap);
}

/// Sets a validator's public key of worker key.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_consensus_pubkey_bytes(
    self: &mut SystemInner,
    consensus_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    self.validator_set.set_next_epoch_consensus_pubkey_bytes(consensus_pubkey_bytes, cap);
}

/// Sets a validator's MPC public data.
/// The change will only take effects starting from the next epoch.
public(package) fun set_next_epoch_mpc_data_bytes(
    self: &mut SystemInner,
    mpc_data_bytes: TableVec<vector<u8>>,
    cap: &ValidatorOperationCap,
): Option<TableVec<vector<u8>>> {
    self
        .validator_set
        .set_next_epoch_mpc_data_bytes(
            mpc_data_bytes,
            cap,
        )
}

public(package) fun is_mid_epoch_time(self: &SystemInner, clock: &Clock): bool {
    let now = clock.timestamp_ms();
    let last_epoch_change = self.epoch_start_timestamp_ms;
    self.epoch > 0 && self.validator_set.next_epoch_active_committee().is_none() && now >= last_epoch_change + (self.epoch_duration_ms / 2)
}

public(package) fun is_end_epoch_time(self: &SystemInner, clock: &Clock): bool {
    let now = clock.timestamp_ms();
    let last_epoch_change = self.epoch_start_timestamp_ms;
    self.epoch > 0 && self.validator_set.next_epoch_active_committee().is_some() && now >= last_epoch_change + self.epoch_duration_ms
}

public(package) fun assert_mid_epoch_time(self: &SystemInner, clock: &Clock) {
    assert!(self.is_mid_epoch_time(clock), EHaveNotReachedMidEpochTime);
}

public(package) fun assert_end_epoch_time(self: &SystemInner, clock: &Clock) {
    assert!(self.is_end_epoch_time(clock), EHaveNotReachedEndEpochTime);
}

public(package) fun create_system_current_status_info(
    self: &SystemInner,
    clock: &Clock,
): SystemCurrentStatusInfo {
    system_current_status_info::create(
        self.epoch,
        self.is_mid_epoch_time(clock),
        self.is_end_epoch_time(clock),
        self.active_committee(),
        self.validator_set.next_epoch_active_committee(),
        &self.system_object_cap,
    )
}

public(package) fun initiate_advance_epoch(
    self: &SystemInner,
    clock: &Clock,
): AdvanceEpochApprover {
    self.assert_end_epoch_time(clock);

    advance_epoch_approver::create(
        self.epoch + 1,
        self.witnesses_approving_advance_epoch,
        balance::zero(),
        &self.system_object_cap,
    )
}

/// This function should be called at the end of an epoch, and advances the system to the next epoch.
/// It does the following things:
/// 1. Add storage charge to the storage fund.
/// 2. Burn the storage rebates from the storage fund. These are already refunded to transaction sender's
///    gas coins.
/// 3. Distribute computation charge to validator stake.
/// 4. Update all validators.
public(package) fun advance_epoch(
    self: &mut SystemInner,
    advance_epoch_approver: AdvanceEpochApprover,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    advance_epoch_approver.assert_all_witnesses_approved();

    assert!(self.received_end_of_publish, EHaveNotReachedEndEpochTime);
    self.received_end_of_publish = false;
    self.epoch_start_tx_digest = *ctx.digest();
    self.epoch_start_timestamp_ms = clock.timestamp_ms();

    self.previous_epoch_last_checkpoint_sequence_number =
        self.last_processed_checkpoint_sequence_number;

    let new_epoch = advance_epoch_approver.new_epoch();
    
    let fee_rewards = advance_epoch_approver.destroy(
        &self.system_object_cap,
    );

    let mut stake_subsidy = balance::zero();

    // during the transition from epoch N to epoch N + 1, self.epoch() will return N
    let current_epoch = self.epoch();
    // Include stake subsidy in the rewards given out to validators and stakers.
    // Delay distributing any stake subsidies until after `stake_subsidy_start_epoch`.
    if (current_epoch >= self.stake_subsidy_start_epoch) {
        stake_subsidy.join(self.protocol_treasury.stake_subsidy_for_distribution(ctx));
    };

    let stake_subsidy_amount = stake_subsidy.value();

    let total_computation_fees = fee_rewards.value();

    let mut total_rewards = sui::balance::zero<IKA>();
    total_rewards.join(fee_rewards);
    total_rewards.join(stake_subsidy);
    total_rewards.join(self.remaining_rewards.withdraw_all());

    let total_reward_amount_before_distribution = total_rewards.value();
    self.epoch = new_epoch;
    if (self.next_protocol_version.is_some()) {
        self.protocol_version = self.next_protocol_version.extract();
    };

    self
        .validator_set
        .advance_epoch(
            new_epoch,
            &mut total_rewards,
        );

    let new_total_stake = self.validator_set.total_stake();

    let total_reward_amount_after_distribution = total_rewards.value();
    let total_reward_distributed =
        total_reward_amount_before_distribution - total_reward_amount_after_distribution;

    // Because of precision issues with integer divisions, we expect that there will be some
    // remaining balance in `remaining_rewards`.
    self.remaining_rewards.join(total_rewards);

    event::emit(SystemEpochInfoEvent {
        epoch: self.epoch,
        protocol_version: self.protocol_version,
        total_stake: new_total_stake,
        stake_subsidy_amount,
        total_computation_fees,
        total_stake_rewards_distributed: total_reward_distributed,
    });
}

public(package) fun initiate_mid_epoch_reconfiguration(self: &mut SystemInner, clock: &Clock) {
    self.assert_mid_epoch_time(clock);

    self.validator_set.initiate_mid_epoch_reconfiguration();
}

/// Return the current epoch number. Useful for applications that need a coarse-grained concept of time,
/// since epochs are ever-increasing and epoch changes are intended to happen every 24 hours.
public(package) fun epoch(self: &SystemInner): u64 {
    self.epoch
}

public(package) fun protocol_version(self: &SystemInner): u64 {
    self.protocol_version
}

/// Returns unix timestamp of the start of current epoch
public(package) fun epoch_start_timestamp_ms(self: &SystemInner): u64 {
    self.epoch_start_timestamp_ms
}

/// Returns the total amount staked with `validator_id`.
/// Aborts if `validator_id` is not an active validator.
public(package) fun validator_stake_amount(self: &mut SystemInner, validator_id: ID): u64 {
    self.validator_set.validator_total_stake_amount(validator_id)
}

/// Returns all the validators who are currently reporting `validator_id`
public(package) fun get_reporters_of(self: &SystemInner, validator_id: ID): VecSet<ID> {
    self.validator_set.get_reporters_of(validator_id)
}

public(package) fun token_exchange_rates(
    self: &SystemInner,
    validator_id: ID,
): &Table<u64, TokenExchangeRate> {
    self.validator_set.token_exchange_rates(validator_id)
}

public(package) fun active_committee(self: &SystemInner): BlsCommittee {
    self.validator_set.active_committee()
}

public(package) fun next_epoch_active_committee(self: &SystemInner): Option<BlsCommittee> {
    self.validator_set.next_epoch_active_committee()
}

public(package) fun verify_validator_cap(
    self: &SystemInner,
    cap: &ValidatorCap,
): VerifiedValidatorCap {
    self.validator_set.verify_validator_cap(cap);
    cap.create_verified_validator_cap(&self.system_object_cap)
}

public(package) fun verify_operation_cap(
    self: &SystemInner,
    cap: &ValidatorOperationCap,
): VerifiedValidatorOperationCap {
    self.validator_set.verify_operation_cap(cap);
    cap.create_verified_validator_operation_cap(&self.system_object_cap)
}

public(package) fun verify_commission_cap(
    self: &SystemInner,
    cap: &ValidatorCommissionCap,
): VerifiedValidatorCommissionCap {
    self.validator_set.verify_commission_cap(cap);
    cap.create_verified_validator_commission_cap(&self.system_object_cap)
}

fun verify_protocol_cap_impl(self: &SystemInner, cap: &ProtocolCap) {
    let protocol_cap_id = object::id(cap);

    assert!(self.authorized_protocol_cap_ids.contains(&protocol_cap_id), EUnauthorizedProtocolCap);
}

public(package) fun add_upgrade_cap_by_cap(
    self: &mut SystemInner,
    upgrade_cap: UpgradeCap,
    cap: &ProtocolCap,
) {
    self.verify_protocol_cap_impl(cap);
    self.upgrade_caps.push_back(upgrade_cap);
}

public(package) fun authorize_upgrade(self: &mut SystemInner, package_id: ID): (UpgradeTicket, UpgradePackageApprover) {
    assert!(self.approved_upgrades.contains(&package_id), EApprovedUpgradeNotFound);
    let (_, digest) = self.approved_upgrades.remove(&package_id);
    let index = self.upgrade_caps.find_index!(|c| c.package() == package_id).extract();
    let policy = self.upgrade_caps[index].policy();
    let upgrade_ticket = self.upgrade_caps[index].authorize(policy, digest);
    let upgrade_package_approver =     upgrade_package_approver::create(
        object::id(&self.upgrade_caps[index]),
        self.witnesses_approving_advance_epoch,
        package_id,
        self.epoch + 1,
        &self.system_object_cap,
    );
    (upgrade_ticket, upgrade_package_approver)
}

public(package) fun commit_upgrade(
    self: &mut SystemInner,
    receipt: UpgradeReceipt,
    upgrade_package_approver: &mut UpgradePackageApprover,
) {
    upgrade_package_approver.commit(&receipt, &self.system_object_cap);
    let receipt_cap_id = receipt.cap();
    let index = self.upgrade_caps.find_index!(|c| object::id(c) == receipt_cap_id).extract();
    self.upgrade_caps[index].commit(receipt);
}

public(package) fun finalize_upgrade(
    self: &SystemInner,
    upgrade_package_approver: UpgradePackageApprover,
) {
    upgrade_package_approver.assert_all_witnesses_approved();
    upgrade_package_approver.destroy(&self.system_object_cap);
}

public(package) fun process_checkpoint_message_by_quorum(
    self: &mut SystemInner,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    message: vector<u8>,
    ctx: &mut TxContext,
) {
    let active_committee = self.validator_set.active_committee();
    assert!(!active_committee.members().is_empty(), EActiveBlsCommitteeMustInitialize);

    let mut intent_bytes = PARAMS_MESSAGE_INTENT;
    intent_bytes.append(message);
    intent_bytes.append(bcs::to_bytes(&self.epoch));

    active_committee.verify_certificate(self.epoch, &signature, &signers_bitmap, &intent_bytes);

    self.process_checkpoint_message(message, ctx);
}

public(package) fun process_checkpoint_message(
    self: &mut SystemInner,
    message: vector<u8>,
    _ctx: &mut TxContext,
) {
    let mut bcs_body = bcs::new(copy message);

    let epoch = bcs_body.peel_u64();
    assert!(epoch == self.epoch, EIncorrectEpochInSystemCheckpoint);

    let sequence_number = bcs_body.peel_u64();

    assert!(
        self.last_processed_checkpoint_sequence_number + 1 == sequence_number,
        EWrongSystemCheckpointSequenceNumber,
    );
    self.last_processed_checkpoint_sequence_number = sequence_number;

    event::emit(SystemCheckpointInfoEvent {
        epoch,
        sequence_number,
    });

    let len = bcs_body.peel_vec_length();
    let mut i = 0;
    // Note: the order of these fields, and the number must correspond to the Rust code in
    // `crates/ika-types/src/messages_system_checkpoints.rs`.
    while (i < len) {
        let message_data_enum_tag = bcs_body.peel_enum_tag();
        // Parses params message BCS bytes directly.
        match (message_data_enum_tag) {
            SET_NEXT_PROTOCOL_VERSION_MESSAGE_TYPE => {
                let next_protocol_version = bcs_body.peel_u64();
                self.next_protocol_version = option::some(next_protocol_version);
                event::emit(SetNextProtocolVersionEvent {
                    epoch: self.epoch,
                    next_protocol_version,
                });
            },
            SET_EPOCH_DURATION_MS_MESSAGE_TYPE => {
                let epoch_duration_ms = bcs_body.peel_u64();
                self.epoch_duration_ms = epoch_duration_ms;
                event::emit(SetEpochDurationMsEvent {
                    epoch: self.epoch,
                    epoch_duration_ms,
                });
            },
            SET_STAKE_SUBSIDY_START_EPOCH_MESSAGE_TYPE => {
                let stake_subsidy_start_epoch = bcs_body.peel_u64();
                self.stake_subsidy_start_epoch = stake_subsidy_start_epoch;
                event::emit(SetStakeSubsidyStartEpochEvent {
                    epoch: self.epoch,
                    stake_subsidy_start_epoch,
                });
            },
            SET_STAKE_SUBSIDY_RATE_MESSAGE_TYPE => {
                let stake_subsidy_rate = bcs_body.peel_u16();
                self.protocol_treasury.set_stake_subsidy_rate(stake_subsidy_rate);
                event::emit(SetStakeSubsidyRateEvent {
                    epoch: self.epoch,
                    stake_subsidy_rate,
                });
            },
            SET_STAKE_SUBSIDY_PERIOD_LENGTH_MESSAGE_TYPE => {
                let stake_subsidy_period_length = bcs_body.peel_u64();
                self.protocol_treasury.set_stake_subsidy_period_length(stake_subsidy_period_length);
                event::emit(SetStakeSubsidyPeriodLengthEvent {
                    epoch: self.epoch,
                    stake_subsidy_period_length,
                });
            },
            SET_MIN_VALIDATOR_COUNT_MESSAGE_TYPE => {
                let min_validator_count = bcs_body.peel_u64();
                self.validator_set.set_min_validator_count(min_validator_count);
                event::emit(SetMinValidatorCountEvent {
                    epoch: self.epoch,
                    min_validator_count,
                });
            },
            SET_MAX_VALIDATOR_COUNT_MESSAGE_TYPE => {
                let max_validator_count = bcs_body.peel_u64();
                self.validator_set.set_max_validator_count(max_validator_count);
                event::emit(SetMaxValidatorCountEvent {
                    epoch: self.epoch,
                    max_validator_count,
                });
            },
            SET_MIN_VALIDATOR_JOINING_STAKE_MESSAGE_TYPE => {
                let min_validator_joining_stake = bcs_body.peel_u64();
                self.validator_set.set_min_validator_joining_stake(min_validator_joining_stake);
                event::emit(SetMinValidatorJoiningStakeEvent {
                    epoch: self.epoch,
                    min_validator_joining_stake,
                });
            },
            SET_MAX_VALIDATOR_CHANGE_COUNT_MESSAGE_TYPE => {
                let max_validator_change_count = bcs_body.peel_u64();
                self.validator_set.set_max_validator_change_count(max_validator_change_count);
                event::emit(SetMaxValidatorChangeCountEvent {
                    epoch: self.epoch,
                    max_validator_change_count,
                });
            },
            SET_REWARD_SLASHING_RATE_MESSAGE_TYPE => {
                let reward_slashing_rate = bcs_body.peel_u16();
                self.validator_set.set_reward_slashing_rate(reward_slashing_rate);
                event::emit(SetRewardSlashingRateEvent {
                    epoch: self.epoch,
                    reward_slashing_rate,
                });
            },
            SET_APPROVED_UPGRADE_MESSAGE_TYPE => {
                let package_id = object::id_from_bytes(bcs_body.peel_vec_u8());
                let digest = bcs_body.peel_option!(|bcs| bcs.peel_vec_u8());
                self.set_approved_upgrade(package_id, digest);
            },
            END_OF_PUBLISH_MESSAGE_TYPE => {
                self.received_end_of_publish = true;
                event::emit(EndOfPublishEvent {
                    epoch: self.epoch,
                });
            },
            SetOrRemoveWitnessApprovingAdvanceEpochMessageType => {
                let witness_type = bcs_body.peel_vec_u8().to_string();
                let remove = bcs_body.peel_bool();
                self.set_or_remove_witness_approving_advance_epoch(witness_type, remove);
            },
            _ => {},
        };
        i = i + 1;
    };
    self.total_messages_processed = self.total_messages_processed + i;
}

/// === Protocol Cap Functions ===

public(package) fun verify_protocol_cap(
    self: &SystemInner,
    cap: &ProtocolCap,
): VerifiedProtocolCap {
    self.verify_protocol_cap_impl(cap);
    protocol_cap::create_verified(&self.system_object_cap)
}

public(package) fun set_approved_upgrade_by_cap(
    self: &mut SystemInner,
    package_id: ID,
    digest: Option<vector<u8>>,
    cap: &ProtocolCap,
) {
    self.verify_protocol_cap_impl(cap);
    self.set_approved_upgrade(package_id, digest);
}

public(package) fun set_or_remove_witness_approving_advance_epoch_by_cap(
    self: &mut SystemInner,
    witness_type: String,
    remove: bool,
    cap: &ProtocolCap,
) {
    self.verify_protocol_cap_impl(cap);
    self.set_or_remove_witness_approving_advance_epoch(witness_type, remove);
}

public(package) fun process_checkpoint_message_by_cap(
    self: &mut SystemInner,
    message: vector<u8>,
    cap: &ProtocolCap,
    ctx: &mut TxContext,
) {
    self.verify_protocol_cap_impl(cap);
    self.process_checkpoint_message(message, ctx);
}

/// === Private Functions ===

/// Set approved upgrade for a package id.
/// If `digest` is `some`, it will be inserted into the `approved_upgrades` map.
/// If `digest` is `none`, it will be removed from the `approved_upgrades` map.
fun set_approved_upgrade(self: &mut SystemInner, package_id: ID, digest: Option<vector<u8>>) {
    if (digest.is_some()) {
        if (self.approved_upgrades.contains(&package_id)) {
            *self.approved_upgrades.get_mut(&package_id) = *digest.borrow();
        } else {
            self.approved_upgrades.insert(package_id, *digest.borrow());
        }
    } else {
        if (self.approved_upgrades.contains(&package_id)) {
            self.approved_upgrades.remove(&package_id);
        }
    };
    event::emit(SetApprovedUpgradeEvent {
        epoch: self.epoch,
        package_id,
        digest,
    });
}

/// Set or remove a witness approving advance epoch.
/// If `remove` is `true`, the witness will be removed from the list of witnesses approving advance epoch.
/// If `remove` is `false`, the witness will be added to the list of witnesses approving advance epoch.
fun set_or_remove_witness_approving_advance_epoch(
    self: &mut SystemInner,
    witness_type: String,
    remove: bool,
) {
    let (found, index) = self.witnesses_approving_advance_epoch.index_of(&witness_type);
    if (remove && found) {
        self.witnesses_approving_advance_epoch.remove(index);
    } else if (!found) {
        self.witnesses_approving_advance_epoch.push_back(witness_type);
    };
    event::emit(SetOrRemoveWitnessApprovingAdvanceEpochEvent {
        epoch: self.epoch,
        witness_type,
        remove,
    });
}

// === Utility functions ===

/// Calculate the rewards for an amount with value `staked_principal`, staked in the validator with
/// the given `validator_id` between `activation_epoch` and `withdraw_epoch`.
public(package) fun calculate_rewards(
    self: &SystemInner,
    node_id: ID,
    staked_principal: u64,
    activation_epoch: u64,
    withdraw_epoch: u64,
): u64 {
    self
        .validator_set
        .calculate_rewards(node_id, staked_principal, activation_epoch, withdraw_epoch)
}

/// Check whether StakedIka can be withdrawn directly.
public(package) fun can_withdraw_staked_ika_early(
    self: &SystemInner,
    staked_ika: &StakedIka,
): bool {
    self.validator_set.can_withdraw_staked_ika_early(staked_ika, self.epoch)
}

/// Returns the duration of an epoch in milliseconds.
public(package) fun epoch_duration_ms(self: &SystemInner): u64 {
    self.epoch_duration_ms
}

// === Test Functions ===

#[test_only]
/// Return the current validator set
public(package) fun validator_set(self: &SystemInner): &ValidatorSet {
    &self.validator_set
}

#[test_only]
public(package) fun get_stake_subsidy_stake_subsidy_distribution_counter(self: &SystemInner): u64 {
    self.protocol_treasury.get_stake_subsidy_distribution_counter()
}

#[test_only]
public(package) fun set_epoch_for_testing(self: &mut SystemInner, epoch_num: u64) {
    self.epoch = epoch_num
}

#[test_only]
public(package) fun request_add_validator_for_testing(self: &mut SystemInner, cap: &ValidatorCap) {
    self.validator_set.request_add_validator(self.epoch, cap);
}

#[test_only]
public(package) fun set_stake_subsidy_stake_subsidy_distribution_counter(
    self: &mut SystemInner,
    counter: u64,
) {
    self.protocol_treasury.set_stake_subsidy_distribution_counter(counter)
}
