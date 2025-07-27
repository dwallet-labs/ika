// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// # Ika System Module
///
/// The `ika_system::system` module provides the core system state management for the Ika network.
/// It acts as the central coordinator for validators, staking, epochs, and network governance.
///
/// ## Overview
///
/// The module implements a versioned wrapper pattern around the core system state:
/// - `System`: A shared object that serves as the public interface and version manager
/// - `SystemInner`: The actual system state implementation containing all business logic
/// - `ProtocolCap`: Capability object for privileged system operations
///
/// ## Architecture
///
/// The system uses a two-layer architecture:
///
/// ### System Wrapper Layer
/// The `System` struct is a thin wrapper that:
/// - Maintains version information for upgrades
/// - Stores the package ID for authorization
/// - Holds the inner system state as a dynamic field
/// - Provides a stable public interface across versions
///
/// ### SystemInner Layer
/// The `SystemInner` struct contains all the core functionality:
/// - Validator set management and operations
/// - Epoch progression and timing
/// - Staking and delegation logic
/// - Protocol treasury and rewards distribution
/// - dWallet network coordination
/// - System parameter management
///
/// ## Key Responsibilities
///
/// ### Validator Management
/// - Adding/removing validator candidates
/// - Managing validator metadata and configuration
/// - Handling validator state transitions (PreActive → Active → Withdrawing)
/// - Processing validator reports and governance actions
///
/// ### Staking Operations
/// - Processing stake additions and withdrawals
/// - Managing staked IKA tokens and rewards
/// - Calculating token exchange rates across epochs
/// - Handling delegation to validators
///
/// ### Epoch Management
/// - Coordinating epoch transitions
/// - Processing mid-epoch reconfigurations
/// - Managing epoch timing and duration
/// - Distributing stake subsidies and rewards
///
/// ### dWallet Integration
/// - Coordinating with dWallet 2PC MPC system
/// - Managing encryption keys and DKG processes
/// - Handling pricing and curve configurations
/// - Processing dWallet network operations
///
/// ### System Governance
/// - Managing protocol upgrades via UpgradeCap
/// - Processing system parameter changes
/// - Handling protocol version transitions
/// - Coordinating checkpoint message processing
///
/// ## State Management
///
/// The system maintains state across multiple components:
/// - **ValidatorSet**: Current and pending validator configurations
/// - **ProtocolTreasury**: Rewards, subsidies, and fee management
/// - **BLS Committee**: Cryptographic committee for consensus
/// - **Token Exchange Rates**: Historical staking reward calculations
/// - **Pending Values**: Future epoch configuration changes
///
/// ## Ika System Upgrade Guide
/// `System` is a versioned wrapper around `SystemInner` that provides upgrade capabilities.
/// The `SystemInner` object is stored as a dynamic field with the version as the key.
/// There are multiple approaches to upgrade the system state:
///
/// The simplest approach is to add dynamic fields to the `extra_fields` field of `SystemInner`
/// or any of its subtypes. This is useful for rapid changes, small modifications, or experimental features.
///
/// To perform a proper type upgrade of `SystemInner`, follow these steps:
/// 1. Define a new `SystemInnerV2` type in system_inner.move.
/// 2. Create a data migration function that transforms `SystemInner` to `SystemInnerV2`.
/// 3. Update the `VERSION` constant to 2 and replace all references to `SystemInner` with `SystemInnerV2`
///    in both system.move and system_inner.move.
/// 4. Modify the `migrate` function to handle the version upgrade by:
///    - Removing the old inner object from the dynamic field
///    - Applying the data migration transformation
///    - Adding the new inner object with the updated version
/// 5. Update the `inner()` and `inner_mut()` functions to work with the new version.
///
/// Along with the Move changes, update the Rust code:
/// 1. Define a new `SystemInnerV2` struct that matches the Move type.
/// 2. Update the `System` enum to include the new version variant.
/// 3. Update relevant system state getter functions to handle the new version.
///
/// To upgrade Validator types:
/// 1. Define a new Validator version (e.g. ValidatorV2) in validator.move.
/// 2. Create migration functions to convert between validator versions.
/// 3. Update validator creation and access functions to use the new version.
/// 4. Update the validator set and related components to handle the new validator type.
///
/// In Rust, add new cases to handle the upgraded validator types in the appropriate getter functions.
/// Validator upgrades can be done independently of SystemInner upgrades, but ensure version consistency
/// across related components.
module ika_system::system;

use ika::ika::IKA;
use ika_common::advance_epoch_approver::AdvanceEpochApprover;
use ika_common::bls_committee::BlsCommittee;
use ika_common::protocol_cap::{VerifiedProtocolCap, ProtocolCap};
use ika_common::system_current_status_info::SystemCurrentStatusInfo;
use ika_common::system_object_cap::SystemObjectCap;
use ika_common::validator_cap::{
    ValidatorCap,
    ValidatorCommissionCap,
    ValidatorOperationCap,
    VerifiedValidatorCap,
    VerifiedValidatorCommissionCap,
    VerifiedValidatorOperationCap
};
use ika_system::protocol_treasury::ProtocolTreasury;
use ika_system::staked_ika::StakedIka;
use ika_system::system_inner::{Self, SystemInner};
use ika_system::token_exchange_rate::TokenExchangeRate;
use ika_system::validator_metadata::ValidatorMetadata;
use ika_system::validator_set::ValidatorSet;
use std::string::String;
use sui::clock::Clock;
use sui::coin::Coin;
use sui::dynamic_field;
use sui::package::{UpgradeCap, UpgradeReceipt, UpgradeTicket};
use sui::table::Table;
use sui::table_vec::TableVec;
use ika_common::upgrade_package_approver::UpgradePackageApprover;

// === Errors ===

/// Attempted to access system inner with wrong version.
const EWrongInnerVersion: u64 = 0;

/// Invalid migration - either version not incremented or new_package_id not set.
const EInvalidMigration: u64 = 1;

// === Constants ===

/// Current version of the system state structure.
/// This version corresponds to SystemInner and should be incremented
/// when the inner system state structure changes requiring migration.
///
/// Version History:
/// - V1: Initial SystemInner implementation with core functionality
const VERSION: u64 = 1;

// === Structs ===

/// The main system state object that coordinates the entire Ika network.
///
/// This is a shared object that acts as the central point for all system operations.
/// It maintains versioning information and delegates actual functionality to the
/// inner system state stored as a dynamic field.
///
/// # Fields
/// - `id`: Unique identifier for this system object
/// - `version`: Current version of the inner system state structure
/// - `package_id`: ID of the current system package for upgrade authorization
/// - `new_package_id`: ID of the new package during upgrades (if any)
///
/// # Design Notes
/// The system uses dynamic fields to store the actual state, allowing for
/// type-safe upgrades while maintaining a stable object ID. The version field
/// ensures that operations are performed against the correct inner state type.
///
/// # Access Pattern
/// All public functions delegate to `inner()` or `inner_mut()` which retrieve
/// the correctly versioned SystemInner from the dynamic field storage.
public struct System has key {
    id: UID,
    version: u64,
    package_id: ID,
    new_package_id: Option<ID>,
    migration_epoch: Option<u64>,
}

// === Functions that can only be called by init ===

/// Create a new System object and make it shared.
/// This function will be called only once in init.
///
/// Creates the initial system state with the provided validators and parameters,
/// then wraps it in a versioned System object and makes it shared for network access.
public(package) fun create(
    package_id: ID,
    system_object_cap: SystemObjectCap,
    upgrade_caps: vector<UpgradeCap>,
    validators: ValidatorSet,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    stake_subsidy_start_epoch: u64,
    protocol_treasury: ProtocolTreasury,
    ctx: &mut TxContext,
): ProtocolCap {
    let (system_state, protocol_cap) = system_inner::create(
        system_object_cap,
        upgrade_caps,
        validators,
        protocol_version,
        epoch_start_timestamp_ms,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        protocol_treasury,
        ctx,
    );
    let mut self = System {
        id: object::new(ctx),
        version: VERSION,
        package_id,
        new_package_id: option::none(),
        migration_epoch: option::none(),
    };
    dynamic_field::add(&mut self.id, VERSION, system_state);
    transfer::share_object(self);
    protocol_cap
}

// === Package Functions ===

public fun initialize(
    self: &mut System,
    max_validator_change_count: u64,
    cap: &ProtocolCap,
    clock: &Clock,
): AdvanceEpochApprover {
    self
        .inner_mut()
        .initialize(
            max_validator_change_count,
            cap,
            clock,
        )
}

/// Can be called by anyone who wishes to become a validator candidate and starts accruing delegated
/// stakes in their staking pool. Once they have at least `MIN_VALIDATOR_JOINING_STAKE` amount of stake they
/// can call `request_add_validator` to officially become an active validator at the next epoch.
/// Aborts if the caller is already a pending or active validator, or a validator candidate.
/// Note: `proof_of_possession_bytes` MUST be a valid signature using sui_address and protocol_pubkey_bytes.
/// To produce a valid PoP, run [fn test_proof_of_possession_bytes].
public fun request_add_validator_candidate(
    self: &mut System,
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
        .inner_mut()
        .request_add_validator_candidate(
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
            ctx,
        )
}

/// Called by a validator candidate to remove themselves from the candidacy. After this call
/// their staking pool becomes deactivate.
public fun request_remove_validator_candidate(self: &mut System, cap: &ValidatorCap) {
    self.inner_mut().request_remove_validator_candidate(cap)
}

/// Called by a validator candidate to add themselves to the active validator set beginning next epoch.
/// Aborts if the validator is a duplicate with one of the pending or active validators, or if the amount of
/// stake the validator has doesn't meet the min threshold, or if the number of new validators for the next
/// epoch has already reached the maximum.
public fun request_add_validator(self: &mut System, cap: &ValidatorCap) {
    self.inner_mut().request_add_validator(cap)
}

/// A validator can call this function to request a removal in the next epoch.
/// We use the sender of `ctx` to look up the validator
/// (i.e. sender must match the sui_address in the validator).
/// At the end of the epoch, the `validator` object will be returned to the sui_address
/// of the validator.
public fun request_remove_validator(self: &mut System, cap: &ValidatorCap) {
    self.inner_mut().request_remove_validator(cap)
}

/// A validator can call this function to set a new commission rate, updated at the end of
/// the epoch.
public fun set_next_commission(
    self: &mut System,
    new_commission_rate: u16,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_commission(new_commission_rate, cap)
}

/// Add stake to a validator's staking pool.
public fun request_add_stake(
    self: &mut System,
    stake: Coin<IKA>,
    validator_id: ID,
    ctx: &mut TxContext,
): StakedIka {
    self.inner_mut().request_add_stake(stake, validator_id, ctx)
}

/// Marks the amount as a withdrawal to be processed and removes it from the stake weight of the
/// node. Allows the user to call withdraw_stake after the epoch change to the next epoch and
/// shard transfer is done.
public fun request_withdraw_stake(self: &mut System, staked_ika: &mut StakedIka) {
    self.inner_mut().request_withdraw_stake(staked_ika);
}

/// Withdraws the staked amount from the staking pool.
public fun withdraw_stake(
    self: &mut System,
    staked_ika: StakedIka,
    ctx: &mut TxContext,
): Coin<IKA> {
    self.inner_mut().withdraw_stake(staked_ika, ctx)
}

/// Report a validator as a bad or non-performant actor in the system.
/// Succeeds if all the following are satisfied:
/// 1. both the reporter in `cap` and the input `reportee_id` are active validators.
/// 2. reporter and reportee not the same address.
/// 3. the cap object is still valid.
/// This function is idempotent.
public fun report_validator(self: &mut System, cap: &ValidatorOperationCap, reportee_id: ID) {
    self.inner_mut().report_validator(cap, reportee_id)
}

/// Undo a `report_validator` action. Aborts if
/// 1. the reportee is not a currently active validator or
/// 2. the sender has not previously reported the `reportee_id`, or
/// 3. the cap is not valid
public fun undo_report_validator(self: &mut System, cap: &ValidatorOperationCap, reportee_id: ID) {
    self.inner_mut().undo_report_validator(cap, reportee_id)
}

// === validator metadata management functions ===

/// Create a new `ValidatorOperationCap` and registers it. The original object is thus revoked.
public fun rotate_operation_cap(
    self: &mut System,
    cap: &ValidatorCap,
    ctx: &mut TxContext,
): ValidatorOperationCap {
    self.inner_mut().rotate_operation_cap(cap, ctx)
}

/// Create a new `ValidatorCommissionCap` and registers it. The original object is thus revoked.
public fun rotate_commission_cap(
    self: &mut System,
    cap: &ValidatorCap,
    ctx: &mut TxContext,
): ValidatorCommissionCap {
    self.inner_mut().rotate_commission_cap(cap, ctx)
}

/// Withdraws the commission from the validator. Amount is optional, if not provided,
/// the full commission is withdrawn.
public fun collect_commission(
    self: &mut System,
    cap: &ValidatorCommissionCap,
    amount: Option<u64>,
    ctx: &mut TxContext,
): Coin<IKA> {
    self.inner_mut().collect_commission(cap, amount, ctx)
}

/// Set a validator's name.
public fun set_validator_name(self: &mut System, name: String, cap: &ValidatorOperationCap) {
    self.inner_mut().set_validator_name(name, cap);
}

/// Get a validator's metadata.
public fun validator_metadata(self: &System, validator_id: ID): ValidatorMetadata {
    self.inner().validator_metadata(validator_id)
}

public fun set_validator_metadata(
    self: &mut System,
    metadata: ValidatorMetadata,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_validator_metadata(cap, metadata);
}

/// Sets a validator's network address.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_network_address(
    self: &mut System,
    network_address: String,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_epoch_network_address(network_address, cap)
}

/// Sets a validator's p2p address.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_p2p_address(
    self: &mut System,
    p2p_address: String,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_epoch_p2p_address(p2p_address, cap)
}

/// Sets a validator's consensus address.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_consensus_address(
    self: &mut System,
    consensus_address: String,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_epoch_consensus_address(consensus_address, cap)
}

/// Sets a validator's public key of protocol key and proof of possession.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_protocol_pubkey_bytes(
    self: &mut System,
    protocol_pubkey: vector<u8>,
    proof_of_possession_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .set_next_epoch_protocol_pubkey_bytes(protocol_pubkey, proof_of_possession_bytes, cap, ctx)
}

/// Sets a validator's public key of network key.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_network_pubkey_bytes(
    self: &mut System,
    network_pubkey: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_epoch_network_pubkey_bytes(network_pubkey, cap)
}

/// Sets a validator's public key of worker key.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_consensus_pubkey_bytes(
    self: &mut System,
    consensus_pubkey_bytes: vector<u8>,
    cap: &ValidatorOperationCap,
) {
    self.inner_mut().set_next_epoch_consensus_pubkey_bytes(consensus_pubkey_bytes, cap)
}

/// Sets a validator's MPC public data.
/// The change will only take effects starting from the next epoch.
public fun set_next_epoch_mpc_data_bytes(
    self: &mut System,
    mpc_data: TableVec<vector<u8>>,
    cap: &ValidatorOperationCap,
): Option<TableVec<vector<u8>>> {
    self.inner_mut().set_next_epoch_mpc_data_bytes(mpc_data, cap)
}

/// Get the pool token exchange rate of a validator. Works for both active and inactive pools.
public fun token_exchange_rates(self: &System, validator_id: ID): &Table<u64, TokenExchangeRate> {
    self.inner().token_exchange_rates(validator_id)
}

/// Get the active committee of the current epoch.
public fun active_committee(self: &System): BlsCommittee {
    self.inner().active_committee()
}

/// Get the active committee of the next epoch.
public fun next_epoch_active_committee(self: &System): Option<BlsCommittee> {
    self.inner().next_epoch_active_committee()
}

/// Locks the committee of the next epoch to allow starting the reconfiguration process.
public fun initiate_mid_epoch_reconfiguration(self: &mut System, clock: &Clock) {
    self.inner_mut().initiate_mid_epoch_reconfiguration(clock);
}

/// Create the system current status info.
public fun create_system_current_status_info(
    self: &System,
    clock: &Clock,
): SystemCurrentStatusInfo {
    self.inner().create_system_current_status_info(clock)
}

/// Initiates the advance epoch process.
public fun initiate_advance_epoch(self: &System, clock: &Clock): AdvanceEpochApprover {
    self.inner().initiate_advance_epoch(clock)
}

/// Advances the epoch to the next epoch.
/// Can only be called after all the witnesses have approved the advance epoch.
public fun advance_epoch(
    self: &mut System,
    advance_epoch_approver: AdvanceEpochApprover,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let inner_system = self.inner_mut();
    inner_system.advance_epoch(advance_epoch_approver, clock, ctx);
}

public fun verify_validator_cap(self: &System, cap: &ValidatorCap): VerifiedValidatorCap {
    self.inner().verify_validator_cap(cap)
}

public fun verify_operation_cap(
    self: &System,
    cap: &ValidatorOperationCap,
): VerifiedValidatorOperationCap {
    self.inner().verify_operation_cap(cap)
}

public fun verify_commission_cap(
    self: &System,
    cap: &ValidatorCommissionCap,
): VerifiedValidatorCommissionCap {
    self.inner().verify_commission_cap(cap)
}

// === Upgrades ===

public fun authorize_upgrade(self: &mut System, package_id: ID): (UpgradeTicket, UpgradePackageApprover) {
    self.inner_mut().authorize_upgrade(package_id)
}

public fun commit_upgrade(self: &mut System, receipt: UpgradeReceipt, upgrade_package_approver: &mut UpgradePackageApprover) {
    self.inner_mut().commit_upgrade(receipt, upgrade_package_approver);
    if (self.package_id == upgrade_package_approver.old_package_id()) {
        self.migration_epoch = option::some(upgrade_package_approver.migration_epoch());
        self.new_package_id = option::some(*upgrade_package_approver.new_package_id().borrow());
    };
}

public fun finalize_upgrade(self: &mut System, upgrade_package_approver: UpgradePackageApprover) {
    self.inner().finalize_upgrade(upgrade_package_approver);
}

public fun process_checkpoint_message_by_quorum(
    self: &mut System,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    message: vector<u8>,
    ctx: &mut TxContext,
) {
    self.inner_mut().process_checkpoint_message_by_quorum(signature, signers_bitmap, message, ctx);
}

// === Protocol Cap Functions ===

public fun add_upgrade_cap_by_cap(self: &mut System, upgrade_cap: UpgradeCap, cap: &ProtocolCap) {
    self.inner_mut().add_upgrade_cap_by_cap(upgrade_cap, cap);
}

public fun verify_protocol_cap(self: &System, cap: &ProtocolCap): VerifiedProtocolCap {
    self.inner().verify_protocol_cap(cap)
}

public fun process_checkpoint_message_by_cap(
    self: &mut System,
    message: vector<u8>,
    cap: &ProtocolCap,
    ctx: &mut TxContext,
) {
    self.inner_mut().process_checkpoint_message_by_cap(message, cap, ctx);
}

public fun set_approved_upgrade_by_cap(
    self: &mut System,
    package_id: ID,
    digest: Option<vector<u8>>,
    cap: &ProtocolCap,
) {
    self.inner_mut().set_approved_upgrade_by_cap(package_id, digest, cap);
}

public fun set_or_remove_witness_approving_advance_epoch_by_cap(
    self: &mut System,
    witness_type: String,
    remove: bool,
    cap: &ProtocolCap,
) {
    self
        .inner_mut()
        .set_or_remove_witness_approving_advance_epoch_by_cap(witness_type, remove, cap);
}

/// Try to migrate the system object to the new package id using a cap.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `system_inner` object if needed.
/// This function can be called immediately after the upgrade is committed.
public fun try_migrate_by_cap(self: &mut System, cap: &ProtocolCap) {
    let _ = self.inner().verify_protocol_cap(cap);
    assert!(self.version < VERSION, EInvalidMigration);
    assert!(self.new_package_id.is_some(), EInvalidMigration);
    self.try_migrate_impl();
}

/// Try to migrate the system object to the new package id.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `system_inner` object if needed.
/// Call this function after the migration epoch is reached.
public fun try_migrate(self: &mut System) {
    assert!(self.version < VERSION, EInvalidMigration);
    assert!(self.new_package_id.is_some(), EInvalidMigration);
    assert!(self.migration_epoch.is_some_and!(|e| self.inner_without_version_check().epoch() >= *e), EInvalidMigration);
    self.try_migrate_impl();
}

/// Try to migrate the system object to the new package id.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `system_inner` object if needed.
fun try_migrate_impl(self: &mut System) {
    // Move the old system inner to the new version.
    let system_inner: SystemInner = dynamic_field::remove(&mut self.id, self.version);
    dynamic_field::add(&mut self.id, VERSION, system_inner);
    self.version = VERSION;

    self.package_id = self.new_package_id.extract();
    // empty the migration epoch
    if (self.migration_epoch.is_some()) {
        let _ = self.migration_epoch.extract();
    };
}

public fun version(self: &System): u64 {
    self.version
}

// === Utility functions ===

/// Calculates the rewards for an amount with value `staked_principal`, staked in the validator with
/// the given `validator_id` between `activation_epoch` and `withdraw_epoch`.
///
/// This function can be used with `dev_inspect` to calculate the expected rewards for a `StakedIka`
/// object or, more generally, the returns provided by a given validator over a given period.
public fun calculate_rewards(
    self: &System,
    validator_id: ID,
    staked_principal: u64,
    activation_epoch: u64,
    withdraw_epoch: u64,
): u64 {
    self.inner().calculate_rewards(validator_id, staked_principal, activation_epoch, withdraw_epoch)
}

/// Call `staked_ika::can_withdraw_early` to allow calling this method in applications.
public fun can_withdraw_staked_ika_early(self: &System, staked_ika: &StakedIka): bool {
    self.inner().can_withdraw_staked_ika_early(staked_ika)
}

// === Internals ===

/// Get a mutable reference to `SystemInnerVX` from the `System`.
fun inner_mut(self: &mut System): &mut SystemInner {
    assert!(self.version == VERSION, EWrongInnerVersion);
    dynamic_field::borrow_mut(&mut self.id, VERSION)
}

/// Get an immutable reference to `SystemInnerVX` from the `System`.
fun inner(self: &System): &SystemInner {
    assert!(self.version == VERSION, EWrongInnerVersion);
    dynamic_field::borrow(&self.id, VERSION)
}

/// Get an immutable reference to `SystemInner` from the `System` without checking the version.
fun inner_without_version_check(self: &System): &SystemInner {
    dynamic_field::borrow(&self.id, self.version)
}

// === Test Functions ===

#[test_only]
/// Return the current epoch number. Useful for applications that need a coarse-grained concept of time,
/// since epochs are ever-increasing and epoch changes are intended to happen every 24 hours.
public fun epoch(self: &System): u64 {
    self.inner().epoch()
}

#[test_only]
/// Returns unix timestamp of the start of current epoch
public fun epoch_start_timestamp_ms(self: &mut System): u64 {
    self.inner().epoch_start_timestamp_ms()
}

#[test_only]
/// Returns the total amount staked with `validator_id`.
/// Aborts if `validator_id` is not an active validator.
public fun validator_stake_amount(self: &mut System, validator_id: ID): u64 {
    self.inner_mut().validator_stake_amount(validator_id)
}

#[test_only]
use sui::vec_set::VecSet;
#[test_only]
/// Returns all the validators who are currently reporting `validator_id`
public fun get_reporters_of(self: &mut System, validator_id: ID): VecSet<ID> {
    self.inner().get_reporters_of(validator_id)
}

#[test_only]
/// Return the current validator set
public fun validator_set(self: &mut System): &ValidatorSet {
    self.inner().validator_set()
}

#[test_only]
public fun set_epoch_for_testing(self: &mut System, epoch_num: u64) {
    self.inner_mut().set_epoch_for_testing(epoch_num)
}

#[test_only]
public fun request_add_validator_for_testing(self: &mut System, cap: &ValidatorCap) {
    self.inner_mut().request_add_validator_for_testing(cap)
}

#[test_only]
public fun get_stake_subsidy_stake_subsidy_distribution_counter(self: &mut System): u64 {
    self.inner().get_stake_subsidy_stake_subsidy_distribution_counter()
}

#[test_only]
public fun set_stake_subsidy_stake_subsidy_distribution_counter(self: &mut System, counter: u64) {
    self.inner_mut().set_stake_subsidy_stake_subsidy_distribution_counter(counter)
}

#[test_only]
public fun inner_mut_for_testing(self: &mut System): &mut SystemInner {
    self.inner_mut()
}
