// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::init;

use ika::ika::IKA;
use ika_common::protocol_cap::ProtocolCap;
use ika_common::system_object_cap::SystemObjectCap;
use ika_system::display;
use ika_system::protocol_treasury;
use ika_system::system;
use ika_system::validator_set;
use std::string::String;
use std::type_name;
use sui::coin::TreasuryCap;
use sui::package::{Self, Publisher, UpgradeCap};

// === Errors ===

/// The provided upgrade cap does not belong to this package.
const EInvalidUpgradeCap: u64 = 1;

// === Structs ===
/// The OTW to create `Publisher` and `Display` objects.
public struct INIT has drop {}

/// Must only be created by `init`.
public struct InitCap has key, store {
    id: UID,
    publisher: Publisher,
}

// === Module Initializer ===

/// Init function, creates an init cap and transfers it to the sender.
/// This allows the sender to call the function to actually initialize the system
/// with the corresponding parameters. Once that function is called, the cap is destroyed.
fun init(otw: INIT, ctx: &mut TxContext) {
    let id = object::new(ctx);
    let publisher = package::claim(otw, ctx);
    let init_cap = InitCap { id, publisher };
    transfer::transfer(init_cap, ctx.sender());
}

// === Public Functions ===

/// Function to initialize ika and share the system object.
/// This can only be called once, after which the `InitCap` is destroyed.
public fun initialize(
    init_cap: InitCap,
    system_object_cap: SystemObjectCap,
    ika_upgrade_cap: UpgradeCap,
    ika_system_upgrade_cap: UpgradeCap,
    protocol_treasury_cap: TreasuryCap<IKA>,
    protocol_version: u64,
    chain_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    // Stake Subsidy parameters
    stake_subsidy_start_epoch: u64,
    stake_subsidy_rate: u16,
    stake_subsidy_period_length: u64,
    // Validator committee parameters
    min_validator_count: u64,
    max_validator_count: u64,
    min_validator_joining_stake: u64,
    reward_slashing_rate: u16,
    // Display parameters
    staked_ika_image_url: String,
    ctx: &mut TxContext,
): ProtocolCap {
    let InitCap { id, publisher } = init_cap;
    id.delete();

    let ika_package_id = ika_upgrade_cap.package();
    let ika_system_package_id = ika_system_upgrade_cap.package();

    assert!(
        type_name::get<IKA>().get_address() == ika_package_id.to_address().to_ascii_string(),
        EInvalidUpgradeCap,
    );

    assert!(
        type_name::get<InitCap>().get_address() == ika_system_package_id.to_address().to_ascii_string(),
        EInvalidUpgradeCap,
    );

    let upgrade_caps = vector[ika_upgrade_cap, ika_system_upgrade_cap];

    let validators = validator_set::new(
        min_validator_count,
        max_validator_count,
        min_validator_joining_stake,
        max_validator_count,
        reward_slashing_rate,
        ctx,
    );

    let protocol_treasury = protocol_treasury::create(
        protocol_treasury_cap,
        stake_subsidy_rate,
        stake_subsidy_period_length,
        ctx,
    );

    let protocol_cap = system::create(
        ika_system_package_id,
        system_object_cap,
        upgrade_caps,
        validators,
        protocol_version,
        chain_start_timestamp_ms,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        protocol_treasury,
        ctx,
    );

    display::create(
        publisher,
        staked_ika_image_url,
        ctx,
    );

    protocol_cap
}

// === Test only ===

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(INIT {}, ctx);
}

#[test_only]
/// Does the same as `initialize` but does not check the package id of the upgrade cap.
///
/// This is needed for testing, since the package ID of all types will be zero, which cannot be used
/// as the package ID for an upgrade cap.
public fun initialize_for_testing(
    init_cap: InitCap,
    system_object_cap: SystemObjectCap,
    ika_upgrade_cap: UpgradeCap,
    ika_system_upgrade_cap: UpgradeCap,
    protocol_treasury_cap: TreasuryCap<IKA>,
    protocol_version: u64,
    chain_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    // Stake Subsidy parameters
    stake_subsidy_start_epoch: u64,
    stake_subsidy_rate: u16,
    stake_subsidy_period_length: u64,
    // Validator committee parameters
    min_validator_count: u64,
    max_validator_count: u64,
    min_validator_joining_stake: u64,
    reward_slashing_rate: u16,
    ctx: &mut TxContext,
): ProtocolCap {
    let InitCap { id, publisher } = init_cap;
    id.delete();

    let ika_system_package_id = ika_system_upgrade_cap.package();
    let upgrade_caps = vector[ika_upgrade_cap, ika_system_upgrade_cap];

    let validators = validator_set::new(
        min_validator_count,
        max_validator_count,
        min_validator_joining_stake,
        max_validator_count,
        reward_slashing_rate,
        ctx,
    );

    let protocol_treasury = protocol_treasury::create(
        protocol_treasury_cap,
        stake_subsidy_rate,
        stake_subsidy_period_length,
        ctx,
    );

    let protocol_cap = system::create(
        ika_system_package_id,
        system_object_cap,
        upgrade_caps,
        validators,
        protocol_version,
        chain_start_timestamp_ms,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        protocol_treasury,
        ctx,
    );

    display::create(
        publisher,
        b"".to_string(),
        ctx,
    );

    protocol_cap
}
