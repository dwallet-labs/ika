// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[allow(unused_mut_ref)]
module ika_system::e2e_runner;

use sui::{clock::{Self, Clock}, test_scenario::{Self, Scenario}, test_utils, coin};
use ika_system::{
    init,
    system::System,
    system_inner::ProtocolCap,
    dwallet_2pc_mpc_coordinator::DWalletCoordinator,
    test_validator::{Self, TestValidator},
    test_utils as ika_test_utils,
    dwallet_checkpoint,
    bls_committee::BlsCommittee,
};
use ika_system::dwallet_pricing;
use sui::vec_map;
use ika_system::dwallet_checkpoint::dwallet_mpc_network_dkg_output;
use sui::coin::burn_for_testing;
use ika_system::dwallet_pricing::DWalletPricing;
use std::unit_test::assert_eq;

const DEFAULT_PROTOCOL_VERSION: u64 = 1;
const DEFAULT_CHAIN_START_TIMESTAMP_MS: u64 = 1717244800000; // 2024-05-31 00:00:00 UTC
const DEFAULT_EPOCH_DURATION_MS: u64 = 24 * 60 * 60 * 1000; // 1 day
const DEFAULT_MID_CONFIGURATION_DELTA_MS: u64 = 24 * 60 * 60 * 1000 / 2; // 1 day / 2
const DEFAULT_STAKE_SUBSIDY_START_EPOCH: u64 = 1; 
const DEFAULT_STAKE_SUBSIDY_RATE: u16 = 1000; // 1000 BPS = 10%
const DEFAULT_STAKE_SUBSIDY_PERIOD_LENGTH: u64 = 365; // 1 year
const DEFAULT_MIN_VALIDATOR_COUNT: u64 = 4;
const DEFAULT_MAX_VALIDATOR_COUNT: u64 = 115;
const DEFAULT_MAX_VALIDATOR_CHANGE_COUNT: u64 = 10;
const DEFAULT_MIN_VALIDATOR_JOINING_STAKE: u64 = 30_000_000 * 1_000_000_000; // 30 million IKA (value is in INKU)
const DEFAULT_REWARD_SLASHING_RATE: u16 = 100;

// === Tests Runner ===

/// The test runner for end-to-end tests.
public struct TestRunner {
    scenario: Scenario,
    timestamp_ms: u64,
    admin: address,
}

/// Add any parameters to the initialization, such as epoch zero duration and number of shards.
/// They will be used by the e2e runner admin during the initialization.
public struct InitBuilder {
    protocol_version: Option<u64>,
    chain_start_timestamp_ms: Option<u64>,
    epoch_duration_ms: Option<u64>,
    // Stake Subsidy parameters
    stake_subsidy_start_epoch: Option<u64>,
    stake_subsidy_rate: Option<u16>,
    stake_subsidy_period_length: Option<u64>,
    // Validator committee parameters
    min_validator_count: Option<u64>,
    max_validator_count: Option<u64>,
    min_validator_joining_stake: Option<u64>,
    reward_slashing_rate: Option<u16>,
    admin: address,
}

/// Prepare the test runner with the given admin address. Returns a builder to
/// set optional parameters.
///
/// Example:
/// ```move
/// let admin = 0xA11CE;
/// let mut runner = e2e_runner::prepare(admin)
///    .protocol_version(1)
///    .chain_start_timestamp_ms(1717622400000)
///    .epoch_duration_ms(100000000)
///    .stake_subsidy_start_epoch(1)
///    .stake_subsidy_rate(100)
///    .stake_subsidy_period_length(100)
///    .min_validator_count(100)
///    .max_validator_count(100)
///    .build();
///
/// runner.tx!(admin, |staking, system, ctx| { /* ... */ });
/// ```
public fun prepare(admin: address): InitBuilder {
    InitBuilder {
        protocol_version: option::none(),
        chain_start_timestamp_ms: option::none(),
        epoch_duration_ms: option::none(),
        stake_subsidy_start_epoch: option::none(),
        stake_subsidy_rate: option::none(),
        stake_subsidy_period_length: option::none(),
        min_validator_count: option::none(),
        max_validator_count: option::none(),
        min_validator_joining_stake: option::none(),
        reward_slashing_rate: option::none(),
        admin,
    }
}

/// Change the protocol version.
public fun protocol_version(mut self: InitBuilder, version: u64): InitBuilder {
    self.protocol_version = option::some(version);
    self
}

/// Change the chain start timestamp.
public fun chain_start_timestamp_ms(mut self: InitBuilder, timestamp: u64): InitBuilder {
    self.chain_start_timestamp_ms = option::some(timestamp);
    self
}

/// Change the epoch duration.
public fun epoch_duration_ms(mut self: InitBuilder, duration: u64): InitBuilder {
    self.epoch_duration_ms = option::some(duration);
    self
}

/// Change the stake subsidy start epoch.
public fun stake_subsidy_start_epoch(mut self: InitBuilder, epoch: u64): InitBuilder {
    self.stake_subsidy_start_epoch = option::some(epoch);
    self
}

/// Change the stake subsidy rate.
public fun stake_subsidy_rate(mut self: InitBuilder, rate: u16): InitBuilder {
    self.stake_subsidy_rate = option::some(rate);
    self
}

/// Change the stake subsidy period length.
public fun stake_subsidy_period_length(mut self: InitBuilder, length: u64): InitBuilder {
    self.stake_subsidy_period_length = option::some(length);
    self
}

/// Change the minimum validator count.
public fun min_validator_count(mut self: InitBuilder, count: u64): InitBuilder {
    self.min_validator_count = option::some(count);
    self
}

/// Change the maximum validator count.
public fun max_validator_count(mut self: InitBuilder, count: u64): InitBuilder {
    self.max_validator_count = option::some(count);
    self
}

/// Change the minimum validator joining stake.
public fun min_validator_joining_stake(mut self: InitBuilder, stake: u64): InitBuilder {
    self.min_validator_joining_stake = option::some(stake);
    self
}

/// Change the reward slashing rate.
public fun reward_slashing_rate(mut self: InitBuilder, rate: u16): InitBuilder {
    self.reward_slashing_rate = option::some(rate);
    self
}

/// Build the test runner with the given parameters.
public fun build(self: InitBuilder): TestRunner {
    let InitBuilder { admin, protocol_version, chain_start_timestamp_ms, epoch_duration_ms, stake_subsidy_start_epoch, stake_subsidy_rate, stake_subsidy_period_length, min_validator_count, max_validator_count, min_validator_joining_stake, reward_slashing_rate } = self;
    let protocol_version = protocol_version.destroy_or!(DEFAULT_PROTOCOL_VERSION);
    let chain_start_timestamp_ms = chain_start_timestamp_ms.destroy_or!(DEFAULT_CHAIN_START_TIMESTAMP_MS);
    let epoch_duration_ms = epoch_duration_ms.destroy_or!(DEFAULT_EPOCH_DURATION_MS);
    let stake_subsidy_start_epoch = stake_subsidy_start_epoch.destroy_or!(DEFAULT_STAKE_SUBSIDY_START_EPOCH);
    let stake_subsidy_rate = stake_subsidy_rate.destroy_or!(DEFAULT_STAKE_SUBSIDY_RATE);
    let stake_subsidy_period_length = stake_subsidy_period_length.destroy_or!(DEFAULT_STAKE_SUBSIDY_PERIOD_LENGTH);
    let min_validator_count = min_validator_count.destroy_or!(DEFAULT_MIN_VALIDATOR_COUNT);
    let max_validator_count = max_validator_count.destroy_or!(DEFAULT_MAX_VALIDATOR_COUNT);
    let min_validator_joining_stake = min_validator_joining_stake.destroy_or!(DEFAULT_MIN_VALIDATOR_JOINING_STAKE);
    let reward_slashing_rate = reward_slashing_rate.destroy_or!(DEFAULT_REWARD_SLASHING_RATE);

    let mut scenario = test_scenario::begin(admin);
    let ctx = scenario.ctx();

    init::init_for_testing(ctx);

    // We need an upgrade cap for package with address 0x0
    let ika_upgrade_cap = sui::package::test_publish(ctx.fresh_object_address().to_id(), ctx);
    let ika_system_upgrade_cap = sui::package::test_publish(ctx.fresh_object_address().to_id(), ctx);
    let mut ika_treasury_cap = ika_test_utils::ika_treasury_for_testing(ctx);
    ika_treasury_cap.supply_mut().increase_supply(10_000_000_000 * 1_000_000_000).destroy_for_testing();

    scenario.next_tx(admin);
    let cap = scenario.take_from_sender<init::InitCap>();
    let ctx = scenario.ctx();
    let protocol_cap = init::initialize_for_testing(
        cap,
        ika_upgrade_cap,
        ika_system_upgrade_cap,
        ika_treasury_cap,
        protocol_version,
        chain_start_timestamp_ms,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        stake_subsidy_rate,
        stake_subsidy_period_length,
        min_validator_count,
        max_validator_count,
        min_validator_joining_stake,
        reward_slashing_rate,
        ctx,
    );

    transfer::public_transfer(protocol_cap, admin);
    scenario.next_tx(admin);

    TestRunner { scenario, timestamp_ms: 0, admin }
}

/// Get the admin address that published Walrus System and Staking.
public fun admin(self: &TestRunner): address { self.admin }

/// Access runner's `Scenario`.
public fun scenario(self: &mut TestRunner): &mut Scenario { &mut self.scenario }

public fun increment_timestamp_ms(self: &mut TestRunner, tick: u64) {
    self.timestamp_ms = self.timestamp_ms + tick;
}

public fun set_timestamp_ms(self: &mut TestRunner, timestamp_ms: u64) {
    assert!(timestamp_ms >= self.timestamp_ms);
    self.timestamp_ms = timestamp_ms;
}

/// Access the current timestamp.
public fun timestamp_ms(self: &mut TestRunner): u64 { self.timestamp_ms }

/// Access the current epoch of the system.
public fun epoch(self: &mut TestRunner): u64 {
    self.scenario.next_tx(self.admin);
    let system = self.scenario.take_shared<System>();
    let epoch = system.epoch();
    test_scenario::return_shared(system);
    epoch
}

/// Access the active committee of the system.
public fun active_committee(self: &mut TestRunner): BlsCommittee {
    self.scenario.next_tx(self.admin);
    let system = self.scenario.take_shared<System>();
    let committee = system.active_committee();
    test_scenario::return_shared(system);
    committee
}

public fun next_epoch_active_committee(self: &mut TestRunner): Option<BlsCommittee> {
    self.scenario.next_tx(self.admin);
    let system = self.scenario.take_shared<System>();
    let committee = system.next_epoch_active_committee();
    test_scenario::return_shared(system);
    committee
}

public fun current_pricing(self: &mut TestRunner): DWalletPricing {
    self.scenario.next_tx(self.admin);
    let dwallet_2pc_mpc_coordinator = self.scenario.take_shared<DWalletCoordinator>();
    let pricing = dwallet_2pc_mpc_coordinator.current_pricing();
    test_scenario::return_shared(dwallet_2pc_mpc_coordinator);
    pricing
}

/// Returns the default epoch duration.
public fun default_epoch_duration_ms(): u64 { DEFAULT_EPOCH_DURATION_MS }

/// Returns the default chain start timestamp.
public fun default_chain_start_timestamp_ms(): u64 { DEFAULT_CHAIN_START_TIMESTAMP_MS }

/// Returns the default max validator change count.
public fun default_max_validator_change_count(): u64 { DEFAULT_MAX_VALIDATOR_CHANGE_COUNT }

/// Run a transaction as a `sender`, and call the function `f` with the `System` and `TxContext` as arguments.
///
/// This is used for initialization of the system, where the `DWalletCoordinator` is not yet created.
public macro fun tx_for_initialization(
    $runner: &mut TestRunner,
    $sender: address,
    $f: |&mut System, &Clock, &mut TxContext|,
) {
    let runner = $runner;
    let timestamp_ms = runner.timestamp_ms();
    let scenario = runner.scenario();
    scenario.next_tx($sender);
    let mut system = scenario.take_shared<System>();
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(timestamp_ms);
    let ctx = scenario.ctx();

    $f(&mut system, &clock, ctx);

    test_scenario::return_shared(system);
    clock::destroy_for_testing(clock);
}

/// Run a transaction as a `sender`, and call the function `f` with the `System`, `ProtocolCap` and `TxContext` as arguments.
///
/// This is used for initialization of the system, where the `DWalletCoordinator` is not yet created.
public macro fun tx_for_initialization_with_protocol_cap(
    $runner: &mut TestRunner,
    $sender: address,
    $f: |&mut System, &ProtocolCap, &Clock, &mut TxContext|,
) {
    let runner = $runner;
    let timestamp_ms = runner.timestamp_ms();
    let scenario = runner.scenario();
    scenario.next_tx($sender);
    let mut system = scenario.take_shared<System>();
    let protocol_cap = scenario.take_from_sender<ProtocolCap>();
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(timestamp_ms);
    let ctx = scenario.ctx();

    $f(&mut system, &protocol_cap, &clock, ctx);

    test_scenario::return_shared(system);
    test_scenario::return_to_address($sender, protocol_cap);
    clock::destroy_for_testing(clock);
}

/// Run a transaction as a `sender`, and call the function `f` with the `System`,
/// `DWalletCoordinator`, and `TxContext` as arguments.
public macro fun tx(
    $runner: &mut TestRunner,
    $sender: address,
    $f: |&mut System, &mut DWalletCoordinator, &Clock, &mut TxContext|,
) {
    let runner = $runner;
    let timestamp_ms = runner.timestamp_ms();
    let scenario = runner.scenario();
    scenario.next_tx($sender);
    let mut system = scenario.take_shared<System>();
    let mut dwallet_2pc_mpc_coordinator = scenario.take_shared<DWalletCoordinator>();
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(timestamp_ms);
    let ctx = scenario.ctx();

    $f(&mut system, &mut dwallet_2pc_mpc_coordinator, &clock, ctx);

    test_scenario::return_shared(system);
    test_scenario::return_shared(dwallet_2pc_mpc_coordinator);
    clock::destroy_for_testing(clock);
}

/// Run a transaction as a `sender`, and call the function `f` with the `System`,
/// `DWalletCoordinator`, and `TxContext` as arguments.
public macro fun tx_with_protocol_cap(
    $runner: &mut TestRunner,
    $sender: address,
    $f: |&mut System, &mut DWalletCoordinator, &ProtocolCap, &Clock, &mut TxContext|,
) {
    let runner = $runner;
    let timestamp_ms = runner.timestamp_ms();
    let scenario = runner.scenario();
    scenario.next_tx($sender);
    let mut system = scenario.take_shared<System>();
    let mut dwallet_2pc_mpc_coordinator = scenario.take_shared<DWalletCoordinator>();
    let protocol_cap = scenario.take_from_sender<ProtocolCap>();
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(timestamp_ms);
    let ctx = scenario.ctx();

    $f(&mut system, &mut dwallet_2pc_mpc_coordinator, &protocol_cap, &clock, ctx);

    test_scenario::return_shared(system);
    test_scenario::return_shared(dwallet_2pc_mpc_coordinator);
    scenario.return_to_sender(protocol_cap);
    clock::destroy_for_testing(clock);
}

/// Returns TransactionEffects of the last transaction.
public fun last_tx_effects(runner: &mut TestRunner): test_scenario::TransactionEffects {
    runner.scenario().next_tx(@1)
}

/// Destroy the test runner and all resources.
public fun destroy(self: TestRunner) {
    test_utils::destroy(self)
}

public fun setup_default_test_runner_and_validators(): (TestRunner, vector<TestValidator>) {
    let admin = @0xA11CE;
    let validators = test_validator::test_validators(10);
    let runner = prepare(admin).build();
    (runner, validators)
}

public fun initialize_committee_for_epoch_one(
    runner: &mut TestRunner,
    validators: &mut vector<TestValidator>,
    initial_timestamp_ms: Option<u64>,
    increment_timestamp_ms_before_initialization: Option<u64>,
    default_pricing: Option<DWalletPricing>,
    default_supported_curves_to_signature_algorithms_to_hash_schemes: Option<vec_map::VecMap<u32, vec_map::VecMap<u32, vector<u32>>>>,
) {
    let admin = runner.admin();
    runner.set_timestamp_ms(initial_timestamp_ms.destroy_or!(DEFAULT_CHAIN_START_TIMESTAMP_MS));

    // === register candidates ===

    validators.do_mut!(|validator| {
        runner.tx_for_initialization!(validator.sui_address(), |system, _clock, ctx| {
            let (cap, operation_cap, commission_cap) = system.request_add_validator_candidate(
                validator.name(),
                validator.protocol_pubkey_bytes(),
                validator.network_pubkey_bytes(),
                validator.consensus_pubkey_bytes(),
                validator.mpc_data(ctx),
                validator.create_proof_of_possession(),
                validator.network_address(),
                validator.p2p_address(),
                validator.consensus_address(),
                validator.commission_rate(),
                validator.metadata(),
                ctx,
            );
            validator.set_validator_cap(cap);
            validator.set_validator_operation_cap(operation_cap);
            validator.set_validator_commission_cap(commission_cap);
        });
    });

    // === stake with each validator ===

    validators.do_mut!(|validator| {
        runner.tx_for_initialization!(validator.sui_address(), |system, _clock, ctx| {
            let coin = ika_test_utils::mint_inku(validator.stake_amount(), ctx);
            let staked_ika = system.request_add_stake(coin, validator.validator_id(), ctx);
            validator.staked_ika().push_back(staked_ika);
        });
    });


    // === join committee each validator ===

    validators.do_ref!(|validator| {
        runner.tx_for_initialization!(validator.sui_address(), |system, _clock, _ctx| {
            system.request_add_validator(validator.cap());
        });
    });

    // === advance clock and initialize ===
    // === check if epoch state is changed correctly ==

    runner.increment_timestamp_ms(increment_timestamp_ms_before_initialization.destroy_or!(DEFAULT_EPOCH_DURATION_MS));
    runner.tx_for_initialization_with_protocol_cap!(admin, |system, protocol_cap, clock, ctx| {
        let pricing = if(default_pricing.is_some()) {
            *default_pricing.borrow()
        } else {
            // default pricing is 0 for all protocols
            let mut pricing = dwallet_pricing::empty();
            pricing.insert_or_update_dwallet_pricing(0, option::none(), 0, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::none(), 1, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::none(), 2, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::none(), 3, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::none(), 4, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::some(0), 5, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::some(0), 6, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::some(0), 7, 0, 0, 0, 0);
            pricing.insert_or_update_dwallet_pricing(0, option::some(0), 8, 0, 0, 0, 0);
            pricing
        };
        let supported_curves_to_signature_algorithms_to_hash_schemes = if(default_supported_curves_to_signature_algorithms_to_hash_schemes.is_some()) {
            *default_supported_curves_to_signature_algorithms_to_hash_schemes.borrow()
        } else {
            let mut supported_curves_to_signature_algorithms_to_hash_schemes = vec_map::empty();
            // default support to curve: secp256k1 -> signature algorithm: ecdsa -> hash scheme: keccak256, sha256
            supported_curves_to_signature_algorithms_to_hash_schemes.insert(0u32, vec_map::from_keys_values(vector[0u32], vector[vector[0u32, 1u32]]));
            supported_curves_to_signature_algorithms_to_hash_schemes
        };
        system.initialize(
            pricing,
            supported_curves_to_signature_algorithms_to_hash_schemes,
            DEFAULT_MAX_VALIDATOR_CHANGE_COUNT,
            protocol_cap,
            clock,
            ctx,
        );
        validators.do_ref!(|validator| assert!(system.active_committee().contains(&validator.validator_id())));       
    });

    runner.perform_network_encryption_key_dkg(validators);
}

public fun perform_network_encryption_key_dkg(
    runner: &mut TestRunner,
    validators: &mut vector<TestValidator>,
) {
    let admin = runner.admin();
    let epoch = runner.epoch();
    runner.tx_with_protocol_cap!(admin, |system, dwallet_2pc_mpc_coordinator, protocol_cap, _clock, ctx| {
        system.request_dwallet_network_encryption_key_dkg_by_cap(dwallet_2pc_mpc_coordinator, protocol_cap, x"", ctx);

        let dwallet_network_encryption_key_id = system.dwallet_2pc_mpc_coordinator_network_encryption_key_ids()[0];
        let next_checkpoint_sequence_number = dwallet_2pc_mpc_coordinator.last_processed_checkpoint_sequence_number().map!(|x| x + 1).destroy_or!(0);
        let dwallet_network_encryption_key_dkg_message = dwallet_checkpoint::dwallet_mpc_network_dkg_output(dwallet_network_encryption_key_id.to_bytes(), x"", true, vector[0u32], false);
        let dwallet_checkpoint_message = dwallet_checkpoint::dwallet_checkpoint_message(epoch, next_checkpoint_sequence_number, 0, vector[dwallet_network_encryption_key_dkg_message]);
        let dwallet_checkpoint_message_bytes = dwallet_checkpoint::dwallet_checkpoint_message_bytes(dwallet_checkpoint_message);
        let dwallet_checkpoint_message_intent = dwallet_checkpoint::dwallet_checkpoint_message_intent(dwallet_checkpoint_message_bytes, epoch);
        let (signature, members_bitmap) = test_validator::sign(validators, dwallet_checkpoint_message_intent);
        let reimbursement = dwallet_2pc_mpc_coordinator.process_checkpoint_message_by_quorum(signature, members_bitmap, dwallet_checkpoint_message_bytes, x"", x"", x"", ctx);

        coin::burn_for_testing(reimbursement);        
    });
}

public fun perform_network_encryption_key_reconfiguration(
    runner: &mut TestRunner,
    validators: &mut vector<TestValidator>,
) {
    let admin = runner.admin();
    let epoch = runner.epoch();
    runner.tx!(admin, |system, dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let dwallet_network_encryption_key_id = system.dwallet_2pc_mpc_coordinator_network_encryption_key_ids()[0];

        let next_checkpoint_sequence_number = dwallet_2pc_mpc_coordinator.last_processed_checkpoint_sequence_number().map!(|x| x + 1).destroy_or!(0);
        let dwallet_network_encryption_key_reconfiguration_message = dwallet_checkpoint::dwallet_mpc_network_reconfiguration_output(dwallet_network_encryption_key_id.to_bytes(), x"", true, vector[0u32], false);
        let dwallet_checkpoint_message = dwallet_checkpoint::dwallet_checkpoint_message(epoch, next_checkpoint_sequence_number, 0, vector[dwallet_network_encryption_key_reconfiguration_message]);
        let dwallet_checkpoint_message_bytes = dwallet_checkpoint::dwallet_checkpoint_message_bytes(dwallet_checkpoint_message);
        let dwallet_checkpoint_message_intent = dwallet_checkpoint::dwallet_checkpoint_message_intent(dwallet_checkpoint_message_bytes, epoch);
        let (signature, members_bitmap) = test_validator::sign(validators, dwallet_checkpoint_message_intent);

        let reimbursement = dwallet_2pc_mpc_coordinator.process_checkpoint_message_by_quorum(signature, members_bitmap, dwallet_checkpoint_message_bytes, x"", x"", x"", ctx);

        coin::burn_for_testing(reimbursement);    
    });
}

public fun perform_default_pricing_calculation_votes(
    runner: &mut TestRunner,
) {
    let admin = runner.admin();
    runner.tx!(admin, |_system, dwallet_2pc_mpc_coordinator, _clock, _ctx| {
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::none(), 0);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::none(), 1);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::none(), 2);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::none(), 3);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::none(), 4);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::some(0), 5);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::some(0), 6);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::some(0), 7);
        dwallet_2pc_mpc_coordinator.calculate_pricing_votes(0, option::some(0), 8);
    });
}

public fun perform_mid_epoch_reconfiguration(
    runner: &mut TestRunner,
    validators: &mut vector<TestValidator>,
    increment_timestamp_ms: Option<u64>,
) {
    let admin = runner.admin();
    runner.increment_timestamp_ms(increment_timestamp_ms.destroy_or!(DEFAULT_MID_CONFIGURATION_DELTA_MS));
    runner.tx!(admin, |system, dwallet_2pc_mpc_coordinator, clock, ctx| {
        system.request_reconfig_mid_epoch(dwallet_2pc_mpc_coordinator, clock, ctx);
    });

    runner.perform_network_encryption_key_reconfiguration(validators);
    runner.perform_default_pricing_calculation_votes();
}

public fun perform_advance_epoch(
    runner: &mut TestRunner,
    increment_timestamp_ms: Option<u64>,
) {
    let admin = runner.admin();
    runner.increment_timestamp_ms(increment_timestamp_ms.destroy_or!(DEFAULT_EPOCH_DURATION_MS - DEFAULT_MID_CONFIGURATION_DELTA_MS));
    runner.tx!(admin, |system, dwallet_2pc_mpc_coordinator, clock, ctx| {
        system.request_lock_epoch_sessions(dwallet_2pc_mpc_coordinator, clock);
        system.request_advance_epoch(dwallet_2pc_mpc_coordinator, clock, ctx);
    });
}

public fun assert_pricing_values_for_default_protocols(
    runner: &mut TestRunner,
    expected_pricing_value: u64,
) {
    let current_pricing = runner.current_pricing();

    let protocol0_value = current_pricing.try_get_dwallet_pricing_value(0, option::none(), 0);
    assert_eq!(protocol0_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol0_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol0_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol0_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol1_value = current_pricing.try_get_dwallet_pricing_value(0, option::none(), 1);
    assert_eq!(protocol1_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol1_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol1_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol1_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol2_value = current_pricing.try_get_dwallet_pricing_value(0, option::none(), 2);
    assert_eq!(protocol2_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol2_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol2_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol2_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol3_value = current_pricing.try_get_dwallet_pricing_value(0, option::none(), 3);
    assert_eq!(protocol3_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol3_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol3_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol3_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol4_value = current_pricing.try_get_dwallet_pricing_value(0, option::none(), 4);
    assert_eq!(protocol4_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol4_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol4_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol4_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol5_value = current_pricing.try_get_dwallet_pricing_value(0, option::some(0), 5);
    assert_eq!(protocol5_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol5_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol5_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol5_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol6_value = current_pricing.try_get_dwallet_pricing_value(0, option::some(0), 6);
    assert_eq!(protocol6_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol6_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol6_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol6_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol7_value = current_pricing.try_get_dwallet_pricing_value(0, option::some(0), 7);
    assert_eq!(protocol7_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol7_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol7_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol7_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);

    let protocol8_value = current_pricing.try_get_dwallet_pricing_value(0, option::some(0), 8);
    assert_eq!(protocol8_value.borrow().consensus_validation_ika(), expected_pricing_value);
    assert_eq!(protocol8_value.borrow().computation_ika(), expected_pricing_value);
    assert_eq!(protocol8_value.borrow().gas_fee_reimbursement_sui(), expected_pricing_value);
    assert_eq!(protocol8_value.borrow().gas_fee_reimbursement_sui_for_system_calls(), expected_pricing_value);
}

#[allow(lint(self_transfer))]
public fun perform_dwallet_dkg_first_round(
    runner: &mut TestRunner,
    validators: &mut vector<TestValidator>,
    sender: address,
) {
    let epoch = runner.epoch();
    runner.tx!(sender, |system, dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let dwallet_network_encryption_key_id = system.dwallet_2pc_mpc_coordinator_network_encryption_key_ids()[0];
        let mut payment_ika = ika_test_utils::mint_ika(1_000, ctx);
        let mut payment_sui = ika_test_utils::mint_sui(1_000, ctx);
        let session_identifier = dwallet_2pc_mpc_coordinator.register_session_identifier(ctx.fresh_object_address().to_bytes(), ctx);
        let dwallet_cap = dwallet_2pc_mpc_coordinator.request_dwallet_dkg_first_round(dwallet_network_encryption_key_id, 0, session_identifier, &mut payment_ika, &mut payment_sui, ctx);

        let next_checkpoint_sequence_number = dwallet_2pc_mpc_coordinator.last_processed_checkpoint_sequence_number().map!(|x| x + 1).destroy_or!(0);
        let last_session_sequence_number = dwallet_2pc_mpc_coordinator.last_session_sequence_number();
        let dwallet_network_encryption_key_dkg_message = dwallet_checkpoint::dkg_first_round_output(dwallet_cap.dwallet_id().to_bytes(), x"", false, last_session_sequence_number);
        let dwallet_checkpoint_message = dwallet_checkpoint::dwallet_checkpoint_message(epoch, next_checkpoint_sequence_number, 0, vector[dwallet_network_encryption_key_dkg_message]);
        let dwallet_checkpoint_message_bytes = dwallet_checkpoint::dwallet_checkpoint_message_bytes(dwallet_checkpoint_message);
        let dwallet_checkpoint_message_intent = dwallet_checkpoint::dwallet_checkpoint_message_intent(dwallet_checkpoint_message_bytes, epoch);
        let (signature, members_bitmap) = test_validator::sign(validators, dwallet_checkpoint_message_intent);

        let reimbursement = dwallet_2pc_mpc_coordinator.process_checkpoint_message_by_quorum(signature, members_bitmap, dwallet_checkpoint_message_bytes, x"", x"", x"", ctx);

        coin::burn_for_testing(reimbursement);    

        transfer::public_transfer(dwallet_cap, ctx.sender());
        transfer::public_transfer(payment_ika, ctx.sender());
        transfer::public_transfer(payment_sui, ctx.sender());
    });
}