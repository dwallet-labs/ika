// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::test_validator;

use std::{string::String};
use sui::address;
use ika_system::{
    test_utils,
    validator_cap::{ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap},
    validator_metadata::{Self, ValidatorMetadata},
    validator_info,
    staked_ika::StakedIka,
};
use sui::table_vec::{Self, TableVec};

const DEFAULT_MIN_VALIDATOR_JOINING_STAKE: u64 = 30_000_000 * 1_000_000_000; // 30 million IKA (value is in INKU)

public struct TestValidator {
    sui_address: address,
    protocol_key_bytes: vector<u8>,
    network_pubkey_bytes: vector<u8>,
    consensus_pubkey_bytes: vector<u8>,
    network_address: String,
    p2p_address: String,
    consensus_address: String,
    commission_rate: u16,
    validator_cap: Option<ValidatorCap>,
    validator_operation_cap: Option<ValidatorOperationCap>,
    validator_commission_cap: Option<ValidatorCommissionCap>,
    stake_amount: Option<u64>,
    staked_ika: vector<StakedIka>,
}

public fun name(self: &TestValidator): String {
    self.sui_address.to_string()
}

public fun protocol_pubkey_bytes(self: &TestValidator): vector<u8> {
    test_utils::bls_min_pk_from_sk(&self.protocol_key_bytes)
}

public fun network_pubkey_bytes(self: &TestValidator): vector<u8> {
    self.network_pubkey_bytes
}

public fun consensus_pubkey_bytes(self: &TestValidator): vector<u8> {
    self.consensus_pubkey_bytes
}

public fun mpc_data(_self: &TestValidator, ctx: &mut TxContext): TableVec<vector<u8>> {
    let mpc_data_bytes = x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab";
    let mut mpc_data = table_vec::empty(ctx);
    mpc_data.push_back(mpc_data_bytes);
    mpc_data
}

public fun create_proof_of_possession(self: &TestValidator): vector<u8> {
    test_utils::bls_min_pk_sign(
        &validator_info::proof_of_possession_intent_bytes(0, self.sui_address, self.protocol_pubkey_bytes()),
        &self.protocol_key_bytes,
    )
}

public fun network_address(self: &TestValidator): String {
    self.network_address
}

public fun p2p_address(self: &TestValidator): String {
    self.p2p_address
}

public fun consensus_address(self: &TestValidator): String {
    self.consensus_address
}

public fun metadata(_self: &TestValidator): ValidatorMetadata {
    validator_metadata::default()
}

public fun stake_amount(self: &TestValidator): u64 {
    self.stake_amount.destroy_or!(DEFAULT_MIN_VALIDATOR_JOINING_STAKE)
}

public fun commission_rate(self: &TestValidator): u16 {
    self.commission_rate
}

/// Signs the message using the BLS secret key of the validator.
public fun sign_message(self: &TestValidator, msg: vector<u8>): vector<u8> {
    test_utils::bls_min_pk_sign(&msg, &self.protocol_key_bytes)
}

/// Returns a reference to the validator cap. Aborts if not set.
public fun cap(self: &TestValidator): &ValidatorCap {
    self.validator_cap.borrow()
}

/// Returns a mutable reference to the validator cap. Aborts if not set.
public fun cap_mut(self: &mut TestValidator): &mut ValidatorCap {
    self.validator_cap.borrow_mut()
}

/// Returns a reference to the validator operation cap. Aborts if not set.
public fun operation_cap(self: &TestValidator): &ValidatorOperationCap {
    self.validator_operation_cap.borrow()
}

/// Returns a reference to the validator operation cap. Aborts if not set.
public fun operation_cap_mut(self: &mut TestValidator): &mut ValidatorOperationCap {
    self.validator_operation_cap.borrow_mut()
}

/// Returns a reference to the validator commission cap. Aborts if not set.
public fun commission_cap(self: &TestValidator): &ValidatorCommissionCap {
    self.validator_commission_cap.borrow()
}

/// Returns a mutable reference to the validator commission cap. Aborts if not set.
public fun commission_cap_mut(self: &mut TestValidator): &mut ValidatorCommissionCap {
    self.validator_commission_cap.borrow_mut()
}

/// Returns the validator ID. Aborts if the validator cap is not set.
public fun validator_id(self: &TestValidator): ID {
    self.validator_cap.borrow().validator_id()
}

public fun sui_address(self: &TestValidator): address {
    self.sui_address
}

/// Sets the commission rate.
public fun set_commission_rate(self: &mut TestValidator, commission_rate: u16) {
    self.commission_rate = commission_rate;
}

/// Sets the validator cap, aborts if cap is already set.
public fun set_validator_cap(self: &mut TestValidator, cap: ValidatorCap) {
    self.validator_cap.fill(cap);
}

/// Sets the validator operation cap, aborts if cap is already set.
public fun set_validator_operation_cap(self: &mut TestValidator, cap: ValidatorOperationCap) {
    self.validator_operation_cap.fill(cap);
}

/// Sets the validator commission cap.
public fun set_validator_commission_cap(self: &mut TestValidator, cap: ValidatorCommissionCap) {
    self.validator_commission_cap.fill(cap);
}

/// Sets the stake amount, call before initialization.
public fun set_stake_amount(self: &mut TestValidator, stake_amount: Option<u64>) {
    self.stake_amount = stake_amount;
}

/// Returns a mutable reference to the staked IKA vector.
public fun staked_ika(self: &mut TestValidator): &mut vector<StakedIka> {
    &mut self.staked_ika
}

public fun destroy(self: TestValidator) {
    let TestValidator { validator_cap, validator_operation_cap, validator_commission_cap, staked_ika,.. } = self;
    validator_cap.destroy!(|cap| cap.destroy_validator_cap_for_testing());
    validator_operation_cap.destroy!(|cap| cap.destroy_validator_operation_cap_for_testing());
    validator_commission_cap.destroy!(|cap| cap.destroy_validator_commission_cap_for_testing());
    staked_ika.destroy!(|staked_ika| staked_ika.destroy_for_testing());
}

/// Returns a vector of `num_validators` test validators, with the secret keys from
/// `test_utils::bls_secret_keys_for_testing`.
///
/// For convenience and symmetry, validators should be sorted by their `sui_address`
/// represented as a `u256`. See `Committee` for sorting reference.
public fun test_validators(num_validators: u64): vector<TestValidator> {
    let mut sui_address: u256 = 0x0;
    test_utils::bls_secret_keys_for_testing(num_validators).map!(|protocol_key_bytes| {
        sui_address = sui_address + 1;
        TestValidator {
            sui_address: address::from_u256(sui_address),
            protocol_key_bytes,
            network_pubkey_bytes: address::from_u256(sui_address + 325431886811252).to_bytes(),
            consensus_pubkey_bytes: address::from_u256(sui_address + 698623709502389).to_bytes(),
            network_address: create_network_address(sui_address),
            p2p_address: create_p2p_address(sui_address),
            consensus_address: create_consensus_address(sui_address),
            commission_rate: 0,
            validator_cap: option::none(),
            validator_operation_cap: option::none(),
            validator_commission_cap: option::none(),
            stake_amount: option::none(),
            staked_ika: vector::empty(),
        }
    })
}

fun create_network_address(val: u256): String {
    let mut res = b"/ip4/127.0.0.1/tcp/80".to_string();
    res.append(val.to_string());
    res.append(b"/http".to_string());
    res
}

fun create_p2p_address(val: u256): String {
    let mut res = b"/ip4/127.0.0.1/udp/81".to_string();
    res.append(val.to_string());
    res
}

fun create_consensus_address(val: u256): String {
    let mut res = b"/ip4/127.0.0.1/udp/82".to_string();
    res.append(val.to_string());
    res
}

public fun sign(validators: &vector<TestValidator>, message: vector<u8>): (vector<u8>, vector<u8>) {
    let signatures = validators.map_ref!(|validator| validator.sign_message(message));
    let members_bitmap = test_utils::signers_to_bitmap(
        &vector::tabulate!(validators.length(), |i| i as u16),
    );
    let signature = test_utils::bls_aggregate_sigs(&signatures);

    (signature, members_bitmap)
}

