// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Common test utilities for the tests.
module ika_system::test_utils;

use std::string::String;
use sui::{
    balance::{Self, Balance},
    bls12381::{Self, bls12381_min_pk_verify, g1_to_uncompressed_g1},
    coin::{Self, Coin, TreasuryCap},
    sui::SUI,
};
use ika::ika::IKA;
use ika_system::{
    ika_test_context::{Self, IkaTestContext},
    bls_committee,
    validator_metadata::{Self, ValidatorMetadata},
    system_inner::SystemInner,
    validator::{Self, Validator},
    validator_info,
    mpc_data,
    validator_cap::{ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap},
    dwallet_pricing::{Self, DWalletPricing},
};
use sui::address::from_u256;

/// Debug macro for pretty printing values.
/// The value must have a `.to_string()` method.
public macro fun dbg<$T: drop>($note: vector<u8>, $value: $T) {
    use std::debug::print;
    let note = $note;
    let value = $value;
    print(&note.to_string());
    print(&value)
}

/// Helper macro to assert equality of two values. Both values must be copyable
/// and have a `.to_string()` method.
public macro fun assert_eq<$T: copy>($left: $T, $right: $T) {
    let left = $left;
    let right = $right;
    if (left != right) {
        let mut str = b"assertion failed: ".to_string();
        str.append(left.to_string());
        str.append(b" != ".to_string());
        str.append(right.to_string());
        std::debug::print(&str);
        assert!(false);
    }
}

// === Coins and Context ===


public fun itctx(epoch: u64, committee_selected: bool): IkaTestContext {
    ika_test_context::new(epoch, committee_selected, bls_committee::empty())
}

public fun ika_treasury_for_testing(ctx: &mut TxContext): TreasuryCap<IKA> {
    coin::create_treasury_cap_for_testing(ctx)
}

/// Mints `amount` denominated in `INKU`.
public fun mint_inku(amount: u64, ctx: &mut TxContext): Coin<IKA> {
    coin::mint_for_testing(amount, ctx)
}

/// Mints `amount` denominated in `INKU` as balance.
public fun mint_inku_balance(amount: u64): Balance<IKA> {
    balance::create_for_testing(amount)
}

/// Mints `amount` denominated in `IKA`.
public fun mint_ika(amount: u64, ctx: &mut TxContext): Coin<IKA> {
    mint_inku(amount * 1_000_000_000, ctx)
}

/// Mints `amount` denominated in `IKA` as balance.
public fun mint_ika_balance(amount: u64): Balance<IKA> {
    mint_inku_balance(amount * 1_000_000_000)
}

/// Mints `amount` denominated in `SUI`.
public fun mint_sui(amount: u64, ctx: &mut TxContext): Coin<SUI> {
    coin::mint_for_testing(amount * 1_000_000_000, ctx)
}

/// Mints `amount` denominated in `SUI` as balance.
public fun mint_sui_balance(amount: u64): Balance<SUI> {
    balance::create_for_testing(amount * 1_000_000_000)
}

// === Context Runner ===

public struct ContextRunner has drop {
    epoch: u64,
    ctx: TxContext,
    committee_selected: bool,
}

/// Creates a new context runner with default values.
public fun context_runner(): ContextRunner {
    ContextRunner {
        epoch: 0,
        ctx: tx_context::dummy(),
        committee_selected: false,
    }
}

public fun epoch(self: &ContextRunner): u64 { self.epoch }

public fun is_committee_selected(self: &ContextRunner): bool { self.committee_selected }

/// Returns the current context and the transaction context.
public fun current(self: &mut ContextRunner): (IkaTestContext, &mut TxContext) {
    (itctx(self.epoch, self.committee_selected), &mut self.ctx)
}

/// Selects committee.
public fun select_committee(self: &mut ContextRunner): (IkaTestContext, &mut TxContext) {
    self.committee_selected = true;
    (itctx(self.epoch, self.committee_selected), &mut self.ctx)
}

/// Advances the epoch by one.
public fun next_epoch(self: &mut ContextRunner): (IkaTestContext, &mut TxContext) {
    self.committee_selected = false;
    self.epoch = self.epoch + 1;
    (itctx(self.epoch, self.committee_selected), &mut self.ctx)
}

/// Macro to run `next_epoch` in a lambda.
public macro fun next_epoch_tx($self: &mut ContextRunner, $f: |&IkaTestContext, &mut TxContext|) {
    let (itctx, ctx) = next_epoch($self);
    $f(&itctx, ctx)
}

// === Validator Builder ===

/// Struct to support building a validator in tests with variable parameters.
public struct ValidatorBuilder has copy, drop {
    name: Option<String>,
    protocol_key_bytes: Option<vector<u8>>,
    network_pubkey_bytes: Option<vector<u8>>,
    consensus_pubkey_bytes: Option<vector<u8>>,
    mpc_data_bytes: Option<vector<u8>>,
    network_address: Option<String>,
    p2p_address: Option<String>,
    consensus_address: Option<String>,
    commission_rate: Option<u16>,
    metadata: Option<ValidatorMetadata>,

}

/// Test Utility: Creates a new `ValidatorBuilder` with default values.
///
/// ```rust
/// // Example usage:
/// let validator_a = validator().commission_rate(1000).build(&itctx, ctx);
/// let validator_b = validator().p2p_address(b"0.0.0.0".to_string()).build(&itctx, ctx);
/// let validator_c = validator()
///     .name(b"my node".to_string())
///     .network_address(b"0.0.0.0".to_string())
///     .protocol_key_bytes(x"75")
///     .network_pubkey_bytes(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab")
///     .commission_rate(1000)
///     .build(&itctx, ctx);
/// ```
public fun validator(): ValidatorBuilder {
    ValidatorBuilder {
        name: option::none(),
        protocol_key_bytes: option::none(),
        network_pubkey_bytes: option::none(),
        consensus_pubkey_bytes: option::none(),
        mpc_data_bytes: option::none(),
        network_address: option::none(),
        p2p_address: option::none(),
        consensus_address: option::none(),
        metadata: option::none(),
        commission_rate: option::none(),
    }
}


/// Sets the name for the validator.
public fun name(mut self: ValidatorBuilder, name: String): ValidatorBuilder {
    self.name.fill(name);
    self
}


/// Sets the protocol key for the validator.
public fun protocol_key_bytes(mut self: ValidatorBuilder, protocol_key_bytes: vector<u8>): ValidatorBuilder {
    self.protocol_key_bytes.fill(protocol_key_bytes);
    self
}

/// Sets the network public key for the validator.
public fun network_pubkey_bytes(mut self: ValidatorBuilder, network_pubkey_bytes: vector<u8>): ValidatorBuilder {
    self.network_pubkey_bytes.fill(network_pubkey_bytes);
    self
}

/// Sets the consensus public key for the validator.
public fun consensus_pubkey_bytes(mut self: ValidatorBuilder, consensus_pubkey_bytes: vector<u8>): ValidatorBuilder {
    self.consensus_pubkey_bytes.fill(consensus_pubkey_bytes);
    self
}

/// Sets the MPC public data for the validator.
public fun mpc_data_bytes(mut self: ValidatorBuilder, mpc_data_bytes: vector<u8>): ValidatorBuilder {
    self.mpc_data_bytes.fill(mpc_data_bytes);
    self
}

/// Sets the network address for the validator.
public fun network_address(mut self: ValidatorBuilder, network_address: String): ValidatorBuilder {
    self.network_address.fill(network_address);
    self
}

/// Sets the p2p address for the validator.
public fun p2p_address(mut self: ValidatorBuilder, p2p_address: String): ValidatorBuilder {
    self.p2p_address.fill(p2p_address);
    self
}

/// Sets the consensus address for the validator.
public fun consensus_address(mut self: ValidatorBuilder, consensus_address: String): ValidatorBuilder {
    self.consensus_address.fill(consensus_address);
    self
}

/// Sets the metadata for the validator.
public fun metadata(mut self: ValidatorBuilder, metadata: ValidatorMetadata): ValidatorBuilder {
    self.metadata.fill(metadata);
    self
}

/// Sets the commission rate for the validator.
public fun commission_rate(mut self: ValidatorBuilder, commission_rate: u16): ValidatorBuilder {
    self.commission_rate.fill(commission_rate);
    self
}

/// Builds a validator with the parameters set in the builder.
public fun build(self: ValidatorBuilder, itctx: &IkaTestContext, ctx: &mut TxContext): (Validator, ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap) {
    let ValidatorBuilder {
        name,
        protocol_key_bytes,
        network_pubkey_bytes,
        consensus_pubkey_bytes,
        mpc_data_bytes,
        network_address,
        p2p_address,
        consensus_address,
        metadata,
        commission_rate,
    } = self;

    let protocol_key_bytes = protocol_key_bytes.destroy_with_default(bls_sk_for_testing());
    let protocol_pubkey_bytes = bls_min_pk_from_sk(&protocol_key_bytes);
    let proof_of_possession_bytes = bls_min_pk_sign(
        &validator_info::proof_of_possession_intent_bytes(itctx.epoch(), ctx.sender(), protocol_pubkey_bytes),
        &protocol_key_bytes,
    );

    let mpc_data_bytes = mpc_data_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab");

    let mut mpc_data = mpc_data::empty(ctx);
    mpc_data.add_public_key_and_proof(mpc_data_bytes, mpc_data_bytes);

    validator::new(
        itctx.epoch(),
        name.destroy_with_default(b"pool".to_string()),
        protocol_pubkey_bytes,
        network_pubkey_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab"),
        consensus_pubkey_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab"),
        mpc_data.finish(ctx),
        proof_of_possession_bytes,
        network_address.destroy_with_default(b"/ip4/127.0.0.1/tcp/8080/http".to_string()),
        p2p_address.destroy_with_default(b"/ip4/127.0.0.1/udp/8084".to_string()),
        consensus_address.destroy_with_default(b"/ip4/127.0.0.1/udp/8081".to_string()),
        commission_rate.destroy_with_default(0),
        metadata.destroy_with_default(validator_metadata::default()),
        ctx,
    )
}

/// Similar to `build` but registers the validator with the staking inner, using the
/// same set of parameters.
public fun register(self: ValidatorBuilder, inner: &mut SystemInner, ctx: &mut TxContext): (ValidatorCap, ValidatorOperationCap, ValidatorCommissionCap) {
    let ValidatorBuilder {
        name,
        metadata,
        protocol_key_bytes,
        network_pubkey_bytes,
        consensus_pubkey_bytes,
        mpc_data_bytes,
        network_address,
        p2p_address,
        consensus_address,
        commission_rate,
    } = self;
    let protocol_key_bytes = protocol_key_bytes.destroy_with_default(bls_sk_for_testing());
    let protocol_pubkey_bytes = bls_min_pk_from_sk(&protocol_key_bytes);
    let proof_of_possession_bytes = bls_min_pk_sign(
        &validator_info::proof_of_possession_intent_bytes(inner.epoch(), ctx.sender(), protocol_pubkey_bytes),
        &protocol_key_bytes,
    );

    let mpc_data_bytes = mpc_data_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab");

    let mut mpc_data = mpc_data::empty(ctx);
    mpc_data.add_public_key_and_proof(mpc_data_bytes, mpc_data_bytes);

    inner.request_add_validator_candidate(
        name.destroy_with_default(b"pool".to_string()),
        protocol_pubkey_bytes,
        network_pubkey_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab"),
        consensus_pubkey_bytes.destroy_with_default(x"0e2b273530a00de66c9727c40f48be985da684286983f398ef7695b8a44677ab"),
        mpc_data.finish(ctx),
        proof_of_possession_bytes,
        network_address.destroy_with_default(b"/ip4/127.0.0.1/tcp/8080/http".to_string()),
        p2p_address.destroy_with_default(b"/ip4/127.0.0.1/udp/8084".to_string()),
        consensus_address.destroy_with_default(b"/ip4/127.0.0.1/udp/8081".to_string()),
        commission_rate.destroy_with_default(0),
        metadata.destroy_with_default(validator_metadata::default()),
        ctx,
    )
}

// === BLS Helpers ===

public fun bls_min_pk_sign(msg: &vector<u8>, sk: &vector<u8>): vector<u8> {
    let sk_element = bls12381::scalar_from_bytes(sk);
    let hashed_msg = bls12381::hash_to_g2(msg);
    let sig = bls12381::g2_mul(&sk_element, &hashed_msg);
    *sig.bytes()
}

public fun bls_min_pk_from_sk(sk: &vector<u8>): vector<u8> {
    let sk_element = bls12381::scalar_from_bytes(sk);
    let g1 = bls12381::g1_generator();
    let pk = bls12381::g1_mul(&sk_element, &g1);
    *pk.bytes()
}

// Prepends the key with zeros to get 32 bytes.
public fun pad_bls_sk(sk: &vector<u8>): vector<u8> {
    let mut sk = *sk;
    if (sk.length() < 32) {
        // Prepend with zeros to get 32 bytes.
        sk.reverse();
        (32 - sk.length()).do!(|_| sk.push_back(0));
        sk.reverse();
    };
    sk
}

/// Returns the secret key scalar 117.
public fun bls_sk_for_testing(): vector<u8> {
    pad_bls_sk(&x"75")
}

/// Returns `num_keys` bls secret keys.
public fun bls_secret_keys_for_testing(num_keys: u64): vector<vector<u8>> {
    let mut res = vector[];
    num_keys.do!(|i| {
        let sk = bls12381::scalar_from_u64(1 + (i as u64));
        res.push_back(*sk.bytes());
    });
    res
}

/// Aggregates the given signatures into one signature.
public fun bls_aggregate_sigs(signatures: &vector<vector<u8>>): vector<u8> {
    let mut aggregate = bls12381::g2_identity();
    signatures.do_ref!(
        |sig| aggregate = bls12381::g2_add(&aggregate, &bls12381::g2_from_bytes(sig)),
    );
    *aggregate.bytes()
}

/// Test committee with one committee member and 100 shards, using
/// `test_utils::bls_sk_for_testing()` as secret key.
public fun new_bls_committee_for_testing(): bls_committee::BlsCommittee {
    let validator_id = tx_context::dummy().fresh_object_address().to_id();
    let sk = bls_sk_for_testing();
    let pub_key = bls12381::g1_from_bytes(&bls_min_pk_from_sk(&sk));
    let member = bls_committee::new_bls_committee_member(
        validator_id,
        g1_to_uncompressed_g1(&pub_key),
    );
    bls_committee::new_bls_committee(vector[member])
}

/// Test committee with 10 committee member and 100 shards, using
/// `test_utils::bls_sk_for_testing()` as secret key.
public fun new_bls_committee_with_multiple_members_for_testing(
    num_members: u64,
    tx_context: &mut TxContext,
): bls_committee::BlsCommittee {
    let keys = bls_secret_keys_for_testing(num_members);
    let members = keys.map!(|sk| {
        let pub_key = bls12381::g1_from_bytes(&bls_min_pk_from_sk(&sk));
        let validator_id = tx_context.fresh_object_address().to_id();
        bls_committee::new_bls_committee_member(validator_id, g1_to_uncompressed_g1(&pub_key))
    });
    bls_committee::new_bls_committee(members)
}

/// Converts a vector of signers to a bitmap.
/// The set of signers MUST be signed.
public fun signers_to_bitmap(signers: &vector<u16>): vector<u8> {
    let mut bitmap: vector<u8> = vector[];
    let mut next_byte = 0;
    signers.do_ref!(|signer| {
        let signer = *signer as u64;
        let byte = signer / 8;
        if (byte > bitmap.length()) {
            bitmap.push_back(next_byte);
            next_byte = 0;
        };
        let bit = (signer % 8) as u8;
        next_byte = next_byte | (1 << bit);
    });
    bitmap.push_back(next_byte);
    bitmap
}

// === Pricing Helpers ===

public fun create_pricing_for_default_protocols(
    value: u64,
): DWalletPricing {
    let mut pricing = dwallet_pricing::empty();
    pricing.insert_or_update_dwallet_pricing(0, option::none(), 0, value, value, value,value);
    pricing.insert_or_update_dwallet_pricing(0, option::none(), 1, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::none(), 2, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::none(), 3, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::none(), 4, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::some(0), 5, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::some(0), 6, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::some(0), 7, value, value, value, value);
    pricing.insert_or_update_dwallet_pricing(0, option::some(0), 8, value, value, value, value);
    pricing
}

// === Unit Tests ===

#[test]
fun test_bls_pk() {
    let sk = bls_sk_for_testing();
    let pub_key_bytes =
        x"95eacc3adc09c827593f581e8e2de068bf4cf5d0c0eb29e5372f0d23364788ee0f9beb112c8a7e9c2f0c720433705cf0";
    assert!(bls_min_pk_from_sk(&sk) == pub_key_bytes)
}

#[test]
fun test_bls_sign() {
    let sk = bls_sk_for_testing();
    let pub_key_bytes = bls_min_pk_from_sk(&sk);
    let msg = x"deadbeef";
    let sig = bls_min_pk_sign(&msg, &sk);

    assert!(
        bls12381_min_pk_verify(
            &sig,
            &pub_key_bytes,
            &msg,
        ),
    );
}
