// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Allowed algorithms rule — restrict which (signature_algorithm, hash_scheme)
/// pairs an agent can use.
///
/// This effectively controls which chains the agent can sign for, since each
/// chain family requires a specific algorithm+hash combination:
///
/// | Chain Family | signature_algorithm | hash_scheme |
/// |-------------|--------------------:|------------:|
/// | EVM         | ECDSASecp256k1      | KECCAK256   |
/// | Bitcoin     | ECDSASecp256k1      | DoubleSHA256|
/// | Solana      | EdDSA               | SHA512      |
/// | Cosmos      | ECDSASecp256k1      | SHA256      |
///
/// # Usage
///
/// ```move
/// // Admin: only allow EVM signing (ECDSA+Keccak)
/// let pairs = vector[allowed_algorithms::new_pair(1, 3)];
/// allowed_algorithms::add(&mut engine, &admin_cap, pairs);
///
/// // Agent: enforce during signing
/// let receipt = allowed_algorithms::enforce(&engine, &request);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::allowed_algorithms;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// The (signature_algorithm, hash_scheme) pair is not in the allowed set.
const EAlgorithmNotAllowed: u64 = 0;

// === Structs ===

/// Rule witness type.
public struct AllowedAlgorithms has drop {}

/// An allowed (signature_algorithm, hash_scheme) pair.
public struct AllowedPair has copy, store, drop {
    signature_algorithm: u32,
    hash_scheme: u32,
}

/// Rule configuration.
public struct AllowedAlgorithmsConfig has store, drop {
    /// Allowed (signature_algorithm, hash_scheme) pairs.
    pairs: vector<AllowedPair>,
}

// === Constructors ===

/// Create an `AllowedPair`.
public fun new_pair(signature_algorithm: u32, hash_scheme: u32): AllowedPair {
    AllowedPair { signature_algorithm, hash_scheme }
}

// === Admin Functions ===

/// Register the allowed algorithms rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    pairs: vector<AllowedPair>,
) {
    engine.add_rule(
        admin_cap,
        AllowedAlgorithms {},
        AllowedAlgorithmsConfig { pairs },
    );
}

/// Remove the allowed algorithms rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: AllowedAlgorithmsConfig = engine.remove_rule<
        AllowedAlgorithms,
        AllowedAlgorithmsConfig,
    >(admin_cap);
}

/// Replace the entire set of allowed pairs.
public fun set_pairs(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    pairs: vector<AllowedPair>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<AllowedAlgorithms, AllowedAlgorithmsConfig>(
        AllowedAlgorithms {},
    );
    config.pairs = pairs;
}

/// Add a single allowed pair.
public fun add_pair(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    pair: AllowedPair,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<AllowedAlgorithms, AllowedAlgorithmsConfig>(
        AllowedAlgorithms {},
    );
    if (!contains_pair(&config.pairs, &pair)) {
        config.pairs.push_back(pair);
    };
}

/// Remove a single allowed pair.
public fun remove_pair(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    pair: AllowedPair,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<AllowedAlgorithms, AllowedAlgorithmsConfig>(
        AllowedAlgorithms {},
    );
    let idx = config.pairs.find_index!(|p| {
        p.signature_algorithm == pair.signature_algorithm
            && p.hash_scheme == pair.hash_scheme
    });
    if (idx.is_some()) {
        config.pairs.swap_remove(idx.destroy_some());
    };
}

// === Enforcement ===

/// Enforce the allowed algorithms rule.
///
/// Reads the request's `signature_algorithm` and `hash_scheme` and checks
/// them against the allowed pairs. Aborts if the combination is not allowed.
public fun enforce(
    engine: &PolicyEngine,
    request: &ApprovalRequest,
): PolicyReceipt<AllowedAlgorithms> {
    let config = engine.rule_config<AllowedAlgorithms, AllowedAlgorithmsConfig>();
    let target = AllowedPair {
        signature_algorithm: request.signature_algorithm(),
        hash_scheme: request.hash_scheme(),
    };
    assert!(contains_pair(&config.pairs, &target), EAlgorithmNotAllowed);
    ika_ows_policy::policy_engine::new_receipt(AllowedAlgorithms {}, request)
}

// === View Functions ===

/// Borrow the config.
public fun config(engine: &PolicyEngine): &AllowedAlgorithmsConfig {
    engine.rule_config<AllowedAlgorithms, AllowedAlgorithmsConfig>()
}

/// The allowed pairs.
public fun pairs(self: &AllowedAlgorithmsConfig): &vector<AllowedPair> {
    &self.pairs
}

/// Signature algorithm of a pair.
public fun pair_signature_algorithm(self: &AllowedPair): u32 {
    self.signature_algorithm
}

/// Hash scheme of a pair.
public fun pair_hash_scheme(self: &AllowedPair): u32 {
    self.hash_scheme
}

// === Internal ===

fun contains_pair(pairs: &vector<AllowedPair>, target: &AllowedPair): bool {
    pairs.any!(|p| {
        p.signature_algorithm == target.signature_algorithm
            && p.hash_scheme == target.hash_scheme
    })
}
