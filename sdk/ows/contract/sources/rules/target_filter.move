// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Target filter rule — restrict which addresses/contracts an agent can
/// interact with.
///
/// Supports two modes (can be combined):
/// - **Allowlist**: if non-empty, the declared target MUST be in the list.
/// - **Blocklist**: if non-empty, the declared target MUST NOT be in the list.
///
/// The agent declares the target address (as raw bytes) when enforcing.
/// The declaration is emitted as an on-chain event for accountability —
/// if the agent lies about the target, the evidence is on-chain alongside
/// the signed message.
///
/// Uses `vector<u8>` for target addresses to support any chain format:
/// - EVM: 20 bytes
/// - Solana: 32 bytes
/// - Bitcoin: 20-32 bytes (depending on address type)
/// - Sui: 32 bytes
///
/// # Usage
///
/// ```move
/// // Admin: only allow interactions with two EVM contracts
/// let allowed = vector[contract_a_bytes, contract_b_bytes];
/// target_filter::add(&mut engine, &admin_cap, allowed, vector[]);
///
/// // Agent: enforce with declared target
/// let receipt = target_filter::enforce(&mut engine, &request, target_bytes);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::target_filter;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// Target is not in the allowlist.
const ETargetNotAllowed: u64 = 0;
/// Target is in the blocklist.
const ETargetBlocked: u64 = 1;

// === Structs ===

/// Rule witness type.
public struct TargetFilter has drop {}

/// Rule configuration.
public struct TargetFilterConfig has store, drop {
    /// If non-empty, declared target must be in this list.
    allowed_targets: vector<vector<u8>>,
    /// If non-empty, declared target must NOT be in this list.
    blocked_targets: vector<vector<u8>>,
}

/// On-chain record of a target declaration. Emitted for accountability.
public struct TargetDeclaration has copy, drop {
    engine_id: ID,
    /// The declared target address (raw bytes).
    declared_target: vector<u8>,
}

// === Admin Functions ===

/// Register the target filter rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    allowed_targets: vector<vector<u8>>,
    blocked_targets: vector<vector<u8>>,
) {
    engine.add_rule(
        admin_cap,
        TargetFilter {},
        TargetFilterConfig { allowed_targets, blocked_targets },
    );
}

/// Remove the target filter rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: TargetFilterConfig = engine.remove_rule<TargetFilter, TargetFilterConfig>(
        admin_cap,
    );
}

/// Replace the allowlist.
public fun set_allowed_targets(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    allowed_targets: vector<vector<u8>>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    config.allowed_targets = allowed_targets;
}

/// Replace the blocklist.
public fun set_blocked_targets(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    blocked_targets: vector<vector<u8>>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    config.blocked_targets = blocked_targets;
}

/// Add a single target to the allowlist.
public fun allow_target(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    target: vector<u8>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    if (!contains(&config.allowed_targets, &target)) {
        config.allowed_targets.push_back(target);
    };
}

/// Remove a single target from the allowlist.
public fun disallow_target(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    target: vector<u8>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    let idx = config.allowed_targets.find_index!(|t| *t == target);
    if (idx.is_some()) {
        config.allowed_targets.swap_remove(idx.destroy_some());
    };
}

/// Add a single target to the blocklist.
public fun block_target(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    target: vector<u8>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    if (!contains(&config.blocked_targets, &target)) {
        config.blocked_targets.push_back(target);
    };
}

/// Remove a single target from the blocklist.
public fun unblock_target(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    target: vector<u8>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TargetFilter, TargetFilterConfig>(TargetFilter {});
    let idx = config.blocked_targets.find_index!(|t| *t == target);
    if (idx.is_some()) {
        config.blocked_targets.swap_remove(idx.destroy_some());
    };
}

// === Enforcement ===

/// Enforce the target filter and produce a receipt.
///
/// The agent declares the target address of this transaction. The contract:
/// 1. If allowlist is non-empty, asserts the target is in the allowlist.
/// 2. If blocklist is non-empty, asserts the target is NOT in the blocklist.
///
/// Emits a `TargetDeclaration` event for on-chain accountability.
public fun enforce(
    engine: &PolicyEngine,
    request: &ApprovalRequest,
    declared_target: vector<u8>,
): PolicyReceipt<TargetFilter> {
    let config = engine.rule_config<TargetFilter, TargetFilterConfig>();

    // Allowlist check.
    if (!config.allowed_targets.is_empty()) {
        assert!(contains(&config.allowed_targets, &declared_target), ETargetNotAllowed);
    };

    // Blocklist check.
    if (!config.blocked_targets.is_empty()) {
        assert!(!contains(&config.blocked_targets, &declared_target), ETargetBlocked);
    };

    sui::event::emit(TargetDeclaration {
        engine_id: request.engine_id(),
        declared_target,
    });

    ika_ows_policy::policy_engine::new_receipt(TargetFilter {}, request)
}

// === View Functions ===

/// Borrow the target filter config.
public fun config(engine: &PolicyEngine): &TargetFilterConfig {
    engine.rule_config<TargetFilter, TargetFilterConfig>()
}

/// The allowed targets.
public fun allowed_targets(self: &TargetFilterConfig): &vector<vector<u8>> {
    &self.allowed_targets
}

/// The blocked targets.
public fun blocked_targets(self: &TargetFilterConfig): &vector<vector<u8>> {
    &self.blocked_targets
}

/// Check if a target is allowed (passes both allowlist and blocklist).
public fun is_target_permitted(self: &TargetFilterConfig, target: &vector<u8>): bool {
    if (!self.allowed_targets.is_empty() && !contains(&self.allowed_targets, target)) {
        return false
    };
    if (!self.blocked_targets.is_empty() && contains(&self.blocked_targets, target)) {
        return false
    };
    true
}

// === Internal ===

fun contains(list: &vector<vector<u8>>, target: &vector<u8>): bool {
    list.any!(|entry| entry == target)
}
