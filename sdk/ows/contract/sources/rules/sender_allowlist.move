// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Sender allowlist rule — only whitelisted addresses can sign.
///
/// Defense in depth on top of `PolicyAccessCap`. Even if an access cap
/// is transferred or compromised, only `ctx.sender()` addresses in the
/// allowlist can produce valid receipts.
///
/// # Usage
///
/// ```move
/// // Admin: register with allowed addresses
/// let allowed = vector[agent_addr_1, agent_addr_2];
/// sender_allowlist::add(&mut engine, &admin_cap, allowed);
///
/// // Agent: enforce during signing
/// let receipt = sender_allowlist::enforce(&engine, &request, ctx);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::sender_allowlist;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// Sender is not in the allowlist.
const ESenderNotAllowed: u64 = 0;

// === Structs ===

/// Rule witness type.
public struct SenderAllowlist has drop {}

/// Rule configuration.
public struct SenderAllowlistConfig has store, drop {
    /// Addresses allowed to produce signatures.
    allowed: vector<address>,
}

// === Admin Functions ===

/// Register the sender allowlist rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    allowed: vector<address>,
) {
    engine.add_rule(
        admin_cap,
        SenderAllowlist {},
        SenderAllowlistConfig { allowed },
    );
}

/// Remove the sender allowlist rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: SenderAllowlistConfig = engine.remove_rule<SenderAllowlist, SenderAllowlistConfig>(
        admin_cap,
    );
}

/// Replace the entire allowlist.
public fun set_allowed(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    allowed: vector<address>,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SenderAllowlist, SenderAllowlistConfig>(
        SenderAllowlist {},
    );
    config.allowed = allowed;
}

/// Add a single address to the allowlist.
public fun add_address(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    addr: address,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SenderAllowlist, SenderAllowlistConfig>(
        SenderAllowlist {},
    );
    if (!config.allowed.contains(&addr)) {
        config.allowed.push_back(addr);
    };
}

/// Remove a single address from the allowlist.
public fun remove_address(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    addr: address,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SenderAllowlist, SenderAllowlistConfig>(
        SenderAllowlist {},
    );
    let idx = config.allowed.find_index!(|a| *a == addr);
    if (idx.is_some()) {
        config.allowed.swap_remove(idx.destroy_some());
    };
}

// === Enforcement ===

/// Enforce the sender allowlist.
///
/// Aborts if `ctx.sender()` is not in the allowlist.
public fun enforce(
    engine: &PolicyEngine,
    request: &ApprovalRequest,
    ctx: &TxContext,
): PolicyReceipt<SenderAllowlist> {
    let config = engine.rule_config<SenderAllowlist, SenderAllowlistConfig>();
    assert!(config.allowed.contains(&ctx.sender()), ESenderNotAllowed);
    ika_ows_policy::policy_engine::new_receipt(SenderAllowlist {}, request)
}

// === View Functions ===

/// Borrow the allowlist config.
public fun config(engine: &PolicyEngine): &SenderAllowlistConfig {
    engine.rule_config<SenderAllowlist, SenderAllowlistConfig>()
}

/// The allowed addresses.
public fun allowed(self: &SenderAllowlistConfig): &vector<address> {
    &self.allowed
}

/// Check if an address is allowed.
public fun is_allowed(self: &SenderAllowlistConfig, addr: address): bool {
    self.allowed.contains(&addr)
}
