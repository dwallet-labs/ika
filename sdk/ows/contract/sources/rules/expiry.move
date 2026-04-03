// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Expiry rule — signing permission expires at a given timestamp.
///
/// Useful for temporary agent delegations. Once the on-chain clock
/// passes `expiry_ms`, the rule blocks all signatures. No admin action
/// needed to revoke — it's automatic.
///
/// # Usage
///
/// ```move
/// // Admin: allow signing until 2025-06-01 00:00:00 UTC (ms timestamp)
/// expiry::add(&mut engine, &admin_cap, 1748736000000);
///
/// // Agent: enforce during signing
/// let receipt = expiry::enforce(&engine, &request, &clock);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::expiry;

use sui::clock::Clock;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// Signing permission has expired.
const EExpired: u64 = 0;

// === Structs ===

/// Rule witness type.
public struct Expiry has drop {}

/// Rule configuration.
public struct ExpiryConfig has store, drop {
    /// Timestamp in milliseconds after which signing is blocked.
    expiry_ms: u64,
}

// === Admin Functions ===

/// Register the expiry rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    expiry_ms: u64,
) {
    engine.add_rule(
        admin_cap,
        Expiry {},
        ExpiryConfig { expiry_ms },
    );
}

/// Remove the expiry rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: ExpiryConfig = engine.remove_rule<Expiry, ExpiryConfig>(admin_cap);
}

/// Update the expiry timestamp.
public fun set_expiry_ms(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    expiry_ms: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<Expiry, ExpiryConfig>(Expiry {});
    config.expiry_ms = expiry_ms;
}

// === Enforcement ===

/// Enforce the expiry rule.
///
/// Aborts if `clock.timestamp_ms() > expiry_ms`.
public fun enforce(
    engine: &PolicyEngine,
    request: &ApprovalRequest,
    clock: &Clock,
): PolicyReceipt<Expiry> {
    let config = engine.rule_config<Expiry, ExpiryConfig>();
    assert!(clock.timestamp_ms() <= config.expiry_ms, EExpired);
    ika_ows_policy::policy_engine::new_receipt(Expiry {}, request)
}

// === View Functions ===

/// Borrow the expiry config.
public fun config(engine: &PolicyEngine): &ExpiryConfig {
    engine.rule_config<Expiry, ExpiryConfig>()
}

/// The expiry timestamp in milliseconds.
public fun expiry_ms(self: &ExpiryConfig): u64 {
    self.expiry_ms
}

/// Whether the rule has expired at the given timestamp.
public fun is_expired(self: &ExpiryConfig, now_ms: u64): bool {
    now_ms > self.expiry_ms
}
