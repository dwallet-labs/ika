// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Rate limit rule — time-window based signature rate limiting.
///
/// Limits the number of signatures within a configurable time window
/// (in milliseconds). The counter resets when the window elapses.
///
/// # Usage
///
/// ```move
/// // Admin: max 100 signatures per hour (3_600_000 ms)
/// rate_limit::add(&mut engine, &admin_cap, 100, 3_600_000, &clock);
///
/// // Agent: enforce during signing
/// let receipt = rate_limit::enforce(&mut engine, &request, &clock);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::rate_limit;

use sui::clock::Clock;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// Rate limit exceeded for this window.
const ERateLimitExceeded: u64 = 0;

// === Structs ===

/// Rule witness type.
public struct RateLimit has drop {}

/// Rule configuration.
public struct RateLimitConfig has store, drop {
    /// Max signatures per time window.
    max_per_window: u64,
    /// Window duration in milliseconds.
    window_ms: u64,
    /// Signature count in the current window.
    window_count: u64,
    /// Timestamp (ms) when the current window started.
    window_start_ms: u64,
}

// === Admin Functions ===

/// Register the rate limit rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    max_per_window: u64,
    window_ms: u64,
    clock: &Clock,
) {
    engine.add_rule(
        admin_cap,
        RateLimit {},
        RateLimitConfig {
            max_per_window,
            window_ms,
            window_count: 0,
            window_start_ms: clock.timestamp_ms(),
        },
    );
}

/// Remove the rate limit rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: RateLimitConfig = engine.remove_rule<RateLimit, RateLimitConfig>(admin_cap);
}

/// Update the max signatures per window.
public fun set_max_per_window(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    max_per_window: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<RateLimit, RateLimitConfig>(RateLimit {});
    config.max_per_window = max_per_window;
}

/// Update the window duration.
public fun set_window_ms(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    window_ms: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<RateLimit, RateLimitConfig>(RateLimit {});
    config.window_ms = window_ms;
}

// === Enforcement ===

/// Enforce the rate limit and produce a receipt.
///
/// Resets the counter when the current window has elapsed.
/// Aborts if the limit is exceeded within the current window.
public fun enforce(
    engine: &mut PolicyEngine,
    request: &ApprovalRequest,
    clock: &Clock,
): PolicyReceipt<RateLimit> {
    let config = engine.rule_config_mut<RateLimit, RateLimitConfig>(RateLimit {});

    let now = clock.timestamp_ms();
    if (now >= config.window_start_ms + config.window_ms) {
        config.window_count = 0;
        config.window_start_ms = now;
    };

    if (config.max_per_window > 0) {
        assert!(config.window_count < config.max_per_window, ERateLimitExceeded);
    };

    config.window_count = config.window_count + 1;

    ika_ows_policy::policy_engine::new_receipt(RateLimit {}, request)
}

// === View Functions ===

/// Borrow the rate limit config.
public fun config(engine: &PolicyEngine): &RateLimitConfig {
    engine.rule_config<RateLimit, RateLimitConfig>()
}

/// Max signatures per window.
public fun max_per_window(self: &RateLimitConfig): u64 {
    self.max_per_window
}

/// Window duration in milliseconds.
public fun window_ms(self: &RateLimitConfig): u64 {
    self.window_ms
}

/// Signature count in the current window.
public fun window_count(self: &RateLimitConfig): u64 {
    self.window_count
}

/// Timestamp when the current window started.
public fun window_start_ms(self: &RateLimitConfig): u64 {
    self.window_start_ms
}
