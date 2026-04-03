// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Spending budget rule — cumulative spending cap per time window.
///
/// The agent declares the value of each signing request. The contract
/// enforces a per-window cumulative budget and a per-transaction cap.
/// The agent cannot exceed the budget without lying — and if it lies,
/// the declared value + signed message are both on-chain as evidence.
///
/// This is a trust-minimized approach: the agent is already trusted to
/// construct valid transactions, so it's accountable for its declarations.
/// The spending rule creates a budget envelope the agent operates within.
///
/// # Usage
///
/// ```move
/// // Admin: max 1000 units per hour, max 100 per tx
/// spending_budget::add(&mut engine, &admin_cap, 1000, 100, 3_600_000, &clock);
///
/// // Agent: enforce with declared value
/// let receipt = spending_budget::enforce(&mut engine, &request, 50, &clock);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::spending_budget;

use sui::clock::Clock;

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// Transaction value exceeds the per-transaction cap.
const EExceedsPerTxCap: u64 = 0;
/// Cumulative spending would exceed the window budget.
const EExceedsBudget: u64 = 1;
/// Declared value must be greater than zero.
const EZeroValue: u64 = 2;

// === Structs ===

/// Rule witness type.
public struct SpendingBudget has drop {}

/// Rule configuration.
public struct SpendingBudgetConfig has store, drop {
    /// Max cumulative value per window (in abstract units — USD cents, wei, sats, etc.).
    /// The admin and agent agree on the unit off-chain.
    max_per_window: u64,
    /// Max value per single transaction. 0 = no per-tx limit (only window cap applies).
    max_per_tx: u64,
    /// Window duration in milliseconds.
    window_ms: u64,
    /// Cumulative value spent in the current window.
    window_spent: u64,
    /// Timestamp (ms) when the current window started.
    window_start_ms: u64,
}

/// On-chain record of a spending declaration. Emitted as an event for
/// accountability — if the agent lies about the value, the evidence is
/// on-chain alongside the signed message.
public struct SpendingDeclaration has copy, drop {
    /// Engine this declaration belongs to.
    engine_id: ID,
    /// Declared value of this transaction.
    declared_value: u64,
    /// Cumulative spending after this transaction.
    cumulative_spent: u64,
    /// Timestamp of the declaration.
    timestamp_ms: u64,
}

// === Admin Functions ===

/// Register the spending budget rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    max_per_window: u64,
    max_per_tx: u64,
    window_ms: u64,
    clock: &Clock,
) {
    engine.add_rule(
        admin_cap,
        SpendingBudget {},
        SpendingBudgetConfig {
            max_per_window,
            max_per_tx,
            window_ms,
            window_spent: 0,
            window_start_ms: clock.timestamp_ms(),
        },
    );
}

/// Remove the spending budget rule.
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let _: SpendingBudgetConfig = engine.remove_rule<SpendingBudget, SpendingBudgetConfig>(
        admin_cap,
    );
}

/// Update the per-window budget.
public fun set_max_per_window(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    max_per_window: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SpendingBudget, SpendingBudgetConfig>(
        SpendingBudget {},
    );
    config.max_per_window = max_per_window;
}

/// Update the per-transaction cap.
public fun set_max_per_tx(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    max_per_tx: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SpendingBudget, SpendingBudgetConfig>(
        SpendingBudget {},
    );
    config.max_per_tx = max_per_tx;
}

/// Update the window duration.
public fun set_window_ms(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    window_ms: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<SpendingBudget, SpendingBudgetConfig>(
        SpendingBudget {},
    );
    config.window_ms = window_ms;
}

// === Enforcement ===

/// Enforce the spending budget and produce a receipt.
///
/// The agent declares the value of this transaction. The contract checks:
/// 1. `declared_value > 0`
/// 2. `declared_value <= max_per_tx` (if max_per_tx > 0)
/// 3. `window_spent + declared_value <= max_per_window`
///
/// Emits a `SpendingDeclaration` event for on-chain accountability.
public fun enforce(
    engine: &mut PolicyEngine,
    request: &ApprovalRequest,
    declared_value: u64,
    clock: &Clock,
): PolicyReceipt<SpendingBudget> {
    assert!(declared_value > 0, EZeroValue);

    let config = engine.rule_config_mut<SpendingBudget, SpendingBudgetConfig>(
        SpendingBudget {},
    );

    // Reset on new window.
    let now = clock.timestamp_ms();
    if (now >= config.window_start_ms + config.window_ms) {
        config.window_spent = 0;
        config.window_start_ms = now;
    };

    // Per-tx cap.
    if (config.max_per_tx > 0) {
        assert!(declared_value <= config.max_per_tx, EExceedsPerTxCap);
    };

    // Window budget.
    assert!(
        config.window_spent + declared_value <= config.max_per_window,
        EExceedsBudget,
    );

    config.window_spent = config.window_spent + declared_value;

    // Emit accountability event.
    sui::event::emit(SpendingDeclaration {
        engine_id: request.engine_id(),
        declared_value,
        cumulative_spent: config.window_spent,
        timestamp_ms: now,
    });

    ika_ows_policy::policy_engine::new_receipt(SpendingBudget {}, request)
}

// === View Functions ===

/// Borrow the spending budget config.
public fun config(engine: &PolicyEngine): &SpendingBudgetConfig {
    engine.rule_config<SpendingBudget, SpendingBudgetConfig>()
}

/// Max cumulative value per window.
public fun max_per_window(self: &SpendingBudgetConfig): u64 {
    self.max_per_window
}

/// Max value per transaction.
public fun max_per_tx(self: &SpendingBudgetConfig): u64 {
    self.max_per_tx
}

/// Window duration in milliseconds.
public fun window_ms(self: &SpendingBudgetConfig): u64 {
    self.window_ms
}

/// Cumulative value spent in the current window.
public fun window_spent(self: &SpendingBudgetConfig): u64 {
    self.window_spent
}

/// Remaining budget in the current window.
public fun remaining(self: &SpendingBudgetConfig): u64 {
    if (self.window_spent >= self.max_per_window) {
        0
    } else {
        self.max_per_window - self.window_spent
    }
}

/// Timestamp when the current window started.
public fun window_start_ms(self: &SpendingBudgetConfig): u64 {
    self.window_start_ms
}
