// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Time delay rule — commit-reveal with owner review window.
///
/// For high-value operations where the wallet owner wants a veto window.
/// The agent commits the message hash first, waits a configurable delay
/// (in milliseconds), then reveals and signs. During the delay, the owner
/// can pause the engine or revoke the specific commitment.
///
/// This is the most trust-minimized spending control — no oracle, no
/// value declaration, just a time window for the owner to review and
/// intervene.
///
/// # Flow
///
/// 1. Agent calls `commit(engine, access_cap, message_hash, clock)`
/// 2. Agent waits `delay_ms` milliseconds
/// 3. Agent calls `enforce(engine, request, clock)` → verifies delay
///    has passed and message matches commitment → produces receipt
///
/// During the delay, the owner can:
/// - `engine.pause(admin_cap)` — block all signatures
/// - `revoke_commitment(engine, admin_cap, message_hash)` — cancel one
///
/// # Usage
///
/// ```move
/// // Admin: register with 1-hour delay (3_600_000 ms)
/// time_delay::add(&mut engine, &admin_cap, 3_600_000, ctx);
///
/// // Agent: commit
/// time_delay::commit(&mut engine, &access_cap, message_hash, &clock);
///
/// // Agent (1 hour later): enforce
/// let receipt = time_delay::enforce(&mut engine, &request, &clock);
/// request.add_receipt(receipt);
/// ```
module ika_ows_policy::time_delay;

use sui::clock::Clock;
use sui::table::{Self, Table};

use ika_ows_policy::policy_engine::{
    PolicyEngine,
    PolicyAdminCap,
    PolicyAccessCap,
    ApprovalRequest,
    PolicyReceipt,
};

// === Errors ===

/// No commitment found for this message.
const ENoCommitment: u64 = 0;
/// Delay period has not elapsed yet.
const EDelayNotElapsed: u64 = 1;
/// Commitment already exists for this message hash.
const ECommitmentExists: u64 = 2;
/// Invalid access cap for this engine.
const EInvalidAccessCap: u64 = 3;

// === Structs ===

/// Rule witness type.
public struct TimeDelay has drop {}

/// Rule configuration.
///
/// Uses `Table` for commitments, so this config only has `store` (no `drop`).
/// The `remove` function must drain the table before removing the rule.
public struct TimeDelayConfig has store {
    /// Delay duration in milliseconds between commit and reveal.
    delay_ms: u64,
    /// Pending commitments: message_hash → commit timestamp (ms).
    commitments: Table<vector<u8>, u64>,
}

/// Event emitted when a commitment is made.
public struct CommitmentCreated has copy, drop {
    engine_id: ID,
    message_hash: vector<u8>,
    commit_ms: u64,
    release_ms: u64,
}

/// Event emitted when a commitment is consumed (signing proceeds).
public struct CommitmentConsumed has copy, drop {
    engine_id: ID,
    message_hash: vector<u8>,
    consumed_ms: u64,
}

/// Event emitted when a commitment is revoked by admin.
public struct CommitmentRevoked has copy, drop {
    engine_id: ID,
    message_hash: vector<u8>,
    revoked_ms: u64,
}

// === Admin Functions ===

/// Register the time delay rule.
public fun add(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    delay_ms: u64,
    ctx: &mut TxContext,
) {
    engine.add_rule(
        admin_cap,
        TimeDelay {},
        TimeDelayConfig {
            delay_ms,
            commitments: table::new(ctx),
        },
    );
}

/// Remove the time delay rule.
///
/// The commitments table must be empty (all commitments consumed or revoked).
public fun remove(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
) {
    let config: TimeDelayConfig = engine.remove_rule<TimeDelay, TimeDelayConfig>(admin_cap);
    let TimeDelayConfig { delay_ms: _, commitments } = config;
    commitments.destroy_empty();
}

/// Update the delay duration. Only affects future commitments.
public fun set_delay_ms(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    delay_ms: u64,
) {
    assert!(admin_cap.admin_cap_engine_id() == object::id(engine), 0);
    let config = engine.rule_config_mut<TimeDelay, TimeDelayConfig>(TimeDelay {});
    config.delay_ms = delay_ms;
}

/// Revoke a specific commitment. The agent will not be able to sign
/// this message even after the delay.
public fun revoke_commitment(
    engine: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    message_hash: vector<u8>,
    clock: &Clock,
) {
    let engine_id = object::id(engine);
    assert!(admin_cap.admin_cap_engine_id() == engine_id, 0);

    let config = engine.rule_config_mut<TimeDelay, TimeDelayConfig>(TimeDelay {});
    config.commitments.remove(message_hash);

    sui::event::emit(CommitmentRevoked {
        engine_id,
        message_hash,
        revoked_ms: clock.timestamp_ms(),
    });
}

// === Agent Functions ===

/// Commit a message hash. The agent must wait `delay_ms` before
/// it can produce a receipt for this message.
///
/// The `message_hash` should be `blake2b256(message)` — the agent
/// computes this off-chain before committing.
public fun commit(
    engine: &mut PolicyEngine,
    access_cap: &PolicyAccessCap,
    message_hash: vector<u8>,
    clock: &Clock,
) {
    let engine_id = object::id(engine);
    assert!(access_cap.access_cap_engine_id() == engine_id, EInvalidAccessCap);

    let config = engine.rule_config_mut<TimeDelay, TimeDelayConfig>(TimeDelay {});
    assert!(!config.commitments.contains(message_hash), ECommitmentExists);

    let commit_ms = clock.timestamp_ms();
    let release_ms = commit_ms + config.delay_ms;
    config.commitments.add(message_hash, commit_ms);

    sui::event::emit(CommitmentCreated {
        engine_id,
        message_hash,
        commit_ms,
        release_ms,
    });
}

// === Enforcement ===

/// Enforce the time delay rule.
///
/// Verifies:
/// 1. A commitment exists for the blake2b256 hash of the request message.
/// 2. At least `delay_ms` milliseconds have passed since the commitment.
///
/// Consumes the commitment (single-use).
public fun enforce(
    engine: &mut PolicyEngine,
    request: &ApprovalRequest,
    clock: &Clock,
): PolicyReceipt<TimeDelay> {
    let message = request.message();
    let message_hash = sui::hash::blake2b256(message);

    let config = engine.rule_config_mut<TimeDelay, TimeDelayConfig>(TimeDelay {});

    assert!(config.commitments.contains(message_hash), ENoCommitment);
    let commit_ms = config.commitments.remove(message_hash);

    let now = clock.timestamp_ms();
    assert!(now >= commit_ms + config.delay_ms, EDelayNotElapsed);

    sui::event::emit(CommitmentConsumed {
        engine_id: request.engine_id(),
        message_hash,
        consumed_ms: now,
    });

    ika_ows_policy::policy_engine::new_receipt(TimeDelay {}, request)
}

// === View Functions ===

/// Borrow the time delay config.
public fun config(engine: &PolicyEngine): &TimeDelayConfig {
    engine.rule_config<TimeDelay, TimeDelayConfig>()
}

/// The delay duration in milliseconds.
public fun delay_ms(self: &TimeDelayConfig): u64 {
    self.delay_ms
}

/// Whether a commitment exists for a message hash.
public fun has_commitment(self: &TimeDelayConfig, message_hash: vector<u8>): bool {
    self.commitments.contains(message_hash)
}

/// The timestamp (ms) a commitment was made (aborts if not found).
public fun commitment_ms(self: &TimeDelayConfig, message_hash: vector<u8>): u64 {
    *self.commitments.borrow(message_hash)
}
