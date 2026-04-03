// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// OWS Policy Engine — composable, on-chain policy enforcement for dWallets.
///
/// Uses a Sui TransferPolicy-style composable rule system. The `DWalletCap`
/// (or `ImportedKeyDWalletCap`) is custodied inside a `PolicyEngine` shared
/// object. The agent cannot call `approve_message` directly — it must go
/// through the engine, which requires proof that every registered policy
/// rule has been satisfied.
///
/// # Composable Rules
///
/// Policy rules are registered by type. Each rule module defines:
/// - A witness type `T` with `drop` ability
/// - A config type `Config` with `store + drop` abilities
/// - An `enforce` function that checks conditions and produces `PolicyReceipt<T>`
///
/// The admin registers rules via `add_rule<T, Config>`. To approve a message:
/// 1. Agent calls `engine.create_request(...)` → gets `ApprovalRequest` (no `drop`)
/// 2. Agent calls each rule's `enforce` → gets `PolicyReceipt<T>` per rule
/// 3. Agent calls `request.add_receipt(receipt)` for each receipt
/// 4. Agent calls `engine.confirm_dkg(coordinator, request)` → gets approval
///    (only succeeds if ALL registered rules have matching receipts)
///
/// Only the module that defines `T` can create `PolicyReceipt<T>` (witness
/// pattern), so rules are unskippable.
///
/// # Capabilities
///
/// - `PolicyAdminCap` — wallet owner. Add/remove rules, pause, grant access.
/// - `PolicyAccessCap` — agent. Can create approval requests.
///
/// # Built-in: Emergency Pause
///
/// The engine has a built-in pause flag (admin-only kill switch). When
/// paused, `create_request` and `confirm_*` both abort. This is not a
/// composable rule — it's an absolute override.
module ika_ows_policy::policy_engine;

use std::type_name::{TypeName};
use sui::bag::{Self, Bag};
use sui::dynamic_object_field;
use sui::vec_set::{Self, VecSet};

use ika_dwallet_2pc_mpc::{
    coordinator::DWalletCoordinator,
    coordinator_inner::{
        DWalletCap,
        ImportedKeyDWalletCap,
        MessageApproval,
        ImportedKeyMessageApproval,
    },
};

// === Errors ===

const EInvalidAccessCap: u64 = 0;
const EPaused: u64 = 1;
const EInvalidAdminCap: u64 = 2;
const EMismatchedRequest: u64 = 3;
const EMissingReceipts: u64 = 4;
const EMismatchedReceipt: u64 = 5;

// === Events ===

public struct PolicyEngineCreatedEvent has copy, drop {
    engine_id: ID,
    admin_cap_id: ID,
}

public struct PolicyAccessGrantedEvent has copy, drop {
    engine_id: ID,
    access_cap_id: ID,
    recipient: address,
}

// === Dynamic Object Field Keys ===

/// Key for storing a `DWalletCap` as a dynamic object field.
public struct DkgCapKey has copy, drop, store {}
/// Key for storing an `ImportedKeyDWalletCap` as a dynamic object field.
public struct ImportedKeyCapKey has copy, drop, store {}

// === Core Structs ===

/// The policy engine. Shared on-chain.
///
/// Custodies a `DWalletCap` or `ImportedKeyDWalletCap` via dynamic object
/// field. Stores registered rule types and their configs.
public struct PolicyEngine has key {
    id: UID,
    /// Registered rule types that must be satisfied for every approval.
    rules: VecSet<TypeName>,
    /// Rule configuration storage. Keyed by `TypeName`, stores each rule's
    /// `Config` value. Managed via `add_rule` / `remove_rule`.
    rule_configs: Bag,
    /// Admin cap ID — validates admin operations.
    admin_cap_id: ID,
    /// Emergency pause. When true, all approvals abort.
    paused: bool,
}

/// Super capability — held by the wallet owner.
public struct PolicyAdminCap has key, store {
    id: UID,
    /// ID of the `PolicyEngine` this cap controls.
    engine_id: ID,
}

/// Access capability — held by agents.
public struct PolicyAccessCap has key, store {
    id: UID,
    /// ID of the `PolicyEngine` this cap grants access to.
    engine_id: ID,
}

/// A request to approve a message. Does NOT have `drop` — must be consumed
/// via `confirm_dkg`, `confirm_imported_key`, or `cancel`.
///
/// Collects `PolicyReceipt<T>` from each registered rule. The `confirm_*`
/// functions assert all receipts are present before issuing an approval.
public struct ApprovalRequest {
    /// Engine this request belongs to.
    engine_id: ID,
    /// Signing parameters.
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
    /// Collected receipts (by type name).
    receipts: VecSet<TypeName>,
}

/// Proof that rule `T` has been satisfied for a specific request.
/// Only the module that defines `T` can create this (witness pattern).
/// Has `drop` — can be discarded if not needed.
public struct PolicyReceipt<phantom T: drop> has drop {
    engine_id: ID,
}

// === Engine Creation ===

/// Create a policy engine that custodies a DKG `DWalletCap`.
///
/// The `DWalletCap` is stored as a dynamic object field on the engine.
/// Returns `PolicyAdminCap` to the caller (wallet owner).
public fun create_with_dkg_cap(
    cap: DWalletCap,
    ctx: &mut TxContext,
): PolicyAdminCap {
    let (mut engine, admin_cap) = create_engine_internal(ctx);
    dynamic_object_field::add(&mut engine.id, DkgCapKey {}, cap);
    transfer::share_object(engine);
    admin_cap
}

/// Create a policy engine that custodies an `ImportedKeyDWalletCap`.
public fun create_with_imported_key_cap(
    cap: ImportedKeyDWalletCap,
    ctx: &mut TxContext,
): PolicyAdminCap {
    let (mut engine, admin_cap) = create_engine_internal(ctx);
    dynamic_object_field::add(&mut engine.id, ImportedKeyCapKey {}, cap);
    transfer::share_object(engine);
    admin_cap
}

// === Rule Management ===

/// Register a composable rule.
///
/// `T` is the rule's witness type (must have `drop`). `Config` is the rule's
/// configuration, stored in the engine. Only the module defining `T` can
/// create instances of `T`, so only it can produce `PolicyReceipt<T>`.
public fun add_rule<T: drop, Config: store>(
    self: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
    _witness: T,
    config: Config,
) {
    self.assert_admin(admin_cap);
    let rule_type = std::type_name::with_defining_ids<T>();
    self.rules.insert(rule_type);
    self.rule_configs.add(rule_type, config);
}

/// Remove a registered rule and return its config.
///
/// All rules must be removed before the engine can be destroyed.
public fun remove_rule<T: drop, Config: store>(
    self: &mut PolicyEngine,
    admin_cap: &PolicyAdminCap,
): Config {
    self.assert_admin(admin_cap);
    let rule_type = std::type_name::with_defining_ids<T>();
    self.rules.remove(&rule_type);
    self.rule_configs.remove(rule_type)
}

/// Check if a rule type is registered.
public fun has_rule<T: drop>(self: &PolicyEngine): bool {
    self.rules.contains(&std::type_name::with_defining_ids<T>())
}

/// Borrow a rule's config (immutable).
public fun rule_config<T: drop, Config: store>(
    self: &PolicyEngine,
): &Config {
    self.rule_configs.borrow(std::type_name::with_defining_ids<T>())
}

/// Borrow a rule's config (mutable). Requires the rule's witness to prove
/// the caller is the defining module.
///
/// Used by rule modules in their `enforce` function to update state
/// (e.g., incrementing a rate limit counter).
public fun rule_config_mut<T: drop, Config: store>(
    self: &mut PolicyEngine,
    _witness: T,
): &mut Config {
    self.rule_configs.borrow_mut(std::type_name::with_defining_ids<T>())
}

// === Request Lifecycle ===

/// Create an approval request.
///
/// Aborts if the engine is paused or the access cap is invalid.
/// The returned `ApprovalRequest` has no `drop` — it must be consumed
/// via `confirm_*` or `cancel`.
public fun create_request(
    self: &PolicyEngine,
    access_cap: &PolicyAccessCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
): ApprovalRequest {
    assert!(!self.paused, EPaused);
    assert!(access_cap.engine_id == object::id(self), EInvalidAccessCap);

    ApprovalRequest {
        engine_id: object::id(self),
        signature_algorithm,
        hash_scheme,
        message,
        receipts: vec_set::empty(),
    }
}

/// Create a `PolicyReceipt<T>` proving that rule `T` has been satisfied.
///
/// Only callable by the module that defines `T` (witness pattern).
/// Rule modules call this at the end of their `enforce` function after
/// checking their conditions.
public fun new_receipt<T: drop>(
    _witness: T,
    request: &ApprovalRequest,
): PolicyReceipt<T> {
    PolicyReceipt { engine_id: request.engine_id }
}

/// Add a receipt to an approval request.
///
/// Each registered rule type must have exactly one receipt added before
/// the request can be confirmed.
public fun add_receipt<T: drop>(
    self: &mut ApprovalRequest,
    receipt: PolicyReceipt<T>,
) {
    assert!(receipt.engine_id == self.engine_id, EMismatchedReceipt);
    self.receipts.insert(std::type_name::with_defining_ids<T>());
}

/// Confirm a request and produce a `MessageApproval` for a DKG dWallet.
///
/// Asserts:
/// 1. Engine is not paused.
/// 2. Request belongs to this engine.
/// 3. All registered rules have matching receipts.
///
/// Then calls `coordinator.approve_message` with the custodied `DWalletCap`.
public fun confirm_dkg(
    self: &PolicyEngine,
    coordinator: &mut DWalletCoordinator,
    request: ApprovalRequest,
): MessageApproval {
    let ApprovalRequest {
        engine_id,
        signature_algorithm,
        hash_scheme,
        message,
        receipts,
    } = request;

    assert!(engine_id == object::id(self), EMismatchedRequest);
    assert!(!self.paused, EPaused);
    assert_receipts_complete(&self.rules, &receipts);

    let cap: &DWalletCap = dynamic_object_field::borrow(&self.id, DkgCapKey {});
    coordinator.approve_message(cap, signature_algorithm, hash_scheme, message)
}

/// Confirm a request and produce an `ImportedKeyMessageApproval`.
public fun confirm_imported_key(
    self: &PolicyEngine,
    coordinator: &mut DWalletCoordinator,
    request: ApprovalRequest,
): ImportedKeyMessageApproval {
    let ApprovalRequest {
        engine_id,
        signature_algorithm,
        hash_scheme,
        message,
        receipts,
    } = request;

    assert!(engine_id == object::id(self), EMismatchedRequest);
    assert!(!self.paused, EPaused);
    assert_receipts_complete(&self.rules, &receipts);

    let cap: &ImportedKeyDWalletCap = dynamic_object_field::borrow(
        &self.id,
        ImportedKeyCapKey {},
    );
    coordinator.approve_imported_key_message(
        cap,
        signature_algorithm,
        hash_scheme,
        message,
    )
}

/// Cancel a request without producing an approval.
/// Consumes the `ApprovalRequest` (which has no `drop`).
public fun cancel(request: ApprovalRequest) {
    let ApprovalRequest {
        engine_id: _,
        signature_algorithm: _,
        hash_scheme: _,
        message: _,
        receipts: _,
    } = request;
}

// === Request Accessors ===

/// Engine ID the request belongs to.
public fun engine_id(self: &ApprovalRequest): ID {
    self.engine_id
}

/// Signature algorithm requested.
public fun signature_algorithm(self: &ApprovalRequest): u32 {
    self.signature_algorithm
}

/// Hash scheme requested.
public fun hash_scheme(self: &ApprovalRequest): u32 {
    self.hash_scheme
}

/// Raw message bytes to be signed.
public fun message(self: &ApprovalRequest): &vector<u8> {
    &self.message
}

// === Admin: Pause ===

/// Pause the engine. All `create_request` and `confirm_*` calls will abort.
public fun pause(self: &mut PolicyEngine, admin_cap: &PolicyAdminCap) {
    self.assert_admin(admin_cap);
    self.paused = true;
}

/// Unpause the engine.
public fun unpause(self: &mut PolicyEngine, admin_cap: &PolicyAdminCap) {
    self.assert_admin(admin_cap);
    self.paused = false;
}

// === Admin: Access Cap Management ===

/// Grant a new `PolicyAccessCap` for this engine.
public fun grant_access(
    self: &PolicyEngine,
    admin_cap: &PolicyAdminCap,
    ctx: &mut TxContext,
): PolicyAccessCap {
    self.assert_admin(admin_cap);
    let access_cap = PolicyAccessCap {
        id: object::new(ctx),
        engine_id: object::id(self),
    };

    sui::event::emit(PolicyAccessGrantedEvent {
        engine_id: object::id(self),
        access_cap_id: object::id(&access_cap),
        recipient: ctx.sender(),
    });

    access_cap
}

/// Revoke a `PolicyAccessCap` by destroying it.
public fun revoke_access(access_cap: PolicyAccessCap) {
    let PolicyAccessCap { id, engine_id: _ } = access_cap;
    id.delete();
}

// === Admin: Engine Destruction ===

/// Destroy the engine and reclaim the custodied DKG `DWalletCap`.
///
/// All rules must be removed first (bag must be empty).
public fun destroy_and_reclaim_dkg_cap(
    mut self: PolicyEngine,
    admin_cap: PolicyAdminCap,
): DWalletCap {
    self.assert_admin(&admin_cap);

    let cap: DWalletCap = dynamic_object_field::remove(&mut self.id, DkgCapKey {});
    destroy_engine(self, admin_cap);
    cap
}

/// Destroy the engine and reclaim the custodied `ImportedKeyDWalletCap`.
///
/// All rules must be removed first (bag must be empty).
public fun destroy_and_reclaim_imported_key_cap(
    mut self: PolicyEngine,
    admin_cap: PolicyAdminCap,
): ImportedKeyDWalletCap {
    self.assert_admin(&admin_cap);

    let cap: ImportedKeyDWalletCap = dynamic_object_field::remove(
        &mut self.id,
        ImportedKeyCapKey {},
    );
    destroy_engine(self, admin_cap);
    cap
}

// === View Functions ===

/// Whether the engine is currently paused.
public fun is_paused(self: &PolicyEngine): bool {
    self.paused
}

/// Number of registered rules.
public fun rules_count(self: &PolicyEngine): u64 {
    self.rules.length()
}

/// The engine ID that an access cap is bound to.
public fun access_cap_engine_id(self: &PolicyAccessCap): ID {
    self.engine_id
}

/// The engine ID that an admin cap is bound to.
public fun admin_cap_engine_id(self: &PolicyAdminCap): ID {
    self.engine_id
}

// === Internal ===

fun create_engine_internal(ctx: &mut TxContext): (PolicyEngine, PolicyAdminCap) {
    let admin_cap_uid = object::new(ctx);
    let admin_cap_id = admin_cap_uid.to_inner();

    let engine = PolicyEngine {
        id: object::new(ctx),
        rules: vec_set::empty(),
        rule_configs: bag::new(ctx),
        admin_cap_id,
        paused: false,
    };

    let engine_id = object::id(&engine);

    let admin_cap = PolicyAdminCap {
        id: admin_cap_uid,
        engine_id,
    };

    sui::event::emit(PolicyEngineCreatedEvent {
        engine_id,
        admin_cap_id,
    });

    (engine, admin_cap)
}

fun destroy_engine(engine: PolicyEngine, admin_cap: PolicyAdminCap) {
    let PolicyEngine {
        id,
        rules: _,
        rule_configs,
        admin_cap_id: _,
        paused: _,
    } = engine;
    rule_configs.destroy_empty();
    id.delete();

    let PolicyAdminCap { id: admin_id, engine_id: _ } = admin_cap;
    admin_id.delete();
}

fun assert_admin(self: &PolicyEngine, admin_cap: &PolicyAdminCap) {
    assert!(object::id(admin_cap) == self.admin_cap_id, EInvalidAdminCap);
}

fun assert_receipts_complete(
    rules: &VecSet<TypeName>,
    receipts: &VecSet<TypeName>,
) {
    assert!(rules.length() == receipts.length(), EMissingReceipts);
    let required = rules.keys();
    let mut i = 0;
    while (i < required.length()) {
        assert!(receipts.contains(&required[i]), EMissingReceipts);
        i = i + 1;
    };
}
