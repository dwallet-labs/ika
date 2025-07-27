// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_dwallet_2pc_mpc::coordinator;

use ika::ika::IKA;
use ika_common::advance_epoch_approver::AdvanceEpochApprover;
use ika_common::protocol_cap::VerifiedProtocolCap;
use ika_common::system_current_status_info::SystemCurrentStatusInfo;
use ika_common::validator_cap::VerifiedValidatorOperationCap;
use ika_dwallet_2pc_mpc::coordinator_inner::{
    Self,
    DWalletCap,
    DWalletCoordinatorInner,
    ImportedKeyDWalletCap,
    ImportedKeyMessageApproval,
    MessageApproval,
    UnverifiedPartialUserSignatureCap,
    UnverifiedPresignCap,
    VerifiedPartialUserSignatureCap,
    VerifiedPresignCap
};
use ika_dwallet_2pc_mpc::pricing::PricingInfo;
use ika_dwallet_2pc_mpc::sessions_manager::SessionIdentifier;
use sui::coin::Coin;
use sui::dynamic_field;
use sui::sui::SUI;
use sui::vec_map::VecMap;
use ika_common::upgrade_package_approver::UpgradePackageApprover;

// === Errors ===

/// The inner version is incorrect.
const EWrongInnerVersion: u64 = 0;
/// The migration is invalid.
const EInvalidMigration: u64 = 1;

// === Constants ===
/// Flag to indicate the version of the ika system.
const VERSION: u64 = 1;

// === Structs ===

public struct DWalletCoordinator has key {
    id: UID,
    version: u64,
    package_id: ID,
    new_package_id: Option<ID>,
    migration_epoch: Option<u64>,
}

// === Functions that can only be called by init ===

/// Create a new System object and make it shared.
/// This function will be called only once in init.
public(package) fun create(
    package_id: ID,
    advance_epoch_approver: &mut AdvanceEpochApprover,
    system_current_status_info: &SystemCurrentStatusInfo,
    pricing: PricingInfo,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    ctx: &mut TxContext,
) {
    let dwallet_coordinator_inner = coordinator_inner::create(
        advance_epoch_approver,
        system_current_status_info,
        pricing,
        supported_curves_to_signature_algorithms_to_hash_schemes,
        ctx,
    );
    let mut self = DWalletCoordinator {
        id: object::new(ctx),
        version: VERSION,
        package_id,
        new_package_id: option::none(),
        migration_epoch: option::none(),
    };
    dynamic_field::add(&mut self.id, VERSION, dwallet_coordinator_inner);
    transfer::share_object(self);
}

// === Public Functions ===

/// Being called by the Ika network to store outputs of completed MPC sessions to Sui.
public fun process_checkpoint_message_by_quorum(
    dwallet_2pc_mpc_coordinator: &mut DWalletCoordinator,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    message: vector<u8>,
    ctx: &mut TxContext,
): Coin<SUI> {
    let dwallet_inner = dwallet_2pc_mpc_coordinator.inner_mut();
    dwallet_inner.process_checkpoint_message_by_quorum(signature, signers_bitmap, message, ctx)
}

public fun initiate_mid_epoch_reconfiguration(
    self: &mut DWalletCoordinator,
    system_current_status_info: &SystemCurrentStatusInfo,
) {
    self.inner_mut().initiate_mid_epoch_reconfiguration(system_current_status_info);
}

public fun request_network_encryption_key_mid_epoch_reconfiguration(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_network_encryption_key_mid_epoch_reconfiguration(
            dwallet_network_encryption_key_id,
            ctx,
        );
}

public fun advance_epoch(
    self: &mut DWalletCoordinator,
    advance_epoch_approver: &mut AdvanceEpochApprover,
) {
    self.inner_mut().advance_epoch(advance_epoch_approver);
}

public fun request_dwallet_network_encryption_key_dkg_by_cap(
    self: &mut DWalletCoordinator,
    params_for_network: vector<u8>,
    cap: &VerifiedProtocolCap,
    ctx: &mut TxContext,
) {
    self.inner_mut().request_dwallet_network_encryption_key_dkg(params_for_network, cap, ctx);
}

public fun process_checkpoint_message_by_cap(
    self: &mut DWalletCoordinator,
    message: vector<u8>,
    cap: &VerifiedProtocolCap,
    ctx: &mut TxContext,
): Coin<SUI> {
    self.inner_mut().process_checkpoint_message_by_cap(message, cap, ctx)
}

public fun set_gas_fee_reimbursement_sui_system_call_value_by_cap(
    self: &mut DWalletCoordinator,
    gas_fee_reimbursement_sui_system_call_value: u64,
    cap: &VerifiedProtocolCap,
) {
    self.inner_mut().set_gas_fee_reimbursement_sui_system_call_value_by_cap(gas_fee_reimbursement_sui_system_call_value, cap);
}

public fun set_supported_and_pricing(
    self: &mut DWalletCoordinator,
    default_pricing: PricingInfo,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    cap: &VerifiedProtocolCap,
) {
    self
        .inner_mut()
        .set_supported_and_pricing(
            default_pricing,
            supported_curves_to_signature_algorithms_to_hash_schemes,
            cap,
        );
}

public fun set_paused_curves_and_signature_algorithms(
    self: &mut DWalletCoordinator,
    paused_curves: vector<u32>,
    paused_signature_algorithms: vector<u32>,
    paused_hash_schemes: vector<u32>,
    cap: &VerifiedProtocolCap,
) {
    self
        .inner_mut()
        .set_paused_curves_and_signature_algorithms(
            paused_curves,
            paused_signature_algorithms,
            paused_hash_schemes,
            cap,
        );
}

public fun request_lock_epoch_sessions(
    self: &mut DWalletCoordinator,
    system_current_status_info: &SystemCurrentStatusInfo,
) {
    self.inner_mut().request_lock_epoch_sessions(system_current_status_info);
}

public fun set_pricing_vote(
    self: &mut DWalletCoordinator,
    pricing: PricingInfo,
    cap: &VerifiedValidatorOperationCap,
) {
    self.inner_mut().set_pricing_vote(pricing, cap);
}

public fun register_session_identifier(
    self: &mut DWalletCoordinator,
    identifier: vector<u8>,
    ctx: &mut TxContext,
): SessionIdentifier {
    self.inner_mut().register_session_identifier(identifier, ctx)
}

public fun get_active_encryption_key(self: &DWalletCoordinator, address: address): ID {
    self.inner().get_active_encryption_key(address)
}

public fun register_encryption_key(
    self: &mut DWalletCoordinator,
    curve: u32,
    encryption_key: vector<u8>,
    encryption_key_signature: vector<u8>,
    signer_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .register_encryption_key(
            curve,
            encryption_key,
            encryption_key_signature,
            signer_public_key,
            ctx,
        )
}

public fun approve_message(
    self: &mut DWalletCoordinator,
    dwallet_cap: &DWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
): MessageApproval {
    self
        .inner()
        .approve_message(
            dwallet_cap,
            signature_algorithm,
            hash_scheme,
            message,
        )
}

public fun approve_imported_key_message(
    self: &mut DWalletCoordinator,
    imported_key_dwallet_cap: &ImportedKeyDWalletCap,
    signature_algorithm: u32,
    hash_scheme: u32,
    message: vector<u8>,
): ImportedKeyMessageApproval {
    self
        .inner()
        .approve_imported_key_message(
            imported_key_dwallet_cap,
            signature_algorithm,
            hash_scheme,
            message,
        )
}

public fun request_dwallet_dkg_first_round(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): DWalletCap {
    self
        .inner_mut()
        .request_dwallet_dkg_first_round(
            dwallet_network_encryption_key_id,
            curve,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_dwallet_dkg_second_round(
    self: &mut DWalletCoordinator,
    dwallet_cap: &DWalletCap,
    centralized_public_key_share_and_proof: vector<u8>,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    encryption_key_address: address,
    user_public_output: vector<u8>,
    singer_public_key: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_dwallet_dkg_second_round(
            dwallet_cap,
            centralized_public_key_share_and_proof,
            encrypted_centralized_secret_share_and_proof,
            encryption_key_address,
            user_public_output,
            singer_public_key,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun calculate_pricing_votes(
    self: &mut DWalletCoordinator,
    curve: u32,
    signature_algorithm: Option<u32>,
    protocol: u32,
) {
    self.inner_mut().calculate_pricing_votes(curve, signature_algorithm, protocol);
}

public fun request_imported_key_dwallet_verification(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    centralized_party_message: vector<u8>,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    encryption_key_address: address,
    user_public_output: vector<u8>,
    signer_public_key: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): ImportedKeyDWalletCap {
    self
        .inner_mut()
        .request_imported_key_dwallet_verification(
            dwallet_network_encryption_key_id,
            curve,
            centralized_party_message,
            encrypted_centralized_secret_share_and_proof,
            encryption_key_address,
            user_public_output,
            signer_public_key,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_make_dwallet_user_secret_key_shares_public(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    public_user_secret_key_shares: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_make_dwallet_user_secret_key_share_public(
            dwallet_id,
            public_user_secret_key_shares,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_re_encrypt_user_share_for(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    destination_encryption_key_address: address,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    source_encrypted_user_secret_key_share_id: ID,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_re_encrypt_user_share_for(
            dwallet_id,
            destination_encryption_key_address,
            encrypted_centralized_secret_share_and_proof,
            source_encrypted_user_secret_key_share_id,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun accept_encrypted_user_share(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    encrypted_user_secret_key_share_id: ID,
    user_output_signature: vector<u8>,
) {
    self
        .inner_mut()
        .accept_encrypted_user_share(
            dwallet_id,
            encrypted_user_secret_key_share_id,
            user_output_signature,
        )
}

public fun request_presign(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    signature_algorithm: u32,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPresignCap {
    self
        .inner_mut()
        .request_presign(
            dwallet_id,
            signature_algorithm,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_global_presign(
    self: &mut DWalletCoordinator,
    dwallet_network_encryption_key_id: ID,
    curve: u32,
    signature_algorithm: u32,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPresignCap {
    self
        .inner_mut()
        .request_global_presign(
            dwallet_network_encryption_key_id,
            curve,
            signature_algorithm,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun is_presign_valid(self: &DWalletCoordinator, presign_cap: &UnverifiedPresignCap): bool {
    self
        .inner()
        .is_presign_valid(
            presign_cap,
        )
}

public fun verify_presign_cap(
    self: &mut DWalletCoordinator,
    cap: UnverifiedPresignCap,
    ctx: &mut TxContext,
): VerifiedPresignCap {
    self.inner_mut().verify_presign_cap(cap, ctx)
}

public fun request_sign(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    message_approval: MessageApproval,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_sign(
            message_approval,
            presign_cap,
            message_centralized_signature,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_imported_key_sign(
    self: &mut DWalletCoordinator,
    presign_cap: VerifiedPresignCap,
    message_approval: ImportedKeyMessageApproval,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_imported_key_sign(
            message_approval,
            presign_cap,
            message_centralized_signature,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_future_sign(
    self: &mut DWalletCoordinator,
    dwallet_id: ID,
    presign_cap: VerifiedPresignCap,
    message: vector<u8>,
    hash_scheme: u32,
    message_centralized_signature: vector<u8>,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
): UnverifiedPartialUserSignatureCap {
    self
        .inner_mut()
        .request_future_sign(
            dwallet_id,
            presign_cap,
            message,
            hash_scheme,
            message_centralized_signature,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun is_partial_user_signature_valid(
    self: &DWalletCoordinator,
    cap: &UnverifiedPartialUserSignatureCap,
): bool {
    self.inner().is_partial_user_signature_valid(cap)
}

public fun verify_partial_user_signature_cap(
    self: &mut DWalletCoordinator,
    cap: UnverifiedPartialUserSignatureCap,
    ctx: &mut TxContext,
): VerifiedPartialUserSignatureCap {
    self
        .inner_mut()
        .verify_partial_user_signature_cap(
            cap,
            ctx,
        )
}

public fun request_sign_with_partial_user_signature(
    self: &mut DWalletCoordinator,
    partial_user_signature_cap: VerifiedPartialUserSignatureCap,
    message_approval: MessageApproval,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_sign_with_partial_user_signature(
            partial_user_signature_cap,
            message_approval,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun request_imported_key_sign_with_partial_user_signature(
    self: &mut DWalletCoordinator,
    partial_user_signature_cap: VerifiedPartialUserSignatureCap,
    message_approval: ImportedKeyMessageApproval,
    session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    ctx: &mut TxContext,
) {
    self
        .inner_mut()
        .request_imported_key_sign_with_partial_user_signature(
            partial_user_signature_cap,
            message_approval,
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        )
}

public fun match_partial_user_signature_with_message_approval(
    self: &DWalletCoordinator,
    partial_user_signature_cap: &VerifiedPartialUserSignatureCap,
    message_approval: &MessageApproval,
): bool {
    self
        .inner()
        .match_partial_user_signature_with_message_approval(
            partial_user_signature_cap,
            message_approval,
        )
}

public fun match_partial_user_signature_with_imported_key_message_approval(
    self: &DWalletCoordinator,
    partial_user_signature_cap: &VerifiedPartialUserSignatureCap,
    message_approval: &ImportedKeyMessageApproval,
): bool {
    self
        .inner()
        .match_partial_user_signature_with_imported_key_message_approval(
            partial_user_signature_cap,
            message_approval,
        )
}

public fun current_pricing(self: &DWalletCoordinator): PricingInfo {
    self.inner().current_pricing()
}

/// Fund the coordinator with SUI - this let you subsidize the protocol.
/// IMPORTANT: YOU WON'T BE ABLE TO WITHDRAW THE FUNDS OR GET ANYTHING IN RETURN.
public fun subsidize_coordinator_with_sui(self: &mut DWalletCoordinator, sui: Coin<SUI>) {
    self.inner_mut().subsidize_coordinator_with_sui(sui);
}

/// Fund the coordinator with IKA - this let you subsidize the protocol.
/// IMPORTANT: YOU WON'T BE ABLE TO WITHDRAW THE FUNDS OR GET ANYTHING IN RETURN.
public fun subsidize_coordinator_with_ika(self: &mut DWalletCoordinator, ika: Coin<IKA>) {
    self.inner_mut().subsidize_coordinator_with_ika(ika);
}

public fun commit_upgrade(self: &mut DWalletCoordinator, upgrade_package_approver: &mut UpgradePackageApprover) {
    let new_package_id = upgrade_package_approver.approve_upgrade_package_by_witness(coordinator_inner::dwallet_coordinator_witness());
    if (self.package_id == upgrade_package_approver.old_package_id()) {
        self.migration_epoch = option::some(upgrade_package_approver.migration_epoch());
        self.new_package_id = option::some(new_package_id);
    };
}

/// Try to migrate the coordinator object to the new package id using a cap.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `coordinator_inner` object if needed.
/// This function can be called immediately after the upgrade is committed.
public fun try_migrate_by_cap(self: &mut DWalletCoordinator, _: &VerifiedProtocolCap) {
    assert!(self.version < VERSION, EInvalidMigration);
    assert!(self.new_package_id.is_some(), EInvalidMigration);
    self.try_migrate_impl();
}

/// Try to migrate the coordinator object to the new package id.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `coordinator_inner` object if needed.
/// Call this function after the migration epoch is reached.
public fun try_migrate(self: &mut DWalletCoordinator) {
    assert!(self.version < VERSION, EInvalidMigration);
    assert!(self.new_package_id.is_some(), EInvalidMigration);
    assert!(self.migration_epoch.is_some_and!(|e| self.inner_without_version_check().epoch() >= *e), EInvalidMigration);
    self.try_migrate_impl();
}

/// Migrate the coordinator object to the new package id.
///
/// This function sets the new package id and version and can be modified in future versions
/// to migrate changes in the `coordinator_inner` object if needed.
fun try_migrate_impl(self: &mut DWalletCoordinator) {
    // Move the old coordinator inner to the new version.
    let coordinator_inner: DWalletCoordinatorInner = dynamic_field::remove(&mut self.id, self.version);
    dynamic_field::add(&mut self.id, VERSION, coordinator_inner);
    self.version = VERSION;

    self.package_id = self.new_package_id.extract();
    // empty the migration epoch
    if (self.migration_epoch.is_some()) {
        let _ = self.migration_epoch.extract();
    };
}

public fun version(self: &DWalletCoordinator): u64 {
    self.version
}

// === Internals ===

/// Get a mutable reference to `DWalletCoordinatorInnerVX` from the `DWalletCoordinator`.
public(package) fun inner_mut(self: &mut DWalletCoordinator): &mut DWalletCoordinatorInner {
    assert!(self.version == VERSION, EWrongInnerVersion);
    dynamic_field::borrow_mut(&mut self.id, VERSION)
}

/// Get an immutable reference to `DWalletCoordinatorVX` from the `DWalletCoordinator`.
public(package) fun inner(self: &DWalletCoordinator): &DWalletCoordinatorInner {
    assert!(self.version == VERSION, EWrongInnerVersion);
    dynamic_field::borrow(&self.id, VERSION)
}

/// Get an immutable reference to `DWalletCoordinatorInner` from the `DWalletCoordinator` without checking the version.
fun inner_without_version_check(self: &DWalletCoordinator): &DWalletCoordinatorInner {
    dynamic_field::borrow(&self.id, self.version)
}

// === Test Functions ===
#[test_only]
use ika_dwallet_2pc_mpc::sessions_manager::SessionsManager;

#[test_only]
public fun last_processed_checkpoint_sequence_number(self: &DWalletCoordinator): u64 {
    self.inner().last_processed_checkpoint_sequence_number()
}

#[test_only]
public fun sessions_manager(self: &DWalletCoordinator): &SessionsManager {
    self.inner().sessions_manager()
}
