// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_dwallet_2pc_mpc::ika_dwallet_2pc_mpc_init;

use ika_common::advance_epoch_approver::AdvanceEpochApprover;
use ika_common::system_current_status_info::SystemCurrentStatusInfo;
use ika_dwallet_2pc_mpc::coordinator;
use ika_dwallet_2pc_mpc::ika_dwallet_2pc_mpc_display;
use ika_dwallet_2pc_mpc::pricing::PricingInfo;
use std::string::String;
use std::type_name;
use sui::address;
use sui::package::{Self, Publisher};
use sui::vec_map::VecMap;

// === Structs ===
/// The OTW to create `Publisher` and `Display` objects.
public struct IKA_DWALLET_2PC_MPC_INIT has drop {}

/// Must only be created by `init`.
public struct InitCap has key, store {
    id: UID,
    publisher: Publisher,
}

// === Module Initializer ===

/// Init function, creates an init cap and transfers it to the sender.
/// This allows the sender to call the function to actually initialize the system
/// with the corresponding parameters. Once that function is called, the cap is destroyed.
fun init(otw: IKA_DWALLET_2PC_MPC_INIT, ctx: &mut TxContext) {
    let id = object::new(ctx);
    let publisher = package::claim(otw, ctx);
    let init_cap = InitCap { id, publisher };
    transfer::transfer(init_cap, ctx.sender());
}

// === Public Functions ===

/// Function to initialize ika and share the system object.
/// This can only be called once, after which the `InitCap` is destroyed.
public fun initialize(
    init_cap: InitCap,
    advance_epoch_approver: &mut AdvanceEpochApprover,
    system_current_status_info: &SystemCurrentStatusInfo,
    pricing: PricingInfo,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    dwallet_cap_image_url: String,
    imported_key_dwallet_cap_image_url: String,
    unverified_presign_cap_image_url: String,
    verified_presign_cap_image_url: String,
    unverified_partial_user_signature_cap_image_url: String,
    verified_partial_user_signature_cap_image_url: String,
    ctx: &mut TxContext,
) {
    let InitCap { id, publisher } = init_cap;
    id.delete();

    let package_id_string = type_name::get<InitCap>().get_address().into_bytes();
    let package_id = address::from_ascii_bytes(&package_id_string).to_id();

    coordinator::create(
        package_id,
        advance_epoch_approver,
        system_current_status_info,
        pricing,
        supported_curves_to_signature_algorithms_to_hash_schemes,
        ctx,
    );

    ika_dwallet_2pc_mpc_display::create(
        publisher,
        dwallet_cap_image_url,
        imported_key_dwallet_cap_image_url,
        unverified_presign_cap_image_url,
        verified_presign_cap_image_url,
        unverified_partial_user_signature_cap_image_url,
        verified_partial_user_signature_cap_image_url,
        ctx,
    );
}

// === Test only ===

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(IKA_DWALLET_2PC_MPC_INIT {}, ctx);
}

#[test_only]
/// Does the same as `initialize` but does not check the package id of the upgrade cap.
///
/// This is needed for testing, since the package ID of all types will be zero, which cannot be used
/// as the package ID for an upgrade cap.
public fun initialize_for_testing(
    init_cap: InitCap,
    advance_epoch_approver: &mut AdvanceEpochApprover,
    system_current_status_info: &SystemCurrentStatusInfo,
    pricing: PricingInfo,
    supported_curves_to_signature_algorithms_to_hash_schemes: VecMap<u32, VecMap<u32, vector<u32>>>,
    ctx: &mut TxContext,
) {
    let InitCap { id, publisher } = init_cap;
    id.delete();

    let package_id_string = type_name::get<InitCap>().get_address().into_bytes();
    let package_id = address::from_ascii_bytes(&package_id_string).to_id();

    coordinator::create(
        package_id,
        advance_epoch_approver,
        system_current_status_info,
        pricing,
        supported_curves_to_signature_algorithms_to_hash_schemes,
        ctx,
    );

    ika_dwallet_2pc_mpc_display::create(
        publisher,
        b"".to_string(),
        b"".to_string(),
        b"".to_string(),
        b"".to_string(),
        b"".to_string(),
        b"".to_string(),
        ctx,
    );
}
