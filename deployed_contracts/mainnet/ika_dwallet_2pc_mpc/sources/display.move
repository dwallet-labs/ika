// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// Implements Sui Object Display for user-owned objects.
///
/// The default fields for Display are:
/// - name
/// - description
/// - image_url
/// - link
/// - project_url
///
/// Optionally:
/// - thumbnail_url
/// - creator
module ika_dwallet_2pc_mpc::ika_dwallet_2pc_mpc_display;

use ika_dwallet_2pc_mpc::coordinator_inner::{
    DWalletCap,
    ImportedKeyDWalletCap,
    UnverifiedPartialUserSignatureCap,
    UnverifiedPresignCap,
    VerifiedPartialUserSignatureCap,
    VerifiedPresignCap
};
use std::string::String;
use std::type_name;
use sui::display::{Self, Display};
use sui::object_bag::{Self, ObjectBag};
use sui::package::Publisher;

// === Structs ===

/// The wrapper that stores the objects.
public struct ObjectDisplay has key {
    id: UID,
    inner: ObjectBag,
}

/// The dynamic field key to use
public struct PublisherKey() has copy, drop, store;

// === Package Functions ===

/// Creates the `ObjectDisplay` instance with default objects in it.
public(package) fun create(
    p: Publisher,
    dwallet_cap_image_url: String,
    imported_key_dwallet_cap_image_url: String,
    unverified_presign_cap_image_url: String,
    verified_presign_cap_image_url: String,
    unverified_partial_user_signature_cap_image_url: String,
    verified_partial_user_signature_cap_image_url: String,
    ctx: &mut TxContext,
) {
    let mut inner = object_bag::new(ctx);

    inner.add(
        type_name::get<DWalletCap>(),
        init_dwallet_cap_display(&p, dwallet_cap_image_url, ctx),
    );
    inner.add(
        type_name::get<ImportedKeyDWalletCap>(),
        init_imported_key_dwallet_cap_display(&p, imported_key_dwallet_cap_image_url, ctx),
    );
    inner.add(
        type_name::get<UnverifiedPresignCap>(),
        init_unverified_presign_cap_display(&p, unverified_presign_cap_image_url, ctx),
    );
    inner.add(
        type_name::get<VerifiedPresignCap>(),
        init_verified_presign_cap_display(&p, verified_presign_cap_image_url, ctx),
    );
    inner.add(
        type_name::get<UnverifiedPartialUserSignatureCap>(),
        init_unverified_partial_user_signature_cap_display(
            &p,
            unverified_partial_user_signature_cap_image_url,
            ctx,
        ),
    );
    inner.add(
        type_name::get<VerifiedPartialUserSignatureCap>(),
        init_verified_partial_user_signature_cap_display(
            &p,
            verified_partial_user_signature_cap_image_url,
            ctx,
        ),
    );
    inner.add(PublisherKey(), p);

    transfer::share_object(ObjectDisplay { id: object::new(ctx), inner })
}

// === Private Functions ===

/// Creates initial `Display` for the `DWalletCap` type.
fun init_dwallet_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<DWalletCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"DWallet Cap".to_string());
    d.add(
        b"description".to_string(),
        b"DWallet cap for: {dwallet_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}

/// Creates initial `Display` for the `ImportedKeyDWalletCap` type.
fun init_imported_key_dwallet_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<ImportedKeyDWalletCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"Imported Key DWallet Cap".to_string());
    d.add(
        b"description".to_string(),
        b"Imported key dWallet cap for: {dwallet_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}

/// Creates initial `Display` for the `UnverifiedPresignCap` type.
fun init_unverified_presign_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<UnverifiedPresignCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"Unverified Presign Cap".to_string());
    d.add(
        b"description".to_string(),
        b"Unverified presign cap for: {presign_id}, dWallet: {dwallet_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}

/// Creates initial `Display` for the `VerifiedPresignCap` type.
fun init_verified_presign_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<VerifiedPresignCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"Verified Presign Cap".to_string());
    d.add(
        b"description".to_string(),
        b"Verified presign cap for: {presign_id}, dWallet: {dwallet_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}

/// Creates initial `Display` for the `UnverifiedPartialUserSignatureCap` type.
fun init_unverified_partial_user_signature_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<UnverifiedPartialUserSignatureCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"Unverified Partial User Signature Cap".to_string());
    d.add(
        b"description".to_string(),
        b"Unverified partial user signature cap for: {partial_centralized_signed_message_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}

/// Creates initial `Display` for the `VerifiedPartialUserSignatureCap` type.
fun init_verified_partial_user_signature_cap_display(
    p: &Publisher,
    image_url: String,
    ctx: &mut TxContext,
): Display<VerifiedPartialUserSignatureCap> {
    let mut d = display::new(p, ctx);

    d.add(b"name".to_string(), b"Verified Partial User Signature Cap".to_string());
    d.add(
        b"description".to_string(),
        b"Verified partial user signature cap for: {partial_centralized_signed_message_id}".to_string(),
    );
    d.add(b"image_url".to_string(), image_url);
    d.add(b"project_url".to_string(), b"https://ika.xyz/".to_string());
    d.add(b"link".to_string(), b"".to_string());
    d.update_version();
    d
}
