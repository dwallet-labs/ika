// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::system_object_cap;

// === Structs ===

public struct SystemObjectCap has key, store {
    id: UID,
}

// === Init Function ===

fun init(ctx: &mut TxContext) {
    let system_object_cap = SystemObjectCap {
        id: object::new(ctx),
    };
    transfer::transfer(system_object_cap, tx_context::sender(ctx));
}