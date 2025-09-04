// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::protocol_cap;
use ika_common::system_object_cap::SystemObjectCap;

// === Structs ===

public struct ProtocolCap has key, store {
    id: UID,
}

public struct VerifiedProtocolCap has drop {}

// === Public Functions ===

public fun create(ctx: &mut TxContext, _: &SystemObjectCap): ProtocolCap {
    ProtocolCap {
        id: object::new(ctx),
    }
}

public fun create_verified(_: &SystemObjectCap): VerifiedProtocolCap {
    VerifiedProtocolCap {}
}
