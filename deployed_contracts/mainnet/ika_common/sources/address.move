// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_common::address;

use sui::address;
use sui::hash;

// === Public Functions ===

public fun ed25519_address(public_key: vector<u8>): address {
    let mut hasher = vector[0u8];
    hasher.append(public_key);
    let address_bytes = hash::blake2b256(&hasher);
    address::from_bytes(address_bytes)
}
