// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! TEMPORARY `ObjectID` <-> `NetworkKeyId` mapping.
//!
//! The cross-epoch handoff identifies a network encryption key by its
//! content-derived [`NetworkKeyId`] (its curve25519 network-owned-address
//! ed25519 public key), while the rest of the validator runtime and the
//! Sui chain still identify it by `ObjectID`. This module translates
//! between the two.
//!
//! It is deliberately a small static map: there is exactly one network
//! key on testnet and one on mainnet, and no new network-key DKG is
//! planned before the on-chain request event starts carrying the
//! `NetworkKeyId` directly. The known deployed keys are seeded as
//! constants so the mapping is available *before* instantiation — a
//! joiner consuming the handoff cert needs it then; tests/localnet that
//! DKG a fresh key call [`register`] at instantiation to self-populate.
//!
//! TODO(NetworkKeyId-from-event): delete this module once the request
//! event carries the `NetworkKeyId`. The runtime/tables then key by
//! `NetworkKeyId` directly and `ObjectID` is dropped as the key identity.

use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::LazyLock;
use sui_types::base_types::ObjectID;

/// Deployed network keys as `(ObjectID, NetworkKeyId)` hex. Derived from
/// chain with the `print_deployed_network_key_ids` tool (see
/// `dwallet_mpc::...::network_dkg`).
const SEED: &[(&str, &str)] = &[
    // testnet
    (
        "0xe7c79a60931299e110297554fc02e0a0e095e96778775092c97f07a1bd1337cc",
        "0x93e7a5e9387f8d900f378df7c39a77600a735179c50ffc7f352d150d078e072b",
    ),
    // mainnet
    (
        "0x0a9c0b88a5c729378bce1a98a8c285f1dde26f89e53d07164dba8a059dc15587",
        "0xeecf7da51fab8228c0af7b9b4ae22fa7be7130df7c8a793fe9f95279c5d4c29f",
    ),
];

struct Mapping {
    object_id_to_network_key_id: HashMap<ObjectID, NetworkKeyId>,
    network_key_id_to_object_id: HashMap<NetworkKeyId, ObjectID>,
}

fn parse_network_key_id(hex_with_prefix: &str) -> NetworkKeyId {
    let bytes = hex::decode(hex_with_prefix.trim_start_matches("0x"))
        .expect("seed NetworkKeyId is valid hex");
    NetworkKeyId(bytes.try_into().expect("seed NetworkKeyId is 32 bytes"))
}

static MAPPING: LazyLock<RwLock<Mapping>> = LazyLock::new(|| {
    let mut object_id_to_network_key_id = HashMap::new();
    let mut network_key_id_to_object_id = HashMap::new();
    for (object_id_hex, network_key_id_hex) in SEED {
        let object_id = ObjectID::from_hex_literal(object_id_hex).expect("seed ObjectID is valid");
        let network_key_id = parse_network_key_id(network_key_id_hex);
        object_id_to_network_key_id.insert(object_id, network_key_id);
        network_key_id_to_object_id.insert(network_key_id, object_id);
    }
    RwLock::new(Mapping {
        object_id_to_network_key_id,
        network_key_id_to_object_id,
    })
});

/// Records an `ObjectID <-> NetworkKeyId` mapping. Called at network-key
/// instantiation so tests/localnet (which DKG fresh keys absent from
/// [`SEED`]) self-populate. Idempotent; the mapping is
/// reconfiguration-invariant, so it never needs clearing.
pub fn register(object_id: ObjectID, network_key_id: NetworkKeyId) {
    let mut mapping = MAPPING.write();
    mapping
        .object_id_to_network_key_id
        .insert(object_id, network_key_id);
    mapping
        .network_key_id_to_object_id
        .insert(network_key_id, object_id);
}

/// The `NetworkKeyId` for a network key's `ObjectID`, if known.
pub fn network_key_id_for(object_id: &ObjectID) -> Option<NetworkKeyId> {
    MAPPING
        .read()
        .object_id_to_network_key_id
        .get(object_id)
        .copied()
}

/// The `ObjectID` for a `NetworkKeyId`, if known.
pub fn object_id_for(network_key_id: &NetworkKeyId) -> Option<ObjectID> {
    MAPPING
        .read()
        .network_key_id_to_object_id
        .get(network_key_id)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_keys_round_trip() {
        for (object_id_hex, network_key_id_hex) in SEED {
            let object_id = ObjectID::from_hex_literal(object_id_hex).unwrap();
            let network_key_id = parse_network_key_id(network_key_id_hex);
            assert_eq!(network_key_id_for(&object_id), Some(network_key_id));
            assert_eq!(object_id_for(&network_key_id), Some(object_id));
        }
    }

    #[test]
    fn register_then_look_up() {
        let object_id = ObjectID::from_single_byte(7);
        let network_key_id = NetworkKeyId([7u8; 32]);
        assert_eq!(network_key_id_for(&object_id), None);
        register(object_id, network_key_id);
        assert_eq!(network_key_id_for(&object_id), Some(network_key_id));
        assert_eq!(object_id_for(&network_key_id), Some(object_id));
    }
}
