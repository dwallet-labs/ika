// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The network-owned-address (NOA) signing key is resolved by the
//! prepare-then-start barrier from the prior epoch's handoff certificate
//! (`dwallet_mpc::network_owned_address_signing_key::select`, whose rule is
//! pinned in that module's own tests) and handed to the MPC manager as a
//! fixed constructor input.
//!
//! These tests pin the manager's side of that contract: with
//! `noa_checkpoints` on, its answer IS that input and never the locally
//! adopted key set — whose contents differ between honest validators while
//! their adoption lags (issue #2019 measured three such windows: the
//! epoch-start fill window, per-key overlay incompleteness, and a
//! handoff-certificate read error) — while the flag-off path keeps the
//! adopted-set pool-role rule byte for byte.

use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::integration_tests::utils;
use crate::network_key_id_mapping;
use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;

/// A network key in its initial-DKG state as the overlay serves it: metadata
/// from chain, the DKG blob from the local producer cache (empty when this
/// validator has not cached it yet — adoption then skips the key).
fn overlay_entry(
    key_id: ObjectID,
    current_epoch: u64,
    network_dkg_public_output: Vec<u8>,
) -> (ObjectID, DWalletNetworkEncryptionKeyData) {
    (
        key_id,
        DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch,
            dkg_at_epoch: 0,
            network_dkg_public_output,
            current_reconfiguration_public_output: vec![],
            state: DWalletNetworkEncryptionKeyState::NetworkDKGCompleted,
        },
    )
}

/// Two keys whose id ordering is known, registered in the process-global
/// mapping (adoption defers any key it cannot map).
fn two_ordered_registered_keys() -> (ObjectID, ObjectID) {
    let (a, b) = (ObjectID::random(), ObjectID::random());
    let (low, high) = if a < b { (a, b) } else { (b, a) };
    network_key_id_mapping::register(low, NetworkKeyId(low.into_bytes()));
    network_key_id_mapping::register(high, NetworkKeyId(high.into_bytes()));
    (low, high)
}

/// Two validators at the same epoch.
struct TwoValidators {
    services: Vec<DWalletMPCService>,
    epoch_id: u64,
}

impl TwoValidators {
    fn build() -> Self {
        let (services, _senders, _collectors, _epoch_stores, _notify, _requests, _outputs) =
            utils::create_dwallet_mpc_services(2);
        let epoch_id = services.first().expect("two services").epoch;
        Self { services, epoch_id }
    }

    /// The barrier's answer, as it would have been handed in at
    /// construction.
    fn set_key(&mut self, index: usize, key_id: Option<ObjectID>) {
        self.services[index].set_network_owned_address_signing_key_id_for_testing(key_id);
    }

    fn adopt(
        &mut self,
        index: usize,
        overlay: &Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>,
    ) {
        self.services[index]
            .dwallet_mpc_manager_mut()
            .adopt_cert_verified_keys(overlay);
    }

    fn adopted_keys(&self, index: usize) -> Vec<ObjectID> {
        let mut keys: Vec<_> = self.services[index]
            .dwallet_mpc_manager()
            .adopted_network_key_data
            .keys()
            .copied()
            .collect();
        keys.sort();
        keys
    }

    fn selected_key(&self, index: usize) -> Option<ObjectID> {
        self.services[index]
            .dwallet_mpc_manager()
            .network_owned_address_signing_network_encryption_key_id()
    }
}

/// Two validators handed the same key with different adopted sets — one
/// holding both keys, the other only the higher-id one because the low key's
/// blob has not reached its local cache — name the same key, including the
/// one that has not adopted it. Under the previous adopted-set rule this was
/// the shape that diverged (per-key overlay incompleteness).
#[tokio::test]
async fn same_key_input_with_different_adopted_sets_selects_the_same_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;
    let (low, high) = two_ordered_registered_keys();

    let complete = Arc::new(HashMap::from([
        overlay_entry(low, epoch_id, b"low key dkg output".to_vec()),
        overlay_entry(high, epoch_id, b"high key dkg output".to_vec()),
    ]));
    let low_blob_missing = Arc::new(HashMap::from([
        overlay_entry(low, epoch_id, vec![]),
        overlay_entry(high, epoch_id, b"high key dkg output".to_vec()),
    ]));
    validators.adopt(0, &complete);
    validators.adopt(1, &low_blob_missing);
    // Control: the adopted sets really differ.
    assert_eq!(validators.adopted_keys(0), {
        let mut both = vec![low, high];
        both.sort();
        both
    });
    assert_eq!(validators.adopted_keys(1), vec![high]);

    // The barrier named the LOW key — the one validator two has not adopted.
    validators.set_key(0, Some(low));
    validators.set_key(1, Some(low));

    let (first, second) = (validators.selected_key(0), validators.selected_key(1));
    tracing::info!(?first, ?second, "selected NOA signing keys");
    assert_eq!(first, Some(low));
    assert_eq!(
        second,
        Some(low),
        "the answer is the barrier's input, not a choice over the adopted set"
    );
}

/// A validator that has adopted NOTHING — every overlay entry still
/// blob-empty, the epoch-start fill window — answers its input like a peer
/// that has adopted everything.
#[tokio::test]
async fn a_validator_that_adopted_nothing_answers_the_same_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;
    let (low, high) = two_ordered_registered_keys();

    validators.adopt(
        0,
        &Arc::new(HashMap::from([
            overlay_entry(low, epoch_id, b"low key dkg output".to_vec()),
            overlay_entry(high, epoch_id, b"high key dkg output".to_vec()),
        ])),
    );
    validators.adopt(
        1,
        &Arc::new(HashMap::from([
            overlay_entry(low, epoch_id, vec![]),
            overlay_entry(high, epoch_id, vec![]),
        ])),
    );
    assert_eq!(validators.adopted_keys(1), Vec::<ObjectID>::new());

    validators.set_key(0, Some(low));
    validators.set_key(1, Some(low));
    assert_eq!(validators.selected_key(0), Some(low));
    assert_eq!(
        validators.selected_key(1),
        Some(low),
        "an empty adopted set does not stop the answer: the key was fixed before adoption ran"
    );
}

/// An epoch with no signing key — no prior certificate, a certificate naming
/// no key, or a validator that could not translate a certified key at the
/// barrier — answers `None` however much it has adopted.
#[tokio::test]
async fn no_key_this_epoch_answers_none_regardless_of_adoption() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;
    let (low, high) = two_ordered_registered_keys();

    validators.adopt(
        0,
        &Arc::new(HashMap::from([
            overlay_entry(low, epoch_id, b"low key dkg output".to_vec()),
            overlay_entry(high, epoch_id, b"high key dkg output".to_vec()),
        ])),
    );
    assert_eq!(validators.adopted_keys(0).len(), 2);
    validators.set_key(0, None);
    assert_eq!(
        validators.selected_key(0),
        None,
        "adopted keys never become the signing key on their own"
    );
}

/// With `noa_checkpoints` OFF — every live network today — the pool-role
/// rule is unchanged: the oldest ADOPTED key, ties to the smaller id, and the
/// barrier's input is ignored. This is what keeps the live protocol
/// version's internal-presign sequence numbers where they are.
#[tokio::test]
async fn flag_off_keeps_the_oldest_adopted_key_rule() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;
    let (low, high) = two_ordered_registered_keys();

    validators.set_key(0, Some(high));
    assert_eq!(
        validators.selected_key(0),
        None,
        "nothing adopted, nothing selected — the input plays no part with the flag off"
    );
    validators.adopt(
        0,
        &Arc::new(HashMap::from([
            overlay_entry(low, epoch_id, b"low key dkg output".to_vec()),
            overlay_entry(high, epoch_id, b"high key dkg output".to_vec()),
        ])),
    );
    assert_eq!(
        validators.selected_key(0),
        Some(low),
        "same dkg_at_epoch, so the smaller adopted id wins"
    );
}
