// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Investigation harness for issue #2019: can two honest validators
//! select a DIFFERENT network-encryption key as the
//! network-owned-address (NOA) signing key at the same moment?
//!
//! The selector
//! (`DWalletMPCManager::network_owned_address_signing_network_encryption_key_id`)
//! takes the minimum over `adopted_network_key_data`, ordered by
//! `dkg_at_epoch` then key id. That is a pure function of the ADOPTED
//! SET, so it is order-independent: two validators can only disagree if
//! their adopted sets differ at that moment. `adopt_cert_verified_keys`
//! is a per-tick LOCAL pass over a LOCAL overlay, so the sets diverge
//! whenever a key is adoptable on one validator and not (yet) on
//! another.
//!
//! These tests drive two managers at the same epoch through the two
//! per-validator skip paths and compare the selector's answer.

use crate::dwallet_mpc::integration_tests::utils;
use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use sui_types::base_types::ObjectID;

/// A network key as the overlay serves it: metadata from chain, blob
/// bytes from the local producer cache (empty when this validator has
/// not cached / fetched them yet).
fn overlay_entry(
    key_id: ObjectID,
    current_epoch: u64,
    dkg_at_epoch: u64,
    network_dkg_public_output: Vec<u8>,
    current_reconfiguration_public_output: Vec<u8>,
) -> DWalletNetworkEncryptionKeyData {
    DWalletNetworkEncryptionKeyData {
        id: key_id,
        current_epoch,
        dkg_at_epoch,
        network_dkg_public_output,
        current_reconfiguration_public_output,
        state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
    }
}

fn cert_pinning(
    prior_epoch: u64,
    keys: &[(NetworkKeyId, &[u8], &[u8])],
) -> CertifiedHandoffAttestation {
    // `HandoffItemKey`'s derived `Ord` puts DKG before reconfiguration;
    // the attestation's items are sorted by key.
    let mut items: Vec<_> = keys
        .iter()
        .flat_map(|(network_key_id, dkg, reconfiguration)| {
            [
                (
                    HandoffItemKey::NetworkDkgOutput {
                        key_id: *network_key_id,
                    },
                    mpc_data_blob_hash(dkg),
                ),
                (
                    HandoffItemKey::NetworkReconfigurationOutput {
                        key_id: *network_key_id,
                    },
                    mpc_data_blob_hash(reconfiguration),
                ),
            ]
        })
        .collect();
    items.sort_by(|(a, _), (b, _)| a.cmp(b));
    CertifiedHandoffAttestation {
        attestation: HandoffAttestation {
            epoch: prior_epoch,
            next_committee_pubkey_set_hash: [0u8; 32],
            items,
        },
        signatures: vec![],
    }
}

/// Two ObjectIDs whose ordering is known, with their `NetworkKeyId`
/// mappings registered (adoption defers any key it cannot map).
fn two_ordered_keys() -> (ObjectID, ObjectID) {
    let (low, high) = {
        let (a, b) = (ObjectID::random(), ObjectID::random());
        if a < b { (a, b) } else { (b, a) }
    };
    // The mapping is a process global; random ObjectIDs keep tests
    // independent. The NetworkKeyId only has to be unique per key.
    crate::network_key_id_mapping::register(low, NetworkKeyId(low.into_bytes()));
    crate::network_key_id_mapping::register(high, NetworkKeyId(high.into_bytes()));
    (low, high)
}

/// SKEW MECHANISM 1 — per-key overlay incompleteness.
///
/// The syncer merges each key's blob bytes from the LOCAL producer
/// cache and publishes the overlay even when a key's bytes are still
/// missing (`overlay_incomplete` in `sui_syncer::sync_network_keys`),
/// and a per-key chain-read `Err` skips only that key. So one validator
/// can hold a complete overlay entry for a key while another holds an
/// empty one. Adoption skips the empty entry
/// (`network_dkg_public_output.is_empty()` => `continue`), and the
/// selector's minimum then differs.
#[tokio::test]
async fn overlay_incompleteness_on_one_validator_diverges_the_noa_signing_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (mut services, _senders, _collectors, epoch_stores, _notify, _req, _out) =
        utils::create_dwallet_mpc_services(2);
    let epoch_id = services.first().unwrap().epoch;
    let prior_epoch = epoch_id - 1;

    let (low_key, high_key) = two_ordered_keys();
    let low_dkg = b"low key dkg output".to_vec();
    let low_reconfiguration = b"low key reconfiguration output".to_vec();
    let high_dkg = b"high key dkg output".to_vec();
    let high_reconfiguration = b"high key reconfiguration output".to_vec();

    // Both keys are DKG'd in the same (prior) epoch, so the selector's
    // tie-break is the key id: `low_key` is the NOA key once adopted.
    let cert = cert_pinning(
        prior_epoch,
        &[
            (
                NetworkKeyId(low_key.into_bytes()),
                &low_dkg,
                &low_reconfiguration,
            ),
            (
                NetworkKeyId(high_key.into_bytes()),
                &high_dkg,
                &high_reconfiguration,
            ),
        ],
    );
    // The cert is network-uniform: BOTH validators are handed the same one.
    for epoch_store in &epoch_stores {
        epoch_store
            .certified_handoff_attestations
            .lock()
            .unwrap()
            .insert(prior_epoch, cert.clone());
    }

    let complete_overlay = Arc::new(HashMap::from([
        (
            low_key,
            overlay_entry(
                low_key,
                epoch_id,
                0,
                low_dkg.clone(),
                low_reconfiguration.clone(),
            ),
        ),
        (
            high_key,
            overlay_entry(
                high_key,
                epoch_id,
                0,
                high_dkg.clone(),
                high_reconfiguration.clone(),
            ),
        ),
    ]));
    // Validator two's local producer cache has not yet filled the LOW
    // key's blobs — the exact shape the syncer publishes as "incomplete".
    let partial_overlay = Arc::new(HashMap::from([
        (low_key, overlay_entry(low_key, epoch_id, 0, vec![], vec![])),
        (
            high_key,
            overlay_entry(
                high_key,
                epoch_id,
                0,
                high_dkg.clone(),
                high_reconfiguration.clone(),
            ),
        ),
    ]));

    let (first, second) = services.split_at_mut(1);
    let first = first[0].dwallet_mpc_manager_mut();
    let second = second[0].dwallet_mpc_manager_mut();
    first.adopt_cert_verified_keys(&complete_overlay);
    second.adopt_cert_verified_keys(&partial_overlay);

    let first_selected = first.network_owned_address_signing_network_encryption_key_id();
    let second_selected = second.network_owned_address_signing_network_encryption_key_id();
    tracing::info!(
        ?first_selected,
        ?second_selected,
        "selected NOA signing keys"
    );
    assert_eq!(
        first_selected,
        Some(low_key),
        "the validator holding both keys must select the lower-id one"
    );
    assert_eq!(
        second_selected,
        Some(high_key),
        "the validator whose low-key overlay entry is still empty selects the high key"
    );
    assert_ne!(
        first_selected, second_selected,
        "SKEW: two honest validators select different NOA signing keys at the same moment"
    );

    // The window closes when the lagging validator's overlay fills.
    second.adopt_cert_verified_keys(&complete_overlay);
    assert_eq!(
        second.network_owned_address_signing_network_encryption_key_id(),
        Some(low_key),
        "the adopted set is monotone, so the laggard converges once its overlay completes"
    );
}

/// SKEW MECHANISM 2 — the handoff-cert READ ERROR skip.
///
/// A store hiccup makes `adopt_cert_verified_keys` return before
/// adopting ANYTHING this tick (deliberately: an error is not the same
/// answer as an absent cert). Everything already adopted stays adopted,
/// so a validator that adopted the high key in an earlier tick and then
/// hits the error keeps selecting it while its peers move to the low key.
///
/// This is also the harness-capability check for the negative result: it
/// shows the harness can drive two validators to genuinely different
/// adopted sets on demand.
#[tokio::test]
async fn handoff_cert_read_error_freezes_one_validator_on_a_different_noa_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (mut services, _senders, _collectors, epoch_stores, _notify, _req, _out) =
        utils::create_dwallet_mpc_services(2);
    let epoch_id = services.first().unwrap().epoch;
    let prior_epoch = epoch_id - 1;

    let (low_key, high_key) = two_ordered_keys();
    let low_dkg = b"low key dkg output".to_vec();
    let low_reconfiguration = b"low key reconfiguration output".to_vec();
    let high_dkg = b"high key dkg output".to_vec();
    let high_reconfiguration = b"high key reconfiguration output".to_vec();

    let cert = cert_pinning(
        prior_epoch,
        &[
            (
                NetworkKeyId(low_key.into_bytes()),
                &low_dkg,
                &low_reconfiguration,
            ),
            (
                NetworkKeyId(high_key.into_bytes()),
                &high_dkg,
                &high_reconfiguration,
            ),
        ],
    );
    for epoch_store in &epoch_stores {
        epoch_store
            .certified_handoff_attestations
            .lock()
            .unwrap()
            .insert(prior_epoch, cert.clone());
    }

    let high_only_overlay = Arc::new(HashMap::from([(
        high_key,
        overlay_entry(
            high_key,
            epoch_id,
            0,
            high_dkg.clone(),
            high_reconfiguration.clone(),
        ),
    )]));
    let both_keys_overlay = Arc::new(HashMap::from([
        (
            high_key,
            overlay_entry(
                high_key,
                epoch_id,
                0,
                high_dkg.clone(),
                high_reconfiguration.clone(),
            ),
        ),
        (
            low_key,
            overlay_entry(
                low_key,
                epoch_id,
                0,
                low_dkg.clone(),
                low_reconfiguration.clone(),
            ),
        ),
    ]));

    let (first, second) = services.split_at_mut(1);
    let first = first[0].dwallet_mpc_manager_mut();
    let second = second[0].dwallet_mpc_manager_mut();

    // Tick 1: only the high key is on chain / resolvable anywhere. Both
    // validators agree.
    first.adopt_cert_verified_keys(&high_only_overlay);
    second.adopt_cert_verified_keys(&high_only_overlay);
    assert_eq!(
        first.network_owned_address_signing_network_encryption_key_id(),
        second.network_owned_address_signing_network_encryption_key_id(),
        "both validators start from the same adopted set"
    );

    // Tick 2: the low key becomes resolvable for both, but validator
    // two's handoff-cert read fails, so its whole adoption pass is
    // skipped while validator one adopts.
    epoch_stores[1]
        .fail_certified_handoff_attestation_reads
        .store(true, Ordering::Relaxed);
    first.adopt_cert_verified_keys(&both_keys_overlay);
    second.adopt_cert_verified_keys(&both_keys_overlay);

    let first_selected = first.network_owned_address_signing_network_encryption_key_id();
    let second_selected = second.network_owned_address_signing_network_encryption_key_id();
    tracing::info!(
        ?first_selected,
        ?second_selected,
        "selected NOA signing keys"
    );
    assert_eq!(first_selected, Some(low_key));
    assert_eq!(
        second_selected,
        Some(high_key),
        "the cert-read error skipped adoption entirely, freezing the earlier answer"
    );
    assert_ne!(
        first_selected, second_selected,
        "SKEW: a transient store error diverges the NOA signing key across honest validators"
    );

    // The skip is per-tick: adoption resumes on the next pass.
    epoch_stores[1]
        .fail_certified_handoff_attestation_reads
        .store(false, Ordering::Relaxed);
    second.adopt_cert_verified_keys(&both_keys_overlay);
    assert_eq!(
        second.network_owned_address_signing_network_encryption_key_id(),
        Some(low_key),
        "the pass retries every service iteration, so this window is one tick"
    );
}

/// SKEW MECHANISM 3 — the epoch-start fill window, with a SINGLE key.
///
/// `adopted_network_key_data` is created empty for every epoch's
/// manager, so at every epoch start the selector answers `None` until
/// the first key is adopted. A validator whose overlay resolves a tick
/// later than its peers' therefore answers `None` while they answer
/// `Some(key)`. This needs no second key and no error injection, and it
/// is what makes "reject an announcement that doesn't match my
/// selection" unsafe even on a one-key network.
#[tokio::test]
async fn epoch_start_fill_window_leaves_one_validator_with_no_noa_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (mut services, _senders, _collectors, epoch_stores, _notify, _req, _out) =
        utils::create_dwallet_mpc_services(2);
    let epoch_id = services.first().unwrap().epoch;
    let prior_epoch = epoch_id - 1;

    let key_id = ObjectID::random();
    crate::network_key_id_mapping::register(key_id, NetworkKeyId(key_id.into_bytes()));
    let dkg = b"the only network key's dkg output".to_vec();
    let reconfiguration = b"the only network key's reconfiguration output".to_vec();
    let cert = cert_pinning(
        prior_epoch,
        &[(NetworkKeyId(key_id.into_bytes()), &dkg, &reconfiguration)],
    );
    for epoch_store in &epoch_stores {
        epoch_store
            .certified_handoff_attestations
            .lock()
            .unwrap()
            .insert(prior_epoch, cert.clone());
    }

    let resolved = Arc::new(HashMap::from([(
        key_id,
        overlay_entry(key_id, epoch_id, 0, dkg.clone(), reconfiguration.clone()),
    )]));
    // Validator two's overlay entry is still blob-empty this tick.
    let unresolved = Arc::new(HashMap::from([(
        key_id,
        overlay_entry(key_id, epoch_id, 0, vec![], vec![]),
    )]));

    let (first, second) = services.split_at_mut(1);
    let first = first[0].dwallet_mpc_manager_mut();
    let second = second[0].dwallet_mpc_manager_mut();
    first.adopt_cert_verified_keys(&resolved);
    second.adopt_cert_verified_keys(&unresolved);

    assert_eq!(
        first.network_owned_address_signing_network_encryption_key_id(),
        Some(key_id),
    );
    assert_eq!(
        second.network_owned_address_signing_network_encryption_key_id(),
        None,
        "SKEW: validator one would announce a demand carrying a key validator two \
         has no selection for at all"
    );

    second.adopt_cert_verified_keys(&resolved);
    assert_eq!(
        second.network_owned_address_signing_network_encryption_key_id(),
        Some(key_id),
    );
}

/// CONTROL — the selector is a pure function of the adopted SET, not of
/// adoption ORDER. Two validators that adopt the same two keys in
/// opposite orders agree at every point where their sets are equal.
/// This bounds the claim: order alone never produces skew, so any real
/// divergence must be a set difference (mechanisms 1-3 above).
#[tokio::test]
async fn adoption_order_alone_does_not_diverge_the_noa_signing_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (mut services, _senders, _collectors, epoch_stores, _notify, _req, _out) =
        utils::create_dwallet_mpc_services(2);
    let epoch_id = services.first().unwrap().epoch;
    let prior_epoch = epoch_id - 1;

    let (low_key, high_key) = two_ordered_keys();
    let low_dkg = b"low key dkg output".to_vec();
    let low_reconfiguration = b"low key reconfiguration output".to_vec();
    let high_dkg = b"high key dkg output".to_vec();
    let high_reconfiguration = b"high key reconfiguration output".to_vec();
    let cert = cert_pinning(
        prior_epoch,
        &[
            (
                NetworkKeyId(low_key.into_bytes()),
                &low_dkg,
                &low_reconfiguration,
            ),
            (
                NetworkKeyId(high_key.into_bytes()),
                &high_dkg,
                &high_reconfiguration,
            ),
        ],
    );
    for epoch_store in &epoch_stores {
        epoch_store
            .certified_handoff_attestations
            .lock()
            .unwrap()
            .insert(prior_epoch, cert.clone());
    }

    let low_entry = overlay_entry(
        low_key,
        epoch_id,
        0,
        low_dkg.clone(),
        low_reconfiguration.clone(),
    );
    let high_entry = overlay_entry(
        high_key,
        epoch_id,
        0,
        high_dkg.clone(),
        high_reconfiguration.clone(),
    );
    let both = Arc::new(HashMap::from([
        (low_key, low_entry.clone()),
        (high_key, high_entry.clone()),
    ]));

    let (first, second) = services.split_at_mut(1);
    let first = first[0].dwallet_mpc_manager_mut();
    let second = second[0].dwallet_mpc_manager_mut();
    // Same two adoptions, opposite orders.
    first.adopt_cert_verified_keys(&Arc::new(HashMap::from([(low_key, low_entry.clone())])));
    first.adopt_cert_verified_keys(&both);
    second.adopt_cert_verified_keys(&Arc::new(HashMap::from([(high_key, high_entry.clone())])));
    second.adopt_cert_verified_keys(&both);

    assert_eq!(
        first.network_owned_address_signing_network_encryption_key_id(),
        second.network_owned_address_signing_network_encryption_key_id(),
        "equal adopted sets must yield the same NOA key regardless of adoption order"
    );
}
