// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The network-owned-address (NOA) signing key is a pure function of the
//! prior epoch's handoff certificate, fixed for the epoch: among the keys the
//! certificate names, the one with the largest `dkg_at_epoch`, ties broken by
//! the smaller `NetworkKeyId`
//! (`DWalletMPCManager::network_owned_address_signing_key_resolution`).
//!
//! It is deliberately NOT read from the locally adopted key set, whose
//! contents differ between honest validators while their adoption lags (issue
//! #2019 measured three such windows: the epoch-start fill window, per-key
//! overlay incompleteness, and a handoff-certificate read error). These tests
//! drive two managers at the same epoch with the SAME certificate and
//! DIFFERENT adopted sets and assert the selector agrees; and they pin the
//! all-or-nothing rule — a validator that cannot translate, or has no chain
//! metadata for, one certified key answers `None` rather than choosing among
//! the keys it can see.
//!
//! The selector reads the certificate from the epoch store, the translation
//! from the process-global `network_key_id_mapping`, and `dkg_at_epoch` from
//! the network-key overlay watch; the adopted set is driven separately through
//! `adopt_cert_verified_keys`, exactly as the service does, so a test can hand
//! the two managers the same watch value and different adoption inputs.

use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::mpc_manager::NetworkOwnedAddressSigningKeyResolution;
use crate::network_key_id_mapping;
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

/// A network key as the overlay serves it: metadata from chain, blob bytes
/// from the local producer cache (empty when this validator has not cached /
/// fetched them yet — adoption then skips the key, but the selector still
/// reads `dkg_at_epoch`).
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

/// A key's inputs to one test: its Sui id, its content-derived id, and the
/// blobs the overlay carries for it.
struct TestKey {
    object_id: ObjectID,
    network_key_id: NetworkKeyId,
    dkg_at_epoch: u64,
    dkg: Vec<u8>,
    reconfiguration: Vec<u8>,
}

impl TestKey {
    /// A key whose `NetworkKeyId` is its `ObjectID`'s bytes — so ordering the
    /// object ids orders the network key ids identically — registered in the
    /// process-global mapping (adoption defers any key it cannot map).
    fn registered(object_id: ObjectID, dkg_at_epoch: u64, tag: &str) -> Self {
        let network_key_id = NetworkKeyId(object_id.into_bytes());
        network_key_id_mapping::register(object_id, network_key_id);
        Self {
            object_id,
            network_key_id,
            dkg_at_epoch,
            dkg: format!("{tag} dkg output").into_bytes(),
            reconfiguration: format!("{tag} reconfiguration output").into_bytes(),
        }
    }

    fn complete_entry(&self, epoch_id: u64) -> (ObjectID, DWalletNetworkEncryptionKeyData) {
        (
            self.object_id,
            overlay_entry(
                self.object_id,
                epoch_id,
                self.dkg_at_epoch,
                self.dkg.clone(),
                self.reconfiguration.clone(),
            ),
        )
    }

    /// Metadata present, blobs not yet cached locally.
    fn blob_empty_entry(&self, epoch_id: u64) -> (ObjectID, DWalletNetworkEncryptionKeyData) {
        (
            self.object_id,
            overlay_entry(self.object_id, epoch_id, self.dkg_at_epoch, vec![], vec![]),
        )
    }
}

/// Two keys whose id ordering is known.
fn two_ordered_keys(dkg_at_epoch: u64) -> (TestKey, TestKey) {
    let (a, b) = (ObjectID::random(), ObjectID::random());
    let (low, high) = if a < b { (a, b) } else { (b, a) };
    (
        TestKey::registered(low, dkg_at_epoch, "low key"),
        TestKey::registered(high, dkg_at_epoch, "high key"),
    )
}

/// A certificate naming `keys` — a DKG item and a reconfiguration item per
/// key, digests over the blobs the overlays carry, so adoption's digest gate
/// admits each key once its blobs are local.
fn certificate_naming(prior_epoch: u64, keys: &[&TestKey]) -> CertifiedHandoffAttestation {
    let mut items: Vec<_> = keys
        .iter()
        .flat_map(|key| {
            [
                (
                    HandoffItemKey::NetworkDkgOutput {
                        key_id: key.network_key_id,
                    },
                    mpc_data_blob_hash(&key.dkg),
                ),
                (
                    HandoffItemKey::NetworkReconfigurationOutput {
                        key_id: key.network_key_id,
                    },
                    mpc_data_blob_hash(&key.reconfiguration),
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

/// Two validators at the same epoch, with `noa_checkpoints` on.
struct TwoValidators {
    services: Vec<crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService>,
    senders: Vec<crate::SuiDataSenders>,
    epoch_stores: Vec<Arc<utils::TestingAuthorityPerEpochStore>>,
    epoch_id: u64,
    prior_epoch: u64,
}

impl TwoValidators {
    fn build() -> Self {
        let (services, senders, _collectors, epoch_stores, _notify, _requests, _outputs) =
            utils::create_dwallet_mpc_services(2);
        let epoch_id = services.first().expect("two services").epoch;
        Self {
            services,
            senders,
            epoch_stores,
            epoch_id,
            prior_epoch: epoch_id - 1,
        }
    }

    /// The certificate is network-uniform: every validator is handed the
    /// same one.
    fn install_certificate(&self, certificate: &CertifiedHandoffAttestation) {
        for epoch_store in &self.epoch_stores {
            epoch_store
                .certified_handoff_attestations
                .lock()
                .unwrap()
                .insert(self.prior_epoch, certificate.clone());
        }
    }

    /// Publishes `overlay` as validator `index`'s network-key watch value —
    /// what the selector reads `dkg_at_epoch` from — and runs its adoption
    /// pass over the same overlay.
    fn publish_and_adopt(
        &mut self,
        index: usize,
        overlay: &Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>,
    ) {
        self.senders[index]
            .network_keys_sender
            .send(overlay.clone())
            .expect("the service holds the overlay receiver");
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

    fn resolution(&self, index: usize) -> NetworkOwnedAddressSigningKeyResolution {
        self.services[index]
            .dwallet_mpc_manager()
            .network_owned_address_signing_key_resolution()
    }
}

/// Two validators with the same certificate but different adopted sets — one
/// holding both certified keys, the other only the higher-id one because the
/// low key's blobs have not reached its local cache (adoption skips a
/// blob-empty entry) — name the same key. Under the previous adopted-set rule
/// this was the shape that diverged (issue #2019, per-key overlay
/// incompleteness).
#[tokio::test]
async fn same_certificate_with_different_adopted_sets_selects_the_same_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let (low, high) = two_ordered_keys(0);
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&low, &high]));

    let complete = Arc::new(HashMap::from([
        low.complete_entry(epoch_id),
        high.complete_entry(epoch_id),
    ]));
    let low_blobs_missing = Arc::new(HashMap::from([
        low.blob_empty_entry(epoch_id),
        high.complete_entry(epoch_id),
    ]));
    validators.publish_and_adopt(0, &complete);
    validators.publish_and_adopt(1, &low_blobs_missing);

    // Control: the adopted sets really differ.
    assert_eq!(validators.adopted_keys(0), {
        let mut both = vec![low.object_id, high.object_id];
        both.sort();
        both
    });
    assert_eq!(validators.adopted_keys(1), vec![high.object_id]);

    // Both keys are certified with the same `dkg_at_epoch`, so the tie-break
    // names the smaller id — on BOTH validators, including the one that has
    // not adopted it.
    let (first, second) = (validators.selected_key(0), validators.selected_key(1));
    tracing::info!(?first, ?second, "selected NOA signing keys");
    assert_eq!(first, Some(low.object_id));
    assert_eq!(
        second,
        Some(low.object_id),
        "the selector must name the certified key even though this validator has not \
         adopted it"
    );
    assert_eq!(first, second);
}

/// A validator that has adopted NOTHING — every overlay entry still
/// blob-empty, the epoch-start fill window of issue #2019 — names the same
/// key as a peer that has adopted everything.
#[tokio::test]
async fn a_validator_that_adopted_nothing_selects_the_same_key() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let (low, high) = two_ordered_keys(0);
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&low, &high]));

    let complete = Arc::new(HashMap::from([
        low.complete_entry(epoch_id),
        high.complete_entry(epoch_id),
    ]));
    let metadata_only = Arc::new(HashMap::from([
        low.blob_empty_entry(epoch_id),
        high.blob_empty_entry(epoch_id),
    ]));
    validators.publish_and_adopt(0, &complete);
    validators.publish_and_adopt(1, &metadata_only);

    assert_eq!(validators.adopted_keys(1), Vec::<ObjectID>::new());
    assert_eq!(validators.selected_key(0), Some(low.object_id));
    assert_eq!(
        validators.selected_key(1),
        Some(low.object_id),
        "an empty adopted set must not stop the derivation: the certificate names the keys \
         and the overlay carries their metadata"
    );
}

/// A validator whose overlay has no entry at all for one certified key — its
/// chain metadata is not known locally yet — answers `None`, never the other
/// certified key it can see, and resolves once the metadata lands.
#[tokio::test]
async fn missing_metadata_for_a_certified_key_yields_none_not_a_partial_choice() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let (low, high) = two_ordered_keys(0);
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&low, &high]));

    let complete = Arc::new(HashMap::from([
        low.complete_entry(epoch_id),
        high.complete_entry(epoch_id),
    ]));
    let low_unknown = Arc::new(HashMap::from([high.complete_entry(epoch_id)]));
    validators.publish_and_adopt(0, &complete);
    validators.publish_and_adopt(1, &low_unknown);

    assert_eq!(validators.selected_key(0), Some(low.object_id));
    assert_eq!(
        validators.selected_key(1),
        None,
        "a certified key with no local metadata must yield None, not a choice among the rest"
    );
    assert_eq!(
        validators.resolution(1),
        NetworkOwnedAddressSigningKeyResolution::Pending
    );

    validators.publish_and_adopt(1, &complete);
    assert_eq!(
        validators.selected_key(1),
        Some(low.object_id),
        "the derivation resolves forward once the metadata lands"
    );
}

/// A certified key with no `NetworkKeyId -> ObjectID` translation yet — the
/// joiner / restart shape, where the mapping registers only when the key is
/// instantiated or derived in the background — yields `None` on every
/// validator, and resolves once the mapping registers.
#[tokio::test]
async fn an_untranslatable_certified_key_yields_none_until_its_mapping_registers() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let (low, _high) = two_ordered_keys(0);
    // A newer key whose `NetworkKeyId` is not derived from its `ObjectID` and
    // is NOT registered: the certificate names it, nothing translates it.
    let newer = TestKey {
        object_id: ObjectID::random(),
        network_key_id: NetworkKeyId(rand::random()),
        dkg_at_epoch: 1,
        dkg: b"newer key dkg output".to_vec(),
        reconfiguration: b"newer key reconfiguration output".to_vec(),
    };
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&low, &newer]));

    // Both validators know both keys' metadata; adoption is only handed the
    // translatable one (an unmapped key would spawn a background derivation
    // over these placeholder blobs).
    let overlay = Arc::new(HashMap::from([
        low.complete_entry(epoch_id),
        newer.complete_entry(epoch_id),
    ]));
    let adoptable = Arc::new(HashMap::from([low.complete_entry(epoch_id)]));
    for index in 0..2 {
        validators.senders[index]
            .network_keys_sender
            .send(overlay.clone())
            .expect("the service holds the overlay receiver");
        validators.services[index]
            .dwallet_mpc_manager_mut()
            .adopt_cert_verified_keys(&adoptable);
    }

    for index in 0..2 {
        assert_eq!(
            validators.selected_key(index),
            None,
            "validator {index} must not choose among the keys it can translate"
        );
        assert_eq!(
            validators.resolution(index),
            NetworkOwnedAddressSigningKeyResolution::Pending
        );
    }

    network_key_id_mapping::register(newer.object_id, newer.network_key_id);
    for index in 0..2 {
        assert_eq!(
            validators.selected_key(index),
            Some(newer.object_id),
            "once translatable, the newest certified key wins on validator {index}"
        );
    }
}

/// A key created by DKG after the certificate — in the epoch under test — is
/// not eligible this epoch, however new it is and however completely it is
/// adopted: the certificate is the sole input.
#[tokio::test]
async fn a_key_created_after_the_certificate_waits_one_epoch() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let (certified, _unused) = two_ordered_keys(0);
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&certified]));
    // DKG'd this epoch: registered, adoptable from its local DKG output
    // (nothing pins it yet), and the newest key on the network.
    let fresh = TestKey {
        reconfiguration: vec![],
        ..TestKey::registered(ObjectID::random(), epoch_id, "fresh key")
    };

    let overlay = Arc::new(HashMap::from([
        certified.complete_entry(epoch_id),
        fresh.complete_entry(epoch_id),
    ]));
    validators.publish_and_adopt(0, &overlay);
    validators.publish_and_adopt(1, &overlay);

    for index in 0..2 {
        assert!(
            validators.adopted_keys(index).contains(&fresh.object_id),
            "control: the fresh key is adopted on validator {index}"
        );
        assert_eq!(
            validators.selected_key(index),
            Some(certified.object_id),
            "a key the certificate does not name is not eligible this epoch (validator {index})"
        );
    }
}

/// The rule itself: the largest `dkg_at_epoch` wins, and among equals the
/// smaller `NetworkKeyId`.
#[tokio::test]
async fn the_newest_certified_key_wins_and_ties_break_to_the_smaller_id() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;

    let mut ids = [ObjectID::random(), ObjectID::random(), ObjectID::random()];
    ids.sort();
    let [oldest_smallest_id, newer_smaller_id, newer_larger_id] = ids;
    // The smallest id is the OLDEST key, so it must lose to both newer keys
    // despite winning every tie-break; the two newer keys tie on epoch.
    let oldest = TestKey::registered(oldest_smallest_id, 0, "oldest");
    let newer_small = TestKey::registered(newer_smaller_id, 1, "newer small");
    let newer_large = TestKey::registered(newer_larger_id, 1, "newer large");
    validators.install_certificate(&certificate_naming(
        validators.prior_epoch,
        &[&oldest, &newer_small, &newer_large],
    ));

    let overlay = Arc::new(HashMap::from([
        oldest.complete_entry(epoch_id),
        newer_small.complete_entry(epoch_id),
        newer_large.complete_entry(epoch_id),
    ]));
    validators.publish_and_adopt(0, &overlay);
    validators.publish_and_adopt(1, &overlay);

    for index in 0..2 {
        assert_eq!(
            validators.selected_key(index),
            Some(newer_small.object_id),
            "validator {index}: largest dkg_at_epoch first, then the smaller NetworkKeyId"
        );
    }
}

/// The three resolution states, and that a resolved answer is cached for the
/// epoch: a later certificate read error or an overlay that has lost the
/// key's metadata cannot change or unset it.
#[tokio::test]
async fn the_resolution_states_and_the_cached_answer() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = utils::create_test_protocol_config_guard_with_noa_checkpoints();
    let mut validators = TwoValidators::build();
    let epoch_id = validators.epoch_id;
    let (key, _unused) = two_ordered_keys(0);
    let overlay = Arc::new(HashMap::from([key.complete_entry(epoch_id)]));
    validators.publish_and_adopt(0, &overlay);

    // No certificate for the prior epoch: no key this epoch, and NOA signing
    // waits for the first handoff.
    assert_eq!(
        validators.resolution(0),
        NetworkOwnedAddressSigningKeyResolution::NoneThisEpoch
    );
    assert_eq!(validators.selected_key(0), None);

    // A certificate read error is no answer at all — pending, not "none".
    validators.install_certificate(&certificate_naming(validators.prior_epoch, &[&key]));
    validators.epoch_stores[0]
        .fail_certified_handoff_attestation_reads
        .store(true, Ordering::Relaxed);
    assert_eq!(
        validators.resolution(0),
        NetworkOwnedAddressSigningKeyResolution::Pending
    );
    validators.epoch_stores[0]
        .fail_certified_handoff_attestation_reads
        .store(false, Ordering::Relaxed);

    assert_eq!(
        validators.resolution(0),
        NetworkOwnedAddressSigningKeyResolution::Resolved(key.object_id)
    );

    // Cached: neither a later read error nor an overlay without the key's
    // metadata moves the answer.
    validators.epoch_stores[0]
        .fail_certified_handoff_attestation_reads
        .store(true, Ordering::Relaxed);
    validators.senders[0]
        .network_keys_sender
        .send(Arc::new(HashMap::new()))
        .expect("the service holds the overlay receiver");
    assert_eq!(
        validators.resolution(0),
        NetworkOwnedAddressSigningKeyResolution::Resolved(key.object_id),
        "the answer is fixed for the epoch once derived"
    );
}
