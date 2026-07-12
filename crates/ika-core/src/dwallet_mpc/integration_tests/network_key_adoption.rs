// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Regression tests for the network-key adoption/instantiation
//! determinism gates.
//!
//! Live-incident background (2026-06-12 localnet, run 3): at an epoch
//! boundary one validator adopted overlay key data whose
//! reconfiguration output didn't match what its peers instantiated,
//! installed a parameter set the committee never agreed to run that
//! epoch, and then honestly computed internal-presign outputs that
//! byte-diverged from its peers'. The output-quorum byte-equality
//! tally convicted it as malicious, its consensus messages were
//! dropped, and the committee silently ran threshold-3-of-4 with zero
//! redundancy. The session's *message subsets* were ruled out as the
//! divergence source (the guaranteed-output-delivery layer pins the
//! advance subset to the first consensus round at which the threshold
//! holds, identically on every validator); the divergent input was the
//! session public input — the protocol public parameters derived from
//! the locally installed network key.
//!
//! The gates under test:
//! - `adopt_cert_verified_keys` must NOT adopt an overlay entry with
//!   an empty reconfiguration output for a key whose prior-epoch
//!   handoff cert pins a reconfiguration digest (a DKG-only
//!   instantiation derives parameters the committee never agreed on).
//! - `instantiate_adopted_network_keys` must NOT spawn an
//!   instantiation for adopted data whose `current_epoch` metadata
//!   doesn't match the manager's epoch (previously the mismatch was
//!   only rejected ~10s later, after the parameter derivation had
//!   already been burnt on the rayon pool).

use crate::dwallet_mpc::integration_tests::utils;
use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use std::sync::Arc;
use sui_types::base_types::ObjectID;

fn network_key_data(
    key_id: ObjectID,
    current_epoch: u64,
    network_dkg_public_output: Vec<u8>,
    current_reconfiguration_public_output: Vec<u8>,
) -> DWalletNetworkEncryptionKeyData {
    DWalletNetworkEncryptionKeyData {
        id: key_id,
        current_epoch,
        dkg_at_epoch: 0,
        network_dkg_public_output,
        current_reconfiguration_public_output,
        state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
    }
}

/// An overlay entry whose reconfiguration output is (transiently) empty
/// must not be adopted through the initial-DKG branch when the prior
/// epoch's handoff cert pins a reconfiguration digest for the key — and
/// must be adopted once the overlay carries the cert-pinned bytes.
#[tokio::test]
async fn empty_reconfiguration_overlay_is_not_adopted_when_cert_pins_reconfiguration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        mut dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
        _network_owned_address_sign_request_senders,
        _network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(1);
    let service = dwallet_mpc_services.first_mut().unwrap();
    let epoch_id = service.epoch;
    let prior_epoch = epoch_id - 1;

    let key_id = ObjectID::random();
    // The cert is keyed by NetworkKeyId; register the mapping so adopt can
    // translate this overlay key's ObjectID to it.
    let network_key_id = NetworkKeyId([0x42; 32]);
    crate::network_key_id_mapping::register(key_id, network_key_id);
    let dkg_output = b"test network dkg public output".to_vec();
    let reconfiguration_output = b"test network reconfiguration public output".to_vec();

    // The prior epoch's cert pins BOTH the stable DKG digest and the
    // epoch-specific reconfiguration digest for this key. Items must be
    // sorted by key (`HandoffItemKey`'s derived `Ord`: DKG < reconfiguration).
    let attestation = HandoffAttestation {
        epoch: prior_epoch,
        next_committee_pubkey_set_hash: [0u8; 32],
        items: vec![
            (
                HandoffItemKey::NetworkDkgOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&dkg_output),
            ),
            (
                HandoffItemKey::NetworkReconfigurationOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&reconfiguration_output),
            ),
        ],
    };
    epoch_stores
        .first()
        .unwrap()
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(
            prior_epoch,
            CertifiedHandoffAttestation {
                attestation,
                signatures: vec![],
            },
        );

    // Overlay with an EMPTY reconfiguration output: pre-fix this slipped
    // through the initial-DKG branch (DKG-digest check only) and
    // instantiated DKG-derived parameters.
    let empty_reconfiguration_overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(key_id, epoch_id, dkg_output.clone(), vec![]),
    )]));
    let manager = service.dwallet_mpc_manager_mut();
    manager.adopt_cert_verified_keys(&empty_reconfiguration_overlay);
    assert!(
        !manager.adopted_network_key_data.contains_key(&key_id),
        "an empty-reconfiguration overlay entry must not be adopted while the prior \
         epoch's cert pins a reconfiguration digest for the key"
    );

    // A non-empty reconfiguration output that MISMATCHES the cert must
    // also stay unadopted (pre-existing behavior, asserted as a guard).
    let mismatching_overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(
            key_id,
            epoch_id,
            dkg_output.clone(),
            b"some other reconfiguration bytes".to_vec(),
        ),
    )]));
    manager.adopt_cert_verified_keys(&mismatching_overlay);
    assert!(
        !manager.adopted_network_key_data.contains_key(&key_id),
        "a cert-mismatching reconfiguration output must not be adopted"
    );

    // Once the overlay carries the cert-pinned bytes, adoption proceeds.
    let matching_overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(
            key_id,
            epoch_id,
            dkg_output.clone(),
            reconfiguration_output.clone(),
        ),
    )]));
    manager.adopt_cert_verified_keys(&matching_overlay);
    let adopted = manager
        .adopted_network_key_data
        .get(&key_id)
        .expect("the cert-matching overlay entry must be adopted");
    assert_eq!(
        adopted.current_reconfiguration_public_output, reconfiguration_output,
        "the adopted data must carry the cert-pinned reconfiguration bytes"
    );
}

/// Adopted key data whose `current_epoch` metadata doesn't match the
/// manager's epoch must be rejected BEFORE spawning the expensive
/// instantiation — not ~10s later by the post-instantiation poll.
#[tokio::test]
async fn stale_epoch_network_key_data_is_not_spawned() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        mut dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        _epoch_stores,
        _notify_services,
        _network_owned_address_sign_request_senders,
        _network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(1);
    let service = dwallet_mpc_services.first_mut().unwrap();
    let epoch_id = service.epoch;
    let manager = service.dwallet_mpc_manager_mut();

    // Stale snapshot: the syncer fetched the chain object before the
    // chain rolled over to the manager's epoch.
    let stale_key_id = ObjectID::random();
    manager.adopted_network_key_data.insert(
        stale_key_id,
        network_key_data(
            stale_key_id,
            epoch_id - 1,
            b"dkg bytes".to_vec(),
            b"reconfiguration bytes".to_vec(),
        ),
    );
    manager.instantiate_adopted_network_keys();
    assert!(
        !manager
            .pending_network_key_instantiations
            .contains_key(&stale_key_id),
        "key data with a stale epoch must not spawn an instantiation"
    );

    // Current-epoch data for the same key spawns normally (the gate
    // discriminates on the epoch, not on the key).
    let current_key_id = ObjectID::random();
    manager.adopted_network_key_data.insert(
        current_key_id,
        network_key_data(
            current_key_id,
            epoch_id,
            b"dkg bytes".to_vec(),
            b"reconfiguration bytes".to_vec(),
        ),
    );
    manager.instantiate_adopted_network_keys();
    assert!(
        !manager
            .pending_network_key_instantiations
            .contains_key(&stale_key_id),
        "the stale-epoch key must still not spawn"
    );
    assert!(
        manager
            .pending_network_key_instantiations
            .contains_key(&current_key_id),
        "current-epoch key data must spawn an instantiation"
    );
}

/// The canonical network DKG output migrates V2->V3 exactly once — when the
/// cert-pinned reconfiguration output becomes V3 and the validator mirrors the
/// reconstructed full output. For that one epoch the overlay's DKG digest moves
/// past the PRIOR epoch's V2 cert. An ALREADY-adopted key must survive that
/// mismatch (keeping its adopted value), not be dropped — mirroring how a moved
/// reconfiguration output is tolerated. (An unadopted key contradicting the cert
/// is still rejected; covered by the empty-overlay test above.)
#[tokio::test]
async fn already_adopted_key_survives_dkg_output_migration() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        mut dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
        _network_owned_address_sign_request_senders,
        _network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(1);
    let service = dwallet_mpc_services.first_mut().unwrap();
    let epoch_id = service.epoch;
    let prior_epoch = epoch_id - 1;

    let key_id = ObjectID::random();
    let network_key_id = NetworkKeyId([0x42; 32]);
    crate::network_key_id_mapping::register(key_id, network_key_id);

    let v2_dkg_output = b"v2 anchor network dkg output".to_vec();
    let reconfiguration_output = b"v3 network reconfiguration output".to_vec();

    // The prior epoch's cert pins the V2 DKG digest and the reconfiguration
    // digest (items sorted by `HandoffItemKey`: DKG < reconfiguration).
    let attestation = HandoffAttestation {
        epoch: prior_epoch,
        next_committee_pubkey_set_hash: [0u8; 32],
        items: vec![
            (
                HandoffItemKey::NetworkDkgOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&v2_dkg_output),
            ),
            (
                HandoffItemKey::NetworkReconfigurationOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&reconfiguration_output),
            ),
        ],
    };
    epoch_stores
        .first()
        .unwrap()
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(
            prior_epoch,
            CertifiedHandoffAttestation {
                attestation,
                signatures: vec![],
            },
        );

    let manager = service.dwallet_mpc_manager_mut();

    // First adopt: the overlay's V2 DKG output and reconfiguration output both
    // match the prior cert, so the key is adopted.
    let v2_overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(
            key_id,
            epoch_id,
            v2_dkg_output.clone(),
            reconfiguration_output.clone(),
        ),
    )]));
    manager.adopt_cert_verified_keys(&v2_overlay);
    assert!(
        manager.adopted_network_key_data.contains_key(&key_id),
        "the cert-matching V2 key must be adopted"
    );

    // Second adopt: the overlay's DKG output has migrated to a different (V3)
    // value while the prior cert still pins V2. The already-adopted key must
    // survive — kept at its adopted V2 value, not dropped, not overwritten by
    // the mismatching overlay.
    let v3_dkg_output = b"v3 reconstructed full network dkg output".to_vec();
    let v3_overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(
            key_id,
            epoch_id,
            v3_dkg_output,
            reconfiguration_output.clone(),
        ),
    )]));
    manager.adopt_cert_verified_keys(&v3_overlay);
    let adopted = manager
        .adopted_network_key_data
        .get(&key_id)
        .expect("the already-adopted key must survive the DKG-output migration");
    assert_eq!(
        adopted.network_dkg_public_output, v2_dkg_output,
        "the migration epoch keeps the prior adopted (V2) value, not the \
         mismatching overlay"
    );
}

/// A cert-referenced key whose `ObjectID` has no `NetworkKeyId` mapping
/// (a joiner that never instantiated the key — the mapping registers at
/// instantiation, which needs adoption first) must NOT be treated as
/// "not pinned by the cert": pre-fix, the reconfigured branch saw
/// `cert_dkg_digest=None`, warned a phantom mismatch, and wedged the key
/// uninstantiated forever (the v118_churn joiner deadlock). Adoption
/// must defer, spawn the background `NetworkKeyId` derivation exactly
/// once, skip the pass memoization so re-evaluation happens with
/// unchanged inputs, and proceed once the registration lands.
#[tokio::test]
async fn unmapped_cert_referenced_key_defers_and_spawns_derivation() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        mut dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
        _network_owned_address_sign_request_senders,
        _network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(1);
    let service = dwallet_mpc_services.first_mut().unwrap();
    let epoch_id = service.epoch;
    let prior_epoch = epoch_id - 1;

    // Deliberately NOT registered: the cert speaks NetworkKeyId, this
    // validator only knows the ObjectID.
    let key_id = ObjectID::random();
    let network_key_id = NetworkKeyId([0x51; 32]);
    let dkg_output = b"joiner network dkg public output".to_vec();
    let reconfiguration_output = b"joiner network reconfiguration public output".to_vec();

    // The prior epoch's cert pins both digests for the key (items sorted
    // by `HandoffItemKey`: DKG < reconfiguration).
    let attestation = HandoffAttestation {
        epoch: prior_epoch,
        next_committee_pubkey_set_hash: [0u8; 32],
        items: vec![
            (
                HandoffItemKey::NetworkDkgOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&dkg_output),
            ),
            (
                HandoffItemKey::NetworkReconfigurationOutput {
                    key_id: network_key_id,
                },
                mpc_data_blob_hash(&reconfiguration_output),
            ),
        ],
    };
    epoch_stores
        .first()
        .unwrap()
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(
            prior_epoch,
            CertifiedHandoffAttestation {
                attestation,
                signatures: vec![],
            },
        );

    let overlay = Arc::new(HashMap::from([(
        key_id,
        network_key_data(
            key_id,
            epoch_id,
            dkg_output.clone(),
            reconfiguration_output.clone(),
        ),
    )]));
    let manager = service.dwallet_mpc_manager_mut();
    manager.adopt_cert_verified_keys(&overlay);
    assert!(
        !manager.adopted_network_key_data.contains_key(&key_id),
        "an unmapped cert-referenced key must be deferred, not adopted"
    );
    assert!(
        manager.network_key_id_derivations_spawned.contains(&key_id),
        "the background NetworkKeyId derivation must be spawned for the unmapped key"
    );

    // Same overlay again: the deferral must have skipped the memoization
    // (so the pass re-evaluates) and must not respawn the derivation.
    manager.adopt_cert_verified_keys(&overlay);
    assert_eq!(
        manager.network_key_id_derivations_spawned.len(),
        1,
        "the derivation must be spawned at most once per key"
    );

    // Simulate the background derivation completing: registration alone —
    // with the overlay bytes unchanged — must unwedge adoption on the
    // next pass.
    crate::network_key_id_mapping::register(key_id, network_key_id);
    manager.adopt_cert_verified_keys(&overlay);
    let adopted = manager
        .adopted_network_key_data
        .get(&key_id)
        .expect("registration must unwedge cert-gated adoption with no overlay change");
    assert_eq!(
        adopted.current_reconfiguration_public_output, reconfiguration_output,
        "the adopted data must carry the cert-pinned reconfiguration bytes"
    );
}

/// THE invariant the internal-presign top-up loop builds on: every key in
/// `adopted_network_key_data` has a resolvable `NetworkKeyId`
/// (`internal_presign_network_key_id` returns `Some`). The per-pool
/// sequence/guard counters and the session identifier both key by the
/// content-derived `NetworkKeyId`, and the top-up loop treats an adopted
/// key that does not resolve as a should-never-happen skip — so adoption
/// (`adopt_cert_verified_keys`) must never admit an unmapped key on ANY
/// adoption branch (cert-anchored or cert-less): it defers until the
/// background derivation registers the `ObjectID → NetworkKeyId` mapping.
///
/// Drives the REAL adoption path in two phases and asserts the invariant
/// over the whole adopted set after every pass:
/// 1. cert-anchored — a cert pins two keys, one mapped, one not;
/// 2. cert-less (the v3/v3→v4-boundary path) — no cert at all, a fresh
///    unmapped key must STILL defer (pre-fix it was blindly adopted, so on
///    any fresh network's first v4 epoch the top-up loop's
///    should-never-happen skip fired routinely).
#[tokio::test]
async fn adopted_keys_always_resolve_a_network_key_id() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        mut dwallet_mpc_services,
        _sui_data_senders,
        _sent_consensus_messages_collectors,
        epoch_stores,
        _notify_services,
        _network_owned_address_sign_request_senders,
        _network_owned_address_sign_output_receivers,
    ) = utils::create_dwallet_mpc_services(1);
    let service = dwallet_mpc_services.first_mut().unwrap();
    let epoch_id = service.epoch;
    let prior_epoch = epoch_id - 1;

    // Two cert-pinned keys: one with a registered mapping, one without.
    let mapped_key_id = ObjectID::random();
    let mapped_network_key_id = NetworkKeyId([0x61; 32]);
    crate::network_key_id_mapping::register(mapped_key_id, mapped_network_key_id);
    let unmapped_key_id = ObjectID::random();
    let unmapped_network_key_id = NetworkKeyId([0x62; 32]);

    let mapped_dkg_output = b"mapped key network dkg public output".to_vec();
    let mapped_reconfiguration_output = b"mapped key reconfiguration public output".to_vec();
    let unmapped_dkg_output = b"unmapped key network dkg public output".to_vec();
    let unmapped_reconfiguration_output = b"unmapped key reconfiguration public output".to_vec();

    // Items sorted by `HandoffItemKey`'s derived `Ord` (all DKG items
    // before all reconfiguration items, then by key id within a variant).
    let mut dkg_items = vec![
        (
            HandoffItemKey::NetworkDkgOutput {
                key_id: mapped_network_key_id,
            },
            mpc_data_blob_hash(&mapped_dkg_output),
        ),
        (
            HandoffItemKey::NetworkDkgOutput {
                key_id: unmapped_network_key_id,
            },
            mpc_data_blob_hash(&unmapped_dkg_output),
        ),
    ];
    let mut reconfiguration_items = vec![
        (
            HandoffItemKey::NetworkReconfigurationOutput {
                key_id: mapped_network_key_id,
            },
            mpc_data_blob_hash(&mapped_reconfiguration_output),
        ),
        (
            HandoffItemKey::NetworkReconfigurationOutput {
                key_id: unmapped_network_key_id,
            },
            mpc_data_blob_hash(&unmapped_reconfiguration_output),
        ),
    ];
    dkg_items.sort_by(|(a, _), (b, _)| a.cmp(b));
    reconfiguration_items.sort_by(|(a, _), (b, _)| a.cmp(b));
    let items = dkg_items.into_iter().chain(reconfiguration_items).collect();
    let attestation = HandoffAttestation {
        epoch: prior_epoch,
        next_committee_pubkey_set_hash: [0u8; 32],
        items,
    };
    epoch_stores
        .first()
        .unwrap()
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(
            prior_epoch,
            CertifiedHandoffAttestation {
                attestation,
                signatures: vec![],
            },
        );

    let overlay = Arc::new(HashMap::from([
        (
            mapped_key_id,
            network_key_data(
                mapped_key_id,
                epoch_id,
                mapped_dkg_output.clone(),
                mapped_reconfiguration_output.clone(),
            ),
        ),
        (
            unmapped_key_id,
            network_key_data(
                unmapped_key_id,
                epoch_id,
                unmapped_dkg_output.clone(),
                unmapped_reconfiguration_output.clone(),
            ),
        ),
    ]));
    let manager = service.dwallet_mpc_manager_mut();

    // The invariant checked after every pass: nothing enters the adopted
    // set without a resolvable NetworkKeyId.
    let assert_all_adopted_resolve =
        |manager: &crate::dwallet_mpc::mpc_manager::DWalletMPCManager, pass: &str| {
            for key_id in manager.adopted_network_key_data.keys() {
                assert!(
                    manager.internal_presign_network_key_id(key_id).is_some(),
                    "{pass}: adopted key {key_id:?} has no resolvable NetworkKeyId — the \
                 internal-presign top-up loop would hit its should-never-happen skip"
                );
            }
        };

    manager.adopt_cert_verified_keys(&overlay);
    assert!(
        manager
            .adopted_network_key_data
            .contains_key(&mapped_key_id),
        "the mapped cert-matching key must be adopted"
    );
    assert!(
        !manager
            .adopted_network_key_data
            .contains_key(&unmapped_key_id),
        "the unmapped key must be deferred, not adopted"
    );
    assert_all_adopted_resolve(manager, "after the first pass");

    // The background derivation lands: the unmapped key becomes mapped and
    // the next pass adopts it. The invariant must hold over BOTH keys.
    crate::network_key_id_mapping::register(unmapped_key_id, unmapped_network_key_id);
    manager.adopt_cert_verified_keys(&overlay);
    assert!(
        manager
            .adopted_network_key_data
            .contains_key(&unmapped_key_id),
        "registration must let the deferred key be adopted on the next pass"
    );
    assert_all_adopted_resolve(manager, "after the registration pass");

    // === Phase 2: the CERT-LESS adoption branch (v3 / v3→v4 boundary) ===
    // Remove the cert entirely: a fresh unmapped key arriving through the
    // cert-less path must be deferred exactly like the cert-anchored case —
    // pre-fix this branch blindly adopted it, violating the invariant on any
    // fresh network's first v4 epoch.
    epoch_stores
        .first()
        .unwrap()
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .remove(&prior_epoch);
    let certless_key_id = ObjectID::random();
    let certless_network_key_id = NetworkKeyId([0x63; 32]);
    let certless_dkg_output = b"certless key network dkg public output".to_vec();
    let certless_reconfiguration_output = b"certless key reconfiguration public output".to_vec();
    let certless_overlay = Arc::new(HashMap::from([(
        certless_key_id,
        network_key_data(
            certless_key_id,
            epoch_id,
            certless_dkg_output.clone(),
            certless_reconfiguration_output.clone(),
        ),
    )]));
    let manager = service.dwallet_mpc_manager_mut();
    manager.adopt_cert_verified_keys(&certless_overlay);
    assert!(
        !manager
            .adopted_network_key_data
            .contains_key(&certless_key_id),
        "an unmapped key must be deferred on the CERT-LESS adoption branch too"
    );
    assert!(
        manager
            .network_key_id_derivations_spawned
            .contains(&certless_key_id),
        "the background NetworkKeyId derivation must be spawned for the cert-less unmapped key"
    );
    assert_all_adopted_resolve(manager, "after the cert-less deferral pass");

    // Registration unwedges the cert-less branch the same way.
    crate::network_key_id_mapping::register(certless_key_id, certless_network_key_id);
    manager.adopt_cert_verified_keys(&certless_overlay);
    assert!(
        manager
            .adopted_network_key_data
            .contains_key(&certless_key_id),
        "registration must let the cert-less deferred key be adopted on the next pass"
    );
    assert_all_adopted_resolve(manager, "after the cert-less registration pass");
}
