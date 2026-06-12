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
                HandoffItemKey::NetworkDkgOutput { key_id },
                mpc_data_blob_hash(&dkg_output),
            ),
            (
                HandoffItemKey::NetworkReconfigurationOutput { key_id },
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
        !manager.agreed_network_key_data.contains_key(&key_id),
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
        !manager.agreed_network_key_data.contains_key(&key_id),
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
        .agreed_network_key_data
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
    manager.agreed_network_key_data.insert(
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
    manager.agreed_network_key_data.insert(
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
