// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Regression tests for issue #1879: the manager must acquire the CURRENT
//! epoch's validator MPC key bundle from durable, consensus-agreed state —
//! the prior epoch's handoff certificate plus the perpetual blob store —
//! because the production watch-channel delivery happens once, in a boundary
//! window a mid-epoch restart cannot replay (the channel is process-local).
//! The tests also pin the divergence guard: with a prior cert present, the
//! manager must NEVER fall back to the channel, whose post-freeze content
//! (the current epoch's frozen set) can be a strict superset of the boundary
//! set the rest of the committee latched.

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::dwallet_mpc::authority_name_to_party_id_from_committee;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::create_test_protocol_config_guard;
use crate::validator_metadata::OffChainCommitteeBundles;
use dwallet_mpc_types::dwallet_mpc::{MPCDataV1, VersionedMPCData};
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::ValidatorEncryptionKeysAndProofs;
use ika_types::crypto::AuthorityName;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};
use std::sync::Arc;

/// Rebuilds a validator's canonical mpc_data blob (`VersionedMPCData::V1`
/// over `ValidatorEncryptionKeysAndProofs`) from the test bundles — the same
/// bytes `derive_mpc_data_blob` produces from the validator's root seed,
/// without re-running the class-groups derivation.
fn mpc_data_blob_for(bundles: &OffChainCommitteeBundles, authority: &AuthorityName) -> Vec<u8> {
    let keys = ValidatorEncryptionKeysAndProofs {
        class_groups: bundles.class_groups[authority].clone(),
        secp256k1_pvss: bundles.secp256k1_pvss[authority].clone(),
        secp256r1_pvss: bundles.secp256r1_pvss[authority].clone(),
        ristretto_pvss: bundles.ristretto_pvss[authority].clone(),
        vss_hpke_public_key_and_proof: bundles.vss_hpke[authority].clone(),
    };
    let mpc_data_bytes = bcs::to_bytes(&keys).expect("encode ValidatorEncryptionKeysAndProofs");
    bcs::to_bytes(&VersionedMPCData::V1(MPCDataV1 { mpc_data_bytes })).expect("encode blob")
}

fn cert_with_mpc_data(
    prior_epoch: u64,
    entries: &[(AuthorityName, [u8; 32])],
) -> CertifiedHandoffAttestation {
    CertifiedHandoffAttestation {
        attestation: HandoffAttestation {
            epoch: prior_epoch,
            next_committee_pubkey_set_hash: [0u8; 32],
            items: entries
                .iter()
                .map(|(validator, digest)| {
                    (
                        HandoffItemKey::ValidatorMpcData {
                            validator: *validator,
                        },
                        *digest,
                    )
                })
                .collect(),
        },
        signatures: vec![],
    }
}

/// The mid-epoch-restart shape: a fresh process has NOTHING on the
/// current-epoch key channel (it is process-local, and the boundary-window
/// delivery already happened in the previous process's lifetime). With the
/// prior epoch's cert and the blobs in the perpetual store — both of which
/// survive a restart — ingestion must complete anyway.
#[tokio::test]
async fn mid_epoch_restart_ingests_keys_without_channel_delivery() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);
    let (mut services, sui_data_senders, _stores, epoch_stores, ..) =
        utils::create_dwallet_mpc_services_with_committee_and_seeds(
            committee.clone(),
            seeds,
            bundles.clone(),
        );
    let service = services.first_mut().unwrap();
    let epoch_id = service.dwallet_mpc_manager().epoch_id;
    let prior_epoch = epoch_id - 1;

    // Simulate the restart: clear the helper's pre-seeded channel delivery —
    // a fresh process's watch channel starts empty.
    let _ = sui_data_senders
        .first()
        .unwrap()
        .current_epoch_mpc_keys_sender
        .send(None);

    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    let members: Vec<AuthorityName> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let cert_entries: Vec<(AuthorityName, [u8; 32])> = members
        .iter()
        .map(|authority| {
            let blob = mpc_data_blob_for(&bundles, authority);
            let digest = mpc_data_blob_hash(&blob);
            perpetual
                .insert_mpc_artifact_blob(digest, &blob)
                .expect("blob insert");
            (*authority, digest)
        })
        .collect();
    let epoch_store = epoch_stores.first().unwrap();
    epoch_store
        .perpetual_tables
        .lock()
        .unwrap()
        .replace(perpetual);
    epoch_store
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(prior_epoch, cert_with_mpc_data(prior_epoch, &cert_entries));

    let manager = service.dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        manager.current_epoch_keys_ingested,
        "cert + perpetual blobs must suffice to ingest the current-epoch keys \
         with an empty channel (the mid-epoch-restart shape)"
    );
    assert_eq!(
        manager.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
        members.len(),
        "every cert-covered committee member must be dealt"
    );
    assert_eq!(
        manager
            .validator_mpc_keys_by_party_id
            .vss_hpke_verified_party_encryption_key_values
            .len(),
        members.len(),
        "the VSS HPKE keys (consumed by VSS presign public inputs) must be \
         rebuilt from the cert-sourced bundle"
    );
}

/// With a prior cert present, the cert set is authoritative even when the
/// channel holds a WIDER bundle. Production shape: the channel's post-freeze
/// content is the current epoch's frozen set, which in a joiner-churn epoch
/// is a strict superset of the boundary set the rest of the committee
/// latched — ingesting it would byte-diverge this validator's VSS presign
/// public inputs from every peer's.
#[tokio::test]
async fn prior_cert_set_wins_over_wider_channel_bundle() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);
    let (mut services, _senders, _stores, epoch_stores, ..) =
        utils::create_dwallet_mpc_services_with_committee_and_seeds(
            committee.clone(),
            seeds,
            bundles.clone(),
        );
    let service = services.first_mut().unwrap();
    let epoch_id = service.dwallet_mpc_manager().epoch_id;
    let prior_epoch = epoch_id - 1;

    // The service helper pre-seeded the channel with the FULL 4-member
    // bundle; the cert covers only 3 (the fourth is the excluded-joiner
    // shape — no prior-cert digest).
    let members: Vec<AuthorityName> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let covered = &members[..3];
    let uncovered_member = members[3];

    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    let cert_entries: Vec<(AuthorityName, [u8; 32])> = covered
        .iter()
        .map(|authority| {
            let blob = mpc_data_blob_for(&bundles, authority);
            let digest = mpc_data_blob_hash(&blob);
            perpetual
                .insert_mpc_artifact_blob(digest, &blob)
                .expect("blob insert");
            (*authority, digest)
        })
        .collect();
    let epoch_store = epoch_stores.first().unwrap();
    epoch_store
        .perpetual_tables
        .lock()
        .unwrap()
        .replace(perpetual);
    epoch_store
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(prior_epoch, cert_with_mpc_data(prior_epoch, &cert_entries));

    let manager = service.dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(manager.current_epoch_keys_ingested);
    assert_eq!(
        manager.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
        covered.len(),
        "the ingested set must be the cert set (3 members), not the wider \
         channel bundle (4 members)"
    );
    let uncovered_party =
        authority_name_to_party_id_from_committee(&committee, &uncovered_member).expect("party id");
    assert!(
        !manager
            .validator_mpc_keys_by_party_id
            .secp256k1_pvss
            .contains_key(&uncovered_party),
        "a member without a prior-cert digest must not be dealt, even though \
         the channel bundle carries its keys"
    );
}

/// A missing blob for a cert-pinned digest must DEFER ingestion (retry when
/// the blob propagates), never fall back to the channel — the channel bundle
/// is not the committee-agreed set whenever a cert exists.
#[tokio::test]
async fn missing_prior_cert_blob_defers_without_channel_fallback() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _guard = create_test_protocol_config_guard();

    let (committee, seeds, bundles) = utils::build_committee_with_random_seeds(4);
    let (mut services, _senders, _stores, epoch_stores, ..) =
        utils::create_dwallet_mpc_services_with_committee_and_seeds(
            committee.clone(),
            seeds,
            bundles.clone(),
        );
    let service = services.first_mut().unwrap();
    let epoch_id = service.dwallet_mpc_manager().epoch_id;
    let prior_epoch = epoch_id - 1;

    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    let members: Vec<AuthorityName> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect();
    // Cert pins all four members, but only three blobs are locally present.
    let mut withheld_blob: Option<([u8; 32], Vec<u8>)> = None;
    let cert_entries: Vec<(AuthorityName, [u8; 32])> = members
        .iter()
        .enumerate()
        .map(|(index, authority)| {
            let blob = mpc_data_blob_for(&bundles, authority);
            let digest = mpc_data_blob_hash(&blob);
            if index == 3 {
                withheld_blob = Some((digest, blob));
            } else {
                perpetual
                    .insert_mpc_artifact_blob(digest, &blob)
                    .expect("blob insert");
            }
            (*authority, digest)
        })
        .collect();
    let epoch_store = epoch_stores.first().unwrap();
    epoch_store
        .perpetual_tables
        .lock()
        .unwrap()
        .replace(perpetual.clone());
    epoch_store
        .certified_handoff_attestations
        .lock()
        .unwrap()
        .insert(prior_epoch, cert_with_mpc_data(prior_epoch, &cert_entries));

    let manager = service.dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        !manager.current_epoch_keys_ingested,
        "a missing cert-pinned blob must defer ingestion — falling back to \
         the channel's complete bundle here would ingest a set the committee \
         did not agree on"
    );

    // The blob propagates (production: P2P fetch / consensus replication) —
    // the next service iteration completes the ingest.
    let (digest, blob) = withheld_blob.expect("withheld blob");
    perpetual
        .insert_mpc_artifact_blob(digest, &blob)
        .expect("late blob insert");
    let manager = services.first_mut().unwrap().dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        manager.current_epoch_keys_ingested,
        "ingestion must complete once the missing blob lands"
    );
    assert_eq!(
        manager.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
        members.len(),
    );
}
