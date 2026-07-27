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
use crate::blob_cache::BlobCache;
use crate::dwallet_mpc::authority_name_to_party_id_from_committee;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::create_test_protocol_config_guard;
use crate::epoch_tasks::peer_blob_fetcher::fetch_missing_prior_cert_mpc_data_blobs;
use crate::validator_metadata::OffChainCommitteeBundles;
use anemo::{Network, PeerId, Router};
use dwallet_mpc_types::dwallet_mpc::{MPCDataV1, VersionedMPCData};
use ika_network::mpc_artifacts::{
    AnnouncementRelayHandle, HandoffCertStorage, InMemoryBlobStore, build_server,
    mpc_data_blob_hash,
};
use ika_types::committee::{EpochId, ValidatorEncryptionKeysAndProofs};
use ika_types::crypto::AuthorityName;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};
use prometheus::{IntCounterVec, Opts};
use std::collections::HashMap;
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

/// Test-local cert store for the serving peer's Anemo endpoint — the test
/// fetches blobs, not certs.
struct NoHandoffCerts;

impl HandoffCertStorage for NoHandoffCerts {
    fn get(&self, _epoch: EpochId) -> Option<CertifiedHandoffAttestation> {
        None
    }
}

fn build_test_network(router: Router) -> Network {
    Network::bind("localhost:0")
        .private_key(rand::random::<[u8; 32]>())
        .server_name("mid-epoch-restart-keys-test")
        .start(router)
        .expect("bind test anemo network")
}

/// The permanent-wedge shape of issue #1881: the perpetual store never held
/// one carried-forward member's cert-pinned blob — the member has been dark
/// for epochs, so it never re-announces, and this host's store post-dates
/// its last announcement. The cert-path deferral must not retry the same
/// local store forever: the peer-blob fetcher's prior-cert repair fetches
/// the missing blob from any committee peer over the real Anemo blob
/// endpoint (content-addressed, cert-digest-verified), persists it to the
/// perpetual store, and the next ingest attempt completes.
#[tokio::test(flavor = "multi_thread")]
async fn missing_prior_cert_blob_is_refetched_from_peers_and_ingested() {
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
    let own_authority = service.name;
    let epoch_id = service.dwallet_mpc_manager().epoch_id;
    let prior_epoch = epoch_id - 1;

    // Restart shape: a fresh process's watch channel starts empty.
    let _ = sui_data_senders
        .first()
        .unwrap()
        .current_epoch_mpc_keys_sender
        .send(None);

    let members: Vec<AuthorityName> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect();
    // The dark member whose blob this host never stored, and the live
    // committee peer that will serve it — both distinct from this
    // validator.
    let dark_member = *members
        .iter()
        .rev()
        .find(|member| **member != own_authority)
        .expect("committee has peers");
    let serving_member = *members
        .iter()
        .find(|member| **member != own_authority && **member != dark_member)
        .expect("committee has a second peer");

    // Cert pins all four members, but the dark member's blob is absent
    // from the local perpetual store.
    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    let mut dark_member_blob: Option<([u8; 32], Vec<u8>)> = None;
    let cert_entries: Vec<(AuthorityName, [u8; 32])> = members
        .iter()
        .map(|authority| {
            let blob = mpc_data_blob_for(&bundles, authority);
            let digest = mpc_data_blob_hash(&blob);
            if *authority == dark_member {
                dark_member_blob = Some((digest, blob));
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

    // Before the repair: ingestion defers, and the deferral is visible as
    // a metric (issue #1881's wedge presented only as absent advances).
    let manager = service.dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        !manager.current_epoch_keys_ingested,
        "a missing cert-pinned blob must defer ingestion"
    );
    assert_eq!(
        manager.dwallet_mpc_metrics.prior_cert_blobs_missing.get(),
        1,
        "the deferral must be scrapable via ika_dwallet_mpc_prior_cert_blobs_missing"
    );

    // A live committee peer serving the dark member's blob over the real
    // Anemo blob endpoint — any holder is authoritative (the blob is
    // content-addressed and pinned by the quorum-signed cert).
    let (dark_digest, dark_blob) = dark_member_blob.expect("dark member blob");
    let serving_store = InMemoryBlobStore::new();
    serving_store.insert(dark_digest, dark_blob);
    let server = build_server(
        serving_store,
        AnnouncementRelayHandle::new(),
        Arc::new(NoHandoffCerts),
    );
    let peer_network = build_test_network(Router::new().add_rpc_service(server));
    let local_network = build_test_network(Router::new());
    let live_peer_id = local_network
        .connect(peer_network.local_addr())
        .await
        .expect("connect to serving peer");

    // The dark owner maps to an unreachable peer id (it is down — that is
    // the scenario), forcing the repair through the any-holder fallback.
    let authority_names_to_peer_ids: HashMap<AuthorityName, PeerId> = HashMap::from([
        (dark_member, PeerId([0u8; 32])),
        (serving_member, live_peer_id),
    ]);
    let blob_cache = BlobCache::new(InMemoryBlobStore::new(), perpetual.clone());
    let fetch_outcomes = IntCounterVec::new(
        Opts::new("test_mpc_data_blob_fetch_total", "test fetch outcomes"),
        &["result"],
    )
    .expect("counter");
    let fetched = fetch_missing_prior_cert_mpc_data_blobs(
        &cert_with_mpc_data(prior_epoch, &cert_entries),
        own_authority,
        &blob_cache,
        &local_network,
        &authority_names_to_peer_ids,
        &HashMap::new(),
        &fetch_outcomes,
    )
    .await;
    assert_eq!(
        fetched, 1,
        "the dark member's cert-pinned blob must be fetched from the live peer"
    );
    assert_eq!(
        fetch_outcomes.with_label_values(&["ok"]).get(),
        1,
        "the repair must record its fetch outcome on the shared counter"
    );
    assert!(
        perpetual
            .get_mpc_artifact_blob(&dark_digest)
            .expect("perpetual read")
            .is_some(),
        "the fetched blob must be persisted to the perpetual store the \
         manager assembles against"
    );

    // Next service iteration: the retry finds the repaired store and
    // ingests — not RetryLater forever.
    let manager = services.first_mut().unwrap().dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        manager.current_epoch_keys_ingested,
        "ingestion must complete after the peer refetch"
    );
    assert_eq!(
        manager.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
        members.len(),
        "every cert-covered committee member must be dealt, including the \
         refetched dark member"
    );
    assert_eq!(
        manager.dwallet_mpc_metrics.prior_cert_blobs_missing.get(),
        0,
        "the gauge must return to 0 once assembly completes"
    );
}

/// The compound case observed live on testnet: the cert-pinned member is
/// ALIVE and reachable — it keeps signing and participating in consensus —
/// but MPC-dead: it never announced this epoch, so its own blob store lacks
/// its blob and its Anemo endpoint answers `GetMpcDataBlob` with not-found.
/// Distinct from the fully-dark case (unreachable peer) above: the repair
/// must fall through from the owner's not-found answer to another live
/// committee holder, persist, and let ingestion complete — recording both
/// the owner's `not_found` and the eventual `ok` on the shared
/// fetch-outcomes counter.
#[tokio::test(flavor = "multi_thread")]
async fn mpc_dead_owner_not_found_falls_through_to_live_holder() {
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
    let own_authority = service.name;
    let epoch_id = service.dwallet_mpc_manager().epoch_id;
    let prior_epoch = epoch_id - 1;

    // Restart shape: a fresh process's watch channel starts empty.
    let _ = sui_data_senders
        .first()
        .unwrap()
        .current_epoch_mpc_keys_sender
        .send(None);

    let members: Vec<AuthorityName> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect();
    // The MPC-dead member whose blob this host never stored, and the live
    // committee holder that will serve it — both distinct from this
    // validator.
    let dead_member = *members
        .iter()
        .rev()
        .find(|member| **member != own_authority)
        .expect("committee has peers");
    let holder_member = *members
        .iter()
        .find(|member| **member != own_authority && **member != dead_member)
        .expect("committee has a second peer");

    // Cert pins all four members, but the MPC-dead member's blob is absent
    // from the local perpetual store.
    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    let mut dead_member_blob: Option<([u8; 32], Vec<u8>)> = None;
    let cert_entries: Vec<(AuthorityName, [u8; 32])> = members
        .iter()
        .map(|authority| {
            let blob = mpc_data_blob_for(&bundles, authority);
            let digest = mpc_data_blob_hash(&blob);
            if *authority == dead_member {
                dead_member_blob = Some((digest, blob));
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
        "a missing cert-pinned blob must defer ingestion"
    );

    // The MPC-dead owner is reachable but has nothing to serve (empty blob
    // store — it never announced this epoch); a live committee holder
    // serves the blob.
    let (dead_digest, dead_blob) = dead_member_blob.expect("dead member blob");
    let owner_network = build_test_network(Router::new().add_rpc_service(build_server(
        InMemoryBlobStore::new(),
        AnnouncementRelayHandle::new(),
        Arc::new(NoHandoffCerts),
    )));
    let holder_store = InMemoryBlobStore::new();
    holder_store.insert(dead_digest, dead_blob);
    let holder_network = build_test_network(Router::new().add_rpc_service(build_server(
        holder_store,
        AnnouncementRelayHandle::new(),
        Arc::new(NoHandoffCerts),
    )));
    let local_network = build_test_network(Router::new());
    let owner_peer_id = local_network
        .connect(owner_network.local_addr())
        .await
        .expect("connect to MPC-dead owner");
    let holder_peer_id = local_network
        .connect(holder_network.local_addr())
        .await
        .expect("connect to live holder");
    let authority_names_to_peer_ids: HashMap<AuthorityName, PeerId> = HashMap::from([
        (dead_member, owner_peer_id),
        (holder_member, holder_peer_id),
    ]);

    let blob_cache = BlobCache::new(InMemoryBlobStore::new(), perpetual.clone());
    let fetch_outcomes = IntCounterVec::new(
        Opts::new("test_mpc_data_blob_fetch_total", "test fetch outcomes"),
        &["result"],
    )
    .expect("counter");
    let fetched = fetch_missing_prior_cert_mpc_data_blobs(
        &cert_with_mpc_data(prior_epoch, &cert_entries),
        own_authority,
        &blob_cache,
        &local_network,
        &authority_names_to_peer_ids,
        &HashMap::new(),
        &fetch_outcomes,
    )
    .await;
    assert_eq!(
        fetched, 1,
        "the repair must fall through from the owner's not-found to the \
         live holder"
    );
    assert_eq!(
        fetch_outcomes.with_label_values(&["not_found"]).get(),
        1,
        "the reachable-but-empty owner must be recorded as not_found"
    );
    assert_eq!(
        fetch_outcomes.with_label_values(&["ok"]).get(),
        1,
        "the holder's serve must be recorded as ok"
    );
    assert!(
        perpetual
            .get_mpc_artifact_blob(&dead_digest)
            .expect("perpetual read")
            .is_some(),
        "the fetched blob must be persisted to the perpetual store"
    );

    let manager = services.first_mut().unwrap().dwallet_mpc_manager_mut();
    manager
        .ingest_offchain_mpc_keys()
        .expect("ingest_offchain_mpc_keys");
    assert!(
        manager.current_epoch_keys_ingested,
        "ingestion must complete after the fall-through refetch"
    );
    assert_eq!(
        manager.validator_mpc_keys_by_party_id.secp256k1_pvss.len(),
        members.len(),
        "every cert-covered committee member must be dealt, including the \
         MPC-dead member"
    );
}
