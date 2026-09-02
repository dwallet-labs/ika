// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Store-backed liveness test for the per-epoch root-seed resolution (#2119).
//!
//! The unit tests in `dwallet_mpc::seed_rotation` drive the decision from a
//! digest handed to them, which proves the RULE and nothing about the wiring.
//! This one goes through the whole production chain a validator walks at every
//! epoch start, with no step stubbed:
//!
//!   real `AuthorityPerEpochStore` at epoch `E`
//!     + real `AuthorityPerpetualTables` (rocksdb, tempdir), installed via
//!       `install_perpetual_tables_for_handoff`
//!     -> `insert_certified_handoff_attestation(E - 1, ...)`
//!     -> `DWalletMPCService::verify_validator_keys(&epoch_store, &config)`
//!        — which is what `ika-node` calls, and which internally does the
//!        `epoch() - 1` indexing, the `perpetual_tables_for_handoff` read, the
//!        `epoch_store.name` keying, and the resolution against real seeds.
//!
//! Two mistakes this shape catches that a direct `resolve` call cannot:
//!
//! - **Off-by-one.** The certificate is written at `E - 1` and never at `E`,
//!   so a reader that looked up the current epoch would find nothing and
//!   every case would collapse to `no_certified_digest`.
//! - **Wrong key basis.** The config's protocol/network/consensus keys are
//!   generated independently of the committee, so `epoch_store.name` and
//!   `config.protocol_public_key()` are DIFFERENT values here — deliberately.
//!   The cert names this validator under `epoch_store.name` only, so a reader
//!   that keyed by the BLS protocol key (the basis the self-lookup two lines
//!   above it uses) would also find nothing.
//!
//! The four cases are the ones the boot check owes: correct seed → starts;
//! wrong seed, no previous → the NON-PARTICIPATING decision, emphatically not
//! a startup error; wrong current, correct previous → starts on the previous
//! seed; and an UNREADABLE previous descriptor → treated as absent, with no
//! panic (the state an operator reaches by following the documented rotation,
//! which ends in deleting the old seed file).

use std::net::SocketAddr;
use std::sync::Arc;

use dwallet_rng::RootSeed;
use ika_config::NodeConfig;
use ika_config::node::{
    AuthorityKeyPairWithPath, KeyPairWithPath, RootSeedWithPath, SuiConnectorConfig, SuiDataSource,
};
use ika_types::committee::Committee;
use ika_types::crypto::AuthorityName;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};
use ika_types::sui::epoch_start_system::{EpochStartSystem, EpochStartValidatorInfoV1};

use crate::authority::authority_per_epoch_store::{AuthorityPerEpochStore, EpochStoreParams};
use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use crate::dwallet_mpc::seed_rotation::{DerivableDigests, EpochSeedDecision};

/// The epoch the store is opened at. Anything `>= 1`; the certificate goes to
/// `EPOCH - 1`, which is the whole point of the indexing assertion.
const EPOCH: u64 = 7;

fn cert_naming(
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

/// A validator `NodeConfig` plus the epoch-start validator record that matches
/// it, so `verify_validator_keys`' network/consensus-key equality checks pass
/// and the seed resolution is the only thing under test.
fn config_and_validator_record(
    root_seed: Option<RootSeedWithPath>,
    previous_root_seed: Option<RootSeedWithPath>,
) -> (NodeConfig, EpochStartValidatorInfoV1) {
    use fastcrypto::traits::KeyPair as _;
    // Keys come from the shared test helpers rather than a locally seeded RNG:
    // `ika-types` builds against rand 0.8 (for fastcrypto) while this crate's
    // `rand` is a different major, so a `StdRng` constructed here does not
    // satisfy `get_key_pair_from_rng`'s bounds.
    let protocol_key = ika_types::crypto::random_committee_key_pairs_of_size(1)
        .pop()
        .expect("one protocol key");
    let (_, network_key): (_, ika_types::crypto::NetworkKeyPair) =
        sui_types::crypto::get_key_pair();
    let (_, consensus_key): (_, ika_types::crypto::NetworkKeyPair) =
        sui_types::crypto::get_key_pair();
    let (_, account_key): (_, ika_types::crypto::AccountKeyPair) =
        sui_types::crypto::get_key_pair();

    let record = EpochStartValidatorInfoV1 {
        validator_id: sui_types::base_types::ObjectID::ZERO,
        protocol_pubkey: protocol_key.public().clone(),
        network_pubkey: network_key.public().clone(),
        consensus_pubkey: consensus_key.public().clone(),
        mpc_data: None,
        network_address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
        p2p_address: "/ip4/127.0.0.1/udp/2".parse().unwrap(),
        consensus_address: "/ip4/127.0.0.1/udp/3".parse().unwrap(),
        voting_power: 1,
        hostname: "seed-rotation-store-test".to_string(),
        name: "seed-rotation-store-test".to_string(),
    };

    let config = NodeConfig {
        root_seed_key_pair: root_seed,
        previous_root_seed_key_pair: previous_root_seed,
        protocol_key_pair: AuthorityKeyPairWithPath::new(protocol_key),
        consensus_key_pair: KeyPairWithPath::new(sui_types::crypto::SuiKeyPair::Ed25519(
            consensus_key,
        )),
        account_key_pair: KeyPairWithPath::new(sui_types::crypto::SuiKeyPair::Ed25519(account_key)),
        network_key_pair: KeyPairWithPath::new(sui_types::crypto::SuiKeyPair::Ed25519(network_key)),
        db_path: "unused-in-this-test".into(),
        network_address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
        sui_connector_config: SuiConnectorConfig {
            sui_data_source: SuiDataSource::SuiStateDirect {
                url: "http://unused:9000".to_string(),
                headers: Default::default(),
                serve_mirror: false,
            },
            sui_state_mirror_peers: vec![],
            sui_genesis: None,
            sui_checkpoint_archive: None,
            sui_chain_identifier: ika_config::node::SuiChainIdentifier::Mainnet,
            ika_unsafe_identity_override: None,
            ika_package_id: sui_types::base_types::ObjectID::ZERO,
            ika_common_package_id: sui_types::base_types::ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id: sui_types::base_types::ObjectID::ZERO,
            ika_dwallet_2pc_mpc_package_id_v2: None,
            ika_system_package_id: sui_types::base_types::ObjectID::ZERO,
            ika_system_object_id: sui_types::base_types::ObjectID::ZERO,
            ika_dwallet_coordinator_object_id: sui_types::base_types::ObjectID::ZERO,
            verified_cache_retention_checkpoints: None,
            notifier_client_key_pair: None,
            sui_ika_system_module_last_processed_event_id_override: None,
        },
        metrics_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        admin_interface_port: 0,
        consensus_config: None,
        remove_deprecated_tables: false,
        p2p_config: Default::default(),
        end_of_epoch_broadcast_channel_capacity: 128,
        metrics: None,
        supported_protocol_versions: None,
        state_archive_write_config: Default::default(),
        state_archive_read_config: vec![],
        authority_overload_config: Default::default(),
        run_with_range: None,
        authority_db_retention_epochs: None,
        authority_db_pruner_period_secs: None,
        max_mpc_computation_cores: None,
        withhold_handoff_anchor_for_testing: None,
    };
    (config, record)
}

/// Opens a real epoch store at [`EPOCH`] whose epoch-start state contains
/// `record`, with real perpetual tables installed for the handoff read.
/// Returns the store and the tempdirs, which must outlive it (RocksDB).
fn epoch_store_with(
    self_name: AuthorityName,
    record: EpochStartValidatorInfoV1,
) -> (
    Arc<AuthorityPerEpochStore>,
    Arc<AuthorityPerpetualTables>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    // The committee's epoch and the epoch-start configuration's must agree —
    // `AuthorityPerEpochStore::new` asserts it — and both must be >= 1 so the
    // `epoch() - 1` handoff lookup has a prior epoch to find.
    let (base, _keys) = Committee::new_simple_test_committee_of_size(4);
    let committee =
        Committee::new_for_testing_with_normalized_voting_power(EPOCH, base.voting_rights.clone());
    let epoch_dir = tempfile::tempdir().expect("tempdir");
    let epoch_start_system = EpochStartSystem::new_v1(
        EPOCH,
        ika_protocol_config::ProtocolVersion::MAX.as_u64(),
        0,
        1_000,
        vec![record],
        0,
        0,
    );
    let epoch_store = AuthorityPerEpochStore::new(EpochStoreParams {
        name: self_name,
        committee: Arc::new(committee),
        parent_path: epoch_dir.path().to_path_buf(),
        db_options: None,
        metrics: crate::epoch::epoch_metrics::EpochMetrics::new(&prometheus::Registry::new()),
        epoch_start_configuration: EpochStartConfiguration::new(epoch_start_system)
            .expect("epoch start configuration"),
        chain_identifier: Default::default(),
        packages_config: ika_types::messages_dwallet_mpc::IkaNetworkConfig::new_for_testing(),
    })
    .expect("epoch store");

    let perpetual_dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(perpetual_dir.path(), None));
    epoch_store.install_perpetual_tables_for_handoff(perpetual.clone());

    (epoch_store, perpetual, (epoch_dir, perpetual_dir))
}

/// All four boot outcomes, driven through `verify_validator_keys` against a
/// real epoch store and a real handoff-cert store.
///
/// One test rather than four so the (expensive, real) class-groups
/// derivations are shared: `DerivableDigests::derive` runs the full
/// derivation, and only two distinct seeds are needed for every case.
#[tokio::test]
async fn boot_seed_resolution_through_verify_validator_keys_and_a_real_cert_store() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let certified_seed = RootSeed::new([31u8; 32]);
    let rotated_seed = RootSeed::new([32u8; 32]);
    let certified_digest = DerivableDigests::derive(&certified_seed)
        .expect("derive the certified seed's bundle")
        .emitted()
        .expect("one encoding");
    let rotated_digest = DerivableDigests::derive(&rotated_seed)
        .expect("derive the rotated seed's bundle")
        .emitted()
        .expect("one encoding");
    assert_ne!(
        certified_digest, rotated_digest,
        "two different seeds must derive two different bundles, or every \
         assertion below is vacuous"
    );

    let resolve = |current: RootSeed, previous: Option<RootSeedWithPath>| {
        let (config, record) =
            config_and_validator_record(Some(RootSeedWithPath::new(current)), previous);
        let self_name = AuthorityName([3; 32]);
        let (epoch_store, perpetual, _dirs) = epoch_store_with(self_name, record);
        assert_eq!(epoch_store.epoch(), EPOCH);
        // The cert lives at E-1 and names this validator by `epoch_store.name`.
        // A second entry under a different authority keeps the self-lookup a
        // real lookup rather than "the only row there is".
        perpetual
            .insert_certified_handoff_attestation(
                EPOCH - 1,
                &cert_naming(
                    EPOCH - 1,
                    &[
                        (self_name, certified_digest),
                        (AuthorityName([4; 32]), rotated_digest),
                    ],
                ),
            )
            .expect("insert the handoff cert");
        let resolution = DWalletMPCService::verify_validator_keys(&epoch_store, &config)
            .expect("key verification and seed resolution must not error");
        (
            resolution.decision(),
            resolution.mpc_active(),
            resolution.state_label().to_string(),
            resolution.mpc_seed().clone(),
        )
    };

    // (a) The certified seed: starts, on the current seed.
    let (decision, active, label, seed) = resolve(certified_seed.clone(), None);
    assert_eq!(
        decision,
        EpochSeedDecision::RunOnCurrent {
            previous_configured: false
        },
        "the cert at E-1 names this seed under `epoch_store.name`; anything else \
         means the read used the wrong epoch or the wrong key basis"
    );
    assert!(active);
    assert_eq!(label, "matches");
    assert_eq!(seed, certified_seed);

    // (b) The rotated seed with NO previous seed configured: the node still
    // starts — there is no error path left — and resolves to the
    // non-participating state.
    let (decision, active, label, _) = resolve(rotated_seed.clone(), None);
    assert_eq!(
        decision,
        EpochSeedDecision::NoParticipation {
            previous_configured: false
        }
    );
    assert!(
        !active,
        "it must sit the epoch out rather than compute with key material the \
         network never dealt to it (#1978)"
    );
    assert_eq!(label, "awaiting_certification");

    // (c) The rotated seed WITH the certified one as previous: starts, and
    // runs the epoch on the previous seed.
    let (decision, active, label, seed) = resolve(
        rotated_seed.clone(),
        Some(RootSeedWithPath::new(certified_seed.clone())),
    );
    assert_eq!(decision, EpochSeedDecision::RunOnPrevious);
    assert!(active);
    assert_eq!(label, "rotating_on_previous_seed");
    assert_eq!(
        seed, certified_seed,
        "the MPC manager must be built from the CERTIFIED seed, not the \
         configured current one"
    );

    // (d) An UNREADABLE previous descriptor. This is the state an operator
    // reaches by following the documented rotation to its last step —
    // deleting the old seed file — without having removed the field yet.
    // `RootSeedWithPath::root_seed()` PANICS there; the resolution must use
    // the fallible accessor, warn, and carry on as if no previous seed were
    // configured. A panic here would turn a completed rotation's cleanup into
    // an outage.
    let unreadable = RootSeedWithPath::new_from_path_lazy("deleted-after-rotation".into());
    let (decision, active, label, _) = resolve(rotated_seed.clone(), Some(unreadable));
    assert_eq!(
        decision,
        EpochSeedDecision::NoParticipation {
            previous_configured: false
        },
        "an unreadable previous seed must resolve exactly as an absent one"
    );
    assert!(!active);
    assert_eq!(label, "awaiting_certification");

    // (e) Same, but the CURRENT seed is the certified one: the far more likely
    // shape of the cleanup mistake, and it must be a complete no-op.
    let (decision, active, _, seed) = resolve(
        certified_seed.clone(),
        Some(RootSeedWithPath::new_from_path_lazy(
            "deleted-after-rotation".into(),
        )),
    );
    assert_eq!(
        decision,
        EpochSeedDecision::RunOnCurrent {
            previous_configured: false
        },
        "deleting the old seed file after the rotation completed must change nothing"
    );
    assert!(active);
    assert_eq!(seed, certified_seed);
}

/// An authority the certificate does not name at all — a genuine first-epoch
/// joiner — resolves to `NoCertifiedDigest` and runs normally. Cert ABSENCE is
/// never evidence of a wrong seed, and this is the case a fail-closed check
/// would have wedged.
#[tokio::test]
async fn an_authority_absent_from_the_cert_starts_normally() {
    let seed = RootSeed::new([33u8; 32]);
    let (config, record) =
        config_and_validator_record(Some(RootSeedWithPath::new(seed.clone())), None);
    let self_name = AuthorityName([9; 32]);
    let (epoch_store, perpetual, _dirs) = epoch_store_with(self_name, record);

    // A cert exists for E-1, but it names a different validator.
    perpetual
        .insert_certified_handoff_attestation(
            EPOCH - 1,
            &cert_naming(EPOCH - 1, &[(AuthorityName([8; 32]), [1u8; 32])]),
        )
        .expect("insert");

    let resolution = DWalletMPCService::verify_validator_keys(&epoch_store, &config)
        .expect("an authority absent from the cert must not error");
    assert_eq!(
        resolution.decision(),
        EpochSeedDecision::NoCertifiedDigest {
            previous_configured: false
        }
    );
    assert!(resolution.mpc_active());
    assert_eq!(resolution.mpc_seed(), &seed);
}
