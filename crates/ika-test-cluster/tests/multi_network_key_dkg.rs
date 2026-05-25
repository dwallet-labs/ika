// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Exercises spinning up *additional* `DWalletNetworkEncryptionKey`s
//! after cluster bootstrap and across epoch boundaries. The
//! bootstrap key is created at genesis; this test requests two more
//! keys at successive epoch starts and verifies each one's network
//! DKG completes AND each prior key continues to get reconfigured
//! at every subsequent epoch transition (the off-chain pipeline
//! must handle N>1 keys, not just the bootstrap one).
//!
//! Timing constraint: the on-chain helper
//! `dwallet_2pc_mpc_coordinator_inner::request_dwallet_network_encryption_key_dkg`
//! aborts with `EAlreadyInitiatedMidEpochReconfiguration` once the
//! system has passed mid-epoch time (`epoch_duration_ms / 2` after
//! the epoch's start). So this test picks an `epoch_duration_ms`
//! comfortably larger than 2× the observed network DKG wall time
//! (~30–60s on this hardware) and triggers each `request_network_key_dkg`
//! immediately after the cluster reaches a new epoch.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyState;
use std::time::Duration;

/// `#[ignore]` on a new (different) gap surfaced after the DKG
/// finalize-gap fix landed: in v4 off_chain mode, the
/// `ConsensusNetworkKeyData` consensus message is sent once per
/// key (`sent_network_key_ids` tracks IDs sent, not data hashes),
/// so when a key's `current_reconfiguration_public_output`
/// updates each epoch the new bytes are NEVER re-broadcast via
/// consensus. Validators that don't reach the `Finalize` step
/// for a given reconfig locally have no way to receive the
/// updated reconfig output (chain reads are disabled in v4).
/// Their per-key view of the network key stays stuck at the DKG
/// output, the reconfig MPC for subsequent epochs deadlocks
/// (only ~half the validators have current data), and the test
/// stalls at epoch 2→3.
///
/// Repro: drop the `#[ignore]` on this test. K0 + K1 DKG settle,
/// epoch 2 starts, K0 reconfig + K1 reconfig run to ~round 4,
/// then no further MPC progress.
///
/// Follow-up: rework `dwallet_mpc_service`'s
/// `new_key_data` filter (or the `sent_network_key_ids` tracking
/// scheme) to re-broadcast `ConsensusNetworkKeyData` when the
/// chain-side bytes change, AND update `handle_network_key_data_messages`
/// to UPDATE `agreed_network_key_data` on later votes instead of
/// skipping once-agreed keys. Once that lands, the DKG-finalize
/// fix in `instantiate_agreed_keys_from_voted_data` + the
/// perpetual digest mirrors will cover the reconfig path the
/// same way they cover the DKG path.
#[ignore = "consensus-voted reconfig-output propagation gap; see test doc"]
#[tokio::test(flavor = "multi_thread")]
async fn multi_network_keys_dkg_across_epochs() {
    telemetry_subscribers::init_for_testing();

    // Epoch length comfortably larger than 2× a single network DKG
    // wall time so each `request_network_key_dkg` lands in the
    // first half (before mid-epoch reconfiguration starts).
    let epoch_duration_ms = 180_000;
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    let (k0_id, _k0_output) = cluster
        .wait_for_network_key()
        .await
        .expect("bootstrap key DKG never settled");
    tracing::info!(?k0_id, "bootstrap network key settled");

    // --- Reach epoch 2's first half, then request K1. By waiting
    //     for the next epoch boundary we guarantee we're back in
    //     the "first half of epoch" window where the on-chain
    //     `request_dwallet_network_encryption_key_dkg` assert
    //     passes.
    cluster.wait_for_epoch(2).await;
    let before_k1 = cluster
        .current_network_key_ids()
        .await
        .expect("snapshot pre-K1 key set");
    assert_eq!(
        before_k1,
        vec![k0_id],
        "expected exactly the bootstrap key to be on chain pre-K1"
    );
    cluster
        .request_network_key_dkg()
        .await
        .expect("request_network_key_dkg (K1) failed");
    let (k1_id, k1_output) = cluster
        .wait_for_new_network_key(&before_k1, Duration::from_secs(300))
        .await
        .expect("K1 DKG never settled");
    assert_ne!(k1_id, k0_id);
    assert!(
        !k1_output.is_empty(),
        "K1 DKG output should be non-empty once settled"
    );
    tracing::info!(?k1_id, "K1 network key settled");

    // --- Reach epoch 3's first half, request K2.
    cluster.wait_for_epoch(3).await;
    let before_k2 = cluster
        .current_network_key_ids()
        .await
        .expect("snapshot pre-K2 key set");
    assert!(
        before_k2.contains(&k0_id) && before_k2.contains(&k1_id),
        "expected K0 and K1 to be on chain pre-K2; saw {before_k2:?}"
    );
    cluster
        .request_network_key_dkg()
        .await
        .expect("request_network_key_dkg (K2) failed");
    let (k2_id, k2_output) = cluster
        .wait_for_new_network_key(&before_k2, Duration::from_secs(300))
        .await
        .expect("K2 DKG never settled");
    assert!(![k0_id, k1_id].contains(&k2_id));
    assert!(
        !k2_output.is_empty(),
        "K2 DKG output should be non-empty once settled"
    );
    tracing::info!(?k2_id, "K2 network key settled");

    // --- Cross one more epoch boundary so K0/K1/K2 ALL go through
    //     reconfig in the multi-key state.
    cluster.wait_for_epoch(4).await;

    // --- Every key (K0, K1, K2) must be present and in the
    //     terminal completed state.
    let client = cluster
        .sui_connector_client()
        .await
        .expect("sui_connector_client");
    let (_, inner) = client.must_get_dwallet_coordinator_inner().await;
    let keys = client
        .get_dwallet_mpc_network_keys(&inner)
        .await
        .expect("get_dwallet_mpc_network_keys");
    for id in [k0_id, k1_id, k2_id] {
        let key = keys
            .get(&id)
            .unwrap_or_else(|| panic!("network key {id} disappeared from chain"));
        assert!(
            matches!(
                key.state,
                DWalletNetworkEncryptionKeyState::NetworkDKGCompleted
                    | DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
            ),
            "network key {id} stuck in state {state:?} — expected DKG/Reconfig completed",
            state = key.state
        );
    }
}
