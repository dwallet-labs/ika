// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Exercises spinning up an *additional* `DWalletNetworkEncryptionKey`
//! after cluster bootstrap. The bootstrap key (K0) is created at
//! genesis; this test requests a second key (K1) in the first half
//! of epoch 2 and verifies the second DKG completes and the chain
//! ends up holding both keys in a terminal state.
//!
//! Why stop at K1 (and not also drive K2, K3, …):
//! the chain's `advance_epoch` Move assert
//! `epoch_dwallet_network_encryption_keys_reconfiguration_completed
//! == dwallet_network_encryption_keys.length()` requires *every*
//! current key to be re-keyed during the same epoch's mid-epoch
//! reconfig pass. If a key finishes its initial DKG too close to
//! mid-epoch (or right after), the validator-side mid-epoch reconfig
//! gate (`sui_executor::run_epoch_switch` line ~177, the
//! `size == len` check) only sees ONE key in its local snapshot
//! by the time the gate first satisfies, so the resulting reconfig
//! PTB only re-keys one of the two — and the next epoch advance is
//! permanently stuck on the count mismatch. That is a real
//! chain/off-chain interaction issue worth tracking separately, but
//! it is orthogonal to the *DKG* code path this cluster test is
//! after. So this test exercises the multi-key DKG path (which is
//! what the off-chain pipeline must handle) and stops before the
//! cross-epoch reconfig dance that the chain currently can't
//! complete for newly DKG'd-mid-epoch keys.
//!
//! Timing constraint: the on-chain helper
//! `dwallet_2pc_mpc_coordinator_inner::request_dwallet_network_encryption_key_dkg`
//! aborts with `EAlreadyInitiatedMidEpochReconfiguration` once the
//! system has passed mid-epoch time (`epoch_duration_ms / 2` after
//! the epoch's start). So the test picks an `epoch_duration_ms`
//! comfortably larger than 2× the observed network DKG wall time
//! and triggers `request_network_key_dkg` immediately after the
//! cluster reaches the new epoch.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;
use ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyState;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn multi_network_keys_dkg_across_epochs() {
    telemetry_subscribers::init_for_testing();

    // 6 min epochs: mid-epoch at 3 min. K1's network DKG takes
    // ~2–3 min on this hardware, so the DKG comfortably finishes
    // in the first half of epoch 2.
    let epoch_duration_ms = 360_000;
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

    // --- Both keys must be present on chain and past the
    //     `AwaitingNetworkDKG` initial state.
    let client = cluster
        .sui_connector_client()
        .await
        .expect("sui_connector_client");
    let (_, inner) = client.must_get_dwallet_coordinator_inner().await;
    let keys = client
        .get_dwallet_mpc_network_keys(&inner)
        .await
        .expect("get_dwallet_mpc_network_keys");
    for id in [k0_id, k1_id] {
        let key = keys
            .get(&id)
            .unwrap_or_else(|| panic!("network key {id} disappeared from chain"));
        assert!(
            matches!(
                key.state,
                DWalletNetworkEncryptionKeyState::NetworkDKGCompleted
                    | DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
                    | DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration
            ),
            "network key {id} stuck in state {state:?} — expected past AwaitingNetworkDKG",
            state = key.state
        );
    }
}
