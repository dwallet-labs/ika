// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Fast Schnorr (VSS) test-cluster test: runs a Fast-Schnorr-enabled (protocol v5)
//! ika cluster's full MPC lifecycle through epoch 2.
//!
//! Per the testing strategy (CLAUDE.md "Picking a test type"), this uses
//! `#[tokio::test(flavor = "multi_thread")]` — real parallel class-groups crypto,
//! fast wall time — rather than `#[sim_test]`: it exercises VSS MPC coordination,
//! not scheduling/ordering nondeterminism (the only thing msim's slow,
//! single-threaded determinism buys). The cluster runs at the max protocol version
//! (`fast_schnorr_supported`), so the launched validators run the VSS-enabled MPC
//! stack; driving to epoch 2 forces the network-key DKG (epoch 0 -> 1) and a
//! reconfiguration (epoch 1 -> 2, which at v5 computes the V3
//! `threshold_encryption_to_sharing_output` the VSS sign reads) to run to
//! completion. End-to-end VSS presign/sign verification is in the in-process
//! integration tests (`ika_core::dwallet_mpc::integration_tests::{sign,
//! network_owned_address_sign}`).

use ika_test_cluster::IkaTestClusterBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn test_vss_enabled_network_reaches_epoch_2() {
    telemetry_subscribers::init_for_testing();

    // Fast Schnorr (VSS) is gated on protocol version 5 (the max), which the test
    // cluster runs at — so the launched validators run the VSS-enabled MPC stack.
    assert!(
        ika_protocol_config::ProtocolConfig::get_for_max_version_UNSAFE().fast_schnorr_supported(),
        "the max protocol version must enable Fast Schnorr (VSS)"
    );

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .build()
        .await
        .expect("Fast-Schnorr-enabled ika cluster failed to boot");

    assert_eq!(
        cluster.swarm.validator_node_handles().len(),
        4,
        "expected 4 validator node handles for the VSS-enabled cluster",
    );

    // Drive the full MPC lifecycle to epoch 2. The ika epoch-switch
    // (process_mid_epoch -> network-key reconfiguration -> request_advance_epoch) is
    // submitted to Sui only by the cluster's Notifier node (see the notifier wired up
    // in `IkaTestClusterBuilder::build`); it fires once the Sui Clock passes
    // `epoch_start + epoch_duration/2` (sui_executor::run_epoch_switch). Kick the Sui
    // committee once so the chain is live, then let the notifier run the
    // reconfiguration MPC (real class-groups crypto) and advance the ika network to
    // epoch 2.
    cluster.test_cluster.trigger_reconfiguration().await;
    cluster.wait_for_epoch(2).await;
}
