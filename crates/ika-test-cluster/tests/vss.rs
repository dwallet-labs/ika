// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Fast Schnorr (VSS) simtest: boots a Fast-Schnorr-enabled (protocol v5) ika
//! cluster under the msim deterministic scheduler and asserts it comes up.
//!
//! The cluster runs at the max protocol version, where `fast_schnorr_supported`
//! is on, so every launched validator runs the VSS-enabled MPC stack: the
//! internal-presign instantiation loop creates VSS presigns and the cryptographic
//! orchestrator dispatches VSS compute on rayon. Booting that stack under msim is
//! what surfaced the rayon-worker / `NodeHandle::current()` abort in the
//! orchestrator, which `orchestrator.rs` now fixes by capturing the node at
//! construction and spawning completions via `NodeHandle::spawn`.
//!
//! This test deliberately does NOT `wait_for_epoch`: epoch advancement runs the
//! full class-groups network DKG + reconfiguration, which under single-threaded
//! msim is too slow for a routine test (see "Why simtest is slow" in CLAUDE.md).
//! End-to-end VSS presign/sign correctness is covered by the in-process
//! integration tests (`ika_core::dwallet_mpc::integration_tests::{sign,
//! network_owned_address_sign}`), which run real parallel crypto under
//! `#[tokio::test]` and verify the VSS NOA + external sign flows on all curves.

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::sim_test;

#[sim_test]
async fn test_vss_enabled_cluster_boots_under_simulation() {
    telemetry_subscribers::init_for_testing();

    // Fast Schnorr (VSS) is gated on protocol version 5 (the max), which the test
    // cluster runs at — so the launched validators run the VSS-enabled MPC stack.
    assert!(
        ika_protocol_config::ProtocolConfig::get_for_max_version_UNSAFE().fast_schnorr_supported(),
        "the max protocol version must enable Fast Schnorr (VSS)"
    );

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .build()
        .await
        .expect("Fast-Schnorr-enabled ika cluster failed to boot under msim");

    // The VSS-enabled validator swarm launched under deterministic simulation.
    assert_eq!(
        cluster.swarm.validator_node_handles().len(),
        4,
        "expected 4 validator node handles after launching the VSS-enabled cluster",
    );

    let cfg = cluster.swarm.config();
    assert_eq!(cfg.validator_configs.len(), 4);
    // The dWallet 2PC-MPC package (which hosts the VSS coordinator) was published.
    assert!(
        !cfg.ika_dwallet_2pc_mpc_package_id
            .as_slice()
            .iter()
            .all(|b| *b == 0),
        "ika_dwallet_2pc_mpc package id should be set after publish",
    );
}
