// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Baseline `#[tokio::test]` for `IkaTestClusterBuilder`. Per the testing
//! strategy in CLAUDE.md, tokio is the default mode for integration tests
//! (real parallel crypto, fast wall time, no msim seed-reproducibility).
//! This test asserts the end-to-end bootstrap pipeline — Sui chain boot,
//! ika package publish, system initialization, ika swarm launch — produces
//! a cluster with the expected validator count. It deliberately does NOT
//! call `wait_for_epoch`; epoch advancement requires full MPC reconfig and
//! belongs in a heavier test.

use ika_test_cluster::IkaTestClusterBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn cluster_boots_with_four_validators() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    let validator_count = cluster.swarm.validator_node_handles().len();
    assert_eq!(
        validator_count, 4,
        "expected 4 validator node handles after build()"
    );

    let cfg = cluster.swarm.config();
    assert_eq!(cfg.validator_configs.len(), 4);
    assert!(!cfg.ika_package_id.as_slice().iter().all(|b| *b == 0));
    assert!(!cfg.ika_system_object_id.as_slice().iter().all(|b| *b == 0));
}
