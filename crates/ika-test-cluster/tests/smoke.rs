// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_test_cluster::IkaTestClusterBuilder;

/// Basic epoch-advance smoke test.
///
/// Runs as a multi-thread tokio cluster test, not `#[sim_test]`. With the
/// correct mysten-sim rev the full cluster does boot, network, and run DKG
/// under msim, but it does not reach epoch 2 within the sim_test timeout — the
/// OCS state-sync path is slow/flaky under madsim (anemo StateSync "connection
/// lost") and the run times out. Per the testing convention, cluster tests use
/// `#[tokio::test(flavor = "multi_thread")]`; `#[sim_test]` is reserved for
/// targets whose subject IS scheduling/ordering nondeterminism. Making the OCS
/// cluster pass under msim is a separate effort.
#[tokio::test(flavor = "multi_thread")]
async fn test_swarm_reaches_epoch_2() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .build()
        .await
        .unwrap();
    cluster.wait_for_epoch(2).await;
}
