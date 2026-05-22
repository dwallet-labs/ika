// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::sim_test;

#[sim_test]
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
