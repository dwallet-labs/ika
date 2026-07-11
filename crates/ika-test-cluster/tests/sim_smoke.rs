// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! First `#[sim_test]` target: boot the full cluster under msim and cross two
//! epoch boundaries. Exists to pin the baseline the fault-matrix suite builds
//! on — deterministic seed, virtual time, mock crypto (the crate's tests
//! always build with `dwallet-mpc-unsafe-mock` via the dev-dependency
//! self-reference) — and to detect any msim-only cluster regression early
//! (historically the OCS state-sync path was flaky under madsim; the mock
//! removes the crypto cost that used to mask where the time went).

#![cfg(msim)]

use ika_test_cluster::IkaTestClusterBuilder;
use sui_macros::sim_test;

#[sim_test]
async fn sim_swarm_reaches_epoch_2() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .build()
        .await
        .unwrap();
    cluster.wait_for_epoch(2).await;
}
