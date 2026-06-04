// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Go/no-go gate for the out-of-process harness: four *same-binary*
//! `ika-validator` child processes, an external Sui localnet, and a notifier —
//! confirm the ika epoch advances on the short genesis `epoch_duration_ms` and
//! `wait_for_epoch` actually observes it on-chain. No binary swap, no workload;
//! this proves the harness plumbing before any cross-binary work.
//!
//! Requires real binaries and a `sui` matching the workspace tag, so it is
//! opt-in via `RUN_UPGRADE_SMOKE=1` and never runs in the normal `cargo test`
//! sweep. Run:
//!
//! ```bash
//! RUN_UPGRADE_SMOKE=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test smoke -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_protocol_config::ProtocolVersion;
use ika_upgrade_test::cluster::ClusterBuilder;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_four_validators_reach_epoch_two() {
    if std::env::var("RUN_UPGRADE_SMOKE").is_err() {
        eprintln!("skipping: set RUN_UPGRADE_SMOKE=1 to run the out-of-process smoke test");
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let validator = bin_from_env("IKA_VALIDATOR_BIN", "target/release/ika-validator");
    let notifier = bin_from_env("IKA_NOTIFIER_BIN", "target/release/ika-notifier");
    let sui = bin_from_env("SUI_BIN", "sui");

    // Persistent base on the big disk (rootfs is small and crashes validators
    // under disk pressure).
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-upgrade-smoke".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    let cluster = ClusterBuilder::new(validator, notifier, sui)
        .with_num_validators(4)
        .with_epoch_duration_ms(60_000)
        .with_genesis_protocol_version(ProtocolVersion::MIN)
        .with_base_dir(base)
        .build()
        .await
        .expect("cluster bring-up");

    let start_epoch = cluster.current_epoch().await.expect("read epoch");
    let start_version = cluster
        .current_protocol_version()
        .await
        .expect("read protocol version");
    tracing::info!(
        start_epoch,
        start_version,
        "cluster up; waiting for epoch 2"
    );

    cluster
        .wait_for_epoch(2, Duration::from_secs(900))
        .await
        .expect("reach epoch 2");

    tracing::info!("go/no-go PASSED: out-of-process cluster reached epoch 2");
}
