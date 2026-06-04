// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end workload-driver check: bring up a single-binary cluster, then
//! drive a real user dWallet DKG and confirm it completes on-chain (the
//! coordinator's completed-session count rises). Proves the workload path —
//! protocol-public-parameters from the network key, centralized Curve25519
//! party, coordinator submission, completion — independently of the
//! cross-binary scenario.
//!
//! Opt-in via `RUN_WORKLOAD_TEST=1`:
//!
//! ```bash
//! RUN_WORKLOAD_TEST=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test workload -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_protocol_config::ProtocolVersion;
use ika_upgrade_test::cluster::ClusterBuilder;
use ika_upgrade_test::workload::{TerminalState, WorkloadDriver};

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_dkg_completes() {
    if std::env::var("RUN_WORKLOAD_TEST").is_err() {
        eprintln!("skipping: set RUN_WORKLOAD_TEST=1 to run the workload driver test");
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let validator = bin_from_env("IKA_VALIDATOR_BIN", "target/release/ika-validator");
    let notifier = bin_from_env("IKA_NOTIFIER_BIN", "target/release/ika-notifier");
    let sui = bin_from_env("SUI_BIN", "sui");
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-workload-test".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    let cluster = ClusterBuilder::new(validator, notifier, sui)
        .with_num_validators(4)
        .with_epoch_duration_ms(120_000)
        .with_genesis_protocol_version(ProtocolVersion::MAX)
        .with_base_dir(base)
        .build()
        .await
        .expect("cluster bring-up");

    // Let the network-key DKG land (it completes during the genesis epoch).
    cluster
        .wait_for_epoch(1, Duration::from_secs(600))
        .await
        .expect("reach epoch 1 (network DKG done)");

    let mut driver = WorkloadDriver::new(
        cluster.rpc_url().to_string(),
        cluster.network_config().clone(),
        cluster.publisher_keypair().copy(),
    )
    .await
    .expect("build workload driver");

    let ika = driver.ika_client().await.expect("ika client");
    let outcome = driver
        .issue_dkg_and_confirm(&ika, Duration::from_secs(300))
        .await
        .expect("issue+confirm DKG");

    assert_eq!(
        outcome,
        TerminalState::Completed,
        "user DKG should complete on-chain"
    );
    tracing::info!("workload PASSED: user DKG completed on-chain");
}
