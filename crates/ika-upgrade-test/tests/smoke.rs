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

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

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

    let validator = BinarySpec::Path(bin_from_env(
        "IKA_VALIDATOR_BIN",
        "target/release/ika-validator",
    ));
    let notifier = bin_from_env("IKA_NOTIFIER_BIN", "target/release/ika-notifier");
    let sui = bin_from_env("SUI_BIN", "sui");
    // Only used to resolve git-ref binaries; this test uses a path binary, so
    // it's never built from — point it at the workspace root like the others.
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();

    // Persistent base on the big disk (rootfs is small and crashes validators
    // under disk pressure).
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-upgrade-smoke".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // The whole go/no-go flow via the Scenario DSL: bring up 4 same-binary
    // validators at genesis v3 on a 60s epoch and confirm the epoch advances
    // on-chain to 2. Progress shows as `[flow N/total]` lines from the
    // scenario executor (no per-phase logging needed in the test).
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(60_000)
        .start_all(validator)
        .wait_for_epoch(2)
        .run()
        .await
        .expect("smoke: out-of-process cluster reaches epoch 2");

    tracing::info!("go/no-go PASSED: out-of-process cluster reached epoch 2");
}
