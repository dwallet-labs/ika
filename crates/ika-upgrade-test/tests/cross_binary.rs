// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Cross-binary rolling upgrade: boot a 4-validator committee on the OLD binary
//! (`mainnet-v1.1.8`, protocol MIN=2/MAX=3), then swap validators to the NEW
//! binary (`dev`, MIN=3/MAX=4) across epochs. Genesis is protocol version 3 —
//! the only version both binaries support (old supports ≤3, new supports ≥3).
//!
//! The protocol-version vote can only advance to 4 once *every* validator runs
//! a binary that supports 4, i.e. after the last v1.1.8 node is replaced. So:
//! while the committee is mixed it stays at v3; once all four run `dev` it
//! advances to v4. Reaching v4 demonstrates the whole rollout — mixed-binary
//! committees process each other's consensus + MPC messages (wire compat), a
//! validator restarts on a new binary against its old RocksDB (on-disk compat),
//! and the capability vote arithmetic fires at the right moment.
//!
//! Opt-in (real binaries + long-running), via `RUN_CROSS_BINARY=1`:
//!
//! ```bash
//! RUN_CROSS_BINARY=1 \
//!   OLD_BIN=/path/to/ika-node@v1.1.8 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test cross_binary -- --nocapture
//! ```

use std::path::PathBuf;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_binary_v118_to_dev_reaches_v4() {
    if std::env::var("RUN_CROSS_BINARY").is_err() {
        eprintln!("skipping: set RUN_CROSS_BINARY=1 (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/SUI_BIN)");
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let old = BinarySpec::Path(bin_from_env("OLD_BIN", "target/release/ika-node"));
    let new = BinarySpec::Path(bin_from_env("NEW_BIN", "target/release/ika-validator"));
    let notifier = bin_from_env("NOTIFIER_BIN", "target/release/ika-notifier");
    let sui = bin_from_env("SUI_BIN", "sui");
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();

    Scenario::new(4, repo, sui, notifier)
        .start_all(old)
        .wait_for_epoch(2)
        .stop_and_swap(&[0, 1], new.clone())
        .wait_for_epoch(3)
        .stop_and_swap(&[2, 3], new)
        .wait_for_epoch(4)
        .expect_protocol_version_at_least(4)
        .run()
        .await
        .expect("cross-binary rolling upgrade reaches protocol v4");

    tracing::info!("cross-binary PASSED: v1.1.8 -> dev rolling upgrade reached protocol v4");
}
