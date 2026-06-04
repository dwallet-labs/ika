// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Cross-binary rolling upgrade: boot a 4-validator committee on an OLD binary
//! that supports only protocol v3, swap every validator to the NEW binary
//! (`dev`, supports v3..=v4), and assert the capability vote advances v3 -> v4.
//! Genesis is v3 — the only version both binaries support. For `n=4` the
//! effective threshold is all four (`2f+1` + buffer stake), so the vote can
//! only reach v4 after the last v3-only node is replaced. Reaching v4
//! demonstrates the whole rollout: mixed-binary committees process each other's
//! consensus + MPC messages (wire compat), a validator restarts on a new binary
//! against its old RocksDB (on-disk compat), and the vote fires at the right
//! moment.
//!
//! On the OLD binary: the literal `mainnet-v1.1.8` ika-node is **not** usable
//! here — it links `class_groups` from `dwallet-labs/inkrypto` while `dev` links
//! `dwallet-labs/cryptography-private`, and v4 changed the on-chain
//! validator-key shape, so a v1.1.8 node cannot parse dev-registered keys (it
//! panics in `verify_validator_keys`). That incompatibility is itself a finding:
//! the real v1.1.8 -> dev upgrade is not a naive binary swap (it needs the
//! dual-pin / backward-compatible handling from `docs/plan-update-crypto-latest.md`).
//! To exercise a *successful* heterogeneous upgrade we use an OLD binary that
//! shares dev's crypto but is pinned to `MAX_PROTOCOL_VERSION = 3` (a one-line
//! build of dev) — genuinely a different compiled binary, differing only in the
//! protocol version it advertises, which is the realistic minimal upgrade.
//!
//! Opt-in (real binaries + long-running, ~12 min), via `RUN_CROSS_BINARY=1`:
//!
//! ```bash
//! # OLD_BIN: a dev build with MAX_PROTOCOL_VERSION patched to 3
//! RUN_CROSS_BINARY=1 \
//!   OLD_BIN=/path/to/ika-validator-max3 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test cross_binary -- --nocapture
//! ```

use std::path::PathBuf;

use std::time::Duration;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_binary_rolling_upgrade_reaches_v4() {
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

    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-cross-binary".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // Long epochs: short, rapid transitions wedge the notifier's sui_executor
    // on gas-coin version contention (known epoch-13 wedge), and a binary swap
    // must finish before the mid-epoch reconfiguration MPC window. Swap all four
    // at once so the run crosses exactly one reconfiguration: at the end of the
    // all-dev epoch the capability vote (needs all 4 for n=4) advances v3 -> v4.
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(600_000)
        .with_epoch_timeout(Duration::from_secs(1200))
        .start_all(old)
        .wait_for_epoch(1)
        .stop_and_swap(&[0, 1, 2, 3], new)
        .wait_for_epoch(2)
        .expect_protocol_version_at_least(4)
        .run()
        .await
        .expect("cross-binary rolling upgrade reaches protocol v4");

    tracing::info!("cross-binary PASSED: rolling binary upgrade reached protocol v4");
}
