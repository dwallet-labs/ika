// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Config-compat rehearsal: the **current binary on old-style (1.1.8-shape)
//! configs** — `sui-rpc-url` only, no `sui-data-source`, no trust anchor —
//! for **every role**: all four validators AND the notifier run the
//! deprecated legacy JSON-RPC transport. That is what a mainnet node runs
//! the moment its binary is swapped: operators upgrade the binary, not the
//! YAML.
//!
//! No other harness covers this: every other scenario's config builder
//! writes `sui-data-source` (gRPC) for validators and the notifier alike, so
//! a regression confined to the legacy path — validator MPC event ingestion
//! over JSON-RPC `query_events`, or notifier checkpoint/`advance_epoch`
//! submission over the JSON-RPC quorum driver — would ship invisibly.
//!
//! What one green run proves, in order:
//! - the binary **boots** from an old-style YAML in Validator and Notifier
//!   modes (config parsing + transport selection);
//! - the genesis network DKG completes and epochs advance — i.e. the
//!   legacy-path notifier actually submits checkpoints and `advance_epoch`
//!   over JSON-RPC (epoch advance is impossible without it);
//! - a full DKG → Presign → Sign lifecycle completes on the legacy
//!   transport.
//!
//! (The version-straddling flavor of this scenario — proving the capability
//! vote fires on legacy configs — was retired when the versions it crossed
//! dropped below the supported range; genesis is `ProtocolVersion::MIN` = 6
//! now, and `MIN == MAX`, so no boundary remains to cross.)
//!
//! Opt-in via `RUN_LEGACY_CONFIG=1`:
//!
//! ```bash
//! RUN_LEGACY_CONFIG=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test legacy_config -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_config_full_lifecycle() {
    if std::env::var("RUN_LEGACY_CONFIG").is_err() {
        eprintln!("skipping: set RUN_LEGACY_CONFIG=1 to run the legacy-config rehearsal");
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
    let ika_cli = bin_from_env("IKA_BIN", "target/release/ika");
    let sui = bin_from_env("SUI_BIN", "sui");
    // Only used to resolve git-ref binaries; this test uses a path binary.
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-legacy-config-test".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // 5-minute epochs: the lifecycle needs room inside an epoch before its
    // own reconfiguration window.
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);

    // - wait_for_epoch(2): the counter reaching 2 is the signal the genesis
    //   network DKG finished — already proof the legacy-path notifier
    //   submits (no epoch advances without it).
    // - run_workload("legacy"): full lifecycle on the legacy transport.
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_ika_cli(ika_cli)
        .with_legacy_sui_config()
        .start_all(validator)
        .wait_for_epoch(2)
        .run_workload("legacy")
        .run()
        .await
        .expect("legacy-config rehearsal: full lifecycle on the legacy JSON-RPC path");
}
