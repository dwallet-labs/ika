// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rollout-day config rehearsal: the **new binary on old-style (1.1.8-shape)
//! configs** — `sui-rpc-url` only, no `sui-data-source`, no trust anchor —
//! for **every role**: all four validators AND the notifier run the
//! deprecated legacy JSON-RPC transport. That is literally what every
//! mainnet node runs the moment its binary is swapped: operators upgrade the
//! binary, not the YAML.
//!
//! No other harness covers this: every other scenario's config builder
//! writes `sui-data-source` (gRPC) for validators and the notifier alike, so
//! a regression confined to the legacy path — validator MPC event ingestion
//! over JSON-RPC `query_events`, or notifier checkpoint/`advance_epoch`
//! submission over the JSON-RPC quorum driver — would ship invisibly.
//!
//! What one green run proves, in order:
//! - the new binary **boots** from an old-style YAML in Validator and
//!   Notifier modes (config parsing + transport selection);
//! - the genesis network DKG completes and epochs advance — i.e. the
//!   legacy-path notifier actually submits checkpoints and `advance_epoch`
//!   over JSON-RPC (epoch advance is impossible without it);
//! - a full DKG → Presign → Sign lifecycle completes at protocol v3 — the
//!   exact post-swap, pre-upgrade mainnet state;
//! - the **capability vote advances v3 → v4 on legacy configs**, answering
//!   an open rollout-sequencing question: operators do NOT have to migrate
//!   to `sui-data-source` before the v4 activation vote (off-chain metadata
//!   is p2p; the legacy event path serves MPC events at v4 the same way);
//! - the lifecycle still completes at v4 on the legacy transport.
//!
//! Genesis is v3 and the vote advances to v4 mid-scenario (same structure as
//! the `workload` scenario) — so both sides of the activation boundary run
//! on the legacy transport.
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
async fn legacy_config_full_lifecycle_across_v4_activation() {
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

    // 5-minute epochs: the flow runs a workload on BOTH sides of the v3→v4
    // boundary, so each epoch needs room for a full lifecycle plus its own
    // reconfiguration window.
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);

    // - wait_for_epoch(2): the counter reaching 2 is the signal the genesis
    //   network DKG finished — already proof the legacy-path notifier
    //   submits (no epoch advances without it).
    // - run_workload("legacy-v3"): full lifecycle in the post-swap,
    //   pre-upgrade mainnet state (global presign served the 1.1.8 way).
    // - set_buffer_stake(0): with n=4 the default 50% buffer requires all
    //   four capability votes; drop to a bare quorum so the v3→v4 vote
    //   tallies at the next boundary.
    // - wait_for_epoch(4): crosses the upgrade boundary (4, not 3: the
    //   v3 workload may straddle the epoch-2→3 boundary, and the vote
    //   tallies at the first boundary after the buffer drop).
    // - run_workload("legacy-v4"): the lifecycle keeps working at v4 on the
    //   legacy transport.
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_ika_cli(ika_cli)
        .with_legacy_sui_config()
        .start_all(validator)
        .wait_for_epoch(2)
        .run_workload("legacy-v3")
        .set_buffer_stake(0)
        .wait_for_epoch(4)
        .expect_protocol_version_at_least(4)
        .run_workload("legacy-v4")
        .run()
        .await
        .expect("legacy-config rehearsal: full lifecycle on the legacy JSON-RPC path, across the v4 activation");
}
