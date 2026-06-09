// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! CLI entry point for the cross-binary upgrade test harness.
//!
//! `dev` vs `mainnet-v1.1.8` is the default example, not a baked-in constant —
//! both sides are `--old` / `--new` binary specs (`path:` / `tag:` / `sha:` /
//! `branch:`, or a bare value the resolver classifies).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

#[derive(Parser, Debug)]
#[command(name = "upgrade-test", about = "Cross-binary Ika upgrade test harness")]
struct Args {
    /// Validators in the cluster (max 4).
    #[arg(long, default_value_t = 4)]
    validators: usize,

    /// Old binary spec, e.g. `tag:mainnet-v1.1.8`.
    #[arg(long)]
    old: String,

    /// New binary spec, e.g. `branch:dev`.
    #[arg(long)]
    new: String,

    /// Path to a workspace-tag-matching `sui` binary.
    #[arg(long)]
    sui_binary: PathBuf,

    /// Path to the notifier binary (auto-detecting `ika-node`/`ika-notifier`).
    #[arg(long)]
    notifier_binary: PathBuf,

    /// Source git repo to build binary specs from (defaults to CWD).
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Named scenario to run.
    #[arg(long, default_value = "rolling_majority_then_minority")]
    scenario: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();
    let args = Args::parse();

    let old = BinarySpec::parse(&args.old);
    let new = BinarySpec::parse(&args.new);
    let repo = args
        .repo
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    tracing::info!(
        scenario = %args.scenario,
        old = %old.label(),
        new = %new.label(),
        "starting upgrade-test",
    );

    let scenario = match args.scenario.as_str() {
        "rolling_majority_then_minority" => {
            // Mirror the proven-good config from `tests/cross_binary.rs`: long
            // (10-min) epochs avoid the short-epoch sui_executor wedge, the
            // timeout covers a full long epoch per `wait_for_epoch`, and the
            // `set_buffer_stake(0)` before the upgrade-crossing wait drops the
            // n=4 threshold from round-up-to-unanimity to a bare quorum so the
            // v3 -> v4 vote can land even if one fresh capability is late to
            // commit at the boundary tally. (Unlike the all-at-once test this is
            // a staged rollout, so it is not exercised in CI — a manual probe.)
            Scenario::new(args.validators, repo, args.sui_binary, args.notifier_binary)
                .with_epoch_duration_ms(600_000)
                .with_epoch_timeout(Duration::from_secs(1800))
                .start_all(old)
                .wait_for_epoch(1)
                .stop_and_swap(&[0, 1], new.clone())
                .wait_for_epoch(2)
                .stop_and_swap(&[2, 3], new)
                .set_buffer_stake(0)
                .wait_for_epoch(3)
                .expect_protocol_version_at_least(4)
        }
        other => anyhow::bail!("unknown scenario: {other}"),
    };

    scenario.run().await
}
