// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end workload check: bring up a single-binary cluster at protocol v3,
//! upgrade it to v4 through the capability vote, then drive a full
//! **DKG → Presign → Sign** dWallet lifecycle (via the `ika` CLI) and confirm
//! a signature is produced on-chain. Proves the session-lifecycle invariant
//! the upgrade harness depends on — sessions started in an epoch actually
//! complete — independently of the cross-binary scenario.
//!
//! Genesis is v3, never v4: at v4 the network DKG needs PVSS keys which only
//! arrive through the off-chain assembly, and that assembly is
//! next-committee-only — so a v4 *genesis* DKG is rejected forever (4/4
//! class-groups keys, 0/4 PVSS). The supported path is genesis v3 → upgrade
//! into v4, which is also the path mainnet takes.
//!
//! Opt-in via `RUN_WORKLOAD_TEST=1` (set `HOLD_CLUSTER=1` to hold the cluster
//! up at the workload step for manual `ika dwallet` driving instead):
//!
//! ```bash
//! RUN_WORKLOAD_TEST=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test workload -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_dkg_presign_sign() {
    if std::env::var("RUN_WORKLOAD_TEST").is_err() {
        eprintln!("skipping: set RUN_WORKLOAD_TEST=1 to run the workload driver test");
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
    // Only used to resolve git-ref binaries; this test uses a path binary, so
    // it's never built from — point it at the workspace root like the others.
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-workload-test".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    // Genesis v3 → upgrade into v4 (the mainnet path), then a full
    // DKG → Presign → Sign lifecycle, via the Scenario DSL:
    // - wait_for_epoch(2): epoch 1 is genesis (reached *before* the network
    //   DKG runs), so the counter advancing to 2 is itself the signal that the
    //   genesis DKG finished and the v3 network key is readable on-chain.
    // - set_buffer_stake(0): with n=4 the default 50% buffer rounds the
    //   capability-vote threshold up to all four validators; drop it to a bare
    //   quorum so the v3→v4 vote tallies at the next boundary (the realistic
    //   behavior on larger committees). Retries across the reconfiguration lag.
    // - wait_for_epoch(3): crosses the v3→v4 upgrade boundary.
    // - run_workload: builds a driver and drives the lifecycle, asserting a
    //   signature is produced. With HOLD_CLUSTER set it holds the cluster up
    //   here (config paths printed) for manual driving instead.
    // Epochs are 3 minutes so the lifecycle fits inside a post-upgrade epoch
    // before its own reconfiguration window.
    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(180_000)
        .with_epoch_timeout(Duration::from_secs(900))
        .with_ika_cli(ika_cli)
        .start_all(validator)
        .wait_for_epoch(2)
        .set_buffer_stake(0)
        .wait_for_epoch(3)
        .expect_protocol_version_at_least(4)
        .run_workload("dkg-presign-sign")
        .run()
        .await
        .expect("workload: DKG → Presign → Sign lifecycle completes on-chain");
}
