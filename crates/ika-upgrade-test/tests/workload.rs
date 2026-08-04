// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end workload check: bring up a single-binary cluster and drive a
//! full **DKG → Presign → Sign** dWallet lifecycle (via the `ika` CLI),
//! confirming a signature is produced on-chain. Proves the session-lifecycle
//! invariant the upgrade harness depends on — sessions started in an epoch
//! actually complete.
//!
//! Genesis is `ProtocolVersion::MIN` (= MAX = 6): the network DKG runs the
//! main (PVSS) party from genesis via the current-epoch off-chain key
//! assembly. (The genesis-at-one-version → vote-into-the-next flavor of this
//! scenario was retired when the versions it crossed dropped below the
//! supported range — no supported version boundary remains to cross;
//! resurrect the vote steps from git history when a v7 exists.)
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

use ika_types::supported_protocol_versions::SupportedProtocolVersions;
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

    // - wait_for_epoch(2): epoch 1 is genesis (reached *before* the network
    //   DKG runs), so the counter advancing to 2 is itself the signal that the
    //   genesis DKG finished and the network key is readable on-chain.
    // - run_workload: builds a driver and drives the lifecycle, asserting a
    //   signature is produced. With HOLD_CLUSTER set it holds the cluster up
    //   here (config paths printed) for manual driving instead.
    // Epochs are 3 minutes so the lifecycle fits inside an epoch before its
    // own reconfiguration window.
    Scenario::new(4, repo, sui, notifier)
        // Pinned to v6: this scenario gates the session lifecycle at a FIXED
        // protocol version. `MAX_PROTOCOL_VERSION` is 7, so without this pin
        // the all-current committee would vote itself to v7 partway through
        // and the lifecycle would straddle a protocol boundary it is not
        // meant to test. Crossing v7 is `v127_v7_upgrade`'s job.
        .with_supported_protocol_versions(SupportedProtocolVersions::new_for_testing(7, 7))
        .with_base_dir(base)
        .with_epoch_duration_ms(180_000)
        .with_epoch_timeout(Duration::from_secs(900))
        .with_ika_cli(ika_cli)
        .start_all(validator)
        .wait_for_epoch(2)
        .expect_protocol_version_at_least(7)
        .run_workload("dkg-presign-sign")
        .run()
        .await
        .expect("workload: DKG → Presign → Sign lifecycle completes on-chain");
}
