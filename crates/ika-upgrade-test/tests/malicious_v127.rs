// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Cross-binary **malicious-party detection** rehearsal (test-testing) —
//! the successor to the retired `malicious_cross_binary`.
//!
//! Boots a 4-validator committee on the HONEST literal v1.2.7 release
//! (deployed on both networks, protocol v6), lets it complete the genesis
//! network DKG, then swaps **one** validator to a deliberately-FAULTY
//! current build (`FAULTY_BIN`) that corrupts its outgoing reconfiguration
//! round message by one trailing byte (the `test-testing`-gated hook in the
//! main reconfiguration advance path). The faulty validator broadcasts a
//! malformed contribution at the next epoch boundary.
//!
//! The faulty binary is NOT a source edit: build `ika-validator` with the
//! general `test-testing` cargo feature (`cargo build --release -p ika-node
//! --bin ika-validator --features test-testing`). The fault is compiled
//! out of every normal build, so a plain release can never carry it.
//!
//! Expectation: the honest v1.2.7 validators must identify the faulty one as
//! a malicious actor and reconfigure without it (committee dips to 3), so
//! the network still reaches epoch 3. Detection is asserted
//! **programmatically** by scraping the
//! `ika_dwallet_mpc_malicious_actors_count` gauge
//! (`expect_malicious_actors_at_least(&[3], 1)`) — no log grep, and the exit
//! code alone is not the assertion: the network could reach epoch 3 without
//! flagging anyone, which is exactly the vacuous-pass this guards against. A
//! green run proves mixed-committee malicious detection against the deployed
//! release is not vacuous — i.e. `v127_rollout`'s zero-malicious gate would
//! actually fire on a real divergence. This is NOT a production test; it
//! validates the test infrastructure (see `.claude/skills/test-testing`).
//!
//! Opt-in, via `RUN_MALICIOUS_V127=1`:
//!
//! ```bash
//! # Build the faulty binary via the feature (no source edit):
//! cargo build --release -p ika-node --bin ika-validator --features test-testing
//! cp target/release/ika-validator /tmp/ika-validator-FAULTY-RECONFIG
//! # then run:
//! RUN_MALICIOUS_V127=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.7 \
//!   FAULTY_BIN=/tmp/ika-validator-FAULTY-RECONFIG \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test malicious_v127 -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_committee_marks_faulty_current_validator_malicious() {
    if std::env::var("RUN_MALICIOUS_V127").is_err() {
        eprintln!(
            "skipping: set RUN_MALICIOUS_V127=1 (needs OLD_BIN/FAULTY_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    // Honest reference binary: the literal v1.2.7 ika-validator.
    let honest = BinarySpec::Path(bin_from_env(
        "OLD_BIN",
        "/tmp/ika-v127/target/release/ika-validator",
    ));
    // Deliberately-faulty current build (corrupts its reshare message),
    // produced by `cargo build --bin ika-validator --features test-testing`.
    let faulty = BinarySpec::Path(bin_from_env(
        "FAULTY_BIN",
        "/tmp/ika-validator-FAULTY-RECONFIG",
    ));
    let notifier = bin_from_env("NOTIFIER_BIN", "target/release/ika-notifier");
    let ika_cli = bin_from_env("IKA_BIN", "target/release/ika");
    let sui = bin_from_env("SUI_BIN", "sui");
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();

    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR").unwrap_or_else(|_| "/tmp/ika-malicious-v127".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        // The committee must be allowed to dip to 3 once the faulty validator
        // is excluded.
        .with_min_validator_count(3)
        .with_ika_cli(ika_cli)
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Empty)
        // Genesis network DKG on the all-honest v1.2.7 committee at v6.
        .start_all(honest)
        .wait_for_epoch(2)
        // Swap ONE validator to the faulty current build — a mixed committee.
        // It broadcasts a corrupted reshare message at the epoch 2->3
        // boundary.
        .stop_and_swap(&[3], faulty)
        // The honest validators must mark validator 3 malicious and reshare
        // without it — the network still reaches epoch 3.
        .wait_for_epoch(3)
        .expect_malicious_actors_at_least(&[3], 1)
        .run()
        .await
        .expect("honest v1.2.7 committee should reconfigure past a faulty current validator");

    tracing::info!(
        "malicious-v127 PASSED: honest v1.2.7 committee reached epoch 3 AND recorded the \
         faulty current validator as malicious (asserted via the \
         ika_dwallet_mpc_malicious_actors_count gauge)"
    );
}
