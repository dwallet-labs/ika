// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal testnet-v1.2.1/current rollout of the aggregated network-key
//! output format (protocol v5).
//!
//! Testnet runs protocol v4 on the `release/testnet-v1.2.1` binary,
//! persisting the network DKG / reconfiguration public outputs in the
//! pre-aggregation (V3-tagged) wire format. The aggregated (V4-tagged) format
//! flips on at protocol v5 — so the rollout has two properties to prove
//! against the *literal deployed binary*, not a stand-in:
//!
//! 1. **Mixed committee at v4**: a current-build validator among literal
//!    v1.2.1 validators must produce byte-identical V3 reconfiguration
//!    outputs (witnessed per-authority via output-digest convergence on the
//!    current validator, which records every authority's submission), report
//!    no malicious actors, and keep serving a full user
//!    DKG → Presign → Sign lifecycle. Two consecutive reshares, so success
//!    is not a one-off transition artifact.
//! 2. **The v4 → v5 flip**: after the remaining validators swap to the
//!    current build, the capability vote advances to v5 and the first
//!    reshare above the gate must produce the aggregated V4 output —
//!    witnessed by the installed-reconfiguration-output-version gauge
//!    reaching 4 on every validator — and the committee must again converge
//!    and keep serving users on the aggregated key data.
//!
//! Genesis is v3 (the only supported genesis path); the all-v1.2.1 committee
//! immediately votes itself to v4, which is where the mixed phase runs — the
//! three literal v1.2.1 validators cap the version there until the full swap.
//!
//! Opt-in (real binaries + long-running), via `RUN_V121_ROLLOUT=1`:
//!
//! ```bash
//! # OLD_BIN: an ika-validator built at the release/testnet-v1.2.1 tag
//! RUN_V121_ROLLOUT=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.1 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v121_rollout -- --nocapture
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
async fn v121_rollout_reaches_aggregated_outputs_at_v5() {
    if std::env::var("RUN_V121_ROLLOUT").is_err() {
        eprintln!(
            "skipping: set RUN_V121_ROLLOUT=1 \
             (needs OLD_BIN/NEW_BIN/NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let old = BinarySpec::Path(bin_from_env(
        "OLD_BIN",
        "/tmp/ika-v121/target/release/ika-validator",
    ));
    let current = BinarySpec::Path(bin_from_env("NEW_BIN", "target/release/ika-validator"));
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
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v121-rollout".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "v121 rollout requires an epoch of at least 480000ms so the bounded sequential \
         restarts complete before the mid-epoch reconfiguration"
    );

    // Validator 0 is the sole current-binary validator through the mixed
    // phase; it records every authority's consensus-submitted reconfiguration
    // output (including the three literal v1.2.1 validators) via canonical
    // BCS digests.
    let current_observer = [0];

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        .start_all(old)
        // Epoch 2 guarantees the all-v1.2.1 committee completed genesis
        // network DKG at v3 and had a boundary to vote itself to v4 (every
        // validator supports it).
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_least(4)
        .expect_protocol_version_at_most(4)
        // Prove this epoch's reshare has not started, so the swap below is
        // not racing active MPC.
        .expect_network_key_reconfiguration_not_started(2)
        // ── Mixed phase: 1 current + 3 literal testnet-v1.2.1 at v4. ────────
        .stop_and_swap(&[0], current.clone())
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        .expect_protocol_version_at_most(4)
        .expect_all_validators_protocol_version_at_most(4)
        // First mixed-binary v4 reshare: the current validator must converge
        // byte-identically with the v1.2.1 quorum on the V3-tagged output.
        .wait_for_network_key_reconfiguration_started(2)
        .wait_for_network_key_reconfiguration_completed(2)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(2, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_protocol_version_at_most(4)
        // The first v4 reshare carries the V2→V3 anchor migration; the
        // installed reconfiguration output must be the pre-aggregation V3.
        .expect_network_dkg_output_version_at_least(3)
        .expect_reconfiguration_output_version_at_least(3)
        // The mixed committee must keep serving users at v4.
        .run_workload("mixed-v4-after-first-reshare")
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(4)
        .expect_all_validators_protocol_version_at_most(4)
        // Second mixed boundary: proves the first convergence was not a
        // transition artifact.
        .wait_for_network_key_reconfiguration_started(3)
        .wait_for_network_key_reconfiguration_completed(3)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(3)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(3, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_protocol_version_at_most(4)
        .run_workload("mixed-v4-after-second-reshare")
        // ── Rollout: swap the remaining literal validators; the committee
        //    votes itself to v5 at the next boundary. ─────────────────────
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_all_validators_healthy()
        .stop_and_swap(&[1, 2, 3], current)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(4)
        .wait_for_epoch(5)
        .wait_for_all_validators_local_epoch(5)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_least(5)
        // First reshare above the aggregated-outputs gate: every validator
        // must install the aggregated V4-tagged reconfiguration output.
        .wait_for_network_key_reconfiguration_started(5)
        .wait_for_network_key_reconfiguration_completed(5)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(5)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(5, &current_observer)
        // Every validator must install the V4-tagged output (gauge polled on
        // all; installation comes from the quorum-agreed chain data, so this
        // is race-free — unlike asserting the local producer log line, which
        // a validator that loses the computation race may never emit).
        .expect_reconfiguration_output_version_at_least(4)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        // The committee must keep serving users on the aggregated key data.
        .run_workload("all-current-v5-after-aggregated-reshare")
        // Whole-run backstops (see v118_mixed_rollout for rationale).
        .expect_log_line_absent("late network-key reconfiguration output DIVERGES")
        .expect_log_line_absent("failed to submit an MPC output message to consensus")
        .run()
        .await
        .expect(
            "literal testnet-v1.2.1/current committee must converge across v4 resharing and \
             reach aggregated (V4) outputs at v5",
        );

    tracing::info!(
        "v1.2.1 rollout PASSED: mixed literal-testnet-v1.2.1/current committee converged \
         across two v4 pre-aggregation reshares, and the fully-upgraded committee produced \
         and installed the aggregated (V4) reconfiguration output at v5 while serving a \
         full user lifecycle at each stage"
    );
}
