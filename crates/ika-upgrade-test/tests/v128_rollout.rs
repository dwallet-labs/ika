// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Strict-bound v6 rolling-upgrade rehearsal for adopting the strict-only
//! inkrypto revision.
//!
//! Protocol v6 migrates the network-key equality-of-coefficients discrete-log
//! bound from the `-10` relaxed bound (transcribed since mainnet-v1.1.8) to the
//! strict bound. Two binaries agree on the strict bound at v6:
//!
//! - **OLD** = the v1.2.7 binary (current inkrypto, both bounds selectable;
//!   produces the strict bound at v6 via the
//!   `strict_network_key_coefficient_bound` protocol flag).
//! - **NEW** = the candidate binary (strict-only inkrypto revision — the
//!   `backward_compatible` machinery removed — so it produces the strict bound
//!   unconditionally).
//!
//! Genesis is protocol **v6** (`with_genesis_protocol_version`), so there is no
//! relaxed (v5) phase: the two binaries only agree at v6, and this test proves
//! that at v6 a mixed OLD/NEW committee produces byte-identical aggregated
//! reconfiguration outputs (per-authority output-digest convergence witnessed
//! on the NEW validator), reports no malicious actors, and keeps serving a full
//! user DKG → Presign → Sign lifecycle across two reshares and a full binary
//! swap. That is the wire-no-op the inkrypto bump must be, once the network is
//! already on v6/strict.
//!
//! Opt-in (real binaries + long-running), via `RUN_V128_ROLLOUT=1`:
//!
//! ```bash
//! # OLD_BIN: the v1.2.7 ika-validator; NEW_BIN: the strict-only candidate
//! RUN_V128_ROLLOUT=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.7 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v128_rollout -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn v128_rollout_converges_across_binary_swap_at_v6() {
    if std::env::var("RUN_V128_ROLLOUT").is_err() {
        eprintln!(
            "skipping: set RUN_V128_ROLLOUT=1 \
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
        "/mnt/nvme0n1p1/v127-bins/ika-validator",
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v6-rollout".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "v6 rollout requires an epoch of at least 480000ms so the bounded sequential \
         restarts complete before the mid-epoch reconfiguration"
    );

    // Validator 0 is the sole NEW-binary validator through the mixed phase; it
    // records every authority's consensus-submitted reconfiguration output
    // (including the three OLD validators) via canonical BCS digests.
    let current_observer = [0];

    Scenario::new(4, repo, sui, notifier)
        // Pinned to v6: this scenario is a BINARY swap, not a protocol
        // transition. `MAX_PROTOCOL_VERSION` is 7, so without this pin the
        // fully-swapped committee would vote itself to v7 partway through and
        // silently start exercising the AuthorityName width flip — conflating
        // deployed-release compatibility with a protocol upgrade. Crossing v7
        // is `v127_v7_upgrade`'s job.
        .with_supported_protocol_versions(SupportedProtocolVersions::new_for_testing(6, 6))
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        // No relaxed (v5) phase: the strict-only NEW binary and the v6-capable
        // OLD binary only agree at v6, so the committee starts at v6.
        .with_genesis_protocol_version(ProtocolVersion::new(6))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        .start_all(old)
        // Epoch 2 guarantees the all-OLD committee completed the genesis network
        // DKG at v6 (strict) and crossed its first reconfiguration boundary.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_least(6)
        .expect_protocol_version_at_most(6)
        .expect_network_key_reconfiguration_not_started(2)
        // ── Mixed phase: 1 NEW + 3 OLD, all at v6/strict. ──────────────────
        .stop_and_swap(&[0], current.clone())
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        .expect_protocol_version_at_most(6)
        .expect_all_validators_protocol_version_at_most(6)
        // First mixed-binary reshare: the NEW validator must converge
        // byte-identically with the OLD quorum on the aggregated (V4-tagged)
        // strict-bound output.
        .wait_for_network_key_reconfiguration_started(2)
        .wait_for_network_key_reconfiguration_completed(2)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(2, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_network_dkg_output_version_at_least(4)
        .expect_reconfiguration_output_version_at_least(4)
        .run_workload("mixed-v6-after-first-reshare")
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .expect_all_validators_protocol_version_at_most(6)
        // Second mixed boundary: proves the first convergence was not a one-off.
        .wait_for_network_key_reconfiguration_started(3)
        .wait_for_network_key_reconfiguration_completed(3)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(3)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(3, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .run_workload("mixed-v6-after-second-reshare")
        // ── Rollout: swap the remaining validators to NEW. ─────────────────
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_all_validators_healthy()
        .stop_and_swap(&[1, 2, 3], current)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(4)
        .wait_for_epoch(5)
        .wait_for_all_validators_local_epoch(5)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_least(6)
        // First all-NEW reshare: the fully-upgraded committee must converge and
        // install the aggregated strict-bound output everywhere.
        .wait_for_network_key_reconfiguration_started(5)
        .wait_for_network_key_reconfiguration_completed(5)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(5)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(5, &current_observer)
        .expect_reconfiguration_output_version_at_least(4)
        .expect_network_dkg_output_version_at_least(4)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .run_workload("all-new-v6-after-full-swap")
        .expect_log_line_absent("late network-key reconfiguration output DIVERGES")
        .expect_log_line_absent("failed to submit an MPC output message to consensus")
        .run()
        .await
        .expect(
            "v1.2.7/candidate committee must converge across the mixed phase and the full binary \
             swap at protocol v6 (strict bound)",
        );

    tracing::info!(
        "v6 rollout PASSED: mixed v1.2.7/candidate committee converged across two strict-bound \
         reshares at v6, and the fully-upgraded committee converged and kept serving a full \
         user lifecycle at each stage"
    );
}
