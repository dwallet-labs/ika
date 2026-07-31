// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal v1.2.7 upgrade rehearsal **with post-upgrade committee churn** —
//! the successor to the retired `v118_churn`/`cross_binary` churn coverage.
//!
//! Boot a 4-validator committee on the actual v1.2.7 release (deployed on
//! mainnet AND testnet, protocol v6), sequentially swap **all validators** to
//! the current build — then, on the now all-current committee:
//!
//! - **join a brand-new validator** (candidate → stake → activate) so the
//!   next reshare encrypts the network key (originally DKG'd by v1.2.7's
//!   binary) to a 5-member committee that includes a party which never held
//!   it. The joiner boots peer-only `SuiStateMirrored`, reading verified Sui
//!   state through the direct relay validators — the OCS joiner
//!   trust-anchor path (`add_joiner_validator` seeds its `sui_genesis`
//!   blob);
//! - **remove one original validator**, so a final reshare shrinks the
//!   committee 5 → 4 (the reshare-to-fewer-parties direction that only the
//!   retired `cross_binary` exercised).
//!
//! The sequential replacement has transient mixed states but intentionally
//! avoids an MPC boundary; real mixed-committee MPC is `v127_rollout`'s job.
//! The OCS read topology splits at the swap: validators 0 and 1 stay direct
//! (serving the relay), 2 and 3 flip to peer-only mirrored, and the joiner
//! comes up mirrored — the topology the retired `cross_binary` exercised.
//!
//! Opt-in, via `RUN_V127_CHURN=1` (same binaries as `v127_rollout`):
//!
//! ```bash
//! RUN_V127_CHURN=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.2.7 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test v127_churn -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn v127_full_swap_then_committee_churn() {
    if std::env::var("RUN_V127_CHURN").is_err() {
        eprintln!(
            "skipping: set RUN_V127_CHURN=1 \
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
        "/tmp/ika-v127/target/release/ika-validator",
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v127-churn".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "v127 churn requires an epoch of at least 480000ms so the bounded sequential \
         restarts complete before the mid-epoch reconfiguration"
    );

    // Validator 0 (current build after the swap) records every authority's
    // consensus-submitted reconfiguration output via canonical BCS digests.
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
        // OCS read topology: 0 and 1 stay direct (relay servers); 2, 3 and
        // the joiner run peer-only SuiStateMirrored through them. The split
        // materializes at the swap; the v1.2.7 boot phase is all-direct.
        .with_direct_validators(&[0, 1])
        .with_ika_cli(ika_cli)
        // Deployed-faithful on-chain state (populated global-presign config).
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        // Boot the literal v1.2.7 committee at protocol v6; epoch 2
        // guarantees the genesis network DKG (v1.2.7 binary) completed
        // before the swap.
        .start_all(old)
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_committee_size(4)
        .expect_protocol_version_at_least(6)
        // Sequentially swap every validator to the current build. The
        // current binaries inherit the v1.2.7-written RocksDB state and
        // reshare the v1.2.7-DKG'd network key.
        .stop_and_swap(&[0, 1, 2, 3], current.clone())
        .expect_all_validators_healthy()
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .expect_committee_size(4)
        // ── Churn 1: grow 4 → 5 with a mirrored joiner. ────────────────────
        // The reshare encrypts the v1.2.7-origin key to a committee
        // including a party that never held it; the joiner installs the key
        // by the cert-pinned digest over the OCS mirrored path.
        .join_validator_mirrored(current)
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_committee_size(5)
        .expect_all_validators_healthy()
        // Every member of the 5-member committee — INCLUDING the mirrored
        // joiner — must report the aggregated (V4-tagged) canonical DKG
        // anchor and reconfiguration output.
        .expect_network_dkg_output_version_at_least(4)
        .expect_reconfiguration_output_version_at_least(4)
        // The 5-member reshare (mid-epoch 4, dealing to the joiner-inclusive
        // committee): per-authority output observations exist only around a
        // reshare in the CURRENT epoch, so convergence is asserted between
        // started/completed — never at epoch entry.
        .wait_for_network_key_reconfiguration_started(4)
        .wait_for_network_key_reconfiguration_completed(4)
        .expect_all_validators_healthy()
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        // The 5-member committee runs a full lifecycle against the reshared
        // v1.2.7-origin network key.
        .run_workload("v6-with-joiner")
        .record_mpc_timings("v6-with-joiner")
        // ── Churn 2: shrink 5 → 4 by removing an original validator. ──────
        // The removal lands mid-epoch 4, AFTER that epoch's reshare already
        // locked the 5-member epoch-5 committee — so epoch 5 still runs all
        // five members, epoch 5's mid-epoch reshare is the SHRINK deal (to
        // the 4-member epoch-6 committee), and the size drop is visible at
        // epoch 6.
        .remove_validator(3)
        .wait_for_epoch(5)
        .wait_for_all_validators_local_epoch(5)
        .expect_committee_size(5)
        .expect_all_validators_healthy()
        .wait_for_network_key_reconfiguration_started(5)
        .wait_for_network_key_reconfiguration_completed(5)
        .expect_all_validators_healthy()
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .wait_for_epoch(6)
        .expect_committee_size(4)
        // The removed validator's process keeps running until stopped.
        .stop_validator(3)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_log_line_absent("late network-key reconfiguration output DIVERGES")
        .expect_log_line_absent("failed to submit an MPC output message to consensus")
        .run()
        .await
        .expect("v1.2.7 -> current full-committee upgrade + committee churn in both directions");

    tracing::info!(
        "v1.2.7 churn PASSED: full binary swap over v1.2.7 state, a mirrored joiner folded \
         into the reshared v1.2.7-origin key (4→5), and a shrink reshare (5→4) all converged \
         while serving a full user lifecycle"
    );
}
