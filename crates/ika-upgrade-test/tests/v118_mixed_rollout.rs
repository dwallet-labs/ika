// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Literal mainnet-v1.1.8/current single-validator rollout gate.
//!
//! A four-validator committee boots on the actual `mainnet-v1.1.8` binary,
//! completes genesis network DKG, then upgrades exactly validator 0 to the
//! release candidate. The other three validators remain on v1.1.8 while the
//! mixed committee completes two protocol-v3 network-key reconfigurations.
//!
//! Epoch advancement alone is not evidence: three matching old validators can
//! preserve quorum while the upgraded validator submits different bytes,
//! records itself malicious, or never enters the new epoch. The scenario
//! therefore witnesses each reconfiguration's on-chain started/completed
//! states and checks local epoch, liveness, malicious reporting, pending work,
//! logs, and per-authority output digests before allowing the next boundary.
//!
//! Beyond the reshare itself, each reconfiguration is followed by a full user
//! **DKG → Presign → ECDSA Sign → Taproot Sign** lifecycle driven through the
//! `ika` CLI, so the gate also proves the mixed committee keeps *serving users*
//! at v3, not only that the system reshare converges. The workloads run in the
//! settled window after a reshare's assertions and before the next epoch — not
//! between the timed reconfiguration start/completed observations, which a
//! multi-minute lifecycle would otherwise perturb.

use std::path::PathBuf;
use std::time::Duration;

use ika_swarm_config::sui_client::GenesisGlobalPresignConfig;
use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::scenario::Scenario;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn v118_single_validator_rollout_survives_v3_network_key_resharing() {
    if std::env::var("RUN_V118_MIXED_ROLLOUT").is_err() {
        eprintln!(
            "skipping: set RUN_V118_MIXED_ROLLOUT=1 \
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
        "/tmp/ika-v118/target/release/ika-node",
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-v118-mixed-rollout".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "v118 mixed rollout requires an epoch of at least 480000ms so the bounded sequential restart completes before the mid-epoch reconfiguration"
    );

    // Validator 0 is the sole current-binary observer. It records every
    // authority's consensus-submitted reconfiguration output, including the
    // three literal historical validators, using canonical BCS digests.
    let current_observer = [0];

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        // Drives DKG/Presign/Sign through the `ika` CLI after each reshare.
        .with_ika_cli(ika_cli)
        .start_all(old)
        // Epoch 2 guarantees the all-v1.1.8 committee completed genesis
        // network DKG. Require every node's local epoch, not just the on-chain
        // counter that quorum progress can advance without a lagging member.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        // Prove this epoch's reshare has not started. With a >=8-minute epoch,
        // the midpoint is at least 4 minutes away; one graceful stop (bounded
        // at 60s) plus startup health wait (bounded at 120s) completes before
        // it, so success does not depend on racing a restart into active MPC.
        .expect_network_key_reconfiguration_not_started(2)
        // Upgrade exactly one validator. stop_and_swap is sequential, but a
        // one-element set makes the rollout topology unambiguous: 1 current +
        // 3 literal v1.1.8 for the rest of the scenario.
        .stop_and_swap(&[0], current)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        // First real mixed-version v3 reshare. Witness start explicitly after
        // the swap, then inspect every invariant before the epoch can hide a
        // minority failure behind quorum progress.
        .wait_for_network_key_reconfiguration_started(2)
        .wait_for_network_key_reconfiguration_completed(2)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        // Check the individual authority outputs first so a compatibility
        // failure reports the exact 3-vs-1 digest split before the aggregate
        // malicious-actor gauge stops the scenario.
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(2, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        // The mixed committee must also keep serving users, not just converge on
        // the system reshare. Run a full user lifecycle in the settled window
        // after the reshare's assertions — a fresh dWallet DKG, a global presign,
        // and an ECDSA + Taproot sign, all across the 1-current/3-v1.1.8
        // committee at v3. Placed here (not between the timed reshare
        // observations) so the ~minutes-long lifecycle cannot perturb them.
        .run_workload("mixed-v3-after-first-reshare")
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        // Repeat at the next boundary. This proves the first success was not a
        // one-off transition artifact and keeps the committee mixed throughout.
        .wait_for_network_key_reconfiguration_started(3)
        .wait_for_network_key_reconfiguration_completed(3)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(3)
        .expect_network_key_output_converged(&current_observer)
        .expect_malicious_actors_exactly(&current_observer, 0)
        .expect_no_pending_network_key_reconfiguration(3, &current_observer)
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        // Serve a second full user lifecycle after the second reshare, proving
        // continued user-facing service is not a one-off of the first boundary.
        .run_workload("mixed-v3-after-second-reshare")
        .wait_for_epoch(4)
        .wait_for_all_validators_local_epoch(4)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(3)
        .expect_all_validators_protocol_version_at_most(3)
        .run()
        .await
        .expect(
            "literal v1.1.8/current mixed committee must converge across v3 network-key resharing",
        );

    tracing::info!(
        "v1.1.8 mixed rollout PASSED: one current + three literal v1.1.8 validators \
         completed two protocol-v3 network-key reconfigurations with identical outputs \
         and served a full DKG/Presign/Sign user lifecycle after each"
    );
}
