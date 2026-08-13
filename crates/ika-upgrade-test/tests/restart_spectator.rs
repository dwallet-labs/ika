// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mid-epoch restart spectator gate (#1952).
//!
//! A validator restarted mid-epoch, in an epoch with an established
//! (prior-epoch-DKG'd) network key and ongoing internal-presign volume, must
//! RESUME registry-driven internal-presign instantiation within a bounded
//! window — not merely stay consensus-healthy while peers absorb every
//! session.
//!
//! This is the ingredient `v131_rollout` lacks: its binary swaps land minutes
//! from an epoch boundary and none of its gates assert per-validator top-up
//! participation, so a restarted validator that silently re-mints
//! already-completed internal-presign ordinals (the in-memory
//! `next_internal_presign_sequence_number` restarting at 1) passes every
//! convergence and workload gate — peers carry the sessions and the wedge
//! self-heals at the next boundary. In production (24h epochs, sustained
//! volume) that same state left all six dWallet Labs validators as pure MPC
//! spectators for the rest of the epoch: `active: 0`, completions only via
//! `reconstructed_from_consensus`, readiness never evaluated.
//!
//! The gate: after the restart, validator 0 must log (1) the ordinal-stream
//! seed from the persisted pool-slot high-water and (2) the one-shot
//! "resumed live instantiation" marker, and the run must stay free of the
//! #1952 silence-proofing invariant markers. The user workload must also
//! still complete (event-driven activation was never the broken path —
//! asserting it alone is exactly how the wedge stayed invisible).
//!
//! Fault-validation (test-testing playbook): revert the seed+fast-forward in
//! `instantiate_internal_presign_session` (restore the bare `.or_insert(1)`)
//! and this scenario must FAIL at step 1/2's timeout while
//! `expect_all_validators_healthy` and the workload still pass — reproducing
//! the production spectator signature.
//!
//! Opt-in (real binaries + long-running), via `RUN_RESTART_SPECTATOR=1`:
//!
//! ```bash
//! RUN_RESTART_SPECTATOR=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test restart_spectator -- --nocapture
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
async fn restarted_validator_resumes_internal_presign_top_up_mid_epoch() {
    if std::env::var("RUN_RESTART_SPECTATOR").is_err() {
        eprintln!(
            "skipping: set RUN_RESTART_SPECTATOR=1 \
             (needs IKA_VALIDATOR_BIN/IKA_NOTIFIER_BIN/IKA_BIN/SUI_BIN)"
        );
        return;
    }
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("info")
        .with_env()
        .init();

    let current = BinarySpec::Path(bin_from_env(
        "IKA_VALIDATOR_BIN",
        "target/release/ika-validator",
    ));
    let notifier = bin_from_env("IKA_NOTIFIER_BIN", "target/release/ika-notifier");
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-restart-spectator".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    // Long enough that the restart (right after the epoch-2 mid-epoch
    // reconfiguration completes) lands minutes from the next boundary — the
    // resume must be proven WITHIN the epoch, not by the boundary reset that
    // masked #1952 everywhere else.
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(600_000);
    assert!(
        epoch_duration_ms >= 480_000,
        "restart_spectator requires an epoch of at least 480000ms so the restart lands \
         far from the boundary and the resume gates complete inside the epoch"
    );

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1200))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        .start_all(current.clone())
        // Epoch 2: the network key was DKG'd in a prior epoch and has crossed
        // a reconfiguration boundary — the "established key" ingredient.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        // Ride past the epoch-2 mid-epoch reconfiguration: by then this
        // epoch's internal-presign pools hold minutes of fills (the persisted
        // ordinal high-water the seed reads), and the restart still lands
        // minutes from the boundary.
        .wait_for_network_key_reconfiguration_started(2)
        .wait_for_network_key_reconfiguration_completed(2)
        .expect_all_validators_healthy()
        // ── The event under test: a pure mid-epoch restart of one validator
        //    (same binary — this is a restart gate, not an upgrade gate). ──
        .stop_and_swap(&[0], current)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        // THE GATE (both lines are post-restart by construction: node.log is
        // truncated on restart): the ordinal stream must be seeded from the
        // persisted pool-slot high-water, and the top-up loop must land a
        // LIVE mint — the spectator state produces neither, ever.
        .wait_for_log_line_on_validator(
            0,
            "seeded internal-presign ordinal stream from the persisted pool-slot high-water",
        )
        .wait_for_log_line_on_validator(
            0,
            "internal presign top-up resumed live instantiation after a mid-epoch restart",
        )
        // Silence-proofing markers must not fire in a healthy run: the seed
        // disagreeing with the session map, or a registry read coming back
        // empty against a non-empty coordinator registry, are #1952 invariant
        // violations, not noise.
        .expect_log_line_absent("internal_presign_ordinal_fast_forward_exhausted")
        .expect_log_line_absent("network_key_registry_read_empty")
        .expect_log_line_absent("stranded_network_key_missing_from_registry_read")
        // The user path must ALSO still work — but it alone proving healthy
        // is exactly how the spectator state stayed invisible, hence the
        // top-up gates above come first.
        .run_workload("post-restart-user-lifecycle")
        // And the network still advances normally afterwards.
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .run()
        .await
        .expect(
            "a validator restarted mid-epoch must resume live internal-presign top-up \
             instantiation within the same epoch",
        );

    tracing::info!(
        "restart_spectator PASSED: the restarted validator seeded its internal-presign \
         ordinal stream from persisted state and resumed live registry-driven \
         instantiation mid-epoch"
    );
}
