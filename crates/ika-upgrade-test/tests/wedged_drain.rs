// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The wedged-but-alive MPC drain, end to end on a real cluster (ika #2102).
//!
//! # What this builds that nothing else has
//!
//! A drain that is ALIVE BUT STUCK: the MPC service keeps running — admin
//! endpoint answering, metrics served, computations spawned, consensus blocks
//! proposed — but it stops taking rounds off the bounded round channel. The
//! consensus fold then parks on that channel, and the commit-liveness watchdog
//! HOLDS, correctly: a parked fold is holding a commit it already received,
//! which is the opposite of the isolation the watchdog exists to catch. So
//! nothing exits, nothing else alarms, and the only external evidence is the
//! counters.
//!
//! Every piece has in-process coverage — the transport's park accounting
//! (`round_transport.rs`), the watchdog's `fold_blocked` hold
//! (`commit_liveness_watchdog.rs`), the out-of-band publisher that keeps
//! writing while the drain is stuck (`publish_round_transport_metrics`). That
//! they COMPOSE this way on a real node did not, which is what
//! `dev-docs/specs/event-sourced-epoch.md` listed as `(REQUIRED)`.
//!
//! # The shape
//!
//! One validator of a healthy four is restarted with the production binary's
//! park hook armed (`IKA_TEST_PARK_MPC_DRAIN_AFTER_ROUND`, read in
//! `ika-core`'s `dwallet_mpc::park_drain_test_hook`), and with its
//! commit-liveness bound lowered so the hold is a claim with teeth. Then, from
//! OUTSIDE — `/metrics` only, no logs, nothing the wedged subsystem reports
//! about itself:
//!
//! - `ika_consensus_fold_blocked_seconds_total` climbs while
//!   `ika_last_process_mpc_consensus_round` stays flat;
//! - `ika_consensus_round_channel_depth` pins at the channel capacity;
//! - `ika_consensus_commit_silence_seconds` does NOT climb toward the bound
//!   (the watchdog is holding) and the process never restarts;
//! - `consensus_ika_last_committed_leader_round` keeps advancing — the node is
//!   still in consensus, which is what separates this from an isolated node;
//! - and the three peers show NONE of it.
//!
//! Then the park is released and the same validator must return to the peers'
//! own healthy predicate, with no restart.
//!
//! # Why the watchdog bound is lowered
//!
//! At the 900s default the watchdog also will not exit a process younger than
//! 1800s, so no test-length park could ever reach a breach and "the watchdog
//! held" would pass by arithmetic rather than by the hold. With the bound at
//! [`WATCHDOG_BOUND_SECS`] the floor is twice that, and the wedge is observed
//! for [`WEDGE_WINDOW`] on a process already older than the floor — so if the
//! `fold_blocked` hold were ever dropped, this validator would EXIT inside the
//! window and the run would fail on the uptime and health assertions. That is
//! the fault-validation for this scenario: delete the `fold_blocked` term from
//! `CommitLivenessWatchdog::tick` and this test must fail while every other
//! upgrade-test scenario still passes.
//!
//! # Timing, and why the park lives in epoch 2's first half
//!
//! The whole park/unpark sequence runs between the cluster entering epoch 2
//! and that epoch's mid-epoch network-key reconfiguration, which
//! `system_inner.move` schedules at `epoch_duration_ms / 2`. Epoch 2 because
//! epoch 1 IS genesis — the on-chain counter starts there and the network DKG
//! runs inside it — so the counter reaching 2 is the signal that the DKG
//! finished and the committee crossed a boundary with it. The first half of
//! that epoch because a validator absent from a RESHARE is a different
//! experiment, one whose outcome is decided by the MPC protocol's treatment of
//! a silent party rather than by anything this scenario is about.
//!
//! The epoch is long ([`EPOCH_DURATION_MS`]) so the sequence fits in that half
//! with room for the unknown — how long the cluster takes to fill 1024 rounds
//! is its commit rate, which differs by an order of magnitude between a loaded
//! CI pod and a quiet machine. `expect_network_key_reconfiguration_not_started`
//! brackets the park so a sequence that DID overrun into the reshare fails
//! loudly with that as the reason, instead of quietly becoming a test of
//! something else. After the recovery the run rides into that same reshare and
//! requires the recovered validator to take part in it with no convictions —
//! a full boundary's worth of evidence without waiting out another epoch.
//!
//! Opt-in (real binaries + long-running), via `RUN_WEDGED_DRAIN=1`:
//!
//! ```bash
//! RUN_WEDGED_DRAIN=1 \
//!   IKA_VALIDATOR_BIN=target/release/ika-validator \
//!   IKA_NOTIFIER_BIN=target/release/ika-notifier \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test wedged_drain -- --nocapture
//! ```

use std::path::PathBuf;
use std::time::Duration;

use ika_upgrade_test::binary::BinarySpec;
use ika_upgrade_test::cluster::COMMIT_SILENCE_NOT_ARMED;
use ika_upgrade_test::scenario::Scenario;

/// The validator whose drain is parked. Every other index is a healthy peer,
/// and the peers are asserted on in the same windows — the wedge has to be one
/// node's, not the cluster's.
const PARKED: usize = 0;
const PEERS: [usize; 3] = [1, 2, 3];

/// Commit-liveness bound for the parked validator only. Above any healthy
/// commit gap this cluster produces, and small enough that a park observed for
/// [`WEDGE_WINDOW`] outlives both it and the watchdog's `2x` uptime floor —
/// see the module docs.
const WATCHDOG_BOUND_SECS: u64 = 120;

/// How long the wedge is observed. Longer than `2 * WATCHDOG_BOUND_SECS`, so
/// a dropped hold breaches inside the window rather than after the run ends.
const WEDGE_WINDOW: Duration = Duration::from_secs(300);

/// How long the recovery is observed. Only has to be long enough for the
/// drain's consumed round and the committed-leader round to move, since the
/// decisive recovery evidence (consuming past the round it was stuck on)
/// is already established before this window opens.
const RESUME_WINDOW: Duration = Duration::from_secs(120);

/// Ceiling for `ika_consensus_commit_silence_seconds` throughout. A held
/// watchdog publishes the `NOT_ARMED` sentinel, and an unheld-but-healthy one
/// publishes seconds since the last commit — a couple of watchdog poll
/// intervals at most on this cluster. Under [`WATCHDOG_BOUND_SECS`] so a
/// watchdog counting a parked fold as silence trips this on the way to the
/// bound (it would then exit, which the uptime and health assertions catch
/// too — this one just reports the cause rather than the corpse), but not so
/// tight that a loaded runner's ordinary commit jitter on a HEALTHY peer reads
/// as a fault.
const SILENCE_CEILING_SECONDS: i64 = WATCHDOG_BOUND_SECS as i64 * 3 / 4;

/// Genesis epoch duration. Half of it is the window the whole park sequence
/// has to fit inside (see the module docs), and the two observation windows
/// are only part of that — the arming restart's replay and the time to fill
/// 1024 rounds are the parts nobody can size in advance. Deliberately generous
/// rather than tight: the cost of an over-long epoch is CI minutes, the cost of
/// a tight one is a scenario that fails for its own timing.
const EPOCH_DURATION_MS: u64 = 1_800_000;

/// The epoch the park runs in: 2, because 1 is genesis and the network DKG
/// runs inside it.
const PARK_EPOCH: u64 = 2;

fn bin_from_env(var: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(var).unwrap_or_else(|_| default.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wedged_mpc_drain_holds_the_watchdog_and_recovers_without_a_restart() {
    if std::env::var("RUN_WEDGED_DRAIN").is_err() {
        eprintln!(
            "skipping: set RUN_WEDGED_DRAIN=1 \
             (needs IKA_VALIDATOR_BIN/IKA_NOTIFIER_BIN/SUI_BIN)"
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
    let sui = bin_from_env("SUI_BIN", "sui");
    let repo = std::env::current_dir()
        .expect("cwd")
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    let base = PathBuf::from(
        std::env::var("UPGRADE_TEST_DIR")
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-wedged-drain".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);

    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(EPOCH_DURATION_MS);
    // The park has to finish inside the FIRST HALF of the epoch — that is when
    // the mid-epoch reshare starts. Demand twice the observation budget there,
    // so the arming restart's replay and the fill to capacity have as much room
    // again as the two windows put together.
    let observation_budget_secs = WEDGE_WINDOW.as_secs() + RESUME_WINDOW.as_secs();
    assert!(
        epoch_duration_ms / 2_000 >= observation_budget_secs * 2,
        "wedged_drain needs an epoch of at least {}ms: the park sequence must finish inside the \
         epoch's FIRST HALF (the mid-epoch reshare starts at epoch_duration_ms/2), and that half \
         has to hold {observation_budget_secs}s of observation plus the arming restart and the \
         time to fill the round channel; got {epoch_duration_ms}ms",
        observation_budget_secs * 4_000
    );
    assert!(
        WEDGE_WINDOW.as_secs() > 2 * WATCHDOG_BOUND_SECS,
        "the wedge must be observed for longer than the watchdog's uptime floor (2x its bound), \
         or a dropped fold-parked hold could not exit the node inside the window and the hold \
         assertion would be vacuous"
    );

    Scenario::new(4, repo, sui, notifier)
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(2400))
        .start_all(current)
        // A settled cluster before anything is broken: epoch 1 is genesis and
        // the network DKG runs inside it, so the counter reaching 2 — on chain
        // AND in every validator's own epoch store — means the DKG finished
        // and the committee crossed a boundary with it. The drain under test
        // is one that was demonstrably working.
        .wait_for_epoch(PARK_EPOCH)
        .wait_for_all_validators_local_epoch(PARK_EPOCH)
        .expect_all_validators_healthy()
        // The park window opens here: the epoch's reshare has not started.
        .expect_network_key_reconfiguration_not_started(PARK_EPOCH)
        // ── The event under test ──────────────────────────────────────────
        .park_mpc_drain(PARKED, WATCHDOG_BOUND_SECS)
        // The wedge is formed when the fold is parked on a full channel, not
        // when the hook fires; how long that takes is the cluster's commit
        // rate, so it is polled rather than slept on.
        .wait_for_round_channel_at_capacity(PARKED)
        .expect_drain_wedged(PARKED, &PEERS, WEDGE_WINDOW, SILENCE_CEILING_SECONDS)
        // Nothing may have exited, including the parked node itself.
        .expect_all_validators_healthy()
        // ...and the park stayed inside the pre-reshare window. If it did not,
        // the parked validator was absent from a reshare and the run is
        // measuring something else — fail here, with that as the reason,
        // rather than downstream on a convergence gate.
        .expect_network_key_reconfiguration_not_started(PARK_EPOCH)
        // A validator doing NO MPC is a spectator, not a malicious actor —
        // production's #1952 spectator validators were never convicted for it.
        // Asserted rather than assumed, because "the peers convicted the
        // parked node" is the way this scenario would quietly become a test of
        // the MPC protocol's treatment of a silent party.
        .expect_malicious_actors_exactly(&PEERS, 0)
        // ── Recovery ──────────────────────────────────────────────────────
        .unpark_mpc_drain(PARKED)
        .expect_drain_resumed(PARKED, &PEERS, RESUME_WINDOW, SILENCE_CEILING_SECONDS)
        .expect_all_validators_healthy()
        // And the recovered validator takes part in this epoch's reshare like
        // any other member — a full boundary's worth of evidence that the park
        // left nothing behind, without waiting out another epoch.
        .wait_for_network_key_reconfiguration_started(PARK_EPOCH)
        .wait_for_network_key_reconfiguration_completed(PARK_EPOCH)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(PARK_EPOCH)
        .expect_malicious_actors_exactly(&[PARKED, PEERS[0], PEERS[1], PEERS[2]], 0)
        // The watchdog's breach line is logged just before it exits the node;
        // it must appear on no validator, which also covers the gaps between
        // the observation windows.
        .expect_log_line_absent("no consensus commit for longer than the commit-liveness bound")
        // A drain that stopped because the node convicted itself is the OTHER
        // way a flat consumed round and a pinned channel can appear, and it is
        // not the one under test. The metric assertions already exclude it —
        // there the fold DETACHES (`RoundTransportSender::send` returns early
        // once `drain_gone` latches), so blocked seconds STOP accruing, and
        // `evaluate_wedged_drain` requires them to climb. This names its cause
        // as well, so a run that got there is diagnosed rather than merely
        // failed. Both literals, because the conviction and the service loop
        // breaking on it are two different emit sites — and the needles are
        // the MESSAGE text, not the Rust identifier `recognized_self_as_
        // malicious`, which no binary ever writes to a log (the anomaly kind
        // it does write is `service_exit_self_malicious`). The "the MPC drain
        // has exited" line is deliberately NOT asserted on: the fold can
        // legitimately observe a closed channel at an epoch boundary, and a
        // whole-run log assertion cannot tell that apart from the failure.
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("the node has identified itself as malicious")
        .run()
        .await
        .expect(
            "a validator whose MPC drain is wedged but alive must hold the commit-liveness \
             watchdog, report the wedge on its counters, leave its peers untouched, and recover \
             without a restart",
        );

    tracing::info!(
        silence_sentinel = COMMIT_SILENCE_NOT_ARMED,
        "wedged_drain PASSED: the parked validator's fold blocked while its consumed round \
         stayed flat and its channel pinned at capacity, the watchdog held rather than exiting, \
         the peers were unaffected, and the drain resumed on release with no restart"
    );
}
