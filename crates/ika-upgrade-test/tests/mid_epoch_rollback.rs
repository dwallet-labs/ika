// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mid-epoch ROLLBACK: the deployed v1.3.1 release restarted, mid-epoch, on
//! stores an event-sourcing binary has been writing.
//!
//! Every other scenario in this crate upgrades forward — v1.3.1 boots first
//! and the candidate replaces it. This one runs the candidate first and puts
//! the RELEASE back afterwards, which is the direction an operator takes to
//! recover from something else and the one direction nothing exercised.
//!
//! # What the rolled-back binary finds
//!
//! The candidate keeps all derived epoch state in memory: no per-round MPC
//! stream, no `last_consensus_stats` watermark, no fold-side tables. Only the
//! 25 tables pinned by `the_epoch_store_keeps_only_state_no_replay_reproduces`
//! (presign pools, assigned presigns, output digests) are durable, and the
//! consensus store and the perpetual checkpoint store are untouched. So v1.3.1
//! reopens an epoch store in which everything its own fold writes is EMPTY,
//! and its `replay_after` — `last_processed_subdag_index()`, read from the
//! absent watermark — is 0. Mysticeti re-sends the epoch from its first
//! commit, and the old fold re-derives all of it through its table-WRITING
//! path, against an empty `consensus_message_processed` dedup table.
//!
//! Three consequences, each asserted here, each with its own evidence:
//!
//! 1. **It comes up and re-derives, tolerating the empty tables.** The witness
//!    is `ika_last_process_mpc_consensus_round` on the rolled-back node: v1.3.1
//!    sets it from the per-round tables *its own fold writes*, so the gauge
//!    climbing from zero to the round its peers have consumed IS the proof
//!    that the table-writing path rebuilt them and reached the epoch's head.
//!    A crash-loop cannot reach this assertion — the swap step blocks on the
//!    node answering its admin server, and every later step re-reads it.
//!
//! 2. **How much already-settled work it re-emits is MEASURED, not
//!    predicted.** Peers still on the candidate count each re-submission on
//!    `ika_skipped_consensus_txns` (incremented once per consensus transaction
//!    whose digest is already in the folding node's processed set). That is
//!    the right counter of the two: it is checked BEFORE the handler's LRU
//!    fast path, and MPC-payload keys are deliberately never cached in that
//!    LRU, so they always reach it rather than
//!    `ika_skipped_consensus_txns_cache_hit`. The reading is a delta over the
//!    rollback window against a CONTROL window of the same composition — one
//!    full user lifecycle each, nothing restarted in the control — and the
//!    difference between them is the figure the operator-facing note is
//!    written from.
//!
//!    The assertion is only a liveness floor on the counters. It is NOT that
//!    the rollback window exceeds the control: the first version asserted
//!    exactly that, on the theory that a re-derivation sprays re-submissions,
//!    and the first measured run recorded 0 against a control of 171. That is
//!    the phenomenon, not a broken test — so the prediction came out of the
//!    assertion and the number goes in the report.
//!
//!    Three layers suppress the spray, and only the first two were anticipated:
//!    v1.3.1's checkpoint-signature gate
//!    (`get_highest_verified_dwallet_checkpoint`) reads the perpetual
//!    checkpoint store, which survives the rollback, so it re-signs only the
//!    band between the verified watermark and what had been certified; the
//!    candidate's broader gate closed that band. And #2023 catch-up mode —
//!    entered on the rolled-back node with a 13k-round backlog — reconstructs
//!    every replayed session as `reconstructed_from_consensus`, `active=false`
//!    and suppresses recomputation until the backlog drains, so the MPC
//!    messages and outputs that would have dominated a re-emission are never
//!    recomputed to be re-sent. The per-class breakdown in the measurement
//!    step reports whatever does show up.
//!
//! 3. **It returns to full participation, witnessed by a peer.** Once catch-up
//!    mode has EXITED — the point at which v1.3.1 resumes computing rather
//!    than reconstructing — a fresh workload is driven and a peer must record
//!    an MPC output authored by the rolled-back validator for a session
//!    outside the snapshot taken at that moment. Every session the
//!    re-derivation reconstructed is inside that snapshot by construction, so
//!    replayed work cannot masquerade as participation, and the claim is a
//!    peer's observation rather than the subject's own liveness metric.
//!    This, not the drain's catch-up time, is what measures how long a
//!    rollback costs MPC.
//!
//! The whole experiment is bracketed by `expect_epoch_at_most`: an epoch
//! boundary hands every validator a fresh epoch store and would make all three
//! assertions trivially true, so drifting across one fails the run instead of
//! quietly voiding it.
//!
//! Opt-in (real binaries + long-running), via `RUN_MID_EPOCH_ROLLBACK=1`:
//!
//! ```bash
//! # OLD_BIN: the v1.3.1 ika-validator; NEW_BIN: the candidate
//! RUN_MID_EPOCH_ROLLBACK=1 \
//!   OLD_BIN=/path/to/ika-validator-v1.3.1 \
//!   NEW_BIN=target/release/ika-validator \
//!   NOTIFIER_BIN=target/release/ika-notifier \
//!   IKA_BIN=target/release/ika \
//!   SUI_BIN=$(which sui) \
//!   cargo test --release -p ika-upgrade-test --test mid_epoch_rollback -- --nocapture
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
async fn a_mid_epoch_rollback_to_v131_re_derives_the_epoch_and_rejoins_mpc() {
    if std::env::var("RUN_MID_EPOCH_ROLLBACK").is_err() {
        eprintln!(
            "skipping: set RUN_MID_EPOCH_ROLLBACK=1 \
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
        "/mnt/nvme0n1p1/v131-bins/ika-validator",
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
            .unwrap_or_else(|_| "/mnt/nvme0n1p1/tmp/ika-mid-epoch-rollback".to_string()),
    );
    let _ = std::fs::remove_dir_all(&base);
    // Everything after the rollback — the re-derivation, its measurement, a
    // fresh workload and a peer's observation of it — has to fit inside the
    // SAME epoch the rollback happened in, because the next boundary hands the
    // node a fresh epoch store and ends the experiment. That is a longer
    // budget than the forward scenarios need.
    let epoch_duration_ms: u64 = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_800_000);
    // Budget, from the timings the first two runs measured rather than from a
    // round number. The phases before the rollback are scheduled as FRACTIONS
    // of the epoch, so they scale with it and only the remainder is absolute:
    //
    //   ~0.55 E  mid-epoch network-key reconfiguration completes
    //   ~0.59 E  control workload done, rollback taken
    //   ~0.635 E epoch-close lock engages (measured 12.7 min into a 20 min
    //            epoch) — global-presign votes are held from here
    //
    // so the usable post-rollback window is about 0.365 E, and it has to cover
    // the swap (~25 s), the catch-up (~15 s), a workload (~40 s), the peer
    // witness (bounded at MPC_WITNESS_TIMEOUT = 300 s) and the closing
    // assertions. That is ~380 s of work plus slack; 0.365 E >= 600 s keeps a
    // factor of 1.5 in hand and puts the floor at 1_644_000 ms.
    const POST_ROLLBACK_BUDGET_SECS: u64 = 600;
    const USABLE_EPOCH_FRACTION_PER_MILLE: u64 = 365;
    let usable_ms = epoch_duration_ms * USABLE_EPOCH_FRACTION_PER_MILLE / 1000;
    assert!(
        usable_ms >= POST_ROLLBACK_BUDGET_SECS * 1000,
        "EPOCH_DURATION_MS={epoch_duration_ms} leaves only {usable_ms}ms after the epoch-close \
         lock engages at ~63.5% of the epoch, and the post-rollback phase needs at least \
         {}ms. Raise it to 1800000 (the recommended value) — everything after the rollback has \
         to finish inside the SAME epoch, because the next boundary hands the validator a fresh \
         epoch store and ends the experiment",
        POST_ROLLBACK_BUDGET_SECS * 1000
    );

    // Validator 0 is rolled back; 1-3 stay on the candidate and are the only
    // honest witnesses of what 0 re-sends. A validator cannot count its own
    // re-emissions: the dedup set that would recognise them is exactly the
    // state its restart discarded.
    const SUBJECT: usize = 0;
    const WITNESS: usize = 1;
    let peers = [1, 2, 3];

    let report = Scenario::new(4, repo, sui, notifier)
        // A pure binary swap in both directions: v7 is the only version either
        // binary supports, so there is no protocol boundary in this scenario
        // and the pin keeps it that way once a v8 exists.
        .with_supported_protocol_versions(SupportedProtocolVersions::new_for_testing(7, 7))
        .with_base_dir(base)
        .with_epoch_duration_ms(epoch_duration_ms)
        .with_epoch_timeout(Duration::from_secs(1800))
        .with_genesis_protocol_version(ProtocolVersion::new(7))
        .with_genesis_global_presign_config(GenesisGlobalPresignConfig::Full)
        .with_ika_cli(ika_cli)
        // ── The candidate runs the network first. This is the direction that
        //    makes the stores event-sourced in the first place. ─────────────
        .start_all(current)
        // Epoch 2: the network key was DKG'd at v7 and has crossed a
        // reconfiguration boundary, so the epoch being rolled back into has a
        // real history to re-derive rather than a genesis stub.
        .wait_for_epoch(2)
        .wait_for_all_validators_local_epoch(2)
        .expect_all_validators_healthy()
        .expect_protocol_version_at_most(7)
        // Ride past the mid-epoch reconfiguration so the epoch holds real MPC
        // traffic — the rounds the old binary's fold will have to rebuild.
        .wait_for_network_key_reconfiguration_started(2)
        .wait_for_network_key_reconfiguration_completed(2)
        .expect_all_validators_healthy()
        // ── Control window: a full user lifecycle, all four validators on the
        //    candidate, nothing restarted. Whatever re-submission this window
        //    records is the noise floor the rollback has to beat. ───────────
        .record_skipped_consensus_txns("control", &peers)
        // CALIBRATION. The same two instruments assertion 3 will use, pointed
        // at the same subject while it is HEALTHY. If a validator that is
        // demonstrably fine cannot be witnessed here, the instrument is broken
        // and the run must say so NOW — naming the instrument — rather than
        // thirty minutes later, after a rollback, in words that blame the
        // rollback. Run 2 died exactly that way: an authority-label format
        // mismatch made the witness structurally incapable of seeing anything,
        // and the failure it produced accused the subject of not doing MPC.
        //
        // It also measures the witness latency on a healthy node, which is the
        // number the post-rollback budget above is built from.
        .record_mpc_output_sessions("calibration", WITNESS, SUBJECT)
        .record_mpc_completions("calibration", SUBJECT)
        .run_workload("pre-rollback-control")
        .expect_new_mpc_output_session("calibration", WITNESS, SUBJECT, 2)
        .expect_more_mpc_completions("calibration", SUBJECT, 2)
        .expect_skipped_consensus_txns_delta("control", &peers, 0, None)
        .expect_epoch_at_most(2)
        // ── The event under test: the deployed release goes back on, on the
        //    same stores, mid-epoch, far from any boundary. ────────────────
        .record_skipped_consensus_txns("rollback", &peers)
        // Probe the #2023 catch-up transitions BEFORE the swap. Both binaries
        // emit these lines verbatim and node.log appends across restarts, so
        // presence proves nothing — only a FRESH occurrence is about v1.3.1.
        .record_log_line_count_on_validator(
            "catch-up-entered",
            SUBJECT,
            "MPC service entered catch-up mode",
        )
        .record_log_line_count_on_validator(
            "catch-up-exited",
            SUBJECT,
            "MPC service exited catch-up mode",
        )
        .stop_and_swap(&[SUBJECT], old)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        // ASSERTION 1 — it re-derives the epoch through its own table-writing
        // fold, against empty fold-side tables, and its rebuilt per-round
        // tables reach the round its peers have consumed.
        .wait_for_mpc_round_to_reach_peers(SUBJECT, &peers)
        // …and the re-derivation goes through #2023 catch-up mode, which is
        // WHY it reaches the head so fast: the replayed stream reconstructs
        // sessions rather than recomputing them. Both transitions are pinned,
        // because entering without exiting is a validator that never resumes
        // computing — a passing assertion 1 with none of its meaning.
        //
        // If the ENTER probe is what fails, read it as the scenario losing its
        // subject rather than as a regression: catch-up needs a backlog past
        // `enter_threshold` (5000 rounds), so no entry means the rollback
        // landed too early in the epoch to force the deep re-derivation this
        // scenario exists to exercise. The first measured run had 13,196
        // rounds of backlog, so the margin is wide — but it is a margin, not a
        // guarantee, and it shrinks if the epoch or the pre-rollback phase does.
        .wait_for_new_log_line_on_validator("catch-up-entered", SUBJECT)
        .wait_for_new_log_line_on_validator("catch-up-exited", SUBJECT)
        // The #2057 signature: the pinned consensus store has no tolerant path
        // when the watermark and the store disagree, and it aborts rather than
        // clamping. An absent watermark reads as 0, which the assert accepts —
        // but that is a property of this store layout, not a guarantee, so the
        // run proves the shape never appeared instead of arguing it cannot.
        .expect_log_line_absent("assertion failed: last_commit_index > replay_after_commit_index")
        .expect_log_line_absent("Should be able to read last consensus index")
        .expect_epoch_at_most(2)
        // ASSERTION 3 — full participation returns. The snapshot is taken
        // after catch-up mode has EXITED, so every session the re-derivation
        // reconstructed is already inside it and cannot satisfy the assertion.
        .record_mpc_output_sessions("after-catch-up", WITNESS, SUBJECT)
        .record_mpc_completions("after-catch-up", SUBJECT)
        .run_workload("post-rollback")
        // Two legs, because they fail for different reasons. The peer-witness
        // is the strong claim — another validator saw this one's output for
        // new work — but it can be lost legitimately: any three of four
        // validators form a quorum, so the subject's output is sometimes
        // superfluous and never observed (measured on a healthy cluster: 147
        // of 306 quorums reached without it). The completions leg asks the
        // narrower question of whether the node carries sessions through to
        // completion at all, which a spectator fails and a merely-unlucky
        // contributor passes.
        //
        // Both POLL. An earlier version read the completions total once and
        // called it "the leg no race can answer falsely"; two fault dispatches
        // then failed on it while a peer had witnessed the same subject
        // contributing 5 ms earlier. The counter moves when the subject's own
        // drain reaches the quorum, which is strictly after a peer can see the
        // output — a claim that something is race-free belongs in an error
        // message only once the race has been ruled out rather than asserted
        // away.
        //
        // Calibration above proves both instruments can see a healthy subject
        // in this cluster, which is what makes a post-rollback failure of
        // either one readable as a statement about the rollback.
        .expect_new_mpc_output_session("after-catch-up", WITNESS, SUBJECT, 2)
        .expect_more_mpc_completions("after-catch-up", SUBJECT, 2)
        // ASSERTION 2 — closed only NOW, so the rollback window spans the whole
        // recovery AND carries exactly one workload, like the control window.
        // Closing it at the catch-up (as the first version did) compared a
        // window containing a full user lifecycle against one containing an
        // idle 15 seconds, which is not a comparison. The floor is a liveness
        // check on the counters; the difference against the control is the
        // measured re-emission figure and is reported, not asserted.
        .expect_skipped_consensus_txns_delta("rollback", &peers, 1, Some("control"))
        // FAULT F4: claim the run is still in epoch 1 when it is demonstrably
        // in epoch 2. The ceiling is what stops the whole scenario silently
        // degrading into a boundary restart, and every other assertion leans
        // on it, so it must be shown to fire.
        .expect_epoch_at_most(1)
        .expect_all_validators_healthy()
        // And the mixed committee still closes the epoch normally afterwards.
        .wait_for_epoch(3)
        .wait_for_all_validators_local_epoch(3)
        .expect_all_validators_healthy()
        .expect_log_line_absent("node recognized itself as malicious")
        .expect_log_line_absent("recognized_self_as_malicious")
        .run()
        .await
        .expect(
            "the v1.3.1 release rolled back mid-epoch onto event-sourced stores must re-derive \
             the epoch through its own catch-up path and return to MPC participation within the \
             same epoch, with the already-settled work it re-sends measured at its peers",
        );

    // The headline number, restated where a reader of the run's last lines
    // will find it: this is the figure the operator-facing "mid-epoch rollback
    // re-emits" note is written from.
    let re_emitted = report
        .resubmission_totals
        .get("rollback")
        .copied()
        .expect("the rollback window was measured or the run would have failed");
    let control = report
        .resubmission_totals
        .get("control")
        .copied()
        .expect("the control window was measured or the run would have failed");
    tracing::info!(
        rollback_window_total = re_emitted,
        control_window_total = control,
        re_emission_attributable_to_the_rollback = re_emitted as i64 - control as i64,
        "mid-epoch rollback PASSED: the v1.3.1 release re-derived the epoch from its first \
         commit against empty fold-side tables and was witnessed by a peer contributing MPC \
         output again before the epoch boundary. Its window re-sent {re_emitted} already-folded \
         consensus transactions against {control} for a window of the same composition without \
         a rollback in it — the difference is what a mid-epoch rollback costs the DAG"
    );
}
