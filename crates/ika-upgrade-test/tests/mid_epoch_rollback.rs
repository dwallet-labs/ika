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
//! 2. **It re-emits already-settled work, and the volume is measured.** Peers
//!    still on the candidate count each re-submission on
//!    `ika_skipped_consensus_txns` (incremented once per consensus transaction
//!    whose digest is already in the folding node's processed set). That is
//!    the right counter of the two: it is checked BEFORE the handler's LRU
//!    fast path, and MPC-payload keys — the dominant term here — are
//!    deliberately never cached in that LRU, so they always reach it rather
//!    than `ika_skipped_consensus_txns_cache_hit`. The count
//!    is taken as a delta over the rollback window and compared against a
//!    CONTROL window of ordinary traffic — a full user lifecycle with nothing
//!    restarted — because the counter is cumulative and submission races nudge
//!    it, so a bare "nonzero" would prove nothing. The measured number is
//!    release-notes material; a count at or below the control level means the
//!    scenario failed to create the conditions it exists to measure.
//!
//!    Note on composition: v1.3.1 is NOT free of settled-state suppression.
//!    Its checkpoint-signature gate (`get_highest_verified_dwallet_checkpoint`)
//!    reads the perpetual checkpoint store, which survives the rollback, so it
//!    re-signs only the band between the verified watermark and what had been
//!    certified — the band the candidate's broader gate closed. The spray is
//!    therefore dominated by MPC messages and outputs replayed over the
//!    rebuilt rounds, which the per-kind breakdown in the measurement step
//!    reports.
//!
//! 3. **It returns to full participation, witnessed by a peer.** After the
//!    catch-up, a fresh workload is driven and a peer must record an MPC
//!    output authored by the rolled-back validator for a session outside the
//!    snapshot taken once catch-up finished. Sessions the re-derivation
//!    re-emitted outputs for are inside that snapshot by construction, so the
//!    spray cannot masquerade as participation, and the claim is a peer's
//!    observation rather than the subject's own liveness metric.
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
    let epoch_duration_ms = std::env::var("EPOCH_DURATION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(900_000);
    assert!(
        epoch_duration_ms >= 600_000,
        "the mid-epoch rollback requires an epoch of at least 600000ms so the re-derivation, \
         its measurement and the post-rollback workload all complete before the boundary that \
         would hand the rolled-back validator a fresh epoch store"
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
        .run_workload("pre-rollback-control")
        .expect_skipped_consensus_txns_delta("control", &peers, 0, None)
        .expect_epoch_at_most(2)
        // ── The event under test: the deployed release goes back on, on the
        //    same stores, mid-epoch, far from any boundary. ────────────────
        .record_skipped_consensus_txns("rollback", &peers)
        .stop_and_swap(&[SUBJECT], old)
        .expect_all_validators_healthy()
        .wait_for_all_validators_local_epoch(2)
        // ASSERTION 1 — it re-derives the epoch through its own table-writing
        // fold, against empty fold-side tables, and its rebuilt per-round
        // tables reach the round its peers have consumed.
        .wait_for_mpc_round_to_reach_peers(SUBJECT, &peers)
        // The #2057 signature: the pinned consensus store has no tolerant path
        // when the watermark and the store disagree, and it aborts rather than
        // clamping. An absent watermark reads as 0, which the assert accepts —
        // but that is a property of this store layout, not a guarantee, so the
        // run proves the shape never appeared instead of arguing it cannot.
        .expect_log_line_absent("assertion failed: last_commit_index > replay_after_commit_index")
        .expect_log_line_absent("Should be able to read last consensus index")
        .expect_epoch_at_most(2)
        // ASSERTION 2 — the spray, counted at the peers and compared against
        // the control window. The measured number is logged prominently by the
        // step itself; it is the "mid-epoch rollback re-emits" figure.
        .expect_skipped_consensus_txns_delta("rollback", &peers, 1, Some("control"))
        // ASSERTION 3 — full participation returns. The snapshot is taken
        // AFTER catch-up, so every session the re-derivation re-emitted an
        // output for is already inside it and cannot satisfy the assertion.
        .record_mpc_output_sessions("after-catch-up", WITNESS, SUBJECT)
        .run_workload("post-rollback")
        .expect_new_mpc_output_session("after-catch-up", WITNESS, SUBJECT)
        // Still the same epoch: everything above is mid-epoch behavior, not
        // the boundary reset that would make all three assertions free.
        .expect_epoch_at_most(2)
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
             the epoch, re-emit a measurable volume of already-settled work, and return to MPC \
             participation within the same epoch",
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
        re_emitted_consensus_transactions = re_emitted,
        control_window_baseline = control,
        "mid-epoch rollback PASSED: the v1.3.1 release re-derived the epoch from its first \
         commit against empty fold-side tables, re-sent {re_emitted} already-folded consensus \
         transactions to its peers (against {control} for an equivalent window of ordinary \
         traffic), and was witnessed by a peer contributing MPC output again before the epoch \
         boundary"
    );
}
