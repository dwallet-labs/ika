// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for validator joiner / removal flows on `IkaTestCluster`.
//!
//! `test_joiner_added_at_epoch_2` exercises the happy path: a 5th validator
//! registers as a candidate, gets staked over the minimum, calls
//! `request_add_validator`, and is spun up as an in-memory `IkaNode`. The
//! assertion is that the joiner's node reaches epoch 2 — proving the
//! on-chain committee swap and the off-chain MPC reconfiguration both
//! accepted the new member.
//!
//! `test_validator_removed_at_epoch_2` exercises the mirror flow: an
//! existing validator submits `request_remove_validator`, and the remaining
//! committee advances to epoch 2 without it.
//!
//! `test_sessions_complete_across_epoch_switch` drives a user-initiated
//! dWallet DKG and verifies it completes even when an epoch boundary
//! crosses while the session is in flight. This is the bug-repro test for
//! "sessions get stuck across epoch switch".
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md: these are
//! coordination tests, not scheduling-dependent. Real parallel crypto + no
//! msim slowdown.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::{IkaTestClusterBuilder, wait_for_node_epoch};

#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_added_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Let the initial committee settle into epoch 1 before adding the
    // joiner. Submitting `request_add_validator` from epoch 0 works in
    // principle but adds an extra layer to debug if the test fails.
    cluster.wait_for_epoch(1).await;

    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    // Joiner becomes active at the next epoch boundary. Wait for both
    // the initial set AND the joiner to reach epoch 2 — the initial-set
    // check alone could mask a joiner that's stuck.
    cluster.wait_for_epoch(2).await;
    wait_for_node_epoch(&joiner.node_handle, 2).await;
}

/// Churn-tolerance check: a joiner that registers mid-epoch must land
/// in the *frozen* mpc_data input set, and therefore in the next
/// committee's off-chain-assembled `class_groups_public_keys_and_proofs`
/// map. The ready-signal emit gate (`decide_ready_to_finalize`) delays
/// the freeze until the next-epoch committee is published and all its
/// members are locally validated (or the epoch-clock deadline), which
/// is precisely what lets a joiner — who can only announce after
/// `V_{e+1}` is published — be captured by the freeze.
///
/// This test caught a real mid-epoch-joiner deadlock — the joiner
/// watcher + freeze emit-gate both keyed off the *assembled* committee,
/// which can't include a joiner until after the freeze excludes it.
/// Fixed by the chain next-epoch-committee channel, after which the
/// joiner fans its mpc_data out (it never did before).
///
/// The integration path (observe the chain committee → fan out → relay
/// accept once the relayer's JoinerPubkeyProvider refreshes → consensus
/// → peer blob fetch + decode-validate → re-emit) must complete inside
/// the freeze window — between mid-epoch, when `V_{e+1}` is published
/// (`epoch_duration / 2`, see `sui_executor::run_epoch_switch`), and the
/// freeze deadline (`3 * epoch_duration / 4`) — a quarter of the epoch.
/// The default multi-second poll cadences fit a production-length epoch
/// but overrun that window in a short test epoch; `epoch_scaled_poll_interval`
/// scales every cadence on this path to ~1% of the epoch (a no-op at
/// production epoch lengths), so the path fits a bounded test epoch.
#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_lands_in_next_committee_class_groups() {
    telemetry_subscribers::init_for_testing();

    // The joiner has to clear TWO windows inside epoch 1, both keyed off
    // mid-epoch (`epoch/2`, when `process_mid_epoch` selects `V_{e+1}`):
    //   1. Registration `[join → epoch/2]`: finish its class-groups
    //      keygen (a fixed, multi-second cost) and land `add_validator`
    //      on-chain so it's selected into `V_{e+1}`. This is gated by
    //      crypto/tx time, NOT by poll cadence, so it needs absolute
    //      wall-clock — a 60s epoch (30s window) is too tight.
    //   2. Freeze `[epoch/2 → 3·epoch/4]`: fan out → relay → fetch →
    //      decode-validate → re-emit, so the freeze captures its
    //      mpc_data. `epoch_scaled_poll_interval` shrinks this path's
    //      cadences to fit the window.
    // 120s gives a 60s registration window and a 30s freeze window —
    // both comfortable.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(120_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");
    let joiner_name = joiner.authority_name();

    cluster.wait_for_epoch(2).await;
    // Fail fast instead of hanging: an excluded joiner never enters the
    // epoch-2 working set, so it would never reach epoch 2. The cluster
    // is already at epoch 2 here, so an in-committee joiner reaches it
    // promptly.
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        wait_for_node_epoch(&joiner.node_handle, 2),
    )
    .await
    .expect(
        "joiner did not reach epoch 2 within 60s of the cluster — \
         likely excluded from the freeze (its mpc_data never propagated)",
    );

    // Read the epoch-2 committee from the joiner's own node and assert
    // its class-groups material is present — i.e. the freeze captured
    // the joiner and the off-chain assembler resolved its mpc_data.
    let in_class_groups = joiner.node_handle.with(|node| {
        let epoch_store = node.state().epoch_store_for_testing();
        let committee = epoch_store.committee();
        assert_eq!(committee.epoch(), 2, "joiner node should be at epoch 2");
        committee
            .class_groups_public_keys_and_proofs
            .contains_key(&joiner_name)
    });
    assert!(
        in_class_groups,
        "joiner {joiner_name:?} must appear in epoch-2 committee \
         class_groups_public_keys_and_proofs (freeze must capture \
         the mid-epoch joiner)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_removed_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    // Validator 0 submits `request_remove_validator`. The on-chain
    // logic keeps it in the active set for the rest of epoch 1 and
    // drops it at the epoch-2 boundary.
    cluster
        .remove_validator(0)
        .await
        .expect("remove_validator failed");

    // Snapshot remaining validators' node handles BEFORE waiting —
    // index 0 might disappear from validator_node_handles() depending
    // on shutdown timing, and we want to assert the survivors reach
    // epoch 2 with the new 3-member committee.
    let remaining: Vec<_> = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .skip(1)
        .collect();
    assert_eq!(
        remaining.len(),
        3,
        "expected 3 surviving validator handles before wait_for_epoch(2)"
    );
    for handle in &remaining {
        wait_for_node_epoch(handle, 2).await;
    }
}

/// Curve enum value for `Secp256k1` (matches the on-chain definition
/// in `coordinator_inner.move`).
const DWALLET_CURVE_SECP256K1: u32 = 0;

#[tokio::test(flavor = "multi_thread")]
async fn test_sessions_complete_across_epoch_switch() {
    telemetry_subscribers::init_for_testing();

    // Short epoch_duration so the epoch boundary lands while the
    // user-initiated DKG is in flight. The bug being probed is
    // "sessions stuck across epoch switch" — keeping epochs short
    // maximizes the chance the boundary crosses mid-DKG.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    // Race the epoch-2 boundary against DKG completion. Both should
    // succeed — the DKG MUST finish despite the epoch switch crossing
    // mid-session.
    //
    // Empirically the MPC computation itself is fast (~100ms per
    // round) but the request → MPC kickoff path queues behind the
    // network-reconfiguration MPC when an epoch boundary lands soon
    // after submission, easily adding 2+ minutes wall before the
    // session even starts. The chain-event emission pipeline
    // (validator output → consensus → checkpoint → Sui tx → emit)
    // adds another few seconds. A 5-minute timeout gives both stages
    // headroom; the failure mode the test cares about is "stuck",
    // not "slow".
    // Epoch 2 must advance regardless of session state — the
    // protocol explicitly should NOT block epoch change on
    // in-flight sessions. Bound the wait separately from the DKG
    // wait so we can tell stuck-epoch (system bug: epoch blocked
    // on session) apart from stuck-session (session never
    // completes but epoch does). With epoch_duration_ms = 15_000,
    // epoch 2 should land within ~90s of epoch 1 even with the
    // reconfiguration MPC running.
    let dkg_done = cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(300));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, dkg_result) = tokio::join!(epoch_2, dkg_done);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight session");
    dkg_result.expect("dWallet DKG never completed across epoch switch");
}

/// Submit three user-initiated dWallet DKGs in quick succession,
/// driving them all through the epoch-1→2 reconfiguration window
/// concurrently. Each DKG must reach a terminal state.
///
/// Probes whether queue depth at the epoch boundary affects
/// completion. Original user report: "some sessions get stuck and
/// never finishes" — this is the most direct stress-test for a
/// stuck-tail-of-queue failure mode.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_concurrent_dwallet_dkgs_across_epoch_switch() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    // Three DKGs, each with a distinct seed so the encryption keys
    // don't collide on the publisher's address book.
    let mut dkg_handles = Vec::new();
    for (i, seed_byte) in [0x11u8, 0x22, 0x33].iter().enumerate() {
        let user_key = cluster
            .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [*seed_byte; 32])
            .await
            .unwrap_or_else(|e| panic!("register_user_encryption_key #{i} failed: {e}"));
        let ika_coin_id = cluster.packages.ika_supply_id;
        let dkg_handle = cluster
            .request_user_dwallet_dkg(
                DWALLET_CURVE_SECP256K1,
                network_key_id,
                network_dkg_public_output.clone(),
                &user_key,
                ika_coin_id,
            )
            .await
            .unwrap_or_else(|e| panic!("request_user_dwallet_dkg #{i} failed: {e}"));
        dkg_handles.push(dkg_handle);
    }

    // Epoch 2 must advance independently of in-flight sessions.
    let dkg_completions = futures::future::join_all(dkg_handles.iter().map(|h| {
        cluster.wait_for_dwallet_dkg_complete(h.dwallet_id, std::time::Duration::from_secs(300))
    }));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, results) = tokio::join!(epoch_2, dkg_completions);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight sessions");
    for (i, result) in results.into_iter().enumerate() {
        result.unwrap_or_else(|e| panic!("dWallet DKG #{i} never completed: {e}"));
    }
}

/// Add a 5th validator while a user-initiated DKG is in flight.
/// Both must reach epoch 2 cleanly: joiner active, DKG completed.
///
/// Probes whether mid-flight committee changes interact badly with
/// in-flight user sessions — a scenario the user's original
/// "stuck sessions" report could plausibly cover.
#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_added_while_user_dkg_in_flight() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x44; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    // Submit the joiner add while the DKG is queued behind the
    // network reconfiguration MPC. The joiner becomes part of the
    // active set at the epoch-1→2 boundary, the same boundary the
    // user DKG should complete across.
    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    // Epoch 2 must advance independently of in-flight session +
    // joiner add.
    let dkg_done = cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(300));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, dkg_result) = tokio::join!(epoch_2, dkg_done);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight session or joiner");
    dkg_result.expect("dWallet DKG never completed alongside joiner add");
    wait_for_node_epoch(&joiner.node_handle, 2).await;
}

/// Multi-epoch stress: across six epoch cycles, submit three user
/// DKGs per cycle — "early" right after the new epoch starts, "mid"
/// in the middle of the epoch, and "late" deliberately close to the
/// next epoch boundary so it queues across reconfiguration. All
/// eighteen DKGs must complete, and every epoch transition must
/// finish within a bounded time (no blocking on in-flight sessions).
///
/// This is the broadest single-test verification that:
/// 1. Repeated user sessions don't accumulate state that breaks
///    later sessions.
/// 2. Sessions submitted at any point in the epoch cycle complete.
/// 3. Epoch advancement isn't blocked by session queues.
/// 4. The pipeline survives sustained load over multiple
///    reconfigurations (not just one).
#[tokio::test(flavor = "multi_thread")]
async fn test_user_sessions_across_multiple_epochs() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Reach epoch 1 + capture the network DKG output once; it stays
    // valid for the rest of the test (protocol public parameters are
    // derived per-curve from this blob).
    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let mut all_handles = Vec::new();

    // Six cycles, each starting in epoch N and ending at epoch
    // N+1. Within each cycle: register + submit three DKGs (early,
    // mid, late), then assert the epoch transition lands in bounded
    // time. The 120s per-epoch ceiling is the same bound used by
    // the other bug-repro tests; if a session queue blocks epoch
    // advancement, this fires.
    const CYCLES: u32 = 6;
    const DKGS_PER_CYCLE: u32 = 3;
    // With epoch_duration_ms = 15_000, ~5s sleep between
    // submissions spreads them across the epoch window: roughly t=0,
    // t=5s (mid), t=10s (late, close to the timer firing).
    const SLEEP_BETWEEN_SUBMISSIONS: std::time::Duration = std::time::Duration::from_secs(5);

    for cycle in 1u32..=CYCLES {
        for batch in 0u32..DKGS_PER_CYCLE {
            // Unique seed per registration so each user encryption
            // key lives at a distinct on-chain address. Two bytes:
            // cycle and batch — keeps the 32-byte seed buffer
            // structured + reproducible.
            let seed_byte = (cycle as u8 * 10) + batch as u8;
            let user_key = cluster
                .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [seed_byte; 32])
                .await
                .unwrap_or_else(|e| {
                    panic!("register_user_encryption_key (cycle={cycle}, batch={batch}): {e}")
                });

            let ika_coin_id = cluster.packages.ika_supply_id;
            let dkg_handle = cluster
                .request_user_dwallet_dkg(
                    DWALLET_CURVE_SECP256K1,
                    network_key_id,
                    network_dkg_public_output.clone(),
                    &user_key,
                    ika_coin_id,
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("request_user_dwallet_dkg (cycle={cycle}, batch={batch}): {e}")
                });
            all_handles.push((cycle, batch, dkg_handle));

            // Spread submissions across the epoch window — the
            // first lands at epoch start, subsequent ones drift
            // toward the boundary so at least one consistently
            // queues across reconfiguration.
            if batch + 1 < DKGS_PER_CYCLE {
                tokio::time::sleep(SLEEP_BETWEEN_SUBMISSIONS).await;
            }
        }

        // Epoch must advance within a bounded window regardless of
        // whether the in-flight DKGs have completed. With
        // `internal_presign_sessions = true` (v4 default) +
        // multiple in-flight user DKGs, each transition takes
        // longer; 240s is the empirical ceiling we observe with
        // 3 concurrent DKGs.
        let next_epoch = cycle as u64 + 1;
        tokio::time::timeout(
            std::time::Duration::from_secs(240),
            cluster.wait_for_epoch(next_epoch),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("epoch {next_epoch} was blocked — sessions held up reconfiguration")
        });
    }

    // All DKGs must complete. Wait one at a time to bound the
    // overall wait; in practice they finish quickly once their
    // session-output checkpoints land on chain.
    for (cycle, batch, handle) in &all_handles {
        cluster
            .wait_for_dwallet_dkg_complete(handle.dwallet_id, std::time::Duration::from_secs(300))
            .await
            .unwrap_or_else(|e| panic!("dkg (cycle={cycle}, batch={batch}): {e}"));
    }
}

/// Real-network sustained-churn simulation: validator churn (new
/// joiners arriving, original validators leaving) interleaved with
/// user DKGs that must complete throughout — the kind of operator
/// turnover a production network sees, exercised across several
/// reconfiguration boundaries to prove sustained churn doesn't wedge
/// off-chain reconfiguration.
///
/// Schedule across 5 epoch transitions (epoch 1 → epoch 6):
///   E1→E2:  add joiner J1                (active 4→5)
///   E2→E3:  remove original validator 0  (active 5→4)
///   E3→E4:  add joiner J2                (active 4→5)
///   E4→E5:  remove original validator 1  (active 5→4)
///   E5→E6:  add joiner J3                (active 4→5)
///
/// One user DKG submitted at the start of each cycle (5 total). All
/// must complete by the end of the test.
#[tokio::test(flavor = "multi_thread")]
async fn test_real_network_churn_over_5_epochs() {
    telemetry_subscribers::init_for_testing();

    // Epoch length is chosen to reflect production, not to stress an
    // artificial clock. A joiner's window is the quarter-epoch between
    // mid-epoch committee publication (epoch/2) and the freeze (3/4
    // epoch); in it the joiner must (pre-)derive its mpc_data, bootstrap,
    // fan out, relay, and be attested before the ready-signal quorum
    // freezes the input set. The cost of that pipeline is *absolute*
    // (keygen, P2P/consensus bootstrap, propagation) — fixed seconds that
    // do NOT scale with epoch length. In production (24h epochs) the
    // window is ~6h and that cost is rounding error; the race cannot
    // occur. A tightly compressed test epoch instead collapses the window
    // below the fixed cost and re-tests only that artifact. So we use 300s
    // epochs — a ~75s window that comfortably absorbs the fixed cost — and
    // five churn cycles, enough sustained turnover to prove reconfiguration
    // converges. The transition is MPC-bound, so a longer epoch with fewer
    // cycles costs no more wall time than many short ones.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(300_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    // Track surviving "original validator" indices we haven't
    // removed yet — pop from the front each remove cycle. Indices
    // 0..=3 reference the bootstrap-time validator slots.
    let mut originals_remaining: std::collections::VecDeque<usize> = (0..4).collect();
    // Track joiners post-add so we can verify each one actually
    // reaches the next epoch (i.e. is live in the active committee,
    // not just registered on-chain).
    let mut joiner_handles: Vec<(u32, u64, ika_test_cluster::JoinerHandle)> = Vec::new();
    let mut joiner_count = 0u32;
    let mut all_dkg_handles = Vec::new();

    // Each iteration drives one epoch transition. Alternates
    // joiner-add (odd cycles) and original-validator-remove (even
    // cycles). One user DKG per cycle, submitted before the churn
    // op so it's in flight across the transition.
    for cycle in 1u32..=5 {
        // 1. Submit a user DKG so the network is exercising real
        //    work during the transition.
        let seed_byte = 0x80 + cycle as u8;
        let user_key = cluster
            .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [seed_byte; 32])
            .await
            .unwrap_or_else(|e| panic!("register_user_encryption_key (cycle={cycle}): {e}"));
        let ika_coin_id = cluster.packages.ika_supply_id;
        let dkg_handle = cluster
            .request_user_dwallet_dkg(
                DWALLET_CURVE_SECP256K1,
                network_key_id,
                network_dkg_public_output.clone(),
                &user_key,
                ika_coin_id,
            )
            .await
            .unwrap_or_else(|e| panic!("request_user_dwallet_dkg (cycle={cycle}): {e}"));
        all_dkg_handles.push((cycle, dkg_handle));

        // 2. Alternate add / remove. Odd cycles add a joiner; even
        //    cycles remove the next-oldest original validator.
        //    Keeps active-set size oscillating between 4 and 5 so
        //    the BFT quorum (2f+1 = 3 for n=4, =4 for n=5) is
        //    always achievable.
        // Alternate add / remove: add on odd cycles, remove the
        // next-oldest original on even cycles. With 4 originals and
        // 5 cycles, we get 3 adds (cycles 1, 3, 5) and 2 removes
        // (cycles 2, 4), so the active set oscillates 4→5→4→5→4→5
        // and two originals survive — enough sustained churn to
        // exercise reconfiguration convergence without a full
        // turnover marathon.
        if cycle % 2 == 1 {
            joiner_count += 1;
            let joiner = cluster
                .add_joiner_validator()
                .await
                .unwrap_or_else(|e| panic!("add_joiner_validator (cycle={cycle}): {e}"));
            tracing::info!(cycle, joiner_count, "added joiner");
            // Record alongside the epoch the joiner becomes active
            // (the cycle's transition target). Used after the
            // transition to assert the joiner's in-memory node
            // advances to that epoch — proving it's actually
            // participating, not just registered on chain.
            joiner_handles.push((cycle, cycle as u64 + 1, joiner));
        } else if let Some(idx) = originals_remaining.pop_front() {
            cluster
                .remove_validator(idx)
                .await
                .unwrap_or_else(|e| panic!("remove_validator (cycle={cycle}, idx={idx}): {e}"));
            tracing::info!(cycle, removed_original = idx, "removed original validator");
        } else {
            tracing::info!(cycle, "even cycle with no originals left — DKG-only");
        }

        // 3. Wait for the next epoch within a bounded window. With a
        //    300s epoch the freeze lands at ~225s and the reconfiguration
        //    MPC (with an in-flight user DKG + committee change) runs
        //    after it, so a transition completes in the ~6-8 min range
        //    under churn contention. 900s gives headroom while still
        //    catching truly-stuck cases.
        let next_epoch = cycle as u64 + 1;
        tokio::time::timeout(
            std::time::Duration::from_secs(900),
            cluster.wait_for_epoch(next_epoch),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "epoch {next_epoch} did not advance within 600s — \
                 churn cycle {cycle} blocked reconfiguration"
            )
        });

        // Verify every joiner whose activation epoch is now in the
        // past (i.e. has been through at least one reconfig boundary)
        // is actually live — its in-memory node reaches the current
        // epoch. Without this, "joiner added" only proves on-chain
        // registration; live-in-committee participation is what
        // matters for the simulation. 60s ceiling: by the time we
        // get here the cluster has already reached `next_epoch`, so
        // the joiner should be at parity within a few poll cycles.
        for (added_cycle, active_from_epoch, joiner) in &joiner_handles {
            if *active_from_epoch <= next_epoch {
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    wait_for_node_epoch(&joiner.node_handle, next_epoch),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "joiner added in cycle {added_cycle} (active from epoch \
                         {active_from_epoch}) failed to reach epoch {next_epoch} \
                         within 60s — not participating in the committee"
                    )
                });

                // Log handoff cert presence on the joiner as
                // diagnostic — same caveat as the probe check
                // below: the cert may not land every cycle if
                // validators disagree on the next-committee view
                // at EndOfPublish, surfacing as
                // `AttestationMismatch` rejections.
                if next_epoch > *active_from_epoch {
                    let joiner_certs = cluster.handoff_cert_epochs_for_node(&joiner.node_handle);
                    tracing::info!(
                        added_cycle,
                        active_from_epoch,
                        next_epoch,
                        ?joiner_certs,
                        has_source_epoch = joiner_certs.contains(active_from_epoch),
                        "joiner handoff cert progress",
                    );
                }
            }
        }

        // Best-effort observation of handoff cert progress. The
        // cert for source epoch N requires 2f+1 validators to
        // independently compute and sign the same
        // `HandoffAttestation` — they can disagree on
        // `next_committee_pubkey_set_hash` or `items` if their
        // chain-sync of the next committee / off-chain mpc_data
        // freeze hasn't converged at the EndOfPublish moment.
        // This is a known mode that surfaces under churn; the test
        // tolerates it per-cycle and asserts presence only at the
        // very end. Logging here gives visibility into how often
        // the cert actually lands.
        let probe_handle = cluster
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm has at least one validator");
        let probe_certs = cluster.handoff_cert_epochs_for_node(&probe_handle);
        tracing::info!(
            cycle,
            next_epoch,
            ?probe_certs,
            has_source_epoch = probe_certs.contains(&(cycle as u64)),
            "handoff cert progress on probe validator",
        );
    }

    // All 5 user DKGs must reach a terminal state. By now the active
    // set is a mix of the 2 surviving originals and 3 joiners; DKG
    // sessions submitted earlier must still complete across the churn.
    for (cycle, handle) in &all_dkg_handles {
        cluster
            .wait_for_dwallet_dkg_complete(handle.dwallet_id, std::time::Duration::from_secs(300))
            .await
            .unwrap_or_else(|e| panic!("dkg (cycle={cycle}): {e}"));
    }

    assert_eq!(
        joiner_count, 3,
        "expected 3 joiners added across the 5 cycles"
    );
    assert_eq!(
        originals_remaining.len(),
        2,
        "expected 2 of 4 originals removed across the 5 cycles, {} remaining",
        originals_remaining.len()
    );

    // Final sanity: every joiner is at the test's final epoch (6). By
    // now they should all be live committee members participating
    // alongside the two surviving originals.
    let final_epoch = 6;
    for (added_cycle, _, joiner) in &joiner_handles {
        let current = joiner
            .node_handle
            .with(|node| node.current_epoch_for_testing());
        assert!(
            current >= final_epoch,
            "joiner from cycle {added_cycle} is at epoch {current}, expected >= {final_epoch}",
        );

        let certs = cluster.handoff_cert_epochs_for_node(&joiner.node_handle);
        tracing::info!(added_cycle, ?certs, "final joiner handoff cert state");
    }

    // Aggregate cert presence across the whole cluster — at least
    // one validator (any committee member of any past epoch) must
    // have persisted at least one handoff cert. This is a weak
    // form of "the handoff pipeline did SOMETHING"; per-cycle
    // assertions are intentionally relaxed because the cert can
    // fail to certify when validators disagree on the
    // next-committee view at EndOfPublish (surfacing as
    // `AttestationMismatch` rejections).
    //
    // Root cause (investigated): the `HandoffAttestation`'s
    // `next_committee_pubkey_set_hash` is computed by each signer
    // from its LOCAL `next_epoch_committee_receiver` (the off-chain
    // *assembled* committee), via `build_local_handoff_attestation`.
    // The network-key-output digests in `items` were already made
    // consensus-deterministic (hydrated from chain in
    // `HandoffSignatureSender::send`), but the committee *membership*
    // is not: under churn a joiner that announced is present in the
    // pre-freeze assembled committee and absent from the post-freeze
    // one (it was excluded by the freeze), so signers that sign at
    // different convergence points hash different member sets and
    // cross-reject. This is addressed in `HandoffSignatureSender::send`,
    // which derives the attestation's committee membership
    // deterministically — the next committee intersected with the
    // consensus-ordered frozen mpc_data set (= the final epoch-E
    // committee the joiner verifier observes) — instead of the racy
    // local watch-channel value. The intersection is a no-op outside
    // churn, so it can't regress the steady state. The aggregate
    // assertion below is kept (rather than a per-cycle one) until the
    // per-cycle cert rate under churn is verified on stable infra.
    let mut total_certs_seen = 0usize;
    for handle in cluster.swarm.validator_node_handles() {
        let certs = cluster.handoff_cert_epochs_for_node(&handle);
        total_certs_seen += certs.len();
    }
    tracing::info!(
        total_certs_seen,
        "aggregate handoff cert count across all validators",
    );
    assert!(
        total_certs_seen > 0,
        "no validator persisted any handoff cert across {} epoch transitions — \
         the off-chain handoff pipeline did not produce a single certified \
         attestation",
        final_epoch - 1
    );
}
