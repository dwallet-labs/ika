// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Validator restart inside the EndOfPublish deferred-close grace window.
//!
//! The v4 epoch close defers `end_of_publish_grace_rounds` (50) consensus
//! leader rounds past the EndOfPublish stake quorum so stragglers'
//! `EndOfPublishV2` bundles — carrying their handoff signatures — are still
//! sequenced before the close. Two persisted markers make that close
//! deterministic across a restart: the quorum anchor round
//! (`end_of_publish_quorum_round`, so a restarted validator counts the grace
//! from the same round as its peers) and the close marker
//! (`epoch_close_emitted`, so a restart cannot re-emit the close set at a
//! later commit). A bug in either forks the final checkpoint of the epoch.
//! Nothing else exercises the restart path through that window — this test
//! does, twice, from both directions:
//!
//! - **Validator X** is stopped after the mpc_data freeze but *before* it
//!   votes EndOfPublish, and restarted mid-grace. Its absence is also what
//!   makes the grace window real: with all four validators healthy the
//!   `all_voted` short-circuit closes the epoch at the fourth vote, leaving
//!   no window to strike. With X silent, the remaining 3-of-4 reach exactly
//!   stake quorum and must sit out the full 50-round countdown. X's recovery
//!   exercises the replay path — it observes the quorum and the close purely
//!   from re-driven consensus commits — and X itself is the straggler the
//!   grace exists for.
//!
//! - **Validator Y** is stopped *inside* the grace window — after its quorum
//!   anchor is persisted, before its close marker is — and restarted
//!   immediately. Its recovery exercises the persisted-anchor path: it must
//!   resume the countdown from the stored round, not re-anchor at a later
//!   one (which would close the epoch late and fork its final checkpoint).
//!
//! The end-state assertions are cross-validator determinism, not liveness
//! alone: every validator (restarted or not) must locally compute and
//! certify a byte-identical final checkpoint for the struck epoch, persist
//! byte-identical handoff attestation certs, and then drive one more full
//! reconfiguration to prove the network keys handed off under all that churn
//! actually work.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": the kill timing is driven by polling real node state, not by
//! controlled scheduling, and the epoch boundary runs real cryptography.

use ika_node::IkaNodeHandle;
use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder, wait_for_node_epoch};
use ika_types::crypto::AuthorityName;
use std::collections::BTreeMap;
use std::time::Duration;

/// The epoch whose close the test strikes. Epoch 0's close also runs the
/// handoff (for the genesis network DKG), so striking epoch 1 means the
/// machinery has already been proven once on a healthy boundary.
const STRUCK_EPOCH: u64 = 1;

fn node_handle(cluster: &IkaTestCluster, name: &AuthorityName) -> IkaNodeHandle {
    cluster
        .swarm
        .node(name)
        .expect("validator node exists for the configured name")
        .get_node_handle()
        .expect("validator node is running")
}

/// Highest certified dwallet checkpoint with `epoch == STRUCK_EPOCH`, as
/// `(sequence_number, bcs(message))`, or `None` if the node hasn't certified
/// the struck epoch's tail yet. Sequence numbers are monotonic across
/// epochs, so walking back from the latest certified checkpoint finds it.
fn final_struck_epoch_checkpoint(handle: &IkaNodeHandle) -> Option<(u64, Vec<u8>)> {
    handle.with(|node| {
        let state = node.state();
        let store = state.get_checkpoint_store();
        let latest = store
            .get_latest_certified_checkpoint()
            .expect("checkpoint store read failed")?;
        let mut message = latest.data().clone();
        while message.epoch > STRUCK_EPOCH {
            let sequence_number = message.sequence_number.checked_sub(1)?;
            message = store
                .get_dwallet_checkpoint_by_sequence_number(sequence_number)
                .expect("checkpoint store read failed")?
                .data()
                .clone();
        }
        (message.epoch == STRUCK_EPOCH).then(|| {
            (
                message.sequence_number,
                bcs::to_bytes(&message).expect("checkpoint message serializes"),
            )
        })
    })
}

/// All persisted handoff attestation certs, keyed by epoch, as bcs bytes.
fn handoff_certs(handle: &IkaNodeHandle) -> BTreeMap<u64, Vec<u8>> {
    handle.with(|node| {
        node.state()
            .perpetual_tables()
            .iter_certified_handoff_attestations()
            .filter_map(Result::ok)
            .map(|(epoch, cert)| {
                (
                    epoch,
                    bcs::to_bytes(&cert).expect("handoff cert serializes"),
                )
            })
            .collect()
    })
}

/// Poll `probe` every 100ms until it returns `Some`, panicking with
/// `what` after `deadline`.
async fn poll_until<T>(deadline: Duration, what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(
            started.elapsed() < deadline,
            "timed out after {deadline:?} waiting for: {what}",
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_restart_mid_end_of_publish_grace() {
    telemetry_subscribers::init_for_testing();

    // 30s epochs leave a wide gap between the mpc_data freeze (early-to-mid
    // epoch: announcement validation is a fixed cost, and full coverage
    // short-circuits the freeze grace when all four signal) and the
    // EndOfPublish votes (epoch duration + session drain) — the window in
    // which X must be stopped. Genesis at v4: the deferred-close grace under
    // test doesn't exist at v3 (the epoch closes inline at the
    // quorum-crossing vote).
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("ika test cluster failed to boot");
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "the deferred-close grace under test is v4-only",
    );

    let names = cluster.validator_names.clone();
    let straggler_name = names[3]; // X: down across the EndOfPublish vote
    let mid_grace_name = names[0]; // Y: down inside the grace window

    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH).await;
    }

    // Stop X only once every validator's blob hash is pinned in X's frozen
    // set — after this point X's mpc_data participates in the handoff
    // whether or not X is up, and the freeze can no longer demote X to
    // excluded. Full coverage (4 entries) rather than mere presence: the
    // freeze fires once and is consensus-deterministic, so 4 here means 4
    // everywhere.
    let straggler_handle = node_handle(&cluster, &straggler_name);
    poll_until(
        Duration::from_secs(60),
        "validator X to observe the full-coverage mpc_data freeze",
        || {
            straggler_handle.with(|node| {
                let epoch_store = node.state().epoch_store_for_testing();
                (epoch_store.epoch() == STRUCK_EPOCH
                    && epoch_store
                        .get_frozen_validator_mpc_data_input_set()
                        .map(|frozen_set| frozen_set.len() == names.len())
                        .unwrap_or(false))
                .then_some(())
            })
        },
    )
    .await;
    tracing::info!("freeze observed on X — stopping X before it votes EndOfPublish");
    cluster
        .swarm
        .node(&straggler_name)
        .expect("X exists")
        .stop();

    // With X silent, the live 3-of-4 reach exactly stake quorum (no
    // all_voted short-circuit) and anchor the 50-round countdown. Catch Y
    // inside it: anchor persisted, close marker not yet.
    let mid_grace_handle = node_handle(&cluster, &mid_grace_name);
    let anchor_at_stop = poll_until(
        // EndOfPublish waits out the epoch duration, the locked-session
        // drain, AND the on-chain reconfiguration-completed gate — with X
        // down the reconfiguration MPC advances at exactly 3-of-4 threshold
        // with zero slack, so the quorum can be several epoch-durations
        // away. A long deadline costs nothing: the grace window only opens
        // AT quorum (X just stays down longer), so waiting doesn't loosen
        // the strike.
        Duration::from_secs(300),
        "validator Y to persist the EndOfPublish quorum anchor",
        || {
            mid_grace_handle.with(|node| {
                let epoch_store = node.state().epoch_store_for_testing();
                assert_eq!(
                    epoch_store.epoch(),
                    STRUCK_EPOCH,
                    "epoch advanced before Y's quorum anchor was observed — \
                     the strike missed the grace window entirely",
                );
                epoch_store
                    .end_of_publish_quorum_round()
                    .expect("epoch store read failed")
            })
        },
    )
    .await;
    let close_emitted_at_stop = mid_grace_handle.with(|node| {
        node.state()
            .epoch_store_for_testing()
            .is_epoch_close_emitted()
            .expect("epoch store read failed")
    });
    let mid_grace_node = cluster.swarm.node(&mid_grace_name).expect("Y exists");
    mid_grace_node.stop();
    assert!(
        !close_emitted_at_stop,
        "Y already emitted the epoch close when stopped (anchor round \
         {anchor_at_stop}) — the strike missed the grace window; the grace \
         is 50 leader rounds, so the poll should have caught the anchor \
         long before the close",
    );
    tracing::info!(
        anchor_at_stop,
        "Y stopped mid-grace (anchor persisted, close not emitted) — restarting",
    );

    // Restart Y first: with both X and Y down the network is 2-of-4 and
    // consensus (and therefore the countdown) is parked until Y returns.
    mid_grace_node.start().await.expect("Y failed to restart");
    cluster
        .swarm
        .node(&straggler_name)
        .expect("X exists")
        .start()
        .await
        .expect("X failed to restart");

    // Persisted-anchor reload check, best-effort: if Y is still inside
    // epoch 1 once it's back up, its anchor must be the stored round, not a
    // re-anchor at some later round. (If the close already happened by the
    // time Y finishes booting, the determinism assertions below still cover
    // the invariant — this just catches a bad anchor at the sharpest point.)
    let mid_grace_handle = node_handle(&cluster, &mid_grace_name);
    let anchor_after_restart = mid_grace_handle.with(|node| {
        let epoch_store = node.state().epoch_store_for_testing();
        (epoch_store.epoch() == STRUCK_EPOCH)
            .then(|| epoch_store.end_of_publish_quorum_round())
            .transpose()
            .expect("epoch store read failed")
            .flatten()
    });
    match anchor_after_restart {
        Some(round) => assert_eq!(
            round, anchor_at_stop,
            "Y re-anchored the grace countdown at a different round after \
             its restart — the persisted anchor was not honored",
        ),
        None => tracing::info!(
            "Y's struck epoch already closed by the time it rebooted — \
             anchor reload not directly observable, covered by the \
             checkpoint determinism assertions",
        ),
    }

    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH + 1).await;
    }

    // The final checkpoint of the struck epoch must be byte-identical on
    // every validator, in BOTH stores: certified (the network agreed on one
    // close) and locally computed (each validator — including both restarted
    // ones, rebuilding through recovery — derived that same close itself; a
    // validator that closed at the wrong round would locally compute a
    // divergent tail while happily syncing the canonical certified one, so
    // certified equality alone would mask exactly the bug this test exists
    // to catch).
    let mut final_checkpoints = Vec::new();
    for name in &names {
        let handle = node_handle(&cluster, name);
        let checkpoint = poll_until(
            Duration::from_secs(90),
            "validator to certify the struck epoch's final checkpoint",
            || final_struck_epoch_checkpoint(&handle),
        )
        .await;
        final_checkpoints.push(checkpoint);
    }
    let (final_sequence_number, canonical_bytes) = final_checkpoints[0].clone();
    for (index, (sequence_number, bytes)) in final_checkpoints.iter().enumerate() {
        assert_eq!(
            (*sequence_number, bytes),
            (final_sequence_number, &canonical_bytes),
            "validator[{index}]'s certified final checkpoint of epoch \
             {STRUCK_EPOCH} diverges from validator[0]'s — the epoch close \
             forked across the restarts",
        );
    }
    for (index, name) in names.iter().enumerate() {
        let handle = node_handle(&cluster, name);
        let locally_computed = poll_until(
            Duration::from_secs(90),
            "validator to locally compute the struck epoch's final checkpoint",
            || {
                handle.with(|node| {
                    node.state()
                        .get_checkpoint_store()
                        .get_locally_computed_checkpoint(final_sequence_number)
                        .expect("checkpoint store read failed")
                })
            },
        )
        .await;
        assert_eq!(
            bcs::to_bytes(&locally_computed).expect("checkpoint message serializes"),
            canonical_bytes,
            "validator[{index}] locally computed a final checkpoint for epoch \
             {STRUCK_EPOCH} that diverges from the certified one — it closed \
             the epoch at a different point than its peers",
        );
    }

    // Handoff attestation certs must converge byte-identically everywhere —
    // including the cert for the struck epoch's handoff, formed while X was
    // down and Y was bouncing. Anchor the expected set on a validator that
    // was never killed.
    let reference_handle = node_handle(&cluster, &names[1]);
    let reference_certs = poll_until(
        Duration::from_secs(90),
        "a never-restarted validator to persist the struck epoch's handoff cert",
        || {
            let certs = handoff_certs(&reference_handle);
            certs.contains_key(&STRUCK_EPOCH).then_some(certs)
        },
    )
    .await;
    for (index, name) in names.iter().enumerate() {
        let handle = node_handle(&cluster, name);
        poll_until(
            Duration::from_secs(90),
            "validator's handoff certs to converge with the reference set",
            || (handoff_certs(&handle) == reference_certs).then_some(()),
        )
        .await;
        tracing::info!(
            validator_index = index,
            cert_epochs = ?reference_certs.keys().collect::<Vec<_>>(),
            "handoff certs match the reference validator",
        );
    }

    // One more full reconfiguration with everyone back: proves the network
    // keys handed off across the struck boundary actually work (a stale or
    // diverged share would stall the next epoch's MPC and block this
    // advance), not just that the bookkeeping converged.
    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH + 2).await;
    }
}
