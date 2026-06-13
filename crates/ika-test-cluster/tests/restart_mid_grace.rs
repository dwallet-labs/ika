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
//! alone: every validator (restarted or not) must persist a byte-identical
//! handoff attestation certificate for the struck epoch — the cert pins the
//! epoch's reconfiguration output and frozen mpc_data, so a validator that
//! closed the epoch at a different round would aggregate a divergent cert —
//! and then drive one more full reconfiguration to prove the network keys
//! handed off under all that churn actually work.
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

/// An `IkaNodeHandle` holds a STRONG `Arc<IkaNode>`. A handle that is
/// still alive when its node is restarted keeps the old instance's
/// RocksDB handles open, and the respawn dies on the still-held store
/// LOCK ("lock hold by current process") — `Node::stop` joins the node
/// thread, but the stores live until the last `Arc` drops, and a
/// test-held handle is such an `Arc`. Acquire handles on demand (inside
/// each poll tick / scoped to one statement); never bind one across a
/// `stop()`/`start()` of its node.
fn node_handle(cluster: &IkaTestCluster, name: &AuthorityName) -> IkaNodeHandle {
    cluster
        .swarm
        .node(name)
        .expect("validator node exists for the configured name")
        .get_node_handle()
        .expect("validator node is running")
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
    poll_until(
        Duration::from_secs(60),
        "validator X to observe the full-coverage mpc_data freeze",
        || {
            node_handle(&cluster, &straggler_name).with(|node| {
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
            node_handle(&cluster, &mid_grace_name).with(|node| {
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
    let close_emitted_at_stop = node_handle(&cluster, &mid_grace_name).with(|node| {
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
    let anchor_after_restart = node_handle(&cluster, &mid_grace_name).with(|node| {
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
             handoff-cert determinism assertion below",
        ),
    }

    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH + 1).await;
    }

    // No-fork proof: every validator must persist a BYTE-IDENTICAL handoff
    // certificate for the struck epoch. The cert is the cross-epoch
    // agreement on that epoch's close and handoff — its items pin the
    // epoch-keyed reconfiguration output and the frozen mpc_data set — so a
    // validator that closed the epoch at a different round (including the
    // two that restarted through the close) would aggregate a divergent
    // attestation and fail this equality. Handoff certs are perpetual
    // (never pruned), so this is robust to the network advancing while we
    // poll — unlike a checkpoint comparison, which races checkpoint pruning.
    let reference_cert = poll_until(
        Duration::from_secs(300),
        "a never-restarted validator to persist the struck epoch's handoff cert",
        || {
            handoff_certs(&node_handle(&cluster, &names[1]))
                .get(&STRUCK_EPOCH)
                .cloned()
        },
    )
    .await;
    for (index, name) in names.iter().enumerate() {
        let cert = poll_until(
            Duration::from_secs(300),
            "validator to persist the struck epoch's handoff cert",
            || {
                handoff_certs(&node_handle(&cluster, name))
                    .get(&STRUCK_EPOCH)
                    .cloned()
            },
        )
        .await;
        assert_eq!(
            cert, reference_cert,
            "validator[{index}]'s handoff cert for epoch {STRUCK_EPOCH} diverges \
             from the never-restarted validator's — the epoch close forked \
             across the restarts",
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
