// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The prepare-then-start barrier on the two epoch-start paths that are not
//! the continuing-validator reconfiguration seam.
//!
//! A validator must hold the previous epoch's verified handoff certificate —
//! and every network-key output it certifies — before it starts the epoch's
//! consensus and MPC components. Without that it can enter consensus, take
//! demands naming a network key it has no verified material for, and sign
//! with stale shares. The barrier that enforces it used to be wired into one
//! path only; these tests cover the other two.
//!
//! - `test_boot_into_epoch_waits_for_handoff_data`: a validator restarted
//!   mid-epoch, with its handoff anchor held back. It must not finish
//!   starting — and therefore cannot have started consensus, which is spawned
//!   during startup — until the anchor is available, and must then rejoin and
//!   carry the network through another epoch boundary.
//!
//! - `test_promoted_joiner_waits_for_handoff_data`: a fullnode promoted into
//!   the committee at a boundary, with its handoff anchor held back. Same
//!   contract, entered from the promotion branch instead of the boot path.
//!   This is the node with the strongest claim on the barrier: it computed
//!   none of the epoch's outputs itself, so it starts holding nothing.
//!
//! - `test_genesis_boot_does_not_wait_for_handoff_data`: entering epoch 0 has
//!   no predecessor epoch to be handed off from, so the barrier is skipped
//!   there. Every validator boots with the anchor held back for ten minutes
//!   and the cluster still comes up.
//!
//! The hold-back is `NodeConfig::withhold_handoff_anchor_for_testing`: for
//! that long after the barrier is entered, the barrier reports the anchor as
//! not obtainable and fetches nothing — the same benign propagation-lag
//! outcome it already retries on. It suppresses only the ACQUISITION of the
//! handoff data; the readiness predicate keeps evaluating real local state.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per `dev-docs/conventions/simtest.md`:
//! the hold-back is a wall-clock window, not a message ordering, so there is
//! no scheduling nondeterminism for `#[sim_test]` to control.

use ika_node::IkaNodeHandle;
use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder, poll_until, wait_for_node_epoch};
use ika_types::crypto::AuthorityName;
use prometheus::proto::MetricType;
use std::time::{Duration, Instant};

/// How long each test holds a node's handoff anchor back. Long enough that a
/// node which ignored the barrier would be observably up and in consensus
/// well inside the window, short enough not to stretch the epochs around it.
const WITHHOLD: Duration = Duration::from_secs(30);

/// An `IkaNodeHandle` holds a STRONG `Arc<IkaNode>`, which keeps the node's
/// RocksDB open. A handle still alive when its node restarts makes the
/// respawn die on the held store lock. Acquire handles on demand, scoped to
/// one statement — never across a `stop()`/`start()`.
fn node_handle(cluster: &IkaTestCluster, name: &AuthorityName) -> IkaNodeHandle {
    cluster
        .swarm
        .node(name)
        .expect("validator node exists for the configured name")
        .get_node_handle()
        .expect("validator node is running")
}

/// Sum of a single-series counter or gauge in this node's own Prometheus
/// registry (each in-process node registers into a registry of its own, so
/// these readings are per-validator). Absent family reads as 0 — the families
/// are registered at process start in validator mode, so 0 means "registered
/// and never moved", which is exactly the vacuous-pass case the assertions
/// below are looking for.
fn metric_value(handle: &IkaNodeHandle, name: &str) -> f64 {
    handle.with(|node| {
        node.registry_service_for_testing()
            .default_registry()
            .gather()
            .iter()
            .filter(|family| family.name() == name)
            .flat_map(|family| {
                family
                    .get_metric()
                    .iter()
                    .map(|metric| (family.get_field_type(), metric))
            })
            .map(|(kind, metric)| match kind {
                MetricType::COUNTER => metric.get_counter().value(),
                MetricType::GAUGE => metric.get_gauge().value(),
                // For the barrier's duration histogram the interesting figure
                // is the total time observed, not a bucket count.
                MetricType::HISTOGRAM => metric.get_histogram().get_sample_sum(),
                _ => 0.0,
            })
            .sum()
    })
}

/// Barrier poll iterations this node has spent waiting for handoff data. The
/// barrier re-checks once a second, so a node held back for `WITHHOLD` must
/// show at least a large fraction of that many.
fn barrier_retries(handle: &IkaNodeHandle) -> f64 {
    metric_value(handle, "ika_handoff_prepare_retries_total")
}

/// 1 while the barrier is blocking this node's epoch components, 0 otherwise.
fn barrier_waiting(handle: &IkaNodeHandle) -> f64 {
    metric_value(handle, "ika_handoff_prepare_waiting")
}

/// Wall-clock seconds this node has spent inside completed barrier waits.
fn barrier_seconds(handle: &IkaNodeHandle) -> f64 {
    metric_value(handle, "ika_handoff_prepare_duration_seconds")
}

/// A 1s-per-iteration barrier held for `WITHHOLD` should log roughly
/// `WITHHOLD` retries. Assert against a floor well below that so a slow CI
/// host (where each iteration's peer fetch costs more than the sleep) still
/// passes, while a node that never entered the barrier — the pre-fix
/// behaviour, and the vacuous pass this guards — reads 0 and fails.
fn min_expected_retries() -> f64 {
    (WITHHOLD.as_secs() / 3) as f64
}

/// The epoch the tests strike. Epoch 0's close mints the first handoff
/// certificate, so from epoch 1 onward there is a real anchor to withhold.
const STRUCK_EPOCH: u64 = 1;

#[tokio::test(flavor = "multi_thread")]
async fn test_boot_into_epoch_waits_for_handoff_data() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .build()
        .await
        .expect("ika test cluster failed to boot");

    let names = cluster.validator_names.clone();
    let restarted = names[3];
    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH).await;
    }

    // Restart the validator with its handoff anchor held back. Consensus for
    // the epoch is spawned from inside node startup, so a node that starts
    // its epoch components without the anchor finishes booting immediately —
    // and the barrier is what makes startup wait instead.
    let node = cluster.swarm.node(&restarted).expect("validator exists");
    node.stop();
    node.config().withhold_handoff_anchor_for_testing = Some(WITHHOLD);
    tracing::info!(
        withhold_secs = WITHHOLD.as_secs(),
        "restarting the validator with its handoff anchor withheld",
    );
    let started_at = Instant::now();
    node.start().await.expect("validator failed to restart");
    let boot_elapsed = started_at.elapsed();

    assert!(
        boot_elapsed >= WITHHOLD,
        "the restarted validator finished booting in {boot_elapsed:?}, before its withheld \
         handoff anchor could possibly be available ({WITHHOLD:?}) — it started its epoch's \
         consensus and MPC components without the verified handoff data for the epoch",
    );

    // The wait has to be the barrier's, not incidental boot slowness: the
    // barrier's own retry counter is what separates the two.
    let retries = barrier_retries(&node_handle(&cluster, &restarted));
    assert!(
        retries >= min_expected_retries(),
        "the restarted validator recorded only {retries} prepare-then-start barrier retries \
         over a {WITHHOLD:?} hold — it did not block in the barrier, so the {boot_elapsed:?} \
         boot was slow for some other reason",
    );
    assert_eq!(
        barrier_waiting(&node_handle(&cluster, &restarted)),
        0.0,
        "the restarted validator is up but still reports itself blocked in the \
         prepare-then-start barrier",
    );
    tracing::info!(
        boot_secs = boot_elapsed.as_secs(),
        retries,
        "restarted validator released from the barrier and started its epoch components",
    );

    // It rejoined for real: the network crosses another boundary with it,
    // which it can only do by contributing to the reconfiguration MPC with
    // the network-key material the barrier made it wait for. A validator that
    // had started on stale or absent shares stalls here.
    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH + 1).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_promoted_joiner_waits_for_handoff_data() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .build()
        .await
        .expect("ika test cluster failed to boot");

    let names = cluster.validator_names.clone();
    for name in &names {
        wait_for_node_epoch(&node_handle(&cluster, name), STRUCK_EPOCH).await;
    }

    // A true joiner: it was in no prior committee, so it computed none of the
    // epoch's network-key outputs and starts holding nothing. It boots as a
    // non-committee node and is promoted at the next boundary.
    let joiner = cluster
        .add_joiner_validator_withholding_handoff_anchor(Some(WITHHOLD))
        .await
        .expect("failed to add the joiner validator");
    let joiner_name = joiner.authority_name();

    // The promotion branch runs the barrier before it constructs the
    // joiner's validator components, so the gauge going to 1 IS the promotion
    // reaching the barrier. Without the barrier on that path it never moves,
    // and this poll is what fails.
    poll_until(
        Duration::from_secs(300),
        "the promoted joiner to enter the prepare-then-start barrier",
        || {
            cluster
                .swarm
                .node(&joiner_name)
                .and_then(|node| node.get_node_handle())
                .filter(|handle| barrier_waiting(handle) == 1.0)
                .map(|_| ())
        },
    )
    .await;
    tracing::info!("promoted joiner is blocked in the prepare-then-start barrier");

    poll_until(
        Duration::from_secs(300),
        "the promoted joiner to be released from the prepare-then-start barrier",
        || {
            cluster
                .swarm
                .node(&joiner_name)
                .and_then(|node| node.get_node_handle())
                .filter(|handle| barrier_waiting(handle) == 0.0)
                .map(|_| ())
        },
    )
    .await;

    let waited = barrier_seconds(&node_handle(&cluster, &joiner_name));
    assert!(
        waited >= WITHHOLD.as_secs_f64(),
        "the promoted joiner spent {waited}s in the prepare-then-start barrier but its handoff \
         anchor was withheld for {}s — it was released before its handoff data could be there",
        WITHHOLD.as_secs(),
    );
    let retries = barrier_retries(&node_handle(&cluster, &joiner_name));
    assert!(
        retries >= min_expected_retries(),
        "the promoted joiner recorded only {retries} prepare-then-start barrier retries over a \
         {WITHHOLD:?} hold",
    );

    // Promotion completed on the far side of the barrier and the joiner is a
    // working committee member: the whole committee, joiner included, crosses
    // another boundary, which needs the joiner's share of the reconfiguration
    // MPC computed against the key material the barrier waited for.
    let joiner_epoch =
        node_handle(&cluster, &joiner_name).with(|node| node.current_epoch_for_testing());
    for name in names.iter().chain(std::iter::once(&joiner_name)) {
        wait_for_node_epoch(&node_handle(&cluster, name), joiner_epoch + 1).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_genesis_boot_does_not_wait_for_handoff_data() {
    telemetry_subscribers::init_for_testing();

    // Entering epoch 0 has no predecessor epoch to be handed off from — the
    // chain-true no-cert genesis epoch — so the boot barrier is skipped
    // there. Every validator is configured to hold its anchor back for ten
    // minutes: if the skip were missing, boot would block in the barrier for
    // the whole window (with nothing to anchor on even after it, since no
    // epoch precedes 0) and the cluster would never come up.
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        // Long enough that the first boundary — where the barrier legitimately
        // engages and WOULD honour the hold-back — cannot fire while the
        // genesis-boot assertions below run.
        .with_epoch_duration_ms(600_000)
        .with_withhold_handoff_anchor(Duration::from_secs(600))
        .build()
        .await
        .expect("ika test cluster failed to boot at genesis with the handoff anchor withheld");

    for name in &cluster.validator_names {
        let handle = node_handle(&cluster, name);
        assert_eq!(
            handle.with(|node| node.current_epoch_for_testing()),
            0,
            "the cluster left the genesis epoch before the genesis-skip assertions ran",
        );
        assert_eq!(
            barrier_waiting(&handle),
            0.0,
            "a validator booting into the genesis epoch is blocked in the prepare-then-start \
             barrier — epoch 0 has no predecessor to be handed off from and must skip it",
        );
        assert_eq!(
            barrier_retries(&handle),
            0.0,
            "a validator booting into the genesis epoch spent barrier retries waiting for a \
             handoff certificate that no epoch could have produced",
        );
    }
}
