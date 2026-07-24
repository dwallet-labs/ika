// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A notifier redeployed with a fresh database must resume writing without
//! full checkpoint history (issue #1892's sync-stall root cause).
//!
//! On a long-lived network, no peer can serve deep checkpoint history:
//! validators only hold what consensus gave them since their own last
//! (re)deploy, and nothing backfills. Before the on-chain sync floor, a
//! notifier deployed on a fresh database chased checkpoint 1 forever ("no
//! peers were able to help sync checkpoint 1") — synced pinned at 0 while
//! known grew — silently blocking every epoch close until a human restored
//! the old database (the 2026-07 testnet incidents; the "gRPC migration"
//! trigger was the fresh deploy that came with it, not the transport).
//!
//! This test waits until the chain has processed a few dwallet checkpoints
//! (on a young localnet the cursor is still 0 at the first close, and a
//! floor of 0 correctly syncs from sequence 1 — the live tip), then wipes
//! the notifier's entire database and restarts it. The fix makes state sync
//! start from the coordinator's on-chain processed cursor instead of
//! sequence 1, so the restarted notifier must:
//! - drive further epoch closes (the writer works from a gap-started store), and
//! - never backfill deep history (checkpoint 1 stays absent locally — proof
//!   the floor engaged rather than the test silently exercising the old
//!   full-history path, which localnet peers COULD serve).
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": real node restart against real chain state and real crypto at the
//! epoch boundaries.

use std::time::Duration;

use ika_test_cluster::IkaTestClusterBuilder;

/// Ceiling for the two post-restart epoch closes (cluster epochs are 30s but
/// closes wait on real MPC reconfiguration).
const POST_RESTART_CLOSE_TIMEOUT: Duration = Duration::from_secs(600);

#[tokio::test(flavor = "multi_thread")]
async fn notifier_resumes_writing_after_full_db_wipe() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .build()
        .await
        .expect("ika test cluster failed to boot");

    // Let the network prove itself healthy (first close = network DKG done
    // and the notifier writing normally).
    cluster.wait_for_epoch(1).await;

    let notifier = cluster
        .swarm
        .fullnodes()
        .next()
        .expect("swarm runs exactly one notifier fullnode");

    // Hold the restart until the chain has processed a few dwallet
    // checkpoints. On a young localnet the on-chain cursor is still 0 at the
    // first close — a floor of 0 legitimately syncs from sequence 1 (it IS
    // the live tip), which would void the "checkpoint 1 absent" assertion
    // below. The notifier's last-written gauge equals the on-chain cursor
    // (writes are finalized before it advances), so cursor >= 2 at the wipe
    // guarantees the post-restart floor starts sync at sequence >= 3.
    // The handle is scoped per poll tick: a held IkaNodeHandle keeps the old
    // instance's RocksDB open across the restart below.
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let last_written = notifier
                .get_node_handle()
                .expect("notifier is running")
                .with(|node| {
                    node.registry_service_for_testing()
                        .default_registry()
                        .gather()
                        .iter()
                        .filter(|family| {
                            family.name()
                                == "ika_sui_connector_last_written_dwallet_checkpoint_sequence"
                        })
                        .flat_map(|family| family.get_metric())
                        .map(|metric| metric.get_gauge().value())
                        .fold(0.0f64, f64::max)
                });
            if last_written >= 2.0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("chain never processed two dwallet checkpoints — no traffic to restart against");

    // Wipe the notifier's ENTIRE database while it is down — a faithful
    // "fresh redeploy" of the writer, checkpoint stores included.
    let notifier_db_path = notifier.config().db_path();
    notifier.stop();
    std::fs::remove_dir_all(&notifier_db_path).expect("wipe notifier database directory");
    assert!(
        !notifier_db_path.exists(),
        "notifier db directory still exists after remove_dir_all: {}",
        notifier_db_path.display()
    );
    notifier.start().await.expect("restart notifier");

    // Diagnostic snapshot immediately after the restart: the store must be
    // empty (proves the wipe hit the directory the node actually opens).
    {
        let handle = notifier
            .get_node_handle()
            .expect("restarted notifier has a node handle");
        let (highest_synced_at_boot, first_present_at_boot) = handle.with(|node| {
            let store = node.dwallet_checkpoint_store_for_testing();
            (
                store
                    .get_highest_synced_dwallet_checkpoint()
                    .expect("read highest synced checkpoint")
                    .map(|checkpoint| checkpoint.sequence_number),
                store
                    .get_dwallet_checkpoint_by_sequence_number(1)
                    .expect("read checkpoint 1")
                    .is_some(),
            )
        });
        println!(
            "post-restart snapshot: db_path={} highest_synced={highest_synced_at_boot:?} \
             checkpoint_1_present={first_present_at_boot}",
            notifier_db_path.display()
        );
        assert!(
            !first_present_at_boot,
            "checkpoint 1 present immediately after restart: the wipe did not clear the \
             store the node opens (db path mismatch or store held elsewhere)"
        );
    }

    // The chain must keep closing epochs, which only the (now history-less)
    // notifier can drive. Two closes from the epoch observed after the
    // restart guarantee at least one full cycle ran entirely on the
    // gap-started store.
    let epoch_after_restart = cluster
        .current_epoch_from_chain()
        .await
        .expect("read current epoch after notifier restart");
    tokio::time::timeout(
        POST_RESTART_CLOSE_TIMEOUT,
        cluster.wait_for_epoch(epoch_after_restart + 2),
    )
    .await
    .expect(
        "epoch stopped closing after the notifier lost its database — cold-start sync floor broken",
    );

    // The floor must have engaged: the restarted notifier synced from the
    // on-chain cursor, so deep history is absent locally. (Localnet peers DO
    // hold full history, so if sync had fallen back to the old from-1 path
    // this store would contain checkpoint 1 and this assertion would fail.)
    let notifier_handle = notifier
        .get_node_handle()
        .expect("restarted notifier has a node handle");
    let (first_checkpoint_present, highest_synced) = notifier_handle.with(|node| {
        let store = node.dwallet_checkpoint_store_for_testing();
        (
            store
                .get_dwallet_checkpoint_by_sequence_number(1)
                .expect("read checkpoint 1")
                .is_some(),
            store
                .get_highest_synced_dwallet_checkpoint()
                .expect("read highest synced checkpoint")
                .map(|checkpoint| checkpoint.sequence_number),
        )
    });
    assert!(
        !first_checkpoint_present,
        "checkpoint 1 present after the wipe: sync backfilled from genesis instead of \
         starting at the on-chain cursor — the cold-start floor did not engage"
    );
    assert!(
        highest_synced.is_some(),
        "notifier synced nothing after the restart despite epochs closing"
    );
}
