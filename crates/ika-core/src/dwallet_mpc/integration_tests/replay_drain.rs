// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The MPC drain must consume rounds WHILE the boot replay is still folding
//! them.
//!
//! This is a deadlock test, and the deadlock is a circular wait between three
//! pieces that each look correct alone:
//!
//! 1. the boot replay folds the epoch's commits, and every fold sends a round
//!    into the bounded channel — blocking when it is full;
//! 2. `ReplayWaiter` releases only once `ConsensusManager::start` publishes the
//!    consumer monitor, which happens after `replay_epoch_commits` has
//!    returned;
//! 3. so a drain that waited for that signal before consuming would let the
//!    channel fill, park the replay's send forever, and never reach the
//!    release.
//!
//! Any epoch store holding more than the channel capacity of finalized commits
//! — about a minute of mainnet — would hang on every boot. It would hang
//! SILENTLY, too: a parked fold holds the commit-liveness watchdog, so nothing
//! exits and the node meets the same wedge on the next restart.
//!
//! The test therefore drives more rounds than the channel can hold, through
//! the real service (`DWalletMPCService::spawn`), the real `ReplayWaiter`, and
//! the real transport, and asserts the sending side finishes.

use std::sync::atomic::Ordering;
use std::time::Duration;

use consensus_core::CommitConsumerArgs;
use tokio::sync::broadcast;

use crate::consensus_manager::ReplayWaiter;
use crate::dwallet_mpc::integration_tests::utils;
use crate::dwallet_mpc::integration_tests::utils::build_test_state;

/// Comfortably more than the harness channel holds, so the sends provably have
/// to park and be released by a drain that is running.
const ROUNDS_BEYOND_CAPACITY: u64 = utils::TEST_ROUND_CHANNEL_CAPACITY as u64 + 64;

/// How long the replay gets before we call it wedged. The drain wakes every
/// 20ms, so a working one clears this in well under a second; the margin is
/// for a loaded CI box, not for the mechanism.
const REPLAY_MUST_FINISH_WITHIN: Duration = Duration::from_secs(60);

#[tokio::test]
async fn a_replay_longer_than_the_channel_still_finishes() {
    let _guard = utils::create_test_protocol_config_guard();
    let mut test_state = build_test_state(1);
    let epoch_store = test_state.epoch_stores[0].clone();

    // The signal `ConsensusManager::start` publishes AFTER the replay returns.
    // Nothing sends on it until then, exactly as in production.
    let (consumer_monitor_sender, consumer_monitor_receiver) = broadcast::channel(1);
    let replay_waiter = ReplayWaiter::new(consumer_monitor_receiver);

    let mut service = test_state.dwallet_mpc_services.remove(0);
    let service_task = tokio::spawn(async move { service.spawn(replay_waiter).await });

    // Stand in for the replay's folds: more rounds than the channel holds,
    // over the same blocking send the fold uses. If the drain is gated behind
    // the waiter, this never returns.
    let replay = async {
        for round in 1..=ROUNDS_BEYOND_CAPACITY {
            epoch_store
                .deliver_round(utils::empty_round_payload(round))
                .await;
        }
    };
    tokio::time::timeout(REPLAY_MUST_FINISH_WITHIN, replay)
        .await
        .expect(
            "the replay never finished handing over its rounds: the drain is not consuming \
             until the replay signal, and the replay cannot reach that signal until it has \
             handed over every round",
        );

    // Only now does consensus start and the waiter release — the ordering the
    // deadlock depends on.
    let (commit_consumer, _commit_receiver) = CommitConsumerArgs::new(0, 0);
    assert!(
        consumer_monitor_sender
            .send(commit_consumer.monitor())
            .is_ok(),
        "the service must still be subscribed, waiting on the replay signal"
    );

    // And the rounds were really consumed, not merely accepted into a channel
    // that happened to be large enough.
    let drained_to = tokio::time::timeout(REPLAY_MUST_FINISH_WITHIN, async {
        loop {
            if epoch_store
                .mpc_consumed_consensus_round
                .load(Ordering::Relaxed)
                >= ROUNDS_BEYOND_CAPACITY
            {
                return epoch_store
                    .mpc_consumed_consensus_round
                    .load(Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the drain stopped at round {} of {ROUNDS_BEYOND_CAPACITY}",
            epoch_store
                .mpc_consumed_consensus_round
                .load(Ordering::Relaxed)
        )
    });
    assert!(
        drained_to >= ROUNDS_BEYOND_CAPACITY,
        "every handed-over round must reach the drain, got {drained_to}"
    );

    service_task.abort();
}

/// The capacity is what makes the test above meaningful, so assert the two
/// have not drifted apart: a harness channel larger than the rounds it drives
/// would never park the sender, and the deadlock would be untested while
/// looking covered.
#[test]
fn the_replay_test_drives_more_rounds_than_the_channel_holds() {
    assert!(
        ROUNDS_BEYOND_CAPACITY > utils::TEST_ROUND_CHANNEL_CAPACITY as u64,
        "the replay must overflow the channel for its sends to park"
    );
}
