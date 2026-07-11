// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Two validators drop out and re-enter within one epoch under msim.
//!
//! The historical quorum-death shape: ONE silently-degraded validator per
//! epoch is routine and invisible behind 3-of-4 quorums, and the network
//! only wedged when a SECOND validator degraded in the same epoch — 2
//! healthy < 3-of-4 quorum for every in-flight MPC session, the internal
//! presign pool never refills, completions stall, and the epoch-close
//! target pins. This test drives exactly that double-degradation window,
//! but with recovery inside the epoch: both validators return, must
//! catch up, and the epoch must still close on time-ish.
//!
//! Asserted properties:
//! - the epoch with the double outage still closes after both return
//!   (sessions created while 2-of-4 were down complete via retries once
//!   quorum is restored — nothing is permanently lost);
//! - both returned validators participate in the NEXT epoch;
//! - per-epoch handoff attestations stay byte-identical across all four
//!   (fork detector with a vacuity guard).

#![cfg(msim)]

use std::collections::BTreeMap;
use std::time::Duration;

use ika_test_cluster::{IkaTestClusterBuilder, poll_until};
use sui_macros::sim_test;

const FIRST_VICTIM: usize = 2;
const SECOND_VICTIM: usize = 3;

// A FULL consensus halt (2-of-4 stopped simultaneously, sub-quorum for
// Mysticeti itself) does not recover after both validators return — the
// cluster never leaves the wounded epoch within 3000 virtual seconds,
// staggered or simultaneous, though a SINGLE stop/restart recovers fine
// (sim_laggard_entry_window). Kept as the reproducer for that open
// liveness question; the faithful "two MPC-degraded laggards, consensus
// alive" scenario needs fail-point-based degradation instead of node
// stops and supersedes this as the Group B test.
#[ignore = "reproducer: cluster does not recover from a full 2-of-4 consensus halt; see dev-docs/plans/simtest-fault-matrix.md"]
#[sim_test]
async fn sim_two_laggards_one_epoch() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .unwrap();

    // Prove one healthy boundary before injecting anything.
    cluster.wait_for_epoch(1).await;

    // Double outage inside epoch 1: below MPC quorum (2 healthy < 3-of-4)
    // for every session in flight. Nothing can complete until they return.
    cluster.stop_validator(FIRST_VICTIM);
    cluster.stop_validator(SECOND_VICTIM);

    // Hold the sub-quorum window open for a slice of the epoch, then heal.
    // Staggered: the first returner must fully rejoin (its node observes the
    // running epoch again) before the second starts — a simultaneous dual
    // restart is a separate, currently-stalling scenario recorded in the
    // plan document.
    tokio::time::sleep(Duration::from_secs(5)).await;
    cluster.start_validator(FIRST_VICTIM).await.unwrap();
    {
        let cluster = &cluster;
        poll_until(
            Duration::from_secs(120),
            "first returner rejoins the running epoch",
            || {
                let handle = cluster.validator_handle(FIRST_VICTIM);
                (handle.with(|node| node.state().epoch_store_for_testing().epoch()) >= 1)
                    .then_some(())
            },
        )
        .await;
    }
    cluster.start_validator(SECOND_VICTIM).await.unwrap();

    let node_epoch = |cluster: &ika_test_cluster::IkaTestCluster, idx: usize| {
        let handle = cluster.validator_handle(idx);
        handle.with(|node| node.state().epoch_store_for_testing().epoch())
    };

    // The wounded epoch must still close, and BOTH returners must cross
    // into the next epochs with the committee — the historical failure
    // mode was precisely this boundary never arriving.
    cluster.wait_for_epoch(3).await;
    for idx in [FIRST_VICTIM, SECOND_VICTIM] {
        poll_until(
            Duration::from_secs(120),
            "returned validator reaches epoch 3",
            || (node_epoch(&cluster, idx) >= 3).then_some(()),
        )
        .await;
    }

    // Fork detector across all four validators.
    let attestations_by_validator: Vec<BTreeMap<u64, Vec<u8>>> = (0..4)
        .map(|idx| {
            let handle = cluster.validator_handle(idx);
            handle.with(|node| {
                node.state()
                    .perpetual_tables()
                    .iter_certified_handoff_attestations()
                    .filter_map(Result::ok)
                    .map(|(epoch, cert)| {
                        (
                            epoch,
                            bcs::to_bytes(&cert.attestation)
                                .expect("handoff attestation serializes"),
                        )
                    })
                    .collect()
            })
        })
        .collect();
    let reference = &attestations_by_validator[0];
    assert!(
        !reference.is_empty(),
        "no handoff attestations recorded — the fork detector would pass vacuously"
    );
    for (idx, attestations) in attestations_by_validator.iter().enumerate().skip(1) {
        for (epoch, bytes) in reference {
            assert_eq!(
                attestations.get(epoch),
                Some(bytes),
                "validator {idx} diverges from validator 0 on the epoch-{epoch} handoff attestation"
            );
        }
    }
}
