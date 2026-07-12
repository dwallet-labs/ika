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

// NOTE on the earlier "full halt never recovers" finding: it was an
// artifact of this test's own injection point. Ika nodes BOOT at epoch 1,
// so `wait_for_epoch(1)` returns immediately and the old shape stopped
// 2-of-4 ~0.3s after genesis — mid network DKG, with Mysticeti still
// bootstrapping — which is not the documented scenario at all. The test
// now waits for a REAL boundary (epoch 2) plus the network key before
// injecting, so what is exercised is the intended shape: a warm cluster
// loses consensus quorum mid-epoch and must recover when both return.
#[sim_test]
async fn sim_two_laggards_one_epoch() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .unwrap();

    // Prove one healthy boundary (nodes boot AT epoch 1, so the first
    // crossed boundary is epoch 2) and an established network key before
    // injecting anything.
    cluster.wait_for_network_key().await.unwrap();
    cluster.wait_for_epoch(2).await;

    // Double outage inside epoch 2: below MPC quorum (2 healthy < 3-of-4)
    // for every session in flight — and below consensus quorum for
    // Mysticeti itself. Nothing can complete until they return.
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
                (handle.with(|node| node.state().epoch_store_for_testing().epoch()) >= 2)
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
    // mode was precisely this boundary never arriving. Bounded: recovery
    // from the heal is a sub-minute affair when it works at all, and an
    // unbounded wait on a halted cluster burns hours of wall clock under
    // msim (dense retry timers) before the sim-level budget fires.
    tokio::time::timeout(Duration::from_secs(600), cluster.wait_for_epoch(4))
        .await
        .expect("cluster never recovered from the dual outage: epoch 4 not reached within 600s of virtual time");
    for idx in [FIRST_VICTIM, SECOND_VICTIM] {
        poll_until(
            Duration::from_secs(120),
            "returned validator reaches epoch 4",
            || (node_epoch(&cluster, idx) >= 4).then_some(()),
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
