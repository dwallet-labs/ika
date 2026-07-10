// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Validator restart in the middle of the epoch's reconfiguration window
//! under msim.
//!
//! The mid-epoch network-key reconfiguration is the longest-running
//! system MPC of every epoch, and a validator that restarts while it is
//! in flight must rejoin the session from persisted state (or sit out to
//! the output quorum of the other three) without stalling the epoch close
//! — `all_network_encryption_keys_reconfiguration_completed` is one of the
//! end-of-publish gate's conditions, so a reconfiguration that loses a
//! participant and never completes pins the epoch.
//!
//! Asserted properties:
//! - the epoch whose reconfiguration hosted the restart still closes;
//! - the restarted validator crosses the next boundaries with the
//!   committee;
//! - per-epoch handoff attestations stay byte-identical across all four
//!   validators (vacuity-guarded fork detector).

#![cfg(msim)]

use std::collections::BTreeMap;
use std::time::Duration;

use ika_test_cluster::{IkaTestClusterBuilder, poll_until};
use sui_macros::sim_test;

const VICTIM: usize = 1;
const EPOCH_MS: u64 = 20_000;

#[sim_test]
async fn sim_restart_during_reconfiguration() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(EPOCH_MS)
        .build()
        .await
        .unwrap();

    // Healthy boundary first, then let epoch 1 reach its mid-epoch window
    // — where the reconfiguration for the next epoch runs.
    cluster.wait_for_epoch(1).await;
    tokio::time::sleep(Duration::from_millis(EPOCH_MS / 2)).await;

    // Bounce the victim inside the reconfiguration window.
    cluster.stop_validator(VICTIM);
    tokio::time::sleep(Duration::from_secs(3)).await;
    cluster.start_validator(VICTIM).await.unwrap();

    // The epoch must close (reconfiguration completed despite the bounce)
    // and the victim must ride the next boundaries with the committee.
    cluster.wait_for_epoch(3).await;
    let node_epoch = |cluster: &ika_test_cluster::IkaTestCluster, idx: usize| {
        let handle = cluster.validator_handle(idx);
        handle.with(|node| node.state().epoch_store_for_testing().epoch())
    };
    poll_until(
        Duration::from_secs(120),
        "restarted validator reaches epoch 3",
        || (node_epoch(&cluster, VICTIM) >= 3).then_some(()),
    )
    .await;

    // Vacuity-guarded fork detector across all four validators.
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
