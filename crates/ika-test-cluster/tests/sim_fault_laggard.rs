// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Laggard epoch entry under msim: one validator misses an epoch boundary
//! entirely and joins the epoch late.
//!
//! This is the epoch-entry key-gap shape behind the historical VSS
//! internal-presign failures and the "two laggards wedge the epoch" quorum
//! death: a validator that enters epoch N late starts with empty off-chain
//! key maps and must ingest the epoch's agreed key set, re-derive its VSS
//! material, and catch up on sessions — while the other three carry the
//! epoch. The properties asserted:
//!
//! - the cluster advances into the boundary epoch on 3-of-4 while the
//!   laggard is down (no liveness dependence on the full set);
//! - the restarted laggard catches up to the current epoch;
//! - the NEXT boundary closes with the laggard participating (a laggard
//!   whose entry-window sessions wedge would pin `all_epoch_sessions_
//!   finished` and the epoch would never close);
//! - every validator holds byte-identical handoff attestations per epoch
//!   (fork detector — catches a laggard that "recovered" onto divergent
//!   state).

#![cfg(msim)]

use std::collections::BTreeMap;
use std::time::Duration;

use ika_test_cluster::{IkaTestClusterBuilder, poll_until};
use sui_macros::sim_test;

const LAGGARD: usize = 3;

#[sim_test]
async fn sim_laggard_entry_window() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .build()
        .await
        .unwrap();

    // Healthy first boundary with the full set: proves the machinery once
    // before any fault, so a later failure is attributable to the fault.
    cluster.wait_for_epoch(1).await;

    // Take the laggard down BEFORE the next boundary...
    cluster.stop_validator(LAGGARD);

    // ...and let the remaining 3-of-4 cross into epoch 2 without it.
    cluster.wait_for_epoch(2).await;

    // Late entry: the laggard starts inside epoch 2 — the entry-window
    // shape (empty key maps, ingestion + VSS re-derivation while the epoch
    // is already running).
    cluster.start_validator(LAGGARD).await.unwrap();

    // The laggard must catch up to the running epoch.
    let laggard_epoch = |cluster: &ika_test_cluster::IkaTestCluster| {
        let handle = cluster.validator_handle(LAGGARD);
        handle.with(|node| node.state().epoch_store_for_testing().epoch())
    };
    poll_until(
        Duration::from_secs(120),
        "laggard catches up to epoch 2",
        || (laggard_epoch(&cluster) >= 2).then_some(()),
    )
    .await;

    // The next boundary must close WITH the laggard: a laggard whose
    // entry-window sessions never complete pins the epoch-close gate.
    cluster.wait_for_epoch(3).await;
    poll_until(Duration::from_secs(120), "laggard reaches epoch 3", || {
        (laggard_epoch(&cluster) >= 3).then_some(())
    })
    .await;

    // Fork detector: per-epoch handoff attestations must be byte-identical
    // across all validators, laggard included.
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
