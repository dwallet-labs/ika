// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Two validators MPC-degraded (computations skipped) while consensus stays
//! alive — the faithful historical two-laggards shape.
//!
//! One MPC-dead validator per epoch is routine and invisible behind 3-of-4
//! output quorums. The network historically wedged only when a SECOND
//! validator went MPC-dead in the same epoch: 2 computing < 3-of-4 quorum
//! for every MPC session, the internal presign pool stops refilling,
//! completions stall, and the epoch-close target pins. Crucially,
//! consensus keeps committing throughout — which a whole-node stop cannot
//! express on a 4-committee (2 stopped halts Mysticeti itself; that
//! scenario lives in `sim_fault_two_laggards` as an ignored reproducer of
//! a separate full-halt-recovery question).
//!
//! Mechanism: the `dwallet-mpc-computation` fail point in the computation
//! orchestrator, scoped to the two victims' sim-node ids. While active,
//! their computations are skipped (MPC-dead); clearing it restores them.
//!
//! Asserted properties:
//! - the epoch wounded by the double MPC degradation still closes after
//!   the fail point clears (in-flight sessions recover via retries — the
//!   stale-batch expiry and re-pull machinery — instead of wedging);
//! - both degraded validators cross into later epochs with the committee;
//! - per-epoch handoff attestations stay byte-identical across all four.

#![cfg(msim)]

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use ika_test_cluster::{IkaTestClusterBuilder, poll_until};
use sui_macros::{clear_fail_point, register_fail_point_if, sim_test};

const FIRST_VICTIM: usize = 2;
const SECOND_VICTIM: usize = 3;

#[sim_test]
async fn sim_two_mpc_degraded_validators_one_epoch() {
    telemetry_subscribers::init_for_testing();
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .build()
        .await
        .unwrap();

    // Prove one healthy boundary before injecting anything.
    cluster.wait_for_epoch(1).await;

    // Degrade the two victims' MPC: their computations are skipped from
    // here on, while their consensus participation continues untouched.
    let degraded: HashSet<_> = [FIRST_VICTIM, SECOND_VICTIM]
        .iter()
        .map(|&idx| {
            let handle = cluster.validator_handle(idx);
            handle.with(|node| node.get_sim_node_id())
        })
        .collect();
    register_fail_point_if("dwallet-mpc-computation", move || {
        degraded.contains(&sui_simulator::current_simnode_id())
    });

    // Hold the MPC-sub-quorum window open across a meaningful slice of the
    // epoch (sessions pile up unservable: 2 computing < 3-of-4 threshold).
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Heal: computations resume on both victims.
    clear_fail_point("dwallet-mpc-computation");

    // The wounded epoch must still close and the cluster must keep
    // reconfiguring — the historical failure mode was this boundary never
    // arriving (pool starvation -> undershoot -> permanent wedge).
    cluster.wait_for_epoch(3).await;

    let node_epoch = |cluster: &ika_test_cluster::IkaTestCluster, idx: usize| {
        let handle = cluster.validator_handle(idx);
        handle.with(|node| node.state().epoch_store_for_testing().epoch())
    };
    for idx in [FIRST_VICTIM, SECOND_VICTIM] {
        poll_until(
            Duration::from_secs(120),
            "degraded validator reaches epoch 3",
            || (node_epoch(&cluster, idx) >= 3).then_some(()),
        )
        .await;
    }

    // Fork detector across all four validators, vacuity-guarded.
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
