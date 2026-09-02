// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Root-seed rotation on a live cluster (issue #2119).
//!
//! A validator rotates by writing a new `root-seed.key` and restarting. The
//! epoch it restarts into was already dealt its MPC shares under the OLD
//! bundle — that is what the `E-1 -> E` handoff certificate records — so the
//! freshly derived digest cannot match. Two supported flows follow from that,
//! and both are exercised here against a real cluster rather than a unit
//! fixture, because what makes them work is the interaction between three
//! things a unit test cannot stand up: the per-epoch seed resolution, the
//! announcement sender (which always announces the CURRENT seed), and the
//! freeze that turns an announcement into the next epoch's certificate.
//!
//! `rotation_with_the_previous_seed_keeps_the_validator_in_mpc` is the
//! no-gap flow: the previous-seed field is set, so the validator runs the
//! rest of epoch `E` on the certified (previous) seed while announcing the
//! new one, and the next certificate names the new bundle.
//!
//! `rotation_without_the_previous_seed_sits_out_then_rejoins` is the
//! degraded flow and the operator escape hatch, in one run:
//!   (b) rotate with NO previous seed -> the validator starts, keeps
//!       consensus, and takes no part in MPC. The metric says so, its
//!       advance counter stays at zero, and the rest of the committee still
//!       freezes and certifies the epoch — including this validator's NEW
//!       digest, which is what lets it rejoin by itself at `E+1`.
//!   (c) rotate again with NO previous seed, then restart with the field
//!       pointed at the seed that is actually certified -> it rejoins the
//!       SAME epoch, no boundary needed.
//!
//! What is deliberately NOT asserted: that a rotation is a crash-free no-op
//! for the network. Losing one validator's MPC stake for an epoch is the
//! documented cost of flow (b), and the assertion that the committee still
//! certifies epoch `E` is exactly the claim that the cost is bounded to that.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md: coordination
//! tests, real parallel crypto, no msim slowdown.

use std::collections::HashMap;
use std::time::Duration;

use dwallet_rng::RootSeed;
use ika_config::node::RootSeedWithPath;
use ika_node::IkaNodeHandle;
use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder};
use ika_types::crypto::AuthorityName;
use ika_types::handoff::HandoffItemKey;

/// Label values of `ika_dwallet_mpc_seed_identity_state`. Kept as literals
/// rather than imported from `ika-core` (not a dependency of this crate): if
/// the production label set is renamed, this test must fail, because an alert
/// written against the old names would have silently stopped matching.
const STATE_MATCHES: &str = "matches";
const STATE_ROTATION_COMPLETE: &str = "rotation_complete";
const STATE_ROTATING_ON_PREVIOUS: &str = "rotating_on_previous_seed";
const STATE_AWAITING_CERTIFICATION: &str = "awaiting_certification";

/// The `state` label carrying `1` on this node, if any. The gauge is a
/// one-hot over a closed set, so at most one value is ever `1`.
fn seed_identity_state(handle: &IkaNodeHandle) -> Option<String> {
    handle.with(|node| {
        node.registry_service_for_testing()
            .default_registry()
            .gather()
            .iter()
            .filter(|family| family.name() == "ika_dwallet_mpc_seed_identity_state")
            .flat_map(|family| family.get_metric())
            .find(|metric| metric.get_gauge().value() >= 1.0)
            .and_then(|metric| {
                metric
                    .get_label()
                    .iter()
                    .find(|label| label.name() == "state")
                    .map(|label| label.value().to_string())
            })
    })
}

/// Total `ika_dwallet_mpc_ready_to_advance_result_total` on this node.
///
/// Incremented once per advanceable session per tick, inside
/// `perform_cryptographic_computation` — which is exactly the call the
/// MPC-inactive state skips. So it is the direct observable for "this
/// validator is (not) doing MPC work", and being a COUNTER on a per-process
/// registry it starts from zero on every restart: "climbed since the restart"
/// is a clean signal with no baseline bookkeeping.
fn mpc_advance_attempts(handle: &IkaNodeHandle) -> u64 {
    handle.with(|node| {
        node.registry_service_for_testing()
            .default_registry()
            .gather()
            .iter()
            .filter(|family| family.name() == "ika_dwallet_mpc_ready_to_advance_result_total")
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_counter().value() as u64)
            .sum()
    })
}

/// The `validator -> mpc_data digest` map of the node's persisted handoff
/// certificate for `source_epoch`, or `None` while it has no such cert
/// (persistence trails the epoch switch by the quorum aggregation of
/// consensus-ordered handoff signatures, so callers poll).
///
/// Read straight off the node's perpetual tables — the raw certified bytes,
/// with no seed derivation of this test's own. That is what makes the digest
/// assertions independent of the code under test: they compare the cert
/// before a rotation with the cert after it.
fn cert_mpc_data_digests(
    handle: &IkaNodeHandle,
    source_epoch: u64,
) -> Option<HashMap<AuthorityName, [u8; 32]>> {
    handle.with(|node| {
        node.state()
            .perpetual_tables()
            .get_certified_handoff_attestation(source_epoch)
            .expect("read the certified handoff attestation")
            .map(|cert| {
                cert.attestation
                    .items
                    .into_iter()
                    .filter_map(|(key, digest)| match key {
                        HandoffItemKey::ValidatorMpcData { validator } => Some((validator, digest)),
                        _ => None,
                    })
                    .collect()
            })
    })
}

/// This node's own committee identity — the basis the handoff certificate
/// names validators by, which below protocol v6 is NOT the BLS protocol key
/// `IkaTestCluster::validator_names` carries.
fn own_authority_name(handle: &IkaNodeHandle) -> AuthorityName {
    handle.with(|node| node.state().epoch_store_for_testing().name)
}

fn current_epoch(handle: &IkaNodeHandle) -> u64 {
    handle.with(|node| node.state().epoch_store_for_testing().epoch())
}

/// Stop the validator, swap in a fresh root seed, optionally record the seed
/// it was running as the previous one, and start it again. This is the
/// operator procedure from `docs/content/docs/cli/validator-commands.mdx`,
/// with the config edit done in memory instead of on a YAML file.
async fn rotate_root_seed(
    cluster: &IkaTestCluster,
    validator_index: usize,
    keep_previous: bool,
) -> RootSeed {
    let name = cluster.validator_names[validator_index];
    let node = cluster
        .swarm
        .node(&name)
        .expect("validator node exists for the configured name");
    node.stop();
    let new_seed = RootSeed::random_seed();
    {
        let mut config = node.config();
        let running = config.root_seed_key_pair.clone();
        config.root_seed_key_pair = Some(RootSeedWithPath::new(new_seed.clone()));
        config.previous_root_seed_key_pair = if keep_previous { running } else { None };
    }
    node.start().await.expect("restart the rotated validator");
    new_seed
}

/// Restart the validator with `previous_root_seed_key_pair` set to the seed it
/// was running before its last rotation — the in-epoch repair an operator
/// performs after seeing the non-participating alert.
async fn set_previous_seed_and_restart(
    cluster: &IkaTestCluster,
    validator_index: usize,
    previous: RootSeed,
) {
    let name = cluster.validator_names[validator_index];
    let node = cluster
        .swarm
        .node(&name)
        .expect("validator node exists for the configured name");
    node.stop();
    node.config().previous_root_seed_key_pair = Some(RootSeedWithPath::new(previous));
    node.start().await.expect("restart with the previous seed");
}

/// Poll a fresh node handle every 500ms until `probe` holds.
///
/// A fresh handle per poll on purpose: an `IkaNodeHandle` is a strong
/// `Arc<IkaNode>`, and holding one across a stop/start pair keeps the old
/// instance's RocksDB open so the respawn dies on the store lock.
async fn poll_node<T>(
    cluster: &IkaTestCluster,
    validator_index: usize,
    deadline: Duration,
    what: &str,
    mut probe: impl FnMut(&IkaNodeHandle) -> Option<T>,
) -> T {
    let started = tokio::time::Instant::now();
    loop {
        {
            let handle = cluster.validator_handle(validator_index);
            if let Some(value) = probe(&handle) {
                return value;
            }
        }
        assert!(
            started.elapsed() < deadline,
            "timed out after {deadline:?} waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn poll_state(
    cluster: &IkaTestCluster,
    validator_index: usize,
    expected: &str,
    deadline: Duration,
) {
    poll_node(
        cluster,
        validator_index,
        deadline,
        &format!("seed-identity state {expected}"),
        |handle| {
            seed_identity_state(handle)
                .filter(|state| state == expected)
                .map(|_| ())
        },
    )
    .await;
}

/// Wait until THIS validator (not merely the fastest one in the swarm) is at
/// or past `epoch` AND has resolved its own seed against a certificate.
///
/// Both halves matter. `wait_for_epoch` returns on the first node to report
/// the epoch, so validator 0 can still be an epoch behind; and until a
/// certificate exists for the prior epoch the resolution reads
/// `no_certified_digest`, against which a rotation would prove nothing at all.
async fn wait_until_certified_at_epoch(
    cluster: &IkaTestCluster,
    validator_index: usize,
    epoch: u64,
) -> u64 {
    poll_node(
        cluster,
        validator_index,
        Duration::from_secs(360),
        "this validator to reach the epoch with its own seed certified",
        |handle| {
            let at = current_epoch(handle);
            (at >= epoch && seed_identity_state(handle).as_deref() == Some(STATE_MATCHES))
                .then_some(at)
        },
    )
    .await
}

async fn build_cluster(num_validators: usize) -> IkaTestCluster {
    IkaTestClusterBuilder::new()
        .with_num_validators(num_validators)
        // Long enough that a rotation restart plus the assertions that follow
        // fit comfortably inside one epoch — the whole point of flows (a) and
        // (c) is that they take effect WITHOUT a boundary, so an epoch that
        // rolls over mid-assertion would mask the property under test. Every
        // in-epoch assertion below re-reads the epoch and says so explicitly
        // if it escaped, rather than silently passing on the wrong epoch.
        .with_epoch_duration_ms(90_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed")
}

/// Flow (a): the previous-seed field is set, so the rotation costs nothing.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_with_the_previous_seed_keeps_the_validator_in_mpc() {
    telemetry_subscribers::init_for_testing();
    let cluster = build_cluster(4).await;

    // Epoch 2 so a `1 -> 2` handoff certificate exists: without one the
    // resolution has nothing to resolve against and every rotation would
    // trivially read as `no_certified_digest`.
    cluster.wait_for_epoch(2).await;
    let rotation_epoch = wait_until_certified_at_epoch(&cluster, 0, 2).await;
    let self_name = own_authority_name(&cluster.validator_handle(0));
    let digest_before = poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "the handoff cert for the epoch before the rotation",
        |handle| {
            cert_mpc_data_digests(handle, rotation_epoch - 1)
                .and_then(|digests| digests.get(&self_name).copied())
        },
    )
    .await;

    rotate_root_seed(&cluster, 0, true).await;

    // The certificate still deals this epoch's shares to the previous seed's
    // bundle, so the epoch runs on the previous seed — and MPC keeps running.
    poll_state(
        &cluster,
        0,
        STATE_ROTATING_ON_PREVIOUS,
        Duration::from_secs(180),
    )
    .await;
    poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "the rotated validator to keep advancing MPC sessions on the previous seed",
        |handle| (mpc_advance_attempts(handle) > 0).then_some(()),
    )
    .await;

    // Meanwhile the sender announces the CURRENT seed, so the freeze captures
    // the new bundle and the next certificate names it. Allow two boundaries:
    // a rotation that lands after this epoch's freeze legitimately takes one
    // extra epoch, and that self-healing is part of the contract.
    let certified_after = poll_node(
        &cluster,
        0,
        Duration::from_secs(300),
        "a handoff cert naming a NEW mpc_data digest for the rotated validator",
        |handle| {
            let epoch = current_epoch(handle);
            (rotation_epoch..=epoch).rev().find_map(|source_epoch| {
                cert_mpc_data_digests(handle, source_epoch)
                    .and_then(|digests| digests.get(&self_name).copied())
                    .filter(|digest| *digest != digest_before)
            })
        },
    )
    .await;
    assert_ne!(
        certified_after, digest_before,
        "the certificate must move to the rotated validator's new bundle"
    );

    // And on the far side of that boundary the validator is back on its
    // CURRENT seed, with the rotation-complete signal telling the operator to
    // drop the previous-seed field.
    poll_state(
        &cluster,
        0,
        STATE_ROTATION_COMPLETE,
        Duration::from_secs(300),
    )
    .await;
    poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "MPC to keep advancing after the rotation completed",
        |handle| (mpc_advance_attempts(handle) > 0).then_some(()),
    )
    .await;
}

/// Flows (b) and (c): rotating without the previous-seed field, and repairing
/// it inside the epoch.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_without_the_previous_seed_sits_out_then_rejoins() {
    telemetry_subscribers::init_for_testing();
    // Five validators so the committee keeps a comfortable quorum with one
    // member out of MPC; four would leave 3/4, which is above threshold but
    // gives the test no margin for an unrelated slow node.
    let cluster = build_cluster(5).await;

    cluster.wait_for_epoch(2).await;
    let rotation_epoch = wait_until_certified_at_epoch(&cluster, 0, 2).await;
    let self_name = own_authority_name(&cluster.validator_handle(0));
    let digest_before = poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "the handoff cert for the epoch before the rotation",
        |handle| {
            cert_mpc_data_digests(handle, rotation_epoch - 1)
                .and_then(|digests| digests.get(&self_name).copied())
        },
    )
    .await;
    // The seed this validator is running now, which is the one the cert
    // names — flow (c) repairs by pointing the previous-seed field at it.
    let certified_seed = cluster
        .swarm
        .node(&cluster.validator_names[0])
        .expect("validator node")
        .config()
        .root_seed_key_pair
        .as_ref()
        .expect("a validator always has a root seed")
        .root_seed()
        .clone();

    // ---- (b) rotate with NO previous seed ----
    rotate_root_seed(&cluster, 0, false).await;

    poll_state(
        &cluster,
        0,
        STATE_AWAITING_CERTIFICATION,
        Duration::from_secs(180),
    )
    .await;

    // It must take NO part in MPC while in that state. The counter is on a
    // per-process registry the restart just reset, so any nonzero value is
    // work done since the rotation. Sampled over a window rather than once:
    // a single read right after the restart would pass even if the gate were
    // missing entirely.
    let mut samples_inside_the_epoch = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let handle = cluster.validator_handle(0);
        // Stop sampling if the epoch rolled over: past the boundary the
        // validator legitimately rejoins, and continuing would assert the
        // opposite of the contract.
        if current_epoch(&handle) != rotation_epoch {
            break;
        }
        assert_eq!(
            mpc_advance_attempts(&handle),
            0,
            "a validator whose seed the certificate does not name must send NO \
             MPC traffic — computing with key material the network never dealt \
             to it is how a node convicts itself as malicious (#1978)"
        );
        samples_inside_the_epoch += 1;
    }
    assert!(
        samples_inside_the_epoch >= 5,
        "only {samples_inside_the_epoch} samples landed inside the rotation \
         epoch; the window escaped the epoch and this run proved nothing — \
         raise the epoch duration"
    );
    // A peer, by contrast, is doing MPC work throughout — the positive
    // control that keeps the assertion above from passing on a dead cluster.
    let peer = cluster.validator_handle(1);
    assert!(
        mpc_advance_attempts(&peer) > 0,
        "the rest of the committee must still be running MPC; a quiet cluster \
         would make the zero above meaningless"
    );

    // The committee still freezes and certifies the epoch WITHOUT this
    // validator's MPC — and the certificate carries its NEW digest, because
    // the announcement sender keeps announcing the current seed even while
    // the node is out of MPC. That is what lets it rejoin unaided at E+1.
    let certified_after = poll_node(
        &cluster,
        0,
        Duration::from_secs(300),
        "a handoff cert naming the NEW mpc_data digest of the sat-out validator",
        |handle| {
            let epoch = current_epoch(handle);
            (rotation_epoch..=epoch).rev().find_map(|source_epoch| {
                cert_mpc_data_digests(handle, source_epoch)
                    .and_then(|digests| digests.get(&self_name).copied())
                    .filter(|digest| *digest != digest_before)
            })
        },
    )
    .await;
    assert_ne!(certified_after, digest_before);

    // Once that certificate is the one its epoch resolves against, it is back
    // in MPC with no operator action at all.
    poll_state(&cluster, 0, STATE_MATCHES, Duration::from_secs(300)).await;
    poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "the sat-out validator to rejoin MPC by itself at the next epoch",
        |handle| (mpc_advance_attempts(handle) > 0).then_some(()),
    )
    .await;

    // ---- (c) the in-epoch repair ----
    // Rotate again with no previous seed to re-enter the non-participating
    // state, then hand it the seed that IS certified and restart. It must
    // rejoin the SAME epoch — the resolution runs at every construction, so
    // no boundary is involved.
    //
    // `certified_seed` is the seed the run started on; the cert has moved on
    // to the seed installed by (b), so that is the one to point at.
    let seed_certified_now = cluster
        .swarm
        .node(&cluster.validator_names[0])
        .expect("validator node")
        .config()
        .root_seed_key_pair
        .as_ref()
        .expect("a validator always has a root seed")
        .root_seed()
        .clone();
    assert_ne!(
        seed_certified_now, certified_seed,
        "flow (b) must have left the validator running the rotated-to seed"
    );

    let repair_epoch = current_epoch(&cluster.validator_handle(0));
    rotate_root_seed(&cluster, 0, false).await;
    poll_state(
        &cluster,
        0,
        STATE_AWAITING_CERTIFICATION,
        Duration::from_secs(180),
    )
    .await;

    set_previous_seed_and_restart(&cluster, 0, seed_certified_now).await;
    poll_state(
        &cluster,
        0,
        STATE_ROTATING_ON_PREVIOUS,
        Duration::from_secs(180),
    )
    .await;
    poll_node(
        &cluster,
        0,
        Duration::from_secs(180),
        "the repaired validator to rejoin MPC inside the same epoch",
        |handle| (mpc_advance_attempts(handle) > 0).then_some(()),
    )
    .await;
    assert_eq!(
        current_epoch(&cluster.validator_handle(0)),
        repair_epoch,
        "the repair must take effect WITHOUT an epoch boundary; if the epoch \
         rolled over during the repair this run proved nothing and the epoch \
         duration needs raising"
    );
}
