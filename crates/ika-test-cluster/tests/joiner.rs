// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for validator joiner / removal flows on `IkaTestCluster`.
//!
//! `test_joiner_added_at_epoch_2` exercises the happy path: a 5th validator
//! registers as a candidate, gets staked over the minimum, calls
//! `request_add_validator`, and is spun up as an in-memory `IkaNode`. The
//! assertion is that the joiner's node reaches epoch 2 — proving the
//! on-chain committee swap and the off-chain MPC reconfiguration both
//! accepted the new member.
//!
//! `test_validator_removed_at_epoch_2` exercises the mirror flow: an
//! existing validator submits `request_remove_validator`, and the remaining
//! committee advances to epoch 2 without it.
//!
//! `test_sessions_complete_across_epoch_switch` drives a user-initiated
//! dWallet DKG and verifies it completes even when an epoch boundary
//! crosses while the session is in flight. This is the bug-repro test for
//! "sessions get stuck across epoch switch".
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md: these are
//! coordination tests, not scheduling-dependent. Real parallel crypto + no
//! msim slowdown.

use ika_node::IkaNodeHandle;
use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::validator_initialization_config::OnChainMpcDataShape;
use ika_test_cluster::{IkaTestCluster, IkaTestClusterBuilder, JoinerHandle, wait_for_node_epoch};
use ika_types::crypto::AuthorityName;

#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_added_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Let the initial committee settle into epoch 1 before adding the
    // joiner. Submitting `request_add_validator` from epoch 0 works in
    // principle but adds an extra layer to debug if the test fails.
    cluster.wait_for_epoch(1).await;

    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    // Joiner becomes active at the next epoch boundary. Wait for both
    // the initial set AND the joiner to reach epoch 2 — the initial-set
    // check alone could mask a joiner that's stuck.
    cluster.wait_for_epoch(2).await;
    wait_for_node_epoch(&joiner.node_handle, 2).await;
}

/// Churn-tolerance check: a joiner that registers mid-epoch must land
/// in the *frozen* mpc_data input set — the consensus-agreed set the
/// reconfiguration MPC deals to. The ready-signal emit gate
/// (`decide_ready_to_finalize`) delays the freeze until the next-epoch
/// committee is published and all its members are locally validated (or
/// the epoch-clock deadline), which is precisely what lets a joiner —
/// who can only announce after `V_{e+1}` is published — be captured by
/// the freeze.
///
/// This test caught a real mid-epoch-joiner deadlock — the joiner
/// watcher + freeze emit-gate both keyed off the *assembled* committee,
/// which can't include a joiner until after the freeze excludes it.
/// Fixed by the chain next-epoch-committee channel, after which the
/// joiner fans its mpc_data out (it never did before).
///
/// The integration path (observe the chain committee → fan out → relay
/// accept once the relayer's JoinerPubkeyProvider refreshes → consensus
/// → peer blob fetch + decode-validate → re-emit) must complete inside
/// the freeze window — between mid-epoch, when `V_{e+1}` is published
/// (`epoch_duration / 2`, see `sui_executor::run_epoch_switch`), and the
/// freeze deadline (`3 * epoch_duration / 4`) — a quarter of the epoch.
/// The default multi-second poll cadences fit a production-length epoch
/// but overrun that window in a short test epoch; `epoch_scaled_poll_interval`
/// scales every cadence on this path to ~1% of the epoch (a no-op at
/// production epoch lengths), so the path fits a bounded test epoch.
///
/// WHAT THIS TEST MEASURES. Two separate things, in this order:
///
///   1. The chain view — `epoch_store.committee()`, built by
///      `EpochStartSystem::get_ika_committee` — must SEAT the joiner:
///      its `voting_rights` carry the joiner's name and stake. That is
///      the whole of what the chain committee contributes to MPC since
///      #2119: a `Committee` supplies the reconfiguration public input
///      with an access structure (weights + thresholds) and nothing
///      else. THIS committee's `class_groups_public_keys_and_proofs`
///      map is empty — it is a CHAIN-derived build, and the deprecated
///      on-chain `mpc_data_bytes` it used to decode is not read
///      anywhere — so asserting on it would measure nothing. (The
///      off-chain assembly in `sui_syncer::new_committee` still fills
///      that map on the next-epoch committee it builds; nothing reads
///      it there either.)
///
///      Historically this half of the test asserted exactly that map,
///      and fault injection while fixing the issue-#1772 flake showed
///      what it was really measuring: disabling the joiner P2P fan-out
///      entirely (so the freeze deterministically EXCLUDED the joiner)
///      still left the joiner in the map, because its class-groups key
///      went on chain at candidate registration. It could never see a
///      freeze miss.
///
///   2. Capture by the off-chain freeze — the thing that actually feeds
///      the reconfiguration MPC — asserted against the handoff
///      certificate's `ValidatorMpcData` items: the durable,
///      consensus-anchored record of the frozen set (kept forever in the
///      perpetual tables). The joiner must appear in the epoch-1 cert
///      (captured by the first freeze) or, tolerated with a warning, in
///      the epoch-2 cert — the self-heal path where a joiner that
///      legitimately missed the freeze (per the spec it is excluded, not
///      waited for; dev-docs/specs/validator-mpc-data-announcements.md) is
///      seated by the chain committee anyway and self-announces into
///      consensus as an epoch-2 member.
#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_lands_in_next_committee_class_groups() {
    telemetry_subscribers::init_for_testing();

    // The joiner has to clear TWO windows inside epoch 1, both keyed off
    // mid-epoch (`epoch/2`, when `process_mid_epoch` selects `V_{e+1}`):
    //   1. Registration `[join → epoch/2]`: finish its class-groups
    //      keygen (a fixed, multi-second cost) and land `add_validator`
    //      on-chain so it's selected into `V_{e+1}`. This is gated by
    //      crypto/tx time, NOT by poll cadence, so it needs absolute
    //      wall-clock.
    //   2. Freeze `[epoch/2 → 3·epoch/4]`: fan out → relay → fetch →
    //      decode-validate → re-emit, so a stake quorum's ready signals
    //      cover the joiner before the `3·epoch/4` deadline forces the
    //      freeze without it. `epoch_scaled_poll_interval` shrinks this
    //      path's cadences to fit the window, but the per-peer
    //      class-groups decode-validate is a fixed crypto cost that does
    //      NOT compress with the epoch.
    //
    // Cluster tests always run with the `dwallet-mpc-unsafe-mock`
    // keygen/protocol mocks, which removed the class-groups compute (and its
    // CPU contention) that the historical 240s epoch absorbed. 10s epochs
    // leave a 2.5s joiner freeze window (epoch/4) over the remaining
    // bootstrap/propagation floor.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    // Cert-read probe, captured BEFORE the joiner spawns so it is
    // guaranteed to be an original committee member (the swarm's
    // handle order is unspecified once the joiner node is in).
    let probe = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .next()
        .expect("swarm has at least one validator");
    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    cluster.wait_for_epoch(2).await;
    // The joiner node must follow the cluster to epoch 2 regardless of
    // the class-groups checks below — its committee seat comes from the
    // chain committee, and even a joiner the off-chain freeze excluded
    // advances epochs normally (CI failure runs of this test showed
    // exactly that). This wait only fails fast on a dead joiner node.
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        wait_for_node_epoch(&joiner.node_handle, 2),
    )
    .await
    .expect(
        "joiner node did not reach epoch 2 within 60s of the cluster — \
         node dead or not following the chain",
    );

    let joiner_name = joiner.authority_name();

    // Chain view: the joiner must be SEATED in the epoch-2 committee its
    // own node built from `EpochStartSystem`. Seat + stake is everything
    // the chain committee contributes to MPC — the reconfiguration public
    // input takes only the access structure from a `Committee` — and the
    // seat comes from the active-validator set, not from the deprecated
    // on-chain `mpc_data_bytes` field, which nothing decodes any more
    // (#2119).
    assert_joiner_seated_with_grace(&mut cluster, &joiner, joiner_name, "real-key joiner").await;

    // The seat check above cannot see a freeze miss (see the test doc)
    // — the off-chain frozen set's durable record is the handoff cert's
    // `ValidatorMpcData` items. Assert the joiner is in the epoch-1 cert.
    let epoch_1_cert_validators = wait_for_handoff_cert_mpc_data(&cluster, &probe, 1).await;
    // Original members reach the frozen set by consensus
    // self-submission — no P2P fan-out or propagation race involved —
    // so their absence means the freeze/handoff pipeline is broken
    // outright and must never fall into the joiner-tolerance path
    // below.
    // Under the same identity basis the cert items use.
    for original in &cluster.validator_names {
        assert!(
            epoch_1_cert_validators.contains(original),
            "original validator {original:?} missing from the epoch-1 handoff cert's \
             ValidatorMpcData items ({epoch_1_cert_validators:?})"
        );
    }
    if !epoch_1_cert_validators.contains(&joiner_name) {
        // Legitimate per the spec: a joiner whose announcement loses
        // the propagation race with the freeze is excluded, not waited
        // for. The network must then self-heal — seated in epoch 2,
        // the joiner self-announces into consensus, so the epoch-2
        // freeze (and therefore the epoch-2 cert) must capture it.
        tracing::warn!(
            ?joiner_name,
            "joiner missing from the epoch-1 handoff cert (excluded by the first freeze); \
             falling back to the epoch-2 cert via the member self-announcement path"
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            cluster.wait_for_epoch(3),
        )
        .await
        .expect("epoch 3 did not arrive within 120s while waiting for the self-heal cert");
        let epoch_2_cert_validators = wait_for_handoff_cert_mpc_data(&cluster, &probe, 2).await;
        assert!(
            epoch_2_cert_validators.contains(&joiner_name),
            "joiner {joiner_name:?} missing from BOTH the epoch-1 and the epoch-2 handoff \
             certs' ValidatorMpcData items (epoch-2: {epoch_2_cert_validators:?}) — the \
             off-chain frozen set never captured the joiner's mpc_data"
        );
    }
}

/// ACCEPTANCE TEST for #2119, placeholder half: a validator that
/// registers with the post-deprecation placeholder — a `VersionedMPCData`
/// whose inner `mpc_data_bytes` is EMPTY — must boot, be seated, and take
/// part in MPC exactly like one that registered a real key.
///
/// This is the shape every new validator registers with once the CLI stops
/// submitting key material. Before #2119 it bricked the registrant at first
/// boot (the seed-identity check decoded the field and failed closed) and
/// broke the bootstrap-window committee build for every node that needed it
/// (one undecodable member failed the whole build).
#[tokio::test(flavor = "multi_thread")]
async fn test_placeholder_registration_joiner_joins_mpc() {
    placeholder_registration_joiner_joins_mpc(OnChainMpcDataShape::EmptyPlaceholder).await;
}

/// ACCEPTANCE TEST for #2119, "assume anything" half: the same, with inner
/// `mpc_data_bytes` that are non-empty and NOT a decodable
/// `ClassGroupsEncryptionKeyAndProof`.
///
/// The decision is that nothing about the field is enforced or verified, so
/// its content must not matter. The genesis validators in the same cluster
/// register REAL keys (pre-#2119 validators keep theirs on chain forever —
/// there is no migration), so each run also covers a mixed network.
#[tokio::test(flavor = "multi_thread")]
async fn test_garbage_on_chain_mpc_data_joiner_joins_mpc() {
    placeholder_registration_joiner_joins_mpc(OnChainMpcDataShape::GarbageBytes).await;
}

/// Invariant sites #2119 RETIRED, pinned by name so a reintroduction is
/// caught rather than merely reviewed away. Each fired when a committee
/// member's on-chain `mpc_data` record was missing or would not decode —
/// exactly what a placeholder registration looks like.
const RETIRED_ON_CHAIN_MPC_DATA_INVARIANT_SITES: &[&str] = &[
    // `sui_syncer::new_committee`, bootstrap-window chain read.
    "chain_fallback_mpc_data_missing",
    "chain_fallback_mpc_data_decode",
    // `epoch_start_system::build_ika_committee`.
    "persisted_epoch_start_mpc_data_missing",
];

async fn placeholder_registration_joiner_joins_mpc(shape: OnChainMpcDataShape) {
    telemetry_subscribers::init_for_testing();
    // Arm the process-global invariant counter BEFORE anything boots, so a
    // violation during genesis, joiner registration or the epoch boundary is
    // recorded and readable below. `get_or_init`, so this is a no-op if the
    // process already registered it.
    ika_types::metrics::init_invariant_violation_metric(&prometheus::Registry::new());

    // Same windows and cadences as `test_joiner_lands_in_next_committee_class_groups`
    // — see its comment for why 10s epochs are the floor here.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    // Captured before the joiner spawns so it is guaranteed to be an
    // original committee member.
    let probe = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .next()
        .expect("swarm has at least one validator");
    let joiner = cluster
        .add_joiner_validator_with_onchain_mpc_data_shape(shape)
        .await
        .unwrap_or_else(|e| panic!("add_joiner_validator failed for {shape:?}: {e:?}"));
    let joiner_name = joiner.authority_name();

    // 1. It boots and follows the chain. The old boot-time seed-identity
    //    check decoded the on-chain field and refused to start MPC when it
    //    did not match the locally derived class-groups key — a validator
    //    registered this way bricked ITSELF here.
    cluster.wait_for_epoch(2).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        wait_for_node_epoch(&joiner.node_handle, 2),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "joiner registered with {shape:?} did not reach epoch 2 within 60s of the \
             cluster — the node is dead or not following the chain"
        )
    });

    // 2. Every ORIGINAL member also advanced. The chain-fallback committee
    //    build used to decode EVERY member's on-chain record and fail the
    //    whole build on one bad member, so a single placeholder registration
    //    broke that path for every node that needed it — not just for the
    //    registrant.
    for handle in cluster.swarm.validator_node_handles() {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            wait_for_node_epoch(&handle, 2),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a committee member did not reach epoch 2 alongside a joiner \
                 registered with {shape:?}"
            )
        });
    }

    // 3. It is SEATED: the chain committee carries its name and stake,
    //    which is all a `Committee` contributes to the reconfiguration MPC.
    assert_joiner_seated_with_grace(
        &mut cluster,
        &joiner,
        joiner_name,
        &format!("registered with {shape:?}"),
    )
    .await;

    // 4. It JOINED MPC: its real key material reached the consensus-agreed
    //    frozen set through the off-chain announcement pipeline, witnessed
    //    by the handoff cert's `ValidatorMpcData` items — the durable,
    //    consensus-anchored record of that set. Nothing about this path
    //    reads the on-chain field, which is the whole point.
    let epoch_1_cert_validators = wait_for_handoff_cert_mpc_data(&cluster, &probe, 1).await;
    for original in &cluster.validator_names {
        assert!(
            epoch_1_cert_validators.contains(original),
            "original validator {original:?} missing from the epoch-1 handoff cert's \
             ValidatorMpcData items ({epoch_1_cert_validators:?}) — the freeze/handoff \
             pipeline is broken outright, independent of the joiner"
        );
    }
    if !epoch_1_cert_validators.contains(&joiner_name) {
        // Per the spec a joiner that loses the propagation race with the
        // freeze is excluded, not waited for; seated in epoch 2 it
        // self-announces and the epoch-2 freeze must capture it. Same
        // tolerance as `test_joiner_lands_in_next_committee_class_groups`.
        tracing::warn!(
            ?joiner_name,
            ?shape,
            "joiner missing from the epoch-1 handoff cert (excluded by the first freeze); \
             falling back to the epoch-2 cert via the member self-announcement path"
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            cluster.wait_for_epoch(3),
        )
        .await
        .expect("epoch 3 did not arrive within 120s while waiting for the self-heal cert");
        let epoch_2_cert_validators = wait_for_handoff_cert_mpc_data(&cluster, &probe, 2).await;
        assert!(
            epoch_2_cert_validators.contains(&joiner_name),
            "joiner {joiner_name:?} registered with {shape:?} is missing from BOTH the \
             epoch-1 and the epoch-2 handoff certs' ValidatorMpcData items (epoch-2: \
             {epoch_2_cert_validators:?}) — its off-chain mpc_data never reached the \
             frozen set, so it never joined MPC"
        );
    }

    // 5. And it did all of that QUIETLY: none of the invariant sites that
    //    used to fire on an undecodable on-chain record was reported, at
    //    boot or across the epoch boundary. A placeholder registration is
    //    legitimate, so it must not look like a chain-read defect on any
    //    node in the network.
    for site in RETIRED_ON_CHAIN_MPC_DATA_INVARIANT_SITES {
        assert_eq!(
            ika_types::metrics::invariant_violation_count(site),
            Some(0),
            "retired invariant site {site:?} fired for a joiner registered with \
             {shape:?} — the deprecated on-chain mpc_data field is being decoded \
             again somewhere"
        );
    }
    // The re-homed seed-identity guard must also stay silent: every
    // validator here runs the seed it announced with.
    assert_eq!(
        ika_types::metrics::invariant_violation_count("mpc_data_frozen_digest_seed_mismatch"),
        Some(0),
        "the frozen mpc_data digest disagreed with some validator's running root seed"
    );
}

/// Assert the joiner is SEATED in the committee its own node built, with
/// the bounded grace issue #1772 established is the only sound shape here.
///
/// Whether a mid-epoch registration makes epoch 2 at all is a per-run race:
/// `request_add_validator` has to land before `process_mid_epoch` selects
/// `V_{e+1}`, and under CI contention it can miss, in which case the joiner
/// legitimately activates at epoch 3 instead. A strict epoch-2 assertion is
/// unsound at any epoch length — it flaked all three joiner tests on their
/// first attempt when this was written strictly.
///
/// So: seated at epoch 2 (normal), or seated at epoch 3 (registration
/// landed after the mid-epoch selection). Absent at epoch 3 too means the
/// joiner never activated — a registration/lifecycle bug, not timing.
async fn assert_joiner_seated_with_grace(
    cluster: &mut IkaTestCluster,
    joiner: &JoinerHandle,
    joiner_name: AuthorityName,
    context: &str,
) {
    fn seated_at(joiner: &JoinerHandle, name: AuthorityName, expected_epoch: u64) -> bool {
        joiner.node_handle.with(|node| {
            let epoch_store = node.state().epoch_store_for_testing();
            let committee = epoch_store.committee();
            assert_eq!(
                committee.epoch(),
                expected_epoch,
                "joiner node should be at epoch {expected_epoch}"
            );
            committee
                .voting_rights
                .iter()
                .any(|(n, stake)| *n == name && *stake > 0)
        })
    }

    if seated_at(joiner, joiner_name, 2) {
        return;
    }
    tracing::warn!(
        ?joiner_name,
        context,
        "joiner not seated in the epoch-2 committee — registration landed after the \
         mid-epoch committee selection, so it activates at epoch 3 (tolerated once); \
         asserting the epoch-3 seat"
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(300),
        cluster.wait_for_epoch(3),
    )
    .await
    .expect("cluster did not reach epoch 3 within 300s during the joiner seat grace window");
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        wait_for_node_epoch(&joiner.node_handle, 3),
    )
    .await
    .expect("joiner node did not reach epoch 3 within 60s of the cluster during the grace window");
    assert!(
        seated_at(joiner, joiner_name, 3),
        "joiner {joiner_name:?} ({context}) was absent from the epoch-2 committee \
         (tolerated once — registration can miss the mid-epoch selection) and is STILL \
         absent at epoch 3: it never activated, which is a registration/lifecycle bug, \
         not a timing race"
    );
}

/// Poll `node_handle`'s perpetual tables until its handoff cert for
/// `source_epoch` is persisted, then return the authority names pinned
/// by the cert's `ValidatorMpcData` items. Cert persistence trails the
/// epoch switch (quorum aggregation of the consensus-ordered handoff
/// signatures runs at the boundary), hence the eventual semantics.
async fn wait_for_handoff_cert_mpc_data(
    cluster: &IkaTestCluster,
    node_handle: &IkaNodeHandle,
    source_epoch: u64,
) -> Vec<AuthorityName> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(validators) =
            cluster.handoff_cert_mpc_data_validators_for_node(node_handle, source_epoch)
        {
            return validators;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no handoff cert for source epoch {source_epoch} persisted on the probe \
             validator within 60s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_removed_at_epoch_2() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        // The production minimum is four, so a four-to-three removal would be
        // rejected before the test could exercise the epoch transition.
        .with_min_validator_count(3)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    // Validator 0 submits `request_remove_validator`. The on-chain
    // logic keeps it in the active set for the rest of epoch 1 and
    // drops it at the epoch-2 boundary.
    cluster
        .remove_validator(0)
        .await
        .expect("remove_validator failed");

    // Snapshot remaining validators' node handles BEFORE waiting —
    // index 0 might disappear from validator_node_handles() depending
    // on shutdown timing, and we want to assert the survivors reach
    // epoch 2 with the new 3-member committee.
    let remaining: Vec<_> = cluster
        .swarm
        .validator_node_handles()
        .into_iter()
        .skip(1)
        .collect();
    assert_eq!(
        remaining.len(),
        3,
        "expected 3 surviving validator handles before wait_for_epoch(2)"
    );
    for handle in &remaining {
        wait_for_node_epoch(handle, 2).await;
    }
}

/// Curve enum value for `Secp256k1` (matches the on-chain definition
/// in `coordinator_inner.move`).
const DWALLET_CURVE_SECP256K1: u32 = 0;

#[tokio::test(flavor = "multi_thread")]
async fn test_sessions_complete_across_epoch_switch() {
    telemetry_subscribers::init_for_testing();

    // Short epoch_duration so the epoch boundary lands while the
    // user-initiated DKG is in flight. The bug being probed is
    // "sessions stuck across epoch switch" — keeping epochs short
    // maximizes the chance the boundary crosses mid-DKG.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [7u8; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    // Race the epoch-2 boundary against DKG completion. Both should
    // succeed — the DKG MUST finish despite the epoch switch crossing
    // mid-session.
    //
    // Empirically the MPC computation itself is fast (~100ms per
    // round) but the request → MPC kickoff path queues behind the
    // network-reconfiguration MPC when an epoch boundary lands soon
    // after submission, easily adding 2+ minutes wall before the
    // session even starts. The chain-event emission pipeline
    // (validator output → consensus → checkpoint → Sui tx → emit)
    // adds another few seconds. A 5-minute timeout gives both stages
    // headroom; the failure mode the test cares about is "stuck",
    // not "slow".
    // Epoch 2 must advance regardless of session state — the
    // protocol explicitly should NOT block epoch change on
    // in-flight sessions. Bound the wait separately from the DKG
    // wait so we can tell stuck-epoch (system bug: epoch blocked
    // on session) apart from stuck-session (session never
    // completes but epoch does). With epoch_duration_ms = 15_000,
    // epoch 2 should land within ~90s of epoch 1 even with the
    // reconfiguration MPC running.
    let dkg_done = cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(300));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, dkg_result) = tokio::join!(epoch_2, dkg_done);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight session");
    dkg_result.expect("dWallet DKG never completed across epoch switch");
}

/// Submit three user-initiated dWallet DKGs in quick succession,
/// driving them all through the epoch-1→2 reconfiguration window
/// concurrently. Each DKG must reach a terminal state.
///
/// Probes whether queue depth at the epoch boundary affects
/// completion. Original user report: "some sessions get stuck and
/// never finishes" — this is the most direct stress-test for a
/// stuck-tail-of-queue failure mode.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_concurrent_dwallet_dkgs_across_epoch_switch() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    // Three DKGs, each with a distinct seed so the encryption keys
    // don't collide on the publisher's address book.
    let mut dkg_handles = Vec::new();
    for (i, seed_byte) in [0x11u8, 0x22, 0x33].iter().enumerate() {
        let user_key = cluster
            .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [*seed_byte; 32])
            .await
            .unwrap_or_else(|e| panic!("register_user_encryption_key #{i} failed: {e}"));
        let ika_coin_id = cluster.packages.ika_supply_id;
        let dkg_handle = cluster
            .request_user_dwallet_dkg(
                DWALLET_CURVE_SECP256K1,
                network_key_id,
                network_dkg_public_output.clone(),
                &user_key,
                ika_coin_id,
            )
            .await
            .unwrap_or_else(|e| panic!("request_user_dwallet_dkg #{i} failed: {e}"));
        dkg_handles.push(dkg_handle);
    }

    // Epoch 2 must advance independently of in-flight sessions.
    let dkg_completions = futures::future::join_all(dkg_handles.iter().map(|h| {
        cluster.wait_for_dwallet_dkg_complete(h.dwallet_id, std::time::Duration::from_secs(300))
    }));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, results) = tokio::join!(epoch_2, dkg_completions);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight sessions");
    for (i, result) in results.into_iter().enumerate() {
        result.unwrap_or_else(|e| panic!("dWallet DKG #{i} never completed: {e}"));
    }
}

/// Add a 5th validator while a user-initiated DKG is in flight.
/// Both must reach epoch 2 cleanly: joiner active, DKG completed.
///
/// Probes whether mid-flight committee changes interact badly with
/// in-flight user sessions — a scenario the user's original
/// "stuck sessions" report could plausibly cover.
#[tokio::test(flavor = "multi_thread")]
async fn test_joiner_added_while_user_dkg_in_flight() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;

    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let user_key = cluster
        .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [0x44; 32])
        .await
        .expect("register_user_encryption_key failed");

    let ika_coin_id = cluster.packages.ika_supply_id;
    let dkg_handle = cluster
        .request_user_dwallet_dkg(
            DWALLET_CURVE_SECP256K1,
            network_key_id,
            network_dkg_public_output,
            &user_key,
            ika_coin_id,
        )
        .await
        .expect("request_user_dwallet_dkg failed");

    // Submit the joiner add while the DKG is queued behind the
    // network reconfiguration MPC. The joiner becomes part of the
    // active set at the epoch-1→2 boundary, the same boundary the
    // user DKG should complete across.
    let joiner = cluster
        .add_joiner_validator()
        .await
        .expect("add_joiner_validator failed");

    // Epoch 2 must advance independently of in-flight session +
    // joiner add.
    let dkg_done = cluster
        .wait_for_dwallet_dkg_complete(dkg_handle.dwallet_id, std::time::Duration::from_secs(300));
    let epoch_2 = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        cluster.wait_for_epoch(2),
    );
    let (epoch_result, dkg_result) = tokio::join!(epoch_2, dkg_done);
    epoch_result.expect("epoch 2 was blocked — likely by in-flight session or joiner");
    dkg_result.expect("dWallet DKG never completed alongside joiner add");
    wait_for_node_epoch(&joiner.node_handle, 2).await;
}

/// Multi-epoch stress: across six epoch cycles, submit three user
/// DKGs per cycle — "early" right after the new epoch starts, "mid"
/// in the middle of the epoch, and "late" deliberately close to the
/// next epoch boundary so it queues across reconfiguration. All
/// eighteen DKGs must complete, and every epoch transition must
/// finish within a bounded time (no blocking on in-flight sessions).
///
/// This is the broadest single-test verification that:
/// 1. Repeated user sessions don't accumulate state that breaks
///    later sessions.
/// 2. Sessions submitted at any point in the epoch cycle complete.
/// 3. Epoch advancement isn't blocked by session queues.
/// 4. The pipeline survives sustained load over multiple
///    reconfigurations (not just one).
#[tokio::test(flavor = "multi_thread")]
async fn test_user_sessions_across_multiple_epochs() {
    telemetry_subscribers::init_for_testing();

    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(15_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Reach epoch 1 + capture the network DKG output once; it stays
    // valid for the rest of the test (protocol public parameters are
    // derived per-curve from this blob).
    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    let mut all_handles = Vec::new();

    // Six cycles, each starting in epoch N and ending at epoch
    // N+1. Within each cycle: register + submit three DKGs (early,
    // mid, late), then assert the epoch transition lands in bounded
    // time. The 120s per-epoch ceiling is the same bound used by
    // the other bug-repro tests; if a session queue blocks epoch
    // advancement, this fires.
    const CYCLES: u32 = 6;
    const DKGS_PER_CYCLE: u32 = 3;
    // With epoch_duration_ms = 15_000, ~5s sleep between
    // submissions spreads them across the epoch window: roughly t=0,
    // t=5s (mid), t=10s (late, close to the timer firing).
    const SLEEP_BETWEEN_SUBMISSIONS: std::time::Duration = std::time::Duration::from_secs(5);

    for cycle in 1u32..=CYCLES {
        for batch in 0u32..DKGS_PER_CYCLE {
            // Unique seed per registration so each user encryption
            // key lives at a distinct on-chain address. Two bytes:
            // cycle and batch — keeps the 32-byte seed buffer
            // structured + reproducible.
            let seed_byte = (cycle as u8 * 10) + batch as u8;
            let user_key = cluster
                .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [seed_byte; 32])
                .await
                .unwrap_or_else(|e| {
                    panic!("register_user_encryption_key (cycle={cycle}, batch={batch}): {e}")
                });

            let ika_coin_id = cluster.packages.ika_supply_id;
            let dkg_handle = cluster
                .request_user_dwallet_dkg(
                    DWALLET_CURVE_SECP256K1,
                    network_key_id,
                    network_dkg_public_output.clone(),
                    &user_key,
                    ika_coin_id,
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("request_user_dwallet_dkg (cycle={cycle}, batch={batch}): {e}")
                });
            all_handles.push((cycle, batch, dkg_handle));

            // Spread submissions across the epoch window — the
            // first lands at epoch start, subsequent ones drift
            // toward the boundary so at least one consistently
            // queues across reconfiguration.
            if batch + 1 < DKGS_PER_CYCLE {
                tokio::time::sleep(SLEEP_BETWEEN_SUBMISSIONS).await;
            }
        }

        // Epoch must advance within a bounded window regardless of
        // whether the in-flight DKGs have completed. With
        // `internal_presign_sessions = true` (v4 default) +
        // multiple in-flight user DKGs, each transition takes
        // longer; 240s is the empirical ceiling we observe with
        // 3 concurrent DKGs.
        let next_epoch = cycle as u64 + 1;
        tokio::time::timeout(
            std::time::Duration::from_secs(240),
            cluster.wait_for_epoch(next_epoch),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("epoch {next_epoch} was blocked — sessions held up reconfiguration")
        });
    }

    // All DKGs must complete. Wait one at a time to bound the
    // overall wait; in practice they finish quickly once their
    // session-output checkpoints land on chain.
    for (cycle, batch, handle) in &all_handles {
        cluster
            .wait_for_dwallet_dkg_complete(handle.dwallet_id, std::time::Duration::from_secs(300))
            .await
            .unwrap_or_else(|e| panic!("dkg (cycle={cycle}, batch={batch}): {e}"));
    }
}

/// Real-network sustained-churn simulation: validator churn (new
/// joiners arriving, original validators leaving) interleaved with
/// user DKGs that must complete throughout — the kind of operator
/// turnover a production network sees, exercised across several
/// reconfiguration boundaries to prove sustained churn doesn't wedge
/// off-chain reconfiguration.
///
/// Schedule across 5 epoch transitions (epoch 1 → epoch 6):
///   E1→E2:  add joiner J1                (active 4→5)
///   E2→E3:  remove original validator 0  (active 5→4)
///   E3→E4:  add joiner J2                (active 4→5)
///   E4→E5:  remove original validator 1  (active 5→4)
///   E5→E6:  add joiner J3                (active 4→5)
///
/// One user DKG submitted at the start of each cycle (5 total). All
/// must complete by the end of the test.
#[tokio::test(flavor = "multi_thread")]
async fn test_real_network_churn_over_5_epochs() {
    telemetry_subscribers::init_for_testing();

    // A joiner's window is the quarter-epoch between mid-epoch committee
    // publication (epoch/2) and the freeze (3·epoch/4); in it the joiner
    // must derive its mpc_data, bootstrap, fan out, relay, and be attested.
    // Cluster tests always run with the `dwallet-mpc-unsafe-mock`
    // keygen/protocol mocks, which removed the dominant class-groups cost
    // from that pipeline; 10s epochs (2.5s window) budget only the
    // remaining bootstrap/propagation floor. Five churn cycles remain
    // enough sustained turnover to prove reconfiguration converges.
    let mut cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .with_protocol_version(ProtocolVersion::MAX)
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    cluster.wait_for_epoch(1).await;
    let (network_key_id, network_dkg_public_output) = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    // Track surviving "original validator" indices we haven't
    // removed yet — pop from the front each remove cycle. Indices
    // 0..=3 reference the bootstrap-time validator slots.
    let mut originals_remaining: std::collections::VecDeque<usize> = (0..4).collect();
    // Track joiners post-add so we can verify each one actually
    // reaches the next epoch (i.e. is live in the active committee,
    // not just registered on-chain).
    let mut joiner_handles: Vec<(u32, u64, ika_test_cluster::JoinerHandle)> = Vec::new();
    let mut joiner_count = 0u32;
    let mut all_dkg_handles = Vec::new();

    // Each iteration drives one epoch transition. Alternates
    // joiner-add (odd cycles) and original-validator-remove (even
    // cycles). One user DKG per cycle, submitted before the churn
    // op so it's in flight across the transition.
    for cycle in 1u32..=5 {
        // 1. Submit a user DKG so the network is exercising real
        //    work during the transition.
        let seed_byte = 0x80 + cycle as u8;
        let user_key = cluster
            .register_user_encryption_key(DWALLET_CURVE_SECP256K1, [seed_byte; 32])
            .await
            .unwrap_or_else(|e| panic!("register_user_encryption_key (cycle={cycle}): {e}"));
        let ika_coin_id = cluster.packages.ika_supply_id;
        let dkg_handle = cluster
            .request_user_dwallet_dkg(
                DWALLET_CURVE_SECP256K1,
                network_key_id,
                network_dkg_public_output.clone(),
                &user_key,
                ika_coin_id,
            )
            .await
            .unwrap_or_else(|e| panic!("request_user_dwallet_dkg (cycle={cycle}): {e}"));
        all_dkg_handles.push((cycle, dkg_handle));

        // 2. Alternate add / remove. Odd cycles add a joiner; even
        //    cycles remove the next-oldest original validator.
        //    Keeps active-set size oscillating between 4 and 5 so
        //    the BFT quorum (2f+1 = 3 for n=4, =4 for n=5) is
        //    always achievable.
        // Alternate add / remove: add on odd cycles, remove the
        // next-oldest original on even cycles. With 4 originals and
        // 5 cycles, we get 3 adds (cycles 1, 3, 5) and 2 removes
        // (cycles 2, 4), so the active set oscillates 4→5→4→5→4→5
        // and two originals survive — enough sustained churn to
        // exercise reconfiguration convergence without a full
        // turnover marathon.
        if cycle % 2 == 1 {
            joiner_count += 1;
            let joiner = cluster
                .add_joiner_validator()
                .await
                .unwrap_or_else(|e| panic!("add_joiner_validator (cycle={cycle}): {e}"));
            tracing::info!(cycle, joiner_count, "added joiner");
            // Record alongside the epoch the joiner becomes active
            // (the cycle's transition target). Used after the
            // transition to assert the joiner's in-memory node
            // advances to that epoch — proving it's actually
            // participating, not just registered on chain.
            joiner_handles.push((cycle, cycle as u64 + 1, joiner));
        } else if let Some(idx) = originals_remaining.pop_front() {
            cluster
                .remove_validator(idx)
                .await
                .unwrap_or_else(|e| panic!("remove_validator (cycle={cycle}, idx={idx}): {e}"));
            tracing::info!(cycle, removed_original = idx, "removed original validator");
        } else {
            tracing::info!(cycle, "even cycle with no originals left — DKG-only");
        }

        // 3. Wait for the next epoch within a bounded window. With a
        //    300s epoch the freeze lands at ~225s and the reconfiguration
        //    MPC (with an in-flight user DKG + committee change) runs
        //    after it, so a transition completes in the ~6-8 min range
        //    under churn contention. 900s gives headroom while still
        //    catching truly-stuck cases.
        let next_epoch = cycle as u64 + 1;
        tokio::time::timeout(
            std::time::Duration::from_secs(900),
            cluster.wait_for_epoch(next_epoch),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "epoch {next_epoch} did not advance within 600s — \
                 churn cycle {cycle} blocked reconfiguration"
            )
        });

        // Verify every joiner whose activation epoch is now in the
        // past (i.e. has been through at least one reconfig boundary)
        // is actually live — its in-memory node reaches the current
        // epoch. Without this, "joiner added" only proves on-chain
        // registration; live-in-committee participation is what
        // matters for the simulation. 60s ceiling: by the time we
        // get here the cluster has already reached `next_epoch`, so
        // the joiner should be at parity within a few poll cycles.
        for (added_cycle, active_from_epoch, joiner) in &joiner_handles {
            if *active_from_epoch <= next_epoch {
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    wait_for_node_epoch(&joiner.node_handle, next_epoch),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "joiner added in cycle {added_cycle} (active from epoch \
                         {active_from_epoch}) failed to reach epoch {next_epoch} \
                         within 60s — not participating in the committee"
                    )
                });

                // Log handoff cert presence on the joiner as
                // diagnostic — same caveat as the probe check
                // below: the cert may not land every cycle if
                // validators disagree on the next-committee view
                // at EndOfPublish, surfacing as
                // `AttestationMismatch` rejections.
                if next_epoch > *active_from_epoch {
                    let joiner_certs = cluster.handoff_cert_epochs_for_node(&joiner.node_handle);
                    tracing::info!(
                        added_cycle,
                        active_from_epoch,
                        next_epoch,
                        ?joiner_certs,
                        has_source_epoch = joiner_certs.contains(active_from_epoch),
                        "joiner handoff cert progress",
                    );
                }
            }
        }

        // Best-effort observation of handoff cert progress. The
        // cert for source epoch N requires 2f+1 validators to
        // independently compute and sign the same
        // `HandoffAttestation` — they can disagree on
        // `next_committee_pubkey_set_hash` or `items` if their
        // chain-sync of the next committee / off-chain mpc_data
        // freeze hasn't converged at the EndOfPublish moment.
        // This is a known mode that surfaces under churn; the test
        // tolerates it per-cycle and asserts presence only at the
        // very end. Logging here gives visibility into how often
        // the cert actually lands.
        let probe_handle = cluster
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm has at least one validator");
        let probe_certs = cluster.handoff_cert_epochs_for_node(&probe_handle);
        tracing::info!(
            cycle,
            next_epoch,
            ?probe_certs,
            has_source_epoch = probe_certs.contains(&(cycle as u64)),
            "handoff cert progress on probe validator",
        );
    }

    // All 5 user DKGs must reach a terminal state. By now the active
    // set is a mix of the 2 surviving originals and 3 joiners; DKG
    // sessions submitted earlier must still complete across the churn.
    for (cycle, handle) in &all_dkg_handles {
        cluster
            .wait_for_dwallet_dkg_complete(handle.dwallet_id, std::time::Duration::from_secs(300))
            .await
            .unwrap_or_else(|e| panic!("dkg (cycle={cycle}): {e}"));
    }

    assert_eq!(
        joiner_count, 3,
        "expected 3 joiners added across the 5 cycles"
    );
    assert_eq!(
        originals_remaining.len(),
        2,
        "expected 2 of 4 originals removed across the 5 cycles, {} remaining",
        originals_remaining.len()
    );

    // Final sanity: every joiner is at the test's final epoch (6). By
    // now they should all be live committee members participating
    // alongside the two surviving originals.
    let final_epoch = 6;
    for (added_cycle, _, joiner) in &joiner_handles {
        let current = joiner
            .node_handle
            .with(|node| node.current_epoch_for_testing());
        assert!(
            current >= final_epoch,
            "joiner from cycle {added_cycle} is at epoch {current}, expected >= {final_epoch}",
        );

        let certs = cluster.handoff_cert_epochs_for_node(&joiner.node_handle);
        tracing::info!(added_cycle, ?certs, "final joiner handoff cert state");
    }

    // Aggregate cert presence across the whole cluster — at least
    // one validator (any committee member of any past epoch) must
    // have persisted at least one handoff cert. This is a weak
    // form of "the handoff pipeline did SOMETHING"; per-cycle
    // assertions are intentionally relaxed because the cert can
    // fail to certify when validators disagree on the
    // next-committee view at EndOfPublish (surfacing as
    // `AttestationMismatch` rejections).
    //
    // Root cause (investigated): the `HandoffAttestation`'s
    // `next_committee_pubkey_set_hash` is computed by each signer
    // from its LOCAL `next_epoch_committee_receiver` (the off-chain
    // *assembled* committee), via `build_local_handoff_attestation`.
    // The network-key-output digests in `items` were already made
    // consensus-deterministic (hydrated from chain in
    // `HandoffSignatureSender::send`), but the committee *membership*
    // is not: under churn a joiner that announced is present in the
    // pre-freeze assembled committee and absent from the post-freeze
    // one (it was excluded by the freeze), so signers that sign at
    // different convergence points hash different member sets and
    // cross-reject. This is addressed in `HandoffSignatureSender::send`,
    // which derives the attestation's committee membership
    // deterministically — the next committee intersected with the
    // consensus-ordered frozen mpc_data set (= the final epoch-E
    // committee the joiner verifier observes) — instead of the racy
    // local watch-channel value. The intersection is a no-op outside
    // churn, so it can't regress the steady state. The aggregate
    // assertion below is kept (rather than a per-cycle one) until the
    // per-cycle cert rate under churn is verified on stable infra.
    let mut total_certs_seen = 0usize;
    for handle in cluster.swarm.validator_node_handles() {
        let certs = cluster.handoff_cert_epochs_for_node(&handle);
        total_certs_seen += certs.len();
    }
    tracing::info!(
        total_certs_seen,
        "aggregate handoff cert count across all validators",
    );
    assert!(
        total_certs_seen > 0,
        "no validator persisted any handoff cert across {} epoch transitions — \
         the off-chain handoff pipeline did not produce a single certified \
         attestation",
        final_epoch - 1
    );
}
