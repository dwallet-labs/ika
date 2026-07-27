// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Gradual protocol-version transition (v5 → v6) across multiple epochs.
//!
//! Models a real rolling upgrade: the network boots at protocol v5 with one
//! validator supporting `5..=MAX` and the other three pinned at `5..=5`. The
//! end-of-epoch capability quorum vote
//! (`choose_highest_protocol_version_and_move_contracts_upgrades_v1`) needs
//! enough stake to support a higher version before `SetNextConfigVersion`
//! fires.
//!
//! v5 → v6 is the boundary where a validator's `AuthorityName` — its
//! canonical committee identity — flips from the BLS protocol key to the
//! Ed25519 consensus key (`consensus_key_authority_names`). The boundary is
//! the asymmetry the flip's bug history lives in: the next-epoch committee is
//! assembled mid-epoch under the OUTGOING version's identity basis but
//! rebuilt by the entering epoch under its own, so the v6-activation
//! reconfiguration crosses bases mid-flight. This is the in-process
//! counterpart of the out-of-process `v125_v6_upgrade` rehearsal
//! (`crates/ika-upgrade-test`): that one swaps REAL old-release binaries and
//! gates deployed-release compatibility; this one runs a single binary with
//! per-validator pinned advertised ranges, gating the capability-vote
//! machinery and the in-process transition — including the epoch-boundary
//! restart/rebuild paths the out-of-process harness does not exercise.
//!
//! (The v4 → v5 flavor of this test was retired when v3/v4 support was
//! removed and MIN = MAX = 5 left no boundary to cross; this resurrects it
//! retargeted at the v6 boundary.)
//!
//! Effective threshold note: ika inherits Sui's
//! `buffer_stake_for_protocol_upgrade_bps` (default 5000). For `n=4` (f=1,
//! quorum=3) the effective threshold is `quorum + ceil(f * 5000/10000) = 4`,
//! so a protocol upgrade requires **all 4** validators to support the new
//! version. The test follows that natural threshold rather than overriding
//! the buffer.
//!
//! Nodes boot at epoch 1. The expected progression for `n=4`:
//!
//! | End-of-epoch vote | v6 supporters | Vote outcome      | Next epoch starts at |
//! |-------------------|---------------|-------------------|----------------------|
//! | 1                 | 1 / 4         | threshold not met | v5                   |
//! | 2                 | 2 / 4         | threshold not met | v5                   |
//! | 3                 | 4 / 4         | **threshold met** | **v6**               |
//! | 4                 | 4 / 4         | already at MAX    | v6                   |
//!
//! Between epochs we "upgrade" another validator (or pair of validators) in
//! place — stop the node, mutate its `NodeConfig.supported_protocol_versions`,
//! restart — so the capability notification the restarted node re-submits
//! carries the new max. This is what
//! `IkaTestCluster::upgrade_validator_supported_protocol_versions` does.
//!
//! Waiting for epoch 5 (one full reconfiguration past the version transition)
//! is what confirms the network operates correctly at *both* versions: epoch
//! 3 → 4's reconfiguration is the cross-basis boundary itself (assembled
//! under BLS names, entered under consensus-key names), and epoch 4 → 5's
//! runs entirely under v6 — every name, handoff signature, and cert
//! verification in the consensus-key basis.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": we exercise coordination + real parallel cryptography, not the kind
//! of scheduling determinism that justifies `#[sim_test]`.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;

const GENESIS_VERSION: u64 = 5;

#[tokio::test(flavor = "multi_thread")]
async fn test_protocol_version_gradual_upgrade_v5_to_v6() {
    telemetry_subscribers::init_for_testing();

    let v5_only = SupportedProtocolVersions::new_for_testing(GENESIS_VERSION, GENESIS_VERSION);
    let v5_to_max =
        SupportedProtocolVersions::new_for_testing(GENESIS_VERSION, ProtocolVersion::MAX.as_u64());

    // validator[0] supports v6 from genesis; the other three are pinned at v5.
    // 20s epochs (not the 10s some cluster tests use): each upgrade is a
    // stop-mutate-restart that must complete — including the restarted node
    // re-submitting its capability notification — within the epoch whose
    // end-of-epoch vote the progression table charges it to, or every
    // subsequent assertion slips an epoch.
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::new(GENESIS_VERSION))
        .with_per_validator_supported_protocol_versions(vec![
            v5_to_max, // validator[0]: supports v5 and v6
            v5_only,   // validator[1]: v5 only
            v5_only,   // validator[2]: v5 only
            v5_only,   // validator[3]: v5 only
        ])
        .build()
        .await
        .expect("ika test cluster failed to boot");

    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "cluster should boot at protocol v5",
    );

    // Drive epoch 1 -> 2. The capability vote sees 1/4 supporting v6 — well
    // below the 4/4 effective threshold — so epoch 2 starts at v5.
    cluster.wait_for_epoch(2).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "with only 1/4 supporting v6, epoch 2 should remain at v5",
    );

    // Upgrade validator[1] to support v6. On restart it re-runs the current
    // epoch's start logic and re-submits its capability notification with the
    // new range, so the vote at the end of THIS epoch already counts it.
    cluster
        .upgrade_validator_supported_protocol_versions(1, v5_to_max)
        .await
        .expect("upgrading validator[1] failed");

    // Drive epoch 2 -> 3. Capability vote: 2/4 — still below the threshold — v5.
    cluster.wait_for_epoch(3).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "with 2/4 supporting v6, epoch 3 should remain at v5",
    );

    // Upgrade validators[2] and [3] together. Now 4/4 support v6 — the full
    // effective threshold (`quorum + ceil(f * 5000/10000) = 4` for n=4) is
    // met. Upgrade them sequentially; the network keeps a 3-of-4 active
    // quorum while either is briefly restarting.
    cluster
        .upgrade_validator_supported_protocol_versions(2, v5_to_max)
        .await
        .expect("upgrading validator[2] failed");
    cluster
        .upgrade_validator_supported_protocol_versions(3, v5_to_max)
        .await
        .expect("upgrading validator[3] failed");

    // Drive epoch 3 -> 4. Capability vote: 4/4 — threshold met — v6. This
    // boundary is the cross-basis reconfiguration: the epoch-4 committee was
    // assembled during epoch 3 under BLS-key names and is rebuilt by epoch 4
    // under consensus-key names.
    cluster.wait_for_epoch(4).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "with 4/4 supporting v6 at end-of-epoch-3, epoch 4 should advance to v6",
    );

    // Drive epoch 4 -> 5. This is the first reconfiguration that runs
    // entirely under v6's rules — consensus-key AuthorityNames end to end —
    // confirming the network operates correctly at the new version (and not
    // just that it can vote into it). v6 is the current MAX, so no further
    // version change is possible.
    cluster.wait_for_epoch(5).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "epoch 5 should stay at v6 (the network just completed a full \
         reconfiguration under v6's rules)",
    );
}
