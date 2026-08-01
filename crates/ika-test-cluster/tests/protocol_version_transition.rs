// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Gradual protocol-version transition (v6 → v7) across multiple epochs.
//!
//! Models a real rolling upgrade: the network boots at protocol v6 with one
//! validator supporting `6..=MAX` and the other three pinned at `6..=6`. The
//! end-of-epoch capability quorum vote
//! (`choose_highest_protocol_version_and_move_contracts_upgrades_v1`) needs
//! enough stake to support a higher version before `SetNextConfigVersion`
//! fires.
//!
//! v6 → v7 is the boundary where `AuthorityName` stops being serialized as
//! the Ed25519 consensus key zero-padded into a 48-byte container and starts
//! being serialized as the raw 32 bytes (`short_authority_names`). That flip
//! is consensus-critical for a reason no decode tolerance can fix: signature
//! and digest bytes are reconstructed by RE-SERIALIZING locally, so two
//! validators emitting different widths compute different
//! `next_committee_pubkey_set_hash` values and reject each other's handoff
//! signatures. What must survive the boundary:
//!
//! - the capability vote itself — `AuthorityCapabilitiesV1.authority` is a
//!   name, so the very messages that carry the network across the boundary
//!   change width as they cross it;
//! - the handoff cert, which is signed at the END of epoch N under the old
//!   width and verified in N+1 under the new one (the dual-width retry in
//!   `verify_certified_handoff_attestation` exists for exactly this);
//! - the ten MPC consensus message types that embed a name and must reach
//!   byte-identical quorum.
//!
//! This is the in-process counterpart of the out-of-process
//! `v127_v7_upgrade` rehearsal (`crates/ika-upgrade-test`): that one swaps
//! REAL old-release binaries and gates deployed-release compatibility; this
//! one runs a single binary with per-validator pinned advertised ranges,
//! gating the capability-vote machinery and the in-process transition —
//! including the epoch-boundary restart/rebuild paths the out-of-process
//! harness does not exercise.
//!
//! CAVEAT specific to this boundary: the emitted width is process-wide state
//! (`AUTHORITY_NAME_SHORT_ENCODING`), and this test runs every validator in
//! ONE process. All four therefore flip together the moment any of them
//! builds an epoch store for the new version, which is more synchronised than
//! a real fleet. It still gates the vote arithmetic and the cross-epoch
//! handoff path; the genuinely independent per-validator flip is what the
//! out-of-process rehearsal covers.
//!
//! (The v5 → v6 flavor of this test was retired when MIN moved to 6 and left
//! no boundary to cross; this resurrects it retargeted at the v7 boundary.)
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
//! | End-of-epoch vote | v7 supporters | Vote outcome      | Next epoch starts at |
//! |-------------------|---------------|-------------------|----------------------|
//! | 1                 | 1 / 4         | threshold not met | v6                   |
//! | 2                 | 2 / 4         | threshold not met | v6                   |
//! | 3                 | 4 / 4         | **threshold met** | **v7**               |
//! | 4                 | 4 / 4         | already at MAX    | v7                   |
//!
//! Between epochs we "upgrade" another validator (or pair of validators) in
//! place — stop the node, mutate its `NodeConfig.supported_protocol_versions`,
//! restart — so the capability notification the restarted node re-submits
//! carries the new max. This is what
//! `IkaTestCluster::upgrade_validator_supported_protocol_versions` does.
//!
//! Waiting for epoch 5 (one full reconfiguration past the version transition)
//! is what confirms the network operates correctly at *both* versions: epoch
//! 3 → 4's reconfiguration is the width boundary itself (the handoff cert
//! signed under the padded encoding, verified under the short one), and epoch
//! 4 → 5's runs entirely under v7 — every name, handoff signature and cert
//! verification at the 32-byte encoding.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": we exercise coordination + real parallel cryptography, not the kind
//! of scheduling determinism that justifies `#[sim_test]`.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;

const GENESIS_VERSION: u64 = 6;

#[tokio::test(flavor = "multi_thread")]
async fn test_protocol_version_gradual_upgrade_v6_to_v7() {
    telemetry_subscribers::init_for_testing();

    let v6_only = SupportedProtocolVersions::new_for_testing(GENESIS_VERSION, GENESIS_VERSION);
    let v6_to_max =
        SupportedProtocolVersions::new_for_testing(GENESIS_VERSION, ProtocolVersion::MAX.as_u64());

    // validator[0] supports v7 from genesis; the other three are pinned at v6.
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
            v6_to_max, // validator[0]: supports v6 and v7
            v6_only,   // validator[1]: v6 only
            v6_only,   // validator[2]: v6 only
            v6_only,   // validator[3]: v6 only
        ])
        .build()
        .await
        .expect("ika test cluster failed to boot");

    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "cluster should boot at protocol v6",
    );

    // Drive epoch 1 -> 2. The capability vote sees 1/4 supporting v7 — well
    // below the 4/4 effective threshold — so epoch 2 starts at v6.
    cluster.wait_for_epoch(2).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "with only 1/4 supporting v7, epoch 2 should remain at v6",
    );

    // Upgrade validator[1] to support v7. On restart it re-runs the current
    // epoch's start logic and re-submits its capability notification with the
    // new range, so the vote at the end of THIS epoch already counts it.
    cluster
        .upgrade_validator_supported_protocol_versions(1, v6_to_max)
        .await
        .expect("upgrading validator[1] failed");

    // Drive epoch 2 -> 3. Capability vote: 2/4 — still below the threshold — v6.
    cluster.wait_for_epoch(3).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::new(GENESIS_VERSION),
        "with 2/4 supporting v7, epoch 3 should remain at v6",
    );

    // Upgrade validators[2] and [3] together. Now 4/4 support v7 — the full
    // effective threshold (`quorum + ceil(f * 5000/10000) = 4` for n=4) is
    // met. Upgrade them sequentially; the network keeps a 3-of-4 active
    // quorum while either is briefly restarting.
    cluster
        .upgrade_validator_supported_protocol_versions(2, v6_to_max)
        .await
        .expect("upgrading validator[2] failed");
    cluster
        .upgrade_validator_supported_protocol_versions(3, v6_to_max)
        .await
        .expect("upgrading validator[3] failed");

    // Drive epoch 3 -> 4. Capability vote: 4/4 — threshold met — v7. This
    // boundary is the encoding-width flip: epoch 3's handoff cert was signed
    // with names padded to 48 bytes and is verified by epoch 4, which emits
    // them as the raw 32.
    cluster.wait_for_epoch(4).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "with 4/4 supporting v7 at end-of-epoch-3, epoch 4 should advance to v7",
    );

    // Drive epoch 4 -> 5. This is the first reconfiguration that runs
    // entirely under v7's rules — 32-byte AuthorityNames end to end —
    // confirming the network operates correctly at the new version (and not
    // just that it can vote into it). v7 is the current MAX, so no further
    // version change is possible.
    cluster.wait_for_epoch(5).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "epoch 5 should stay at v7 (the network just completed a full \
         reconfiguration under v7's rules)",
    );
}
