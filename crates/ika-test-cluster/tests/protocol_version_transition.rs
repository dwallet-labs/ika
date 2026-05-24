// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Gradual protocol-version transition (v3 → v4) across multiple epochs.
//!
//! Models a real rolling upgrade: the network boots at `ProtocolVersion::MIN`
//! (currently 3) with one validator supporting `MIN..=MAX` and the other three
//! pinned at `MIN..=MIN`. The end-of-epoch capability quorum vote
//! (`choose_highest_protocol_version_and_move_contracts_upgrades_v1`) needs
//! `2f+1 = 3` of `n=4` validators to support a higher version before
//! `SetNextConfigVersion` fires.
//!
//! Effective threshold note: ika inherits Sui's
//! `buffer_stake_for_protocol_upgrade_bps` (default 5000). For `n=4` (f=1,
//! quorum=3) the effective threshold is `quorum + ceil(f * 5000/10000) = 4`,
//! so a protocol upgrade requires **all 4** validators to support the new
//! version. The test follows that natural threshold rather than overriding
//! the buffer.
//!
//! The expected progression for `n=4`:
//!
//! | After epoch | v4 supporters | Vote outcome           | Next epoch starts at |
//! |-------------|---------------|------------------------|----------------------|
//! | 0           | 1 / 4         | threshold not met      | v3                   |
//! | 1           | 2 / 4         | threshold not met      | v3                   |
//! | 2           | 4 / 4         | **threshold met**      | **v4**               |
//! | 3           | 4 / 4         | already at MAX         | v4                   |
//!
//! Between epochs we "upgrade" another validator (or pair of validators) in
//! place — stop the node, mutate its `NodeConfig.supported_protocol_versions`,
//! restart — so the capability notification at the start of the next epoch
//! carries the new max. This is what
//! `IkaTestCluster::upgrade_validator_supported_protocol_versions` does.
//!
//! Waiting for epoch 4 (one full reconfiguration past the version transition)
//! is what confirms the network operates correctly at *both* versions: epoch
//! 2 → 3's reconfiguration runs entirely at v3, and epoch 3 → 4's runs
//! entirely at v4 (different `network_encryption_key_version`,
//! `reconfiguration_message_version`, plus the new feature flags).
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": we exercise coordination + real parallel cryptography, not the kind
//! of scheduling determinism that justifies `#[sim_test]`.

use ika_protocol_config::ProtocolVersion;
use ika_test_cluster::IkaTestClusterBuilder;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;

#[tokio::test(flavor = "multi_thread")]
async fn test_protocol_version_gradual_upgrade_v3_to_v4() {
    telemetry_subscribers::init_for_testing();

    let min_only = SupportedProtocolVersions::new_for_testing(
        ProtocolVersion::MIN.as_u64(),
        ProtocolVersion::MIN.as_u64(),
    );
    let min_to_max = SupportedProtocolVersions::SYSTEM_DEFAULT; // MIN..=MAX

    // validator[0] supports v4 from genesis; the other three are pinned at v3.
    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(10_000)
        .with_protocol_version(ProtocolVersion::MIN)
        .with_per_validator_supported_protocol_versions(vec![
            min_to_max, // validator[0]: supports v3 and v4
            min_only,   // validator[1]: v3 only
            min_only,   // validator[2]: v3 only
            min_only,   // validator[3]: v3 only
        ])
        .build()
        .await
        .expect("ika test cluster failed to boot");

    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MIN,
        "cluster should boot at ProtocolVersion::MIN",
    );

    // Drive epoch 0 -> 1. The capability vote sees 1/4 supporting v4 — well
    // below the 4/4 effective threshold — so epoch 1 starts at v3.
    cluster.test_cluster.trigger_reconfiguration().await;
    cluster.wait_for_epoch(1).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MIN,
        "with only 1/4 supporting v4, epoch 1 should remain at v3",
    );

    // Upgrade validator[1] to support v4. With the stop-mutate-start helper
    // it picks up the new range on restart and sends an updated capability
    // notification at the start of the next epoch it observes.
    cluster
        .upgrade_validator_supported_protocol_versions(1, min_to_max)
        .await
        .expect("upgrading validator[1] failed");

    // Drive epoch 1 -> 2. Capability vote: 2/4 — still below the threshold — v3.
    cluster.wait_for_epoch(2).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MIN,
        "with 2/4 supporting v4, epoch 2 should remain at v3",
    );

    // Upgrade validators[2] and [3] together. Now 4/4 support v4 — the full
    // effective threshold (`quorum + ceil(f * 5000/10000) = 4` for n=4) is
    // met. Upgrade them sequentially; the network keeps a 3-of-4 active
    // quorum while either is briefly restarting.
    cluster
        .upgrade_validator_supported_protocol_versions(2, min_to_max)
        .await
        .expect("upgrading validator[2] failed");
    cluster
        .upgrade_validator_supported_protocol_versions(3, min_to_max)
        .await
        .expect("upgrading validator[3] failed");

    // Drive epoch 2 -> 3. Capability vote: 4/4 — threshold met — v4.
    cluster.wait_for_epoch(3).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "with 4/4 supporting v4 at end-of-epoch-2, epoch 3 should advance to v4",
    );

    // Drive epoch 3 -> 4. This is the first reconfiguration that runs
    // entirely under v4's rules — confirming the network operates correctly
    // at the new version (and not just that it can vote into it). v4 is the
    // current MAX, so no further version change is possible.
    cluster.wait_for_epoch(4).await;
    assert_eq!(
        cluster.current_protocol_version(),
        ProtocolVersion::MAX,
        "epoch 4 should stay at v4 (the network just completed a full \
         reconfiguration under v4's rules)",
    );
}
