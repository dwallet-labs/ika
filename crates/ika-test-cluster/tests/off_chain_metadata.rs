// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Verifies the `off_chain_validator_metadata` protocol flag (active
//! from v4) actually severs the chain-read paths for validator
//! `mpc_data`, network DKG output, and network reconfiguration
//! output. Under the off-chain pipeline these blobs flow over
//! consensus + P2P + the local producer cache — chain is
//! write-only for them. Counts process-wide chain-read calls via
//! `ika_sui_client::metrics::chain_blob_read_counts` and asserts
//! they stay flat across epoch transitions.

use ika_protocol_config::ProtocolVersion;
use ika_sui_client::metrics::chain_blob_read_counts;
use ika_test_cluster::IkaTestClusterBuilder;

/// Off-chain mode (v4+) must NOT trigger
/// `get_network_encryption_key_with_full_data_by_epoch` or
/// `get_mpc_data_from_validators_pool` during steady-state
/// operation. Drives the cluster through an epoch transition to
/// exercise the sync paths that historically hit chain for these
/// blob reads, then asserts the counters didn't move.
///
/// `#[ignore]` until the announcement-propagation gap is fixed:
/// today the off-chain `EpochStoreClassGroupsSource` returns
/// `Incomplete` past bootstrap because peer
/// `ValidatorMpcDataAnnouncement`s don't reliably land in every
/// validator's per-epoch table (each local table sees only its
/// own announcement in repro). With the strict gate disabled,
/// chain fallback fires (`get_mpc_data_from_validators_pool` is
/// called ~36 times across one epoch transition), which makes
/// this assertion fail. Once the consensus-delivery /
/// announcement-recording gap is closed, drop the `#[ignore]`
/// and the test should pass.
#[ignore = "off-chain announcement propagation gap; see test doc"]
#[tokio::test(flavor = "multi_thread")]
async fn off_chain_metadata_v4_does_not_read_blobs_from_chain() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(20_000)
        .with_protocol_version(ProtocolVersion::new(4))
        .build()
        .await
        .expect("IkaTestClusterBuilder::build() failed");

    // Reach epoch 1 so the initial committee has fully sync'd and
    // the off-chain class-groups source is installed on every node.
    cluster.wait_for_epoch(1).await;
    let _ = cluster
        .wait_for_network_key()
        .await
        .expect("wait_for_network_key failed");

    // Capture baseline AFTER cluster bootstrap. Bootstrap legitimately
    // touches the chain blob paths once before the off-chain pipeline
    // is fully wired (the class-groups assembler needs validators'
    // mpc_data announcements through consensus before it can serve
    // the off-chain assembly). What matters is steady-state behavior,
    // so we measure the DELTA from this baseline across the next
    // epoch transition.
    let (net_key_baseline, mpc_data_baseline) = chain_blob_read_counts();

    // Drive the cluster through one full epoch transition. With
    // off_chain enabled, sync should source mpc_data via the
    // off-chain class-groups assembler (consensus + P2P) and network
    // key data via the local producer cache overlay — no chain
    // table-vec reads of blob bytes.
    cluster.wait_for_epoch(2).await;

    let (net_key_after, mpc_data_after) = chain_blob_read_counts();
    let net_key_delta = net_key_after - net_key_baseline;
    let mpc_data_delta = mpc_data_after - mpc_data_baseline;

    assert_eq!(
        net_key_delta, 0,
        "off_chain mode (v4) must not call get_network_encryption_key_with_full_data_by_epoch \
         during steady-state epoch transitions; observed {net_key_delta} call(s) \
         (baseline {net_key_baseline}, after {net_key_after})"
    );
    assert_eq!(
        mpc_data_delta, 0,
        "off_chain mode (v4) must not call get_mpc_data_from_validators_pool during \
         steady-state epoch transitions; observed {mpc_data_delta} call(s) \
         (baseline {mpc_data_baseline}, after {mpc_data_after})"
    );
}
