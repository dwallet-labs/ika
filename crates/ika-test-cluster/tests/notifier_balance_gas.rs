// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! End-to-end SIP-58 address-balance gas on the writer path.
//!
//! The notifier's funding arrives as ordinary coin objects, so this drives the
//! address-balance contract for real against a live Sui localnet running at
//! max protocol version (address-balance gas enabled):
//!
//! - boot: chain-identifier resolution, funds read, the automatic migration
//!   sweep of coin objects into the address balance, and the balance
//!   preflight — a failure in any of them aborts the notifier's boot and the
//!   cluster build fails;
//! - steady state: every dwallet/system checkpoint submission and every
//!   epoch-switch call (`process_mid_epoch`, pricing, session lock,
//!   `advance_epoch`) is an empty-gas-payment `ValidDuring` transaction paid
//!   from the address balance — epochs closing AT ALL is therefore the
//!   proof that balance-gas submission works end to end (there is no other
//!   writer and no gas-coin fallback in this mode);
//! - the checkpoint fee reimbursement takes the balance-mode branch
//!   (transfer to the writer address) on every dwallet checkpoint.
//!
//! Two closes are required so at least one full epoch cycle (mid-epoch →
//! pricing → lock → advance + checkpoints) runs on balance gas beyond the
//! boot-adjacent first close.
//!
//! `#[tokio::test(flavor = "multi_thread")]` per CLAUDE.md "Picking a test
//! type": real chain, real crypto at the epoch boundaries.

use ika_test_cluster::IkaTestClusterBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn epochs_close_with_notifier_on_address_balance_gas() {
    telemetry_subscribers::init_for_testing();

    let cluster = IkaTestClusterBuilder::new()
        .with_num_validators(4)
        .with_epoch_duration_ms(30_000)
        .build()
        .await
        .expect(
            "cluster failed to boot with address-balance gas enabled — chain-id resolution, \
             funds read, migration sweep, or balance preflight failed on the notifier",
        );

    // Two full closes on balance gas. Every write the close depends on is an
    // empty-gas-payment ValidDuring transaction; there is nothing else that
    // can advance the epoch.
    cluster.wait_for_epoch(2).await;

    // The funds gauge is only written in balance mode, seeded from the
    // swept-in address balance: positive means the sweep funded the balance
    // and the writer is metering it.
    let notifier = cluster
        .swarm
        .fullnodes()
        .next()
        .expect("swarm runs exactly one notifier fullnode");
    let notifier_handle = notifier.get_node_handle().expect("notifier is running");
    let address_balance_gauge: f64 = notifier_handle.with(|node| {
        node.registry_service_for_testing()
            .default_registry()
            .gather()
            .iter()
            .filter(|family| family.name() == "ika_sui_connector_gas_coin_balance")
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_gauge().value())
            .fold(0.0f64, f64::max)
    });
    assert!(
        address_balance_gauge > 0.0,
        "address-balance funds gauge is zero after two closes on balance gas — \
         the sweep/preflight path did not fund or meter the balance"
    );
}
