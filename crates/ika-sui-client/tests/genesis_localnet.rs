// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Manual integration test against a running Sui localnet at `127.0.0.1:9000`.
//!
//! Run with:
//!   `cargo test -p ika-sui-client --test genesis_localnet -- --ignored --nocapture`
//!
//! Requires Sui localnet running. Default ports.

use ika_config::node::SuiChainIdentifier;
use ika_sui_client::genesis::{fetch_genesis_blob, load_and_verify_sui_genesis};

/// The reconstructed blob must round-trip through the node's own verifying
/// loader: serialize it, load it as a `Custom`-chain genesis, and get a
/// non-empty committee[0] out — proving gRPC reconstruction produces a blob
/// the summary→contents→effects→objects binding accepts.
#[tokio::test]
#[ignore]
async fn fetched_genesis_blob_passes_the_verifying_loader() {
    let url = "http://127.0.0.1:9000";
    let genesis = fetch_genesis_blob(url)
        .await
        .expect("localnet must serve its genesis checkpoint");
    let path =
        std::env::temp_dir().join(format!("ika_genesis_localnet_{}.blob", std::process::id()));
    std::fs::write(
        &path,
        bcs::to_bytes(&genesis).expect("serialize genesis blob"),
    )
    .expect("write genesis blob");
    let boot = load_and_verify_sui_genesis(&path, SuiChainIdentifier::Custom)
        .expect("reconstructed blob must pass the verifying loader");
    let _ = std::fs::remove_file(&path);
    println!(
        "genesis committee: epoch={} size={} chain={}",
        boot.committee.epoch,
        boot.committee.num_members(),
        boot.chain_identifier.base58_encode(),
    );
}
