// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Manual integration test against a running Sui localnet at `127.0.0.1:9000`.
//!
//! Run with:
//!   `cargo test -p ika-sui-client --test anchor_localnet -- --ignored --nocapture`
//!
//! Requires Sui localnet running. Default ports.

use ika_sui_client::anchor::{fetch_genesis_committee, fetch_last_eoe_checkpoint_digest};

#[tokio::test]
#[ignore]
async fn fetch_anchor_from_localnet() {
    let url = "http://127.0.0.1:9000";
    match fetch_last_eoe_checkpoint_digest(url).await {
        Ok(digest) => println!("last_eoe_checkpoint_digest = {digest}"),
        Err(e) => {
            println!("no end-of-epoch yet ({e}); falling back to genesis committee");
            let committee = fetch_genesis_committee(url)
                .await
                .expect("localnet must serve genesis committee");
            println!(
                "genesis committee: epoch={} size={}",
                committee.epoch,
                committee.num_members()
            );
        }
    }
}
