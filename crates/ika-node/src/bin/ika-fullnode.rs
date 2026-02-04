// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Ika Fullnode binary - runs as a fullnode.
//!
//! A fullnode syncs state via P2P but doesn't participate in consensus.
//! This binary requires:
//! - `consensus_config` to NOT be set in the NodeConfig
//! - `notifier_client_key_pair` to NOT be set in SuiConnectorConfig
//!
//! For other node types, use:
//! - `ika-validator`: For validator nodes (consensus participation)
//! - `ika-notifier`: For notifier nodes (submits checkpoints to Sui)
//! - `ika-node`: Auto-detects mode from configuration

use ika_node::NodeMode;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

fn main() {
    // Run as fullnode with explicit mode validation
    ika_node::run_node(Some(NodeMode::Fullnode), VERSION);
}
