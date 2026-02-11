// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Ika Validator binary - runs as a validator node.
//!
//! A validator participates in consensus and MPC operations.
//! This binary requires `consensus_config` to be set in the NodeConfig.
//!
//! For other node types, use:
//! - `ika-fullnode`: For fullnode nodes (no consensus participation)
//! - `ika-notifier`: For notifier nodes (submits checkpoints to Sui)
//! - `ika-node`: Auto-detects mode from configuration

use ika_node::NodeMode;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

fn main() {
    // Run as validator with explicit mode validation
    ika_node::run_node(Some(NodeMode::Validator), VERSION);
}
