// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Ika Notifier binary - runs as a notifier node.
//!
//! A notifier submits certified checkpoints to the Sui chain.
//! This binary requires:
//! - `notifier_client_key_pair` to be set in SuiConnectorConfig
//! - `consensus_config` to NOT be set (notifiers don't participate in consensus)
//!
//! For other node types, use:
//! - `ika-validator`: For validator nodes (consensus participation)
//! - `ika-fullnode`: For fullnode nodes (no consensus, no notifying)
//! - `ika-node`: Auto-detects mode from configuration

use ika_node::NodeMode;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

fn main() {
    // Run as notifier with explicit mode validation
    ika_node::run_node(Some(NodeMode::Notifier), VERSION);
}
