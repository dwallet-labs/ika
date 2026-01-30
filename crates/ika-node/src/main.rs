// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Ika Node binary - auto-detects mode from configuration.
//!
//! This binary automatically detects whether to run as a validator, fullnode, or notifier
//! based on the configuration file:
//! - Validator: when `consensus_config` is present
//! - Notifier: when `notifier_client_key_pair` is present in `sui_connector_config`
//! - Fullnode: when neither of the above are present
//!
//! For explicit mode selection, use the dedicated binaries:
//! - `ika-validator`: For validator nodes
//! - `ika-fullnode`: For fullnode nodes
//! - `ika-notifier`: For notifier nodes

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

fn main() {
    // Auto-detect mode from config
    ika_node::run_node(None, VERSION);
}
