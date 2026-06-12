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

// Compiled-in jemalloc as the global allocator (mirrors sui-node):
// better fragmentation behavior than glibc malloc for long-running
// RocksDB-heavy processes, and arch-independent.
#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[global_allocator]
static JEMALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use ika_node::NodeMode;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

fn main() {
    // Run as fullnode with explicit mode validation
    ika_node::run_node(Some(NodeMode::Fullnode), VERSION);
}
