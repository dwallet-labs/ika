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
    // Run as validator with explicit mode validation
    ika_node::run_node(Some(NodeMode::Validator), VERSION);
}
