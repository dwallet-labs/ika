// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{IntCounterVec, Registry, register_int_counter_vec_with_registry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide counter for chain-side calls to
/// `get_network_encryption_key_with_full_data_by_epoch`. Test
/// suites that need to assert the off-chain pipeline isn't
/// silently re-reading the heavy DKG / reconfig output blobs from
/// chain inspect this counter directly. Production code uses the
/// per-`SuiClient` Prometheus counter on `SuiClientMetrics`.
pub static CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA: AtomicU64 = AtomicU64::new(0);

/// Process-wide counter for chain-side calls to
/// `get_mpc_data_from_validators_pool`. Mirrors the rationale of
/// [`CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA`] for the validator
/// mpc_data fallback path.
pub static CHAIN_BLOB_READ_MPC_DATA_FROM_VALIDATORS_POOL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of both process-wide counters. Used by the off-chain
/// cluster test to capture a baseline before exercising the
/// scenario and re-check after.
pub fn chain_blob_read_counts() -> (u64, u64) {
    (
        CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA.load(Ordering::Relaxed),
        CHAIN_BLOB_READ_MPC_DATA_FROM_VALIDATORS_POOL.load(Ordering::Relaxed),
    )
}

#[derive(Clone, Debug)]
pub struct SuiClientMetrics {
    pub sui_rpc_errors: IntCounterVec,
    /// Counts on-chain reads of the heavy blob fields backed by
    /// `mpc_data` / network-key / reconfig outputs. Each label is the
    /// name of a method that performs a chain-side blob fetch. Used by
    /// the off-chain validator-metadata test path to assert that the
    /// off-chain pipeline genuinely sources these blobs from
    /// consensus + P2P rather than re-reading them from chain.
    pub chain_blob_reads: IntCounterVec,
}

impl SuiClientMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            sui_rpc_errors: register_int_counter_vec_with_registry!(
                "sui_client_sui_rpc_errors",
                "Total number of errors from sui RPC, by RPC method",
                &["method"],
                registry,
            )
            .unwrap(),
            chain_blob_reads: register_int_counter_vec_with_registry!(
                "sui_client_chain_blob_reads",
                "Total chain-side blob reads (mpc_data, network DKG output, reconfig output)",
                &["method"],
                registry,
            )
            .unwrap(),
        };
        Arc::new(this)
    }

    pub fn new_for_testing() -> Arc<Self> {
        let registry = Registry::new();
        Self::new(&registry)
    }
}
