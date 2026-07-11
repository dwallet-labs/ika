// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_config::NodeConfig;
use ika_config::node::{NodeMode, SuiChainIdentifier};
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tracing::error;

pub struct IkaRuntimes {
    // Order in this struct is the order in which runtimes are stopped.
    pub ika_node: Runtime,
    pub metrics: Runtime,
}

const SIXTEEN_MEGA_BYTES: usize = 16 * 1024 * 1024;

/// Whether this process enforces the minimum-CPU requirement, decided once in
/// `IkaRuntimes::new`. Read later by `calculate_num_of_computations_cores`
/// (the MPC orchestrator calls it after startup); unset — e.g. in tests that
/// never build the runtimes — means no enforcement.
static ENFORCE_MINIMUM_CPU: OnceLock<bool> = OnceLock::new();

/// The minimum-CPU requirement applies only when ALL hold: the
/// `enforce-minimum-cpu` feature is compiled in (dropped by test builds via
/// `--no-default-features`), the node runs as a validator (fullnodes and
/// notifiers don't do MPC computations), and the network is testnet or
/// mainnet (localnets/devnets run on ordinary dev hosts).
fn should_enforce_minimum_cpu(
    feature_enabled: bool,
    node_mode: NodeMode,
    chain: SuiChainIdentifier,
) -> bool {
    feature_enabled
        && node_mode.is_validator()
        && matches!(
            chain,
            SuiChainIdentifier::Mainnet | SuiChainIdentifier::Testnet
        )
}

impl IkaRuntimes {
    pub fn new(config: &NodeConfig, node_mode: NodeMode) -> Self {
        let enforce = should_enforce_minimum_cpu(
            cfg!(feature = "enforce-minimum-cpu"),
            node_mode,
            config.sui_connector_config.sui_chain_identifier,
        );
        let _ = ENFORCE_MINIMUM_CPU.set(enforce);
        let mut builder = rayon::ThreadPoolBuilder::new()
            .panic_handler(|err| error!("Rayon thread pool task panicked: {:?}", err))
            .stack_size(SIXTEEN_MEGA_BYTES);
        if enforce {
            // When passing 0, Rayon will use the default number of threads, which is the number of available cores
            // on the machine
            builder = builder.num_threads(Self::calculate_num_of_computations_cores());
        }

        if let Err(err) = builder.build_global() {
            error!(error=?err, "failed to create rayon thread pool");
            panic!("Failed to create rayon thread pool");
        }
        let ika_node = tokio::runtime::Builder::new_multi_thread()
            .thread_name("ika-node-runtime")
            .thread_stack_size(SIXTEEN_MEGA_BYTES)
            .enable_all()
            .build()
            .expect("Failed to create ika-node runtime");
        let metrics = tokio::runtime::Builder::new_multi_thread()
            .thread_name("metrics-runtime")
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create metrics runtime");

        Self { ika_node, metrics }
    }

    pub(crate) fn calculate_num_of_computations_cores() -> usize {
        let Ok(total_cores_available) = std::thread::available_parallelism() else {
            error!("failed to get available parallelism, using default value");
            return 0;
        };
        let total_cores_available: usize = total_cores_available.into();
        if ENFORCE_MINIMUM_CPU.get().copied().unwrap_or(false) {
            assert!(
                total_cores_available >= 16,
                "Validator must have at least 16 CPU cores"
            );
            total_cores_available - TOKIO_ALLOCATED_CORES
        } else {
            total_cores_available
        }
    }
}

/// Number of cores unavailable to cryptographic computation, reserved solely for `tokio` i.e. consensus and network services use.
pub const TOKIO_ALLOCATED_CORES: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforced_only_for_validator_on_testnet_or_mainnet() {
        for chain in [SuiChainIdentifier::Mainnet, SuiChainIdentifier::Testnet] {
            assert!(should_enforce_minimum_cpu(true, NodeMode::Validator, chain));
        }
        for chain in [SuiChainIdentifier::Devnet, SuiChainIdentifier::Custom] {
            assert!(!should_enforce_minimum_cpu(
                true,
                NodeMode::Validator,
                chain
            ));
        }
        for mode in [NodeMode::Fullnode, NodeMode::Notifier] {
            assert!(!should_enforce_minimum_cpu(
                true,
                mode,
                SuiChainIdentifier::Mainnet
            ));
        }
    }

    #[test]
    fn never_enforced_without_the_feature() {
        assert!(!should_enforce_minimum_cpu(
            false,
            NodeMode::Validator,
            SuiChainIdentifier::Mainnet
        ));
    }
}
