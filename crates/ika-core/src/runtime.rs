// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_config::NodeConfig;
use ika_config::node::NodeMode;
use ika_protocol_config::Chain;
use ika_types::digests::ChainIdentifier;
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
/// notifiers don't do MPC computations), and the IKA network is testnet or
/// mainnet — derived from the deployed ika system object's `ChainIdentifier`
/// (NOT the Sui settlement chain: an ika devnet/localnet deployed on Sui
/// testnet must not enforce). Anything else maps to `Chain::Unknown` and runs
/// on ordinary dev hosts.
fn should_enforce_minimum_cpu(
    feature_enabled: bool,
    node_mode: NodeMode,
    ika_chain: Chain,
) -> bool {
    feature_enabled
        && node_mode.is_validator()
        && matches!(ika_chain, Chain::Mainnet | Chain::Testnet)
}

/// A binary compiled with the INSECURE `dwallet-mpc-unsafe-mock` feature
/// (deterministic mock crypto for fast tests) must never join a real
/// network, regardless of role: mocked MPC neither interoperates with real
/// validators nor produces real signatures. Derived from the deployed ika
/// system object's `ChainIdentifier`, same as the minimum-CPU gate above.
fn mock_crypto_forbidden_on(ika_chain: Chain) -> bool {
    matches!(ika_chain, Chain::Mainnet | Chain::Testnet)
}

impl IkaRuntimes {
    pub fn new(config: &NodeConfig, node_mode: NodeMode) -> Self {
        let ika_chain =
            ChainIdentifier::from(config.sui_connector_config.ika_system_object_id).chain();
        if cfg!(feature = "dwallet-mpc-unsafe-mock") {
            assert!(
                !mock_crypto_forbidden_on(ika_chain),
                "this binary was built with dwallet-mpc-unsafe-mock (INSECURE deterministic \
                 mock crypto for tests) and refuses to run against the ika {ika_chain:?} network"
            );
            // Loud, grep-able marker so a mocked binary can never be mistaken
            // for a real-crypto one in logs or test evidence.
            error!(
                insecure_mock_crypto = true,
                "running with dwallet-mpc-unsafe-mock: all dwallet MPC crypto is MOCKED and INSECURE — test builds only"
            );
        }
        let enforce =
            should_enforce_minimum_cpu(cfg!(feature = "enforce-minimum-cpu"), node_mode, ika_chain);
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
    use sui_types::base_types::ObjectID;

    #[test]
    fn enforced_only_for_validator_on_ika_testnet_or_mainnet() {
        for chain in [Chain::Mainnet, Chain::Testnet] {
            assert!(should_enforce_minimum_cpu(true, NodeMode::Validator, chain));
        }
        for chain in [Chain::Devnet, Chain::Unknown] {
            assert!(!should_enforce_minimum_cpu(
                true,
                NodeMode::Validator,
                chain
            ));
        }
        for mode in [NodeMode::Fullnode, NodeMode::Notifier] {
            assert!(!should_enforce_minimum_cpu(true, mode, Chain::Mainnet));
        }
    }

    #[test]
    fn never_enforced_without_the_feature() {
        assert!(!should_enforce_minimum_cpu(
            false,
            NodeMode::Validator,
            Chain::Mainnet
        ));
    }

    /// The gate reads the IKA network from the deployed ika system object id,
    /// not the Sui settlement chain: an unknown (e.g. localnet) system object
    /// maps to `Chain::Unknown` and must not enforce.
    #[test]
    fn unknown_ika_system_object_maps_to_unknown_chain() {
        assert_eq!(
            ChainIdentifier::from(ObjectID::ZERO).chain(),
            Chain::Unknown
        );
    }

    #[test]
    fn mock_crypto_forbidden_exactly_on_real_networks() {
        for chain in [Chain::Mainnet, Chain::Testnet] {
            assert!(mock_crypto_forbidden_on(chain));
        }
        for chain in [Chain::Devnet, Chain::Unknown] {
            assert!(!mock_crypto_forbidden_on(chain));
        }
    }
}
