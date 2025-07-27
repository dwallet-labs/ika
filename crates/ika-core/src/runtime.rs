// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_config::NodeConfig;
use tokio::runtime::Runtime;
use tracing::error;

pub struct IkaRuntimes {
    // Order in this struct is the order in which runtimes are stopped.
    pub ika_node: Runtime,
    pub metrics: Runtime,
}

const SIXTEEN_MEGA_BYTES: usize = 16 * 1024 * 1024;

impl IkaRuntimes {
    pub fn new(_config: &NodeConfig) -> Self {
        let mut builder = rayon::ThreadPoolBuilder::new()
            .panic_handler(|err| error!("Rayon thread pool task panicked: {:?}", err))
            .stack_size(SIXTEEN_MEGA_BYTES);
        if cfg!(feature = "enforce-minimum-cpu") {
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
        if cfg!(feature = "enforce-minimum-cpu") {
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
