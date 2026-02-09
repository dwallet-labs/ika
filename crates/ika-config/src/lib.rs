// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub mod initiation;
pub mod local_ip_utils;
pub mod node;
pub mod node_config_metrics;
pub mod p2p;
pub mod validator_info;

pub use node::{ConsensusConfig, NodeConfig, NodeMode};
pub use sui_config::object_storage_config;
pub use sui_config::{Config, PersistedConfig};
use sui_types::multiaddr::Multiaddr;

const IKA_DIR: &str = ".ika";
pub const IKA_CONFIG_DIR: &str = "ika_config";
pub const IKA_NETWORK_CONFIG: &str = "network.yaml";
pub const IKA_FULLNODE_CONFIG: &str = "fullnode.yaml";
pub const IKA_CLIENT_CONFIG: &str = "client.yaml";
pub const IKA_SUI_CONFIG: &str = "ika_sui_config.yaml";
pub const IKA_KEYSTORE_FILENAME: &str = "ika.keystore";
pub const IKA_KEYSTORE_ALIASES_FILENAME: &str = "ika.aliases";
pub const IKA_BENCHMARK_GENESIS_GAS_KEYSTORE_FILENAME: &str = "benchmark.keystore";
pub const IKA_GENESIS_FILENAME: &str = "genesis.blob";
pub const IKA_DEV_NET_URL: &str = "https://fullnode.devnet.ika.io:443";

pub const AUTHORITIES_DB_NAME: &str = "authorities_db";
pub const CONSENSUS_DB_NAME: &str = "consensus_db";
pub const FULL_NODE_DB_PATH: &str = "full_node_db";

pub fn ika_config_dir() -> Result<PathBuf, anyhow::Error> {
    match std::env::var_os("IKA_CONFIG_DIR") {
        Some(config_env) => Ok(config_env.into()),
        None => match dirs::home_dir() {
            Some(v) => Ok(v.join(IKA_DIR).join(IKA_CONFIG_DIR)),
            None => anyhow::bail!("Cannot obtain home directory path"),
        },
    }
    .and_then(|dir| {
        if !dir.exists() {
            fs::create_dir_all(dir.clone())?;
        }
        Ok(dir)
    })
}

/// Check if the network config blob exists in the given directory or the default directory.
pub fn network_config_exists(config_dir: Option<PathBuf>) -> bool {
    if let Some(dir) = config_dir {
        dir.join(IKA_NETWORK_CONFIG).exists()
    } else if let Some(config_env) = std::env::var_os("IKA_CONFIG_DIR") {
        Path::new(&config_env).join(IKA_NETWORK_CONFIG).exists()
    } else if let Some(home) = dirs::home_dir() {
        let mut config = PathBuf::new();
        config.push(&home);
        config.extend([IKA_DIR, IKA_CONFIG_DIR, IKA_NETWORK_CONFIG]);
        config.exists()
    } else {
        false
    }
}

pub fn validator_config_file(address: Multiaddr, i: usize) -> String {
    multiaddr_to_filename(address).unwrap_or(format!("validator-config-{i}.yaml"))
}

pub fn ssfn_config_file(address: Multiaddr, i: usize) -> String {
    multiaddr_to_filename(address).unwrap_or(format!("ssfn-config-{i}.yaml"))
}

fn multiaddr_to_filename(address: Multiaddr) -> Option<String> {
    if let Some(hostname) = address.hostname()
        && let Some(port) = address.port()
    {
        return Some(format!("{hostname}-{port}.yaml"));
    }
    None
}
