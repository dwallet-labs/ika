// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use sui_config::PersistedConfig;
use sui_sdk::wallet_context::WalletContext;

#[macro_use]
pub mod ika_commands;
#[cfg(feature = "protocol-commands")]
pub(crate) mod protocol_commands;
pub(crate) mod validator_commands;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IkaPackagesConfigFile {
    pub envs: HashMap<String, IkaNetworkConfig>,
}

impl sui_config::Config for IkaPackagesConfigFile {}

pub(crate) fn read_ika_sui_config_yaml(
    context: &WalletContext,
    config_path: &PathBuf,
) -> Result<IkaNetworkConfig, anyhow::Error> {
    let config: IkaPackagesConfigFile = PersistedConfig::read(config_path).map_err(|err| {
        err.context(format!(
            "Cannot open Ika network config file at {config_path:?}"
        ))
    })?;
    let sui_env = context.get_active_env()?.alias.clone();
    let Some(config) = config.envs.get(&sui_env) else {
        println!(
            "Ika network config not found for Sui environment: {sui_env}, {:?}, {:?}, {:?}, {:?}",
            config_path,
            context.config.path(),
            context.config.envs,
            config.envs
        );
        return Err(anyhow::anyhow!(
            "Ika network config not found for Sui environment: {sui_env}"
        ));
    };
    Ok(config.clone())
}
