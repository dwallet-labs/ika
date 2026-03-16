// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::path::PathBuf;

use anyhow::Result;
use sui_config::{SUI_CLIENT_CONFIG, sui_config_dir};
use sui_sdk::wallet_context::WalletContext;

use ika_config::{IKA_SUI_CONFIG, ika_config_dir};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;

use crate::read_ika_sui_config_yaml;

/// Shared CLI context providing wallet access, Ika network configuration, and output preferences.
pub struct CliContext {
    pub wallet: WalletContext,
    pub ika_config: Option<IkaNetworkConfig>,
    pub json_output: bool,
    pub gas_budget: Option<u64>,
}

impl CliContext {
    /// Create a new CLI context from the given configuration paths.
    pub fn new(
        sui_config: Option<PathBuf>,
        ika_config: Option<PathBuf>,
        json_output: bool,
        gas_budget: Option<u64>,
    ) -> Result<Self> {
        let config_path = sui_config.unwrap_or(sui_config_dir()?.join(SUI_CLIENT_CONFIG));
        let wallet = WalletContext::new(&config_path)?;

        let ika_config = ika_config
            .or_else(|| ika_config_dir().ok().map(|dir| dir.join(IKA_SUI_CONFIG)))
            .and_then(|path| read_ika_sui_config_yaml(&wallet, &path).ok());

        Ok(Self {
            wallet,
            ika_config,
            json_output,
            gas_budget,
        })
    }
}
