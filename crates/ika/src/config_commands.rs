// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use ika_config::{IKA_SUI_CONFIG, ika_config_dir};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use serde::Deserialize;
use sui_types::base_types::ObjectID;

use crate::IkaPackagesConfigFile;

const GITHUB_RAW_BASE: &str =
    "https://raw.githubusercontent.com/dwallet-labs/ika/main/deployed_contracts";

/// Known Sui RPC URLs per network.
fn sui_rpc_url(network: &str) -> &'static str {
    match network {
        "mainnet" => "https://fullnode.mainnet.sui.io:443",
        "testnet" => "https://fullnode.testnet.sui.io:443",
        _ => "http://127.0.0.1:9000",
    }
}

/// Config management commands.
#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum IkaConfigCommand {
    /// Initialize Ika CLI config by fetching deployed contract addresses from GitHub.
    ///
    /// Fetches the address.yaml for the specified network(s) and writes the
    /// ika_sui_config.yaml used by all dwallet commands.
    #[clap(name = "init")]
    Init {
        /// Networks to configure. Can be specified multiple times.
        #[clap(long, value_delimiter = ',', default_value = "testnet,mainnet")]
        network: Vec<String>,
        /// Output path for the config file.
        #[clap(long)]
        output: Option<PathBuf>,
    },

    /// Show the current Ika CLI config.
    #[clap(name = "show")]
    Show {
        /// Path to the config file.
        #[clap(long)]
        config: Option<PathBuf>,
    },
}

/// Raw address.yaml structure from deployed_contracts/{network}/address.yaml.
#[derive(Debug, Deserialize)]
struct DeployedAddresses {
    ika_package_id: String,
    ika_common_package_id: String,
    ika_dwallet_2pc_mpc_package_id: String,
    ika_system_package_id: String,
    ika_system_object_id: String,
    ika_coordinator_object_id: String,
    #[serde(default)]
    ika_dwallet_2pc_mpc_package_id_v2: Option<String>,
    #[serde(default)]
    ika_system_package_id_v2: Option<String>,
}

impl DeployedAddresses {
    fn to_network_config(&self) -> Result<IkaNetworkConfig> {
        // Use v2 package IDs if available, otherwise fall back to v1
        let dwallet_2pc_mpc_id = self
            .ika_dwallet_2pc_mpc_package_id_v2
            .as_deref()
            .unwrap_or(&self.ika_dwallet_2pc_mpc_package_id);
        let system_id = self
            .ika_system_package_id_v2
            .as_deref()
            .unwrap_or(&self.ika_system_package_id);

        Ok(IkaNetworkConfig::new(
            parse_object_id(&self.ika_package_id)?,
            parse_object_id(&self.ika_common_package_id)?,
            parse_object_id(dwallet_2pc_mpc_id)?,
            None,
            parse_object_id(system_id)?,
            parse_object_id(&self.ika_system_object_id)?,
            parse_object_id(&self.ika_coordinator_object_id)?,
        ))
    }
}

fn parse_object_id(s: &str) -> Result<ObjectID> {
    s.parse().with_context(|| format!("Invalid object ID: {s}"))
}

impl IkaConfigCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            IkaConfigCommand::Init { network, output } => {
                let output_path = output.unwrap_or_else(|| {
                    ika_config_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(IKA_SUI_CONFIG)
                });

                let mut envs: HashMap<String, IkaNetworkConfig> = HashMap::new();

                for net in &network {
                    let url = format!("{GITHUB_RAW_BASE}/{net}/address.yaml");
                    println!("Fetching {net} config from {url}");

                    let body = reqwest::get(&url)
                        .await
                        .with_context(|| format!("Failed to fetch {url}"))?
                        .text()
                        .await
                        .with_context(|| format!("Failed to read response from {url}"))?;

                    let addresses: DeployedAddresses = serde_yaml::from_str(&body)
                        .with_context(|| format!("Failed to parse address.yaml for {net}"))?;

                    let config = addresses.to_network_config()?;
                    envs.insert(net.clone(), config);

                    println!(
                        "  Sui RPC: {} (configure with: sui client new-env --alias {net} --rpc {})",
                        sui_rpc_url(net),
                        sui_rpc_url(net)
                    );
                }

                let config_file = IkaPackagesConfigFile { envs };
                let yaml =
                    serde_yaml::to_string(&config_file).context("Failed to serialize config")?;

                if let Some(parent) = output_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&output_path, format!("---\n{yaml}"))
                    .with_context(|| format!("Failed to write config to {output_path:?}"))?;

                println!("\nConfig written to: {}", output_path.display());
                println!(
                    "\nNext steps:\n\
                     1. Configure Sui CLI environments:\n\
                     {}
                     2. Set active environment: sui client switch --env <network>\n\
                     3. Ensure you have SUI tokens for gas and IKA tokens for operations",
                    network
                        .iter()
                        .map(|n| {
                            format!(
                                "   sui client new-env --alias {n} --rpc {}\n",
                                sui_rpc_url(n)
                            )
                        })
                        .collect::<String>()
                );
                Ok(())
            }

            IkaConfigCommand::Show { config } => {
                let config_path = config.unwrap_or_else(|| {
                    ika_config_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(IKA_SUI_CONFIG)
                });

                let content = std::fs::read_to_string(&config_path).with_context(|| {
                    format!(
                        "Cannot read config at {}. Run 'ika config init' first.",
                        config_path.display()
                    )
                })?;
                println!("{content}");
                Ok(())
            }
        }
    }
}
