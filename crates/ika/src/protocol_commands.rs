// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use ika_config::{IKA_SUI_CONFIG, ika_config_dir};
use ika_sui_client::ika_protocol_transactions::{
    perform_approved_upgrade, set_approved_upgrade_by_cap,
    set_gas_fee_reimbursement_sui_system_call_value_by_cap,
    set_paused_curves_and_signature_algorithms, set_supported_and_pricing, try_migrate_coordinator,
    try_migrate_system,
};
use ika_types::messages_dwallet_mpc::IkaPackagesConfig;
use ika_types::sui::{PricingInfoKey, PricingInfoValue};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::{
    fmt,
    fmt::{Debug, Display, Formatter, Write},
    fs,
    path::PathBuf,
};
use sui_config::PersistedConfig;
use sui_sdk::rpc_types::SuiTransactionBlockResponse;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::ObjectID;
use sui_types::collection_types::Entry;

const DEFAULT_GAS_BUDGET: u64 = 200_000_000;

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
pub enum IkaProtocolCommand {
    #[clap(name = "set-approved-upgrade-by-cap")]
    SetApprovedUpgradeByCap {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "protocol-cap-id", long)]
        protocol_cap_id: ObjectID,
        #[clap(name = "package-id", long)]
        package_id: ObjectID,
        #[clap(long, name = "bytecode-dump-base64")]
        bytecode_dump_base64: Option<String>,
        #[clap(long, name = "bytecode-dump-base64-file")]
        bytecode_dump_base64_file: Option<PathBuf>,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "perform-approved-upgrade")]
    PerformApprovedUpgrade {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "package-id", long)]
        package_id: ObjectID,
        #[clap(long, name = "bytecode-dump-base64")]
        bytecode_dump_base64: Option<String>,
        #[clap(long, name = "bytecode-dump-base64-file")]
        bytecode_dump_base64_file: Option<PathBuf>,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "try-migrate-system")]
    TryMigrateSystem {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "new-package-id", long)]
        new_package_id: ObjectID,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "try-migrate-coordinator")]
    TryMigrateCoordinator {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "new-package-id", long)]
        new_package_id: ObjectID,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "set-paused-curves-and-signature-algorithms")]
    SetPausedCurvesAndSignatureAlgorithms {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "protocol-cap-id", long)]
        protocol_cap_id: ObjectID,
        #[clap(name = "paused-curves", long, use_value_delimiter = true)]
        paused_curves: Vec<u32>,
        #[clap(name = "paused-signature-algorithms", long, use_value_delimiter = true)]
        paused_signature_algorithms: Vec<u32>,
        #[clap(name = "paused-hash-schemes", long, use_value_delimiter = true)]
        paused_hash_schemes: Vec<u32>,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "set-supported-and-pricing")]
    SetSupportedAndPricing {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "protocol-cap-id", long)]
        protocol_cap_id: ObjectID,
        #[clap(name = "default-pricing", long)]
        default_pricing_yaml: PathBuf,
        #[clap(
            name = "supported-curves-to-signature-algorithms-to-hash-schemes",
            long
        )]
        supported_curves_to_signature_algorithms_to_hash_schemes_yaml: PathBuf,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
    #[clap(name = "set-gas-fee-reimbursement-sui-system-call-value-by-cap")]
    SetGasFeeReimbursementSuiSystemCallValueByCap {
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
        #[clap(name = "protocol-cap-id", long)]
        protocol_cap_id: ObjectID,
        #[clap(name = "gas-fee-reimbursement-sui-system-call-value", long)]
        gas_fee_reimbursement_sui_system_call_value: u64,
        #[clap(name = "ika-sui-config", long)]
        ika_sui_config: Option<PathBuf>,
    },
}

pub enum IkaProtocolCommandResponse {
    SetApprovedUpgradeByCap(SuiTransactionBlockResponse),
    PerformApprovedUpgrade(SuiTransactionBlockResponse),
    TryMigrateSystem(SuiTransactionBlockResponse),
    TryMigrateCoordinator(SuiTransactionBlockResponse),
    SetPausedCurvesAndSignatureAlgorithms(SuiTransactionBlockResponse),
    SetSupportedAndPricing(SuiTransactionBlockResponse),
    SetGasFeeReimbursementSuiSystemCallValueByCap(SuiTransactionBlockResponse),
}

impl IkaProtocolCommand {
    pub async fn execute(
        self,
        context: &mut WalletContext,
    ) -> Result<IkaProtocolCommandResponse, anyhow::Error> {
        let response = match self {
            IkaProtocolCommand::SetApprovedUpgradeByCap {
                gas_budget,
                protocol_cap_id,
                package_id,
                bytecode_dump_base64,
                bytecode_dump_base64_file,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let bytecode_dump_base64_obj: BytecodeDumpBase64 = if let Some(json_str) =
                    bytecode_dump_base64
                {
                    serde_json::from_str(&json_str)
                        .context(format!("Cannot parse bytecode_dump_base64: {json_str:?}"))?
                } else if let Some(file_path) = bytecode_dump_base64_file {
                    let content = fs::read_to_string(file_path).expect("Failed to read file");
                    serde_json::from_str(&content).context(format!(
                        "Cannot parse bytecode_dump_base64_file: {content:?}"
                    ))?
                } else {
                    return Err(anyhow::anyhow!(
                        "You must provide either --bytecode-dump-base64 or --bytecode-dump-base64-file"
                    ));
                };

                let response = set_approved_upgrade_by_cap(
                    context,
                    config.ika_system_package_id,
                    config.ika_system_object_id,
                    protocol_cap_id,
                    package_id,
                    Some(bytecode_dump_base64_obj.digest),
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::SetApprovedUpgradeByCap(response)
            }
            IkaProtocolCommand::PerformApprovedUpgrade {
                gas_budget,
                package_id,
                bytecode_dump_base64,
                bytecode_dump_base64_file,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let bytecode_dump_base64_obj: BytecodeDumpBase64 = if let Some(json_str) =
                    bytecode_dump_base64
                {
                    serde_json::from_str(&json_str)
                        .context(format!("Cannot parse bytecode_dump_base64: {json_str:?}"))?
                } else if let Some(file_path) = bytecode_dump_base64_file {
                    let content = fs::read_to_string(file_path).expect("Failed to read file");
                    serde_json::from_str(&content).context(format!(
                        "Cannot parse bytecode_dump_base64_file: {content:?}"
                    ))?
                } else {
                    return Err(anyhow::anyhow!(
                        "You must provide either --bytecode-dump-base64 or --bytecode-dump-base64-file"
                    ));
                };

                let response = perform_approved_upgrade(
                    context,
                    config.ika_system_package_id,
                    config.ika_system_object_id,
                    config.ika_dwallet_2pc_mpc_package_id,
                    config.ika_dwallet_coordinator_object_id,
                    package_id,
                    bytecode_dump_base64_obj.modules,
                    bytecode_dump_base64_obj.dependencies,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::PerformApprovedUpgrade(response)
            }
            IkaProtocolCommand::TryMigrateSystem {
                gas_budget,
                new_package_id,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let response = try_migrate_system(
                    context,
                    new_package_id,
                    config.ika_system_object_id,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::TryMigrateSystem(response)
            }
            IkaProtocolCommand::TryMigrateCoordinator {
                gas_budget,
                new_package_id,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let response = try_migrate_coordinator(
                    context,
                    new_package_id,
                    config.ika_dwallet_coordinator_object_id,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::TryMigrateCoordinator(response)
            }
            IkaProtocolCommand::SetPausedCurvesAndSignatureAlgorithms {
                gas_budget,
                protocol_cap_id,
                paused_curves,
                paused_signature_algorithms,
                paused_hash_schemes,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let response = set_paused_curves_and_signature_algorithms(
                    context,
                    config.ika_dwallet_2pc_mpc_package_id,
                    config.ika_dwallet_coordinator_object_id,
                    config.ika_system_package_id,
                    config.ika_system_object_id,
                    protocol_cap_id,
                    paused_curves,
                    paused_signature_algorithms,
                    paused_hash_schemes,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::SetPausedCurvesAndSignatureAlgorithms(response)
            }
            IkaProtocolCommand::SetSupportedAndPricing {
                gas_budget,
                protocol_cap_id,
                default_pricing_yaml,
                supported_curves_to_signature_algorithms_to_hash_schemes_yaml,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let default_pricing_yaml: Vec<Entry<PricingInfoKey, PricingInfoValue>> =
                    serde_yaml::from_reader(BufReader::new(File::open(default_pricing_yaml)?))?;

                let supported_curves_to_signature_algorithms_to_hash_schemes =
                    serde_yaml::from_reader(BufReader::new(File::open(
                        supported_curves_to_signature_algorithms_to_hash_schemes_yaml,
                    )?))?;

                let response = set_supported_and_pricing(
                    context,
                    config.ika_dwallet_2pc_mpc_package_id,
                    config.ika_dwallet_coordinator_object_id,
                    config.ika_system_package_id,
                    config.ika_system_object_id,
                    protocol_cap_id,
                    default_pricing_yaml,
                    supported_curves_to_signature_algorithms_to_hash_schemes,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::SetSupportedAndPricing(response)
            }
            IkaProtocolCommand::SetGasFeeReimbursementSuiSystemCallValueByCap {
                gas_budget,
                protocol_cap_id,
                gas_fee_reimbursement_sui_system_call_value,
                ika_sui_config,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let config_path = ika_sui_config.unwrap_or(ika_config_dir()?.join(IKA_SUI_CONFIG));
                let config: IkaPackagesConfig =
                    PersistedConfig::read(&config_path).map_err(|err| {
                        err.context(format!(
                            "Cannot open Ika network config file at {config_path:?}"
                        ))
                    })?;

                let response = set_gas_fee_reimbursement_sui_system_call_value_by_cap(
                    context,
                    config.ika_dwallet_2pc_mpc_package_id,
                    config.ika_dwallet_coordinator_object_id,
                    config.ika_system_package_id,
                    config.ika_system_object_id,
                    protocol_cap_id,
                    gas_fee_reimbursement_sui_system_call_value,
                    gas_budget,
                )
                .await?;
                IkaProtocolCommandResponse::SetGasFeeReimbursementSuiSystemCallValueByCap(response)
            }
        };
        Ok(response)
    }
}

impl Display for IkaProtocolCommandResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match self {
            IkaProtocolCommandResponse::SetApprovedUpgradeByCap(response)
            | IkaProtocolCommandResponse::PerformApprovedUpgrade(response)
            | IkaProtocolCommandResponse::TryMigrateSystem(response)
            | IkaProtocolCommandResponse::TryMigrateCoordinator(response)
            | IkaProtocolCommandResponse::SetPausedCurvesAndSignatureAlgorithms(response)
            | IkaProtocolCommandResponse::SetSupportedAndPricing(response)
            | IkaProtocolCommandResponse::SetGasFeeReimbursementSuiSystemCallValueByCap(response) =>
            {
                write!(
                    writer,
                    "{}",
                    write_transaction_response_without_transaction_data(response)?
                )?;
            }
        }
        write!(f, "{}", writer.trim_end_matches('\n'))
    }
}

impl Debug for IkaProtocolCommandResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl IkaProtocolCommandResponse {
    pub fn print(&self, pretty: bool) {
        if pretty {
            println!("{self}");
        } else {
            println!("{self:?}");
        }
    }
}

fn write_transaction_response_without_transaction_data(
    response: &SuiTransactionBlockResponse,
) -> Result<String, fmt::Error> {
    // we requested with for full_content, so the following content should be available.
    let success = response.status_ok().unwrap();
    let lines = vec![
        String::from("----- Transaction Digest ----"),
        response.digest.to_string(),
        String::from("----- Transaction Effects ----"),
        response.effects.as_ref().unwrap().to_string(),
    ];
    let mut writer = String::new();
    for line in lines {
        let colorized_line = if success { line.green() } else { line.red() };
        writeln!(writer, "{colorized_line}")?;
    }
    Ok(writer)
}

#[derive(Debug, Deserialize)]
struct BytecodeDumpBase64 {
    modules: Vec<String>,
    dependencies: Vec<ObjectID>,
    digest: Vec<u8>,
}
