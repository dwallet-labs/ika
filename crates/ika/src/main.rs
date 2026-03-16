// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::path::PathBuf;

use clap::*;
use colored::Colorize;
use ika::ika_commands::IkaCommand;
use tracing::debug;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

#[derive(Parser)]
#[clap(
    name = env!("CARGO_BIN_NAME"),
    about = "Ika decentralized MPC network",
    rename_all = "kebab-case",
    author,
    version = VERSION,
    propagate_version = true,
)]
struct Args {
    /// Return command outputs in JSON format.
    #[clap(long, global = true)]
    json: bool,

    /// Sets the file storing the state of our user accounts (an empty one will be created if
    /// missing).
    #[clap(long = "client.config", global = true)]
    client_config: Option<PathBuf>,

    /// Path to the Ika network config (ika_sui_config.yml).
    #[clap(long = "ika-config", global = true)]
    ika_config: Option<PathBuf>,

    /// Override the default gas budget (in MIST).
    #[clap(long, global = true)]
    gas_budget: Option<u64>,

    /// Skip confirmation prompts.
    #[clap(short = 'y', long = "yes", global = true)]
    accept_defaults: bool,

    /// Suppress non-essential output.
    #[clap(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    #[clap(subcommand)]
    command: IkaCommand,
}

#[tokio::main]
async fn main() {
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).unwrap();

    let args = Args::parse();
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_log_level("error")
        .with_env()
        .init();
    debug!("Ika CLI version: {VERSION}");

    let json = args.json;
    let quiet = args.quiet;
    let result = args
        .command
        .execute(
            json,
            quiet,
            args.client_config,
            args.ika_config,
            args.gas_budget,
        )
        .await;

    match result {
        Ok(_) => (),
        Err(err) => {
            if json {
                let error_json = serde_json::json!({ "error": format!("{err:#}") });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error_json).unwrap_or_default()
                );
            } else {
                let err = format!("{err:?}");
                println!("{}", err.bold().red());
            }
            std::process::exit(1);
        }
    }
}
