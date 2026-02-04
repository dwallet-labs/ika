// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Common node running logic shared by all node binaries.

use clap::{ArgGroup, Args, FromArgMatches, Parser};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{error, info};

use ika_config::node::RunWithRange;
use ika_config::{Config, NodeConfig};
use ika_core::runtime::IkaRuntimes;
use ika_telemetry::send_telemetry_event;
use ika_types::crypto::KeypairTraits;
use ika_types::digests::ChainIdentifier;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use mysten_common::sync::async_once_cell::AsyncOnceCell;
use sui_types::committee::EpochId;
use sui_types::multiaddr::Multiaddr;

use crate::{IkaNode, NodeMode};

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(group(ArgGroup::new("exclusive").required(false)))]
pub struct NodeArgs {
    #[clap(long)]
    pub config_path: PathBuf,

    #[clap(long, help = "Specify address to listen on")]
    pub listen_address: Option<Multiaddr>,

    #[clap(long, group = "exclusive")]
    pub run_with_range_epoch: Option<EpochId>,

    #[clap(long, group = "exclusive")]
    pub run_with_range_checkpoint: Option<DWalletCheckpointSequenceNumber>,
}

/// Runs an Ika node with the specified mode.
///
/// If `mode` is `None`, the mode is auto-detected from the configuration.
/// If `mode` is `Some(mode)`, the configuration is validated against the expected mode.
///
/// # Arguments
/// * `mode` - Optional explicit mode to run in. If None, auto-detects from config.
/// * `version` - The version string for this binary.
pub fn run_node(mode: Option<NodeMode>, version: &'static str) {
    let bin_name = mode
        .map(|m| match m {
            NodeMode::Validator => "ika-validator",
            NodeMode::Fullnode => "ika-fullnode",
            NodeMode::Notifier => "ika-notifier",
        })
        .unwrap_or("ika-node");
    run_node_with_name(mode, version, bin_name);
}

/// Runs an Ika node with the specified mode and binary name.
///
/// # Arguments
/// * `mode` - Optional explicit mode to run in. If None, auto-detects from config.
/// * `version` - The version string for this binary.
/// * `bin_name` - The name to use in CLI help/version output.
pub fn run_node_with_name(mode: Option<NodeMode>, version: &'static str, bin_name: &'static str) {
    // Ensure that a validator never calls get_for_min_version/get_for_max_version_UNSAFE.
    // TODO: re-enable after we figure out how to eliminate crashes in prod because of this.
    // ProtocolConfig::poison_get_for_min_version();

    let cmd = clap::Command::new(bin_name).version(version);
    let args = NodeArgs::augment_args(cmd).get_matches();
    let args = NodeArgs::from_arg_matches(&args).expect("Failed to parse arguments");
    let mut config = NodeConfig::load(&args.config_path).unwrap();
    assert!(
        config.supported_protocol_versions.is_none(),
        "supported_protocol_versions cannot be read from the config file"
    );
    config.supported_protocol_versions = Some(SupportedProtocolVersions::SYSTEM_DEFAULT);

    // Match run_with_range args
    // this means that we always modify the config used to start the node
    // for run_with_range.
    // I.e., if this is set in the config, it is ignored.
    // Only the cli args
    // enable/disable run_with_range
    match (args.run_with_range_epoch, args.run_with_range_checkpoint) {
        (None, Some(checkpoint)) => {
            config.run_with_range = Some(RunWithRange::Checkpoint(checkpoint))
        }
        (Some(epoch), None) => config.run_with_range = Some(RunWithRange::Epoch(epoch)),
        _ => config.run_with_range = None,
    };

    // Determine the mode to run in
    let node_mode = match mode {
        Some(explicit_mode) => {
            // Validate the config matches the expected mode
            if let Err(e) = explicit_mode.validate_config(&config) {
                eprintln!(
                    "Configuration validation failed for {} mode: {}",
                    explicit_mode, e
                );
                std::process::exit(1);
            }
            explicit_mode
        }
        None => {
            // Auto-detect mode from config
            NodeMode::detect_from_config(&config)
        }
    };

    let runtimes = IkaRuntimes::new(&config);
    let metrics_rt = runtimes.metrics.enter();
    let registry_service = mysten_metrics::start_prometheus_server(config.metrics_address);
    let prometheus_registry = registry_service.default_registry();

    // Initialize logging
    let (_guard, filter_handle) = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .with_prom_registry(&prometheus_registry)
        .init();

    drop(metrics_rt);

    info!("Ika Node version: {version}");
    info!("Node mode: {node_mode}");
    info!(
        "Supported protocol versions: {:?}",
        config.supported_protocol_versions
    );

    info!(
        "Started Prometheus HTTP endpoint at {}",
        config.metrics_address
    );

    {
        let _enter = runtimes.metrics.enter();
        if let Some(metrics_config) = &config.metrics
            && let Some(push_url) = &metrics_config.push_url
        {
            sui_metrics_push_client::start_metrics_push_task(
                metrics_config.push_interval_seconds,
                push_url.clone(),
                config.network_key_pair().copy(),
                registry_service.clone(),
            );
        }
    }

    if let Some(listen_address) = args.listen_address {
        config.network_address = listen_address;
    }

    let admin_interface_port = config.admin_interface_port;

    // Run node in a separate runtime so that admin/monitoring functions continue to work
    // if it deadlocks.
    let node_once_cell = Arc::new(AsyncOnceCell::<Arc<IkaNode>>::new());
    let node_once_cell_clone = node_once_cell.clone();

    // Let ika-node signal main to shut runtimes.
    let (runtime_shutdown_tx, runtime_shutdown_rx) = broadcast::channel::<()>(1);
    let chain_identifier =
        ChainIdentifier::from(config.sui_connector_config.clone().ika_system_object_id);

    runtimes.ika_node.spawn(async move {
        match IkaNode::start_with_mode(config, registry_service, version, node_mode).await {
            Ok(ika_node) => node_once_cell_clone
                .set(ika_node)
                .expect("Failed to set node in AsyncOnceCell"),

            Err(e) => {
                error!("Failed to start node: {e:?}");
                std::process::exit(1);
            }
        }

        // get node, subscribe to shutdown channel
        let node = node_once_cell_clone.get().await;
        let mut shutdown_rx = node.subscribe_to_shutdown_channel();

        // When we get a shutdown signal from ika-node,
        // forward it on to the `runtime_shutdown_channel` here in
        // main to signal runtimes to all shutdown.
        tokio::select! {
           _ = shutdown_rx.recv() => {
                runtime_shutdown_tx.send(()).expect("failed to forward shutdown signal from ika-node to ika-node main");
            }
        }
        // TODO: Do we want to provide a way for the node to gracefully shutdown?
        loop {
            tokio::time::sleep(Duration::from_secs(1000)).await;
        }
    });

    let node_once_cell_clone = node_once_cell.clone();
    let uptime_label = node_mode.uptime_metric_label();

    runtimes.metrics.spawn(async move {
        let node = node_once_cell_clone.get().await;
        info!("Ika chain identifier: {chain_identifier}");
        prometheus_registry
            .register(mysten_metrics::uptime_metric(
                uptime_label,
                version,
                &chain_identifier.to_string(),
            ))
            .unwrap();

        crate::admin::run_admin_server(node, admin_interface_port, filter_handle).await
    });

    let is_validator = node_mode.is_validator();
    runtimes.metrics.spawn(async move {
        let node = node_once_cell.get().await;
        let state = node.state();
        loop {
            send_telemetry_event(state.clone(), is_validator).await;
            sleep(Duration::from_secs(3600)).await;
        }
    });

    // wait for SIGINT on the main thread
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(wait_termination(runtime_shutdown_rx));

    // Drop and wait for all runtimes on the main thread.
    drop(runtimes);
}

#[cfg(not(unix))]
async fn wait_termination(mut shutdown_rx: broadcast::Receiver<()>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = shutdown_rx.recv() => {},
    }
}

#[cfg(unix)]
async fn wait_termination(mut shutdown_rx: broadcast::Receiver<()>) {
    use futures::FutureExt;
    use tokio::signal::unix::*;

    let sigint = tokio::signal::ctrl_c().boxed();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let sigterm_recv = sigterm.recv().boxed();
    let shutdown_recv = shutdown_rx.recv().boxed();

    tokio::select! {
        _ = sigint => {},
        _ = sigterm_recv => {},
        _ = shutdown_recv => {},
    }
}
