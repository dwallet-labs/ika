// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use crate::admin::{Labels, ReqwestClient};
use crate::consumer::{NodeMetric, convert_to_remote_write, populate_labels};
use crate::histogram_relay::HistogramRelay;
use crate::middleware::LenDelimProtobuf;
use crate::peers::AllowedPeer;
use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
};
use hex;
use multiaddr::Multiaddr;
use once_cell::sync::Lazy;
use prometheus::{CounterVec, HistogramVec};
use prometheus::{register_counter_vec, register_histogram_vec};
use std::env;
use std::net::SocketAddr;
use tracing::{debug, info};

static HANDLER_HITS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "http_handler_hits",
        "Number of HTTP requests made.",
        &["handler", "remote"]
    )
    .unwrap()
});

static HTTP_HANDLER_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "http_handler_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["handler", "remote"],
        vec![
            1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 3.25, 3.5, 3.75, 4.0, 4.25, 4.5, 4.75,
            5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0
        ],
    )
    .unwrap()
});

/// Publish handler, which receives metrics from nodes and relays them to upstream TSDB.
///
/// This handler uses Axum's dependency injection system via Extension extractors to access
/// shared application state and services. Each Extension(..) parameter extracts a different
/// piece of functionality from the application context.
///
/// # Parameters
///
/// ## Dependency Injection via Extensions
/// - `Extension(labels): Extension<Labels>` - Shared configuration labels (network name,
///   inventory hostname) used for consistent metric labeling across all requests
/// - `Extension(client): Extension<ReqwestClient>` - Shared HTTP client for making outbound
///   requests to upstream time-series databases
/// - `Extension(allowed_peer): Extension<Option<AllowedPeer>>` - Optional authenticated
///   peer information. Contains the peer's name and public key for access control and
///   metric labeling when authentication is enabled
/// - `Extension(relay): Extension<HistogramRelay>` - Histogram processing service that
///   handles specialized histogram metric processing
///
/// ## Request Data
/// - `ConnectInfo(addr): ConnectInfo<SocketAddr>` - Client's socket address (IP + port)
///   automatically provided by Axum for peer tracking
/// - `LenDelimProtobuf(data): LenDelimProtobuf` - Length-delimited protobuf payload
///   containing the metrics data from the node
///
/// # Flow
/// 1. Metrics are received from authenticated nodes via protobuf
/// 2. Request is tracked via prometheus counters and timing histograms
/// 3. Metrics are populated with consistent labels (network, hostname, peer name)
/// 4. Histogram data is submitted to the relay for specialized processing
/// 5. Metrics are converted to remote write format and forwarded to upstream TSDB
/// 6. Response is returned to the client after successful upstream relay
///
/// # Returns
/// `(StatusCode, &'static str)` - HTTP status and response message indicating success/failure
pub async fn publish_metrics(
    Extension(labels): Extension<Labels>,
    Extension(client): Extension<ReqwestClient>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(AllowedPeer { name, public_key }): Extension<AllowedPeer>,
    Extension(relay): Extension<HistogramRelay>,
    LenDelimProtobuf(data): LenDelimProtobuf,
) -> (StatusCode, &'static str) {
    // Check if verbose HTTP logging is enabled.
    let verbose_logging = env::var("IKA_PROXY_VERBOSE_HTTP")
        .map(|val| val.to_lowercase() == "true" || val == "1")
        .unwrap_or(false);

    if verbose_logging {
        info!(
            ?name,
            ?addr,
            public_key = %hex::encode(&public_key),
            metrics_count = %data.len(),
            network = %labels.network,
            inventory_hostname = %labels.inventory_hostname,
            "Processing metrics request from node"
        );
    } else {
        info!(?name, "received metrics from a node");
    }

    HANDLER_HITS
        .with_label_values(&["publish_metrics", &name])
        .inc();
    let timer = HTTP_HANDLER_DURATION
        .with_label_values(&["publish_metrics", &name])
        .start_timer();
    let data = populate_labels(
        name.clone(),
        labels.network,
        labels.inventory_hostname,
        data,
    );
    relay.submit(data.clone());
    let response = convert_to_remote_write(
        client.clone(),
        NodeMetric {
            data,
            peer_addr: Multiaddr::from(addr.ip()),
            public_key,
        },
    )
    .await;
    timer.observe_duration();

    if verbose_logging {
        let (status, message) = &response;
        debug!(
            name=?&name,
            ?addr,
            status_code = %status.as_u16(),
            response_message = %message,
            "Completed metrics request processing"
        );
    }

    response
}
