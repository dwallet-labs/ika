// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::IkaNode;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use humantime::parse_duration;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use telemetry_subscribers::TracingHandle;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::{error, info, warn};

// Example commands:
//
// Set buffer stake for current epoch 2 to 1500 basis points:
//
//   $ curl -X POST 'http://127.0.0.1:1337/set-override-buffer-stake?buffer_bps=1500&epoch=2'
//
// Clear buffer stake override for current epoch 2, use
// ProtocolConfig::buffer_stake_for_protocol_upgrade_bps:
//
//   $ curl -X POST 'http://127.0.0.1:1337/clear-override-buffer-stake?epoch=2'
//
// Vote to close epoch 2 early
//
//   $ curl -X POST 'http://127.0.0.1:1337/force-close-epoch?epoch=2'
//
// View current all capabilities from all authorities that have been received by this node:
//
//   $ curl 'http://127.0.0.1:1337/capabilities'
//
// View the node config (private keys will be masked):
//
//   $ curl 'http://127.0.0.1:1337/node-config'
//
// Set a time-limited tracing config. After the duration expires, tracing will be disabled
// automatically.
//
//   $ curl -X POST 'http://127.0.0.1:1337/enable-tracing?filter=info&duration=10s'
//
// Reset tracing to the TRACE_FILTER env var.
//
//   $ curl -X POST 'http://127.0.0.1:1337/reset-tracing'
//

const LOGGING_ROUTE: &str = "/logging";
const TRACING_ROUTE: &str = "/enable-tracing";
const TRACING_RESET_ROUTE: &str = "/reset-tracing";
const SET_BUFFER_STAKE_ROUTE: &str = "/set-override-buffer-stake";
const CLEAR_BUFFER_STAKE_ROUTE: &str = "/clear-override-buffer-stake";
const CAPABILITIES: &str = "/capabilities";
const NODE_CONFIG: &str = "/node-config";

/// How long to wait between admin-server bind attempts.
const BIND_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// How many times to attempt the bind before giving up on the admin server.
/// Together with the interval this keeps trying for ~2 minutes, comfortably
/// past the ~60s a socket spends in `TIME_WAIT` after a restart.
const BIND_ATTEMPTS: u32 = 25;

struct AppState {
    node: Arc<IkaNode>,
    tracing_handle: TracingHandle,
}

pub async fn run_admin_server(node: Arc<IkaNode>, port: u16, tracing_handle: TracingHandle) {
    let filter = tracing_handle.get_log().unwrap();

    let app_state = AppState {
        node,
        tracing_handle,
    };

    let app = Router::new()
        .route(LOGGING_ROUTE, get(get_filter))
        .route(CAPABILITIES, get(capabilities))
        .route(NODE_CONFIG, get(node_config))
        .route(LOGGING_ROUTE, post(set_filter))
        .route(
            SET_BUFFER_STAKE_ROUTE,
            post(set_override_protocol_upgrade_buffer_stake),
        )
        .route(
            CLEAR_BUFFER_STAKE_ROUTE,
            post(clear_override_protocol_upgrade_buffer_stake),
        )
        .route(TRACING_ROUTE, post(enable_tracing))
        .route(TRACING_RESET_ROUTE, post(reset_tracing))
        .with_state(Arc::new(app_state));

    let socket_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    info!(
        filter =% filter,
        address =% socket_address,
        "starting admin server"
    );

    serve_admin(app, socket_address, BIND_ATTEMPTS, BIND_RETRY_INTERVAL).await;
}

/// Serve `app` on `socket_address`, riding out a transient bind failure and
/// then giving up quietly — never panicking.
///
/// The admin endpoint is an operational convenience, not a correctness
/// component, and losing it is the entire cost of a failure here. Since
/// panics kill the process by default, an `unwrap` on this bind turned a
/// transient `AddrInUse` — a port race on a shared CI runner, or a restart
/// racing its own port through `TIME_WAIT` — into node death at boot. A node
/// without an admin endpoint is strictly healthier than a dead node.
///
/// The retries are bounded so a genuinely misconfigured duplicate port ends
/// in a single loud give-up rather than an unbounded background loop; each
/// attempt warns with the address, so that misconfiguration is visible
/// immediately either way.
async fn serve_admin(
    app: Router,
    socket_address: SocketAddr,
    attempts: u32,
    retry_interval: Duration,
) {
    let Some(listener) = bind_with_retry(socket_address, attempts, retry_interval).await else {
        error!(
            address =% socket_address,
            "gave up binding the admin server; the node continues without the admin endpoint"
        );
        return;
    };
    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!(
            address =% socket_address,
            error =? err,
            "admin server stopped; the node continues without the admin endpoint"
        );
    }
}

/// Bind the admin listener, retrying `attempts` times at `retry_interval`.
/// `None` once the attempts are exhausted.
async fn bind_with_retry(
    socket_address: SocketAddr,
    attempts: u32,
    retry_interval: Duration,
) -> Option<TcpListener> {
    for attempt in 1..=attempts {
        match TcpListener::bind(&socket_address).await {
            Ok(listener) => return Some(listener),
            Err(err) => warn!(
                address =% socket_address,
                attempt,
                attempts,
                error =? err,
                "failed to bind the admin server, retrying"
            ),
        }
        if attempt < attempts {
            sleep(retry_interval).await;
        }
    }
    None
}

#[derive(Deserialize)]
struct EnableTracing {
    // These params change the filter, and reset it after the duration expires.
    filter: Option<String>,
    duration: Option<String>,

    // Change the trace output file (if file output was enabled at program start)
    trace_file: Option<String>,

    // Change the tracing sample rate
    sample_rate: Option<f64>,
}

async fn enable_tracing(
    State(state): State<Arc<AppState>>,
    query: Query<EnableTracing>,
) -> (StatusCode, String) {
    let Query(EnableTracing {
        filter,
        duration,
        trace_file,
        sample_rate,
    }) = query;

    let mut response = Vec::new();

    if let Some(sample_rate) = sample_rate {
        state.tracing_handle.update_sampling_rate(sample_rate);
        response.push(format!("sample rate set to {sample_rate:?}"));
    }

    if let Some(trace_file) = trace_file {
        if let Err(err) = state.tracing_handle.update_trace_file(&trace_file) {
            response.push(format!("can't update trace file: {err:?}"));
            return (StatusCode::BAD_REQUEST, response.join("\n"));
        } else {
            response.push(format!("trace file set to {trace_file:?}"));
        }
    }

    let Some(filter) = filter else {
        return (StatusCode::OK, response.join("\n"));
    };

    // Duration is required if filter is set
    let Some(duration) = duration else {
        response.push("can't update filter: missing duration".into());
        return (StatusCode::BAD_REQUEST, response.join("\n"));
    };

    let Ok(duration) = parse_duration(&duration) else {
        response.push("can't update filter: invalid duration".into());
        return (StatusCode::BAD_REQUEST, response.join("\n"));
    };

    match state.tracing_handle.update_trace_filter(&filter, duration) {
        Ok(()) => {
            response.push(format!("filter set to {filter:?}"));
            response.push(format!("filter will be reset after {duration:?}"));
            (StatusCode::OK, response.join("\n"))
        }
        Err(err) => {
            response.push(format!("can't update filter: {err:?}"));
            (StatusCode::BAD_REQUEST, response.join("\n"))
        }
    }
}

async fn reset_tracing(State(state): State<Arc<AppState>>) -> (StatusCode, String) {
    state.tracing_handle.reset_trace();
    (
        StatusCode::OK,
        "tracing filter reset to TRACE_FILTER env var".into(),
    )
}

async fn get_filter(State(state): State<Arc<AppState>>) -> (StatusCode, String) {
    match state.tracing_handle.get_log() {
        Ok(filter) => (StatusCode::OK, filter),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn set_filter(
    State(state): State<Arc<AppState>>,
    new_filter: String,
) -> (StatusCode, String) {
    match state.tracing_handle.update_log(&new_filter) {
        Ok(()) => {
            info!(filter =% new_filter, "Log filter updated");
            (StatusCode::OK, "".into())
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn capabilities(State(state): State<Arc<AppState>>) -> (StatusCode, String) {
    let epoch_store = state.node.state().load_epoch_store_one_call_per_task();

    // Only one of v1 or v2 will be populated at a time
    let capabilities = epoch_store.get_capabilities_v1();
    let mut output = String::new();
    for capability in capabilities.unwrap_or_default() {
        output.push_str(&format!("{capability:?}\n"));
    }

    (StatusCode::OK, output)
}

async fn node_config(State(state): State<Arc<AppState>>) -> (StatusCode, String) {
    let node_config = &state.node.config;

    // Note private keys will be masked
    (StatusCode::OK, format!("{node_config:#?}\n"))
}

#[derive(Deserialize)]
struct Epoch {
    epoch: u64,
}

async fn clear_override_protocol_upgrade_buffer_stake(
    State(state): State<Arc<AppState>>,
    epoch: Query<Epoch>,
) -> (StatusCode, String) {
    let Query(Epoch { epoch }) = epoch;

    match state
        .node
        .clear_override_protocol_upgrade_buffer_stake(epoch)
    {
        Ok(()) => (
            StatusCode::OK,
            "protocol upgrade buffer stake cleared\n".to_string(),
        ),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Deserialize)]
struct SetBufferStake {
    buffer_bps: u64,
    epoch: u64,
}

async fn set_override_protocol_upgrade_buffer_stake(
    State(state): State<Arc<AppState>>,
    buffer_state: Query<SetBufferStake>,
) -> (StatusCode, String) {
    let Query(SetBufferStake { buffer_bps, epoch }) = buffer_state;

    match state
        .node
        .set_override_protocol_upgrade_buffer_stake(epoch, buffer_bps)
    {
        Ok(()) => (
            StatusCode::OK,
            format!("protocol upgrade buffer stake set to '{buffer_bps}'\n"),
        ),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::time::timeout;

    /// A stand-in for the real admin router: `serve_admin` only ever sees an
    /// already-stateless `Router`, so the routes it carries are irrelevant to
    /// the bind path under test.
    fn test_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    /// A listener squatting on an ephemeral port, plus that port's address.
    async fn squatted_port() -> (TcpListener, SocketAddr) {
        let squatter = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind a squatter on an ephemeral port");
        let address = squatter.local_addr().expect("squatter local address");
        (squatter, address)
    }

    async fn get_ping(address: SocketAddr) -> Option<String> {
        let response = reqwest::Client::new()
            .get(format!("http://{address}/ping"))
            .send()
            .await
            .ok()?;
        response.text().await.ok()
    }

    /// The node-side failure this guards: another process holds the admin
    /// port, and the node dies at boot because the bind panicked on a runtime
    /// where panics are fatal. `serve_admin` must exhaust its retries and
    /// return normally instead — the node runs on, minus the admin endpoint.
    #[tokio::test]
    async fn a_squatted_admin_port_does_not_take_the_node_down() {
        let (_squatter, address) = squatted_port().await;

        timeout(
            Duration::from_secs(30),
            serve_admin(test_router(), address, 3, Duration::from_millis(50)),
        )
        .await
        .expect("a permanently squatted admin port must be given up on, not waited on forever");
    }

    /// The retries ride out a transient squatter: once the port is released
    /// the admin server comes up on its own, with no node restart.
    #[tokio::test]
    async fn the_admin_server_comes_up_once_the_port_is_released() {
        let (squatter, address) = squatted_port().await;

        let server = tokio::spawn(serve_admin(
            test_router(),
            address,
            600,
            Duration::from_millis(50),
        ));

        // Let the first attempts fail against the squatter before it lets go.
        sleep(Duration::from_millis(120)).await;
        drop(squatter);

        let body = timeout(Duration::from_secs(30), async {
            loop {
                if let Some(body) = get_ping(address).await {
                    return body;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the admin server must come up once the port is released");
        assert_eq!(body, "pong");

        server.abort();
    }

    /// The retry budget is a bound, not a loop: a duplicate port that is
    /// never released ends in one give-up after the configured attempts.
    #[tokio::test]
    async fn the_bind_retry_is_bounded() {
        let (_squatter, address) = squatted_port().await;

        let started = Instant::now();
        assert!(
            bind_with_retry(address, 4, Duration::from_millis(50))
                .await
                .is_none()
        );
        // Four attempts are three sleeps; no sleep is wasted after the last.
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
