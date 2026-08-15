// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use crate::bind_retry::{BIND_ATTEMPTS, BIND_RETRY_INTERVAL, bind_with_retry};
use axum::{Extension, Router, routing::get};
use mysten_metrics::{METRICS_ROUTE, RegistryService};
use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, Registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{error, warn};

/// Start the Prometheus scrape endpoint on `addr` and return the
/// [`RegistryService`] backing it.
///
/// A local equivalent of `mysten_metrics::start_prometheus_server`, which
/// `unwrap`s both the `TcpListener::bind` and the `axum::serve` inside its
/// spawned task. Under this node those `unwrap`s are fatal — the release
/// profile sets `panic = 'abort'` and the node enables `crash_on_panic` — so
/// a squatted metrics port (a shared CI runner, a duplicated port in a
/// deployment, or a restart racing its own port through `TIME_WAIT`) takes the
/// whole process down at boot, before telemetry is even initialized. This
/// version retries the bind and then gives up loudly, exactly like the admin
/// server; a node without a scrape endpoint is strictly healthier than a dead
/// node.
///
/// Metrics are more load-bearing than the admin endpoint — losing them blinds
/// every dashboard and alert for this validator — so the give-up logs at
/// `error!` and names the address.
///
/// The rest of the behaviour is upstream's, unchanged: same route, same
/// handler, same registry wiring, and the same simulator short-circuit.
pub fn start_prometheus_server(addr: SocketAddr) -> RegistryService {
    let registry = Registry::new();

    let registry_service = RegistryService::new(registry);

    if cfg!(msim) {
        // prometheus uses difficult-to-support features such as
        // TcpSocket::from_raw_fd(), so it can't run in the simulator.
        // Identical to upstream: return the registry service without ever
        // spawning a server.
        warn!("not starting prometheus server in simulator");
        return registry_service;
    }

    let app = Router::new()
        .route(METRICS_ROUTE, get(mysten_metrics::metrics))
        .layer(Extension(registry_service.clone()));

    tokio::spawn(serve_metrics(app, addr, BIND_ATTEMPTS, BIND_RETRY_INTERVAL));

    registry_service
}

/// Serve the metrics `app` on `socket_address`, riding out a transient bind
/// failure and then giving up loudly — never panicking.
async fn serve_metrics(
    app: Router,
    socket_address: SocketAddr,
    attempts: u32,
    retry_interval: Duration,
) {
    let Some(listener) = bind_with_retry("metrics", socket_address, attempts, retry_interval).await
    else {
        error!(
            address =% socket_address,
            "gave up binding the metrics server; the node continues without a metrics \
             endpoint and will not be scrapable"
        );
        return;
    };
    if let Err(err) = axum::serve(listener, app.into_make_service()).await {
        error!(
            address =% socket_address,
            error =? err,
            "metrics server stopped; the node continues without a metrics endpoint and \
             will not be scrapable"
        );
    }
}

pub struct IkaNodeMetrics {
    pub current_protocol_version: IntGauge,
    pub binary_max_protocol_version: IntGauge,
    pub configured_max_protocol_version: IntGauge,

    /// 1 while the prepare-then-start barrier is blocking the new epoch's
    /// MPC components on full verified handoff data; 0 otherwise. A value
    /// stuck at 1 is the dashboard signal that a validator is wedged
    /// waiting for handoff data and is not signing.
    pub handoff_prepare_waiting: IntGauge,
    /// Number of prepare-then-start barrier poll iterations spent waiting
    /// for handoff data.
    pub handoff_prepare_retries_total: IntCounter,
    /// Wall-clock seconds spent inside the prepare-then-start barrier.
    /// Observed only on successful barrier exit, so this trends the
    /// distribution of completed (possibly slow) waits — stuck-barrier
    /// alerting is `handoff_prepare_waiting` + `handoff_prepare_retries_total`.
    pub handoff_prepare_duration_seconds: Histogram,

    /// Joiner/anchor bootstrap cert-fetch outcomes, by outcome
    /// (`verified` / `rejected` / `unavailable`). `rejected` fail-closes
    /// the node, so its durable value is the `verified` epoch-cadence
    /// sanity check and `unavailable` wedge-cause attribution.
    pub joiner_bootstrap_outcomes_total: IntCounterVec,

    /// P2P mpc_data blob fetch outcomes, by result (`ok` / `not_found` /
    /// `hash_mismatch` / `decode_failed` / `cache_insert_failed` /
    /// `transport_error`). `decode_failed` is the announcer-byzantine
    /// signal; a high `transport_error` rate explains slow ready-signal
    /// coverage.
    pub mpc_data_blob_fetch_total: IntCounterVec,

    /// Sub-phase of the epoch-reconfiguration critical section while the
    /// reconfig watchdog is armed (see `reconfig_watchdog::phase`); 0
    /// outside it. Any nonzero value that persists is a node parked in the
    /// teardown-to-restart window (#1864), and the value names the hanging
    /// await.
    pub reconfig_phase: IntGauge,

    /// Seconds since this process last finished processing a consensus
    /// commit, while the commit-liveness watchdog is armed and running;
    /// `-1` while it is unarmed (no commit processed yet this process) or
    /// held (consensus torn down for reconfiguration, or the watchdog
    /// disabled). A healthy validator reads single-digit seconds. Sustained
    /// growth is the #1864 isolation signature — subscriptions gone in both
    /// directions with the process otherwise healthy — and the watchdog
    /// exits the node once it passes the bound. This is the in-node twin of
    /// the fleet-side staleness alert on
    /// `ika_consensus_last_committed_timestamp_seconds`, measured on the
    /// LOCAL clock instead of the consensus clock, so a validator replaying
    /// a backlog of old commits reads healthy here while it makes progress.
    pub consensus_commit_silence_seconds: IntGauge,
}

impl IkaNodeMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            current_protocol_version: register_int_gauge_with_registry!(
                "ika_current_protocol_version",
                "Current protocol version in this epoch",
                registry,
            )
            .unwrap(),
            binary_max_protocol_version: register_int_gauge_with_registry!(
                "ika_binary_max_protocol_version",
                "Max protocol version supported by this binary",
                registry,
            )
            .unwrap(),
            configured_max_protocol_version: register_int_gauge_with_registry!(
                "ika_configured_max_protocol_version",
                "Max protocol version configured in the node config",
                registry,
            )
            .unwrap(),
            handoff_prepare_waiting: register_int_gauge_with_registry!(
                "ika_handoff_prepare_waiting",
                "1 while the prepare-then-start barrier is blocking the new epoch's MPC \
                 components on full verified handoff data; 0 otherwise",
                registry,
            )
            .unwrap(),
            handoff_prepare_retries_total: register_int_counter_with_registry!(
                "ika_handoff_prepare_retries_total",
                "Number of prepare-then-start barrier poll iterations spent waiting for \
                 handoff data",
                registry,
            )
            .unwrap(),
            handoff_prepare_duration_seconds: register_histogram_with_registry!(
                "ika_handoff_prepare_duration_seconds",
                "Wall-clock seconds spent inside the prepare-then-start barrier",
                // Barrier waits are legitimately minutes (cert fetch + blob
                // convergence at the epoch boundary); the prometheus default
                // buckets top out at 10s and would collapse every slow exit
                // into +Inf.
                vec![
                    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0
                ],
                registry,
            )
            .unwrap(),
            joiner_bootstrap_outcomes_total: register_int_counter_vec_with_registry!(
                "ika_joiner_bootstrap_outcomes_total",
                "Joiner/anchor bootstrap cert-fetch outcomes",
                &["outcome"],
                registry,
            )
            .unwrap(),
            mpc_data_blob_fetch_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_data_blob_fetch_total",
                "P2P mpc_data blob fetch outcomes",
                &["result"],
                registry,
            )
            .unwrap(),
            reconfig_phase: register_int_gauge_with_registry!(
                "ika_reconfig_phase",
                "Sub-phase of the epoch-reconfiguration critical section while the reconfig \
                 watchdog is armed; 0 outside it",
                registry,
            )
            .unwrap(),
            consensus_commit_silence_seconds: register_int_gauge_with_registry!(
                "ika_consensus_commit_silence_seconds",
                "Seconds since this process last finished processing a consensus commit; -1 \
                 while the commit-liveness watchdog is unarmed, held for reconfiguration, or \
                 disabled",
                registry,
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind_retry::test_support::squatted_port;
    use prometheus::{IntCounter, Registry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    pub async fn test_metrics_endpoint_with_multiple_registries_add_remove() {
        let port: u16 = 8081;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        let registry_service = start_prometheus_server(socket);

        tokio::task::yield_now().await;

        // now add a few registries to the service along side with metrics
        let registry_1 = Registry::new_custom(Some("vendored".to_string()), None).unwrap();
        let counter_1 = IntCounter::new("counter_1", "a sample counter 1").unwrap();
        registry_1.register(Box::new(counter_1)).unwrap();

        let registry_2 = Registry::new_custom(Some("ika".to_string()), None).unwrap();
        let counter_2 = IntCounter::new("counter_2", "a sample counter 2").unwrap();
        registry_2.register(Box::new(counter_2.clone())).unwrap();

        let registry_1_id = registry_service.add(registry_1);
        let _registry_2_id = registry_service.add(registry_2);

        // request the endpoint
        let result = get_metrics(port).await;

        assert!(result.contains(
            "# HELP ika_counter_2 a sample counter 2
# TYPE ika_counter_2 counter
ika_counter_2 0"
        ));

        assert!(result.contains(
            "# HELP vendored_counter_1 a sample counter 1
# TYPE vendored_counter_1 counter
vendored_counter_1 0"
        ));

        // Now remove registry 1
        assert!(registry_service.remove(registry_1_id));

        // AND increase metric 2
        counter_2.inc();

        // Now pull again metrics
        // request the endpoint
        let result = get_metrics(port).await;

        // Registry 1 metrics should not be present anymore
        assert!(!result.contains(
            "# HELP vendored_counter_1 a sample counter 1
# TYPE vendored_counter_1 counter
vendored_counter_1 0"
        ));

        // Registry 2 metric should have increased by 1
        assert!(result.contains(
            "# HELP ika_counter_2 a sample counter 2
# TYPE ika_counter_2 counter
ika_counter_2 1"
        ));
    }

    async fn get_metrics(port: u16) -> String {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/metrics"))
            .send()
            .await
            .unwrap();
        response.text().await.unwrap()
    }

    /// A stand-in for the real metrics router: `serve_metrics` only ever sees
    /// an already-built `Router`, so the routes it carries are irrelevant to
    /// the bind path under test.
    fn test_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    async fn get_ping(address: SocketAddr) -> Option<String> {
        let response = reqwest::Client::new()
            .get(format!("http://{address}/ping"))
            .send()
            .await
            .ok()?;
        response.text().await.ok()
    }

    /// The node-side failure this guards: something already holds the metrics
    /// port, and the node dies at boot because the bind panicked on a runtime
    /// where panics are fatal — before telemetry is even initialized, so the
    /// death is close to silent. `serve_metrics` must exhaust its retries and
    /// return normally instead: the node runs on, minus the scrape endpoint.
    #[tokio::test]
    async fn a_squatted_metrics_port_does_not_take_the_node_down() {
        let (_squatter, address) = squatted_port().await;

        timeout(
            Duration::from_secs(30),
            serve_metrics(test_router(), address, 3, Duration::from_millis(50)),
        )
        .await
        .expect("a permanently squatted metrics port must be given up on, not waited on forever");
    }

    /// The retries ride out a transient squatter: once the port is released
    /// the metrics server comes up on its own, with no node restart.
    #[tokio::test]
    async fn the_metrics_server_comes_up_once_the_port_is_released() {
        let (squatter, address) = squatted_port().await;

        let server = tokio::spawn(serve_metrics(
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
        .expect("the metrics server must come up once the port is released");
        assert_eq!(body, "pong");

        server.abort();
    }

    /// `start_prometheus_server` must hand back a usable `RegistryService`
    /// even when the port can never be bound — the node keeps recording
    /// metrics into the registry, it just has nothing serving them.
    #[tokio::test]
    async fn a_squatted_port_still_yields_a_working_registry_service() {
        let (_squatter, address) = squatted_port().await;

        let registry_service = start_prometheus_server(address);
        let registry = Registry::new_custom(Some("ika".to_string()), None).unwrap();
        let counter = IntCounter::new("counter", "a sample counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        registry_service.add(registry);
        counter.inc();

        assert!(
            registry_service
                .gather_all()
                .iter()
                .any(|family| family.name() == "ika_counter"),
            "the registry service must keep collecting even with no server bound"
        );
    }
}
