// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, Registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};

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
        }
    }
}

#[cfg(test)]
mod tests {
    use mysten_metrics::start_prometheus_server;
    use prometheus::{IntCounter, Registry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
}
