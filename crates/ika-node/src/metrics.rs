// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};

pub struct IkaNodeMetrics {
    pub current_protocol_version: IntGauge,
    pub binary_max_protocol_version: IntGauge,
    pub configured_max_protocol_version: IntGauge,
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
        let registry_1 = Registry::new_custom(Some("narwhal".to_string()), None).unwrap();
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
            "# HELP narwhal_counter_1 a sample counter 1
# TYPE narwhal_counter_1 counter
narwhal_counter_1 0"
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
            "# HELP narwhal_counter_1 a sample counter 1
# TYPE narwhal_counter_1 counter
narwhal_counter_1 0"
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
