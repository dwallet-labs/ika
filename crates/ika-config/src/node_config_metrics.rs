// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::NodeConfig;
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};
use std::sync::Arc;

#[allow(unused)]
pub struct NodeConfigMetrics {
    tx_deny_config_user_transaction_disabled: IntGauge,
    tx_deny_config_shared_object_disabled: IntGauge,
    tx_deny_config_package_publish_disabled: IntGauge,
    tx_deny_config_package_upgrade_disabled: IntGauge,
    tx_deny_config_num_denied_objects: IntGauge,
    tx_deny_config_num_denied_packages: IntGauge,
    tx_deny_config_num_denied_addresses: IntGauge,
}

impl NodeConfigMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            tx_deny_config_user_transaction_disabled: register_int_gauge_with_registry!(
                "tx_deny_config_user_transaction_disabled",
                "Whether all user transactions are disabled",
                registry
            )
            .unwrap(),
            tx_deny_config_shared_object_disabled: register_int_gauge_with_registry!(
                "tx_deny_config_shared_object_disabled",
                "Whether all shared object transactions are disabled",
                registry
            )
            .unwrap(),
            tx_deny_config_package_publish_disabled: register_int_gauge_with_registry!(
                "tx_deny_config_package_publish_disabled",
                "Whether all package publish transactions are disabled",
                registry
            )
            .unwrap(),
            tx_deny_config_package_upgrade_disabled: register_int_gauge_with_registry!(
                "tx_deny_config_package_upgrade_disabled",
                "Whether all package upgrade transactions are disabled",
                registry
            )
            .unwrap(),
            tx_deny_config_num_denied_objects: register_int_gauge_with_registry!(
                "tx_deny_config_num_denied_objects",
                "Number of denied objects",
                registry
            )
            .unwrap(),
            tx_deny_config_num_denied_packages: register_int_gauge_with_registry!(
                "tx_deny_config_num_denied_packages",
                "Number of denied packages",
                registry
            )
            .unwrap(),
            tx_deny_config_num_denied_addresses: register_int_gauge_with_registry!(
                "tx_deny_config_num_denied_addresses",
                "Number of denied addresses",
                registry
            )
            .unwrap(),
        };
        Arc::new(this)
    }

    pub fn record_metrics(&self, _config: &NodeConfig) {}
}
