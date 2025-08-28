// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    IntGauge, IntGaugeVec, Registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use std::sync::Arc;

#[allow(unused)]
const FINE_GRAINED_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9,
    1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 6.5, 7.0, 7.5, 8.0, 8.5, 9.0, 9.5,
    10., 15., 20., 25., 30., 35., 40., 45., 50., 60., 70., 80., 90., 100., 120., 140., 160., 180.,
    200., 250., 300., 350., 400.,
];

#[derive(Clone, Debug)]
pub struct SuiConnectorMetrics {
    pub last_synced_sui_checkpoints: IntGaugeVec,

    pub gas_coin_balance: IntGauge,

    /// Sequence number of the next dwallet checkpoint to write to Sui.
    pub(crate) dwallet_checkpoint_sequence: IntGauge,

    /// Sequence number of the last dwallet checkpoint successfully written to Sui.
    pub(crate) last_written_dwallet_checkpoint_sequence: IntGauge,

    /// Total number of dwallet checkpoint write requests sent to Sui.
    pub(crate) dwallet_checkpoint_write_requests_total: IntGauge,

    /// Total number of successful dwallet checkpoint writes to Sui.
    pub(crate) dwallet_checkpoint_writes_success_total: IntGauge,

    /// Total number of failed dwallet checkpoint writes to Sui.
    pub(crate) dwallet_checkpoint_writes_failure_total: IntGauge,

    /// Sequence number of the next dwallet checkpoint to write to Sui.
    pub(crate) system_checkpoint_sequence: IntGauge,

    /// Sequence number of the last system checkpoint successfully written to Sui.
    pub(crate) last_written_system_checkpoint_sequence: IntGauge,

    /// Total number of system checkpoint write requests sent to Sui.
    pub(crate) system_checkpoint_write_requests_total: IntGauge,

    /// Total number of successful system checkpoint writes to Sui.
    pub(crate) system_checkpoint_writes_success_total: IntGauge,

    /// Total number of failed system checkpoint writes to Sui.
    pub(crate) system_checkpoint_writes_failure_total: IntGauge,
}

impl SuiConnectorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            last_synced_sui_checkpoints: register_int_gauge_vec_with_registry!(
                "sui_connector_last_synced_sui_checkpoints",
                "The latest sui checkpoints synced for each module",
                &["module_name"],
                registry,
            )
            .unwrap(),
            gas_coin_balance: register_int_gauge_with_registry!(
                "sui_connector_gas_coin_balance",
                "Current balance of gas coin, in mist",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_sequence",
                "Sequence number of the next dwallet checkpoint to write to Sui",
                registry,
            )
            .unwrap(),

            last_written_dwallet_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_last_written_dwallet_checkpoint_sequence",
                "Sequence number of the last dwallet checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_write_requests_total",
                "Total number of dwallet checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_writes_success_total",
                "Total number of successful dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),

            dwallet_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "sui_connector_dwallet_checkpoint_writes_failure_total",
                "Total number of failed dwallet checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_failure_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_writes_failure_total",
                "Total number of failed system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_writes_success_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_writes_success_total",
                "Total number of successful system checkpoint writes to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_write_requests_total: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_write_requests_total",
                "Total number of system checkpoint write requests sent to Sui",
                registry,
            )
            .unwrap(),
            system_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_system_checkpoint_sequence",
                "Sequence number of the next system checkpoint to write to Sui",
                registry,
            )
            .unwrap(),
            last_written_system_checkpoint_sequence: register_int_gauge_with_registry!(
                "sui_connector_last_written_system_checkpoint_sequence",
                "Sequence number of the last system checkpoint successfully written to Sui",
                registry,
            )
            .unwrap(),
        };
        Arc::new(this)
    }

    pub fn new_for_testing() -> Arc<Self> {
        let registry = Registry::new();
        Self::new(&registry)
    }
}
