// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::NodeConfig;
use prometheus::Registry;
use std::sync::Arc;

pub struct NodeConfigMetrics {}

impl NodeConfigMetrics {
    pub fn new(_registry: &Registry) -> Arc<Self> {
        let this = Self {};
        Arc::new(this)
    }

    pub fn record_metrics(&self, _config: &NodeConfig) {}
}
