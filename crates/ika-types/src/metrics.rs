// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub struct LimitsMetrics {}

impl LimitsMetrics {
    pub fn new(_registry: &prometheus::Registry) -> LimitsMetrics {
        Self {}
    }
}

pub struct BytecodeVerifierMetrics {}

impl BytecodeVerifierMetrics {
    /// DEPRECATED in latest metered verifier, which only report overall success or timeout.
    pub const MOVE_VERIFIER_TAG: &'static str = "move_verifier";

    /// DEPRECATED in latest metered verifier, which only report overall success or timeout.
    pub const IKA_VERIFIER_TAG: &'static str = "ika_verifier";

    pub const OVERALL_TAG: &'static str = "overall";
    pub const SUCCESS_TAG: &'static str = "success";
    pub const TIMEOUT_TAG: &'static str = "failed";
    pub fn new(_registry: &prometheus::Registry) -> Self {
        Self {}
    }
}
