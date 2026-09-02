// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use once_cell::sync::OnceCell;
use prometheus::{IntCounterVec, Registry, register_int_counter_vec_with_registry};

static INVARIANT_VIOLATIONS_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
pub fn init_invariant_violation_metric(registry: &Registry) {
    INVARIANT_VIOLATIONS_TOTAL.get_or_init(|| {
        register_int_counter_vec_with_registry!(
            "ika_invariant_violations_total",
            "Invariant violations that should never happen, by bounded call-site identifier",
            &["site"],
            registry,
        )
        .expect("invariant violation metric registration must succeed")
    });
}

#[doc(hidden)]
pub fn record_invariant_violation(site: &'static str) {
    if let Some(metric) = INVARIANT_VIOLATIONS_TOTAL.get() {
        metric.with_label_values(&[site]).inc();
    }
}

/// Current value of the invariant-violation counter for `site`, or `None`
/// when [`init_invariant_violation_metric`] has not run in this process.
///
/// Read-back for tests and diagnostics only — nothing in production reads
/// the counter. Integration tests use it to assert that a retired
/// invariant site stays retired: naming a site that never fires keeps the
/// assertion pinned to that site instead of to whatever else the run
/// happened to report.
pub fn invariant_violation_count(site: &str) -> Option<u64> {
    INVARIANT_VIOLATIONS_TOTAL
        .get()
        .map(|metric| metric.with_label_values(&[site]).get())
}

/// Records a broken invariant in both Prometheus and the structured logs.
///
/// The site must be a literal so the `site` label's cardinality is bounded by
/// the number of call sites in the binary.
#[macro_export]
macro_rules! report_invariant_violation {
    ($site:literal, $($field:tt)+) => {{
        $crate::metrics::record_invariant_violation($site);
        tracing::error!(should_never_happen = true, $($field)+);
    }};
}

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

#[cfg(test)]
mod tests {
    use prometheus::Registry;

    use super::init_invariant_violation_metric;

    #[test]
    fn invariant_violation_macro_increments_only_for_marked_events() {
        let registry = Registry::new();
        init_invariant_violation_metric(&registry);
        assert!(
            registry
                .gather()
                .iter()
                .all(|family| family.name() != "ika_invariant_violations_total"),
            "counter vector must not export a series before a site fires"
        );

        crate::report_invariant_violation!("metrics_test", "marked event");
        tracing::error!("ordinary error");

        let metric_family = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "ika_invariant_violations_total")
            .expect("invariant violation metric must be exported");
        let metric = metric_family.get_metric();
        assert_eq!(metric.len(), 1);
        assert_eq!(metric[0].get_counter().value(), 1.0);
        assert_eq!(metric[0].get_label()[0].value(), "metrics_test");
    }
}
