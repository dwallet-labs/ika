// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use once_cell::sync::OnceCell;
use prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};

static INVARIANT_VIOLATIONS_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
static AUTHORITY_NAME_ENCODING_WIDTH: OnceCell<IntGauge> = OnceCell::new();
static HANDOFF_ATTESTATION_WIDTH_RETRY_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();

/// Outcome labels for [`record_handoff_attestation_width_retry`]. Bounded to
/// two by construction — the retry either rescues the verification or does not.
pub const WIDTH_RETRY_RECOVERED: &str = "recovered";
pub const WIDTH_RETRY_EXHAUSTED: &str = "exhausted";

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

/// Registers the `AuthorityName` wire-width metrics.
///
/// Both exist because the width is a PROCESS-WIDE property with no other
/// readout: a validator emitting the wrong width computes different digests
/// and is rejected by its peers while parsing their messages perfectly, so the
/// condition presents as unexplained rejection rather than as anything naming
/// an encoding. During the v6→v7 activation this was diagnosable only by
/// inference from what did not break.
pub fn init_authority_name_width_metrics(registry: &Registry) {
    AUTHORITY_NAME_ENCODING_WIDTH.get_or_init(|| {
        register_int_gauge_with_registry!(
            "ika_authority_name_encoding_width_bytes",
            "Wire width in bytes this process serializes AuthorityName at: 48 \
             (zero-padded, pre-v7) or 32 (raw consensus key, v7+). The fleet \
             must agree — two distinct values across hosts is a split",
            registry,
        )
        .expect("authority name width gauge registration must succeed")
    });
    HANDOFF_ATTESTATION_WIDTH_RETRY_TOTAL.get_or_init(|| {
        register_int_counter_vec_with_registry!(
            "ika_handoff_attestation_width_retry_total",
            "Handoff-attestation verifications that fell back to the other \
             AuthorityName width, by outcome",
            &["outcome"],
            registry,
        )
        .expect("handoff width retry metric registration must succeed")
    });
}

#[doc(hidden)]
pub fn record_invariant_violation(site: &'static str) {
    if let Some(metric) = INVARIANT_VIOLATIONS_TOTAL.get() {
        metric.with_label_values(&[site]).inc();
    }
}

/// Publishes the wire width this process is serializing `AuthorityName` at.
///
/// Called from the one place the width is set, so every path is covered —
/// including the test-only inversion fault, which is the point: a gate that
/// injects a width straggler should be able to SEE the straggler.
pub fn record_authority_name_encoding_width(short: bool) {
    if let Some(metric) = AUTHORITY_NAME_ENCODING_WIDTH.get() {
        metric.set(if short { 32 } else { 48 });
    }
}

/// Records that a handoff-attestation verification retried at the other width.
///
/// `recovered` is the expected shape at an activation boundary and exactly
/// once: the cert is signed at the end of epoch N under the old width and
/// verified in N+1 under the new one. Anywhere else it means two validators
/// disagree about the width mid-epoch. `exhausted` means neither width
/// verified, i.e. the cert is bad for reasons that have nothing to do with
/// encoding — worth separating so the retry is not blamed for it.
pub fn record_handoff_attestation_width_retry(outcome: &'static str) {
    if let Some(metric) = HANDOFF_ATTESTATION_WIDTH_RETRY_TOTAL.get() {
        metric.with_label_values(&[outcome]).inc();
    }
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

    /// The width metrics live behind a process-global `OnceCell`, so every
    /// test in this binary has to share the registry it was initialised with —
    /// a second `init_*` call with a fresh registry is silently a no-op, and
    /// the metrics keep reporting into the first one.
    fn width_metrics_registry() -> &'static Registry {
        static REGISTRY: once_cell::sync::OnceCell<Registry> = once_cell::sync::OnceCell::new();
        REGISTRY.get_or_init(|| {
            let registry = Registry::new();
            super::init_authority_name_width_metrics(&registry);
            registry
        })
    }

    /// The gauge must report the WIDTH IN BYTES, not a boolean, and must
    /// follow the setter rather than the protocol version — a validator on the
    /// wrong width is exactly the case where those two disagree, and it is the
    /// only case this metric exists to catch.
    #[test]
    fn authority_name_width_gauge_reports_the_wire_width() {
        let registry = width_metrics_registry();

        let width = || {
            registry
                .gather()
                .into_iter()
                .find(|f| f.name() == "ika_authority_name_encoding_width_bytes")
                .expect("width gauge must be exported")
                .get_metric()[0]
                .get_gauge()
                .value()
        };

        crate::crypto::set_authority_name_short_encoding(false);
        assert_eq!(width(), 48.0, "pre-v7 emits the zero-padded 48-byte form");
        crate::crypto::set_authority_name_short_encoding(true);
        assert_eq!(width(), 32.0, "v7+ emits the raw 32-byte consensus key");
        // Restore, so this test cannot leak a width into any other test in the
        // process — the value is a process-wide global by design.
        crate::crypto::set_authority_name_short_encoding(false);
        assert_eq!(width(), 48.0);
    }

    /// `recovered` and `exhausted` must land on separate series. Collapsing
    /// them would make a bad certificate look like an encoding straddle, which
    /// is the one confusion this counter exists to prevent.
    #[test]
    fn handoff_width_retry_counter_separates_recovery_from_a_bad_cert() {
        let registry = width_metrics_registry();
        assert!(
            registry
                .gather()
                .iter()
                .all(|f| f.name() != "ika_handoff_attestation_width_retry_total"),
            "no series before a retry actually happens — absent is not zero"
        );

        super::record_handoff_attestation_width_retry(super::WIDTH_RETRY_RECOVERED);
        super::record_handoff_attestation_width_retry(super::WIDTH_RETRY_RECOVERED);
        super::record_handoff_attestation_width_retry(super::WIDTH_RETRY_EXHAUSTED);

        let by_outcome: std::collections::HashMap<String, f64> = registry
            .gather()
            .into_iter()
            .find(|f| f.name() == "ika_handoff_attestation_width_retry_total")
            .expect("retry counter must be exported")
            .get_metric()
            .iter()
            .map(|m| {
                (
                    m.get_label()[0].value().to_string(),
                    m.get_counter().value(),
                )
            })
            .collect();
        assert_eq!(by_outcome.get("recovered"), Some(&2.0));
        assert_eq!(by_outcome.get("exhausted"), Some(&1.0));
    }
}
