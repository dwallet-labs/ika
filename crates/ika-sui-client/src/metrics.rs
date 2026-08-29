// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    IntCounterVec, IntGauge, IntGaugeVec, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Label value published on [`SuiClientMetrics::sui_node_info`] from process
/// start until the node's `GetServiceInfo` first answers. A validator whose
/// series is *still* on this label is the signal: its Sui uplink has never
/// once told us what it is.
pub const SUI_NODE_INFO_UNKNOWN: &str = "unknown";

/// Label value for a client whose transport has no service-info RPC at all —
/// a peer-only validator reading Sui through the Ika p2p mirror relay. There
/// is no operator fullnode on the other end to have a version, so this is a
/// *healthy* terminal state and must not be read as `unknown`.
pub const SUI_NODE_INFO_UNSUPPORTED: &str = "unsupported";

/// Label value for a node that answered `GetServiceInfo` but left the field
/// empty (both fields are `optional` in the proto, and a proxy in front of a
/// fullnode can strip them). Distinct from `unknown`: the RPC works.
pub const SUI_NODE_INFO_UNREPORTED: &str = "unreported";

/// Process-wide counter for chain-side calls to
/// `get_network_encryption_key_with_full_data_by_epoch`. Test
/// suites that need to assert the off-chain pipeline isn't
/// silently re-reading the heavy DKG / reconfig output blobs from
/// chain inspect this counter directly. Production code uses the
/// per-`SuiClient` Prometheus counter on `SuiClientMetrics`.
pub static CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA: AtomicU64 = AtomicU64::new(0);

/// Process-wide counter for chain-side calls to
/// `get_mpc_data_from_validators_pool`. Mirrors the rationale of
/// [`CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA`] for the validator
/// mpc_data fallback path.
pub static CHAIN_BLOB_READ_MPC_DATA_FROM_VALIDATORS_POOL: AtomicU64 = AtomicU64::new(0);

/// Snapshot of both process-wide counters. Used by the off-chain
/// cluster test to capture a baseline before exercising the
/// scenario and re-check after.
pub fn chain_blob_read_counts() -> (u64, u64) {
    (
        CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA.load(Ordering::Relaxed),
        CHAIN_BLOB_READ_MPC_DATA_FROM_VALIDATORS_POOL.load(Ordering::Relaxed),
    )
}

#[derive(Clone, Debug)]
pub struct SuiClientMetrics {
    pub sui_rpc_errors: IntCounterVec,
    /// Counts on-chain reads of the heavy blob fields backed by
    /// `mpc_data` / network-key / reconfig outputs. Each label is the
    /// name of a method that performs a chain-side blob fetch. Used by
    /// the off-chain validator-metadata test path to assert that the
    /// off-chain pipeline genuinely sources these blobs from
    /// consensus + P2P rather than re-reading them from chain.
    pub chain_blob_reads: IntCounterVec,
    /// Upstream Sui responses classified as rate limiting (HTTP 429 / gRPC
    /// `RESOURCE_EXHAUSTED`) by [`crate::rate_limit`]. Labelled by which signal
    /// identified it: `grpc_code` for the canonical gRPC code, `message_marker`
    /// for the message-text heuristic that is the only surviving evidence when
    /// an HTTP gateway answers 429 (tonic maps that to `Code::Unavailable`).
    ///
    /// Steady-state non-zero means the node's read load is exceeding what its
    /// configured endpoint will serve, and its own retries are part of what
    /// keeps the endpoint refusing. Fleet-wide this should be flat at zero;
    /// growth on a single node points at that node's endpoint, not at ika.
    pub sui_rate_limited_errors: IntCounterVec,
    /// Info-style gauge (always `1` on exactly one child) identifying the Sui
    /// fullnode this validator's uplink is pointed at: `server_version` is the
    /// node's own software version string, `chain_identifier` its genesis
    /// digest.
    ///
    /// # Why
    ///
    /// Two mainnet validators wedged in early boot at consecutive epoch
    /// boundaries (2026-08-28 and 08-29). Both had their own Sui fullnode's
    /// RPC failing for hours beforehand — one at ~440 errors/hour, the other
    /// ~316, against a fleet baseline of 0–6. The leading hypothesis for the
    /// first is simply that the operator never upgraded their Sui node across
    /// a Sui release rollout. We could not confirm or refute that, because
    /// nothing anywhere in the fleet's telemetry says which Sui version a
    /// validator is talking to: `sui_rpc_errors` tells us an uplink is
    /// unhealthy, never *what* is on the other end of it. This gauge closes
    /// that gap — one `group by (server_version)` over the fleet shows the
    /// version spread and singles out the operator who is behind.
    ///
    /// # Semantics
    ///
    /// Registered eagerly with `server_version="unknown"` at `1`, so a node
    /// that never gets an answer still publishes a series — a validator stuck
    /// on `unknown` is itself the signal that its Sui RPC never replied.
    /// Refreshes never *remove* a child, they flip the old one to `0` and the
    /// new one to `1`, so a version change reads as a clean 1→0 / 0→1
    /// transition across a scrape gap instead of a disappearing series.
    ///
    /// # Cardinality
    ///
    /// One child at `1` per node at a time, plus one retired child at `0` per
    /// version the node has ever reported — in practice one or two per
    /// process lifetime, since an operator's Sui version changes only when
    /// they upgrade and the process restarts on ours. Negligible.
    pub sui_node_info: IntGaugeVec,
    /// Unix seconds of the last successful `GetServiceInfo`; `0` until the
    /// first one lands.
    ///
    /// Freshness companion to [`Self::sui_node_info`], which on its own cannot
    /// distinguish "this really is the version, confirmed minutes ago" from
    /// "this was the version hours ago and the RPC has been dead since" — the
    /// info gauge holds its last known value by design. `0` additionally
    /// separates "never answered" from "answered once and went stale", which
    /// matters because a boot-time wedge produces the former and a mid-life
    /// failure the latter.
    ///
    /// Left at `0` forever on a peer-only node (see
    /// [`SUI_NODE_INFO_UNSUPPORTED`]) — there is nothing to refresh, so pair
    /// any staleness query with `server_version != "unsupported"`.
    pub sui_node_info_last_success_unixtime: IntGauge,
    /// The `(server_version, chain_identifier)` pair currently published at
    /// `1`. Held so a refresh can flip exactly the previous child to `0`
    /// without enumerating (or resetting) the vec.
    active_sui_node_info: Arc<Mutex<[String; 2]>>,
}

impl SuiClientMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            sui_rpc_errors: register_int_counter_vec_with_registry!(
                "ika_sui_client_sui_rpc_errors",
                "Total number of errors from sui RPC, by RPC method",
                &["method"],
                registry,
            )
            .unwrap(),
            chain_blob_reads: register_int_counter_vec_with_registry!(
                "ika_sui_client_chain_blob_reads",
                "Total chain-side blob reads (mpc_data, network DKG output, reconfig output)",
                &["method"],
                registry,
            )
            .unwrap(),
            sui_rate_limited_errors: register_int_counter_vec_with_registry!(
                "ika_sui_client_rate_limited_errors_total",
                "Total upstream Sui responses classified as rate limiting (HTTP 429 / gRPC RESOURCE_EXHAUSTED), by classifying signal",
                &["signal"],
                registry,
            )
            .unwrap(),
            sui_node_info: register_int_gauge_vec_with_registry!(
                "ika_sui_client_sui_node_info",
                "Info gauge (always 1) identifying the Sui fullnode this validator's uplink is connected to, by its reported server version and chain id",
                &["server_version", "chain_identifier"],
                registry,
            )
            .unwrap(),
            sui_node_info_last_success_unixtime: register_int_gauge_with_registry!(
                "ika_sui_client_sui_node_info_last_success_unixtime",
                "Unix seconds of the last successful Sui GetServiceInfo call; 0 until the first one succeeds",
                registry,
            )
            .unwrap(),
            active_sui_node_info: Arc::new(Mutex::new([
                SUI_NODE_INFO_UNKNOWN.to_string(),
                SUI_NODE_INFO_UNKNOWN.to_string(),
            ])),
        };
        // Publish both series from process start so a dashboard/alert can tell
        // "no rate limiting" apart from "this node never reported".
        for signal in [
            crate::rate_limit::RateLimitSignal::GrpcCode,
            crate::rate_limit::RateLimitSignal::MessageMarker,
        ] {
            this.sui_rate_limited_errors
                .with_label_values(&[signal.label()])
                .inc_by(0);
        }
        // Same reasoning, one step stronger: the `unknown` child is not just a
        // zero placeholder, it is the value that stays at 1 for a node whose
        // Sui RPC never answers. It has to exist before the first refresh —
        // which for a wedged node is a refresh that never completes.
        this.sui_node_info
            .with_label_values(&[SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN])
            .set(1);
        this.sui_node_info_last_success_unixtime.set(0);
        Arc::new(this)
    }

    pub fn new_for_testing() -> Arc<Self> {
        let registry = Registry::new();
        Self::new(&registry)
    }

    /// Publish a fresh `GetServiceInfo` answer: flip the previously-active
    /// child of [`Self::sui_node_info`] to `0`, the new one to `1`, and stamp
    /// [`Self::sui_node_info_last_success_unixtime`].
    ///
    /// Re-reporting the same pair is the common case (the version only changes
    /// when the operator upgrades) and is cheap: it re-asserts `1` and
    /// re-stamps the freshness gauge without touching any other child.
    pub fn set_sui_node_info(&self, server_version: Option<&str>, chain_identifier: Option<&str>) {
        self.flip_sui_node_info(
            server_version.unwrap_or(SUI_NODE_INFO_UNREPORTED),
            chain_identifier.unwrap_or(SUI_NODE_INFO_UNREPORTED),
        );
        self.sui_node_info_last_success_unixtime
            .set(unix_seconds_now());
    }

    /// Mark this client's uplink as having no service-info RPC — a peer-only
    /// validator reading through the p2p mirror relay.
    ///
    /// Deliberately does *not* stamp the freshness gauge: there is no fullnode
    /// to be fresh about, and leaving it at `0` keeps "never answered" and
    /// "cannot answer" apart in queries by the label alone.
    pub fn set_sui_node_info_unsupported(&self) {
        self.flip_sui_node_info(SUI_NODE_INFO_UNSUPPORTED, SUI_NODE_INFO_UNSUPPORTED);
    }

    fn flip_sui_node_info(&self, server_version: &str, chain_identifier: &str) {
        // A poisoned lock here carries no invariant worth propagating — the
        // guarded value is two label strings — and this runs on a background
        // refresh whose whole contract is to never disturb the client.
        let mut active = self
            .active_sui_node_info
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active[0] != server_version || active[1] != chain_identifier {
            self.sui_node_info
                .with_label_values(&[active[0].as_str(), active[1].as_str()])
                .set(0);
            *active = [server_version.to_string(), chain_identifier.to_string()];
        }
        self.sui_node_info
            .with_label_values(&[server_version, chain_identifier])
            .set(1);
    }
}

fn unix_seconds_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
