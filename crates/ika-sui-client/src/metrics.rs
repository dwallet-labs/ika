// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::error::IkaError;
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

/// The `kind` label of [`SuiClientMetrics::sui_response_errors`] — *why* a read
/// failed once the Sui RPC had already answered it.
///
/// Closed set, and deliberately small: the label's whole job is to let one
/// panel say "this is a decoding/data bug" instead of "Sui is down", so it
/// needs enough resolution to point at a code path and no more. Every variant
/// corresponds to at least one increment site in [`crate::SuiClient`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiResponseErrorKind {
    /// The response bytes did not deserialize (BCS).
    Decode,
    /// The RPC answered, but the record we asked about is not in the answer —
    /// e.g. a committee member with no row in the fetched validator set.
    NotFound,
    /// The record is present but a field/table entry the caller requires is
    /// absent — e.g. an active committee member with no `mpc_data` row.
    MissingField,
    /// A `StakingPool`'s on-chain validator metadata (keys, addresses) is
    /// present but does not parse.
    ///
    /// **Effectively unreachable against the gRPC backend, and pre-existing.**
    /// `get_epoch_start_system` calls `get_mpc_data_from_validators_pool`
    /// before its committee-member loop, and that backend method runs
    /// `verified_validator_info()` over the same validator set
    /// (`grpc_backend.rs`), short-circuiting on the first failure. So the
    /// identical defect surfaces one call earlier, collapsed into
    /// `SuiClientInternalError`, and is counted on `sui_rpc_errors` — the
    /// residual described on [`SuiClientMetrics::sui_rpc_errors`]. The
    /// synthetic `epoch_start_invalid_validator_info` label this replaced was
    /// dead for exactly the same reason. Kept because the site is real, the
    /// shadowing is a property of one backend, and a kind that exists costs
    /// nothing until it fires.
    ValidatorInfoParse,
    /// A frozen committee member's BLS protocol public key does not parse.
    /// Kept apart from [`Self::ValidatorInfoParse`] because the two read from
    /// different on-chain sources (the committee snapshot vs. the validator
    /// record), which is the first thing you need to know when one fires.
    InvalidCommitteePubkeyParse,
    /// A retry wrapper gave up on a read that failed with
    /// [`IkaError::InvalidCommittee`]. The precise kind was already recorded
    /// by the site inside the read that produced the error; this is the
    /// coarser once-per-retry-round re-count, which is all the wrapper can
    /// see.
    InvalidCommittee,
}

impl SuiResponseErrorKind {
    /// The `kind` label value. Stable — dashboards and alerts match on these.
    pub fn label(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::NotFound => "not_found",
            Self::MissingField => "missing_field",
            Self::ValidatorInfoParse => "validator_info_parse",
            Self::InvalidCommitteePubkeyParse => "committee_pubkey_parse",
            Self::InvalidCommittee => "invalid_committee",
        }
    }

    /// Classify a read that already came back as an [`IkaError`]: `Some(kind)`
    /// if Sui answered and the answer was unusable, `None` if the RPC itself
    /// is what failed.
    ///
    /// Used where the only thing in hand is the terminal error — the
    /// `must_get_*` retry wrappers, which sit above a read that may have
    /// failed for either reason and would otherwise re-count every decoding
    /// bug as an RPC outage once per retry round. The backoff runs
    /// 0.4+0.8+1.6+3.2+6.4+12.8s and the 7th check exceeds the 30s budget, so
    /// a round is ~25.2s: ~143 wrapper increments/hour while the failure
    /// persists, above the fleet's RPC-error alert threshold on its own.
    ///
    /// The catch-all arm resolves to "RPC failure", i.e. the historical
    /// behaviour, so a variant added later keeps landing on the counter it
    /// lands on today rather than silently changing an alert's meaning.
    pub fn classify(error: &IkaError) -> Option<Self> {
        match error {
            IkaError::SuiClientSerializationError(_) => Some(Self::Decode),
            IkaError::InvalidCommittee(_) => Some(Self::InvalidCommittee),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SuiClientMetrics {
    /// Failures of the Sui RPC *transport*: the call did not come back with an
    /// answer. Name, labels and help are unchanged since 1.2.0 and must stay
    /// that way — this is the counter the fleet's Sui-uplink alerting is built
    /// on, and its healthy baseline (0–6/hour) is what makes it a usable lead
    /// indicator for a boot wedge.
    ///
    /// Failures where Sui *did* answer and the answer was unusable belong on
    /// [`Self::sui_response_errors`]; mixing the two is what made an outage and
    /// a decoding bug indistinguishable here (ika #2116 follow-up).
    ///
    /// # Known residual
    ///
    /// The split is clean in one direction only: nothing that reaches
    /// [`Self::sui_response_errors`] is a transport failure. The reverse does
    /// not hold. Every `self.inner.*` call in [`crate::SuiClient`] collapses
    /// its backend error into `IkaError::SuiClientInternalError` before the
    /// counter sees it, and the backend errors it collapses include genuine
    /// bad-payload cases — `GrpcSuiClientError::Decode` (a fetched object that
    /// is not a `MoveObject`, a `decode_chain_mirror` failure, an unparsable
    /// validator record) and `TransportError::Encoding` (a response with no
    /// `object.bcs`, an `Object` that will not decode). Those still land here.
    ///
    /// Left alone deliberately: fixing it means changing error *variants*
    /// across the backend rather than moving an increment site, and it would
    /// shift the calibration of the fleet's rate alert on this counter. Read a
    /// spike here as "the uplink is unhealthy" — usually true, occasionally
    /// "the uplink answered with something we could not read".
    pub sui_rpc_errors: IntCounterVec,
    /// Failures of reads whose RPC **succeeded** and whose response could not
    /// be used: BCS decode failures, a committee member missing from a fetched
    /// validator set, unparsable on-chain key material, an absent `mpc_data`
    /// record.
    ///
    /// Every one of these is a defect in ika's own data or decoding path (or in
    /// what is on chain), not in the operator's fullnode — the opposite
    /// on-call response from [`Self::sui_rpc_errors`], which is why they cannot
    /// share a counter.
    ///
    /// # Cardinality
    ///
    /// `method` is the client method name, from the same closed set as
    /// `sui_rpc_errors`; `kind` is [`SuiResponseErrorKind`], six values. Ten
    /// `(method, kind)` pairs are reachable today — six from sites that name
    /// their own kind, four more from the three `must_get_*` wrappers, which
    /// can only reach `decode` and `invalid_committee`.
    ///
    /// # No zero baseline
    ///
    /// Deliberately not pre-registered at `0`, unlike
    /// [`Self::sui_rate_limited_errors`]. The pairs are a cross product that
    /// only the increment sites know, so seeding them means a second hand-kept
    /// list of exactly the kind this repo's metric conventions exist to avoid —
    /// and the counter it splits off from has no zero baseline either, so a
    /// companion alert is written the same way its sibling already is.
    pub sui_response_errors: IntCounterVec,
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
            sui_response_errors: register_int_counter_vec_with_registry!(
                "ika_sui_client_sui_response_errors_total",
                "Total number of sui RPC calls that answered but whose response could not be used, by RPC method and failure kind",
                &["method", "kind"],
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

    /// Record one failure of `method` whose RPC succeeded and whose response
    /// was unusable. Never touches [`Self::sui_rpc_errors`].
    pub fn record_response_error(&self, method: &str, kind: SuiResponseErrorKind) {
        self.sui_response_errors
            .with_label_values(&[method, kind.label()])
            .inc();
    }

    /// Record one failed read of `method`, routing it to the counter its cause
    /// belongs to: [`Self::sui_response_errors`] when Sui answered and the
    /// answer was unusable, [`Self::sui_rpc_errors`] otherwise.
    ///
    /// For call sites that hold only the terminal [`IkaError`] and cannot see
    /// which of the two happened — the `must_get_*` retry wrappers. A site
    /// that *knows* it is looking at a bad response (a `bcs::from_bytes` arm,
    /// say) should call [`Self::record_response_error`] with the precise kind
    /// instead.
    pub fn record_read_error(&self, method: &str, error: &IkaError) {
        match SuiResponseErrorKind::classify(error) {
            Some(kind) => self.record_response_error(method, kind),
            None => self.sui_rpc_errors.with_label_values(&[method]).inc(),
        }
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
