// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Rate-limit classification and the node's single shared admission gate for
//! the direct Sui uplink.
//!
//! # Why this exists
//!
//! Nearly every component that reads Sui converges on one
//! [`crate::grpc::SuiGrpcClient`] (see `ika_core::sui_connector::setup`): the
//! committee ratchet, the `LocalProofProvider` under the verified reader (and
//! therefore the bag event pump), and the checkpoint pusher all hold the *same*
//! `Arc`. Each of them has its own retry loop with its own backoff, and none of
//! them knows about the others. When the upstream endpoint starts refusing
//! requests — a shared or metered Sui endpoint answering HTTP 429 — every one
//! of those loops independently retries, and their combined rate is what keeps
//! the endpoint throttling. The retries are the reason the throttle does not
//! lift.
//!
//! So the throttle-awareness belongs *below* all of them, at the one place they
//! already share: the client. One [`RateLimitGate`] there makes the whole node
//! back off as a unit, and no component has to grow its own 429 handling.
//!
//! One caveat the gate has to handle explicitly: a node opens **two** gRPC
//! clients against the same endpoint — the connector stack's read client and
//! the notifier's read/write `SuiClient` (which the pubkey-provider updater and
//! the syncer also poll through). Two clients with two gates would still retry
//! through each other's cooldown, so the gate lives behind an `Arc` and
//! `ika-node` builds exactly one, handing it to both. That is what
//! [`crate::grpc::SuiGrpcClient::with_gate`] is for.
//!
//! # Classification
//!
//! Two signals, in priority order (see [`classify_status`]):
//!
//! 1. **The gRPC status code.** `RESOURCE_EXHAUSTED` is the canonical gRPC code
//!    for "you are being rate limited", and a Sui fullnode's own load shedder
//!    uses it.
//!
//! 2. **A marker phrase in the message.** This is *not* redundant with (1). When
//!    an HTTP gateway in front of the fullnode answers 429, the response never
//!    carries a `grpc-status` trailer, so tonic falls back to its
//!    HTTP-status→gRPC-code table — and that table maps
//!    `429 TOO_MANY_REQUESTS` to `Code::Unavailable`, not to
//!    `Code::ResourceExhausted` (tonic `status.rs`, `infer_grpc_status`, which
//!    follows grpc's `http-grpc-status-mapping.md`). The only place the 429
//!    survives is the message text tonic synthesizes:
//!    `"grpc-status header missing, mapped from HTTP status code 429"`. Some
//!    gateways instead let their HTML error body through, in which case the
//!    message carries `<title>429 Too Many Requests</title>`.
//!
//!    String matching is therefore not a shortcut taken instead of reading a
//!    typed field — for the gateway case there **is** no typed field left to
//!    read. It is the only signal that survives the mapping.
//!
//! The marker list below deliberately contains no bare `"429"`. Sui error
//! messages are full of digits — checkpoint sequence numbers, epoch numbers,
//! object IDs — and a bare substring test would classify
//! `"checkpoint 4291 pruned"` as a rate limit. Every marker is a phrase that
//! does not occur by accident.
//!
//! # Retry-After
//!
//! It cannot be honored from here, because it does not reach here. In tonic's
//! HTTP-status mapping path the `Status` is built as `Status::new(code, msg)`
//! with an **empty** metadata map — the gateway's response headers, including
//! `Retry-After`, are dropped before any caller sees the error. Even on the
//! path that does preserve headers (`Status::from_header_map`, used when the
//! peer sent a real `grpc-status`), `TransportError` keeps only
//! `status.to_string()`, and tonic's `Display for Status` deliberately omits
//! metadata. So the header is structurally unavailable at every layer ika
//! owns; the schedule below is what we have. Plumbing it through would mean
//! changing tonic's mapping or carrying a typed status all the way up, which
//! is a transport change, not this fix.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mysten_common::backoff::ExponentialBackoff;
use tokio::time::Instant;

use crate::metrics::SuiClientMetrics;

/// First cooldown after a rate-limited response. Short enough that a single
/// misclassified error costs a healthy node almost nothing (a node in
/// steady state completes a successful read within milliseconds, and any
/// success resets the gate), long enough to matter if the classification was
/// right.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(250);
/// Cap on the shared cooldown. This is the whole node's read admission
/// interval during a sustained throttling episode — at the cap the node
/// issues on the order of two upstream requests per minute in total, instead
/// of the tens of thousands per hour its combined poll loops produce
/// unthrottled. It is deliberately far above every per-component backoff cap
/// (the bag pump caps at 5s, the executor's verified-read retry at 30s):
/// those caps bound one loop, this one bounds all of them together.
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(30);
/// Growth factor per consecutive rate-limited episode.
pub const DEFAULT_FACTOR: f64 = 2.0;

/// Marker phrases that identify a rate-limit refusal in an error message,
/// matched case-insensitively. See the module docs for why a bare `"429"` is
/// not among them.
const RATE_LIMIT_MARKERS: &[&str] = &[
    // HTTP 429's reason phrase. Also covers `<title>429 Too Many Requests</title>`.
    "too many requests",
    "rate limit",
    "rate-limit",
    "rate_limit",
    "ratelimit",
    // gRPC's own name for the condition, however the peer spelled it.
    "resource exhausted",
    "resource_exhausted",
    "resourceexhausted",
    // tonic's synthesized message when it maps a non-gRPC HTTP response.
    "http status code 429",
    "status code 429",
    "status: 429",
    "http 429",
    "error 429",
    // A gateway HTML error body that reached us verbatim.
    "<title>429",
];

/// Which signal identified an error as rate limiting. Carried onto the metric
/// so an operator can tell the canonical gRPC code apart from the
/// message-marker heuristic — if `message_marker` ever fires on a node that is
/// plainly not being throttled, that is the marker list to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitSignal {
    /// The gRPC status code was `RESOURCE_EXHAUSTED`.
    GrpcCode,
    /// The status code was generic; a marker phrase in the message identified it.
    MessageMarker,
}

impl RateLimitSignal {
    pub fn label(self) -> &'static str {
        match self {
            Self::GrpcCode => "grpc_code",
            Self::MessageMarker => "message_marker",
        }
    }
}

/// `Some` if `message` names a rate-limit refusal.
pub fn classify_message(message: &str) -> Option<RateLimitSignal> {
    let haystack = message.to_ascii_lowercase();
    RATE_LIMIT_MARKERS
        .iter()
        .any(|marker| haystack.contains(marker))
        .then_some(RateLimitSignal::MessageMarker)
}

/// `Some` if `status` is a rate-limit refusal, and by which signal.
pub fn classify_status(status: &tonic::Status) -> Option<RateLimitSignal> {
    if status.code() == tonic::Code::ResourceExhausted {
        return Some(RateLimitSignal::GrpcCode);
    }
    classify_message(status.message())
}

/// Backoff schedule for the shared gate. Mirrors the parameters of
/// `mysten_common::backoff::ExponentialBackoff` (the in-tree precedent —
/// consensus-core's `subscriber` retries its stream on exactly this
/// generator), and is used to build one.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitBackoffConfig {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub factor: f64,
    /// Uniform jitter added to each generated delay. Prevents a fleet whose
    /// nodes share one endpoint from re-converging on the same retry instant.
    /// Set to `Duration::ZERO` in tests to make the schedule exact.
    pub max_jitter: Duration,
}

impl Default for RateLimitBackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: DEFAULT_INITIAL_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
            factor: DEFAULT_FACTOR,
            max_jitter: DEFAULT_INITIAL_DELAY,
        }
    }
}

impl RateLimitBackoffConfig {
    fn generator(&self) -> ExponentialBackoff {
        ExponentialBackoff::new(self.initial_delay, self.max_delay)
            .factor(self.factor)
            .max_jitter(self.max_jitter)
    }
}

struct GateInner {
    /// Delay generator; replaced with a fresh one on every success, so a node
    /// that recovers does not carry an escalated schedule into the next
    /// (unrelated) episode.
    backoff: ExponentialBackoff,
    /// While set and in the future, no request is admitted until it passes.
    open_at: Option<Instant>,
    /// Consecutive rate-limit *episodes* (not responses) since the last success.
    consecutive_episodes: u32,
}

/// The node's shared rate-limit state for one upstream endpoint.
///
/// Requests call [`RateLimitGate::wait_for_capacity`] before going out and
/// report their outcome with [`RateLimitGate::note_status`] /
/// [`RateLimitGate::note_success`]. Generic transient errors are *not* reported
/// here at all: they keep whatever retry behavior their own component already
/// has, and only a classified rate limit arms the gate.
pub struct RateLimitGate {
    inner: Mutex<GateInner>,
    config: RateLimitBackoffConfig,
    metrics: Option<Arc<SuiClientMetrics>>,
}

impl std::fmt::Debug for RateLimitGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitGate")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RateLimitGate {
    pub fn new(config: RateLimitBackoffConfig, metrics: Option<Arc<SuiClientMetrics>>) -> Self {
        Self {
            inner: Mutex::new(GateInner {
                backoff: config.generator(),
                open_at: None,
                consecutive_episodes: 0,
            }),
            config,
            metrics,
        }
    }

    pub fn with_metrics(metrics: Arc<SuiClientMetrics>) -> Self {
        Self::new(RateLimitBackoffConfig::default(), Some(metrics))
    }

    /// A gate with no metrics sink. Used by the one-shot CLI / test-cluster
    /// clients, which have no Prometheus registry; the backoff still applies.
    pub fn unmetered() -> Self {
        Self::new(RateLimitBackoffConfig::default(), None)
    }

    /// Block until the shared cooldown (if any) has elapsed. A no-op — not even
    /// a yield — when the gate is not armed, which is the steady state.
    pub async fn wait_for_capacity(&self) {
        let open_at = self.open_at();
        if let Some(open_at) = open_at
            && open_at > Instant::now()
        {
            tokio::time::sleep_until(open_at).await;
        }
    }

    /// Report a successful upstream call: disarm the gate and reset the
    /// schedule.
    ///
    /// A success from a request that was already in flight when the gate armed
    /// can clear it early. That is deliberate — the endpoint answering at all
    /// is the best evidence available that it is answering — and it is
    /// self-correcting, since the next refusal re-arms from `initial_delay`.
    pub fn note_success(&self) {
        let mut inner = self.lock();
        if inner.open_at.is_none() && inner.consecutive_episodes == 0 {
            return;
        }
        inner.open_at = None;
        inner.consecutive_episodes = 0;
        inner.backoff = self.config.generator();
    }

    /// Classify `status` and, if it is a rate limit, arm/escalate the shared
    /// cooldown. Returns the signal and the cooldown now in force, or `None`
    /// for anything that is not a rate limit (the caller's existing retry
    /// behavior is then completely unchanged).
    pub fn note_status(&self, status: &tonic::Status) -> Option<(RateLimitSignal, Duration)> {
        let signal = classify_status(status)?;
        Some((signal, self.note_rate_limited(signal)))
    }

    /// Count one classified rate-limit response and return the cooldown now in
    /// force.
    ///
    /// Escalation is per *episode*, not per response: while a cooldown is still
    /// running, the in-flight requests that were admitted before it armed will
    /// all come back 429 too, and treating each of those as its own escalation
    /// would jump straight to the cap on the first burst. They still count on
    /// the metric — that is the real error rate — they just do not compound the
    /// delay.
    fn note_rate_limited(&self, signal: RateLimitSignal) -> Duration {
        if let Some(metrics) = &self.metrics {
            metrics
                .sui_rate_limited_errors
                .with_label_values(&[signal.label()])
                .inc();
        }
        let mut inner = self.lock();
        let now = Instant::now();
        if let Some(open_at) = inner.open_at
            && now < open_at
        {
            return open_at - now;
        }
        let delay = inner
            .backoff
            .next()
            .expect("ExponentialBackoff::next never terminates");
        inner.consecutive_episodes = inner.consecutive_episodes.saturating_add(1);
        inner.open_at = Some(now + delay);
        let episodes = inner.consecutive_episodes;
        drop(inner);
        tracing::warn!(
            signal = signal.label(),
            consecutive_episodes = episodes,
            cooldown_ms = delay.as_millis() as u64,
            "Sui endpoint is rate limiting us; holding every Sui read/write on this \
             uplink for the cooldown (all components share one gate)"
        );
        delay
    }

    fn open_at(&self) -> Option<Instant> {
        self.lock().open_at
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateInner> {
        // No await happens while this guard is held, so the only way to poison
        // it is a panic inside one of the tiny critical sections below.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Consecutive rate-limit episodes since the last success. Test-facing.
    pub fn consecutive_episodes(&self) -> u32 {
        self.lock().consecutive_episodes
    }
}

impl Default for RateLimitGate {
    fn default() -> Self {
        Self::unmetered()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_gate() -> RateLimitGate {
        // Jitter off: the assertions below are on exact delays.
        RateLimitGate::new(
            RateLimitBackoffConfig {
                max_jitter: Duration::ZERO,
                ..Default::default()
            },
            None,
        )
    }

    /// The canonical gRPC rate-limit code classifies on the code alone.
    #[test]
    fn resource_exhausted_classifies_by_code() {
        assert_eq!(
            classify_status(&tonic::Status::resource_exhausted("slow down")),
            Some(RateLimitSignal::GrpcCode)
        );
    }

    /// The case this fix exists for. tonic maps an HTTP 429 that carries no
    /// `grpc-status` trailer to `Code::Unavailable` — NOT to
    /// `ResourceExhausted` — so the code is useless here and the synthesized
    /// message is the only surviving evidence. If this test ever starts
    /// passing on the code alone, tonic changed its mapping and the marker
    /// list can shrink.
    #[test]
    fn gateway_429_classifies_by_message_because_the_code_is_unavailable() {
        let mapped = tonic::Status::unavailable(
            "grpc-status header missing, mapped from HTTP status code 429",
        );
        assert_eq!(mapped.code(), tonic::Code::Unavailable);
        assert_eq!(
            classify_status(&mapped),
            Some(RateLimitSignal::MessageMarker)
        );
    }

    /// A gateway that leaks its HTML error page into the message.
    #[test]
    fn html_error_body_classifies() {
        let html = tonic::Status::unknown(
            "transport error: <html>\r\n<head><title>429 Too Many Requests</title></head>\r\n\
             <body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n</body>\r\n</html>",
        );
        assert_eq!(classify_status(&html), Some(RateLimitSignal::MessageMarker));
        // ...and the bare-titled variant, without the reason phrase.
        assert_eq!(
            classify_message("<html><head><title>429</title></head></html>"),
            Some(RateLimitSignal::MessageMarker)
        );
    }

    /// The false-positive guard. Sui messages are full of digits, and a bare
    /// `"429"` substring test would classify every one of these as throttling
    /// and then throttle a perfectly healthy node.
    #[test]
    fn ordinary_sui_errors_with_429_digits_are_not_rate_limits() {
        for message in [
            "checkpoint 4291 pruned",
            "epoch 429 not found",
            "object 0x429a3f...c2 is not a MoveObject",
            "last_checkpoint not yet set for epoch 1429",
            "tx 429 not yet committed in any checkpoint",
        ] {
            assert_eq!(
                classify_message(message),
                None,
                "{message:?} must not classify as rate limiting"
            );
        }
        for status in [
            tonic::Status::not_found("checkpoint 429 pruned"),
            tonic::Status::unavailable("backend down"),
            tonic::Status::deadline_exceeded("slow"),
            tonic::Status::internal("boom"),
        ] {
            assert_eq!(classify_status(&status), None);
        }
    }

    /// Consecutive rate-limit episodes must escalate the shared cooldown
    /// exponentially and stop at the cap. Deterministic: `start_paused` means
    /// `sleep_until` advances the test clock instead of the wall clock, so the
    /// cooldowns are observed exactly and nothing actually sleeps.
    #[tokio::test(start_paused = true)]
    async fn rate_limited_errors_escalate_the_shared_cooldown_and_cap() {
        let gate = exact_gate();
        let status = tonic::Status::resource_exhausted("slow down");

        let mut delays = Vec::new();
        for _ in 0..10 {
            let (signal, delay) = gate.note_status(&status).expect("classified");
            assert_eq!(signal, RateLimitSignal::GrpcCode);
            delays.push(delay);
            // Serve out the cooldown so the next error opens a new episode.
            gate.wait_for_capacity().await;
        }

        assert_eq!(
            &delays[..4],
            &[
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
            ],
            "each episode must double the previous cooldown"
        );
        assert!(
            delays.windows(2).all(|w| w[1] >= w[0]),
            "the schedule must be monotonic: {delays:?}"
        );
        assert_eq!(
            *delays.last().unwrap(),
            DEFAULT_MAX_DELAY,
            "the schedule must reach a real cap, not grow without bound"
        );
        assert_eq!(gate.consecutive_episodes(), 10);
    }

    /// The gate actually holds requests for the cooldown, and only for it.
    #[tokio::test(start_paused = true)]
    async fn wait_for_capacity_holds_for_the_cooldown_then_releases() {
        let gate = exact_gate();

        // Not armed: admission is immediate.
        let before = Instant::now();
        gate.wait_for_capacity().await;
        assert_eq!(Instant::now(), before, "an unarmed gate must not delay");

        gate.note_status(&tonic::Status::resource_exhausted("slow down"))
            .expect("classified");
        let armed_at = Instant::now();
        gate.wait_for_capacity().await;
        assert_eq!(
            Instant::now() - armed_at,
            Duration::from_millis(250),
            "the gate must hold for exactly the cooldown it reported"
        );

        // Cooldown served: admission is immediate again.
        let after = Instant::now();
        gate.wait_for_capacity().await;
        assert_eq!(Instant::now(), after);
    }

    /// A success is what ends an episode: it disarms the gate and resets the
    /// schedule, so an unrelated later episode starts from the initial delay
    /// rather than from wherever the last one left off.
    #[tokio::test(start_paused = true)]
    async fn a_success_resets_the_schedule() {
        let gate = exact_gate();
        let status = tonic::Status::resource_exhausted("slow down");

        for _ in 0..5 {
            gate.note_status(&status).expect("classified");
            gate.wait_for_capacity().await;
        }
        assert!(gate.consecutive_episodes() > 1);

        gate.note_success();
        assert_eq!(gate.consecutive_episodes(), 0);

        // Nothing is held after a success...
        let before = Instant::now();
        gate.wait_for_capacity().await;
        assert_eq!(Instant::now(), before);

        // ...and the next episode restarts from the initial delay.
        let (_, delay) = gate.note_status(&status).expect("classified");
        assert_eq!(delay, DEFAULT_INITIAL_DELAY);
    }

    /// Generic transient errors keep today's behavior exactly: the gate never
    /// arms, so every component's own retry loop runs unchanged.
    #[tokio::test(start_paused = true)]
    async fn generic_transients_never_arm_the_gate() {
        let gate = exact_gate();
        for status in [
            tonic::Status::unavailable("backend down"),
            tonic::Status::deadline_exceeded("slow"),
            tonic::Status::internal("boom"),
            tonic::Status::not_found("checkpoint 4291 pruned"),
            tonic::Status::unknown("?"),
        ] {
            assert!(
                gate.note_status(&status).is_none(),
                "{:?} must not be classified as a rate limit",
                status.code()
            );
        }
        assert_eq!(gate.consecutive_episodes(), 0);
        let before = Instant::now();
        gate.wait_for_capacity().await;
        assert_eq!(
            Instant::now(),
            before,
            "generic transients must not add any delay"
        );
    }

    /// A burst of responses from requests already in flight when the gate armed
    /// is ONE episode. Without this, twenty concurrent pump/pusher/ratchet
    /// reads failing together would escalate twenty times and jump the shared
    /// cooldown straight to the cap on the first blip.
    #[tokio::test(start_paused = true)]
    async fn an_in_flight_burst_counts_as_one_episode() {
        let gate = exact_gate();
        let status = tonic::Status::resource_exhausted("slow down");

        let (_, first) = gate.note_status(&status).expect("classified");
        assert_eq!(first, DEFAULT_INITIAL_DELAY);
        for _ in 0..19 {
            let (_, delay) = gate.note_status(&status).expect("classified");
            assert!(
                delay <= first,
                "a burst inside the cooldown must not compound it"
            );
        }
        assert_eq!(gate.consecutive_episodes(), 1);

        // Once the cooldown is served, the next refusal is a new episode.
        gate.wait_for_capacity().await;
        let (_, next) = gate.note_status(&status).expect("classified");
        assert_eq!(next, Duration::from_millis(500));
        assert_eq!(gate.consecutive_episodes(), 2);
    }

    /// Jitter is on by default (a fleet sharing one endpoint must not
    /// re-converge on the same retry instant), and it must not break the cap.
    #[tokio::test(start_paused = true)]
    async fn default_config_jitters_within_bounds() {
        let gate = RateLimitGate::new(RateLimitBackoffConfig::default(), None);
        let status = tonic::Status::resource_exhausted("slow down");
        for _ in 0..12 {
            let (_, delay) = gate.note_status(&status).expect("classified");
            assert!(
                delay <= DEFAULT_MAX_DELAY + DEFAULT_INITIAL_DELAY,
                "jitter must stay within one initial delay of the cap, got {delay:?}"
            );
            gate.wait_for_capacity().await;
        }
    }
}
