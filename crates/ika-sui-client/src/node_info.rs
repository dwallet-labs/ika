// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Background refresher for `ika_sui_client_sui_node_info`.
//!
//! # Why this is a background task
//!
//! The metric exists because an operator's *outdated or failing* Sui fullnode
//! is invisible to the fleet (see
//! [`crate::metrics::SuiClientMetrics::sui_node_info`]). The nodes it most
//! needs to describe are therefore precisely the nodes whose RPC is slow,
//! hanging, or dead — so identifying them must never sit on a code path any
//! real client operation waits for. Nothing here is awaited by a caller: the
//! task is spawned at client construction, every call is deadlined, and every
//! failure is a no-op that leaves the last known labels in place.
//!
//! # Why failures are not counted in `sui_rpc_errors`
//!
//! Deliberate. `ika_sui_client_sui_rpc_errors` is the fleet's Sui-uplink
//! health signal, and its healthy baseline is 0–6 errors/hour — a band narrow
//! enough that a passive probe contributing its own floor to it would blunt
//! exactly the signal the probe exists to explain. A probe failing while the
//! node's real reads succeed is also not an incident, and would be a false
//! positive in that counter. The probe's failures are already fully
//! observable in its own two metrics: the `server_version` label stays at
//! `unknown` (or goes stale) and
//! `ika_sui_client_sui_node_info_last_success_unixtime` stops advancing.
//!
//! One counter the refresh *does* still feed, unavoidably and correctly:
//! calls go through the node's shared [`crate::rate_limit::RateLimitGate`],
//! so a rate-limited response is classified like any other and increments
//! `ika_sui_client_rate_limited_errors_total`. At a maximum of five calls an
//! hour that is negligible, and if the endpoint really is refusing, saying so
//! is right.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};

use crate::metrics::SuiClientMetrics;
use crate::transport::{SuiNodeInfo, SuiTransport, TransportError};

/// Steady-state refresh cadence. An operator's Sui version changes only when
/// they deploy an upgrade, so minutes of staleness cost nothing; the interval
/// is set by wanting a fleet-wide version census to converge within a Grafana
/// panel's typical lookback, not by any need for freshness.
const REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 60);

/// Delay before the second attempt while the node has *never* been
/// identified, doubling up to [`REFRESH_INTERVAL`]. A node that answers on
/// the first try never uses this; one whose uplink is flaky at boot gets
/// identified in tens of seconds instead of waiting out a full interval,
/// without turning a sustained outage into a polling loop.
const INITIAL_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Per-call deadline. A hung fullnode is one of the failure modes this metric
/// was built to expose, so the probe cannot be allowed to hang with it: a
/// task blocked forever in `GetServiceInfo` would leave the labels frozen and
/// never retry, which looks identical to a healthy node that stopped changing.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Handle to the spawned refresh task; aborts it on drop so the task's
/// lifetime is exactly the owning client's.
#[derive(Debug)]
pub struct SuiNodeInfoRefresh(tokio::task::JoinHandle<()>);

impl Drop for SuiNodeInfoRefresh {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Start refreshing `ika_sui_client_sui_node_info` from `transport`.
///
/// Must be called from inside a Tokio runtime (every construction path is
/// already `async`). Returns immediately; the first probe runs on the spawned
/// task, not here.
pub fn spawn_sui_node_info_refresh(
    transport: Arc<dyn SuiTransport>,
    metrics: Arc<SuiClientMetrics>,
) -> SuiNodeInfoRefresh {
    SuiNodeInfoRefresh(tokio::spawn(refresh_loop(
        move || {
            let transport = transport.clone();
            async move { transport.get_sui_node_info().await }
        },
        metrics,
    )))
}

/// Result of one probe, in the terms the loop schedules on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tick {
    /// The node answered; labels now describe it.
    Identified,
    /// This transport structurally cannot answer. Terminal — nothing about it
    /// will change on a later attempt.
    Unsupported,
    /// The call failed or timed out. Previous labels are left untouched.
    Failed,
}

async fn refresh_loop<F, Fut>(fetch: F, metrics: Arc<SuiClientMetrics>)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = Result<Option<SuiNodeInfo>, TransportError>> + Send,
{
    let mut acquisition_delay = INITIAL_RETRY_INTERVAL;
    let mut ever_identified = false;
    loop {
        let sleep_for = match refresh_once(&fetch, &metrics).await {
            Tick::Identified => {
                if !ever_identified {
                    ever_identified = true;
                    info!("identified the connected Sui node; publishing sui_node_info");
                }
                REFRESH_INTERVAL
            }
            // Nothing to poll for. Leaving the task alive would burn a timer
            // forever to re-derive a constant.
            Tick::Unsupported => return,
            // Once we know the version, a failed refresh is not urgent — the
            // last known labels stay published and the freshness gauge already
            // says how old they are. The fast ramp is only for *acquiring* a
            // version we have never had.
            Tick::Failed if ever_identified => REFRESH_INTERVAL,
            Tick::Failed => {
                let now = acquisition_delay;
                acquisition_delay = (acquisition_delay * 2).min(REFRESH_INTERVAL);
                now
            }
        };
        tokio::time::sleep(sleep_for).await;
    }
}

async fn refresh_once<F, Fut>(fetch: &F, metrics: &SuiClientMetrics) -> Tick
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<Option<SuiNodeInfo>, TransportError>>,
{
    match tokio::time::timeout(CALL_TIMEOUT, fetch()).await {
        Ok(Ok(Some(info))) => {
            metrics.set_sui_node_info(
                info.server_version.as_deref(),
                info.chain_identifier.as_deref(),
            );
            Tick::Identified
        }
        Ok(Ok(None)) => {
            metrics.set_sui_node_info_unsupported();
            Tick::Unsupported
        }
        // Debug, not warn: on the wedged nodes this metric describes, the Sui
        // uplink fails continuously for hours, and a probe that narrates that
        // once per interval adds nothing the metric does not already say.
        Ok(Err(error)) => {
            debug!(
                ?error,
                "Sui GetServiceInfo probe failed; sui_node_info unchanged"
            );
            Tick::Failed
        }
        Err(_) => {
            debug!(
                timeout = ?CALL_TIMEOUT,
                "Sui GetServiceInfo probe timed out; sui_node_info unchanged"
            );
            Tick::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{
        SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNREPORTED, SUI_NODE_INFO_UNSUPPORTED,
    };

    fn info(server: &str) -> SuiNodeInfo {
        SuiNodeInfo {
            server_version: Some(server.to_string()),
            chain_identifier: Some("35834a8a".to_string()),
        }
    }

    fn gauge(metrics: &SuiClientMetrics, server: &str, chain: &str) -> i64 {
        metrics
            .sui_node_info
            .with_label_values(&[server, chain])
            .get()
    }

    /// The eager registration is the whole reason a never-answering node is
    /// visible at all: before any probe runs the client must already export
    /// `unknown = 1`, with the freshness gauge at 0 to say "never".
    #[test]
    fn unknown_is_published_before_any_refresh() {
        let metrics = SuiClientMetrics::new_for_testing();
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            1
        );
        assert_eq!(metrics.sui_node_info_last_success_unixtime.get(), 0);
    }

    /// A successful probe flips `unknown` to 0 and the real version to 1 —
    /// and `unknown` must still EXIST at 0 rather than vanish, so a query
    /// spanning the transition sees a value on both sides of it.
    #[tokio::test]
    async fn success_flips_unknown_to_the_reported_version() {
        let metrics = SuiClientMetrics::new_for_testing();

        let tick = refresh_once(&|| async { Ok(Some(info("sui-node/1.78.1"))) }, &metrics).await;

        assert_eq!(tick, Tick::Identified);
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            0
        );
        assert_eq!(gauge(&metrics, "sui-node/1.78.1", "35834a8a"), 1);
        assert!(metrics.sui_node_info_last_success_unixtime.get() > 0);
    }

    /// An operator upgrading their fullnode must read as one series going to
    /// 0 and one to 1, never as two series at 1.
    #[tokio::test]
    async fn a_version_change_leaves_exactly_one_child_at_one() {
        let metrics = SuiClientMetrics::new_for_testing();

        refresh_once(&|| async { Ok(Some(info("sui-node/1.77.2"))) }, &metrics).await;
        refresh_once(&|| async { Ok(Some(info("sui-node/1.78.1"))) }, &metrics).await;

        assert_eq!(gauge(&metrics, "sui-node/1.77.2", "35834a8a"), 0);
        assert_eq!(gauge(&metrics, "sui-node/1.78.1", "35834a8a"), 1);
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            0
        );
    }

    /// Re-reporting the same version is the steady state; it must stay at 1
    /// and keep advancing the freshness stamp.
    #[tokio::test]
    async fn repeating_the_same_version_is_idempotent() {
        let metrics = SuiClientMetrics::new_for_testing();

        refresh_once(&|| async { Ok(Some(info("sui-node/1.78.1"))) }, &metrics).await;
        metrics.sui_node_info_last_success_unixtime.set(1);
        refresh_once(&|| async { Ok(Some(info("sui-node/1.78.1"))) }, &metrics).await;

        assert_eq!(gauge(&metrics, "sui-node/1.78.1", "35834a8a"), 1);
        assert!(metrics.sui_node_info_last_success_unixtime.get() > 1);
    }

    /// A failing probe must change nothing at all — not the labels, not the
    /// freshness stamp. Staying on `unknown` IS the report.
    #[tokio::test]
    async fn a_failed_probe_leaves_the_previous_labels_alone() {
        let metrics = SuiClientMetrics::new_for_testing();

        let first = refresh_once(
            &|| async { Err(TransportError::Network("down".into())) },
            &metrics,
        )
        .await;

        assert_eq!(first, Tick::Failed);
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            1
        );
        assert_eq!(metrics.sui_node_info_last_success_unixtime.get(), 0);

        refresh_once(&|| async { Ok(Some(info("sui-node/1.78.1"))) }, &metrics).await;
        let stamped = metrics.sui_node_info_last_success_unixtime.get();
        refresh_once(
            &|| async { Err(TransportError::Network("down".into())) },
            &metrics,
        )
        .await;

        assert_eq!(gauge(&metrics, "sui-node/1.78.1", "35834a8a"), 1);
        assert_eq!(metrics.sui_node_info_last_success_unixtime.get(), stamped);
    }

    /// A node that answers but leaves `server` unset is a working RPC, so it
    /// must not be reported as `unknown` — and its answer is fresh.
    #[tokio::test]
    async fn an_empty_server_field_reports_unreported_not_unknown() {
        let metrics = SuiClientMetrics::new_for_testing();

        refresh_once(&|| async { Ok(Some(SuiNodeInfo::default())) }, &metrics).await;

        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNREPORTED, SUI_NODE_INFO_UNREPORTED),
            1
        );
        assert!(metrics.sui_node_info_last_success_unixtime.get() > 0);
    }

    /// The p2p-relay case: terminal, and pointedly not stamped fresh, so a
    /// staleness query can exclude it by label instead of by timestamp.
    #[tokio::test]
    async fn an_unsupporting_transport_is_terminal_and_never_stamped_fresh() {
        let metrics = SuiClientMetrics::new_for_testing();

        let tick = refresh_once(&|| async { Ok(None) }, &metrics).await;

        assert_eq!(tick, Tick::Unsupported);
        assert_eq!(
            gauge(
                &metrics,
                SUI_NODE_INFO_UNSUPPORTED,
                SUI_NODE_INFO_UNSUPPORTED
            ),
            1
        );
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            0
        );
        assert_eq!(metrics.sui_node_info_last_success_unixtime.get(), 0);
    }

    /// A hung fullnode must not hang the probe: the deadline fires and the
    /// tick reports failure, leaving the loop free to try again.
    #[tokio::test(start_paused = true)]
    async fn a_hanging_call_times_out_instead_of_wedging_the_task() {
        let metrics = SuiClientMetrics::new_for_testing();

        let tick = refresh_once(
            &|| async {
                tokio::time::sleep(CALL_TIMEOUT * 10).await;
                Ok(Some(info("never-arrives")))
            },
            &metrics,
        )
        .await;

        assert_eq!(tick, Tick::Failed);
        assert_eq!(
            gauge(&metrics, SUI_NODE_INFO_UNKNOWN, SUI_NODE_INFO_UNKNOWN),
            1
        );
    }

    /// The loop must stop itself on an unsupporting transport rather than
    /// re-deriving a constant every interval forever.
    #[tokio::test(start_paused = true)]
    async fn the_loop_exits_on_an_unsupporting_transport() {
        let metrics = SuiClientMetrics::new_for_testing();

        // Completes only because the loop returns; a poll loop would hang here.
        refresh_loop(|| async { Ok(None) }, metrics.clone()).await;

        assert_eq!(
            gauge(
                &metrics,
                SUI_NODE_INFO_UNSUPPORTED,
                SUI_NODE_INFO_UNSUPPORTED
            ),
            1
        );
    }

    /// Before the first success the loop retries on the short schedule; after
    /// it, it settles onto the steady interval. Asserted through elapsed
    /// virtual time on a paused clock.
    #[tokio::test(start_paused = true)]
    async fn retries_are_fast_until_identified_then_settle() {
        let metrics = SuiClientMetrics::new_for_testing();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let started = tokio::time::Instant::now();
        let counter = attempts.clone();
        let loop_task = tokio::spawn(refresh_loop(
            move || {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(TransportError::Network("down".into()))
                    } else {
                        Ok(Some(info("sui-node/1.78.1")))
                    }
                }
            },
            metrics.clone(),
        ));

        // Two failures (30s + 60s of backoff) then the success.
        tokio::time::sleep(Duration::from_secs(91)).await;
        assert_eq!(gauge(&metrics, "sui-node/1.78.1", "35834a8a"), 1);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);

        // Having succeeded, it now waits the full interval rather than 120s.
        tokio::time::sleep(REFRESH_INTERVAL - Duration::from_secs(60)).await;
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(started.elapsed() < REFRESH_INTERVAL * 2);

        loop_task.abort();
    }
}
