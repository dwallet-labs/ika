// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use crate::bind_retry::{BIND_ATTEMPTS, BIND_RETRY_INTERVAL, bind_with_retry};
use axum::{Extension, Router, routing::get};
use mysten_metrics::{METRICS_ROUTE, RegistryService};
use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, Registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{error, warn};

/// Start the Prometheus scrape endpoint on `addr` and return the
/// [`RegistryService`] backing it.
///
/// A local equivalent of `mysten_metrics::start_prometheus_server`, which
/// `unwrap`s both the `TcpListener::bind` and the `axum::serve` inside its
/// spawned task. Under this node those `unwrap`s are fatal — the release
/// profile sets `panic = 'abort'` and the node enables `crash_on_panic` — so
/// a squatted metrics port (a shared CI runner, a duplicated port in a
/// deployment, or a restart racing its own port through `TIME_WAIT`) takes the
/// whole process down at boot, before telemetry is even initialized. This
/// version retries the bind and then gives up loudly, exactly like the admin
/// server; a node without a scrape endpoint is strictly healthier than a dead
/// node.
///
/// Metrics are more load-bearing than the admin endpoint — losing them blinds
/// every dashboard and alert for this validator — so the give-up logs at
/// `error!` and names the address.
///
/// The rest of the behaviour is upstream's, unchanged: same route, same
/// handler, same registry wiring, and the same simulator short-circuit.
pub fn start_prometheus_server(addr: SocketAddr) -> RegistryService {
    let registry = Registry::new();

    let registry_service = RegistryService::new(registry);

    if cfg!(msim) {
        // prometheus uses difficult-to-support features such as
        // TcpSocket::from_raw_fd(), so it can't run in the simulator.
        // Identical to upstream: return the registry service without ever
        // spawning a server.
        warn!("not starting prometheus server in simulator");
        return registry_service;
    }

    let app = Router::new()
        .route(METRICS_ROUTE, get(mysten_metrics::metrics))
        .layer(Extension(registry_service.clone()));

    tokio::spawn(serve_metrics(app, addr, BIND_ATTEMPTS, BIND_RETRY_INTERVAL));

    registry_service
}

/// Serve the metrics `app` on `socket_address`, riding out a transient bind
/// failure and then giving up loudly — never panicking.
async fn serve_metrics(
    app: Router,
    socket_address: SocketAddr,
    attempts: u32,
    retry_interval: Duration,
) {
    let Some(listener) = bind_with_retry("metrics", socket_address, attempts, retry_interval).await
    else {
        error!(
            address =% socket_address,
            "gave up binding the metrics server; the node continues without a metrics \
             endpoint and will not be scrapable"
        );
        return;
    };
    if let Err(err) = axum::serve(listener, app.into_make_service()).await {
        error!(
            address =% socket_address,
            error =? err,
            "metrics server stopped; the node continues without a metrics endpoint and \
             will not be scrapable"
        );
    }
}

pub struct IkaNodeMetrics {
    pub current_protocol_version: IntGauge,
    pub binary_max_protocol_version: IntGauge,
    pub configured_max_protocol_version: IntGauge,

    /// Joiner/anchor bootstrap cert-fetch outcomes, by outcome
    /// (`verified` / `rejected` / `unavailable`). `rejected` fail-closes
    /// the node, so its durable value is the `verified` epoch-cadence
    /// sanity check and `unavailable` wedge-cause attribution.
    pub joiner_bootstrap_outcomes_total: IntCounterVec,

    /// P2P mpc_data blob fetch outcomes, by result (`ok` / `not_found` /
    /// `hash_mismatch` / `decode_failed` / `cache_insert_failed` /
    /// `transport_error`). `decode_failed` is the announcer-byzantine
    /// signal; a high `transport_error` rate explains slow ready-signal
    /// coverage.
    pub mpc_data_blob_fetch_total: IntCounterVec,

    /// Sub-phase of the epoch-reconfiguration critical section while the
    /// reconfig watchdog is armed (see `reconfig_watchdog::phase`); 0
    /// outside it. Any nonzero value that persists is a node parked in the
    /// teardown-to-restart window (#1864), and the value names the hanging
    /// await. Every mode arms that watchdog — a fullnode or notifier crosses
    /// the same unbounded awaits in `reconfigure_state` — so this is not
    /// validator-only telemetry.
    pub reconfig_phase: IntGauge,
}

/// Telemetry for subsystems only a validator-mode process runs: the
/// prepare-then-start handoff barrier and the commit-liveness watchdog.
///
/// Registered only in validator mode, so a fullnode or notifier does not
/// export these families at all. Each of them reads as a healthy validator
/// when it sits at its default — a `handoff_prepare_waiting` of 0 says "not
/// wedged at the barrier" and a `consensus_commit_silence_seconds` of 0 says
/// "a commit landed this second" — which is precisely why absence, not a
/// zero, is the correct signal on a process with no such subsystem
/// (ika #2051).
pub struct ValidatorTelemetryMetrics {
    /// 1 while the prepare-then-start barrier is blocking the new epoch's
    /// MPC components on full verified handoff data; 0 otherwise. A value
    /// stuck at 1 is the dashboard signal that a validator is wedged
    /// waiting for handoff data and is not signing.
    pub handoff_prepare_waiting: IntGauge,
    /// Number of prepare-then-start barrier poll iterations spent waiting
    /// for handoff data.
    pub handoff_prepare_retries_total: IntCounter,
    /// Wall-clock seconds spent inside the prepare-then-start barrier.
    /// Observed only on successful barrier exit, so this trends the
    /// distribution of completed (possibly slow) waits — stuck-barrier
    /// alerting is `handoff_prepare_waiting` + `handoff_prepare_retries_total`.
    pub handoff_prepare_duration_seconds: Histogram,

    /// Seconds since this process last finished processing a consensus
    /// commit, while the commit-liveness watchdog is armed and running;
    /// `-1` while it is unarmed (no commit processed yet this process) or
    /// held (consensus torn down for reconfiguration, or the watchdog
    /// disabled). A healthy validator reads single-digit seconds. Sustained
    /// growth is the #1864 isolation signature — subscriptions gone in both
    /// directions with the process otherwise healthy — and the watchdog
    /// exits the node once it passes the bound. This is the in-node twin of
    /// the fleet-side staleness alert on
    /// `ika_consensus_last_committed_timestamp_seconds`, measured on the
    /// LOCAL clock instead of the consensus clock, so a validator replaying
    /// a backlog of old commits reads healthy here while it makes progress.
    pub consensus_commit_silence_seconds: IntGauge,
}

impl IkaNodeMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            current_protocol_version: register_int_gauge_with_registry!(
                "ika_current_protocol_version",
                "Current protocol version in this epoch",
                registry,
            )
            .unwrap(),
            binary_max_protocol_version: register_int_gauge_with_registry!(
                "ika_binary_max_protocol_version",
                "Max protocol version supported by this binary",
                registry,
            )
            .unwrap(),
            configured_max_protocol_version: register_int_gauge_with_registry!(
                "ika_configured_max_protocol_version",
                "Max protocol version configured in the node config",
                registry,
            )
            .unwrap(),
            joiner_bootstrap_outcomes_total: register_int_counter_vec_with_registry!(
                "ika_joiner_bootstrap_outcomes_total",
                "Joiner/anchor bootstrap cert-fetch outcomes",
                &["outcome"],
                registry,
            )
            .unwrap(),
            mpc_data_blob_fetch_total: register_int_counter_vec_with_registry!(
                "ika_dwallet_mpc_data_blob_fetch_total",
                "P2P mpc_data blob fetch outcomes",
                &["result"],
                registry,
            )
            .unwrap(),
            reconfig_phase: register_int_gauge_with_registry!(
                "ika_reconfig_phase",
                "Sub-phase of the epoch-reconfiguration critical section while the reconfig \
                 watchdog is armed; 0 outside it",
                registry,
            )
            .unwrap(),
        }
    }
}

impl ValidatorTelemetryMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            handoff_prepare_waiting: register_int_gauge_with_registry!(
                "ika_handoff_prepare_waiting",
                "1 while the prepare-then-start barrier is blocking the new epoch's MPC \
                 components on full verified handoff data; 0 otherwise",
                registry,
            )
            .unwrap(),
            handoff_prepare_retries_total: register_int_counter_with_registry!(
                "ika_handoff_prepare_retries_total",
                "Number of prepare-then-start barrier poll iterations spent waiting for \
                 handoff data",
                registry,
            )
            .unwrap(),
            handoff_prepare_duration_seconds: register_histogram_with_registry!(
                "ika_handoff_prepare_duration_seconds",
                "Wall-clock seconds spent inside the prepare-then-start barrier",
                // Barrier waits are legitimately minutes (cert fetch + blob
                // convergence at the epoch boundary); the prometheus default
                // buckets top out at 10s and would collapse every slow exit
                // into +Inf.
                vec![
                    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0
                ],
                registry,
            )
            .unwrap(),
            consensus_commit_silence_seconds: register_int_gauge_with_registry!(
                "ika_consensus_commit_silence_seconds",
                "Seconds since this process last finished processing a consensus commit; -1 \
                 while the commit-liveness watchdog is unarmed, held for reconfiguration, or \
                 disabled",
                registry,
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind_retry::test_support::squatted_port;
    use prometheus::{IntCounter, Registry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    pub async fn test_metrics_endpoint_with_multiple_registries_add_remove() {
        let port: u16 = 8081;
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        let registry_service = start_prometheus_server(socket);

        tokio::task::yield_now().await;

        // now add a few registries to the service along side with metrics
        let registry_1 = Registry::new_custom(Some("vendored".to_string()), None).unwrap();
        let counter_1 = IntCounter::new("counter_1", "a sample counter 1").unwrap();
        registry_1.register(Box::new(counter_1)).unwrap();

        let registry_2 = Registry::new_custom(Some("ika".to_string()), None).unwrap();
        let counter_2 = IntCounter::new("counter_2", "a sample counter 2").unwrap();
        registry_2.register(Box::new(counter_2.clone())).unwrap();

        let registry_1_id = registry_service.add(registry_1);
        let _registry_2_id = registry_service.add(registry_2);

        // request the endpoint
        let result = get_metrics(port).await;

        assert!(result.contains(
            "# HELP ika_counter_2 a sample counter 2
# TYPE ika_counter_2 counter
ika_counter_2 0"
        ));

        assert!(result.contains(
            "# HELP vendored_counter_1 a sample counter 1
# TYPE vendored_counter_1 counter
vendored_counter_1 0"
        ));

        // Now remove registry 1
        assert!(registry_service.remove(registry_1_id));

        // AND increase metric 2
        counter_2.inc();

        // Now pull again metrics
        // request the endpoint
        let result = get_metrics(port).await;

        // Registry 1 metrics should not be present anymore
        assert!(!result.contains(
            "# HELP vendored_counter_1 a sample counter 1
# TYPE vendored_counter_1 counter
vendored_counter_1 0"
        ));

        // Registry 2 metric should have increased by 1
        assert!(result.contains(
            "# HELP ika_counter_2 a sample counter 2
# TYPE ika_counter_2 counter
ika_counter_2 1"
        ));
    }

    async fn get_metrics(port: u16) -> String {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://127.0.0.1:{port}/metrics"))
            .send()
            .await
            .unwrap();
        response.text().await.unwrap()
    }

    /// A stand-in for the real metrics router: `serve_metrics` only ever sees
    /// an already-built `Router`, so the routes it carries are irrelevant to
    /// the bind path under test.
    fn test_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    async fn get_ping(address: SocketAddr) -> Option<String> {
        let response = reqwest::Client::new()
            .get(format!("http://{address}/ping"))
            .send()
            .await
            .ok()?;
        response.text().await.ok()
    }

    /// The node-side failure this guards: something already holds the metrics
    /// port, and the node dies at boot because the bind panicked on a runtime
    /// where panics are fatal — before telemetry is even initialized, so the
    /// death is close to silent. `serve_metrics` must exhaust its retries and
    /// return normally instead: the node runs on, minus the scrape endpoint.
    #[tokio::test]
    async fn a_squatted_metrics_port_does_not_take_the_node_down() {
        let (_squatter, address) = squatted_port().await;

        timeout(
            Duration::from_secs(30),
            serve_metrics(test_router(), address, 3, Duration::from_millis(50)),
        )
        .await
        .expect("a permanently squatted metrics port must be given up on, not waited on forever");
    }

    /// The retries ride out a transient squatter: once the port is released
    /// the metrics server comes up on its own, with no node restart.
    #[tokio::test]
    async fn the_metrics_server_comes_up_once_the_port_is_released() {
        let (squatter, address) = squatted_port().await;

        let server = tokio::spawn(serve_metrics(
            test_router(),
            address,
            600,
            Duration::from_millis(50),
        ));

        // Let the first attempts fail against the squatter before it lets go.
        sleep(Duration::from_millis(120)).await;
        drop(squatter);

        let body = timeout(Duration::from_secs(30), async {
            loop {
                if let Some(body) = get_ping(address).await {
                    return body;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the metrics server must come up once the port is released");
        assert_eq!(body, "pong");

        server.abort();
    }

    /// `start_prometheus_server` must hand back a usable `RegistryService`
    /// even when the port can never be bound — the node keeps recording
    /// metrics into the registry, it just has nothing serving them.
    #[tokio::test]
    async fn a_squatted_port_still_yields_a_working_registry_service() {
        let (_squatter, address) = squatted_port().await;

        let registry_service = start_prometheus_server(address);
        let registry = Registry::new_custom(Some("ika".to_string()), None).unwrap();
        let counter = IntCounter::new("counter", "a sample counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        registry_service.add(registry);
        counter.inc();

        assert!(
            registry_service
                .gather_all()
                .iter()
                .any(|family| family.name() == "ika_counter"),
            "the registry service must keep collecting even with no server bound"
        );
    }
}

/// What each `NodeMode` registers, pinned.
///
/// The node used to register every metric family in the shared part of its
/// start sequence, so a notifier exported `ika_dwallet_mpc_*`, the consensus
/// handler counters, the handoff-barrier gauges and the chain-observation
/// gauges it never drives — at values indistinguishable from a healthy
/// validator's (ika #2051). Registration now follows the subsystems each mode
/// actually runs, and these lists are what pins it.
///
/// # Deliberately mode-independent
///
/// A family in all three lists is not an oversight. `ika_sui_client_*` comes
/// from [`ika_sui_client::metrics::SuiClientMetrics`], which every mode
/// constructs on the exported registry in one unconditional line of
/// `IkaNode::start_with_mode`, because every mode really does talk to Sui: a
/// notifier runs a read/write `SuiClient` to push checkpoints, and a fullnode
/// runs the connector stack's read client. There is no subsystem behind those
/// families that a mode can decline to run, so "absence is the correct signal"
/// has nothing to say about them and they stay everywhere.
///
/// The same holds for the protocol-version gauges (`ika_binary_*`,
/// `ika_configured_*`, `ika_supported_protocol_version_*`) and
/// `ika_reconfig_phase`: properties of the running binary, or of a watchdog
/// every mode arms. See "A process registers only the families it drives" in
/// `dev-docs/conventions/metrics.md`.
#[cfg(test)]
mod per_mode_registration {
    use super::IkaNodeMetrics;
    use crate::ValidatorModeMetrics;
    use ika_config::NodeMode;
    use prometheus::Registry;

    /// Whether the composition registers [`SuiClientMetrics`] — flipped only
    /// by `omitting_the_sui_client_metrics_reports_them_missing`, which is
    /// what proves the pins would actually catch that struct being gated
    /// behind a mode.
    ///
    /// [`SuiClientMetrics`]: ika_sui_client::metrics::SuiClientMetrics
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SuiClient {
        Registered,
        Omitted,
    }

    /// The ika-side metric structs the start sequence registers in `mode`,
    /// composed into one registry, returning the family names the endpoint
    /// would serve.
    ///
    /// `gather()` — what `/metrics` actually serves — is the right domain
    /// here, and it omits a `*_vec` family with no label children: a family
    /// nothing has observed never reaches the endpoint. Every registered
    /// literal, vec or not, is covered instead by
    /// `scripts/check-metric-names.sh`.
    ///
    /// Three of the six `ika_sui_client_*` families are exactly that case and
    /// are therefore absent from all three lists below — not dropped, just not
    /// served until something observes them: `ika_sui_client_sui_rpc_errors`,
    /// `ika_sui_client_sui_response_errors_total` and
    /// `ika_sui_client_chain_blob_reads` are label vecs whose children are
    /// only created at an increment site. Seeding them would mean a hand-kept
    /// list of `method` (and `method`×`kind`) values, which
    /// `SuiClientMetrics` documents as the thing it deliberately does not do;
    /// the two vecs that DO have a zero baseline
    /// (`ika_sui_client_rate_limited_errors_total`,
    /// `ika_sui_client_sui_node_info`) are pre-materialized at construction
    /// and are pinned, so gating the whole struct behind a mode still shows up
    /// here.
    ///
    /// The families left out of this composition are mode-independent (the
    /// anemo/quinn network, rocksdb via `DBMetrics::init`, the mysten runtime
    /// families via `mysten_metrics::init_metrics`, archive and pruner) or
    /// already mode-gated elsewhere (the host telemetry in `node_runner`), so
    /// none of them can move a per-mode difference. `NodeConfigMetrics` is
    /// unconditional in the start sequence too and is absent here because it
    /// registers nothing at all — it is an empty struct with a no-op
    /// `record_metrics`.
    fn exported_families(mode: NodeMode) -> Vec<String> {
        composed_families(mode, SuiClient::Registered)
    }

    fn composed_families(mode: NodeMode, sui_client: SuiClient) -> Vec<String> {
        let registry = Registry::new();

        // Registered by every mode, each internally registering only the
        // families that mode's own subsystems write.
        let _epoch = ika_core::epoch::epoch_metrics::EpochMetrics::new_for_mode(mode, &registry);
        let _authority = ika_core::authority::AuthorityMetrics::new_for_mode(mode, &registry);
        let _sui_connector =
            ika_core::sui_connector::metrics::SuiConnectorMetrics::new_for_mode(mode, &registry);
        let _ocs = ika_core::sui_connector::ocs_metrics::OcsMetrics::new(&registry);
        let _proof_provider = ika_network::proof_provider::ProofProviderMetrics::new(&registry);
        let _node = IkaNodeMetrics::new(&registry);

        // Mode-independent by construction: `IkaNode::start_with_mode` builds
        // this one on `registry_service.default_registry()` before it branches
        // on the mode at all, so the notifier's and fullnode's `/metrics`
        // carry it too (ika #2124).
        if sui_client == SuiClient::Registered {
            let _sui_client = ika_sui_client::metrics::SuiClientMetrics::new(&registry);
        }

        // Registered only where the subsystems behind them run: the MPC
        // service, the checkpoint builders and the validator telemetry, plus
        // the consensus handles built inside `construct_validator_components`.
        let _validator = ValidatorModeMetrics::for_mode(mode, &registry);
        let _consensus = mode.is_validator().then(|| {
            (
                ika_core::consensus_manager::ConsensusManagerMetrics::new(&registry),
                ika_core::consensus_adapter::ConsensusAdapterMetrics::new(&registry),
            )
        });

        let mut names: Vec<String> = registry
            .gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// `(no longer exported, newly exported)` for `actual` against a pinned
    /// list — the comparison `assert_families` renders, factored out so a test
    /// can assert on the report itself rather than on a panic message.
    fn diff_families(actual: &[String], expected: &[&str]) -> (Vec<String>, Vec<String>) {
        let missing = expected
            .iter()
            .filter(|name| !actual.iter().any(|found| found == *name))
            .map(|name| (*name).to_string())
            .collect();
        let unexpected = actual
            .iter()
            .filter(|found| !expected.contains(&found.as_str()))
            .cloned()
            .collect();
        (missing, unexpected)
    }

    fn assert_families(mode: NodeMode, expected: &[&str]) {
        let (missing, unexpected) = diff_families(&exported_families(mode), expected);
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "{mode} export set changed.\n  no longer exported: {missing:?}\n  newly exported: \
             {unexpected:?}"
        );
    }

    /// The set a validator exports. This change must leave it untouched: it
    /// is the set EVERY mode registered before registration was gated.
    const VALIDATOR_FAMILIES: &[&str] = &[
        "ika_binary_max_protocol_version",
        "ika_committee_quorum_threshold",
        "ika_committee_total_stake",
        "ika_committee_validity_threshold",
        "ika_configured_max_protocol_version",
        "ika_consensus_boot_replay_folded_commit_index",
        "ika_consensus_boot_replay_latency_seconds",
        "ika_consensus_boot_replay_target_commit_index",
        "ika_consensus_calculated_throughput",
        "ika_consensus_calculated_throughput_profile",
        "ika_consensus_commit_silence_seconds",
        "ika_consensus_fold_blocked_seconds_total",
        "ika_consensus_fold_blocked_sends_total",
        "ika_consensus_handler_cancelled_transactions",
        "ika_consensus_handler_num_low_scoring_authorities",
        "ika_consensus_last_committed_timestamp_seconds",
        "ika_consensus_manager_shutdown_latency",
        "ika_consensus_manager_start_latency",
        "ika_consensus_round_channel_depth",
        "ika_current_epoch",
        "ika_current_protocol_version",
        "ika_current_voting_right",
        "ika_dwallet_checkpoint_aggregator_committed_stake",
        "ika_dwallet_checkpoint_aggregator_current_seq",
        "ika_dwallet_checkpoint_aggregator_distinct_digests",
        "ika_dwallet_checkpoint_aggregator_plurality_stake",
        "ika_dwallet_checkpoint_aggregator_uncommitted_stake",
        "ika_dwallet_checkpoint_creation_latency",
        "ika_dwallet_checkpoint_errors",
        "ika_dwallet_checkpoint_pending_queue_depth",
        "ika_dwallet_checkpoint_roots_count",
        "ika_dwallet_checkpoint_signatures_verified",
        "ika_dwallet_handoff_cert_epoch",
        "ika_dwallet_handoff_signatures_buffered",
        "ika_dwallet_handoff_signatures_collected",
        "ika_dwallet_handoff_signatures_stake",
        "ika_dwallet_mpc_catchup_gap_rounds",
        "ika_dwallet_mpc_catchup_mode",
        "ika_dwallet_mpc_cryptographic_computation_core_budget",
        "ika_dwallet_mpc_cryptographic_computations_running",
        "ika_dwallet_mpc_data_announcements_received",
        "ika_dwallet_mpc_data_excluded_validators",
        "ika_dwallet_mpc_data_freeze_epoch",
        "ika_dwallet_mpc_data_freeze_grace_rounds",
        "ika_dwallet_mpc_data_freeze_round",
        "ika_dwallet_mpc_data_locally_validated_peers",
        "ika_dwallet_mpc_data_ready_quorum_round",
        "ika_dwallet_mpc_data_ready_signal_deadline_timestamp_seconds",
        "ika_dwallet_mpc_data_ready_signal_stake",
        "ika_dwallet_mpc_data_ready_signals",
        "ika_dwallet_mpc_global_presign_requests_waiting",
        "ika_dwallet_mpc_internal_presign_requests_pending_for_network_key_data",
        "ika_dwallet_mpc_malicious_actors_count",
        "ika_dwallet_mpc_messages_after_terminal_session_total",
        "ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version",
        "ika_dwallet_mpc_network_encryption_key_latest_reconfiguration_output_version",
        "ika_dwallet_mpc_network_key_instantiations_in_flight",
        "ika_dwallet_mpc_number_of_expected_sign_sessions",
        "ika_dwallet_mpc_number_of_unexpected_sign_sessions",
        "ika_dwallet_mpc_seed_identity_state",
        "ika_dwallet_mpc_self_malicious_total",
        "ika_dwallet_mpc_prior_cert_blobs_missing",
        "ika_dwallet_mpc_requests_pending_for_frozen_mpc_data",
        "ika_dwallet_mpc_requests_pending_for_next_active_committee",
        "ika_dwallet_mpc_self_output_to_quorum_consensus_rounds",
        "ika_dwallet_mpc_service_end_of_publish_local",
        "ika_dwallet_mpc_sessions_with_self_output_no_quorum",
        "ika_dwallet_mpc_user_sessions_active_without_local_output",
        "ika_effective_buffer_stake",
        "ika_epoch_first_checkpoint_created_time_since_epoch_begin_ms",
        "ika_epoch_first_system_checkpoint_created_time_since_epoch_begin_ms",
        "ika_epoch_pending_dwallet_checkpoint_signatures",
        "ika_epoch_pending_dwallet_checkpoints",
        "ika_epoch_pending_system_checkpoint_signatures",
        "ika_epoch_pending_system_checkpoints",
        "ika_epoch_processed_consensus_messages",
        "ika_epoch_reconfig_start_time_since_epoch_close_ms",
        "ika_epoch_total_computation_reward",
        "ika_epoch_total_duration",
        "ika_epoch_validator_halt_duration_ms",
        "ika_handoff_prepare_duration_seconds",
        "ika_handoff_prepare_retries_total",
        "ika_handoff_prepare_waiting",
        "ika_highest_accumulated_system_checkpoint_epoch",
        "ika_last_certified_dwallet_checkpoint",
        "ika_last_certified_dwallet_checkpoint_age",
        "ika_last_certified_system_checkpoint",
        "ika_last_certified_system_checkpoint_age",
        "ika_last_committed_leader_consensus_round",
        "ika_last_constructed_dwallet_checkpoint",
        "ika_last_constructed_system_checkpoint",
        "ika_last_created_dwallet_checkpoint_age",
        "ika_last_created_system_checkpoint_age",
        "ika_last_dwallet_checkpoint_pending_height",
        "ika_last_ignored_dwallet_checkpoint_signature_received",
        "ika_last_ignored_system_checkpoint_signature_received",
        "ika_last_process_mpc_consensus_round",
        "ika_last_sent_dwallet_checkpoint_signature",
        "ika_last_sent_system_checkpoint_signature",
        "ika_last_skipped_dwallet_checkpoint_signature_submission",
        "ika_last_skipped_system_checkpoint_signature_submission",
        "ika_last_system_checkpoint_pending_height",
        "ika_messages_included_in_dwallet_checkpoint",
        "ika_messages_included_in_system_checkpoint",
        "ika_mpc_catch_up_stuck_condition_active",
        "ika_mpc_consensus_round_lag",
        "ika_mpc_data_announcement_blob_bytes",
        "ika_mpc_stopped_contributing_condition_active",
        "ika_network_key_overlay_incomplete",
        "ika_network_key_registry_read_empty_condition_active",
        "ika_ocs_cache_first_stale_total",
        "ika_ocs_chain_latest_epoch",
        "ika_ocs_committee_head_epoch",
        "ika_ocs_dynamic_fields_walk_entries_returned_total",
        "ika_ocs_dynamic_fields_walk_entries_seen_total",
        "ika_ocs_dynamic_fields_walk_entries_skipped_transient_total",
        "ika_ocs_high_water_violations_total",
        "ika_ocs_last_successful_relay_timestamp_seconds",
        "ika_ocs_proof_snapshot_cache_hits_total",
        "ika_ocs_proof_tree_cache_hits_total",
        "ika_ocs_proof_tree_cache_misses_total",
        "ika_ocs_pusher_cursor_seq",
        "ika_ocs_pusher_fetch_failures_total",
        "ika_ocs_pusher_fold_verify_seconds",
        "ika_ocs_pusher_gap_archive_repairs_total",
        "ika_ocs_pusher_gap_dropped_total",
        "ika_ocs_pusher_pushed_total",
        "ika_ocs_pusher_skipped_irrelevant_total",
        "ika_ocs_pusher_stalled",
        "ika_ocs_ratchet_stalled",
        "ika_off_chain_assembly_consecutive_incomplete_ticks",
        "ika_off_chain_assembly_incomplete",
        "ika_off_chain_assembly_incomplete_duration_seconds",
        "ika_off_chain_assembly_incomplete_ticks_total",
        "ika_off_chain_assembly_last_success_timestamp_seconds",
        "ika_off_chain_assembly_missing",
        "ika_off_chain_assembly_wedged",
        "ika_own_mpc_data_blob_unhealthy",
        "ika_protocol_upgrade_effective_threshold",
        "ika_protocol_upgrade_supporting_stake",
        "ika_reconfig_phase",
        "ika_remote_dwallet_checkpoint_forks",
        "ika_remote_system_checkpoint_forks",
        "ika_sequencing_certificate_authority_position",
        "ika_sequencing_certificate_positions_moved",
        "ika_sequencing_certificate_preceding_disconnected",
        "ika_sequencing_in_flight_semaphore_wait",
        "ika_sequencing_in_flight_submissions",
        "ika_skipped_consensus_txns",
        "ika_skipped_consensus_txns_cache_hit",
        "ika_split_brain_dwallet_checkpoint_forks",
        "ika_split_brain_system_checkpoint_forks",
        "ika_stranded_network_key_missing_from_registry_read_condition_active",
        // Mode-independent: every mode constructs `SuiClientMetrics`.
        "ika_sui_client_rate_limited_errors_total",
        "ika_sui_client_sui_node_info",
        "ika_sui_client_sui_node_info_last_success_unixtime",
        "ika_sui_connector_chain_active_system_sessions_count",
        "ika_sui_connector_chain_active_user_sessions_count",
        "ika_sui_connector_chain_dwallet_checkpoint_writer_lag",
        "ika_sui_connector_chain_epoch_overdue_seconds",
        "ika_sui_connector_chain_user_sessions_lag",
        "ika_sui_connector_dwallet_checkpoint_sequence",
        "ika_sui_connector_dwallet_checkpoint_write_requests_total",
        "ika_sui_connector_dwallet_checkpoint_writes_failure_total",
        "ika_sui_connector_dwallet_checkpoint_writes_success_total",
        "ika_sui_connector_gas_coin_balance",
        "ika_sui_connector_last_written_dwallet_checkpoint_sequence",
        "ika_sui_connector_last_written_system_checkpoint_sequence",
        "ika_sui_connector_system_checkpoint_sequence",
        "ika_sui_connector_system_checkpoint_write_requests_total",
        "ika_sui_connector_system_checkpoint_writes_failure_total",
        "ika_sui_connector_system_checkpoint_writes_success_total",
        "ika_sui_connector_uncompleted_events_backlog",
        "ika_supported_protocol_version_max",
        "ika_supported_protocol_version_min",
        "ika_system_checkpoint_creation_latency",
        "ika_system_checkpoint_errors",
        "ika_system_checkpoint_roots_count",
        "ika_system_checkpoint_signatures_verified",
        "verifier_runtime_per_module_success_latency",
        "verifier_runtime_per_module_timeout_latency",
        "verifier_runtime_per_ptb_success_latency",
        "verifier_runtime_per_ptb_timeout_latency",
    ];

    const NOTIFIER_FAMILIES: &[&str] = &[
        "ika_binary_max_protocol_version",
        "ika_committee_quorum_threshold",
        "ika_committee_total_stake",
        "ika_committee_validity_threshold",
        "ika_configured_max_protocol_version",
        "ika_current_epoch",
        "ika_current_protocol_version",
        "ika_current_voting_right",
        "ika_effective_buffer_stake",
        "ika_epoch_reconfig_start_time_since_epoch_close_ms",
        "ika_epoch_total_duration",
        "ika_epoch_validator_halt_duration_ms",
        "ika_network_key_overlay_incomplete",
        "ika_network_key_registry_read_empty_condition_active",
        "ika_ocs_cache_first_stale_total",
        "ika_ocs_chain_latest_epoch",
        "ika_ocs_committee_head_epoch",
        "ika_ocs_dynamic_fields_walk_entries_returned_total",
        "ika_ocs_dynamic_fields_walk_entries_seen_total",
        "ika_ocs_dynamic_fields_walk_entries_skipped_transient_total",
        "ika_ocs_high_water_violations_total",
        "ika_ocs_last_successful_relay_timestamp_seconds",
        "ika_ocs_proof_snapshot_cache_hits_total",
        "ika_ocs_proof_tree_cache_hits_total",
        "ika_ocs_proof_tree_cache_misses_total",
        "ika_ocs_pusher_cursor_seq",
        "ika_ocs_pusher_fetch_failures_total",
        "ika_ocs_pusher_fold_verify_seconds",
        "ika_ocs_pusher_gap_archive_repairs_total",
        "ika_ocs_pusher_gap_dropped_total",
        "ika_ocs_pusher_pushed_total",
        "ika_ocs_pusher_skipped_irrelevant_total",
        "ika_ocs_pusher_stalled",
        "ika_ocs_ratchet_stalled",
        "ika_protocol_upgrade_effective_threshold",
        "ika_protocol_upgrade_supporting_stake",
        "ika_reconfig_phase",
        "ika_stranded_network_key_missing_from_registry_read_condition_active",
        // Mode-independent: a notifier runs a read/write `SuiClient` of its
        // own, so it exports the same uplink telemetry a validator does.
        "ika_sui_client_rate_limited_errors_total",
        "ika_sui_client_sui_node_info",
        "ika_sui_client_sui_node_info_last_success_unixtime",
        "ika_sui_connector_dwallet_checkpoint_sequence",
        "ika_sui_connector_dwallet_checkpoint_write_requests_total",
        "ika_sui_connector_dwallet_checkpoint_writes_failure_total",
        "ika_sui_connector_dwallet_checkpoint_writes_success_total",
        "ika_sui_connector_gas_coin_balance",
        "ika_sui_connector_last_written_dwallet_checkpoint_sequence",
        "ika_sui_connector_last_written_system_checkpoint_sequence",
        "ika_sui_connector_system_checkpoint_sequence",
        "ika_sui_connector_system_checkpoint_write_requests_total",
        "ika_sui_connector_system_checkpoint_writes_failure_total",
        "ika_sui_connector_system_checkpoint_writes_success_total",
        "ika_supported_protocol_version_max",
        "ika_supported_protocol_version_min",
    ];

    const FULLNODE_FAMILIES: &[&str] = &[
        "ika_binary_max_protocol_version",
        "ika_committee_quorum_threshold",
        "ika_committee_total_stake",
        "ika_committee_validity_threshold",
        "ika_configured_max_protocol_version",
        "ika_current_epoch",
        "ika_current_protocol_version",
        "ika_current_voting_right",
        "ika_effective_buffer_stake",
        "ika_epoch_reconfig_start_time_since_epoch_close_ms",
        "ika_epoch_total_duration",
        "ika_epoch_validator_halt_duration_ms",
        "ika_network_key_overlay_incomplete",
        "ika_network_key_registry_read_empty_condition_active",
        "ika_ocs_cache_first_stale_total",
        "ika_ocs_chain_latest_epoch",
        "ika_ocs_committee_head_epoch",
        "ika_ocs_dynamic_fields_walk_entries_returned_total",
        "ika_ocs_dynamic_fields_walk_entries_seen_total",
        "ika_ocs_dynamic_fields_walk_entries_skipped_transient_total",
        "ika_ocs_high_water_violations_total",
        "ika_ocs_last_successful_relay_timestamp_seconds",
        "ika_ocs_proof_snapshot_cache_hits_total",
        "ika_ocs_proof_tree_cache_hits_total",
        "ika_ocs_proof_tree_cache_misses_total",
        "ika_ocs_pusher_cursor_seq",
        "ika_ocs_pusher_fetch_failures_total",
        "ika_ocs_pusher_fold_verify_seconds",
        "ika_ocs_pusher_gap_archive_repairs_total",
        "ika_ocs_pusher_gap_dropped_total",
        "ika_ocs_pusher_pushed_total",
        "ika_ocs_pusher_skipped_irrelevant_total",
        "ika_ocs_pusher_stalled",
        "ika_ocs_ratchet_stalled",
        "ika_protocol_upgrade_effective_threshold",
        "ika_protocol_upgrade_supporting_stake",
        "ika_reconfig_phase",
        "ika_stranded_network_key_missing_from_registry_read_condition_active",
        // Mode-independent: the connector stack's read client is a real
        // `SuiClient`, so a fullnode's uplink telemetry is the validator's.
        "ika_sui_client_rate_limited_errors_total",
        "ika_sui_client_sui_node_info",
        "ika_sui_client_sui_node_info_last_success_unixtime",
        "ika_supported_protocol_version_max",
        "ika_supported_protocol_version_min",
    ];

    #[test]
    fn a_validator_exports_every_family() {
        assert_families(NodeMode::Validator, VALIDATOR_FAMILIES);
    }

    #[test]
    fn a_notifier_exports_only_the_families_it_drives() {
        assert_families(NodeMode::Notifier, NOTIFIER_FAMILIES);
    }

    #[test]
    fn a_fullnode_exports_only_the_families_it_drives() {
        assert_families(NodeMode::Fullnode, FULLNODE_FAMILIES);
    }

    /// The pins are only worth their maintenance if they FAIL on the
    /// regression they exist for. Composing a notifier without
    /// `SuiClientMetrics` — the shape of gating that struct behind
    /// `mode.is_validator()`, which is what #2124 found the pins could not
    /// see — must report its families as no longer exported, and must not
    /// disturb anything else.
    #[test]
    fn omitting_the_sui_client_metrics_reports_them_missing() {
        let gated = composed_families(NodeMode::Notifier, SuiClient::Omitted);
        let (missing, unexpected) = diff_families(&gated, NOTIFIER_FAMILIES);

        assert_eq!(
            missing,
            vec![
                "ika_sui_client_rate_limited_errors_total".to_string(),
                "ika_sui_client_sui_node_info".to_string(),
                "ika_sui_client_sui_node_info_last_success_unixtime".to_string(),
            ],
            "gating SuiClientMetrics behind a mode must be reported as families that stopped \
             being exported"
        );
        assert!(
            unexpected.is_empty(),
            "omitting SuiClientMetrics must not add a family: {unexpected:?}"
        );
    }
}
