// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    num::NonZeroUsize,
    sync::Arc,
};

use crate::system_checkpoints::SystemCheckpointService;
use crate::{
    authority::{
        AuthorityMetrics, AuthorityState,
        authority_per_epoch_store::{
            AuthorityPerEpochStore, ConsensusStats, ConsensusStatsAPI, ExecutionIndices,
            ExecutionIndicesWithStats,
        },
    },
    consensus_throughput_calculator::ConsensusThroughputCalculator,
    consensus_types::consensus_output_api::ConsensusCommitAPI,
    dwallet_checkpoints::{DWalletCheckpointService, DWalletCheckpointServiceNotify},
    scoring_decision::update_low_scoring_authorities,
};
use arc_swap::ArcSwap;
use consensus_config::Committee as ConsensusCommittee;
use consensus_core::storage::Store;
use consensus_core::storage::rocksdb_store::RocksDBStore;
use consensus_core::{CommitAPI, CommitConsumerMonitor};
use ika_protocol_config::ProtocolConfig;
use ika_types::crypto::AuthorityName;
use ika_types::digests::ConsensusCommitDigest;
use ika_types::messages_consensus::{
    AuthorityIndex, ConsensusTransaction, ConsensusTransactionKey, ConsensusTransactionKind,
};
use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
use lru::LruCache;
use mysten_metrics::{monitored_future, monitored_mpsc::UnboundedReceiver, monitored_scope};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sui_macros::{fail_point_async, fail_point_if};
use sui_types::base_types::EpochId;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{debug, error, instrument, trace_span, warn};

/// Notified once for every consensus commit this node RECEIVES.
///
/// Arrival, not completion — and the distinction is load-bearing. The
/// watchdog behind this sink exits the node when commits stop for longer than
/// its bound, and it exists to catch a validator whose consensus
/// subscriptions were lost at an epoch boundary (ika #1864): the failure it
/// names is commits no longer ARRIVING. Nothing else distinguishes that from
/// a quiet network — `ika_dwallet_mpc_catchup_gap_rounds` in particular reads
/// 0 on an isolated node.
///
/// This used to be reported after the commit boundary finished, on the
/// argument that a handler wedged inside the boundary has stopped making
/// progress just as completely as one receiving nothing. That argument no
/// longer holds, because the boundary can now block legitimately: it hands
/// each round to the MPC drain over a bounded channel and waits when the
/// drain is behind (`authority::round_transport`). A deep burst can hold the
/// fold for longer than the watchdog's bound, and reporting on completion
/// would make the node kill itself for being busy — then replay, meet the
/// same burst, and do it again.
///
/// KNOWN GAP, deliberate: a fold that is genuinely WEDGED — as opposed to
/// blocked on a drain that is still consuming — no longer trips this
/// watchdog, because commits keep arriving. That case is covered by
/// observability rather than by self-exit: `ika_consensus_round_channel_depth`
/// pinned at capacity together with `ika_consensus_fold_blocked_seconds_total`
/// climbing while `ika_last_process_mpc_consensus_round` is flat is a wedged drain,
/// and the MPC lag alarm fires on it. Do not "fix" this by moving the call
/// back after the boundary.
///
/// Consumers must be cheap and non-blocking: this runs on the commit path,
/// once per commit, at sub-second cadence.
pub trait ConsensusCommitSink: Send + Sync {
    fn commit_received(&self, leader_round: u64);
}

pub struct ConsensusHandlerInitializer {
    state: Arc<AuthorityState>,
    checkpoint_service: Option<Arc<DWalletCheckpointService>>,
    system_checkpoint_service: Option<Arc<SystemCheckpointService>>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    low_scoring_authorities: Arc<ArcSwap<HashMap<AuthorityName, u64>>>,
    throughput_calculator: Arc<ConsensusThroughputCalculator>,
    commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
}

impl ConsensusHandlerInitializer {
    pub fn new(
        state: Arc<AuthorityState>,
        checkpoint_service: Option<Arc<DWalletCheckpointService>>,
        system_checkpoint_service: Option<Arc<SystemCheckpointService>>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        low_scoring_authorities: Arc<ArcSwap<HashMap<AuthorityName, u64>>>,
        throughput_calculator: Arc<ConsensusThroughputCalculator>,
        commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
    ) -> Self {
        Self {
            state,
            checkpoint_service,
            system_checkpoint_service,
            epoch_store,
            low_scoring_authorities,
            throughput_calculator,
            commit_sink,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_for_testing(
        state: Arc<AuthorityState>,
        checkpoint_service: Option<Arc<DWalletCheckpointService>>,
        system_checkpoint_service: Option<Arc<SystemCheckpointService>>,
    ) -> Self {
        Self {
            state: state.clone(),
            checkpoint_service,
            system_checkpoint_service,
            epoch_store: state.epoch_store_for_testing().clone(),
            low_scoring_authorities: Arc::new(Default::default()),
            throughput_calculator: Arc::new(ConsensusThroughputCalculator::new(
                None,
                state.metrics.clone(),
            )),
            commit_sink: None,
        }
    }

    pub(crate) fn new_consensus_handler(self) -> ConsensusHandler<DWalletCheckpointService> {
        let new_epoch_start_state = self.epoch_store.epoch_start_state();
        let consensus_committee = new_epoch_start_state.get_consensus_committee();

        ConsensusHandler::new(
            self.epoch_store,
            self.checkpoint_service,
            self.system_checkpoint_service,
            self.low_scoring_authorities,
            consensus_committee,
            self.state.metrics.clone(),
            self.throughput_calculator,
            self.commit_sink,
        )
    }

    // todo(zeev): fix
    #[allow(dead_code)]
    pub(crate) fn metrics(&self) -> &Arc<AuthorityMetrics> {
        &self.state.metrics
    }
}

pub struct ConsensusHandler<C> {
    /// A store created for each epoch. ConsensusHandler is recreated each epoch, with the
    /// corresponding store. This store is also used to get the current epoch ID.
    epoch_store: Arc<AuthorityPerEpochStore>,
    /// Holds the indices, hash and stats after the last consensus commit
    /// It is used for avoiding replaying already processed transactions,
    /// checking chain consistency, and accumulating per-epoch consensus output stats.
    last_consensus_stats: ExecutionIndicesWithStats,
    checkpoint_service: Option<Arc<C>>,
    system_checkpoint_service: Option<Arc<SystemCheckpointService>>,
    /// Reputation scores used by consensus adapter that we update, forwarded from consensus
    low_scoring_authorities: Arc<ArcSwap<HashMap<AuthorityName, u64>>>,
    /// The consensus committee used to do stake computations for deciding set of low scoring authorities
    committee: ConsensusCommittee,
    // TODO: ConsensusHandler doesn't really share metrics with AuthorityState. We could define
    // a new metrics type here if we want to.
    metrics: Arc<AuthorityMetrics>,
    /// Lru cache to quickly discard transactions processed by consensus
    processed_cache: LruCache<SequencedConsensusTransactionKey, ()>,
    /// Using the throughput calculator to record the current consensus throughput
    throughput_calculator: Arc<ConsensusThroughputCalculator>,
    /// Notified once per processed commit. Unlike everything else here it is
    /// process-scoped, not epoch-scoped: it outlives the handler so that the
    /// interval between the LAST commit of one epoch's handler and the FIRST
    /// commit of the next one's is measurable — which is precisely the
    /// interval that never ends on an isolated validator (ika #1864).
    commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
}

const PROCESSED_CACHE_CAP: usize = 1024 * 1024;

impl<C> ConsensusHandler<C> {
    pub fn new(
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_service: Option<Arc<C>>,
        system_checkpoint_service: Option<Arc<SystemCheckpointService>>,
        low_scoring_authorities: Arc<ArcSwap<HashMap<AuthorityName, u64>>>,
        committee: ConsensusCommittee,
        metrics: Arc<AuthorityMetrics>,
        throughput_calculator: Arc<ConsensusThroughputCalculator>,
        commit_sink: Option<Arc<dyn ConsensusCommitSink>>,
    ) -> Self {
        // Recover last_consensus_stats so it is consistent across validators.
        let mut last_consensus_stats = epoch_store
            .get_last_consensus_stats()
            .expect("Should be able to read last consensus index");
        // stats is empty at the beginning of epoch.
        if !last_consensus_stats.stats.is_initialized() {
            last_consensus_stats.stats = ConsensusStats::new(committee.size());
        }

        Self {
            epoch_store,
            last_consensus_stats,
            checkpoint_service,
            system_checkpoint_service,
            low_scoring_authorities,
            committee,
            metrics,
            processed_cache: LruCache::new(NonZeroUsize::new(PROCESSED_CACHE_CAP).unwrap()),
            throughput_calculator,
            commit_sink,
        }
    }
}

impl<C> ConsensusHandler<C> {
    /// Reports a commit's ARRIVAL to the commit-liveness watchdog.
    ///
    /// Called by every path that receives a commit — the live loop and the
    /// boot replay alike — before the fold, so that a fold waiting on the MPC
    /// drain never reads as consensus silence. Boot replay reports too, which
    /// is what arms the watchdog on a node whose whole start is replay.
    pub(crate) fn report_commit_received(&self, consensus_commit: &impl ConsensusCommitAPI) {
        let round = consensus_commit.leader_round();
        // Also the catch-up gate's view of how far there is to go. Recorded
        // here, on arrival, because the fold's own position cannot answer it:
        // the fold is never more than the round channel's capacity ahead of
        // the drain.
        self.epoch_store.record_observed_consensus_head_round(round);
        if let Some(sink) = &self.commit_sink {
            sink.commit_received(round);
        }
    }

    /// Publishes the consensus store's head before the boot replay folds
    /// anything.
    ///
    /// Arrival reporting alone is not enough during replay: the replay's
    /// arrivals ARE its folds, so under a blocking transport they advance
    /// only as fast as the drain and the gate would see a gap no larger than
    /// the channel. Publishing the target up front is what lets the gate see
    /// the real backlog — the hundreds of thousands of rounds it exists for.
    pub(crate) fn publish_observed_consensus_head(&self, round: u64) {
        self.epoch_store.record_observed_consensus_head_round(round);
    }
}

impl<C: DWalletCheckpointServiceNotify + Send + Sync> ConsensusHandler<C> {
    /// Folds one consensus commit into this epoch's derived state.
    ///
    /// The same entry point serves live commits and the boot replay that
    /// rebuilds the epoch from the consensus store
    /// (`consensus_manager::boot_replay`) — deliberately, because the two must
    /// produce identical state from identical commits, and a second fold
    /// implementation is a second thing that can disagree.
    #[instrument(level = "debug", skip_all)]
    pub(crate) async fn handle_consensus_commit(
        &mut self,
        consensus_commit: impl ConsensusCommitAPI,
    ) {
        let _scope = monitored_scope("ConsensusCommitHandler::handle_consensus_commit");
        let round = consensus_commit.leader_round();

        let last_committed_round = self.last_consensus_stats.index.last_committed_round;

        // more than one leader per round so we are not in danger of ignoring any commits.
        assert!(round >= last_committed_round);
        if last_committed_round == round {
            // we can receive the same commit twice after restart
            // It is critical that the writes done by this function are atomic - otherwise we can
            // lose the later parts of a commit if we restart midway through processing it.
            warn!(
                "Ignoring consensus output for round {} as it is already committed. NOTE: This is only expected if consensus is running.",
                round
            );
            return;
        }

        /* (transaction, serialized length) */
        let mut transactions = vec![];
        let timestamp = consensus_commit.commit_timestamp_ms();
        let leader_author = consensus_commit.leader_author_index();
        let commit_sub_dag_index = consensus_commit.commit_sub_dag_index();

        let epoch_start = self
            .epoch_store
            .epoch_start_config()
            .epoch_start_timestamp_ms();
        let timestamp = if timestamp < epoch_start {
            error!(
                "Unexpected commit timestamp {timestamp} less then epoch start time {epoch_start}, author {leader_author}, round {round}",
            );
            epoch_start
        } else {
            timestamp
        };

        debug!(
            %consensus_commit,
            epoch = ?self.epoch_store.epoch(),
            "Received consensus output"
        );

        let execution_index = ExecutionIndices {
            last_committed_round: round,
            sub_dag_index: commit_sub_dag_index,
            transaction_index: 0_u64,
        };
        // This function has filtered out any already processed consensus output.
        // So we can safely assume that the index is always increasing.
        assert!(self.last_consensus_stats.index < execution_index);

        // TODO: test empty commit explicitly.
        // Note that consensus commit batch may contain no transactions, but we still need to record the current
        // round and subdag index in the last_consensus_stats, so that it won't be re-executed in the future.
        self.last_consensus_stats.index = execution_index;

        update_low_scoring_authorities(
            self.low_scoring_authorities.clone(),
            self.epoch_store.committee(),
            &self.committee,
            consensus_commit.reputation_score_sorted_desc(),
            &self.metrics,
            self.epoch_store
                .protocol_config()
                .consensus_bad_nodes_stake_threshold(),
        );

        self.metrics
            .consensus_committed_subdags
            .with_label_values(&[&leader_author.to_string()])
            .inc();

        {
            let span = trace_span!("ConsensusHandler::HandleCommit::process_consensus_txns");
            let _guard = span.enter();
            for (block, parsed_transactions) in consensus_commit.transactions() {
                let author = block.author.value();
                // TODO: consider only messages within 1~3 rounds of the leader?
                self.last_consensus_stats.stats.inc_num_messages(author);
                for parsed in parsed_transactions {
                    if parsed.rejected {
                        // Skip executing rejected transactions.
                        continue;
                    }
                    let kind = classify(&parsed.transaction);
                    self.metrics
                        .consensus_handler_processed
                        .with_label_values(&[kind])
                        .inc();
                    self.metrics
                        .consensus_handler_transaction_sizes
                        .with_label_values(&[kind])
                        .observe(parsed.serialized_len as f64);
                    let transaction =
                        SequencedConsensusTransactionKind::External(parsed.transaction);
                    transactions.push((transaction, author as u32));
                }
            }
        }
        debug!(num_txs = transactions.len(), "Parsed transactions");
        for (i, authority) in self.committee.authorities() {
            let hostname = &authority.hostname;
            self.metrics
                .consensus_committed_messages
                .with_label_values(&[hostname])
                .set(self.last_consensus_stats.stats.get_num_messages(i.value()) as i64);
            self.metrics
                .consensus_committed_user_transactions
                .with_label_values(&[hostname])
                .set(
                    self.last_consensus_stats
                        .stats
                        .get_num_user_transactions(i.value()) as i64,
                );
        }

        let mut all_transactions = Vec::new();
        {
            // We need a set here as well, since the processed_cache is a LRU cache and can drop
            // entries while we're iterating over the sequenced transactions.
            let mut processed_set = HashSet::new();

            for (seq, (transaction, cert_origin)) in transactions.into_iter().enumerate() {
                // In process_consensus_transactions_and_commit_boundary(), we will add a system consensus commit
                // prologue transaction, which will be the first transaction in this consensus commit batch.
                // Therefore, the transaction sequence number starts from 1 here.
                let current_tx_index = ExecutionIndices {
                    last_committed_round: round,
                    sub_dag_index: commit_sub_dag_index,
                    transaction_index: (seq + 1) as u64,
                };

                self.last_consensus_stats.index = current_tx_index;

                let certificate_author = *self
                    .epoch_store
                    .committee()
                    .authority_by_index(cert_origin)
                    .unwrap();

                let sequenced_transaction = SequencedConsensusTransaction {
                    certificate_author_index: cert_origin,
                    certificate_author,
                    consensus_index: current_tx_index,
                    transaction,
                };

                // Verify before keying the dedup structures, matching the
                // ordering used upstream: only an authenticated transaction
                // should occupy a dedup key, since the key is derived from
                // fields the submitter controls.
                let Some(verified_transaction) = self.epoch_store.verify_consensus_transaction(
                    sequenced_transaction,
                    &self.metrics.skipped_consensus_txns,
                ) else {
                    continue;
                };

                let key = verified_transaction.0.key();
                let in_set = !processed_set.insert(key.clone());
                // The LRU is a local fast path in front of the durable
                // `is_consensus_message_processed` check, so declining to cache
                // a key costs one DB read and nothing else. The MPC-payload key
                // variants (see `embeds_payload`) embed their whole payload, so
                // admitting them budgets `PROCESSED_CACHE_CAP` entries times an
                // unbounded per-entry size — a cap in name only. They are the
                // ones least worth caching anyway: an MPC message or output is
                // submitted once.
                let in_cache = if key.embeds_payload() {
                    false
                } else {
                    self.processed_cache.put(key, ()).is_some()
                };

                if in_set || in_cache {
                    self.metrics.skipped_consensus_txns_cache_hit.inc();
                    continue;
                }

                all_transactions.push(verified_transaction);
            }
        }

        let (executable_transactions, system_checkpoint_executable_transactions) = self
            .epoch_store
            .process_consensus_transactions_and_commit_boundary(
                all_transactions,
                &self.last_consensus_stats,
                &self.checkpoint_service,
                &self.system_checkpoint_service,
                &ConsensusCommitInfo::new(self.epoch_store.protocol_config(), &consensus_commit),
                &self.metrics,
            )
            .await
            .expect("Unrecoverable error in consensus handler");

        // update the calculated throughput
        self.throughput_calculator.add_transactions(
            timestamp,
            (executable_transactions.len() + system_checkpoint_executable_transactions.len())
                as u64,
        );

        fail_point_if!("correlated-crash-after-consensus-commit-boundary", || {
            let key = [commit_sub_dag_index, self.epoch_store.epoch()];
            if sui_simulator::random::deterministic_probability(key, 0.01) {
                sui_simulator::task::kill_current_node(None);
            }
        });

        fail_point_async!("crash"); // for tests that produce random crashes
    }
}

/// Manages the lifetime of tasks handling the commits and transactions output by consensus.
pub(crate) struct MysticetiConsensusHandler {
    tasks: JoinSet<()>,
}

impl MysticetiConsensusHandler {
    /// Starts the task that folds commits as consensus delivers them.
    ///
    /// There is no already-processed skip here any more, and no watermark to
    /// drive one. The boot replay has already folded the consensus store up to
    /// its replay target — the store's last commit, or its last finalized
    /// commit where transaction voting is on
    /// (`consensus_manager::boot_replay::replay_epoch_commits`) — and consensus
    /// is started with that same index as its `replay_after_commit_index`, so
    /// nothing consensus delivers has been folded before. On ika, where voting
    /// is off at every protocol version, that target is the store head and
    /// consensus re-delivers nothing at all. The watermark that used to gate
    /// this loop was a second
    /// record of the same fact as the consensus store's head, kept in a
    /// different database — and when the two disagreed the node could not start
    /// at all (ika #2057).
    pub(crate) fn new(
        mut consensus_handler: ConsensusHandler<DWalletCheckpointService>,
        mut commit_receiver: UnboundedReceiver<consensus_core::CommittedSubDag>,
        commit_consumer_monitor: Arc<CommitConsumerMonitor>,
    ) -> Self {
        let mut tasks = JoinSet::new();
        tasks.spawn(monitored_future!(async move {
            // TODO: pause when execution is overloaded, so consensus can detect the backpressure.
            while let Some(consensus_commit) = commit_receiver.recv().await {
                let commit_index = consensus_commit.commit_ref.index;
                // Report ARRIVAL, before the fold — the fold can block on the
                // drain for longer than the watchdog's bound, and a node that
                // killed itself for that would replay into the same burst.
                consensus_handler.report_commit_received(&consensus_commit);
                consensus_handler
                    .handle_consensus_commit(consensus_commit)
                    .await;
                commit_consumer_monitor.set_highest_handled_commit(commit_index);
            }
        }));
        Self { tasks }
    }

    /// Publishes the consensus store's own head round, on a task of its own,
    /// until the epoch ends.
    ///
    /// The catch-up gate needs to know how far behind the drain is. It cannot
    /// learn that from the fold: the fold BLOCKS on the round channel, so the
    /// arrivals stamped in the loop above stop the moment the drain falls a
    /// channel's-worth behind. Everything the fold can report is therefore
    /// pinned within the capacity (1,024) of the drain's own cursor, always
    /// far below the gate's entry threshold — and a validator that fell a
    /// hundred thousand rounds behind WITHOUT restarting would never enter
    /// catch-up at all, which is precisely the collapse the gate was built for
    /// (#2023). Only a restart would fix it, via the boot replay's head
    /// publication.
    ///
    /// The consensus store is the one place the true backlog is visible: it is
    /// written by consensus-core as commits are decided, and nothing about
    /// that path waits on the fold. `ConsensusAuthority::store()` hands out the
    /// RUNNING instance's own handle, so this is not a second RocksDB open and
    /// cannot contend for the lock.
    ///
    /// This shares the handler's `JoinSet` deliberately: the set is shut down
    /// by `abort()` at the epoch boundary, which is exactly this task's
    /// lifetime. It must NOT hold the `ConsensusAuthority` itself — shutdown
    /// `Arc::try_unwrap`s that and panics on a surviving reference — and it
    /// does not need to; the store handle is a separate `Arc`.
    pub(crate) fn spawn_observed_head_publisher(
        &mut self,
        store: Arc<RocksDBStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
    ) {
        const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);
        self.tasks.spawn(monitored_future!(async move {
            loop {
                match store.read_last_commit() {
                    Ok(Some(commit)) => {
                        epoch_store
                            .record_observed_consensus_head_round(commit.leader().round as u64);
                    }
                    // An epoch whose consensus store has no commit yet: there
                    // is no head to report and no backlog to be behind.
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            error = ?e,
                            "failed to read the consensus store's head; the catch-up gate will \
                             keep the last head it was given until this recovers"
                        );
                    }
                }
                sleep(PUBLISH_INTERVAL).await;
            }
        }));
    }

    pub(crate) async fn abort(&mut self) {
        self.tasks.shutdown().await;
    }
}

impl<C> ConsensusHandler<C> {
    #[allow(dead_code)]
    fn epoch(&self) -> EpochId {
        self.epoch_store.epoch()
    }
}

pub(crate) fn classify(transaction: &ConsensusTransaction) -> &'static str {
    match &transaction.kind {
        ConsensusTransactionKind::DWalletCheckpointSignature(_) => "dwallet_checkpoint_signature",
        ConsensusTransactionKind::DWalletMPCMessage(..) => "dwallet_mpc_message",
        ConsensusTransactionKind::DWalletMPCOutput(..) => "dwallet_mpc_output",
        ConsensusTransactionKind::DWalletInternalMPCOutput(..) => "dwallet_internal_mpc_output",
        ConsensusTransactionKind::CapabilityNotificationV1(_) => "capability_notification_v1",
        ConsensusTransactionKind::SystemCheckpointSignature(_) => "system_checkpoint_signature",
        ConsensusTransactionKind::EndOfPublish(_) => "end_of_publish",
        ConsensusTransactionKind::IdleStatusUpdate(_) => "idle_status_update",
        ConsensusTransactionKind::SuiChainObservationUpdate(_) => "sui_chain_observation_update",
        ConsensusTransactionKind::GlobalPresignRequest(_) => "global_presign_request",
        ConsensusTransactionKind::NOAObservation(_) => "noa_observation",
        ConsensusTransactionKind::NOAPresignDemand(_) => "noa_presign_demand",
        ConsensusTransactionKind::ValidatorMpcDataAnnouncement(..) => {
            "validator_mpc_data_announcement"
        }
        ConsensusTransactionKind::RelayedValidatorMpcDataAnnouncement(..) => {
            "relayed_validator_mpc_data_announcement"
        }
        ConsensusTransactionKind::EpochMpcDataReadySignal(_) => "epoch_mpc_data_ready_signal",
        ConsensusTransactionKind::EndOfPublishV2 { .. } => "end_of_publish_v2",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedConsensusTransaction {
    pub certificate_author_index: AuthorityIndex,
    pub certificate_author: AuthorityName,
    pub consensus_index: ExecutionIndices,
    pub transaction: SequencedConsensusTransactionKind,
}

#[derive(Debug, Clone)]
pub enum SequencedConsensusTransactionKind {
    External(ConsensusTransaction),
}

impl Serialize for SequencedConsensusTransactionKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let serializable = SerializableSequencedConsensusTransactionKind::from(self);
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SequencedConsensusTransactionKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let serializable =
            SerializableSequencedConsensusTransactionKind::deserialize(deserializer)?;
        Ok(serializable.into())
    }
}

// We can't serialize SequencedConsensusTransactionKind directly because it contains a
// VerifiedExecutableTransaction, which is not serializable (by design). This wrapper allows us to
// convert to a serializable format easily.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SerializableSequencedConsensusTransactionKind {
    External(ConsensusTransaction),
}

impl From<&SequencedConsensusTransactionKind> for SerializableSequencedConsensusTransactionKind {
    fn from(kind: &SequencedConsensusTransactionKind) -> Self {
        match kind {
            SequencedConsensusTransactionKind::External(ext) => {
                SerializableSequencedConsensusTransactionKind::External(ext.clone())
            }
        }
    }
}

impl From<SerializableSequencedConsensusTransactionKind> for SequencedConsensusTransactionKind {
    fn from(kind: SerializableSequencedConsensusTransactionKind) -> Self {
        match kind {
            SerializableSequencedConsensusTransactionKind::External(ext) => {
                SequencedConsensusTransactionKind::External(ext)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Hash, PartialEq, Eq, Debug, Ord, PartialOrd)]
pub enum SequencedConsensusTransactionKey {
    External(ConsensusTransactionKey),
}

impl SequencedConsensusTransactionKey {
    /// See [`ConsensusTransactionKey::embeds_payload`].
    pub fn embeds_payload(&self) -> bool {
        match self {
            Self::External(key) => key.embeds_payload(),
        }
    }
}

impl SequencedConsensusTransactionKind {
    pub fn key(&self) -> SequencedConsensusTransactionKey {
        match self {
            SequencedConsensusTransactionKind::External(ext) => {
                SequencedConsensusTransactionKey::External(ext.key())
            }
        }
    }

    pub fn get_tracking_id(&self) -> u64 {
        match self {
            SequencedConsensusTransactionKind::External(ext) => ext.get_tracking_id(),
        }
    }
}

impl SequencedConsensusTransaction {
    pub fn sender_authority(&self) -> AuthorityName {
        self.certificate_author
    }

    pub fn key(&self) -> SequencedConsensusTransactionKey {
        self.transaction.key()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSequencedConsensusTransaction(pub SequencedConsensusTransaction);

#[cfg(test)]
impl VerifiedSequencedConsensusTransaction {
    pub fn new_test(transaction: ConsensusTransaction) -> Self {
        Self(SequencedConsensusTransaction::new_test(transaction))
    }
}

impl SequencedConsensusTransaction {
    pub fn new_test(transaction: ConsensusTransaction) -> Self {
        Self {
            certificate_author_index: 0,
            certificate_author: AuthorityName::ZERO,
            consensus_index: Default::default(),
            transaction: SequencedConsensusTransactionKind::External(transaction),
        }
    }
}

/// Represents the information from the current consensus commit.
pub struct ConsensusCommitInfo {
    pub round: u64,
    pub timestamp: u64,
    pub consensus_commit_digest: ConsensusCommitDigest,

    #[cfg(any(test, feature = "test-utils"))]
    skip_consensus_commit_prologue_in_test: bool,
}

impl ConsensusCommitInfo {
    fn new(_protocol_config: &ProtocolConfig, consensus_commit: &impl ConsensusCommitAPI) -> Self {
        Self {
            round: consensus_commit.leader_round(),
            timestamp: consensus_commit.commit_timestamp_ms(),
            consensus_commit_digest: consensus_commit.consensus_digest(),

            #[cfg(any(test, feature = "test-utils"))]
            skip_consensus_commit_prologue_in_test: false,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(
        commit_round: u64,
        commit_timestamp: u64,
        skip_consensus_commit_prologue_in_test: bool,
    ) -> Self {
        Self {
            round: commit_round,
            timestamp: commit_timestamp,
            consensus_commit_digest: ConsensusCommitDigest::default(),
            skip_consensus_commit_prologue_in_test,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn skip_consensus_commit_prologue_in_test(&self) -> bool {
        self.skip_consensus_commit_prologue_in_test
    }
}
