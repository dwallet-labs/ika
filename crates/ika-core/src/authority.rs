// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use arc_swap::{ArcSwap, Guard};
use chrono::prelude::*;
use ika_config::NodeConfig;
use ika_types::messages_consensus::{AuthorityCapabilitiesV1, MovePackageDigest};
use itertools::Itertools;
use parking_lot::Mutex;
use prometheus::{
    HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use std::{pin::Pin, sync::Arc, vec};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use tracing::{debug, error, info, instrument, warn};

use ika_types::committee::EpochId;
use ika_types::committee::ProtocolVersion;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use sui_macros::fail_point;
use sui_types::crypto::Signer;
use sui_types::digests::Digest;
use sui_types::executable_transaction::VerifiedExecutableTransaction;
use sui_types::metrics::{BytecodeVerifierMetrics, LimitsMetrics};

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::epoch_start_configuration::EpochStartConfigTrait;
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::epoch::committee_store::CommitteeStore;
use ika_config::node::AuthorityOverloadConfig;
use ika_types::{
    committee::Committee,
    crypto::{AuthorityName, AuthoritySignature},
    error::{IkaError, IkaResult},
};
use sui_types::base_types::*;

use crate::metrics::LatencyObserver;
use crate::metrics::RateTracker;
use crate::stake_aggregator::StakeAggregator;

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::dwallet_checkpoints::DWalletCheckpointStore;
use ika_types::messages_dwallet_mpc::SessionIdentifier;

pub mod authority_per_epoch_store;

pub mod authority_perpetual_tables;
pub mod epoch_start_configuration;

#[allow(unused)]
/// Prometheus metrics which can be displayed in Grafana, queried and alerted on.
pub struct AuthorityMetrics {
    pub(crate) skipped_consensus_txns: IntCounter,
    pub(crate) skipped_consensus_txns_cache_hit: IntCounter,

    /// Consensus commit and transaction handler metrics
    pub consensus_handler_processed: IntCounterVec,
    pub consensus_handler_transaction_sizes: HistogramVec,
    pub consensus_handler_num_low_scoring_authorities: IntGauge,
    pub consensus_handler_scores: IntGaugeVec,
    pub consensus_handler_cancelled_transactions: IntCounter,
    pub consensus_committed_subdags: IntCounterVec,
    pub consensus_committed_messages: IntGaugeVec,
    pub consensus_committed_user_transactions: IntGaugeVec,
    pub consensus_calculated_throughput: IntGauge,
    pub consensus_calculated_throughput_profile: IntGauge,

    pub limits_metrics: Arc<LimitsMetrics>,

    /// bytecode verifier metrics for tracking timeouts
    pub bytecode_verifier_metrics: Arc<BytecodeVerifierMetrics>,

    // Tracks recent average txn queueing delay between when it is ready for execution
    // until it starts executing.
    pub execution_queueing_latency: LatencyObserver,

    // Tracks the rate of transactions become ready for execution in transaction manager.
    // The need for the Mutex is that the tracker is updated in transaction manager and read
    // in the overload_monitor. There should be low mutex contention because
    // transaction manager is single threaded and the read rate in overload_monitor is
    // low. In the case where transaction manager becomes multi-threaded, we can
    // create one rate tracker per thread.
    pub txn_ready_rate_tracker: Arc<Mutex<RateTracker>>,

    // Tracks the rate of transactions starts execution in execution driver.
    // Similar reason for using a Mutex here as to `txn_ready_rate_tracker`.
    pub execution_rate_tracker: Arc<Mutex<RateTracker>>,
}

// Override default Prom buckets for positive numbers in 0-10M range
const POSITIVE_INT_BUCKETS: &[f64] = &[
    1., 2., 5., 7., 10., 20., 50., 70., 100., 200., 500., 700., 1000., 2000., 5000., 7000., 10000.,
    20000., 50000., 70000., 100000., 200000., 500000., 700000., 1000000., 2000000., 5000000.,
    7000000., 10000000.,
];

pub const DEV_INSPECT_GAS_COIN_VALUE: u64 = 1_000_000_000_000;

impl AuthorityMetrics {
    pub fn new(registry: &prometheus::Registry) -> AuthorityMetrics {
        Self {
            skipped_consensus_txns: register_int_counter_with_registry!(
                "ika_skipped_consensus_txns",
                "Total number of consensus transactions skipped",
                registry,
            )
            .unwrap(),
            skipped_consensus_txns_cache_hit: register_int_counter_with_registry!(
                "ika_skipped_consensus_txns_cache_hit",
                "Total number of consensus transactions skipped because of local cache hit",
                registry,
            )
            .unwrap(),
            consensus_handler_processed: register_int_counter_vec_with_registry!(
                "ika_consensus_handler_processed",
                "Number of transactions processed by consensus handler",
                &["class"],
                registry
            ).unwrap(),
            consensus_handler_transaction_sizes: register_histogram_vec_with_registry!(
                "ika_consensus_handler_transaction_sizes",
                "Sizes of each type of transactions processed by consensus handler",
                &["class"],
                POSITIVE_INT_BUCKETS.to_vec(),
                registry
            ).unwrap(),
            consensus_handler_num_low_scoring_authorities: register_int_gauge_with_registry!(
                "ika_consensus_handler_num_low_scoring_authorities",
                "Number of low scoring authorities based on reputation scores from consensus",
                registry
            ).unwrap(),
            consensus_handler_scores: register_int_gauge_vec_with_registry!(
                "ika_consensus_handler_scores",
                "scores from consensus for each authority",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_handler_cancelled_transactions: register_int_counter_with_registry!(
                "ika_consensus_handler_cancelled_transactions",
                "Number of transactions cancelled by consensus handler",
                registry,
            ).unwrap(),
            consensus_committed_subdags: register_int_counter_vec_with_registry!(
                "ika_consensus_committed_subdags",
                "Number of committed subdags, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_messages: register_int_gauge_vec_with_registry!(
                "ika_consensus_committed_messages",
                "Total number of committed consensus messages, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_user_transactions: register_int_gauge_vec_with_registry!(
                "ika_consensus_committed_user_transactions",
                "Number of committed user transactions, sliced by submitter",
                &["authority"],
                registry,
            ).unwrap(),
            limits_metrics: Arc::new(LimitsMetrics::new(registry)),
            bytecode_verifier_metrics: Arc::new(BytecodeVerifierMetrics::new(registry)),
            consensus_calculated_throughput: register_int_gauge_with_registry!(
                "ika_consensus_calculated_throughput",
                "The calculated throughput from consensus output. Result is calculated based on unique transactions.",
                registry,
            ).unwrap(),
            consensus_calculated_throughput_profile: register_int_gauge_with_registry!(
                "ika_consensus_calculated_throughput_profile",
                "The current active calculated throughput profile",
                registry
            ).unwrap(),
            execution_queueing_latency: LatencyObserver::new(),
            txn_ready_rate_tracker: Arc::new(Mutex::new(RateTracker::new(Duration::from_secs(10)))),
            execution_rate_tracker: Arc::new(Mutex::new(RateTracker::new(Duration::from_secs(10)))),
        }
    }
}

pub type ExecutionLockReadGuard<'a> = RwLockReadGuard<'a, EpochId>;
pub type ExecutionLockWriteGuard<'a> = RwLockWriteGuard<'a, EpochId>;

/// a Trait object for `Signer` that is:
/// - Pin, i.e. confined to one place in memory (we don't want to copy private keys).
/// - Sync, i.e. can be safely shared between threads.
///
/// Typically instantiated with Box::pin(keypair) where keypair is a `KeyPair`
///
pub type StableSyncAuthoritySigner = Pin<Arc<dyn Signer<AuthoritySignature> + Send + Sync>>;

pub(crate) struct AuthorityCapabilitiesVotingResults {
    pub(crate) protocol_version: ProtocolVersion,
    /// Move package ID -> Move package digest
    pub(crate) move_contracts_to_upgrade: Vec<(ObjectID, MovePackageDigest)>,
}

/// One tallied capability-vote group: the protocol-config digest, the set of
/// Move packages that group votes to upgrade, and the group's aggregated stake.
pub type ProtocolUpgradeVoteGroup = (Digest, Vec<(ObjectID, MovePackageDigest)>, u64);

/// Trait for AuthorityState, which gets created once per validator (NOT recreated on epoch switch).
pub trait AuthorityStateTrait: Sync + Send + 'static {
    fn insert_dwallet_mpc_computation_completed_sessions(
        &self,
        newly_completed_session_ids: &[SessionIdentifier],
    ) -> IkaResult;

    fn get_dwallet_mpc_sessions_completed_status(
        &self,
        session_identifiers: Vec<SessionIdentifier>,
    ) -> IkaResult<HashMap<SessionIdentifier, bool>>;
}

impl AuthorityStateTrait for AuthorityState {
    fn insert_dwallet_mpc_computation_completed_sessions(
        &self,
        newly_completed_session_ids: &[SessionIdentifier],
    ) -> IkaResult {
        self.perpetual_tables
            .insert_dwallet_mpc_computation_completed_sessions(newly_completed_session_ids)
    }

    fn get_dwallet_mpc_sessions_completed_status(
        &self,
        session_identifiers: Vec<SessionIdentifier>,
    ) -> IkaResult<HashMap<SessionIdentifier, bool>> {
        self.perpetual_tables
            .get_dwallet_mpc_sessions_completed_status(session_identifiers)
    }
}

pub struct AuthorityState {
    // Fixed size, static, identity of the authority
    /// The name of this authority.
    pub name: AuthorityName,
    /// The signature key of the authority.
    pub secret: StableSyncAuthoritySigner,

    pub(crate) perpetual_tables: Arc<AuthorityPerpetualTables>,

    epoch_store: ArcSwap<AuthorityPerEpochStore>,

    /// This lock denotes current 'execution epoch'.
    /// Execution acquires read lock, checks certificate epoch and holds it until all writes are complete.
    /// Reconfiguration acquires write lock, changes the epoch and revert all transactions
    /// from previous epoch that are executed but did not make into checkpoint.
    execution_lock: RwLock<EpochId>,

    checkpoint_store: Arc<DWalletCheckpointStore>,
    committee_store: Arc<CommitteeStore>,

    pub metrics: Arc<AuthorityMetrics>,

    pub config: NodeConfig,
}

/// The authority state encapsulates all state, drives execution, and ensures safety.
///
/// Note the authority operations can be accessed through a read ref (&) and do not
/// require &mut. Internally a database is synchronized through a mutex lock.
///
/// Repeating valid commands should produce no changes and return no error.
impl AuthorityState {
    pub fn is_validator(&self, epoch_store: &AuthorityPerEpochStore) -> bool {
        epoch_store.committee().authority_exists(&self.name)
    }

    pub fn is_fullnode(&self, epoch_store: &AuthorityPerEpochStore) -> bool {
        !self.is_validator(epoch_store)
    }

    pub fn committee_store(&self) -> &Arc<CommitteeStore> {
        &self.committee_store
    }

    pub fn clone_committee_store(&self) -> Arc<CommitteeStore> {
        self.committee_store.clone()
    }

    pub fn overload_config(&self) -> &AuthorityOverloadConfig {
        &self.config.authority_overload_config
    }

    pub fn check_system_overload_at_signing(&self) -> bool {
        self.config
            .authority_overload_config
            .check_system_overload_at_signing
    }

    fn check_protocol_version(
        supported_protocol_versions: SupportedProtocolVersions,
        current_version: ProtocolVersion,
    ) {
        info!("current protocol version is now {:?}", current_version);
        info!("supported versions are: {:?}", supported_protocol_versions);
        if !supported_protocol_versions.is_version_supported(current_version) {
            let msg = format!(
                "Unsupported protocol version. The network is at {current_version:?}, but this IkaNode only supports: {supported_protocol_versions:?}. Shutting down.",
            );

            error!("{}", msg);
            eprintln!("{msg}");

            #[cfg(not(msim))]
            std::process::exit(1);

            #[cfg(msim)]
            sui_simulator::task::shutdown_current_node();
        }
    }

    pub async fn new(
        name: AuthorityName,
        secret: StableSyncAuthoritySigner,
        supported_protocol_versions: SupportedProtocolVersions,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        committee_store: Arc<CommitteeStore>,
        checkpoint_store: Arc<DWalletCheckpointStore>,
        prometheus_registry: &Registry,
        config: NodeConfig,
    ) -> Arc<Self> {
        // The advertised capability range is constant for the process; export
        // it so fleet dashboards can measure upgrade support directly against
        // the committee thresholds (see ika_committee_quorum_threshold).
        epoch_store
            .metrics
            .supported_protocol_version_min
            .set(supported_protocol_versions.min.as_u64() as i64);
        epoch_store
            .metrics
            .supported_protocol_version_max
            .set(supported_protocol_versions.max.as_u64() as i64);
        Self::check_protocol_version(supported_protocol_versions, epoch_store.protocol_version());

        let metrics = Arc::new(AuthorityMetrics::new(prometheus_registry));

        let epoch = epoch_store.epoch();

        Arc::new(AuthorityState {
            name,
            secret,
            perpetual_tables,
            execution_lock: RwLock::new(epoch),
            epoch_store: ArcSwap::new(epoch_store.clone()),
            checkpoint_store,
            committee_store,
            metrics,
            config,
        })
    }

    /// Attempts to acquire execution lock for an executable transaction.
    /// Returns the lock if the transaction is matching current executed epoch
    /// Returns None otherwise
    pub async fn execution_lock_for_executable_transaction(
        &self,
        transaction: &VerifiedExecutableTransaction,
    ) -> IkaResult<ExecutionLockReadGuard<'_>> {
        let lock = self.execution_lock.read().await;
        if *lock == transaction.auth_sig().epoch() {
            Ok(lock)
        } else {
            Err(IkaError::WrongEpoch {
                expected_epoch: *lock,
                actual_epoch: transaction.auth_sig().epoch(),
            })
        }
    }

    /// Acquires the execution lock for the duration of a transaction signing request.
    /// This prevents reconfiguration from starting until we are finished handling the signing request.
    /// Otherwise, in-memory lock state could be cleared (by `ObjectLocks::clear_cached_locks`)
    /// while we are attempting to acquire locks for the transaction.
    pub async fn execution_lock_for_signing(&self) -> ExecutionLockReadGuard<'_> {
        self.execution_lock.read().await
    }

    pub async fn execution_lock_for_reconfiguration(&self) -> ExecutionLockWriteGuard<'_> {
        self.execution_lock.write().await
    }

    #[instrument(level = "error", skip_all)]
    pub async fn reconfigure(
        &self,
        cur_epoch_store: &AuthorityPerEpochStore,
        supported_protocol_versions: SupportedProtocolVersions,
        new_committee: Committee,
        epoch_start_configuration: EpochStartConfiguration,
    ) -> IkaResult<Arc<AuthorityPerEpochStore>> {
        Self::check_protocol_version(
            supported_protocol_versions,
            epoch_start_configuration
                .epoch_start_state()
                .protocol_version(),
        );

        self.committee_store.insert_new_committee(&new_committee)?;

        // Wait until no transactions are being executed.
        let mut execution_lock = self.execution_lock_for_reconfiguration().await;

        // Terminate all epoch-specific tasks (those started with within_alive_epoch).
        cur_epoch_store.epoch_terminated().await;

        let new_epoch = new_committee.epoch;
        let new_epoch_store = self
            .reopen_epoch_db(cur_epoch_store, new_committee, epoch_start_configuration)
            .await?;
        assert_eq!(new_epoch_store.epoch(), new_epoch);
        *execution_lock = new_epoch;
        // drop execution_lock after epoch store was updated
        // see also assert in AuthorityState::process_certificate
        // on the epoch store and execution lock epoch match
        Ok(new_epoch_store)
    }

    pub fn current_epoch_for_testing(&self) -> EpochId {
        self.epoch_store_for_testing().epoch()
    }

    /// Load the current epoch store. This can change during reconfiguration. To ensure that
    /// we never end up accessing different epoch stores in a single task, we need to make sure
    /// that this is called once per task. Each call needs to be carefully audited to ensure it is
    /// the case. This also means we should minimize the number of call-sites. Only call it when
    /// there is no way to obtain it from somewhere else.
    pub fn load_epoch_store_one_call_per_task(&self) -> Guard<Arc<AuthorityPerEpochStore>> {
        self.epoch_store.load()
    }

    /// Returns the shared `AuthorityPerpetualTables` handle. Used by
    /// producer-side broadcasters (e.g. mpc_data announcement) to
    /// persist content-addressed blobs so peers can fetch them by
    /// digest over the existing `GetMpcDataBlob` RPC.
    pub fn perpetual_tables(&self) -> Arc<AuthorityPerpetualTables> {
        self.perpetual_tables.clone()
    }

    // Load the epoch store, should be used in tests only.
    pub fn epoch_store_for_testing(&self) -> Guard<Arc<AuthorityPerEpochStore>> {
        self.load_epoch_store_one_call_per_task()
    }

    pub fn clone_committee_for_testing(&self) -> Committee {
        Committee::clone(self.epoch_store_for_testing().committee())
    }

    pub fn get_checkpoint_store(&self) -> &Arc<DWalletCheckpointStore> {
        &self.checkpoint_store
    }

    /// Ordinarily, protocol upgrades occur when 2f + 1 + (f *
    /// ProtocolConfig::buffer_stake_for_protocol_upgrade_bps) vote for the upgrade.
    ///
    /// This method can be used to dynamic adjust the amount of buffer. If set to 0, the upgrade
    /// will go through with only 2f+1 votes.
    ///
    /// IMPORTANT: If this is used, it must be used on >=2f+1 validators (all should have the same
    /// value), or you risk halting the chain.
    pub fn set_override_protocol_upgrade_buffer_stake(
        &self,
        expected_epoch: EpochId,
        buffer_stake_bps: u64,
    ) -> IkaResult {
        let epoch_store = self.load_epoch_store_one_call_per_task();
        let actual_epoch = epoch_store.epoch();
        if actual_epoch != expected_epoch {
            return Err(IkaError::WrongEpoch {
                expected_epoch,
                actual_epoch,
            });
        }

        epoch_store.set_override_protocol_upgrade_buffer_stake(buffer_stake_bps)
    }

    pub fn clear_override_protocol_upgrade_buffer_stake(
        &self,
        expected_epoch: EpochId,
    ) -> IkaResult {
        let epoch_store = self.load_epoch_store_one_call_per_task();
        let actual_epoch = epoch_store.epoch();
        if actual_epoch != expected_epoch {
            return Err(IkaError::WrongEpoch {
                expected_epoch,
                actual_epoch,
            });
        }

        epoch_store.clear_override_protocol_upgrade_buffer_stake()
    }

    /// The stake required for a protocol upgrade to arm: quorum plus
    /// `buffer_stake_bps` of f, rounded up (0bps => plain 2f+1 suffices,
    /// 10000bps => unanimity). SINGLE SOURCE OF TRUTH: consumed by the
    /// activation decision (`is_protocol_version_supported_v1`) and by the
    /// `ika_protocol_upgrade_effective_threshold` metric, so the exported
    /// activation line can never drift from what the tally enforces.
    pub fn protocol_upgrade_effective_threshold(
        committee: &Committee,
        mut buffer_stake_bps: u64,
    ) -> u64 {
        if buffer_stake_bps > 10000 {
            warn!("clamping buffer_stake_bps to 10000");
            buffer_stake_bps = 10000;
        }
        let quorum_threshold = committee.quorum_threshold();
        let f = committee.total_votes() - committee.quorum_threshold();
        // multiply by buffer_stake_bps / 10000, rounded up.
        let buffer_stake = (f * buffer_stake_bps).div_ceil(10000);
        quorum_threshold + buffer_stake
    }

    /// Group capability votes for `proposed_protocol_version` by
    /// (protocol-config digest, move contracts) and tally each group's stake,
    /// in the tally's deterministic sorted order. SINGLE SOURCE OF TRUTH for
    /// what counts as "supporting stake": the activation decision walks these
    /// groups in order, the `ika_protocol_upgrade_supporting_stake` metric
    /// reports the strongest group. `None` when nobody votes for the version.
    pub fn tally_protocol_upgrade_votes(
        proposed_protocol_version: ProtocolVersion,
        committee: &Committee,
        capabilities: Vec<AuthorityCapabilitiesV1>,
    ) -> Option<Vec<ProtocolUpgradeVoteGroup>> {
        // For each validator, gather the protocol version and system packages that it would like
        // to upgrade to in the next epoch.
        let mut desired_upgrades: Vec<_> = capabilities
            .into_iter()
            .filter_map(|cap| {
                debug!(
                    "validator {:?} supports {:?} with move packages: {:?}",
                    cap.authority.concise(),
                    cap.supported_protocol_versions,
                    cap.move_contracts_to_upgrade,
                );

                // A validator that only supports the current protocol version is also voting
                // against any change, because framework upgrades always require a protocol version
                // bump.
                cap.supported_protocol_versions
                    .get_version_digest(proposed_protocol_version)
                    .map(|digest| (digest, cap.move_contracts_to_upgrade, cap.authority))
            })
            .collect();

        if desired_upgrades.is_empty() {
            return None;
        }

        // There can only be one set of votes that have a majority, find one if it exists.
        desired_upgrades.sort();
        Some(
            desired_upgrades
                .into_iter()
                .chunk_by(|(digest, move_contracts_to_upgrade, _authority)| {
                    (*digest, move_contracts_to_upgrade.clone())
                })
                .into_iter()
                .map(|((digest, move_contracts_to_upgrade), group)| {
                    let mut stake_aggregator: StakeAggregator<(), true> =
                        StakeAggregator::new(Arc::new(committee.clone()));

                    for (_, _, authority) in group {
                        stake_aggregator.insert_generic(authority, ());
                    }

                    (
                        digest,
                        move_contracts_to_upgrade,
                        stake_aggregator.total_votes(),
                    )
                })
                .collect(),
        )
    }

    fn is_protocol_version_supported_v1(
        proposed_protocol_version: ProtocolVersion,
        committee: &Committee,
        capabilities: Vec<AuthorityCapabilitiesV1>,
        buffer_stake_bps: u64,
    ) -> (Option<AuthorityCapabilitiesVotingResults>, bool) {
        let effective_threshold =
            Self::protocol_upgrade_effective_threshold(committee, buffer_stake_bps);

        let Some(vote_groups) =
            Self::tally_protocol_upgrade_votes(proposed_protocol_version, committee, capabilities)
        else {
            return (None, true);
        };

        let res =
            vote_groups
                .into_iter()
                .find_map(|(digest, move_contracts_to_upgrade, total_votes)| {
                    let has_support = total_votes >= effective_threshold;

                    info!(
                        protocol_config_digest = ?digest,
                        ?total_votes,
                        ?buffer_stake_bps,
                        ?effective_threshold,
                        ?proposed_protocol_version,
                        ?move_contracts_to_upgrade,
                        has_support,
                        "checking support for upgrade"
                    );

                    has_support.then_some(AuthorityCapabilitiesVotingResults {
                        protocol_version: proposed_protocol_version,
                        move_contracts_to_upgrade,
                    })
                });
        (res, false)
    }

    pub(crate) fn choose_highest_protocol_version_and_move_contracts_upgrades_v1(
        current_protocol_version: ProtocolVersion,
        committee: &Committee,
        capabilities: Vec<AuthorityCapabilitiesV1>,
        buffer_stake_bps: u64,
    ) -> AuthorityCapabilitiesVotingResults {
        let mut next_protocol_version = current_protocol_version;
        let mut versions = vec![];
        let mut completed = false;

        while !completed {
            let (version, current_completed) = Self::is_protocol_version_supported_v1(
                next_protocol_version,
                committee,
                capabilities.clone(),
                buffer_stake_bps,
            );
            completed = current_completed;
            versions.push(version);
            next_protocol_version = next_protocol_version + 1;
        }

        let versions = versions.into_iter().flatten().collect_vec();
        let last_version = versions.into_iter().last();

        if let Some(version) = last_version {
            version
        } else {
            AuthorityCapabilitiesVotingResults {
                protocol_version: current_protocol_version,
                move_contracts_to_upgrade: vec![],
            }
        }
    }

    pub fn unixtime_now_ms() -> u64 {
        let ts_ms = Utc::now().timestamp_millis();
        u64::try_from(ts_ms).expect("Travelling in time machine")
    }

    #[instrument(level = "error", skip_all)]
    async fn reopen_epoch_db(
        &self,
        cur_epoch_store: &AuthorityPerEpochStore,
        new_committee: Committee,
        epoch_start_configuration: EpochStartConfiguration,
    ) -> IkaResult<Arc<AuthorityPerEpochStore>> {
        let new_epoch = new_committee.epoch;
        info!(new_epoch = ?new_epoch, "re-opening AuthorityEpochTables for new epoch");
        assert_eq!(
            epoch_start_configuration.epoch_start_state().epoch(),
            new_committee.epoch
        );
        fail_point!("before-open-new-epoch-store");
        let new_epoch_store = cur_epoch_store.new_at_next_epoch(
            self.name,
            new_committee,
            epoch_start_configuration,
            cur_epoch_store.get_chain_identifier(),
        )?;
        // The new epoch store starts with `perpetual_tables_for_handoff`
        // empty. Install ours so the per-epoch handoff record path
        // persists freshly certified attestations into perpetual
        // storage from this epoch onward (mirrors what
        // `IkaNode::new` does for the genesis epoch store). Without
        // this, every reconfig after the first drops handoff certs
        // silently — the cert insert site logs "perpetual tables
        // not installed; handoff cert not persisted" and joiners
        // never see the cert that authenticated their place in the
        // committee.
        new_epoch_store.install_perpetual_tables_for_handoff(self.perpetual_tables.clone());
        self.epoch_store.store(new_epoch_store.clone());
        Ok(new_epoch_store)
    }
}
