// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use arc_swap::{ArcSwap, Guard};
use chrono::prelude::*;
use ika_config::NodeConfig;
use ika_types::messages_consensus::{AuthorityCapabilitiesV1, MovePackageDigest};
use itertools::Itertools;
use mysten_metrics::{TX_TYPE_SHARED_OBJ_TX, TX_TYPE_SINGLE_WRITER_TX};
use parking_lot::Mutex;
use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
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
#[cfg(msim)]
use sui_types::committee::CommitteeTrait;

pub mod authority_per_epoch_store;

pub mod authority_perpetual_tables;
pub mod epoch_start_configuration;

#[allow(unused)]
/// Prometheus metrics which can be displayed in Grafana, queried and alerted on.
pub struct AuthorityMetrics {
    tx_orders: IntCounter,
    total_certs: IntCounter,
    total_cert_attempts: IntCounter,
    total_effects: IntCounter,
    pub shared_obj_tx: IntCounter,
    sponsored_tx: IntCounter,
    tx_already_processed: IntCounter,
    num_input_objs: Histogram,
    num_shared_objects: Histogram,
    batch_size: Histogram,

    authority_state_handle_transaction_latency: Histogram,
    authority_state_handle_transaction_v2_latency: Histogram,

    execute_certificate_latency_single_writer: Histogram,
    execute_certificate_latency_shared_object: Histogram,
    await_transaction_latency: Histogram,

    internal_execution_latency: Histogram,
    execution_load_input_objects_latency: Histogram,
    prepare_certificate_latency: Histogram,
    commit_certificate_latency: Histogram,
    db_checkpoint_latency: Histogram,

    pub(crate) transaction_manager_num_enqueued_certificates: IntCounterVec,
    pub(crate) transaction_manager_num_missing_objects: IntGauge,
    pub(crate) transaction_manager_num_pending_certificates: IntGauge,
    pub(crate) transaction_manager_num_executing_certificates: IntGauge,
    pub(crate) transaction_manager_num_ready: IntGauge,
    pub(crate) transaction_manager_object_cache_size: IntGauge,
    pub(crate) transaction_manager_object_cache_hits: IntCounter,
    pub(crate) transaction_manager_object_cache_misses: IntCounter,
    pub(crate) transaction_manager_object_cache_evictions: IntCounter,
    pub(crate) transaction_manager_package_cache_size: IntGauge,
    pub(crate) transaction_manager_package_cache_hits: IntCounter,
    pub(crate) transaction_manager_package_cache_misses: IntCounter,
    pub(crate) transaction_manager_package_cache_evictions: IntCounter,
    pub(crate) transaction_manager_transaction_queue_age_s: Histogram,

    pub(crate) execution_driver_executed_transactions: IntCounter,
    pub(crate) execution_driver_dispatch_queue: IntGauge,
    pub(crate) execution_queueing_delay_s: Histogram,
    pub(crate) prepare_cert_gas_latency_ratio: Histogram,
    pub(crate) execution_gas_latency_ratio: Histogram,

    pub(crate) skipped_consensus_txns: IntCounter,
    pub(crate) skipped_consensus_txns_cache_hit: IntCounter,

    pub(crate) authority_overload_status: IntGauge,
    pub(crate) authority_load_shedding_percentage: IntGauge,

    pub(crate) transaction_overload_sources: IntCounterVec,

    /// Post processing metrics
    post_processing_total_events_emitted: IntCounter,
    post_processing_total_tx_indexed: IntCounter,
    post_processing_total_tx_had_event_processed: IntCounter,
    post_processing_total_failures: IntCounter,

    /// Consensus commit and transaction handler metrics
    pub consensus_handler_processed: IntCounterVec,
    pub consensus_handler_transaction_sizes: HistogramVec,
    pub consensus_handler_num_low_scoring_authorities: IntGauge,
    pub consensus_handler_scores: IntGaugeVec,
    pub consensus_handler_deferred_transactions: IntCounter,
    pub consensus_handler_congested_transactions: IntCounter,
    pub consensus_handler_cancelled_transactions: IntCounter,
    pub consensus_handler_max_object_costs: IntGaugeVec,
    pub consensus_committed_subdags: IntCounterVec,
    pub consensus_committed_messages: IntGaugeVec,
    pub consensus_committed_user_transactions: IntGaugeVec,
    pub consensus_calculated_throughput: IntGauge,
    pub consensus_calculated_throughput_profile: IntGauge,
    pub consensus_transaction_handler_processed: IntCounterVec,
    pub consensus_transaction_handler_fastpath_executions: IntCounter,

    pub limits_metrics: Arc<LimitsMetrics>,

    /// bytecode verifier metrics for tracking timeouts
    pub bytecode_verifier_metrics: Arc<BytecodeVerifierMetrics>,

    /// Count of zklogin signatures
    pub zklogin_sig_count: IntCounter,
    /// Count of multisig signatures
    pub multisig_sig_count: IntCounter,

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

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 2., 3., 4., 5., 6., 7., 8., 9.,
    10., 20., 30., 60., 90.,
];

// Buckets for low latency samples. Starts from 10us.
const LOW_LATENCY_SEC_BUCKETS: &[f64] = &[
    0.00001, 0.00002, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1,
    0.2, 0.5, 1., 2., 5., 10., 20., 50., 100.,
];

const GAS_LATENCY_RATIO_BUCKETS: &[f64] = &[
    10.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1000.0, 2000.0,
    3000.0, 4000.0, 5000.0, 6000.0, 7000.0, 8000.0, 9000.0, 10000.0, 50000.0, 100000.0, 1000000.0,
];

pub const DEV_INSPECT_GAS_COIN_VALUE: u64 = 1_000_000_000_000;

impl AuthorityMetrics {
    pub fn new(registry: &prometheus::Registry) -> AuthorityMetrics {
        let execute_certificate_latency = register_histogram_vec_with_registry!(
            "authority_state_execute_certificate_latency",
            "Latency of executing certificates, including waiting for inputs",
            &["tx_type"],
            LATENCY_SEC_BUCKETS.to_vec(),
            registry,
        )
        .unwrap();

        let execute_certificate_latency_single_writer =
            execute_certificate_latency.with_label_values(&[TX_TYPE_SINGLE_WRITER_TX]);
        let execute_certificate_latency_shared_object =
            execute_certificate_latency.with_label_values(&[TX_TYPE_SHARED_OBJ_TX]);

        Self {
            tx_orders: register_int_counter_with_registry!(
                "total_transaction_orders",
                "Total number of transaction orders",
                registry,
            )
            .unwrap(),
            total_certs: register_int_counter_with_registry!(
                "total_transaction_certificates",
                "Total number of transaction certificates handled",
                registry,
            )
            .unwrap(),
            total_cert_attempts: register_int_counter_with_registry!(
                "total_handle_certificate_attempts",
                "Number of calls to handle_certificate",
                registry,
            )
            .unwrap(),
            // total_effects == total transactions finished
            total_effects: register_int_counter_with_registry!(
                "total_transaction_effects",
                "Total number of transaction effects produced",
                registry,
            )
            .unwrap(),

            shared_obj_tx: register_int_counter_with_registry!(
                "num_shared_obj_tx",
                "Number of transactions involving shared objects",
                registry,
            )
            .unwrap(),

            sponsored_tx: register_int_counter_with_registry!(
                "num_sponsored_tx",
                "Number of sponsored transactions",
                registry,
            )
            .unwrap(),

            tx_already_processed: register_int_counter_with_registry!(
                "num_tx_already_processed",
                "Number of transaction orders already processed previously",
                registry,
            )
            .unwrap(),
            num_input_objs: register_histogram_with_registry!(
                "num_input_objects",
                "Distribution of number of input TX objects per TX",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            num_shared_objects: register_histogram_with_registry!(
                "num_shared_objects",
                "Number of shared input objects per TX",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            batch_size: register_histogram_with_registry!(
                "batch_size",
                "Distribution of size of transaction batch",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            authority_state_handle_transaction_latency: register_histogram_with_registry!(
                "authority_state_handle_transaction_latency",
                "Latency of handling transactions",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            authority_state_handle_transaction_v2_latency: register_histogram_with_registry!(
                "authority_state_handle_transaction_v2_latency",
                "Latency of handling transactions with v2",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            execute_certificate_latency_single_writer,
            execute_certificate_latency_shared_object,
            await_transaction_latency: register_histogram_with_registry!(
                "await_transaction_latency",
                "Latency of awaiting user transaction execution, including waiting for inputs",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            internal_execution_latency: register_histogram_with_registry!(
                "authority_state_internal_execution_latency",
                "Latency of actual certificate executions",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            execution_load_input_objects_latency: register_histogram_with_registry!(
                "authority_state_execution_load_input_objects_latency",
                "Latency of loading input objects for execution",
                LOW_LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            prepare_certificate_latency: register_histogram_with_registry!(
                "authority_state_prepare_certificate_latency",
                "Latency of executing certificates, before committing the results",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            commit_certificate_latency: register_histogram_with_registry!(
                "authority_state_commit_certificate_latency",
                "Latency of committing certificate execution results",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            db_checkpoint_latency: register_histogram_with_registry!(
                "db_checkpoint_latency",
                "Latency of checkpointing dbs",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            ).unwrap(),
            transaction_manager_num_enqueued_certificates: register_int_counter_vec_with_registry!(
                "transaction_manager_num_enqueued_certificates",
                "Current number of certificates enqueued to TransactionManager",
                &["result"],
                registry,
            )
            .unwrap(),
            transaction_manager_num_missing_objects: register_int_gauge_with_registry!(
                "transaction_manager_num_missing_objects",
                "Current number of missing objects in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_num_pending_certificates: register_int_gauge_with_registry!(
                "transaction_manager_num_pending_certificates",
                "Number of certificates pending in TransactionManager, with at least 1 missing input object",
                registry,
            )
            .unwrap(),
            transaction_manager_num_executing_certificates: register_int_gauge_with_registry!(
                "transaction_manager_num_executing_certificates",
                "Number of executing certificates, including queued and actually running certificates",
                registry,
            )
            .unwrap(),
            transaction_manager_num_ready: register_int_gauge_with_registry!(
                "transaction_manager_num_ready",
                "Number of ready transactions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_size: register_int_gauge_with_registry!(
                "transaction_manager_object_cache_size",
                "Current size of object-availability cache in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_hits: register_int_counter_with_registry!(
                "transaction_manager_object_cache_hits",
                "Number of object-availability cache hits in TransactionManager",
                registry,
            )
            .unwrap(),
            authority_overload_status: register_int_gauge_with_registry!(
                "authority_overload_status",
                "Whether authority is current experiencing overload and enters load shedding mode.",
                registry)
            .unwrap(),
            authority_load_shedding_percentage: register_int_gauge_with_registry!(
                "authority_load_shedding_percentage",
                "The percentage of transactions is shed when the authority is in load shedding mode.",
                registry)
            .unwrap(),
            transaction_manager_object_cache_misses: register_int_counter_with_registry!(
                "transaction_manager_object_cache_misses",
                "Number of object-availability cache misses in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_object_cache_evictions: register_int_counter_with_registry!(
                "transaction_manager_object_cache_evictions",
                "Number of object-availability cache evictions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_size: register_int_gauge_with_registry!(
                "transaction_manager_package_cache_size",
                "Current size of package-availability cache in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_hits: register_int_counter_with_registry!(
                "transaction_manager_package_cache_hits",
                "Number of package-availability cache hits in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_misses: register_int_counter_with_registry!(
                "transaction_manager_package_cache_misses",
                "Number of package-availability cache misses in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_package_cache_evictions: register_int_counter_with_registry!(
                "transaction_manager_package_cache_evictions",
                "Number of package-availability cache evictions in TransactionManager",
                registry,
            )
            .unwrap(),
            transaction_manager_transaction_queue_age_s: register_histogram_with_registry!(
                "transaction_manager_transaction_queue_age_s",
                "Time spent in waiting for transaction in the queue",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            transaction_overload_sources: register_int_counter_vec_with_registry!(
                "transaction_overload_sources",
                "Number of times each source indicates transaction overload.",
                &["source"],
                registry)
            .unwrap(),
            execution_driver_executed_transactions: register_int_counter_with_registry!(
                "execution_driver_executed_transactions",
                "Cumulative number of transaction executed by execution driver",
                registry,
            )
            .unwrap(),
            execution_driver_dispatch_queue: register_int_gauge_with_registry!(
                "execution_driver_dispatch_queue",
                "Number of transaction pending in execution driver dispatch queue",
                registry,
            )
            .unwrap(),
            execution_queueing_delay_s: register_histogram_with_registry!(
                "execution_queueing_delay_s",
                "Queueing delay between a transaction is ready for execution until it starts executing.",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            prepare_cert_gas_latency_ratio: register_histogram_with_registry!(
                "prepare_cert_gas_latency_ratio",
                "The ratio of computation gas divided by VM execution latency.",
                GAS_LATENCY_RATIO_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            execution_gas_latency_ratio: register_histogram_with_registry!(
                "execution_gas_latency_ratio",
                "The ratio of computation gas divided by certificate execution latency, include committing certificate.",
                GAS_LATENCY_RATIO_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            skipped_consensus_txns: register_int_counter_with_registry!(
                "skipped_consensus_txns",
                "Total number of consensus transactions skipped",
                registry,
            )
            .unwrap(),
            skipped_consensus_txns_cache_hit: register_int_counter_with_registry!(
                "skipped_consensus_txns_cache_hit",
                "Total number of consensus transactions skipped because of local cache hit",
                registry,
            )
            .unwrap(),
            post_processing_total_events_emitted: register_int_counter_with_registry!(
                "post_processing_total_events_emitted",
                "Total number of events emitted in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_tx_indexed: register_int_counter_with_registry!(
                "post_processing_total_tx_indexed",
                "Total number of txes indexed in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_tx_had_event_processed: register_int_counter_with_registry!(
                "post_processing_total_tx_had_event_processed",
                "Total number of txes finished event processing in post processing",
                registry,
            )
            .unwrap(),
            post_processing_total_failures: register_int_counter_with_registry!(
                "post_processing_total_failures",
                "Total number of failure in post processing",
                registry,
            )
            .unwrap(),
            consensus_handler_processed: register_int_counter_vec_with_registry!(
                "consensus_handler_processed",
                "Number of transactions processed by consensus handler",
                &["class"],
                registry
            ).unwrap(),
            consensus_handler_transaction_sizes: register_histogram_vec_with_registry!(
                "consensus_handler_transaction_sizes",
                "Sizes of each type of transactions processed by consensus handler",
                &["class"],
                POSITIVE_INT_BUCKETS.to_vec(),
                registry
            ).unwrap(),
            consensus_handler_num_low_scoring_authorities: register_int_gauge_with_registry!(
                "consensus_handler_num_low_scoring_authorities",
                "Number of low scoring authorities based on reputation scores from consensus",
                registry
            ).unwrap(),
            consensus_handler_scores: register_int_gauge_vec_with_registry!(
                "consensus_handler_scores",
                "scores from consensus for each authority",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_handler_deferred_transactions: register_int_counter_with_registry!(
                "consensus_handler_deferred_transactions",
                "Number of transactions deferred by consensus handler",
                registry,
            ).unwrap(),
            consensus_handler_congested_transactions: register_int_counter_with_registry!(
                "consensus_handler_congested_transactions",
                "Number of transactions deferred by consensus handler due to congestion",
                registry,
            ).unwrap(),
            consensus_handler_cancelled_transactions: register_int_counter_with_registry!(
                "consensus_handler_cancelled_transactions",
                "Number of transactions cancelled by consensus handler",
                registry,
            ).unwrap(),
            consensus_handler_max_object_costs: register_int_gauge_vec_with_registry!(
                "consensus_handler_max_congestion_control_object_costs",
                "Max object costs for congestion control in the current consensus commit",
                &["commit_type"],
                registry,
            ).unwrap(),
            consensus_committed_subdags: register_int_counter_vec_with_registry!(
                "consensus_committed_subdags",
                "Number of committed subdags, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_messages: register_int_gauge_vec_with_registry!(
                "consensus_committed_messages",
                "Total number of committed consensus messages, sliced by author",
                &["authority"],
                registry,
            ).unwrap(),
            consensus_committed_user_transactions: register_int_gauge_vec_with_registry!(
                "consensus_committed_user_transactions",
                "Number of committed user transactions, sliced by submitter",
                &["authority"],
                registry,
            ).unwrap(),
            limits_metrics: Arc::new(LimitsMetrics::new(registry)),
            bytecode_verifier_metrics: Arc::new(BytecodeVerifierMetrics::new(registry)),
            zklogin_sig_count: register_int_counter_with_registry!(
                "zklogin_sig_count",
                "Count of zkLogin signatures",
                registry,
            )
            .unwrap(),
            multisig_sig_count: register_int_counter_with_registry!(
                "multisig_sig_count",
                "Count of zkLogin signatures",
                registry,
            )
            .unwrap(),
            consensus_calculated_throughput: register_int_gauge_with_registry!(
                "consensus_calculated_throughput",
                "The calculated throughput from consensus output. Result is calculated based on unique transactions.",
                registry,
            ).unwrap(),
            consensus_calculated_throughput_profile: register_int_gauge_with_registry!(
                "consensus_calculated_throughput_profile",
                "The current active calculated throughput profile",
                registry
            ).unwrap(),
            consensus_transaction_handler_processed: register_int_counter_vec_with_registry!(
                "consensus_transaction_handler_processed",
                "Number of transactions processed by consensus transaction handler, by whether they are certified or rejected.",
                &["outcome"],
                registry
            ).unwrap(),
            consensus_transaction_handler_fastpath_executions: register_int_counter_with_registry!(
                "consensus_transaction_handler_fastpath_executions",
                "Number of fastpath transactions sent for execution by consensus transaction handler",
                registry,
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

    #[allow(dead_code)]
    fn update_overload_metrics(&self, source: &str) {
        self.metrics
            .transaction_overload_sources
            .with_label_values(&[source])
            .inc();
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
            ika_simulator::task::shutdown_current_node();
        }
    }

    #[allow(clippy::disallowed_methods)] // allow unbounded_channel()
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
    ) -> IkaResult<ExecutionLockReadGuard> {
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
    pub async fn execution_lock_for_signing(&self) -> ExecutionLockReadGuard {
        self.execution_lock.read().await
    }

    pub async fn execution_lock_for_reconfiguration(&self) -> ExecutionLockWriteGuard {
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
        //self.transaction_manager.reconfigure(new_epoch);
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

    fn is_protocol_version_supported_v1(
        proposed_protocol_version: ProtocolVersion,
        committee: &Committee,
        capabilities: Vec<AuthorityCapabilitiesV1>,
        mut buffer_stake_bps: u64,
    ) -> (Option<AuthorityCapabilitiesVotingResults>, bool) {
        if buffer_stake_bps > 10000 {
            warn!("clamping buffer_stake_bps to 10000");
            buffer_stake_bps = 10000;
        }

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
            return (None, true);
        }

        // There can only be one set of votes that have a majority, find one if it exists.
        desired_upgrades.sort();
        let res = desired_upgrades
            .into_iter()
            .chunk_by(|(digest, move_contracts_to_upgrade, _authority)| {
                (*digest, move_contracts_to_upgrade.clone())
            })
            .into_iter()
            .find_map(|((digest, move_contracts_to_upgrade), group)| {
                let mut stake_aggregator: StakeAggregator<(), true> =
                    StakeAggregator::new(Arc::new(committee.clone()));

                for (_, _, authority) in group {
                    stake_aggregator.insert_generic(authority, ());
                }

                let total_votes = stake_aggregator.total_votes();
                let quorum_threshold = committee.quorum_threshold();
                let f = committee.total_votes() - committee.quorum_threshold();

                // multiply by buffer_stake_bps / 10000, rounded up.
                let buffer_stake = (f * buffer_stake_bps).div_ceil(10000);
                let effective_threshold = quorum_threshold + buffer_stake;
                let has_support = total_votes >= effective_threshold;

                info!(
                    protocol_config_digest = ?digest,
                    ?total_votes,
                    ?quorum_threshold,
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
        self.epoch_store.store(new_epoch_store.clone());
        Ok(new_epoch_store)
    }
}
