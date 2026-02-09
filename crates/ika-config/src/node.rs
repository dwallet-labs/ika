// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::Config;
use crate::object_storage_config::ObjectStoreConfig;
use crate::p2p::P2pConfig;
use anyhow::{Result, anyhow};
use consensus_config::Parameters as ConsensusParameters;
use ika_types::committee::EpochId;
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sui_types::base_types::{ObjectID, SuiAddress};

use dwallet_rng::RootSeed;
use ika_types::crypto::AuthorityPublicKeyBytes;
use ika_types::crypto::KeypairTraits;
use ika_types::crypto::NetworkKeyPair;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
pub use sui_config::node::KeyPairWithPath;
use sui_types::crypto::SuiKeyPair;

use ika_types::crypto::{
    AccountKeyPair, AuthorityKeyPair, EncodeDecodeBase64, get_key_pair_from_rng,
};
use sui_types::event::EventID;
use sui_types::multiaddr::Multiaddr;

/// The mode in which an Ika node operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Validator mode: participates in consensus and MPC operations.
    /// Requires `consensus_config` to be set in NodeConfig.
    Validator,
    /// Fullnode mode: syncs state via P2P but doesn't participate in consensus.
    /// Requires `consensus_config` to be None and `notifier_client_key_pair` to be None.
    Fullnode,
    /// Notifier mode: submits certified checkpoints to Sui chain.
    /// Requires `notifier_client_key_pair` to be set in SuiConnectorConfig.
    Notifier,
}

impl NodeMode {
    /// Detects the node mode from the configuration.
    /// Returns the appropriate mode based on the config settings.
    pub fn detect_from_config(config: &NodeConfig) -> Self {
        if config.consensus_config().is_some() {
            NodeMode::Validator
        } else if config
            .sui_connector_config
            .notifier_client_key_pair
            .is_some()
        {
            NodeMode::Notifier
        } else {
            NodeMode::Fullnode
        }
    }

    /// Validates that the configuration matches the expected mode.
    /// Returns an error if the configuration is incompatible with the mode.
    pub fn validate_config(&self, config: &NodeConfig) -> Result<()> {
        match self {
            NodeMode::Validator => {
                if config.consensus_config().is_none() {
                    return Err(anyhow!(
                        "Validator mode requires consensus_config to be set in NodeConfig"
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_some()
                {
                    return Err(anyhow!(
                        "Validator mode should not have notifier_client_key_pair set"
                    ));
                }
                Ok(())
            }
            NodeMode::Fullnode => {
                if config.consensus_config().is_some() {
                    return Err(anyhow!(
                        "Fullnode mode requires consensus_config to be None. \
                         Use ika-validator binary for validator nodes."
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_some()
                {
                    return Err(anyhow!(
                        "Fullnode mode should not have notifier_client_key_pair set. \
                         Use ika-notifier binary for notifier nodes."
                    ));
                }
                Ok(())
            }
            NodeMode::Notifier => {
                if config.consensus_config().is_some() {
                    return Err(anyhow!(
                        "Notifier mode requires consensus_config to be None. \
                         Notifiers should not participate in consensus."
                    ));
                }
                if config
                    .sui_connector_config
                    .notifier_client_key_pair
                    .is_none()
                {
                    return Err(anyhow!(
                        "Notifier mode requires notifier_client_key_pair to be set in SuiConnectorConfig"
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns true if this mode participates in consensus.
    pub fn is_validator(&self) -> bool {
        matches!(self, NodeMode::Validator)
    }

    /// Returns true if this mode is a notifier.
    pub fn is_notifier(&self) -> bool {
        matches!(self, NodeMode::Notifier)
    }

    /// Returns true if this mode is a fullnode.
    pub fn is_fullnode(&self) -> bool {
        matches!(self, NodeMode::Fullnode)
    }

    /// Returns the uptime metric label for this mode.
    pub fn uptime_metric_label(&self) -> &'static str {
        match self {
            NodeMode::Validator => "validator",
            NodeMode::Fullnode => "fullnode",
            NodeMode::Notifier => "notifier",
        }
    }
}

impl fmt::Display for NodeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeMode::Validator => write!(f, "validator"),
            NodeMode::Fullnode => write!(f, "fullnode"),
            NodeMode::Notifier => write!(f, "notifier"),
        }
    }
}

pub fn get_testing_sui_fullnode_rpc_url() -> String {
    std::env::var("SUI_FULLNODE_RPC_URL")
        .unwrap_or_else(|_| LOCAL_DEFAULT_SUI_FULLNODE_RPC_URL.to_string())
}

pub fn get_testing_sui_faucet_url() -> String {
    std::env::var("SUI_FAUCET_URL").unwrap_or_else(|_| LOCAL_DEFAULT_SUI_FAUCET_URL.to_string())
}

pub const LOCAL_DEFAULT_SUI_FULLNODE_RPC_URL: &str = "http://127.0.0.1:9000";
pub const LOCAL_DEFAULT_SUI_FAUCET_URL: &str = "http://127.0.0.1:9123/gas";

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum SuiChainIdentifier {
    Mainnet,
    Testnet,
    Custom,
}

impl fmt::Display for SuiChainIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SuiChainIdentifier::Mainnet => write!(f, "Mainnet"),
            SuiChainIdentifier::Testnet => write!(f, "Testnet"),
            SuiChainIdentifier::Custom => write!(f, "Custom"),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SuiConnectorConfig {
    /// Rpc url for Sui fullnode, used for query stuff and submit transactions.
    #[serde(default = "default_sui_rpc_url")]
    pub sui_rpc_url: String,
    /// The expected sui chain identifier connecting to.
    pub sui_chain_identifier: SuiChainIdentifier,
    /// The move package ID of ika (IKA) on sui.
    pub ika_package_id: ObjectID,
    /// The move package id of `ika_common` on sui.
    pub ika_common_package_id: ObjectID,
    /// The move package id of ika_dwallet_2pc_mpc on sui.
    pub ika_dwallet_2pc_mpc_package_id: ObjectID,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ika_dwallet_2pc_mpc_package_id_v2: Option<ObjectID>,
    /// The move package ID of `ika_system` on sui.
    pub ika_system_package_id: ObjectID,
    /// The object ID of the Ika system on sui.
    pub ika_system_object_id: ObjectID,
    /// The object id of ika_dwallet_coordinator on sui.
    pub ika_dwallet_coordinator_object_id: ObjectID,

    /// Only for sui connector notifiers, don't set `notifier_client_key_pair` otherwise.
    /// Path of the file where sui client key (any SuiKeyPair) is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifier_client_key_pair: Option<KeyPairWithPath>,

    /// Override the last processed EventID for sui module `ika_system`.
    /// When set, SuiSyncer will start from this cursor (exclusively) instead of the one in storage.
    /// If the cursor is not found in storage or override, the query will start from genesis.
    /// Key: sui module, Value: last processed EventID (tx_digest, event_seq).
    /// Note 1: This field should be rarely used. Only use it when you understand how to follow up.
    /// Note 2: the EventID needs to be valid, namely it must exist and matches the filter.
    /// Otherwise, it will miss one event because of fullnode Event query semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_ika_system_module_last_processed_event_id_override: Option<EventID>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_seed_key_pair: Option<RootSeedWithPath>,
    #[serde(default = "default_authority_key_pair")]
    pub protocol_key_pair: AuthorityKeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub consensus_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub account_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub network_key_pair: KeyPairWithPath,

    pub db_path: PathBuf,

    #[serde(default = "default_grpc_address")]
    pub network_address: Multiaddr,

    pub sui_connector_config: SuiConnectorConfig,

    #[serde(default = "default_metrics_address")]
    pub metrics_address: SocketAddr,

    #[serde(default = "default_admin_interface_port")]
    pub admin_interface_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_config: Option<ConsensusConfig>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove_deprecated_tables: bool,

    #[serde(default)]
    pub p2p_config: P2pConfig,

    /// Size of the broadcast channel used for notifying other systems of end of epoch.
    ///
    /// If unspecified, this will default to `128`.
    #[serde(default = "default_end_of_epoch_broadcast_channel_capacity")]
    pub end_of_epoch_broadcast_channel_capacity: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,

    /// In a `ika-node` binary, this is set to SupportedProtocolVersions::SYSTEM_DEFAULT
    /// in ika-node/src/main.rs. It is present in the config so that it can be changed by tests in
    /// order to test protocol upgrades.
    #[serde(skip)]
    pub supported_protocol_versions: Option<SupportedProtocolVersions>,

    #[serde(default)]
    pub state_archive_write_config: StateArchiveConfig,

    #[serde(default)]
    pub state_archive_read_config: Vec<StateArchiveConfig>,
    #[serde(default = "default_authority_overload_config")]
    pub authority_overload_config: AuthorityOverloadConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_with_range: Option<RunWithRange>,
}

fn default_sui_rpc_url() -> String {
    LOCAL_DEFAULT_SUI_FULLNODE_RPC_URL.to_string()
}

fn default_grpc_address() -> Multiaddr {
    "/ip4/0.0.0.0/tcp/8080".parse().unwrap()
}
fn default_authority_key_pair() -> AuthorityKeyPairWithPath {
    AuthorityKeyPairWithPath::new(get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut OsRng).1)
}

fn default_key_pair() -> KeyPairWithPath {
    KeyPairWithPath::new(
        get_key_pair_from_rng::<AccountKeyPair, _>(&mut OsRng)
            .1
            .into(),
    )
}

fn default_metrics_address() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9184)
}

pub fn default_admin_interface_port() -> u16 {
    1337
}

pub fn default_end_of_epoch_broadcast_channel_capacity() -> usize {
    128
}

impl Config for NodeConfig {}

impl NodeConfig {
    pub fn protocol_key_pair(&self) -> &AuthorityKeyPair {
        self.protocol_key_pair.authority_keypair()
    }

    pub fn consensus_key_pair(&self) -> &NetworkKeyPair {
        match self.consensus_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => {
                panic!("Invalid keypair type: {other:?}, only Ed25519 is allowed for worker key")
            }
        }
    }

    pub fn network_key_pair(&self) -> &NetworkKeyPair {
        match self.network_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => {
                panic!("Invalid keypair type: {other:?}, only Ed25519 is allowed for network key")
            }
        }
    }

    pub fn protocol_public_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_key_pair().public().into()
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_path.join("live")
    }

    pub fn db_checkpoint_path(&self) -> PathBuf {
        self.db_path.join("db_checkpoints")
    }

    pub fn archive_path(&self) -> PathBuf {
        self.db_path.join("archive")
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.db_path.join("snapshot")
    }

    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }

    pub fn consensus_config(&self) -> Option<&ConsensusConfig> {
        self.consensus_config.as_ref()
    }

    pub fn sui_address(&self) -> SuiAddress {
        (&self.account_key_pair.keypair().public()).into()
    }

    pub fn archive_reader_config(&self) -> Vec<ArchiveReaderConfig> {
        self.state_archive_read_config
            .iter()
            .flat_map(|config| {
                config
                    .object_store_config
                    .as_ref()
                    .map(|remote_store_config| ArchiveReaderConfig {
                        remote_store_config: remote_store_config.clone(),
                        download_concurrency: NonZeroUsize::new(config.concurrency)
                            .unwrap_or(NonZeroUsize::new(5).unwrap()),
                        use_for_pruning_watermark: config.use_for_pruning_watermark,
                    })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConsensusConfig {
    /// Base consensus DB path for all epochs.
    pub db_path: PathBuf,

    /// The number of epochs for which to retain the consensus DBs. Setting it to 0 will make a consensus DB getting
    /// dropped as soon as system is switched to a new epoch.
    pub db_retention_epochs: Option<u64>,

    /// Pruner will run on every epoch change, but it will also check periodically on every `db_pruner_period_secs`
    /// seconds to see if there are any epoch DBs to remove.
    pub db_pruner_period_secs: Option<u64>,

    /// Maximum number of pending transactions to submit to consensus, including those
    /// in submission wait.
    /// Default to 20_000 inflight limit, assuming 20_000 txn tps * 1 sec consensus latency.
    pub max_pending_transactions: Option<usize>,

    /// When defined caps the calculated submission position to the max_submit_position. Even if the
    /// is elected to submit from a higher position than this, it will "reset" to the max_submit_position.
    pub max_submit_position: Option<usize>,

    /// The submit delay step to consensus defined in milliseconds. When provided it will
    /// override the current back off logic otherwise the default backoff logic will be applied based
    /// on consensus latency estimates.
    pub submit_delay_step_override_millis: Option<u64>,

    pub parameters: Option<ConsensusParameters>,
}

impl ConsensusConfig {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn max_pending_transactions(&self) -> usize {
        self.max_pending_transactions.unwrap_or(20_000)
    }

    pub fn submit_delay_step_override(&self) -> Option<Duration> {
        self.submit_delay_step_override_millis
            .map(Duration::from_millis)
    }

    pub fn db_retention_epochs(&self) -> u64 {
        self.db_retention_epochs.unwrap_or(0)
    }

    pub fn db_pruner_period(&self) -> Duration {
        // Default to 1 hour
        self.db_pruner_period_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3_600))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArchiveReaderConfig {
    pub remote_store_config: ObjectStoreConfig,
    pub download_concurrency: NonZeroUsize,
    pub use_for_pruning_watermark: bool,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StateArchiveConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_store_config: Option<ObjectStoreConfig>,
    pub concurrency: usize,
    pub use_for_pruning_watermark: bool,
}

/// Configuration for the threshold(s) at which we consider the system
/// to be overloaded. When one of the threshold is passed, the node may
/// stop processing new transactions and/or certificates until the congestion
/// resolves.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthorityOverloadConfig {
    #[serde(default = "default_max_txn_age_in_queue")]
    pub max_txn_age_in_queue: Duration,

    // The interval of checking overload signal.
    #[serde(default = "default_overload_monitor_interval")]
    pub overload_monitor_interval: Duration,

    // The execution queueing latency when entering load shedding mode.
    #[serde(default = "default_execution_queue_latency_soft_limit")]
    pub execution_queue_latency_soft_limit: Duration,

    // The execution queueing latency when entering aggressive load shedding mode.
    #[serde(default = "default_execution_queue_latency_hard_limit")]
    pub execution_queue_latency_hard_limit: Duration,

    // The maximum percentage of transactions to shed in load shedding mode.
    #[serde(default = "default_max_load_shedding_percentage")]
    pub max_load_shedding_percentage: u32,

    // When in aggressive load shedding mode, the minimum percentage of
    // transactions to shed.
    #[serde(default = "default_min_load_shedding_percentage_above_hard_limit")]
    pub min_load_shedding_percentage_above_hard_limit: u32,

    // If transaction ready rate is below this rate, we consider the validator
    // is well under used, and will not enter load shedding mode.
    #[serde(default = "default_safe_transaction_ready_rate")]
    pub safe_transaction_ready_rate: u32,

    // When set to true, transaction signing may be rejected when the validator
    // is overloaded.
    #[serde(default = "default_check_system_overload_at_signing")]
    pub check_system_overload_at_signing: bool,

    // When set to true, transaction execution may be rejected when the validator
    // is overloaded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub check_system_overload_at_execution: bool,

    // Reject a transaction if transaction manager queue length is above this threshold.
    // 100_000 = 10k TPS * 5s resident time in transaction manager (pending + executing) * 2.
    #[serde(default = "default_max_transaction_manager_queue_length")]
    pub max_transaction_manager_queue_length: usize,

    // Reject a transaction if the number of pending transactions depending on the object
    // is above the threshold.
    #[serde(default = "default_max_transaction_manager_per_object_queue_length")]
    pub max_transaction_manager_per_object_queue_length: usize,
}

fn default_max_txn_age_in_queue() -> Duration {
    Duration::from_millis(500)
}

fn default_overload_monitor_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_execution_queue_latency_soft_limit() -> Duration {
    Duration::from_secs(1)
}

fn default_execution_queue_latency_hard_limit() -> Duration {
    Duration::from_secs(10)
}

fn default_max_load_shedding_percentage() -> u32 {
    95
}

fn default_min_load_shedding_percentage_above_hard_limit() -> u32 {
    50
}

fn default_safe_transaction_ready_rate() -> u32 {
    100
}

fn default_check_system_overload_at_signing() -> bool {
    true
}

fn default_max_transaction_manager_queue_length() -> usize {
    100_000
}

fn default_max_transaction_manager_per_object_queue_length() -> usize {
    20
}

impl Default for AuthorityOverloadConfig {
    fn default() -> Self {
        Self {
            max_txn_age_in_queue: default_max_txn_age_in_queue(),
            overload_monitor_interval: default_overload_monitor_interval(),
            execution_queue_latency_soft_limit: default_execution_queue_latency_soft_limit(),
            execution_queue_latency_hard_limit: default_execution_queue_latency_hard_limit(),
            max_load_shedding_percentage: default_max_load_shedding_percentage(),
            min_load_shedding_percentage_above_hard_limit:
                default_min_load_shedding_percentage_above_hard_limit(),
            safe_transaction_ready_rate: default_safe_transaction_ready_rate(),
            check_system_overload_at_signing: true,
            check_system_overload_at_execution: false,
            max_transaction_manager_queue_length: default_max_transaction_manager_queue_length(),
            max_transaction_manager_per_object_queue_length:
                default_max_transaction_manager_per_object_queue_length(),
        }
    }
}

fn default_authority_overload_config() -> AuthorityOverloadConfig {
    AuthorityOverloadConfig::default()
}

// RunWithRange is used to specify the ending epoch/checkpoint to process.
// this is intended for use with disaster recovery debugging and verification workflows, never in normal operations
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum RunWithRange {
    Epoch(EpochId),
    Checkpoint(DWalletCheckpointSequenceNumber),
}

impl RunWithRange {
    // is epoch_id > RunWithRange::Epoch
    pub fn is_epoch_gt(&self, epoch_id: EpochId) -> bool {
        matches!(self, RunWithRange::Epoch(e) if epoch_id > *e)
    }

    pub fn matches_checkpoint(&self, seq_num: DWalletCheckpointSequenceNumber) -> bool {
        matches!(self, RunWithRange::Checkpoint(seq) if *seq == seq_num)
    }
}

/// Wrapper struct for AuthorityKeyPair that can be deserialized from a file path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuthorityKeyPairWithPath {
    #[serde(flatten)]
    location: AuthorityKeyPairLocation,

    #[serde(skip)]
    keypair: OnceCell<Arc<AuthorityKeyPair>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde_as]
#[serde(untagged)]
enum AuthorityKeyPairLocation {
    InPlace { value: Arc<AuthorityKeyPair> },
    File { path: PathBuf },
}

impl AuthorityKeyPairWithPath {
    pub fn new(kp: AuthorityKeyPair) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        let arc_kp = Arc::new(kp);
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(arc_kp.clone())
            .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::InPlace { value: arc_kp },
            keypair: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(Arc::new(read_authority_keypair_from_file(&path)))
            .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::File { path },
            keypair: cell,
        }
    }

    pub fn authority_keypair(&self) -> &AuthorityKeyPair {
        self.keypair
            .get_or_init(|| match &self.location {
                AuthorityKeyPairLocation::InPlace { value } => value.clone(),
                AuthorityKeyPairLocation::File { path } => {
                    // OK to unwrap panic because authority should not start without all keypairs loaded.
                    Arc::new(read_authority_keypair_from_file(path))
                }
            })
            .as_ref()
    }
}

/// Read from file as Base64 encoded `privkey` and return a AuthorityKeyPair.
pub fn read_authority_keypair_from_file(path: &PathBuf) -> AuthorityKeyPair {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Invalid authority keypair file at path {:?}", &path));
    AuthorityKeyPair::decode_base64(contents.as_str().trim())
        .unwrap_or_else(|_| panic!("Invalid authority keypair file at path {:?}", &path))
}

/// Wrapper struct for RootSeed that can be deserialized from a file path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RootSeedWithPath {
    #[serde(flatten)]
    location: RootSeedLocation,

    #[serde(skip)]
    seed: OnceCell<RootSeed>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde(untagged)]
enum RootSeedLocation {
    InPlace { value: RootSeed },
    File { path: PathBuf },
}

impl RootSeedWithPath {
    pub fn new(seed: RootSeed) -> Self {
        let cell: OnceCell<RootSeed> = OnceCell::new();
        // OK to unwrap panic because validator should not start without root seed loaded.
        cell.set(seed.clone()).expect("Failed to set root seed");
        Self {
            location: RootSeedLocation::InPlace { value: seed },
            seed: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<RootSeed> = OnceCell::new();
        // OK to unwrap panic because class_groups should not start without all keypairs loaded.
        cell.set(RootSeed::from_file(path.clone()).unwrap())
            .expect("Failed to set root seed");
        Self {
            location: RootSeedLocation::File { path },
            seed: cell,
        }
    }

    pub fn root_seed(&self) -> &RootSeed {
        self.seed.get_or_init(|| match &self.location {
            RootSeedLocation::InPlace { value } => value.clone(),
            RootSeedLocation::File { path } => {
                // OK to unwrap panic because validator
                // should not start without seed loaded.
                RootSeed::from_file(path.clone()).unwrap()
            }
        })
    }
}
