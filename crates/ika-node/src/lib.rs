// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use anemo::Network;
use anemo::PeerId;
use anemo_tower::callback::CallbackLayer;
use anemo_tower::trace::DefaultMakeSpan;
use anemo_tower::trace::DefaultOnFailure;
use anemo_tower::trace::TraceLayer;
use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use prometheus::Registry;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(msim)]
use std::sync::atomic::Ordering;
use std::time::Duration;

// Re-export NodeMode from ika-config
pub use ika_config::NodeMode;

use ika_core::consensus_adapter::ConsensusClient;
use ika_core::consensus_manager::UpdatableConsensusClient;

use ika_types::digests::ChainIdentifier;
use ika_types::sui::{DWalletCoordinatorInner, SystemInner};
use sui_types::base_types::{ConciseableName, ObjectID};
use tap::tap::TapFallible;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, broadcast, watch};
use tokio::task::JoinSet;
use tower::ServiceBuilder;
use tracing::{debug, warn};
use tracing::{error, info};

pub use handle::IkaNodeHandle;
use ika_archival::reader::ArchiveReaderBalancer;
use ika_archival::writer::ArchiveWriter;
use ika_config::node::RunWithRange;
use ika_config::node_config_metrics::NodeConfigMetrics;
use ika_config::object_storage_config::{ObjectStoreConfig, ObjectStoreType};
use ika_config::{ConsensusConfig, NodeConfig};
use ika_core::authority::AuthorityState;
use ika_core::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, AuthorityPerEpochStoreTrait, EPOCH_DB_PREFIX,
};
use ika_core::authority::epoch_start_configuration::EpochStartConfiguration;
use ika_core::consensus_adapter::{
    CheckConnection, ConnectionMonitorStatus, ConsensusAdapter, ConsensusAdapterMetrics,
};
use ika_core::consensus_manager::ConsensusManager;
use ika_core::consensus_throughput_calculator::{
    ConsensusThroughputCalculator, ConsensusThroughputProfiler, ThroughputProfileRanges,
};
use ika_core::consensus_validator::{IkaTxValidator, IkaTxValidatorMetrics};
use ika_core::dwallet_checkpoints::{
    DWalletCheckpointMetrics, DWalletCheckpointService, DWalletCheckpointStore,
    SendDWalletCheckpointToStateSync, SubmitDWalletCheckpointToConsensus,
};
use ika_core::epoch::committee_store::CommitteeStore;
use ika_core::epoch::consensus_store_pruner::ConsensusStorePruner;
use ika_core::epoch::epoch_metrics::EpochMetrics;
use ika_core::storage::RocksDbStore;
use ika_network::discovery::TrustedPeerChangeEvent;
use ika_network::{discovery, state_sync};
use ika_protocol_config::{ProtocolConfig, ProtocolVersion};
use mysten_metrics::{RegistryService, spawn_monitored_task};
use sui_macros::{fail_point_async, replay_log};
use sui_storage::{FileCompression, StorageFormat};
use sui_types::base_types::EpochId;

use ika_types::committee::{Committee, CommitteeMembership};
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use ika_types::messages_consensus::{AuthorityCapabilitiesV1, ConsensusTransaction};
use ika_types::sui::SystemInnerTrait;
use ika_types::sui::epoch_start_system::EpochStartSystem;
use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
use sui_types::crypto::KeypairTraits;

use ika_core::consensus_adapter::SubmitToConsensus;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use std::str::FromStr;
use typed_store::DBMetrics;
use typed_store::rocks::default_db_options;

use crate::metrics::IkaNodeMetrics;

pub mod admin;
mod handle;
pub mod metrics;
mod node_runner;

pub use node_runner::{NodeArgs, run_node, run_node_with_name};

pub struct ValidatorComponents {
    consensus_manager: Arc<ConsensusManager>,
    consensus_store_pruner: ConsensusStorePruner,
    consensus_adapter: Arc<ConsensusAdapter>,
    // Keeping the handle to the checkpoint service tasks to shut them down during reconfiguration.
    checkpoint_service_tasks: JoinSet<()>,
    system_checkpoint_service_tasks: JoinSet<()>,
    checkpoint_metrics: Arc<DWalletCheckpointMetrics>,
    system_checkpoint_metrics: Arc<SystemCheckpointMetrics>,
    ika_tx_validator_metrics: Arc<IkaTxValidatorMetrics>,

    dwallet_mpc_service_exit: watch::Sender<()>,
    dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
}

pub struct P2pComponents {
    p2p_network: Network,
    known_peers: HashMap<PeerId, String>,
    discovery_handle: discovery::Handle,
    state_sync_handle: state_sync::Handle,
    mpc_announcement_relay: Arc<ika_network::mpc_artifacts::AnnouncementRelayHandle>,
    /// In-memory cache backing the local Anemo `GetMpcDataBlob`
    /// server. Producer caches own blob into it on epoch start;
    /// `PeerBlobFetcher` mirrors fetched peer blobs into it so we
    /// can serve them to other peers too.
    mpc_data_blob_store: Arc<ika_network::mpc_artifacts::InMemoryBlobStore>,
}

#[cfg(msim)]
mod simulator {
    use std::sync::atomic::AtomicBool;

    use super::*;
    pub(super) struct SimState {
        pub sim_node: sui_simulator::runtime::NodeHandle,
        pub sim_safe_mode_expected: AtomicBool,
        _leak_detector: sui_simulator::NodeLeakDetector,
    }

    impl Default for SimState {
        fn default() -> Self {
            Self {
                sim_node: sui_simulator::runtime::NodeHandle::current(),
                sim_safe_mode_expected: AtomicBool::new(false),
                _leak_detector: sui_simulator::NodeLeakDetector::new(),
            }
        }
    }
}

use ika_core::SuiDataReceivers;
use ika_core::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use ika_core::consensus_handler::ConsensusHandlerInitializer;
use ika_core::dwallet_checkpoints::dwallet_checkpoint_output::{
    CertifiedDWalletCheckpointMessageOutput,
    DWalletCheckpointOutput as DWalletCheckpointOutputTrait,
};
use ika_core::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use ika_core::dwallet_mpc::dwallet_mpc_service::{
    DWalletMPCService, NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
};
use ika_core::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};
use ika_core::epoch::submit_to_consensus::EpochStoreSubmitToConsensus;
use ika_core::epoch_tasks::end_of_publish_sender::EndOfPublishSender;
use ika_core::noa_checkpoints::{LogOnlyChainSubmitter, NOAChainSubmitter, NOACheckpointHandler};
use ika_core::sui_connector::SuiConnectorService;
use ika_core::sui_connector::metrics::SuiConnectorMetrics;
use ika_core::sui_connector::setup as sui_connector_setup;
use ika_core::sui_connector::sui_executor::StopReason;
use ika_core::sui_connector::verified_transport::VerifiedSuiTransport;
use ika_core::system_checkpoints::system_checkpoint_output::{
    CertifiedSystemCheckpointOutput, SystemCheckpointOutput as SystemCheckpointOutputTrait,
};
use ika_core::system_checkpoints::{
    SendSystemCheckpointToStateSync, SubmitSystemCheckpointToConsensus, SystemCheckpointMetrics,
    SystemCheckpointService, SystemCheckpointStore,
};
use ika_network::mpc_artifacts::{fetch_blob, mpc_data_blob_hash};
use ika_sui_client::metrics::SuiClientMetrics;
use ika_sui_client::{SuiClient, SuiConnectorClient};
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, IkaObjectsConfig, IkaPackageConfig};
#[cfg(msim)]
use simulator::*;

pub struct IkaNode {
    config: NodeConfig,
    validator_components: Mutex<Option<ValidatorComponents>>,

    state: Arc<AuthorityState>,
    registry_service: RegistryService,
    metrics: Arc<IkaNodeMetrics>,

    _discovery: discovery::Handle,
    _connection_monitor_handle: mysten_network::anemo_connection_monitor::ConnectionMonitorHandle,
    state_sync_handle: state_sync::Handle,
    dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
    connection_monitor_status: Arc<ConnectionMonitorStatus>,

    /// Broadcast channel to send the starting system state for the next epoch.
    end_of_epoch_channel: broadcast::Sender<SystemInner>,

    /// Broadcast channel to notify state-sync for new validator peers.
    trusted_peer_change_tx: watch::Sender<TrustedPeerChangeEvent>,

    #[cfg(msim)]
    sim_state: SimState,

    sui_connector_service: Arc<SuiConnectorService>,

    /// Late-bindable holder for the joiner-relay impl mounted on
    /// the Anemo `SubmitMpcDataAnnouncement` server. Replaced per
    /// epoch so the relay always points at the current epoch
    /// store + consensus adapter.
    mpc_announcement_relay: Arc<ika_network::mpc_artifacts::AnnouncementRelayHandle>,

    /// In-memory cache shared with the Anemo `GetMpcDataBlob`
    /// server. Producer and `PeerBlobFetcher` push blobs into it so
    /// the server can respond to peer fetches without a restart.
    mpc_data_blob_store: Arc<ika_network::mpc_artifacts::InMemoryBlobStore>,

    /// Anemo network handle, retained so per-epoch
    /// `PeerBlobFetcher` instances can issue `fetch_blob` against
    /// committee peers without re-deriving the network.
    p2p_network: Network,

    _state_archive_handle: Option<broadcast::Sender<()>>,

    shutdown_channel_tx: broadcast::Sender<Option<RunWithRange>>,
    system_checkpoint_store: Arc<SystemCheckpointStore>,
    /// Per-kind flags for NOA checkpoint finalization epoch gate.
    noa_dwallet_finalized: Arc<std::sync::atomic::AtomicBool>,
    noa_system_finalized: Arc<std::sync::atomic::AtomicBool>,

    /// Prunes per-epoch authority store directories
    /// (`<db-path>/live/store/epoch_<N>/`); the `perpetual/` sibling never
    /// matches its prefix filter and is never touched. Constructed once at
    /// node start (seeded with the boot epoch so the periodic tick works
    /// across restarts) and notified at every epoch transition after the
    /// outgoing epoch store's DB handles are released.
    authority_store_pruner: ConsensusStorePruner,
}

impl fmt::Debug for IkaNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IkaNode")
            .field("name", &self.state.name.concise())
            .finish()
    }
}

const EVENTS_CHANNEL_BUFFER_SIZE: usize = 10_000;

impl IkaNode {
    pub async fn start(
        config: NodeConfig,
        registry_service: RegistryService,
        _custom_rpc_runtime: Option<Handle>,
    ) -> Result<Arc<IkaNode>> {
        Self::start_async(config, registry_service, "unknown").await
    }

    /// Start the node with automatic mode detection from config.
    pub async fn start_async(
        config: NodeConfig,
        registry_service: RegistryService,
        software_version: &'static str,
    ) -> Result<Arc<IkaNode>> {
        let mode = NodeMode::detect_from_config(&config);
        Self::start_with_mode(config, registry_service, software_version, mode).await
    }

    /// Start the node in a specific mode with validation.
    /// This method validates that the configuration matches the expected mode.
    pub async fn start_with_mode(
        config: NodeConfig,
        registry_service: RegistryService,
        _software_version: &'static str,
        mode: NodeMode,
    ) -> Result<Arc<IkaNode>> {
        // Validate the configuration matches the expected mode
        mode.validate_config(&config)?;

        info!("Starting Ika node in {} mode", mode);
        NodeConfigMetrics::new(&registry_service.default_registry()).record_metrics(&config);
        let mut config = config.clone();
        if config.supported_protocol_versions.is_none() {
            info!(
                "populating config.supported_protocol_versions with default {:?}",
                SupportedProtocolVersions::SYSTEM_DEFAULT
            );
            config.supported_protocol_versions = Some(SupportedProtocolVersions::SYSTEM_DEFAULT);
        }

        let prometheus_registry = registry_service.default_registry();

        info!(node =? config.protocol_public_key(),
            "Initializing ika-node listening on {}", config.network_address
        );

        // Initialize metrics to track db usage before creating any stores
        DBMetrics::init(registry_service.clone());

        // Initialize Mysten metrics.
        mysten_metrics::init_metrics(&prometheus_registry);
        // Unsupported (because of the use of static variable) and unnecessary in simtests.
        #[cfg(not(msim))]
        mysten_metrics::thread_stall_monitor::start_thread_stall_monitor();

        let sui_client_metrics = SuiClientMetrics::new(&registry_service.default_registry());

        let mut ika_dwallet_2pc_mpc_package_id_v2 = config
            .sui_connector_config
            .ika_dwallet_2pc_mpc_package_id_v2;

        // Testnet V2
        if ika_dwallet_2pc_mpc_package_id_v2.is_none()
            && config.sui_connector_config.ika_dwallet_2pc_mpc_package_id
                == ObjectID::from_str(
                    "0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730",
                )?
        {
            ika_dwallet_2pc_mpc_package_id_v2 = Some(ObjectID::from_str(
                "0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293",
            )?)
        }

        // Mainnet V2
        if ika_dwallet_2pc_mpc_package_id_v2.is_none()
            && config.sui_connector_config.ika_dwallet_2pc_mpc_package_id
                == ObjectID::from_str(
                    "0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317",
                )?
        {
            ika_dwallet_2pc_mpc_package_id_v2 = Some(ObjectID::from_str(
                "0x23b5bd96051923f800c3a2150aacdcdd8d39e1df2dce4dac69a00d2d8c7f7e77",
            )?)
        }

        let ika_network_config = IkaNetworkConfig {
            packages: IkaPackageConfig {
                ika_package_id: config.sui_connector_config.ika_package_id,
                ika_common_package_id: config.sui_connector_config.ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id: config
                    .sui_connector_config
                    .ika_dwallet_2pc_mpc_package_id,
                ika_dwallet_2pc_mpc_package_id_v2,
                ika_system_package_id: config.sui_connector_config.ika_system_package_id,
            },
            objects: IkaObjectsConfig {
                ika_system_object_id: config.sui_connector_config.ika_system_object_id,
                ika_dwallet_coordinator_object_id: config
                    .sui_connector_config
                    .ika_dwallet_coordinator_object_id,
            },
        };

        // Perpetual tables are opened here (rather than after the sui_client)
        // because the OCS-mode decision below needs to know whether we've
        // already verified past a committee head.
        let perpetual_tables_options =
            default_db_options().optimize_db_for_write_throughput(4, false);
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(
            &config.db_path().join("store"),
            Some(perpetual_tables_options.options),
        ));

        // OCS mode (`has_anchor`) drives ALL Sui I/O through gRPC instead of
        // JSON-RPC. The decision mirrors `ocs_enabled` further down and must
        // be made before constructing `sui_client` so the right backend is
        // built. See the OCS startup comment below for the data-source modes.
        use ika_config::node::{SuiDataSource, compiled_in_trusted_anchor};
        let perpetual_has_committees = perpetual_tables
            .highest_sui_committee_epoch()
            .map_err(|e| anyhow!("read sui_committee_head: {e}"))?
            .is_some();
        let has_anchor = perpetual_has_committees
            || config.sui_connector_config.sui_trusted_anchor.is_some()
            || config
                .sui_connector_config
                .sui_unsafe_genesis_committee
                .is_some()
            || compiled_in_trusted_anchor(config.sui_connector_config.sui_chain_identifier)
                .is_some();

        // --- Read-independent boot infrastructure, hoisted above the Sui
        // bootstrap reads below. A peer-only validator (sui-state-mirrored with
        // no fallback_grpc_url) has no direct uplink, so it must stand up its
        // p2p network + OCS relay reader — and from them a verified
        // `sui_client` — *before* it can read any Sui state (which it can only
        // do over that relay). None of these bindings depend on the bootstrap
        // reads; they key off config, perpetual storage, and the metrics
        // registry, so hoisting them is behavior-preserving for every node. ---
        let committee_store = Arc::new(CommitteeStore::new(config.db_path().join("epochs"), None));
        let chain_identifier =
            ChainIdentifier::from(config.sui_connector_config.ika_system_object_id);
        let dwallet_checkpoint_store =
            DWalletCheckpointStore::new(&config.db_path().join("dwallet_checkpoints"));
        let system_checkpoint_store =
            SystemCheckpointStore::new(&config.db_path().join("system_checkpoints"));
        let state_sync_store = RocksDbStore::new(
            committee_store.clone(),
            dwallet_checkpoint_store.clone(),
            system_checkpoint_store.clone(),
        );
        let authority_name = config.protocol_public_key();
        let archive_readers =
            ArchiveReaderBalancer::new(config.archive_reader_config(), &prometheus_registry)?;
        let (trusted_peer_change_tx, trusted_peer_change_rx) = watch::channel(Default::default());

        // Shared metrics for the OCS subsystem. Created here so all consumers
        // (verifier, pusher, push handler) report into the same registry.
        let ocs_metrics =
            ika_core::sui_connector::ocs_metrics::OcsMetrics::new(&prometheus_registry);
        let proof_provider_metrics =
            ika_network::proof_provider::ProofProviderMetrics::new(&prometheus_registry);

        // OCS verified reads are a *node-level* choice (a configured trust
        // anchor), not a protocol feature; without one a node uses the legacy
        // JSON-RPC event path. `has_anchor` is computed above.
        let ocs_enabled = has_anchor;
        let proof_cache_cfg = ika_network::proof_provider::ProofCacheConfig::default();
        let is_sui_state_direct = ocs_enabled
            && matches!(
                config.sui_connector_config.sui_data_source,
                Some(SuiDataSource::SuiStateDirect { .. })
            );
        let is_sui_state_mirrored = ocs_enabled
            && matches!(
                config.sui_connector_config.sui_data_source,
                Some(SuiDataSource::SuiStateMirrored { .. })
            );
        if !ocs_enabled {
            info!(
                has_anchor,
                "OCS verifier not active (no trust anchor configured); \
                 using the legacy JSON-RPC event-ingestion path."
            );
        }

        // `sui_client` transport selection, keyed off the SHAPE of the node's
        // own config — old-style vs new-style — never off chain state (a
        // protocol flag must not be able to halt running validators en masse
        // at an upgrade boundary; transport choice is node-local, and both
        // read paths consume the same on-chain state):
        //
        //   * Old-style config (no `sui-data-source` section): the node
        //     predates the OCS rollout and its only configured endpoint is
        //     `sui_rpc_url`. A VALIDATOR on such a config keeps the legacy
        //     JSON-RPC read path — its MPC events come from `query_events`,
        //     which gRPC cannot serve. DEPRECATED: Sui is sunsetting JSON-RPC;
        //     migrate by adding `sui-data-source` plus a trust anchor.
        //     Notifiers and fullnodes run no event ingestion, so even on an
        //     old-style config they read gRPC at the same endpoint (Sui
        //     fullnodes serve both APIs on one port).
        //
        //   * New-style config (`sui-data-source` present): all Sui I/O runs
        //     over gRPC — direct, mirrored-with-fallback, or peer-only over
        //     the verified relay (built after the OCS reader + p2p network
        //     exist; peer-only nodes never submit transactions, so they need
        //     no direct uplink). Notifiers — the only nodes that submit
        //     transactions (gas + writes) — always use a direct gRPC uplink.
        //
        // Mixed shapes fail closed here rather than guessing:
        if has_anchor && config.sui_connector_config.sui_data_source.is_none() {
            return Err(anyhow!(
                "a Sui trust anchor is configured but `sui-data-source` is not; the \
                 anchor-verified OCS path runs over gRPC — add a sui-data-source section"
            ));
        }
        if config.sui_connector_config.sui_data_source.is_some()
            && mode.is_validator()
            && !has_anchor
        {
            return Err(anyhow!(
                "`sui-data-source` is set but no Sui trust anchor is configured: a validator on \
                 the gRPC path has no MPC event source without one (no JSON-RPC `query_events`, \
                 and the verified BagEventPump requires the anchor); set sui_trusted_anchor (or \
                 sui_unsafe_genesis_committee on private nets)"
            ));
        }
        let legacy_json_rpc =
            config.sui_connector_config.sui_data_source.is_none() && mode.is_validator();
        let peer_only = matches!(
            config.sui_connector_config.sui_data_source,
            Some(SuiDataSource::SuiStateMirrored {
                fallback_grpc_url: None
            })
        );
        // A peer-only validator stands up its p2p network + OCS stack inside the
        // transport gate below (it needs them to read any Sui state), then
        // reuses them — the normal post-read network/stack builds are skipped.
        let mut peer_only_p2p: Option<P2pComponents> = None;
        let mut peer_only_stack: Option<sui_connector_setup::SuiConnectorStack> = None;
        let sui_client = if legacy_json_rpc {
            warn!(
                "DEPRECATED: old-style config (no sui-data-source) — this validator reads Sui \
                 over JSON-RPC, which Sui is sunsetting; migrate by adding sui-data-source plus \
                 a trust anchor"
            );
            Arc::new(
                SuiClient::new(
                    &config.sui_connector_config.sui_rpc_url,
                    sui_client_metrics,
                    ika_network_config,
                )
                .await?,
            )
        } else if peer_only {
            // Peer-only (sui-state-mirrored, no fallback_grpc_url): no direct
            // Sui uplink. Stand up the p2p network + OCS relay stack now, then
            // serve every `sui_client` read — including the committee/epoch
            // bootstrap just below — over the relay through a verified
            // `sui_client`. Network + stack are stashed and reused below.
            //
            // `is_notifier` here gates state_sync's *pull* behavior: when true
            // the node actively pulls checkpoint summaries from peers (what
            // non-committee nodes need — committee members get them via
            // consensus). The normal path derives it from committee
            // membership (`!authority_exists`), but the committee isn't
            // readable yet at this point — reading it is exactly what this
            // network is being built for. `mode.is_notifier()` (false for a
            // validator) assumes the peer-only validator IS in the committee,
            // which holds for every supported peer-only deployment today; a
            // peer-only *joiner* (not yet in the committee) would need
            // pull-mode state sync and is not supported on this path yet.
            // No mirror server: peer-only nodes consume the relay, they
            // don't serve it.
            let p2p = Self::create_p2p_network(
                &config,
                state_sync_store.clone(),
                chain_identifier,
                trusted_peer_change_rx.clone(),
                archive_readers.clone(),
                &prometheus_registry,
                mode.is_notifier(),
                perpetual_tables.clone(),
                None,
            )?;
            // Anemo dials seed peers asynchronously; `build_sui_connector_stack`
            // probes the relay at construction, so wait for a configured mirror
            // peer to be reachable first (as the sui-state-mirrored path does).
            let mirror_peer_ids =
                sui_connector_setup::configured_mirror_peer_ids(&config.sui_connector_config);
            Self::wait_for_specific_peers(
                &p2p.p2p_network,
                &mirror_peer_ids,
                std::time::Duration::from_secs(60),
            )
            .await;
            info!(
                peer_count = p2p.p2p_network.peers().len(),
                "Building OCS verifier stack (peer-only, p2p relay; no direct uplink)"
            );
            let stack = sui_connector_setup::build_sui_connector_stack(
                &config.sui_connector_config,
                perpetual_tables.clone(),
                Some(p2p.p2p_network.clone()),
                proof_cache_cfg.clone(),
                ocs_metrics.clone(),
                proof_provider_metrics.clone(),
            )
            .await
            .map_err(|e| anyhow!("build OCS connector stack (peer-only): {e}"))?;
            // A peer-only node cannot read any Sui state until its committee
            // head is current: the bootstrap reads below verify every object
            // against the committee store, and the periodic ratchet task is
            // only spawned after those reads complete — so a stale head here
            // has nothing to heal it and the reads retry forever. (The
            // mirrored-with-fallback path tolerates a failed initial ratchet
            // because its bootstrap reads go over direct gRPC instead.)
            // Retry with backoff until the ratchet succeeds; the relay peer
            // was reachable moments ago in wait_for_specific_peers.
            let mut ratchet_backoff = std::time::Duration::from_secs(1);
            loop {
                match stack.ratchet.ratchet_to_current_epoch().await {
                    Ok(()) => break,
                    Err(e) => {
                        warn!(
                            error = ?e,
                            retry_in = ?ratchet_backoff,
                            "initial ratchet to current epoch (peer-only) failed; retrying"
                        );
                        tokio::time::sleep(ratchet_backoff).await;
                        ratchet_backoff =
                            (ratchet_backoff * 2).min(std::time::Duration::from_secs(10));
                    }
                }
            }
            let relay = stack.ratchet.transport().clone();
            let verified: Arc<dyn ika_sui_client::transport::SuiTransport> =
                Arc::new(VerifiedSuiTransport::new(stack.reader.clone(), relay));
            let client = Arc::new(
                SuiClient::new_grpc_with_transport(
                    verified,
                    sui_client_metrics,
                    ika_network_config,
                )
                .await?,
            );
            peer_only_p2p = Some(p2p);
            peer_only_stack = Some(stack);
            client
        } else {
            let grpc_url = match &config.sui_connector_config.sui_data_source {
                Some(SuiDataSource::SuiStateDirect { url, .. }) => url.clone(),
                Some(SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: Some(url),
                }) => url.clone(),
                Some(SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: None,
                }) => unreachable!("peer_only is handled in the branch above"),
                // Old-style config on a notifier/fullnode: Sui fullnodes
                // serve gRPC on the same endpoint as JSON-RPC.
                None => config.sui_connector_config.sui_rpc_url.clone(),
            };
            Arc::new(SuiClient::new_grpc(&grpc_url, sui_client_metrics, ika_network_config).await?)
        };

        let (_, latest_system_inner) = sui_client.must_get_system_inner_object().await;
        let previous_epoch_last_system_checkpoint_sequence_number =
            latest_system_inner.previous_epoch_last_checkpoint_sequence_number();
        let epoch_start_system_state = sui_client
            .must_get_epoch_start_system(&latest_system_inner)
            .await;

        let (_, dwallet_coordinator_inner) = sui_client.must_get_dwallet_coordinator_inner().await;
        let DWalletCoordinatorInner::V1(dwallet_coordinator_inner) = dwallet_coordinator_inner;
        let previous_epoch_last_dwallet_checkpoint_sequence_number =
            dwallet_coordinator_inner.previous_epoch_last_checkpoint_sequence_number;

        let committee = epoch_start_system_state.get_ika_committee();
        let committee_arc = Arc::new(committee.clone());

        let secret = Arc::pin(config.protocol_key_pair().copy());

        //let cur_epoch = latest_system_state.epoch();
        // let committee = committee_store
        //     .get_committee(&cur_epoch)?
        //     .expect("Committee of the current epoch must exist");

        let epoch_start_configuration = EpochStartConfiguration::new(epoch_start_system_state)
            .expect("EpochStartConfiguration construction cannot fail");

        // let epoch_start_configuration = store
        //     .get_epoch_start_configuration()?
        //     .expect("EpochStartConfiguration of the current epoch must exist");

        let epoch_options = default_db_options().optimize_db_for_write_throughput(4, false);

        let mut ika_dwallet_2pc_mpc_package_id_v2 = config
            .sui_connector_config
            .ika_dwallet_2pc_mpc_package_id_v2;

        // Testnet V2
        if ika_dwallet_2pc_mpc_package_id_v2.is_none()
            && config.sui_connector_config.ika_dwallet_2pc_mpc_package_id
                == ObjectID::from_str(
                    "0xf02f5960c94fce1899a3795b5d11fd076bc70a8d0e20a2b19923d990ed490730",
                )?
        {
            ika_dwallet_2pc_mpc_package_id_v2 = Some(ObjectID::from_str(
                "0x6573a6c13daf26a64eb8a37d3c7a4391b353031e223072ca45b1ff9366f59293",
            )?)
        }

        // Mainnet V2
        if ika_dwallet_2pc_mpc_package_id_v2.is_none()
            && config.sui_connector_config.ika_dwallet_2pc_mpc_package_id
                == ObjectID::from_str(
                    "0xdd24c62739923fbf582f49ef190b4a007f981ca6eb209ca94f3a8eaf7c611317",
                )?
        {
            ika_dwallet_2pc_mpc_package_id_v2 = Some(ObjectID::from_str(
                "0x23b5bd96051923f800c3a2150aacdcdd8d39e1df2dce4dac69a00d2d8c7f7e77",
            )?)
        }

        let packages_config = IkaNetworkConfig::new(
            config.sui_connector_config.ika_package_id,
            config.sui_connector_config.ika_common_package_id,
            config.sui_connector_config.ika_dwallet_2pc_mpc_package_id,
            ika_dwallet_2pc_mpc_package_id_v2,
            config.sui_connector_config.ika_system_package_id,
            config.sui_connector_config.ika_system_object_id,
            config
                .sui_connector_config
                .ika_dwallet_coordinator_object_id,
        );

        let dwallet_mpc_metrics = DWalletMPCMetrics::new(&registry_service.default_registry());

        let epoch_store = AuthorityPerEpochStore::new(
            config.protocol_public_key(),
            committee_arc.clone(),
            &config.db_path().join("store"),
            Some(epoch_options.options),
            EpochMetrics::new(&registry_service.default_registry()),
            epoch_start_configuration,
            chain_identifier,
            packages_config,
        )?;

        // Allow the per-epoch handoff record path to persist freshly
        // certified attestations into perpetual storage.
        epoch_store.install_perpetual_tables_for_handoff(perpetual_tables.clone());

        info!("created epoch store");

        replay_log!(
            "Beginning replay run. Epoch: {:?}, Protocol config: {:?}",
            epoch_store.epoch(),
            epoch_store.protocol_config()
        );

        let effective_buffer_stake = epoch_store.get_effective_buffer_stake_bps();
        let default_buffer_stake = epoch_store
            .protocol_config()
            .buffer_stake_for_protocol_upgrade_bps();
        if effective_buffer_stake != default_buffer_stake {
            warn!(
                ?effective_buffer_stake,
                ?default_buffer_stake,
                "buffer_stake_for_protocol_upgrade_bps is currently overridden"
            );
        }

        // OCS connector startup is two-phased to handle both data-source modes.
        //
        // sui-state-direct: the OCS stack is built up-front and produces a
        // `SuiStateMirrorServer` that must be registered on the anemo router
        // at construction time:
        //   build OCS (no network) → pre-network ratchet → bind network with mirror_server.
        //
        // sui-state-mirrored: the OCS stack's transport is `SuiMirrorTransport`,
        // which needs the live anemo network to reach peers. There's no mirror
        // server to register. Order:
        //   bind network (no mirror_server) → build OCS → post-network ratchet.
        //
        // The pre-network ratchet on sui-state-direct prevents a window where
        // the push handler is reachable while our committee head is still at
        // the trust anchor's epoch (which would reject every push as
        // `missing_committee` until the first periodic ratchet tick).
        //
        // `has_anchor` is computed earlier (it selects the gRPC vs JSON-RPC
        // `sui_client` backend); reuse it here.
        // OCS verified reads are a *node-level* choice, not a protocol
        // feature: both paths read the same on-chain state (the
        // `session_events` bag and the emitted event are written together,
        // unconditionally, by the contract), so which one a node uses can't
        // desync the network. A node opts in by configuring a trust anchor
        // (`has_anchor`); without one it uses the legacy JSON-RPC event path.
        // This is independent of `off_chain_validator_metadata_enabled`,
        // which still gates the v4 metadata-v2 pipeline (handoff, MPC-data
        // announcements, peer-blob fetch, ...) further down.

        let (
            mut reader_opt,
            mut ratchet_opt,
            sui_state_mirror_server,
            raw_transport_for_pushing,
            mut state_cache_opt,
            push_handler_opt,
        ) = {
            // Spread a built stack into the individually-wired component
            // slots the rest of boot threads around.
            let unpack = |stack: sui_connector_setup::SuiConnectorStack| {
                (
                    Some(stack.reader),
                    Some(stack.ratchet),
                    stack.mirror_server,
                    stack.raw_transport_for_pushing,
                    Some(stack.state_cache),
                    stack.push_handler,
                )
            };
            if is_sui_state_direct {
                info!("Building OCS verifier stack (sui-state-direct, direct gRPC)");
                let stack = sui_connector_setup::build_sui_connector_stack(
                    &config.sui_connector_config,
                    perpetual_tables.clone(),
                    None,
                    proof_cache_cfg.clone(),
                    ocs_metrics.clone(),
                    proof_provider_metrics.clone(),
                )
                .await
                .map_err(|e| anyhow!("build OCS connector stack: {e}"))?;
                match stack.ratchet.ratchet_to_current_epoch().await {
                    Ok(()) => info!(
                        head_epoch = stack.ratchet.committees().head_epoch(),
                        "Sui committee ratchet caught up before binding p2p"
                    ),
                    Err(e) => warn!(
                        error = ?e,
                        "initial ratchet to current epoch failed; periodic ratchet will retry"
                    ),
                }
                unpack(stack)
            } else if peer_only {
                // Built before the bootstrap reads (see the transport gate); reuse.
                let stack = peer_only_stack
                    .take()
                    .expect("peer-only OCS stack built in the transport gate above");
                unpack(stack)
            } else {
                (None, None, None, None, None, None)
            }
        };

        let P2pComponents {
            p2p_network,
            known_peers,
            discovery_handle,
            state_sync_handle,
            mpc_announcement_relay,
            mpc_data_blob_store,
        } = if let Some(p2p) = peer_only_p2p.take() {
            // Built before the bootstrap reads (see the transport gate); reuse.
            p2p
        } else {
            Self::create_p2p_network(
                &config,
                state_sync_store.clone(),
                chain_identifier,
                trusted_peer_change_rx,
                archive_readers.clone(),
                &prometheus_registry,
                !epoch_store.committee().authority_exists(&authority_name),
                perpetual_tables.clone(),
                sui_state_mirror_server,
            )?
        };

        // Hand the (sui-state-direct) push handler the bound network so a
        // detected push gap can pull a verified snapshot from the peer that
        // revealed it. The handler was built before the network existed.
        if let Some(push_handler) = &push_handler_opt {
            push_handler.set_network(p2p_network.clone());
        }

        if is_sui_state_mirrored && !peer_only {
            // sui-state-mirrored *with* a fallback URL: the OCS stack is built
            // here, after the network is up. (Peer-only — mirrored with no
            // fallback — already built it in the transport gate above.)
            //
            // Anemo connects to seed peers asynchronously. `build_sui_connector_stack`
            // probes the transport (`get_latest_checkpoint`) at construction; if it
            // runs before any configured sui-state-direct mirror peer is reachable
            // the probe fails with "no peers reachable". Wait specifically for one
            // of the configured `sui_state_mirror_peers` to come online.
            let mirror_peer_ids =
                sui_connector_setup::configured_mirror_peer_ids(&config.sui_connector_config);
            Self::wait_for_specific_peers(
                &p2p_network,
                &mirror_peer_ids,
                std::time::Duration::from_secs(60),
            )
            .await;
            info!(
                peer_count = p2p_network.peers().len(),
                "Building OCS verifier stack (sui-state-mirrored, p2p relay)"
            );
            let stack = sui_connector_setup::build_sui_connector_stack(
                &config.sui_connector_config,
                perpetual_tables.clone(),
                Some(p2p_network.clone()),
                proof_cache_cfg,
                ocs_metrics.clone(),
                proof_provider_metrics.clone(),
            )
            .await
            .map_err(|e| anyhow!("build OCS connector stack (sui-state-mirrored): {e}"))?;
            if let Err(e) = stack.ratchet.ratchet_to_current_epoch().await {
                warn!(
                    error = ?e,
                    "initial ratchet to current epoch (sui-state-mirrored) failed; periodic ratchet will retry"
                );
            }
            reader_opt = Some(stack.reader);
            ratchet_opt = Some(stack.ratchet);
            state_cache_opt = Some(stack.state_cache);
        }

        // Periodic Sui-committee ratchet + a task mirroring the committee
        // head into the ocs_metrics gauge.
        if let Some(ratchet) = ratchet_opt.clone() {
            let metrics_for_head = ocs_metrics.clone();
            let ratchet_for_head = ratchet.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                loop {
                    tick.tick().await;
                    metrics_for_head
                        .committee_head_epoch
                        .set(ratchet_for_head.committees().head_epoch() as i64);
                }
            });
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    tick.tick().await;
                    if let Err(e) = ratchet.ratchet_to_current_epoch().await {
                        warn!(error = ?e, "Sui committee ratchet failed; will retry");
                    }
                }
            });
        }

        // sui-state-direct only: spawn the checkpoint pusher now that the anemo
        // network is up. It fans out Ika-relevant CheckpointData + all
        // end-of-epoch checkpoints to peers via SuiStateMirror.
        if let Some(raw_transport) = raw_transport_for_pushing {
            let cache_for_push = state_cache_opt
                .clone()
                .expect("state_cache present on sui-state-direct (set in the same branch)");
            let packages = ika_types::messages_dwallet_mpc::IkaPackageConfig {
                ika_package_id: config.sui_connector_config.ika_package_id,
                ika_common_package_id: config.sui_connector_config.ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id: config
                    .sui_connector_config
                    .ika_dwallet_2pc_mpc_package_id,
                ika_dwallet_2pc_mpc_package_id_v2: config
                    .sui_connector_config
                    .ika_dwallet_2pc_mpc_package_id_v2,
                ika_system_package_id: config.sui_connector_config.ika_system_package_id,
            };
            let network_for_push = p2p_network.clone();
            let perpetual_for_push = perpetual_tables.clone();
            let metrics_for_push = ocs_metrics.clone();
            tokio::spawn(async move {
                use ika_core::sui_connector::push_worker::IkaCheckpointPusher;
                match IkaCheckpointPusher::new(
                    raw_transport,
                    network_for_push,
                    perpetual_for_push,
                    metrics_for_push,
                    &packages,
                    std::time::Duration::from_secs(2),
                    cache_for_push,
                )
                .await
                {
                    Ok(pusher) => pusher.run().await,
                    Err(e) => warn!(error = ?e, "checkpoint pusher failed to start; not pushing"),
                }
            });
        }

        // We must explicitly send this instead of relying on the initial value to trigger
        // watch value change, so that state-sync is able to process it.
        send_trusted_peer_change(
            &config,
            &trusted_peer_change_tx,
            epoch_store.epoch_start_state(),
        )
        .expect("Initial trusted peers must be set");

        info!("start state archival");
        // Start archiving local state to remote store
        let state_archive_handle =
            Self::start_state_archival(&config, &prometheus_registry, state_sync_store.clone())
                .await?;

        info!("create authority state");
        let state = AuthorityState::new(
            authority_name,
            secret,
            config.supported_protocol_versions.unwrap(),
            perpetual_tables.clone(),
            epoch_store.clone(),
            committee_store.clone(),
            dwallet_checkpoint_store.clone(),
            &prometheus_registry,
            config.clone(),
        )
        .await;
        info!("created authority state");

        let sui_connector_metrics = SuiConnectorMetrics::new(&registry_service.default_registry());
        let (next_epoch_committee_sender, next_epoch_committee_receiver) =
            watch::channel::<Committee>(committee.clone());
        let (chain_next_committee_sender, chain_next_epoch_committee_receiver) =
            watch::channel(CommitteeMembership {
                epoch: committee.epoch,
                voting_rights: committee.voting_rights,
                quorum_threshold: committee.quorum_threshold,
                validity_threshold: committee.validity_threshold,
            });
        let (new_requests_sender, new_requests_receiver) =
            broadcast::channel(EVENTS_CHANNEL_BUFFER_SIZE);
        let (end_of_publish_sender, end_of_publish_receiver) = watch::channel::<Option<u64>>(None);
        let (
            last_session_to_complete_in_current_epoch_sender,
            last_session_to_complete_in_current_epoch_receiver,
        ) = watch::channel((0, 0));
        let (uncompleted_requests_sender, uncompleted_requests_receiver) =
            watch::channel((Vec::new(), 0));
        // Separate flags for each NOA checkpoint kind to avoid race between handlers.
        let noa_dwallet_finalized = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let noa_system_finalized = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let noa_dwallet_finalized_clone = noa_dwallet_finalized.clone();
        let noa_system_finalized_clone = noa_system_finalized.clone();
        let noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            noa_dwallet_finalized_clone.load(std::sync::atomic::Ordering::Acquire)
                && noa_system_finalized_clone.load(std::sync::atomic::Ordering::Acquire)
        });

        let (sui_connector_service, network_keys_receiver) = SuiConnectorService::new(
            dwallet_checkpoint_store.clone(),
            system_checkpoint_store.clone(),
            sui_client.clone(),
            config.sui_connector_config.clone(),
            sui_connector_metrics,
            mode,
            next_epoch_committee_sender,
            chain_next_committee_sender,
            new_requests_sender,
            end_of_publish_sender.clone(),
            last_session_to_complete_in_current_epoch_sender,
            uncompleted_requests_sender,
            noa_checkpoints_finalized,
            reader_opt.clone(),
            ocs_metrics.clone(),
        )
        .await?;

        let (end_of_epoch_channel, _end_of_epoch_receiver) =
            broadcast::channel(config.end_of_epoch_broadcast_channel_capacity);

        let authority_names_to_peer_ids = epoch_store
            .epoch_start_state()
            .get_authority_names_to_peer_ids();

        let network_connection_metrics = mysten_network::quinn_metrics::QuinnConnectionMetrics::new(
            "ika",
            &registry_service.default_registry(),
        );

        let authority_names_to_peer_ids = ArcSwap::from_pointee(authority_names_to_peer_ids);

        let connection_monitor_handle =
            mysten_network::anemo_connection_monitor::AnemoConnectionMonitor::spawn(
                p2p_network.downgrade(),
                Arc::new(network_connection_metrics),
                known_peers,
            );

        let connection_monitor_status = ConnectionMonitorStatus {
            connection_statuses: connection_monitor_handle.connection_statuses(),
            authority_names_to_peer_ids,
        };

        let connection_monitor_status = Arc::new(connection_monitor_status);
        let ika_node_metrics = Arc::new(IkaNodeMetrics::new(&registry_service.default_registry()));

        ika_node_metrics
            .binary_max_protocol_version
            .set(ProtocolVersion::MAX.as_u64() as i64);
        ika_node_metrics
            .configured_max_protocol_version
            .set(config.supported_protocol_versions.unwrap().max.as_u64() as i64);
        let sui_data_receivers = SuiDataReceivers {
            network_keys_receiver,
            new_requests_receiver,
            next_epoch_committee_receiver,
            chain_next_epoch_committee_receiver,
            last_session_to_complete_in_current_epoch_receiver,
            end_of_publish_receiver,
            uncompleted_requests_receiver,
        };
        let validator_components = if state.is_validator(&epoch_store) {
            let components = Self::construct_validator_components(
                config.clone(),
                state.clone(),
                committee_arc,
                epoch_store.clone(),
                dwallet_checkpoint_store.clone(),
                system_checkpoint_store.clone(),
                state_sync_handle.clone(),
                connection_monitor_status.clone(),
                &registry_service,
                ika_node_metrics.clone(),
                previous_epoch_last_dwallet_checkpoint_sequence_number,
                previous_epoch_last_system_checkpoint_sequence_number,
                dwallet_mpc_metrics.clone(),
                sui_data_receivers.clone(),
                noa_dwallet_finalized.clone(),
                noa_system_finalized.clone(),
            )
            .await?;
            // This is only needed during cold start.
            components.consensus_adapter.submit_recovered(&epoch_store);

            Some(components)
        } else {
            None
        };

        // setup shutdown channel
        let (shutdown_channel, _) = broadcast::channel::<Option<RunWithRange>>(1);

        // Per-epoch authority store directories grow unbounded without
        // pruning, and everything later epochs depend on lives in the
        // `perpetual/` sibling by design (handoff certs, epoch-keyed
        // reconfiguration outputs, blob mirror). Keep a bounded window of
        // prior epochs; see `authority_db_retention_epochs`.
        let authority_store_pruner = ConsensusStorePruner::new_with_layout(
            config.db_path().join("store"),
            EPOCH_DB_PREFIX,
            "authority",
            epoch_store.epoch(),
            config.authority_db_retention_epochs(),
            config.authority_db_pruner_period(),
            &registry_service.default_registry(),
        );

        let node = Self {
            config,
            validator_components: Mutex::new(validator_components),
            state,
            registry_service,
            metrics: ika_node_metrics,

            _discovery: discovery_handle,
            _connection_monitor_handle: connection_monitor_handle,
            state_sync_handle,
            dwallet_checkpoint_store,
            system_checkpoint_store,

            end_of_epoch_channel,
            connection_monitor_status,
            trusted_peer_change_tx,

            #[cfg(msim)]
            sim_state: Default::default(),

            sui_connector_service,
            mpc_announcement_relay,
            mpc_data_blob_store,
            p2p_network,
            _state_archive_handle: state_archive_handle,
            shutdown_channel_tx: shutdown_channel,
            noa_dwallet_finalized,
            noa_system_finalized,
            authority_store_pruner,
        };

        info!("IkaNode started!");
        let node = Arc::new(node);
        let node_copy = node.clone();
        let sui_client_clone = sui_client.clone();

        // Joiner-side announcement fan-out: a node selected into the
        // next-epoch committee but not yet in the current one isn't a
        // consensus participant, so it relays its mpc_data
        // announcement to current-committee peers over P2P. Runs on
        // all nodes; it only acts when it observes itself as a true
        // joiner. Spawned alongside (not inside) reconfiguration
        // because it must fire mid-epoch when `V_{e+1}` is published,
        // not at the epoch boundary.
        let joiner_node = node.clone();
        // Use the CHAIN next-epoch committee (published before the
        // off-chain assembly), not the assembled one — otherwise the
        // joiner can't learn it's a joiner until after the freeze has
        // already excluded it (see the channel's doc on SuiDataReceivers).
        let joiner_next_committee_receiver = sui_data_receivers
            .chain_next_epoch_committee_receiver
            .clone();
        spawn_monitored_task!(async move {
            Self::monitor_joiner_announcements(joiner_node, joiner_next_committee_receiver).await;
        });

        spawn_monitored_task!(async move {
            let result = Self::monitor_reconfiguration(
                node_copy,
                sui_client_clone,
                dwallet_mpc_metrics,
                sui_data_receivers.clone(),
            )
            .await;
            if let Err(error) = result {
                warn!("Reconfiguration finished with error {:?}", error);
            }
        });

        Ok(node)
    }

    /// Watches the next-epoch committee and, when this node is a true
    /// joiner (in `V_{e+1}` but not the current committee), fans its
    /// signed `ValidatorMpcDataAnnouncement` out to current-committee
    /// peers via P2P so an honest relayer forwards it into consensus.
    /// Continuing validators (in both committees) and leaving/observer
    /// nodes never act — they fall through the membership check.
    async fn monitor_joiner_announcements(
        node: Arc<Self>,
        mut next_epoch_committee_receiver: tokio::sync::watch::Receiver<
            ika_types::committee::CommitteeMembership,
        >,
    ) {
        use ika_core::blob_cache::BlobCache;
        use ika_core::epoch_tasks::joiner_announcement_sender::{
            JoinerAnnouncementSender, JoinerFanoutConfig, P2pAnnouncementFanout,
        };
        use ika_types::sui::epoch_start_system::EpochStartSystemTrait;

        // Without a root seed we can't derive our mpc_data blob, so
        // we can't be a joiner — nothing to do.
        let Some(root_seed_kp) = node.config.root_seed_key_pair.as_ref() else {
            return;
        };
        let root_seed = root_seed_kp.root_seed().clone();
        let consensus_keypair = Arc::new(node.config.consensus_key_pair().copy());
        // Pre-derive our stable, seed-deterministic mpc_data blob once, up
        // front and off the critical path. The class-groups derivation is
        // slow; doing it lazily the moment we discover we're a next-epoch
        // joiner would put it on the narrow committee-publish → freeze-
        // deadline window and miss the freeze under short epochs. The blob is
        // identical every epoch (a pure function of the root seed), so one
        // derivation serves every future joiner announcement.
        let own_mpc_data_blob = match tokio::task::spawn_blocking({
            let root_seed = root_seed.clone();
            move || ika_core::validator_metadata::derive_mpc_data_blob(&root_seed)
        })
        .await
        {
            Ok(Ok(blob)) => blob,
            Ok(Err(e)) => {
                warn!(error = ?e, "joiner monitor: failed to derive own mpc_data blob; not announcing as a joiner");
                return;
            }
            Err(e) => {
                warn!(error = ?e, "joiner monitor: mpc_data blob derivation task panicked; not announcing as a joiner");
                return;
            }
        };
        let mut last_handled_next_epoch: Option<u64> = None;
        loop {
            let next_committee = next_epoch_committee_receiver.borrow_and_update().clone();
            let next_epoch = next_committee.epoch();
            if last_handled_next_epoch != Some(next_epoch) {
                let epoch_store = node.state.load_epoch_store_one_call_per_task();
                if epoch_store
                    .protocol_config()
                    .off_chain_validator_metadata_enabled()
                    && next_epoch == epoch_store.epoch() + 1
                {
                    let self_name = epoch_store.name;
                    let in_next = next_committee
                        .voting_rights
                        .iter()
                        .any(|(name, _)| *name == self_name);
                    let in_current = epoch_store.committee().authority_exists(&self_name);
                    if in_next && !in_current {
                        let peer_ids: Vec<anemo::PeerId> = epoch_store
                            .epoch_start_state()
                            .get_authority_names_to_peer_ids()
                            .into_values()
                            .collect();
                        let current_committee_size = epoch_store.committee().voting_rights.len();
                        // f+1 distinct accepting peers ensures at least
                        // one honest relayer (committee is 3f+1).
                        let min_accepts = current_committee_size / 3 + 1;
                        let blob_cache = BlobCache::new(
                            node.mpc_data_blob_store.clone(),
                            node.state.perpetual_tables(),
                        );
                        let fanout = Arc::new(P2pAnnouncementFanout::new(
                            node.p2p_network.clone(),
                            peer_ids,
                        ));
                        let sender = JoinerAnnouncementSender::new(
                            self_name,
                            next_epoch,
                            own_mpc_data_blob.clone(),
                            consensus_keypair.clone(),
                            blob_cache,
                            fanout,
                            JoinerFanoutConfig {
                                min_accepts,
                                // Retry briskly: the common early
                                // rejection is `UnregisteredJoiner`
                                // during the brief window before each
                                // relayer's JoinerPubkeyProvider picks
                                // up the just-published next committee.
                                // A coarse retry burns most of the
                                // freeze window, so scale the cadence to
                                // the epoch length (a no-op at
                                // production epoch lengths; compressed in
                                // short test epochs). max_attempts keeps
                                // a generous bound across the window.
                                retry_interval:
                                    ika_core::validator_metadata::epoch_scaled_poll_interval(
                                        epoch_store.epoch_start_state().epoch_duration_ms(),
                                        Duration::from_secs(3),
                                    ),
                                max_attempts: 100,
                            },
                        );
                        info!(
                            next_epoch,
                            "this node is a next-epoch joiner; fanning out its mpc_data announcement"
                        );
                        spawn_monitored_task!(async move {
                            sender.run().await;
                        });
                        last_handled_next_epoch = Some(next_epoch);
                    }
                }
            }
            if next_epoch_committee_receiver.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn subscribe_to_epoch_change(&self) -> broadcast::Receiver<SystemInner> {
        self.end_of_epoch_channel.subscribe()
    }

    pub fn subscribe_to_shutdown_channel(&self) -> broadcast::Receiver<Option<RunWithRange>> {
        self.shutdown_channel_tx.subscribe()
    }

    pub fn current_epoch_for_testing(&self) -> EpochId {
        self.state.current_epoch_for_testing()
    }

    /// Protocol version of the validator's current epoch store. Useful for
    /// asserting on protocol-version transitions across reconfigurations.
    pub fn current_protocol_version_for_testing(&self) -> ika_protocol_config::ProtocolVersion {
        self.state.epoch_store_for_testing().protocol_version()
    }

    pub fn db_checkpoint_path(&self) -> PathBuf {
        self.config.db_checkpoint_path()
    }

    pub fn clear_override_protocol_upgrade_buffer_stake(&self, epoch: EpochId) -> IkaResult {
        self.state
            .clear_override_protocol_upgrade_buffer_stake(epoch)
    }

    pub fn set_override_protocol_upgrade_buffer_stake(
        &self,
        epoch: EpochId,
        buffer_stake_bps: u64,
    ) -> IkaResult {
        self.state
            .set_override_protocol_upgrade_buffer_stake(epoch, buffer_stake_bps)
    }

    async fn start_state_archival(
        config: &NodeConfig,
        prometheus_registry: &Registry,
        state_sync_store: RocksDbStore,
    ) -> Result<Option<broadcast::Sender<()>>> {
        if let Some(remote_store_config) = &config.state_archive_write_config.object_store_config {
            let local_store_config = ObjectStoreConfig {
                object_store: Some(ObjectStoreType::File),
                directory: Some(config.archive_path()),
                ..Default::default()
            };
            let archive_writer = ArchiveWriter::new(
                local_store_config,
                remote_store_config.clone(),
                FileCompression::Zstd,
                StorageFormat::Blob,
                Duration::from_secs(600),
                256 * 1024 * 1024,
                prometheus_registry,
            )
            .await?;
            Ok(Some(archive_writer.start(state_sync_store).await?))
        } else {
            Ok(None)
        }
    }

    /// Block until at least one of `wanted` peers is connected, or `timeout`
    /// elapses. Used by sui-state-mirrored startup so the OCS stack's transport
    /// probe doesn't run before a sui-state-direct mirror peer is reachable.
    async fn wait_for_specific_peers(
        network: &anemo::Network,
        wanted: &[PeerId],
        timeout: std::time::Duration,
    ) {
        if wanted.is_empty() {
            return;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
        loop {
            if wanted.iter().any(|p| network.peer(*p).is_some()) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    timeout_secs = timeout.as_secs(),
                    wanted_count = wanted.len(),
                    "no configured sui-state-direct peer connected within timeout; proceeding anyway \
                     (sui-state-mirrored OCS build is likely to fail and the node will exit)"
                );
                return;
            }
            interval.tick().await;
        }
    }

    fn create_p2p_network(
        config: &NodeConfig,
        state_sync_store: RocksDbStore,
        chain_identifier: ChainIdentifier,
        trusted_peer_change_rx: watch::Receiver<TrustedPeerChangeEvent>,
        archive_readers: ArchiveReaderBalancer,
        prometheus_registry: &Registry,
        is_notifier: bool,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        sui_state_mirror_server: Option<
            ika_network::sui_state_mirror::SuiStateMirrorServer<
                ika_network::sui_state_mirror::Server,
            >,
        >,
    ) -> Result<P2pComponents> {
        let (state_sync, state_sync_server) = state_sync::Builder::new()
            .config(config.p2p_config.state_sync.clone().unwrap_or_default())
            .store(state_sync_store)
            .archive_readers(archive_readers)
            .with_metrics(prometheus_registry)
            .build();

        let (discovery, discovery_server) = discovery::Builder::new(trusted_peer_change_rx)
            .config(config.p2p_config.clone())
            .build();

        // Content-addressed cache of MPC data blobs, hydrated from
        // perpetual storage so a restart doesn't lose blobs the
        // validator was serving to peers. Producer caching + cross-
        // node fetch are wired in later steps; for now this just
        // serves whatever's been persisted previously.
        let mpc_data_blob_store =
            ika_network::mpc_artifacts::InMemoryBlobStore::new_with_metrics(prometheus_registry);
        for entry in perpetual_tables.iter_mpc_artifact_blobs() {
            match entry {
                Ok((digest, bytes)) => mpc_data_blob_store.insert(digest, bytes),
                Err(e) => warn!(
                    error = ?e,
                    "skipping corrupt mpc_artifact_blobs row during hydration"
                ),
            }
        }
        let mpc_announcement_relay = ika_network::mpc_artifacts::AnnouncementRelayHandle::new();
        // Serve through a read-through BlobCache: the in-memory hot
        // cache first, durable perpetual on a miss. The fallback lets
        // the server return blobs written only to perpetual (e.g. a
        // network DKG / reconfiguration output cached by the per-epoch
        // store) without waiting for a restart to re-hydrate.
        let mpc_blob_cache = ika_core::blob_cache::BlobCache::new(
            mpc_data_blob_store.clone(),
            perpetual_tables.clone(),
        );
        let validator_metadata_server = ika_network::mpc_artifacts::build_server(
            mpc_blob_cache,
            mpc_announcement_relay.clone(),
            perpetual_tables.clone(),
        );

        let discovery_config = config.p2p_config.discovery.clone().unwrap_or_default();
        let known_peers: HashMap<PeerId, String> = discovery_config
            .allowlisted_peers
            .clone()
            .into_iter()
            .map(|ap| (ap.peer_id, "allowlisted_peer".to_string()))
            .chain(config.p2p_config.seed_peers.iter().filter_map(|peer| {
                peer.peer_id
                    .map(|peer_id| (peer_id, "seed_peer".to_string()))
            }))
            .collect();

        let p2p_network = {
            let mut routes = anemo::Router::new()
                .add_rpc_service(discovery_server)
                .add_rpc_service(state_sync_server)
                .add_rpc_service(validator_metadata_server);
            // sui-state-direct validators serve the OCS verified-read relay.
            if let Some(mirror_server) = sui_state_mirror_server {
                routes = routes.add_rpc_service(mirror_server);
            }
            let inbound_network_metrics =
                mysten_network::metrics::NetworkMetrics::new("ika", "inbound", prometheus_registry);
            let outbound_network_metrics = mysten_network::metrics::NetworkMetrics::new(
                "ika",
                "outbound",
                prometheus_registry,
            );

            let service = ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_server_errors()
                        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
                        .on_failure(DefaultOnFailure::new().level(tracing::Level::WARN)),
                )
                .layer(CallbackLayer::new(
                    mysten_network::metrics::MetricsMakeCallbackHandler::new(
                        Arc::new(inbound_network_metrics),
                        config.p2p_config.excessive_message_size(),
                    ),
                ))
                .service(routes);

            let outbound_layer = ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_client_and_server_errors()
                        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO))
                        .on_failure(DefaultOnFailure::new().level(tracing::Level::WARN)),
                )
                .layer(CallbackLayer::new(
                    mysten_network::metrics::MetricsMakeCallbackHandler::new(
                        Arc::new(outbound_network_metrics),
                        config.p2p_config.excessive_message_size(),
                    ),
                ))
                .into_inner();

            let mut anemo_config = config.p2p_config.anemo_config.clone().unwrap_or_default();
            // Set the max_frame_size to be 1 GB to work around the issue of there being too many
            // staking events in the epoch change txn.
            anemo_config.max_frame_size = Some(1 << 30);

            // Set a higher default value for socket send/receive buffers if not already
            // configured.
            let mut quic_config = anemo_config.quic.unwrap_or_default();
            if quic_config.socket_send_buffer_size.is_none() {
                quic_config.socket_send_buffer_size = Some(20 << 20);
            }
            if quic_config.socket_receive_buffer_size.is_none() {
                quic_config.socket_receive_buffer_size = Some(20 << 20);
            }
            quic_config.allow_failed_socket_buffer_size_setting = true;

            // Set high-performance defaults for quinn transport.
            // With 200MiB buffer size and ~500ms RTT, max throughput ~400MiB/s.
            if quic_config.max_concurrent_bidi_streams.is_none() {
                quic_config.max_concurrent_bidi_streams = Some(500);
            }
            if quic_config.max_concurrent_uni_streams.is_none() {
                quic_config.max_concurrent_uni_streams = Some(500);
            }
            if quic_config.stream_receive_window.is_none() {
                quic_config.stream_receive_window = Some(100 << 20);
            }
            if quic_config.receive_window.is_none() {
                quic_config.receive_window = Some(200 << 20);
            }
            if quic_config.send_window.is_none() {
                quic_config.send_window = Some(200 << 20);
            }
            if quic_config.crypto_buffer_size.is_none() {
                quic_config.crypto_buffer_size = Some(1 << 20);
            }
            if quic_config.max_idle_timeout_ms.is_none() {
                quic_config.max_idle_timeout_ms = Some(30_000);
            }
            if quic_config.keep_alive_interval_ms.is_none() {
                quic_config.keep_alive_interval_ms = Some(5_000);
            }
            anemo_config.quic = Some(quic_config);

            let server_name = format!("ika-{chain_identifier}");
            let network = Network::bind(config.p2p_config.listen_address)
                .server_name(&server_name)
                .private_key(config.network_key_pair().copy().private().0.to_bytes())
                .config(anemo_config)
                .outbound_request_layer(outbound_layer)
                .start(service)?;
            info!(
                server_name = server_name,
                "P2p network started on {}",
                network.local_addr()
            );

            network
        };

        let discovery_handle =
            discovery.start(p2p_network.clone(), config.network_key_pair().copy());
        let state_sync_handle = state_sync.start(p2p_network.clone(), is_notifier);

        Ok(P2pComponents {
            p2p_network,
            known_peers,
            discovery_handle,
            state_sync_handle,
            mpc_announcement_relay,
            mpc_data_blob_store,
        })
    }

    async fn construct_validator_components(
        config: NodeConfig,
        state: Arc<AuthorityState>,
        committee: Arc<Committee>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        state_sync_handle: state_sync::Handle,
        connection_monitor_status: Arc<ConnectionMonitorStatus>,
        registry_service: &RegistryService,
        ika_node_metrics: Arc<IkaNodeMetrics>,
        previous_epoch_last_dwallet_checkpoint_sequence_number: u64,
        previous_epoch_last_system_checkpoint_sequence_number: u64,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        sui_data_receivers: SuiDataReceivers,
        noa_dwallet_finalized: Arc<std::sync::atomic::AtomicBool>,
        noa_system_finalized: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<ValidatorComponents> {
        let mut config_clone = config.clone();
        let consensus_config = config_clone
            .consensus_config
            .as_mut()
            .ok_or_else(|| anyhow!("Validator is missing consensus config"))?;

        let client = Arc::new(UpdatableConsensusClient::new());
        let consensus_adapter = Arc::new(Self::construct_consensus_adapter(
            &committee,
            consensus_config,
            state.name,
            connection_monitor_status.clone(),
            &registry_service.default_registry(),
            epoch_store.protocol_config().clone(),
            client.clone(),
        ));

        let consensus_manager = Arc::new(ConsensusManager::new(
            &config,
            consensus_config,
            registry_service,
            client,
        ));

        // This only gets started up once, not on every epoch. (Make call to remove every epoch.)
        let consensus_store_pruner = ConsensusStorePruner::new(
            consensus_manager.get_storage_base_path(),
            epoch_store.epoch(),
            consensus_config.db_retention_epochs(),
            consensus_config.db_pruner_period(),
            &registry_service.default_registry(),
        );

        let dwallet_checkpoint_metrics =
            DWalletCheckpointMetrics::new(&registry_service.default_registry());
        let system_checkpoint_metrics =
            SystemCheckpointMetrics::new(&registry_service.default_registry());
        let ika_tx_validator_metrics =
            IkaTxValidatorMetrics::new(&registry_service.default_registry());
        Self::start_epoch_specific_validator_components(
            &config,
            state.clone(),
            consensus_adapter,
            dwallet_checkpoint_store,
            system_checkpoint_store,
            epoch_store,
            state_sync_handle,
            consensus_manager,
            consensus_store_pruner,
            dwallet_checkpoint_metrics,
            dwallet_mpc_metrics,
            system_checkpoint_metrics,
            ika_node_metrics,
            ika_tx_validator_metrics,
            previous_epoch_last_dwallet_checkpoint_sequence_number,
            previous_epoch_last_system_checkpoint_sequence_number,
            sui_data_receivers,
            noa_dwallet_finalized,
            noa_system_finalized,
        )
        .await
    }

    async fn start_epoch_specific_validator_components(
        config: &NodeConfig,
        state: Arc<AuthorityState>,
        consensus_adapter: Arc<ConsensusAdapter>,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        state_sync_handle: state_sync::Handle,
        consensus_manager: Arc<ConsensusManager>,
        consensus_store_pruner: ConsensusStorePruner,
        dwallet_checkpoint_metrics: Arc<DWalletCheckpointMetrics>,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        system_checkpoint_metrics: Arc<SystemCheckpointMetrics>,
        _ika_node_metrics: Arc<IkaNodeMetrics>,
        ika_tx_validator_metrics: Arc<IkaTxValidatorMetrics>,
        previous_epoch_last_dwallet_checkpoint_sequence_number: u64,
        previous_epoch_last_system_checkpoint_sequence_number: u64,
        sui_data_receivers: SuiDataReceivers,
        noa_dwallet_finalized: Arc<std::sync::atomic::AtomicBool>,
        noa_system_finalized: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<ValidatorComponents> {
        // Channel for network-owned-address sign requests (sender unused after
        // pipeline→handler migration; receiver still drained by service loop).
        let (
            _network_owned_address_sign_request_sender,
            network_owned_address_sign_request_receiver,
        ) = tokio::sync::mpsc::channel::<NetworkOwnedAddressSignRequest>(
            NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
        );
        // Output channel: MPC service sends completed signatures here.
        let (network_owned_address_sign_output_sender, network_owned_address_sign_output_receiver) =
            tokio::sync::mpsc::channel::<NetworkOwnedAddressSignOutput>(
                NETWORK_OWNED_ADDRESS_SIGN_CHANNEL_CAPACITY,
            );

        // Start as true: at epoch start there are no checkpoints to finalize.
        // The service loop will flip to false if checkpoints arrive.
        // There is a brief window where the flag could be stale, but the epoch gate
        // has other conditions (BLS checkpoints, consensus, etc.) that take longer.
        noa_dwallet_finalized.store(true, std::sync::atomic::Ordering::Release);
        noa_system_finalized.store(true, std::sync::atomic::Ordering::Release);

        // Create NOA checkpoint handlers (driven directly by DWalletMPCService).
        let (dwallet_checkpoint_handler, system_checkpoint_handler) = if epoch_store
            .protocol_config()
            .noa_checkpoints()
        {
            use ika_types::noa_checkpoint;

            info!("Creating NOA checkpoint handlers");

            warn!(
                "Using LogOnlyChainSubmitter — NOA checkpoint chain submission is a no-op. \
                       Replace with actual chain submitter for production."
            );
            let dwallet_chain_submitter: Arc<
                dyn NOAChainSubmitter<noa_checkpoint::SuiDWalletCheckpoint>,
            > = Arc::new(LogOnlyChainSubmitter);
            let system_chain_submitter: Arc<
                dyn NOAChainSubmitter<noa_checkpoint::SuiSystemCheckpoint>,
            > = Arc::new(LogOnlyChainSubmitter);

            let dwallet_handler = NOACheckpointHandler::<noa_checkpoint::SuiDWalletCheckpoint>::new(
                dwallet_chain_submitter,
                epoch_store.epoch(),
                vec![],
                noa_dwallet_finalized.clone(),
            );
            let system_handler = NOACheckpointHandler::<noa_checkpoint::SuiSystemCheckpoint>::new(
                system_chain_submitter,
                epoch_store.epoch(),
                vec![],
                noa_system_finalized.clone(),
            );
            (Some(dwallet_handler), Some(system_handler))
        } else {
            info!("NOA checkpoints disabled, skipping NOA checkpoint handlers");
            (None, None)
        };

        let bls_dwallet = Self::start_dwallet_checkpoint_service(
            config,
            consensus_adapter.clone(),
            dwallet_checkpoint_store,
            epoch_store.clone(),
            state.clone(),
            state_sync_handle.clone(),
            dwallet_checkpoint_metrics.clone(),
            previous_epoch_last_dwallet_checkpoint_sequence_number,
        );
        let (checkpoint_service, checkpoint_service_tasks): (
            Option<Arc<DWalletCheckpointService>>,
            JoinSet<()>,
        ) = match bls_dwallet {
            Some((svc, tasks)) => (Some(svc), tasks),
            None => (None, JoinSet::new()),
        };

        let bls_system = Self::start_system_checkpoint_service(
            config,
            consensus_adapter.clone(),
            system_checkpoint_store,
            epoch_store.clone(),
            state.clone(),
            state_sync_handle.clone(),
            system_checkpoint_metrics.clone(),
            previous_epoch_last_system_checkpoint_sequence_number,
        );
        let (system_checkpoint_service, system_checkpoint_service_tasks): (
            Option<Arc<SystemCheckpointService>>,
            JoinSet<()>,
        ) = match bls_system {
            Some((svc, tasks)) => (Some(svc), tasks),
            None => (None, JoinSet::new()),
        };

        let (dwallet_mpc_service_exit_sender, dwallet_mpc_service_exit_receiver) =
            watch::channel(());
        if let Err(e) =
            DWalletMPCService::verify_validator_keys(epoch_store.epoch_start_state(), config)
        {
            error!(error = ?e, "Failed to verify validator keys");
            panic!("Failed to verify validator keys: {e}");
        };

        let dwallet_checkpoint_service_notify: Option<
            Arc<dyn ika_core::dwallet_checkpoints::DWalletCheckpointServiceNotify + Send + Sync>,
        > = checkpoint_service.clone().map(|svc| {
            svc as Arc<
                dyn ika_core::dwallet_checkpoints::DWalletCheckpointServiceNotify + Send + Sync,
            >
        });

        let mut dwallet_mpc_service = DWalletMPCService::new(
            epoch_store.clone(),
            dwallet_mpc_service_exit_receiver,
            EpochStoreSubmitToConsensus::new(epoch_store.clone(), consensus_adapter.clone()),
            config.clone(),
            dwallet_checkpoint_service_notify,
            dwallet_mpc_metrics.clone(),
            state.clone(),
            sui_data_receivers,
            epoch_store.name,
            epoch_store.epoch(),
            epoch_store.committee().clone(),
            epoch_store.protocol_config().clone(),
            network_owned_address_sign_request_receiver,
            network_owned_address_sign_output_sender,
            network_owned_address_sign_output_receiver,
            dwallet_checkpoint_handler,
            system_checkpoint_handler,
        );

        // create a new map that gets injected into both the consensus handler and the consensus adapter
        // the consensus handler will write values forwarded from consensus, and the consensus adapter
        // will read the values to make decisions about which validator submits a transaction to consensus
        let low_scoring_authorities = Arc::new(ArcSwap::new(Arc::new(HashMap::new())));

        consensus_adapter.swap_low_scoring_authorities(low_scoring_authorities.clone());

        let throughput_calculator = Arc::new(ConsensusThroughputCalculator::new(
            None,
            state.metrics.clone(),
        ));

        let throughput_profiler = Arc::new(ConsensusThroughputProfiler::new(
            throughput_calculator.clone(),
            None,
            None,
            state.metrics.clone(),
            ThroughputProfileRanges::from_chain(epoch_store.get_chain_identifier()),
        ));

        consensus_adapter.swap_throughput_profiler(throughput_profiler);

        let consensus_handler_initializer = ConsensusHandlerInitializer::new(
            state.clone(),
            checkpoint_service.clone(),
            system_checkpoint_service.clone(),
            epoch_store.clone(),
            low_scoring_authorities,
            throughput_calculator,
        );

        info!("Starting consensus manager asynchronously");

        // Spawn consensus startup asynchronously to avoid blocking other components
        tokio::spawn({
            let config = config.clone();
            let epoch_store = epoch_store.clone();
            let dwallet_ckpt_notify: Option<
                Arc<
                    dyn ika_core::dwallet_checkpoints::DWalletCheckpointServiceNotify + Send + Sync,
                >,
            > = checkpoint_service.clone().map(|svc| svc as _);
            let system_ckpt_notify: Option<
                Arc<dyn ika_core::system_checkpoints::SystemCheckpointServiceNotify + Send + Sync>,
            > = system_checkpoint_service.clone().map(|svc| svc as _);
            let sui_tx_validator = IkaTxValidator::new(
                state.clone(),
                consensus_adapter.clone(),
                dwallet_ckpt_notify,
                system_ckpt_notify,
                ika_tx_validator_metrics.clone(),
            );
            let consensus_manager = consensus_manager.clone();
            async move {
                consensus_manager
                    .start(
                        &config,
                        epoch_store,
                        consensus_handler_initializer,
                        sui_tx_validator,
                    )
                    .await;
            }
        });
        let replay_waiter = consensus_manager.replay_waiter();

        // Spawn the dWallet MPC Service now that we are done with bootstrapping both
        // from storage and from the consensus.
        spawn_monitored_task!(dwallet_mpc_service.spawn(replay_waiter));

        Ok(ValidatorComponents {
            consensus_manager,
            consensus_store_pruner,
            consensus_adapter,
            checkpoint_service_tasks,
            system_checkpoint_service_tasks,
            checkpoint_metrics: dwallet_checkpoint_metrics,
            system_checkpoint_metrics,
            ika_tx_validator_metrics,
            dwallet_mpc_metrics,
            dwallet_mpc_service_exit: dwallet_mpc_service_exit_sender,
        })
    }

    fn start_dwallet_checkpoint_service(
        config: &NodeConfig,
        consensus_adapter: Arc<ConsensusAdapter>,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        state: Arc<AuthorityState>,
        state_sync_handle: state_sync::Handle,
        checkpoint_metrics: Arc<DWalletCheckpointMetrics>,
        previous_epoch_last_dwallet_checkpoint_sequence_number: u64,
    ) -> Option<(Arc<DWalletCheckpointService>, JoinSet<()>)> {
        if !epoch_store.protocol_config().bls_checkpoints() {
            info!("BLS checkpoints disabled, skipping DWallet checkpoint service");
            return None;
        }

        let epoch_start_timestamp_ms = epoch_store.epoch_start_state().epoch_start_timestamp_ms();
        let epoch_duration_ms = epoch_store.epoch_start_state().epoch_duration_ms();

        debug!(
            "Starting checkpoint service with epoch start timestamp {}
            and epoch duration {}",
            epoch_start_timestamp_ms, epoch_duration_ms
        );

        let checkpoint_output: Box<dyn DWalletCheckpointOutputTrait> =
            Box::new(SubmitDWalletCheckpointToConsensus {
                sender: consensus_adapter,
                signer: state.secret.clone(),
                authority: config.protocol_public_key(),
                metrics: checkpoint_metrics.clone(),
            });

        let certified_checkpoint_output: Option<Box<dyn CertifiedDWalletCheckpointMessageOutput>> =
            Some(Box::new(SendDWalletCheckpointToStateSync::new(
                state_sync_handle,
            )));

        let max_tx_per_checkpoint = max_tx_per_checkpoint(epoch_store.protocol_config());
        let max_dwallet_checkpoint_size_bytes = epoch_store
            .protocol_config()
            .max_dwallet_checkpoint_size_bytes()
            as usize;

        Some(DWalletCheckpointService::spawn(
            state.clone(),
            dwallet_checkpoint_store,
            epoch_store,
            checkpoint_output,
            certified_checkpoint_output,
            checkpoint_metrics,
            max_tx_per_checkpoint,
            max_dwallet_checkpoint_size_bytes,
            previous_epoch_last_dwallet_checkpoint_sequence_number,
        ))
    }

    fn start_system_checkpoint_service(
        config: &NodeConfig,
        consensus_adapter: Arc<ConsensusAdapter>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        state: Arc<AuthorityState>,
        state_sync_handle: state_sync::Handle,
        system_checkpoint_metrics: Arc<SystemCheckpointMetrics>,
        previous_epoch_last_system_checkpoint_sequence_number: u64,
    ) -> Option<(Arc<SystemCheckpointService>, JoinSet<()>)> {
        if !epoch_store.protocol_config().bls_checkpoints() {
            info!("BLS checkpoints disabled, skipping System checkpoint service");
            return None;
        }

        let epoch_start_timestamp_ms = epoch_store.epoch_start_state().epoch_start_timestamp_ms();
        let epoch_duration_ms = epoch_store.epoch_start_state().epoch_duration_ms();

        debug!(
            "Starting system_checkpoint service with epoch start timestamp {}
            and epoch duration {}",
            epoch_start_timestamp_ms, epoch_duration_ms
        );

        let system_checkpoint_output: Box<dyn SystemCheckpointOutputTrait> =
            Box::new(SubmitSystemCheckpointToConsensus {
                sender: consensus_adapter,
                signer: state.secret.clone(),
                authority: config.protocol_public_key(),
                metrics: system_checkpoint_metrics.clone(),
            });

        let certified_system_checkpoint_output: Option<Box<dyn CertifiedSystemCheckpointOutput>> =
            Some(Box::new(SendSystemCheckpointToStateSync::new(
                state_sync_handle,
            )));

        let max_tx_per_system_checkpoint = epoch_store
            .protocol_config()
            .max_messages_per_system_checkpoint();
        let max_system_checkpoint_size_bytes = epoch_store
            .protocol_config()
            .max_system_checkpoint_size_bytes()
            as usize;

        Some(SystemCheckpointService::spawn(
            state.clone(),
            system_checkpoint_store,
            epoch_store,
            system_checkpoint_output,
            certified_system_checkpoint_output,
            system_checkpoint_metrics,
            max_tx_per_system_checkpoint as usize,
            max_system_checkpoint_size_bytes,
            previous_epoch_last_system_checkpoint_sequence_number,
        ))
    }

    fn construct_consensus_adapter(
        committee: &Committee,
        consensus_config: &ConsensusConfig,
        authority: AuthorityName,
        connection_monitor_status: Arc<ConnectionMonitorStatus>,
        prometheus_registry: &Registry,
        protocol_config: ProtocolConfig,
        consensus_client: Arc<dyn ConsensusClient>,
    ) -> ConsensusAdapter {
        let ca_metrics = ConsensusAdapterMetrics::new(prometheus_registry);
        // The consensus adapter allows the authority to send user certificates through consensus.

        ConsensusAdapter::new(
            consensus_client,
            authority,
            connection_monitor_status,
            consensus_config.max_pending_transactions(),
            consensus_config.max_pending_transactions() * 2 / committee.num_members(),
            consensus_config.max_submit_position,
            consensus_config.submit_delay_step_override(),
            ca_metrics,
            protocol_config,
        )
    }

    pub fn state(&self) -> Arc<AuthorityState> {
        self.state.clone()
    }

    pub fn clone_committee_store(&self) -> Arc<CommitteeStore> {
        self.state.committee_store().clone()
    }

    /*
    pub fn clone_authority_store(&self) -> Arc<AuthorityStore> {
        self.state.db()
    }
    */

    /// This function awaits the completion of checkpoint execution of the current epoch,
    /// after which it initiates reconfiguration of the entire system.
    pub async fn monitor_reconfiguration(
        self: Arc<Self>,
        sui_client: Arc<SuiConnectorClient>,
        dwallet_mpc_metrics: Arc<DWalletMPCMetrics>,
        sui_data_receivers: SuiDataReceivers,
    ) -> Result<()> {
        loop {
            let run_with_range = self.config.run_with_range;

            let cur_epoch_store = self.state.load_epoch_store_one_call_per_task();

            let config = cur_epoch_store.protocol_config();

            // Update the current protocol version metric.
            self.metrics
                .current_protocol_version
                .set(config.version.as_u64() as i64);

            let transaction =
                ConsensusTransaction::new_capability_notification_v1(AuthorityCapabilitiesV1::new(
                    self.state.name,
                    cur_epoch_store.get_chain_identifier().chain(),
                    self.config
                        .supported_protocol_versions
                        .expect("Supported versions should be populated")
                        // no need to send digests of versions less than the current version
                        .truncate_below(config.version),
                    vec![],
                    // Note: this is a temp fix, we will handle package upgrades later.
                    // sui_client
                    // .get_available_move_packages()
                    //     .await
                    //     .map_err(|e| anyhow!("Cannot get available move packages: {:?}", e))?,
                ));

            if let Some(components) = &*self.validator_components.lock().await {
                info!(?transaction, "submitting capabilities to consensus");
                components
                    .consensus_adapter
                    .submit_to_consensus(&[transaction], &cur_epoch_store)
                    .await?;
            }

            // Off-chain validator-metadata pipeline gate. When the
            // protocol config flag is off, skip every install/spawn
            // below — handoff signing, mpc_data announcements,
            // joiner relay, pubkey updaters, syncer overlay sources.
            // The tasks themselves also self-gate at the top of
            // `run()`, but checking once here avoids the spawn churn.
            let off_chain_metadata_enabled = cur_epoch_store
                .protocol_config()
                .off_chain_validator_metadata_enabled();

            let (end_of_publish_sender_handle, handoff_signature_sender_handle) = if let Some(
                components,
            ) =
                &*self.validator_components.lock().await
            {
                let end_of_publish_sender = EndOfPublishSender::new(
                    Arc::downgrade(&cur_epoch_store),
                    Arc::new(components.consensus_adapter.clone()),
                    sui_data_receivers.end_of_publish_receiver.clone(),
                    cur_epoch_store.epoch(),
                );
                let end_of_publish_handle = Some(tokio::spawn(async move {
                    end_of_publish_sender.run().await;
                }));

                let handoff_handle = if off_chain_metadata_enabled {
                    let consensus_keypair = Arc::new(self.config.consensus_key_pair().copy());
                    let builders = ika_core::validator_metadata::default_handoff_items_builders(
                        &cur_epoch_store,
                    );
                    let handoff_sender =
                        ika_core::epoch_tasks::handoff_signature_sender::HandoffSignatureSender::new(
                            Arc::downgrade(&cur_epoch_store),
                            cur_epoch_store.epoch(),
                            Arc::new(components.consensus_adapter.clone()),
                            sui_data_receivers.end_of_publish_receiver.clone(),
                            consensus_keypair,
                            sui_data_receivers.next_epoch_committee_receiver.clone(),
                            sui_data_receivers.network_keys_receiver.clone(),
                            builders,
                        );
                    Some(tokio::spawn(async move {
                        handoff_sender.run().await;
                    }))
                } else {
                    None
                };

                (end_of_publish_handle, handoff_handle)
            } else {
                (None, None)
            };

            // Producer-side broadcaster: announces this validator's
            // own mpc_data and ready signals so the freeze quorum
            // can be reached. Without it, no validator publishes its
            // mpc_data digest and the off-chain freeze never lands,
            // which leaves the step-14 kickoff gate closed and stalls
            // network DKG / reconfig.
            let mpc_data_announcement_handle = if off_chain_metadata_enabled
                && let Some(components) = &*self.validator_components.lock().await
                && let Some(root_seed_kp) = self.config.root_seed_key_pair.as_ref()
            {
                let blob_cache = ika_core::blob_cache::BlobCache::new(
                    self.mpc_data_blob_store.clone(),
                    self.state.perpetual_tables(),
                );
                let sender = ika_core::epoch_tasks::mpc_data_announcement_sender::MpcDataAnnouncementSender::new(
                        Arc::downgrade(&cur_epoch_store),
                        cur_epoch_store.epoch(),
                        cur_epoch_store.name,
                        Arc::new(components.consensus_adapter.clone()),
                        blob_cache,
                        root_seed_kp.root_seed().clone(),
                        // Chain next-epoch committee (pre-assembly) for
                        // the freeze emit-gate — so the freeze waits for
                        // joiners that the assembled committee can't yet
                        // include (see SuiDataReceivers doc).
                        sui_data_receivers.chain_next_epoch_committee_receiver.clone(),
                    );
                let sender = Arc::new(sender);
                Some(tokio::spawn(async move {
                    sender.run().await;
                }))
            } else {
                None
            };

            // Consumer-side fetcher: pulls peer validators' mpc_data
            // blobs from their Anemo `GetMpcDataBlob` endpoint and
            // caches them locally so the off-chain validator-mpc_data
            // assembler can resolve every committee member without a
            // chain read.
            let peer_blob_fetcher_handle = if off_chain_metadata_enabled {
                let authority_names_to_peer_ids = cur_epoch_store
                    .epoch_start_state()
                    .get_authority_names_to_peer_ids();
                let blob_cache = ika_core::blob_cache::BlobCache::new(
                    self.mpc_data_blob_store.clone(),
                    self.state.perpetual_tables(),
                );
                let fetcher = ika_core::epoch_tasks::peer_blob_fetcher::PeerBlobFetcher::new(
                    Arc::downgrade(&cur_epoch_store),
                    cur_epoch_store.epoch(),
                    cur_epoch_store.name,
                    blob_cache,
                    self.p2p_network.clone(),
                    authority_names_to_peer_ids,
                    self.metrics.mpc_data_blob_fetch_total.clone(),
                );
                let fetcher = Arc::new(fetcher);
                Some(tokio::spawn(async move {
                    fetcher.run().await;
                }))
            } else {
                None
            };

            // Joiner bootstrap verification: a node that is a validator
            // this epoch (E) but was NOT in the prior committee (E-1) is
            // a true joiner. Its cross-epoch off-chain trust anchor is
            // the E-1 handoff cert (signed by the E-1 committee, pinning
            // the handoff into E). Fetch it from current-committee peers
            // and verify it (epoch-bound, prior committee, next-committee
            // pubkey-set hash). Surfaces a tampered/wrong bootstrap; does
            // not halt on failure.
            let joiner_bootstrap_handle = if off_chain_metadata_enabled
                && cur_epoch_store.epoch() >= 1
            {
                use ika_core::epoch_tasks::joiner_bootstrap_verifier::{
                    BootstrapOutcome, BootstrapRetryConfig, CertVerifier, JoinerBootstrapVerifier,
                    P2pHandoffCertSource, warn_bootstrap_inputs_unavailable,
                };
                use ika_core::sui_connector::pubkey_provider_updater::{
                    fetch_previous_committee, fetch_previous_committee_consensus_pubkeys,
                };
                use ika_core::validator_metadata::{
                    StaticConsensusPubkeyProvider, next_committee_pubkey_set,
                    verify_joiner_bootstrap_cert,
                };
                use ika_types::sui::epoch_start_system::{
                    EpochStartSystemTrait, EpochStartValidatorInfoTrait,
                };
                let current_epoch = cur_epoch_store.epoch();
                let prior_epoch = current_epoch - 1;
                let self_name = cur_epoch_store.name;
                let prior_committee = match self
                    .state
                    .committee_store()
                    .get_committee(&prior_epoch)
                    .ok()
                    .flatten()
                {
                    Some(committee) => Some(committee),
                    // A true joiner that never observed/persisted the prior
                    // epoch has no local committee for it, so the cross-epoch
                    // trust anchor (and the network-key blob install it gates)
                    // would be skipped — leaving the joiner's off-chain overlay
                    // permanently incomplete and wedging the epoch advance.
                    // Chain-read the prior committee from
                    // `validator_set.previous_committee` (the same source the
                    // bootstrap already chain-reads consensus pubkeys from) so
                    // bootstrap can still run.
                    None => match fetch_previous_committee(&sui_client, prior_epoch).await {
                        Ok(committee) => {
                            info!(
                                prior_epoch,
                                "prior committee absent locally; chain-read it for joiner \
                                 bootstrap from validator_set.previous_committee"
                            );
                            Some(Arc::new(committee))
                        }
                        Err(error) => {
                            warn!(
                                ?error,
                                prior_epoch,
                                "failed to chain-read the prior committee for joiner bootstrap"
                            );
                            None
                        }
                    },
                };
                let perpetual = self.state.perpetual_tables();
                // Every validator anchors the new epoch on the prior
                // epoch's handoff cert. A continuing validator that
                // crossed quorum already persisted it during E-1 — that
                // cert is re-verified before it anchors (a persisted cert
                // is never trusted blindly); anyone missing it (a joiner,
                // or a continuing validator that didn't observe quorum)
                // fetches + verifies + persists it here, so the
                // cross-epoch trust anchor is locally available for
                // network-key instantiation.
                let already_have_cert = perpetual
                    .get_certified_handoff_attestation(prior_epoch)
                    .ok()
                    .flatten()
                    .is_some();
                match prior_committee {
                    Some(prior_committee) => {
                        let is_joiner = !prior_committee.authority_exists(&self_name);
                        // Consensus pubkeys are fixed at registration, so
                        // the current epoch's active-validator set supplies
                        // the continuing prior-committee signers' keys.
                        // Members that have since departed the active set
                        // are resolved from chain inside the task below.
                        let current_consensus_pubkeys: Vec<_> = cur_epoch_store
                            .epoch_start_state()
                            .get_ika_validators()
                            .into_iter()
                            .map(|v| (v.authority_name(), v.get_consensus_pubkey()))
                            .collect();
                        let expected_next = next_committee_pubkey_set(cur_epoch_store.committee());
                        let peer_ids: Vec<anemo::PeerId> = cur_epoch_store
                            .epoch_start_state()
                            .get_authority_names_to_peer_ids()
                            .into_values()
                            .collect();
                        if already_have_cert {
                            info!(
                                current_epoch,
                                prior_epoch,
                                is_joiner,
                                "anchoring the new epoch on the locally-persisted prior-epoch \
                                 handoff cert (re-verifying it before it anchors)"
                            );
                        } else {
                            info!(
                                current_epoch,
                                prior_epoch,
                                is_joiner,
                                "anchoring the new epoch on the prior-epoch handoff cert \
                                 (not held locally; fetching + verifying from peers)"
                            );
                        }
                        let fetch_network = self.p2p_network.clone();
                        let source_network = self.p2p_network.clone();
                        let fetch_store = cur_epoch_store.clone();
                        let cert_perpetual = perpetual.clone();
                        let fail_closed_shutdown = self.shutdown_channel_tx.clone();
                        let bootstrap_sui_client = sui_client.clone();
                        let bootstrap_outcomes =
                            self.metrics.joiner_bootstrap_outcomes_total.clone();
                        Some(tokio::spawn(async move {
                            // Resolve the prior committee's consensus
                            // pubkeys for cert verification. Continuing
                            // members come from the current active set
                            // (already in hand); members that departed the
                            // active set since signing are chain-read by
                            // object id (their StakingPool persists), so a
                            // valid cert isn't wrongly Rejected under churn.
                            // Best-effort: on RPC failure proceed with the
                            // current set and let the retry loop re-attempt.
                            let mut consensus_pubkeys = current_consensus_pubkeys;
                            match fetch_previous_committee_consensus_pubkeys(&bootstrap_sui_client)
                                .await
                            {
                                Ok(prior) => consensus_pubkeys.extend(prior),
                                Err(e) => warn!(
                                    error = ?e,
                                    prior_epoch,
                                    "failed to chain-read prior-committee consensus pubkeys; \
                                     proceeding with the current active set only"
                                ),
                            }
                            let provider = Arc::new(StaticConsensusPubkeyProvider::from_iter(
                                consensus_pubkeys,
                            ));
                            let verify: CertVerifier = Arc::new(move |cert| {
                                verify_joiner_bootstrap_cert(
                                    cert,
                                    prior_epoch,
                                    &prior_committee,
                                    provider.as_ref(),
                                    expected_next.iter().copied(),
                                )
                            });
                            // Defense in depth — same policy as
                            // `prepare_handoff_anchor`: a persisted cert is
                            // ALWAYS re-verified before it anchors, so a
                            // tampered or corrupted local handoff-cert DB
                            // can't silently anchor the epoch. On a verified
                            // persisted cert, (re-)install the outputs it
                            // certifies (idempotent: digests already held
                            // locally skip the fetch) and skip the peer fetch.
                            // (When the cert vanished between the epoch-start
                            // check and this task, fall through to the peer
                            // fetch path below.)
                            if already_have_cert
                                && let Some(persisted) = cert_perpetual
                                    .get_certified_handoff_attestation(prior_epoch)
                                    .ok()
                                    .flatten()
                            {
                                match verify(&persisted) {
                                    Ok(()) => {
                                        let missing_outputs = install_joiner_network_key_outputs(
                                            &persisted,
                                            &fetch_network,
                                            &peer_ids,
                                            &fetch_store,
                                        )
                                        .await;
                                        if !missing_outputs.is_empty() {
                                            warn!(
                                                prior_epoch,
                                                missing_key_ids = ?missing_outputs,
                                                "could not fetch cert-matching network-key \
                                                 outputs for some keys from any peer; the \
                                                 prepare barrier will keep retrying"
                                            );
                                        }
                                        return;
                                    }
                                    Err(e) => {
                                        error!(
                                            prior_epoch,
                                            error = ?e,
                                            "the locally-persisted handoff cert FAILED \
                                             re-verification at epoch start — the local \
                                             handoff-cert DB is tampered or corrupted. \
                                             Halting the node (fail-closed) rather than \
                                             anchoring the epoch on an unverified cert."
                                        );
                                        let _ = fail_closed_shutdown.send(None);
                                        return;
                                    }
                                }
                            }
                            let source = Arc::new(P2pHandoffCertSource::new(
                                source_network,
                                peer_ids.clone(),
                            ));
                            let verifier = JoinerBootstrapVerifier::new(
                                prior_epoch,
                                source,
                                verify,
                                BootstrapRetryConfig {
                                    retry_interval: Duration::from_secs(10),
                                    max_attempts: 30,
                                },
                            );
                            match verifier.run().await {
                                BootstrapOutcome::Verified(cert) => {
                                    bootstrap_outcomes.with_label_values(&["verified"]).inc();
                                    // Persist the verified anchor so
                                    // network-key instantiation can read
                                    // it locally and this node can serve
                                    // it to peers still fetching.
                                    if let Err(e) = cert_perpetual
                                        .insert_certified_handoff_attestation(prior_epoch, &cert)
                                    {
                                        warn!(
                                            error = ?e,
                                            prior_epoch,
                                            "failed to persist bootstrap handoff cert"
                                        );
                                    }
                                    let missing_outputs = install_joiner_network_key_outputs(
                                        &cert,
                                        &fetch_network,
                                        &peer_ids,
                                        &fetch_store,
                                    )
                                    .await;
                                    if !missing_outputs.is_empty() {
                                        // One summary warn for the one-shot
                                        // bootstrap path (the per-key fetch
                                        // failures inside log at debug); the
                                        // prepare barrier keeps retrying.
                                        warn!(
                                            prior_epoch,
                                            missing_key_ids = ?missing_outputs,
                                            "joiner bootstrap could not fetch cert-matching \
                                             network-key outputs for some keys from any peer; \
                                             the prepare barrier will keep retrying"
                                        );
                                    }
                                }
                                BootstrapOutcome::Rejected => {
                                    bootstrap_outcomes.with_label_values(&["rejected"]).inc();
                                    // Fail-closed: peers served certs but
                                    // NONE verified against the prior
                                    // committee — a genuine cross-epoch
                                    // trust-anchor mismatch (a wrong
                                    // prior-committee view, or every
                                    // reachable peer serving certs for the
                                    // wrong committee — a possible eclipse).
                                    // A single bad peer can't cause this
                                    // (every peer is tried each round), so
                                    // refuse to participate on a broken
                                    // anchor: halt the node so an operator
                                    // investigates instead of silently
                                    // limping without a verified handoff.
                                    error!(
                                        prior_epoch,
                                        "cross-epoch bootstrap trust anchor REJECTED — \
                                         halting the node (fail-closed). Investigate a wrong \
                                         prior-committee view or peers serving certs for the \
                                         wrong committee (possible eclipse)."
                                    );
                                    let _ = fail_closed_shutdown.send(None);
                                }
                                // Benign: no peer served a cert within the
                                // attempt budget (propagation lag) — already
                                // logged inside `run()`; the anchor is merely
                                // unconfirmed, not contradicted.
                                BootstrapOutcome::Unavailable => {
                                    bootstrap_outcomes.with_label_values(&["unavailable"]).inc();
                                }
                            }
                        }))
                    }
                    None => {
                        warn_bootstrap_inputs_unavailable(
                            prior_epoch,
                            "prior committee not in committee store",
                        );
                        None
                    }
                }
            } else {
                None
            };

            // Installs a `JoinerPubkeyProvider` derived from the
            // next-epoch committee so the per-epoch store accepts
            // next-epoch (joiner) `ValidatorMpcDataAnnouncement`s
            // instead of silently dropping them.
            let joiner_pubkey_updater_handle = if off_chain_metadata_enabled {
                let updater = ika_core::sui_connector::pubkey_provider_updater::PubkeyProviderUpdater::new_for_next_epoch_committee(
                        Arc::downgrade(&cur_epoch_store),
                        cur_epoch_store.epoch(),
                        sui_client.clone(),
                    );
                let updater = Arc::new(updater);
                Some(tokio::spawn(async move {
                    updater.run().await;
                }))
            } else {
                None
            };

            // Install the off-chain blob overlay so the network-
            // keys sync task prefers locally-cached DKG /
            // reconfiguration output bytes (populated by the
            // producer cache) over the chain blobs. Replaces the
            // previous-epoch installation (if any); the `Weak`
            // adapter naturally expires when the per-epoch store
            // drops.
            if off_chain_metadata_enabled {
                self.sui_connector_service
                    .install_network_key_blob_source(Box::new(
                        ika_core::validator_metadata::EpochStoreBlobSource::new(Arc::downgrade(
                            &cur_epoch_store,
                        )),
                    ));

                // Install the off-chain validator-mpc_data assembler so
                // `sync_next_committee` builds the next `Committee`'s
                // class_groups_public_keys_and_proofs from validators'
                // own `mpc_data` announcements + the perpetual blob
                // store instead of refetching from chain. Falls back
                // to chain when the off-chain set is `Incomplete`.
                self.sui_connector_service.install_mpc_data_source(Box::new(
                    ika_core::validator_metadata::EpochStoreMpcDataSource::new(
                        Arc::downgrade(&cur_epoch_store),
                        self.state.perpetual_tables(),
                    ),
                ));

                // Install the joiner-announcement relay impl on the
                // Anemo `SubmitMpcDataAnnouncement` server so a peer
                // joiner's announcement gets verified locally and
                // forwarded into consensus instead of being rejected
                // with "relay not installed".
                if let Some(components) = &*self.validator_components.lock().await {
                    self.mpc_announcement_relay.install(Box::new(
                        ika_core::epoch_tasks::announcement_relay::ConsensusBackedAnnouncementRelay::new(
                            Arc::downgrade(&cur_epoch_store),
                            Arc::new(components.consensus_adapter.clone()),
                            ika_core::blob_cache::BlobCache::new(
                                self.mpc_data_blob_store.clone(),
                                self.state.perpetual_tables(),
                            ),
                        ),
                    ));
                }
            }

            // Installs a `ConsensusPubkeyProvider` from the current
            // committee's on-chain `consensus_pubkey_bytes` so the
            // per-epoch store can verify incoming
            // `HandoffSignatureMessage`s (otherwise every one drops
            // as `UnknownSigner`).
            let consensus_pubkey_updater_handle = if off_chain_metadata_enabled {
                let updater = ika_core::sui_connector::pubkey_provider_updater::PubkeyProviderUpdater::new_for_active_committee(
                        Arc::downgrade(&cur_epoch_store),
                        cur_epoch_store.epoch(),
                        sui_client.clone(),
                    );
                let updater = Arc::new(updater);
                Some(tokio::spawn(async move {
                    updater.run().await;
                }))
            } else {
                None
            };

            let stop_condition = self
                .sui_connector_service
                .run_epoch(cur_epoch_store.epoch(), run_with_range)
                .await;

            let (latest_system_state, epoch_start_system_state) = match stop_condition {
                StopReason::EpochComplete(latest_system_state, epoch_start_system_state) => {
                    info!(
                        epoch_number=?latest_system_state.epoch(),
                        "Epoch completed, switching to the next epoch"
                    );
                    (latest_system_state, epoch_start_system_state)
                }
                StopReason::RunWithRangeCondition => {
                    IkaNode::shutdown(&self).await;
                    self.shutdown_channel_tx
                        .send(run_with_range)
                        .expect("RunWithRangeCondition met but failed to send shutdown message");
                    return Ok(());
                }
            };
            end_of_publish_sender_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            handoff_signature_sender_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            mpc_data_announcement_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            joiner_pubkey_updater_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            peer_blob_fetcher_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            joiner_bootstrap_handle.map(|handle| {
                handle.abort();
                Some(())
            });
            consensus_pubkey_updater_handle.map(|handle| {
                handle.abort();
                Some(())
            });

            if let Err(err) = self.end_of_epoch_channel.send(*latest_system_state)
                && self.state.is_fullnode(&cur_epoch_store)
            {
                warn!(
                    "Failed to send the end-of-epoch notification to subscriber: {:?}",
                    err
                );
            }
            let (_, dwallet_coordinator_inner) =
                sui_client.must_get_dwallet_coordinator_inner().await;
            let DWalletCoordinatorInner::V1(dwallet_coordinator_inner) = dwallet_coordinator_inner;
            let previous_epoch_last_checkpoint_sequence_number =
                dwallet_coordinator_inner.previous_epoch_last_checkpoint_sequence_number;

            let (_, system_inner) = sui_client.must_get_system_inner_object().await;
            let previous_epoch_last_system_checkpoint_sequence_number =
                system_inner.previous_epoch_last_checkpoint_sequence_number();

            let next_epoch_committee = epoch_start_system_state.get_ika_committee();
            let next_epoch = next_epoch_committee.epoch();
            assert_eq!(cur_epoch_store.epoch() + 1, next_epoch);

            info!(
                next_epoch,
                "Finished executing all checkpoints in the epoch. About to reconfigure the system."
            );

            fail_point_async!("reconfig_delay");

            // We save the connection monitor status map regardless of validator / fullnode status
            // so that we don't need to restart the connection monitor every epoch.
            // Update the mappings that will be used by the consensus adapter if it exists or is
            // about to be created.
            let authority_names_to_peer_ids =
                epoch_start_system_state.get_authority_names_to_peer_ids();
            self.connection_monitor_status
                .update_mapping_for_epoch(authority_names_to_peer_ids);

            cur_epoch_store.record_epoch_reconfig_start_time_metric();

            let _ = send_trusted_peer_change(
                &self.config,
                &self.trusted_peer_change_tx,
                &epoch_start_system_state,
            );

            // The following code handles 4 different cases, depending on whether the node
            // was a validator in the previous epoch
            // and whether the node is a validator
            // in the new epoch.
            let new_validator_components = if let Some(ValidatorComponents {
                consensus_manager,
                consensus_store_pruner,
                consensus_adapter,
                mut checkpoint_service_tasks,
                mut system_checkpoint_service_tasks,
                checkpoint_metrics,
                system_checkpoint_metrics,
                ika_tx_validator_metrics,
                dwallet_mpc_metrics,
                dwallet_mpc_service_exit,
            }) = self.validator_components.lock().await.take()
            {
                info!("Reconfiguring the validator.");
                // Cancel the old dwallet checkpoint service & system checkpoint service tasks.
                // Waiting for checkpoint builder to finish gracefully is not possible, because it
                // may wait on transactions while consensus on peers have already shut down.
                checkpoint_service_tasks.abort_all();
                system_checkpoint_service_tasks.abort_all();

                if let Err(err) = dwallet_mpc_service_exit.send(()) {
                    warn!(error=?err, "failed to send exit signal to dwallet mpc service");
                }
                drop(dwallet_mpc_service_exit);

                while let Some(result) = checkpoint_service_tasks.join_next().await {
                    if let Err(err) = result {
                        if err.is_panic() {
                            std::panic::resume_unwind(err.into_panic());
                        }
                        warn!(error=?err, "error in checkpoint service task");
                    }
                }
                info!("DWallet checkpoint service has shut down.");

                while let Some(result) = system_checkpoint_service_tasks.join_next().await {
                    if let Err(err) = result {
                        if err.is_panic() {
                            std::panic::resume_unwind(err.into_panic());
                        }
                        warn!("Error in system_checkpoint service task: {:?}", err);
                    }
                }
                info!("System checkpoint service was shut down");

                consensus_manager.shutdown().await;
                info!("Consensus was shut down");

                let new_epoch_store = self
                    .reconfigure_state(
                        &cur_epoch_store,
                        next_epoch_committee.clone(),
                        epoch_start_system_state,
                    )
                    .await;
                info!("Epoch store finished reconfiguration.");

                consensus_store_pruner.prune(next_epoch).await;

                // Prepare-then-start barrier. Block here until the full
                // verified handoff data for the epoch we are entering is
                // locally present, THEN start the epoch's MPC components.
                // Otherwise the components start while network-key handoff
                // data is still arriving asynchronously, and epoch-N sign
                // rounds run against STALE (epoch N-1) network-key shares,
                // failing with `FailedToAdvanceMPC(InvalidParameters)`.
                //
                // Readiness is decided off the verified handoff cert + this
                // validator's local reconfiguration-output digest slice (see
                // `wait_for_handoff_data_ready`), so the barrier needs no
                // blob-source overlay pre-install here — the per-iteration
                // install (~line 1991) handles the syncer overlay in the
                // next loop iteration as before.
                //
                // Only a validator in the NEW epoch needs the handoff data,
                // so only it prepares. A node leaving the committee
                // (validator last epoch, not this one) must not block on
                // handoff data it will never use.
                if self.state.is_validator(&new_epoch_store) {
                    self.wait_for_handoff_data_ready(
                        next_epoch,
                        cur_epoch_store.epoch(),
                        &cur_epoch_store,
                        &new_epoch_store,
                    )
                    .await;
                }

                if self.state.is_validator(&new_epoch_store) {
                    // Only restart consensus if this node is still a validator in the new epoch.
                    Some(
                        Self::start_epoch_specific_validator_components(
                            &self.config,
                            self.state.clone(),
                            consensus_adapter,
                            self.dwallet_checkpoint_store.clone(),
                            self.system_checkpoint_store.clone(),
                            new_epoch_store.clone(),
                            self.state_sync_handle.clone(),
                            consensus_manager,
                            consensus_store_pruner,
                            checkpoint_metrics,
                            dwallet_mpc_metrics,
                            system_checkpoint_metrics,
                            self.metrics.clone(),
                            ika_tx_validator_metrics,
                            previous_epoch_last_checkpoint_sequence_number,
                            previous_epoch_last_system_checkpoint_sequence_number,
                            sui_data_receivers.clone(),
                            self.noa_dwallet_finalized.clone(),
                            self.noa_system_finalized.clone(),
                        )
                        .await?,
                    )
                } else {
                    info!("This node is no longer a validator after reconfiguration");
                    None
                }
            } else {
                let new_epoch_store = self
                    .reconfigure_state(
                        &cur_epoch_store,
                        next_epoch_committee.clone(),
                        epoch_start_system_state,
                    )
                    .await;

                if self.state.is_validator(&new_epoch_store) {
                    info!("Promoting the node from fullnode to validator, starting grpc server");

                    Some(
                        Self::construct_validator_components(
                            self.config.clone(),
                            self.state.clone(),
                            Arc::new(next_epoch_committee.clone()),
                            new_epoch_store.clone(),
                            self.dwallet_checkpoint_store.clone(),
                            self.system_checkpoint_store.clone(),
                            self.state_sync_handle.clone(),
                            self.connection_monitor_status.clone(),
                            &self.registry_service,
                            self.metrics.clone(),
                            previous_epoch_last_checkpoint_sequence_number,
                            previous_epoch_last_system_checkpoint_sequence_number,
                            dwallet_mpc_metrics.clone(),
                            sui_data_receivers.clone(),
                            self.noa_dwallet_finalized.clone(),
                            self.noa_system_finalized.clone(),
                        )
                        .await?,
                    )
                } else {
                    None
                }
            };
            *self.validator_components.lock().await = new_validator_components;
            // Force releasing the current epoch store DB handle, because the
            // Arc<AuthorityPerEpochStore> may linger.
            cur_epoch_store.release_db_handles();

            // Only after the handles release is dropping epoch dirs safe in
            // every configuration; with the default retention (>0) the
            // pruned dirs are older still.
            self.authority_store_pruner.prune(next_epoch).await;

            info!("Reconfiguration finished, sending exit signal");
        }
    }

    async fn shutdown(&self) {
        if let Some(validator_components) = &*self.validator_components.lock().await {
            validator_components.consensus_manager.shutdown().await;
        }
    }

    async fn reconfigure_state(
        &self,
        cur_epoch_store: &AuthorityPerEpochStore,
        next_epoch_committee: Committee,
        next_epoch_start_system_state: EpochStartSystem,
    ) -> Arc<AuthorityPerEpochStore> {
        let next_epoch = next_epoch_committee.epoch();

        let epoch_start_configuration = EpochStartConfiguration::new(next_epoch_start_system_state)
            .expect("EpochStartConfiguration construction cannot fail");

        let new_epoch_store = self
            .state
            .reconfigure(
                cur_epoch_store,
                self.config.supported_protocol_versions.unwrap(),
                next_epoch_committee,
                epoch_start_configuration,
            )
            .await
            .expect("Reconfigure authority state cannot fail");
        info!(next_epoch, "Node State has been reconfigured");
        assert_eq!(next_epoch, new_epoch_store.epoch());

        new_epoch_store
    }

    /// Ensures the cross-epoch trust anchor for the epoch we are entering
    /// is locally present + verified, fetching it inline if it is not.
    ///
    /// Every validator anchors the epoch it enters (`anchor_epoch + 1`) on
    /// the `anchor_epoch` handoff cert — the cert the `anchor_epoch`
    /// committee produced, pinning the handoff into `anchor_epoch + 1` (it
    /// certifies the network-key output digests the new epoch inherits and
    /// binds the hash of the new committee's pubkey set). A continuing
    /// validator that crossed quorum at `anchor_epoch`'s EndOfPublish has
    /// already persisted this cert; for anyone missing it (a joiner, or a
    /// continuing validator that didn't observe quorum) it must be
    /// fetched + verified + persisted here.
    ///
    /// This is the synchronous, inline-awaited sibling of the
    /// `joiner_bootstrap_handle` task spawned at epoch start: that task
    /// anchors the *prior* epoch and runs in the *next* loop iteration,
    /// which is too late for the prepare-then-start barrier at the
    /// reconfigure seam (the barrier would deadlock waiting on a cert that
    /// nothing fetches until after the barrier). So the barrier calls this
    /// directly for `anchor_epoch = cur_epoch`.
    ///
    /// `anchor_epoch` here is the *current* epoch, so the committee that
    /// signed the cert is the one we are still in (`cur_epoch_store`'s
    /// committee) and whose consensus pubkeys come from the current active
    /// validator set — no chain read of a departed prior committee is
    /// needed (unlike the prior-epoch joiner-bootstrap path).
    ///
    /// REDUNDANT VERIFICATION (defense in depth): a handoff cert is
    /// verified TWICE in its lifetime. The first verification is in the
    /// bootstrap fetch path, before the cert is ever written to the local
    /// DB. The second is HERE, when the cert is *consumed* to anchor the
    /// new epoch — a persisted cert is ALWAYS re-verified against the
    /// signing committee before it is allowed to anchor, so a corrupted or
    /// tampered local handoff-cert DB cannot silently anchor an epoch on a
    /// cert that no longer verifies. The same `verify` closure backs both
    /// the persisted-cert re-check and the fetch path's per-candidate
    /// verification.
    ///
    /// Returns `Some(cert)` — the verified anchor cert — iff one is locally
    /// present afterward, so the caller can read the output digests it
    /// certifies without a second DB read. Returns `None` when the anchor
    /// is not yet confirmed (no peer served a cert within the attempt
    /// budget — propagation lag, re-attempt) OR after fail-closing (halts
    /// the node via the shutdown channel) when a persisted cert fails
    /// re-verification (tampered/corrupted DB), or when peers served certs
    /// but none verified against the signing committee — a genuine
    /// cross-epoch trust-anchor mismatch (a possible eclipse), not
    /// something to limp past.
    async fn prepare_handoff_anchor(
        &self,
        anchor_epoch: EpochId,
        cur_epoch_store: &AuthorityPerEpochStore,
        new_epoch_store: &Arc<AuthorityPerEpochStore>,
    ) -> Option<CertifiedHandoffAttestation> {
        use ika_core::epoch_tasks::joiner_bootstrap_verifier::{
            BootstrapOutcome, BootstrapRetryConfig, CertVerifier, JoinerBootstrapVerifier,
            P2pHandoffCertSource,
        };
        use ika_core::validator_metadata::{
            StaticConsensusPubkeyProvider, next_committee_pubkey_set, verify_joiner_bootstrap_cert,
        };
        use ika_types::sui::epoch_start_system::{
            EpochStartSystemTrait, EpochStartValidatorInfoTrait,
        };

        // Build the verification closure FIRST so it can re-verify a
        // persisted cert as well as back the fetch path. The signing
        // committee is the one we are still in: `anchor_epoch` is
        // `cur_epoch`, and `cur_epoch_store.committee()` is exactly that
        // committee. Its members' consensus pubkeys are fixed at
        // registration and are in the current active validator set.
        let signing_committee = cur_epoch_store.committee().as_ref().clone();
        let consensus_pubkeys: Vec<_> = cur_epoch_store
            .epoch_start_state()
            .get_ika_validators()
            .into_iter()
            .map(|v| (v.authority_name(), v.get_consensus_pubkey()))
            .collect();
        // The cert pins the hash of the committee being handed into —
        // the epoch we are entering, whose committee is `new_epoch_store`'s.
        let expected_next = next_committee_pubkey_set(new_epoch_store.committee());
        let peer_ids: Vec<anemo::PeerId> = cur_epoch_store
            .epoch_start_state()
            .get_authority_names_to_peer_ids()
            .into_values()
            .collect();

        let provider = Arc::new(StaticConsensusPubkeyProvider::from_iter(consensus_pubkeys));
        let verify: CertVerifier = Arc::new(move |cert| {
            verify_joiner_bootstrap_cert(
                cert,
                anchor_epoch,
                &signing_committee,
                provider.as_ref(),
                expected_next.iter().copied(),
            )
        });

        // SECOND verification (the first was before this cert was written
        // to the DB in the bootstrap path): a persisted cert must NOT
        // silently anchor an epoch — re-verify it now. A tampered or
        // corrupted local handoff-cert DB fails here and fail-closes
        // rather than anchoring the new epoch on a cert that no longer
        // verifies against the signing committee.
        if let Some(persisted) = new_epoch_store
            .get_certified_handoff_attestation(anchor_epoch)
            .ok()
            .flatten()
        {
            return match verify(&persisted) {
                Ok(()) => {
                    // Holding the cert does NOT imply holding the network-key
                    // outputs it certifies: a lagging validator can adopt the
                    // cert from a buffered peer-signature quorum (see
                    // `quorum_attestation_in_buffer`) without ever computing or
                    // caching those outputs. The barrier's condition 2 requires
                    // every certified reconfiguration output held locally, so
                    // fetch + cache them now (idempotent — a no-op when already
                    // present). Without this a cert-but-no-outputs validator
                    // blocks at the barrier forever, never enters the epoch, and
                    // never publishes its mpc_data — wedging the next
                    // reconfiguration's committee assembly at sub-full coverage.
                    install_joiner_network_key_outputs(
                        &persisted,
                        &self.p2p_network,
                        &peer_ids,
                        new_epoch_store,
                    )
                    .await;
                    Some(persisted)
                }
                Err(e) => {
                    error!(
                        anchor_epoch,
                        error = ?e,
                        "prepare-then-start: the locally-persisted handoff cert FAILED \
                         re-verification — the local handoff-cert DB is tampered or corrupted. \
                         Halting the node (fail-closed) rather than anchoring the epoch on an \
                         unverified cert."
                    );
                    let _ = self.shutdown_channel_tx.send(None);
                    None
                }
            };
        }

        // Absent from the DB — fetch + verify + persist + install.
        info!(
            anchor_epoch,
            "prepare-then-start: anchor cert for the epoch being entered is not held locally; \
             fetching + verifying it inline from peers before starting MPC"
        );

        let source = Arc::new(P2pHandoffCertSource::new(
            self.p2p_network.clone(),
            peer_ids.clone(),
        ));
        let verifier = JoinerBootstrapVerifier::new(
            anchor_epoch,
            source,
            verify,
            BootstrapRetryConfig {
                retry_interval: Duration::from_secs(10),
                max_attempts: 30,
            },
        );

        match verifier.run().await {
            BootstrapOutcome::Verified(cert) => {
                self.metrics
                    .joiner_bootstrap_outcomes_total
                    .with_label_values(&["verified"])
                    .inc();
                // Persist the verified anchor so network-key
                // instantiation can read it locally and this node can
                // serve it to peers still fetching.
                if let Err(e) = self
                    .state
                    .perpetual_tables()
                    .insert_certified_handoff_attestation(anchor_epoch, &cert)
                {
                    warn!(error = ?e, anchor_epoch, "failed to persist anchor handoff cert");
                }
                install_joiner_network_key_outputs(
                    &cert,
                    &self.p2p_network,
                    &peer_ids,
                    new_epoch_store,
                )
                .await;
                Some(*cert)
            }
            BootstrapOutcome::Rejected => {
                self.metrics
                    .joiner_bootstrap_outcomes_total
                    .with_label_values(&["rejected"])
                    .inc();
                // Fail-closed: peers served certs but NONE verified
                // against the signing committee — a genuine cross-epoch
                // trust-anchor mismatch (a wrong committee view, or every
                // reachable peer serving certs for the wrong committee, a
                // possible eclipse). Refuse to participate on a broken
                // anchor: halt so an operator investigates rather than
                // silently entering the epoch on an unverified handoff.
                error!(
                    anchor_epoch,
                    "prepare-then-start: cross-epoch anchor REJECTED — halting the node \
                     (fail-closed). Investigate a wrong committee view or peers serving certs \
                     for the wrong committee (possible eclipse)."
                );
                let _ = self.shutdown_channel_tx.send(None);
                None
            }
            // No peer served a cert within the attempt budget
            // (propagation lag) — the anchor is unconfirmed, not
            // contradicted. The barrier will re-attempt.
            BootstrapOutcome::Unavailable => {
                self.metrics
                    .joiner_bootstrap_outcomes_total
                    .with_label_values(&["unavailable"])
                    .inc();
                None
            }
        }
    }

    /// Prepare-then-start barrier: blocks until the full handoff data for
    /// the epoch being entered (`next_epoch`) is locally present AND
    /// verified, then returns so the new epoch's MPC components may start.
    ///
    /// WHY THIS EXISTS: without it, the new epoch's MPC components start
    /// immediately at the reconfigure seam while the network-key handoff
    /// data still arrives asynchronously. A validator can then begin
    /// epoch-N signing with STALE (epoch N-1) network-key shares, and
    /// threshold sign rounds fail with `FailedToAdvanceMPC(InvalidParameters)`.
    /// Starting the epoch stale is never acceptable, so this blocks
    /// INDEFINITELY (no timeout): a stuck validator that is visibly not
    /// signing is strictly safer than one signing with the wrong shares.
    ///
    /// The barrier waits on two conditions, both grounded in off-chain data
    /// (the verified handoff cert + this validator's local outputs) — no
    /// chain state, and no dependency on the chain-fed `network_keys_receiver`:
    ///   1. The cross-epoch trust anchor (the `cur_epoch` handoff cert) is
    ///      locally present + verified — `prepare_handoff_anchor` returns it,
    ///      fetching it inline if missing.
    ///   2. Every `NetworkReconfigurationOutput` item the cert certifies is
    ///      held locally with a digest matching the cert. The cert's single
    ///      `epoch` field scopes the whole handoff, so there is no per-key
    ///      epoch to check — only per-key presence in this validator's
    ///      reconfiguration-output digest slice (keyed by `cur_epoch`, the
    ///      reconfiguration session's epoch). A continuing validator caches
    ///      its own MPC output there; a joiner has `prepare_handoff_anchor`
    ///      fetch + cache the cert's outputs into the same slice. See
    ///      `all_cert_reconfiguration_outputs_held_locally`.
    async fn wait_for_handoff_data_ready(
        &self,
        next_epoch: EpochId,
        cur_epoch: EpochId,
        cur_epoch_store: &AuthorityPerEpochStore,
        new_epoch_store: &Arc<AuthorityPerEpochStore>,
    ) {
        // Off-chain handoff is the only thing this barrier waits for; when
        // the protocol flag is off (pre-v4) there is no off-chain handoff
        // data to wait for, so skip the barrier entirely.
        if !cur_epoch_store
            .protocol_config()
            .off_chain_validator_metadata_enabled()
        {
            return;
        }

        info!(
            next_epoch,
            "prepare-then-start: awaiting full verified handoff data for epoch {next_epoch} \
             before starting MPC"
        );
        self.metrics.handoff_prepare_waiting.set(1);
        let started_at = std::time::Instant::now();
        let mut retries: u64 = 0;

        // The verified anchor is obtained ONCE and reused across iterations:
        // the cert is immutable for the epoch, so re-fetching/re-verifying its
        // committee signatures every second would be pure waste (and on the
        // fetch path, a per-second P2P hammering of converging peers).
        let mut anchor_cert: Option<CertifiedHandoffAttestation> = None;
        loop {
            // Condition 1: the cross-epoch trust anchor — the `cur_epoch`
            // handoff cert — is present + verified. `prepare_handoff_anchor`
            // returns it (re-verified) when already held, fetches + verifies
            // + persists it inline when missing, and also fetches + caches
            // the certified outputs this node is missing into the local
            // digest slice condition 2 reads. `None` means the anchor is not
            // yet confirmed (propagation lag) — re-attempt next iteration.
            if anchor_cert.is_none() {
                anchor_cert = self
                    .prepare_handoff_anchor(cur_epoch, cur_epoch_store, new_epoch_store)
                    .await;
            }
            let cert = anchor_cert.as_ref();

            // Condition 2: every network-key reconfiguration output the cert
            // certifies is held locally with a digest matching the cert.
            // Grounded entirely in the verified cert (the off-chain anchor)
            // and this validator's own reconfiguration-output digest slice,
            // keyed by the reconfiguration session's epoch (`cur_epoch`) — no
            // chain state, and no per-key epoch (the cert's single epoch
            // scopes the whole handoff). A read error is treated as not-ready
            // (empty slice); the periodic WARN below surfaces a persistent
            // failure.
            let local_reconfiguration_digests = cur_epoch_store
                .get_network_reconfiguration_output_digests_for_epoch(cur_epoch)
                .unwrap_or_default();
            let ready = cert.is_some_and(|cert| {
                all_cert_reconfiguration_outputs_held_locally(cert, &local_reconfiguration_digests)
            });

            if ready {
                let elapsed = started_at.elapsed();
                self.metrics.handoff_prepare_waiting.set(0);
                self.metrics
                    .handoff_prepare_duration_seconds
                    .observe(elapsed.as_secs_f64());
                info!(
                    next_epoch,
                    "prepare-then-start: epoch {next_epoch} handoff data ready+verified after \
                     {}s, {retries} retries; starting MPC",
                    elapsed.as_secs()
                );
                return;
            }

            retries += 1;
            self.metrics.handoff_prepare_retries_total.inc();

            // Anchor held but some certified output still missing locally:
            // retry fetching JUST the missing ones (the local-presence
            // precheck inside skips everything already held, so this is not
            // a refetch of held blobs).
            if let Some(cert) = cert {
                let peer_ids: Vec<anemo::PeerId> = cur_epoch_store
                    .epoch_start_state()
                    .get_authority_names_to_peer_ids()
                    .into_values()
                    .collect();
                install_joiner_network_key_outputs(
                    cert,
                    &self.p2p_network,
                    &peer_ids,
                    new_epoch_store,
                )
                .await;
            }

            // Surface the breakdown roughly every 10s so a hang is never
            // silent on a dashboard or in the logs.
            if retries.is_multiple_of(10) {
                let (cert_reconfiguration_items, missing_key_ids) = match &cert {
                    Some(cert) => {
                        let total = cert
                            .attestation
                            .items
                            .iter()
                            .filter(|(item, _)| {
                                matches!(item, HandoffItemKey::NetworkReconfigurationOutput { .. })
                            })
                            .count();
                        let missing: Vec<ObjectID> = cert
                            .attestation
                            .items
                            .iter()
                            .filter_map(|(item, digest)| match item {
                                HandoffItemKey::NetworkReconfigurationOutput { key_id }
                                    if local_reconfiguration_digests.get(key_id)
                                        != Some(digest) =>
                                {
                                    Some(*key_id)
                                }
                                _ => None,
                            })
                            .collect();
                        (total, missing)
                    }
                    None => (0, Vec::new()),
                };
                warn!(
                    next_epoch,
                    cur_epoch,
                    have_cert = cert.is_some(),
                    cert_reconfiguration_items,
                    missing_locally = missing_key_ids.len(),
                    missing_key_ids = ?missing_key_ids,
                    retries,
                    "prepare-then-start: still awaiting full verified handoff data for epoch \
                     {next_epoch}"
                );
            }

            // Re-check after 1s. No timeout — block indefinitely
            // (safety-first: never start the epoch without the verified
            // handoff outputs the cert certifies).
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub fn get_config(&self) -> &NodeConfig {
        &self.config
    }
}

#[cfg(msim)]
impl IkaNode {
    pub fn get_sim_node_id(&self) -> sui_simulator::task::NodeId {
        self.sim_state.sim_node.id()
    }

    pub fn set_safe_mode_expected(&self, new_value: bool) {
        info!("Setting safe mode expected to {}", new_value);
        self.sim_state
            .sim_safe_mode_expected
            .store(new_value, Ordering::Relaxed);
    }
}

/// A freshly-active joiner never computed this epoch's network-key
/// outputs — it wasn't in the committee that produced them, so it
/// *receives* them. After its bootstrap cert verifies, fetch each DKG /
/// reconfiguration output the cert certifies from current-committee
/// peers (by the cert's item digest), verify the returned bytes against
/// that digest (the serving peer is untrusted and `fetch_blob` does not
/// check), and cache it locally so the node can instantiate the key.
/// Best-effort and idempotent — a content-addressed re-cache is a no-op.
///
/// Items whose certified output is ALREADY held locally (the local digest
/// equals the cert's) are skipped before any network I/O: a continuing
/// validator holds every output it computed, so without this precheck each
/// epoch boundary would re-download multi-MB blobs from peers that are
/// busy converging the same handoff.
///
/// Returns the key ids of certified outputs that could NOT be fetched and
/// installed this pass. Per-key fetch failures log at debug only — the
/// prepare barrier calls this every second of its 1s retry loop, so the
/// operator-facing stall signal is the barrier's own every-10th-retry warn
/// (which carries the missing key ids); one-shot callers (joiner bootstrap)
/// summarize the returned list themselves.
async fn install_joiner_network_key_outputs(
    cert: &CertifiedHandoffAttestation,
    network: &Network,
    peers: &[PeerId],
    epoch_store: &Arc<AuthorityPerEpochStore>,
) -> Vec<ObjectID> {
    let mut missing_key_ids: Vec<ObjectID> = Vec::new();
    let local_dkg_digests = epoch_store
        .get_network_dkg_output_digests()
        .unwrap_or_default();
    let local_reconfiguration_digests = epoch_store
        .get_network_reconfiguration_output_digests_for_epoch(cert.attestation.epoch)
        .unwrap_or_default();
    for (item_key, expected_digest) in &cert.attestation.items {
        let (key_id, is_reconfiguration) = match item_key {
            HandoffItemKey::NetworkDkgOutput { key_id } => (*key_id, false),
            HandoffItemKey::NetworkReconfigurationOutput { key_id } => (*key_id, true),
            HandoffItemKey::ValidatorMpcData { .. } => continue,
        };
        let held_locally = if is_reconfiguration {
            local_reconfiguration_digests.get(&key_id) == Some(expected_digest)
        } else {
            local_dkg_digests.get(&key_id) == Some(expected_digest)
        };
        if held_locally {
            continue;
        }
        let mut verified_bytes = None;
        for peer in peers {
            match fetch_blob(network, *peer, *expected_digest).await {
                Ok(Some(bytes)) => {
                    // `fetch_blob` trusts the serving peer; the network-key
                    // output digest is `Blake2b256`, identical to
                    // `mpc_data_blob_hash`, so re-derive and match against
                    // the cert's item digest before accepting the bytes.
                    if &mpc_data_blob_hash(&bytes) == expected_digest {
                        verified_bytes = Some(bytes);
                        break;
                    }
                    debug!(
                        ?key_id,
                        ?peer,
                        "network-key output blob from peer did not match the cert digest; ignoring"
                    );
                }
                Ok(None) => {}
                Err(e) => debug!(?key_id, error = %e, "network-key output fetch transport error"),
            }
        }
        let Some(bytes) = verified_bytes else {
            debug!(
                ?key_id,
                "could not fetch a cert-matching network-key output from any peer this pass"
            );
            missing_key_ids.push(key_id);
            continue;
        };
        let cached = if is_reconfiguration {
            // Key the digest under the epoch this cert attests — the
            // epoch whose reconfiguration output the cert certifies —
            // not the joiner's wall-clock epoch, matching the producer
            // side's session-epoch keying.
            epoch_store.cache_network_reconfiguration_output(key_id, cert.attestation.epoch, &bytes)
        } else {
            epoch_store.cache_network_dkg_output(key_id, &bytes)
        };
        if let Err(e) = cached {
            warn!(?key_id, error = ?e, "failed to cache fetched joiner network-key output");
            missing_key_ids.push(key_id);
        }
    }
    missing_key_ids
}

/// Notify state-sync that a new list of trusted peers are now available.
fn send_trusted_peer_change(
    config: &NodeConfig,
    sender: &watch::Sender<TrustedPeerChangeEvent>,
    epoch_state_state: &EpochStartSystem,
) -> Result<(), watch::error::SendError<TrustedPeerChangeEvent>> {
    sender
        .send(TrustedPeerChangeEvent {
            new_peers: epoch_state_state.get_validator_as_p2p_peers(config.protocol_public_key()),
        })
        .tap_err(|err| {
            warn!(
                "Failed to send validator peer information to state sync: {:?}",
                err
            );
        })
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Threshold {
    pub threshold_seconds: Option<u32>,
}

#[allow(unused)]
async fn health_check_handler(
    axum::extract::Query(Threshold { threshold_seconds }): axum::extract::Query<Threshold>,
    axum::Extension(state): axum::Extension<Arc<AuthorityState>>,
) -> impl axum::response::IntoResponse {
    if let Some(threshold_seconds) = threshold_seconds {
        // Attempt to get the latest checkpoint
        let summary = match state
            .get_checkpoint_store()
            .get_highest_executed_dwallet_checkpoint()
        {
            Ok(Some(summary)) => summary,
            Ok(None) => {
                warn!("Highest executed checkpoint not found");
                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down");
            }
            Err(err) => {
                warn!("Failed to retrieve highest executed checkpoint: {:?}", err);
                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down");
            }
        };

        // // Calculate the threshold time based on the provided threshold_seconds
        // let latest_chain_time = summary.timestamp();
        // let threshold =
        //     std::time::SystemTime::now() - Duration::from_secs(threshold_seconds as u64);
        //
        // // Check if the latest checkpoint is within the threshold
        // if latest_chain_time < threshold {
        //     warn!(
        //         ?latest_chain_time,
        //         ?threshold,
        //         "failing healthcheck due to checkpoint lag"
        //     );
        //     return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down");
        // }
    }
    // if health endpoint is responding and no threshold is given, respond success
    (axum::http::StatusCode::OK, "up")
}

#[cfg(not(test))]
fn max_tx_per_checkpoint(protocol_config: &ProtocolConfig) -> usize {
    protocol_config.max_messages_per_dwallet_checkpoint() as usize
}

#[cfg(test)]
fn max_tx_per_checkpoint(_: &ProtocolConfig) -> usize {
    2
}

/// Readiness predicate for the prepare-then-start barrier's network-key
/// condition, grounded entirely in the verified handoff cert (the off-chain
/// cross-epoch trust anchor) and this validator's local reconfiguration-output
/// digest slice — no chain state.
///
/// The cert's single `epoch` field scopes the whole handoff (one cert per
/// epoch, committee-signed), so there is no per-key epoch to check: every
/// `NetworkReconfigurationOutput` item is an output of the same reconfiguration
/// session (the one that ran during `cert.attestation.epoch`). The only per-key
/// question is presence: for each reconfiguration output the cert certifies,
/// has this validator locally computed/cached a digest-matching copy? (A
/// continuing validator caches its own MPC output; a joiner has
/// `install_joiner_network_key_outputs` fetch + cache the cert's outputs into
/// the same slice.)
///
/// Returns true iff every `NetworkReconfigurationOutput { key_id }` item in the
/// cert has a local digest equal to the cert's item digest. DKG and
/// validator-mpc_data items are not gated here — the barrier exists to keep the
/// new epoch from signing against a stale reconfiguration sharing, and the
/// reconfiguration output is the epoch-varying material. A cert with no
/// reconfiguration items is trivially ready on this condition.
fn all_cert_reconfiguration_outputs_held_locally(
    cert: &CertifiedHandoffAttestation,
    local_reconfiguration_digests: &BTreeMap<ObjectID, [u8; 32]>,
) -> bool {
    cert.attestation
        .items
        .iter()
        .all(|(item, cert_digest)| match item {
            HandoffItemKey::NetworkReconfigurationOutput { key_id } => {
                local_reconfiguration_digests.get(key_id) == Some(cert_digest)
            }
            HandoffItemKey::NetworkDkgOutput { .. } | HandoffItemKey::ValidatorMpcData { .. } => {
                true
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};

    fn key_id(index: u8) -> ObjectID {
        ObjectID::new([index; 32])
    }

    /// Builds a cert whose only items are `NetworkReconfigurationOutput`s for
    /// the given `(key_id, digest)` pairs. Signatures are irrelevant to the
    /// readiness predicate, so they are left empty.
    fn cert_with_reconfiguration_items(
        items: Vec<(ObjectID, [u8; 32])>,
    ) -> CertifiedHandoffAttestation {
        CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch: 7,
                next_committee_pubkey_set_hash: [0u8; 32],
                items: items
                    .into_iter()
                    .map(|(key_id, digest)| {
                        (
                            HandoffItemKey::NetworkReconfigurationOutput { key_id },
                            digest,
                        )
                    })
                    .collect(),
            },
            signatures: vec![],
        }
    }

    #[test]
    fn all_cert_reconfiguration_outputs_held_locally_cases() {
        // Cert certifies one reconfiguration output; the local slice holds a
        // matching digest → ready.
        let cert = cert_with_reconfiguration_items(vec![(key_id(0), [1u8; 32])]);
        let held = BTreeMap::from([(key_id(0), [1u8; 32])]);
        assert!(all_cert_reconfiguration_outputs_held_locally(&cert, &held));

        // Output not yet computed/cached locally (empty slice) → not ready.
        assert!(!all_cert_reconfiguration_outputs_held_locally(
            &cert,
            &BTreeMap::new()
        ));

        // Local digest differs from the cert's (a stale/wrong local output —
        // the exact condition the cert-digest match exists to catch) → not ready.
        let stale = BTreeMap::from([(key_id(0), [9u8; 32])]);
        assert!(!all_cert_reconfiguration_outputs_held_locally(
            &cert, &stale
        ));

        // Two certified outputs, only one held locally → not ready (EVERY item
        // the cert certifies must be held + matching).
        let cert_two =
            cert_with_reconfiguration_items(vec![(key_id(0), [1u8; 32]), (key_id(1), [2u8; 32])]);
        let one = BTreeMap::from([(key_id(0), [1u8; 32])]);
        assert!(!all_cert_reconfiguration_outputs_held_locally(
            &cert_two, &one
        ));

        // Both held with matching digests → ready.
        let both = BTreeMap::from([(key_id(0), [1u8; 32]), (key_id(1), [2u8; 32])]);
        assert!(all_cert_reconfiguration_outputs_held_locally(
            &cert_two, &both
        ));

        // A cert with no reconfiguration items is trivially ready (nothing to
        // wait for), even against an empty slice — and a DKG-only item must NOT
        // be gated by this reconfiguration-readiness predicate.
        let dkg_only = CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch: 7,
                next_committee_pubkey_set_hash: [0u8; 32],
                items: vec![(
                    HandoffItemKey::NetworkDkgOutput { key_id: key_id(0) },
                    [5u8; 32],
                )],
            },
            signatures: vec![],
        };
        assert!(all_cert_reconfiguration_outputs_held_locally(
            &dkg_only,
            &BTreeMap::new()
        ));
    }
}
