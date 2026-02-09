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
use std::collections::HashMap;
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
use ika_core::authority::authority_per_epoch_store::AuthorityPerEpochStore;
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

use ika_types::committee::Committee;
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
}

#[cfg(msim)]
mod simulator {
    use std::sync::atomic::AtomicBool;

    use super::*;
    pub(super) struct SimState {
        pub sim_node: ika_simulator::runtime::NodeHandle,
        pub sim_safe_mode_expected: AtomicBool,
        _leak_detector: ika_simulator::NodeLeakDetector,
    }

    impl Default for SimState {
        fn default() -> Self {
            Self {
                sim_node: ika_simulator::runtime::NodeHandle::current(),
                sim_safe_mode_expected: AtomicBool::new(false),
                _leak_detector: ika_simulator::NodeLeakDetector::new(),
            }
        }
    }
}

use ika_core::SuiDataReceivers;
use ika_core::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use ika_core::consensus_handler::ConsensusHandlerInitializer;
use ika_core::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use ika_core::dwallet_mpc::dwallet_mpc_service::DWalletMPCService;
use ika_core::epoch::submit_to_consensus::EpochStoreSubmitToConsensus;
use ika_core::sui_connector::SuiConnectorService;
use ika_core::sui_connector::end_of_publish_sender::EndOfPublishSender;
use ika_core::sui_connector::metrics::SuiConnectorMetrics;
use ika_core::sui_connector::sui_executor::StopReason;
use ika_core::system_checkpoints::{
    SendSystemCheckpointToStateSync, SubmitSystemCheckpointToConsensus, SystemCheckpointMetrics,
    SystemCheckpointService, SystemCheckpointStore,
};
use ika_sui_client::metrics::SuiClientMetrics;
use ika_sui_client::{SuiClient, SuiConnectorClient};
use ika_types::messages_dwallet_mpc::{IkaNetworkConfig, IkaObjectsConfig, IkaPackageConfig};
#[cfg(msim)]
pub use simulator::set_jwk_injector;
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

    _state_archive_handle: Option<broadcast::Sender<()>>,

    shutdown_channel_tx: broadcast::Sender<Option<RunWithRange>>,
    system_checkpoint_store: Arc<SystemCheckpointStore>,
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

        let sui_client = Arc::new(
            SuiClient::new(
                &config.sui_connector_config.sui_rpc_url,
                sui_client_metrics,
                ika_network_config,
            )
            .await?,
        );

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
        let committee_store = Arc::new(CommitteeStore::new(config.db_path().join("epochs"), None));
        let perpetual_tables_options = default_db_options().optimize_db_for_write_throughput(4);
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(
            &config.db_path().join("store"),
            Some(perpetual_tables_options.options),
        ));

        //let cur_epoch = latest_system_state.epoch();
        // let committee = committee_store
        //     .get_committee(&cur_epoch)?
        //     .expect("Committee of the current epoch must exist");
        let chain_identifier =
            ChainIdentifier::from(config.sui_connector_config.ika_system_object_id);

        let epoch_start_configuration = EpochStartConfiguration::new(epoch_start_system_state)
            .expect("EpochStartConfiguration construction cannot fail");

        // let epoch_start_configuration = store
        //     .get_epoch_start_configuration()?
        //     .expect("EpochStartConfiguration of the current epoch must exist");

        let epoch_options = default_db_options().optimize_db_for_write_throughput(4);

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

        info!("creating checkpoint store");

        let dwallet_checkpoint_store =
            DWalletCheckpointStore::new(&config.db_path().join("dwallet_checkpoints"));
        let system_checkpoint_store =
            SystemCheckpointStore::new(&config.db_path().join("system_checkpoints"));

        info!("Creating state sync store");
        let state_sync_store = RocksDbStore::new(
            committee_store.clone(),
            dwallet_checkpoint_store.clone(),
            system_checkpoint_store.clone(),
        );

        info!("creating archive reader");
        // Create network
        // TODO only configure validators as seed/preferred peers for validators and not for
        // fullnodes once we've had a chance to re-work fullnode configuration generation.

        let authority_name = config.protocol_public_key();

        let archive_readers =
            ArchiveReaderBalancer::new(config.archive_reader_config(), &prometheus_registry)?;
        let (trusted_peer_change_tx, trusted_peer_change_rx) = watch::channel(Default::default());
        let P2pComponents {
            p2p_network,
            known_peers,
            discovery_handle,
            state_sync_handle,
        } = Self::create_p2p_network(
            &config,
            state_sync_store.clone(),
            chain_identifier,
            trusted_peer_change_rx,
            archive_readers.clone(),
            &prometheus_registry,
            !epoch_store.committee().authority_exists(&authority_name),
        )?;

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
            watch::channel::<Committee>(committee);
        let (new_requests_sender, new_requests_receiver) =
            broadcast::channel(EVENTS_CHANNEL_BUFFER_SIZE);
        let (end_of_publish_sender, end_of_publish_receiver) = watch::channel::<Option<u64>>(None);
        let (
            last_session_to_complete_in_current_epoch_sender,
            last_session_to_complete_in_current_epoch_receiver,
        ) = watch::channel((0, 0));
        let (uncompleted_requests_sender, uncompleted_requests_receiver) =
            watch::channel((Vec::new(), 0));
        let (sui_connector_service, network_keys_receiver) = SuiConnectorService::new(
            dwallet_checkpoint_store.clone(),
            system_checkpoint_store.clone(),
            sui_client.clone(),
            config.sui_connector_config.clone(),
            sui_connector_metrics,
            mode,
            next_epoch_committee_sender,
            new_requests_sender,
            end_of_publish_sender.clone(),
            last_session_to_complete_in_current_epoch_sender,
            uncompleted_requests_sender,
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
            _state_archive_handle: state_archive_handle,
            shutdown_channel_tx: shutdown_channel,
        };

        info!("IkaNode started!");
        let node = Arc::new(node);
        let node_copy = node.clone();
        let sui_client_clone = sui_client.clone();
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

    pub fn subscribe_to_epoch_change(&self) -> broadcast::Receiver<SystemInner> {
        self.end_of_epoch_channel.subscribe()
    }

    pub fn subscribe_to_shutdown_channel(&self) -> broadcast::Receiver<Option<RunWithRange>> {
        self.shutdown_channel_tx.subscribe()
    }

    pub fn current_epoch_for_testing(&self) -> EpochId {
        self.state.current_epoch_for_testing()
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

    fn create_p2p_network(
        config: &NodeConfig,
        state_sync_store: RocksDbStore,
        chain_identifier: ChainIdentifier,
        trusted_peer_change_rx: watch::Receiver<TrustedPeerChangeEvent>,
        archive_readers: ArchiveReaderBalancer,
        prometheus_registry: &Registry,
        is_notifier: bool,
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
            let routes = anemo::Router::new()
                .add_rpc_service(discovery_server)
                .add_rpc_service(state_sync_server);
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
    ) -> Result<ValidatorComponents> {
        let (checkpoint_service, checkpoint_service_tasks) = Self::start_dwallet_checkpoint_service(
            config,
            consensus_adapter.clone(),
            dwallet_checkpoint_store,
            epoch_store.clone(),
            state.clone(),
            state_sync_handle.clone(),
            dwallet_checkpoint_metrics.clone(),
            previous_epoch_last_dwallet_checkpoint_sequence_number,
        );

        let (system_checkpoint_service, system_checkpoint_service_tasks) =
            Self::start_system_checkpoint_service(
                config,
                consensus_adapter.clone(),
                system_checkpoint_store,
                epoch_store.clone(),
                state.clone(),
                state_sync_handle.clone(),
                system_checkpoint_metrics.clone(),
                previous_epoch_last_system_checkpoint_sequence_number,
            );

        let (dwallet_mpc_service_exit_sender, dwallet_mpc_service_exit_receiver) =
            watch::channel(());
        if let Err(e) =
            DWalletMPCService::verify_validator_keys(epoch_store.epoch_start_state(), config)
        {
            error!(error = ?e, "Failed to verify validator keys");
            panic!("Failed to verify validator keys: {e}");
        };

        let mut dwallet_mpc_service = DWalletMPCService::new(
            epoch_store.clone(),
            dwallet_mpc_service_exit_receiver,
            EpochStoreSubmitToConsensus::new(epoch_store.clone(), consensus_adapter.clone()),
            config.clone(),
            checkpoint_service.clone(),
            dwallet_mpc_metrics.clone(),
            state.clone(),
            sui_data_receivers,
            epoch_store.name,
            epoch_store.epoch(),
            epoch_store.committee().clone(),
            epoch_store.protocol_config().clone(),
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
            let sui_tx_validator = IkaTxValidator::new(
                state.clone(),
                consensus_adapter.clone(),
                checkpoint_service.clone(),
                system_checkpoint_service.clone(),
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
    ) -> (Arc<DWalletCheckpointService>, JoinSet<()>) {
        let epoch_start_timestamp_ms = epoch_store.epoch_start_state().epoch_start_timestamp_ms();
        let epoch_duration_ms = epoch_store.epoch_start_state().epoch_duration_ms();

        debug!(
            "Starting checkpoint service with epoch start timestamp {}
            and epoch duration {}",
            epoch_start_timestamp_ms, epoch_duration_ms
        );

        let checkpoint_output = Box::new(SubmitDWalletCheckpointToConsensus {
            sender: consensus_adapter,
            signer: state.secret.clone(),
            authority: config.protocol_public_key(),
            metrics: checkpoint_metrics.clone(),
        });

        let certified_checkpoint_output = SendDWalletCheckpointToStateSync::new(state_sync_handle);
        let max_tx_per_checkpoint = max_tx_per_checkpoint(epoch_store.protocol_config());
        let max_dwallet_checkpoint_size_bytes = epoch_store
            .protocol_config()
            .max_dwallet_checkpoint_size_bytes()
            as usize;

        DWalletCheckpointService::spawn(
            state.clone(),
            dwallet_checkpoint_store,
            epoch_store,
            checkpoint_output,
            Box::new(certified_checkpoint_output),
            checkpoint_metrics,
            max_tx_per_checkpoint,
            max_dwallet_checkpoint_size_bytes,
            previous_epoch_last_dwallet_checkpoint_sequence_number,
        )
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
    ) -> (Arc<SystemCheckpointService>, JoinSet<()>) {
        let epoch_start_timestamp_ms = epoch_store.epoch_start_state().epoch_start_timestamp_ms();
        let epoch_duration_ms = epoch_store.epoch_start_state().epoch_duration_ms();

        debug!(
            "Starting system_checkpoint service with epoch start timestamp {}
            and epoch duration {}",
            epoch_start_timestamp_ms, epoch_duration_ms
        );

        let system_checkpoint_output = Box::new(SubmitSystemCheckpointToConsensus {
            sender: consensus_adapter,
            signer: state.secret.clone(),
            authority: config.protocol_public_key(),
            metrics: system_checkpoint_metrics.clone(),
        });

        let certified_system_checkpoint_output =
            SendSystemCheckpointToStateSync::new(state_sync_handle);
        let max_tx_per_system_checkpoint = epoch_store
            .protocol_config()
            .max_messages_per_system_checkpoint();
        let max_system_checkpoint_size_bytes = epoch_store
            .protocol_config()
            .max_system_checkpoint_size_bytes()
            as usize;

        SystemCheckpointService::spawn(
            state.clone(),
            system_checkpoint_store,
            epoch_store,
            system_checkpoint_output,
            Box::new(certified_system_checkpoint_output),
            system_checkpoint_metrics,
            max_tx_per_system_checkpoint as usize,
            max_system_checkpoint_size_bytes,
            previous_epoch_last_system_checkpoint_sequence_number,
        )
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

            let end_of_publish_sender_handle =
                if let Some(components) = &*self.validator_components.lock().await {
                    let end_of_publish_sender = EndOfPublishSender::new(
                        Arc::downgrade(&cur_epoch_store),
                        Arc::new(components.consensus_adapter.clone()),
                        sui_data_receivers.end_of_publish_receiver.clone(),
                        cur_epoch_store.epoch(),
                    );

                    Some(tokio::spawn(async move {
                        end_of_publish_sender.run().await;
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

            // // Safe to call because we are in the middle of reconfiguration.
            // let latest_system_state = self
            //     .state
            //     .get_object_cache_reader()
            //     .get_ika_system_state_object_unsafe()
            //     .expect("Read Ika System State object cannot fail");

            #[cfg(msim)]
            if !self
                .sim_state
                .sim_safe_mode_expected
                .load(Ordering::Relaxed)
            {
                debug_assert!(!latest_system_state.safe_mode());
            }

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

    pub fn get_config(&self) -> &NodeConfig {
        &self.config
    }
}

#[cfg(msim)]
impl IkaNode {
    pub fn get_sim_node_id(&self) -> ika_simulator::task::NodeId {
        self.sim_state.sim_node.id()
    }

    pub fn set_safe_mode_expected(&self, new_value: bool) {
        info!("Setting safe mode expected to {}", new_value);
        self.sim_state
            .sim_safe_mode_expected
            .store(new_value, Ordering::Relaxed);
    }

    #[allow(unused_variables)]
    async fn fetch_jwks(
        authority: AuthorityName,
        provider: &OIDCProvider,
    ) -> IkaResult<Vec<(JwkId, JWK)>> {
        get_jwk_injector()(authority, provider)
    }
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
