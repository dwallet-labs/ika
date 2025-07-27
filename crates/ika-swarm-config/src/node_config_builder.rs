// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::net::SocketAddr;

use crate::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::KeyPair;
use ika_config::node::{
    AuthorityKeyPairWithPath, AuthorityOverloadConfig, KeyPairWithPath, RootSeedWithPath,
    RunWithRange, StateArchiveConfig, SuiChainIdentifier, SuiConnectorConfig,
    default_end_of_epoch_broadcast_channel_capacity,
};
use std::path::PathBuf;
use sui_types::base_types::ObjectID;

use ika_config::p2p::{P2pConfig, SeedPeer, StateSyncConfig};

use ika_config::{
    AUTHORITIES_DB_NAME, CONSENSUS_DB_NAME, ConsensusConfig, FULL_NODE_DB_PATH, NodeConfig,
    local_ip_utils,
};
use ika_types::crypto::{AuthorityKeyPair, AuthorityPublicKeyBytes, NetworkKeyPair};
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use sui_types::crypto::SuiKeyPair;
use sui_types::multiaddr::Multiaddr;

/// This builder contains information not included in [`ValidatorInitializationConfig`] for building
/// a validator NodeConfig. It can be used to build either a genesis validator or a new validator.
#[derive(Clone, Default)]
pub struct ValidatorConfigBuilder {
    config_directory: Option<PathBuf>,
    supported_protocol_versions: Option<SupportedProtocolVersions>,
    authority_overload_config: Option<AuthorityOverloadConfig>,
    max_submit_position: Option<usize>,
    submit_delay_step_override_millis: Option<u64>,
}

impl ValidatorConfigBuilder {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn with_config_directory(mut self, config_directory: PathBuf) -> Self {
        assert!(self.config_directory.is_none());
        self.config_directory = Some(config_directory);
        self
    }

    pub fn with_supported_protocol_versions(
        mut self,
        supported_protocol_versions: SupportedProtocolVersions,
    ) -> Self {
        assert!(self.supported_protocol_versions.is_none());
        self.supported_protocol_versions = Some(supported_protocol_versions);
        self
    }

    pub fn with_authority_overload_config(mut self, config: AuthorityOverloadConfig) -> Self {
        self.authority_overload_config = Some(config);
        self
    }

    pub fn with_max_submit_position(mut self, max_submit_position: usize) -> Self {
        self.max_submit_position = Some(max_submit_position);
        self
    }

    pub fn with_submit_delay_step_override_millis(
        mut self,
        submit_delay_step_override_millis: u64,
    ) -> Self {
        self.submit_delay_step_override_millis = Some(submit_delay_step_override_millis);
        self
    }

    pub fn build(
        self,
        validator: &ValidatorInitializationConfig,
        sui_rpc_url: String,
        ika_package_id: ObjectID,
        ika_common_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        ika_system_package_id: ObjectID,
        ika_system_object_id: ObjectID,
        ika_dwallet_coordinator_object_id: ObjectID,
    ) -> NodeConfig {
        let key_path = get_key_path(&validator.key_pair);
        let config_directory = self
            .config_directory
            .unwrap_or_else(|| tempfile::tempdir().unwrap().keep());
        let db_path = config_directory
            .join(AUTHORITIES_DB_NAME)
            .join(key_path.clone());

        let network_address = validator.network_address.clone();
        let consensus_db_path = config_directory.join(CONSENSUS_DB_NAME).join(key_path);
        let localhost = local_ip_utils::localhost_for_testing();
        let consensus_config = ConsensusConfig {
            db_path: consensus_db_path,
            db_retention_epochs: None,
            db_pruner_period_secs: None,
            max_pending_transactions: None,
            max_submit_position: self.max_submit_position,
            submit_delay_step_override_millis: self.submit_delay_step_override_millis,
            parameters: Default::default(),
        };

        let p2p_config = P2pConfig {
            listen_address: validator.p2p_listen_address.unwrap_or_else(|| {
                validator
                    .p2p_address
                    .udp_multiaddr_to_listen_address()
                    .unwrap()
            }),
            external_address: Some(validator.p2p_address.clone()),
            // Set a shorter timeout for checkpoint content download in tests, since
            // checkpoint pruning also happens much faster, and the network is local.
            state_sync: Some(StateSyncConfig {
                dwallet_checkpoint_content_timeout_ms: Some(10_000),
                ..Default::default()
            }),
            ..Default::default()
        };
        NodeConfig {
            root_seed_key_pair: Some(RootSeedWithPath::new(validator.root_seed.clone())),
            protocol_key_pair: AuthorityKeyPairWithPath::new(validator.key_pair.copy()),
            network_key_pair: KeyPairWithPath::new(SuiKeyPair::Ed25519(
                validator.network_key_pair.copy(),
            )),
            account_key_pair: KeyPairWithPath::new(validator.account_key_pair.copy()),
            consensus_key_pair: KeyPairWithPath::new(SuiKeyPair::Ed25519(
                validator.consensus_key_pair.copy(),
            )),
            sui_connector_config: SuiConnectorConfig {
                sui_rpc_url: sui_rpc_url.to_string(),
                sui_chain_identifier: SuiChainIdentifier::Custom,
                ika_package_id,
                ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id,
                ika_system_package_id,
                ika_system_object_id,
                ika_dwallet_coordinator_object_id,
                notifier_client_key_pair: None,
                sui_ika_system_module_last_processed_event_id_override: None,
            },
            db_path,
            network_address,
            metrics_address: validator.metrics_address,
            admin_interface_port: local_ip_utils::get_available_port(&localhost),

            consensus_config: Some(consensus_config),
            remove_deprecated_tables: false,
            p2p_config,

            end_of_epoch_broadcast_channel_capacity:
                default_end_of_epoch_broadcast_channel_capacity(),
            metrics: None,
            supported_protocol_versions: self.supported_protocol_versions,
            state_archive_write_config: StateArchiveConfig::default(),
            state_archive_read_config: vec![],

            authority_overload_config: self.authority_overload_config.unwrap_or_default(),
            run_with_range: None,
        }
    }

    pub fn build_new_validator<R: rand::RngCore + rand::CryptoRng>(
        self,
        rng: &mut R,
        sui_rpc_url: String,
        ika_package_id: ObjectID,
        ika_common_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        ika_system_package_id: ObjectID,
        ika_system_object_id: ObjectID,
        ika_dwallet_coordinator_object_id: ObjectID,
    ) -> NodeConfig {
        let validator_initialization_config =
            ValidatorInitializationConfigBuilder::new().build(rng);
        self.build(
            &validator_initialization_config,
            sui_rpc_url,
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct FullnodeConfigBuilder {
    config_directory: Option<PathBuf>,
    supported_protocol_versions: Option<SupportedProtocolVersions>,
    db_path: Option<PathBuf>,
    network_address: Option<Multiaddr>,
    metrics_address: Option<SocketAddr>,
    admin_interface_port: Option<u16>,
    p2p_external_address: Option<Multiaddr>,
    p2p_listen_address: Option<SocketAddr>,
    network_key_pair: Option<KeyPairWithPath>,
    run_with_range: Option<RunWithRange>,
    disable_pruning: bool,
}

impl FullnodeConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config_directory(mut self, config_directory: PathBuf) -> Self {
        self.config_directory = Some(config_directory);
        self
    }

    pub fn with_supported_protocol_versions(mut self, versions: SupportedProtocolVersions) -> Self {
        self.supported_protocol_versions = Some(versions);
        self
    }

    pub fn with_disable_pruning(mut self, disable_pruning: bool) -> Self {
        self.disable_pruning = disable_pruning;
        self
    }

    pub fn with_db_path(mut self, db_path: PathBuf) -> Self {
        self.db_path = Some(db_path);
        self
    }

    pub fn with_network_address(mut self, network_address: Multiaddr) -> Self {
        self.network_address = Some(network_address);
        self
    }

    pub fn with_metrics_address(mut self, metrics_address: SocketAddr) -> Self {
        self.metrics_address = Some(metrics_address);
        self
    }

    pub fn with_admin_interface_port(mut self, admin_interface_port: u16) -> Self {
        self.admin_interface_port = Some(admin_interface_port);
        self
    }

    pub fn with_p2p_external_address(mut self, p2p_external_address: Multiaddr) -> Self {
        self.p2p_external_address = Some(p2p_external_address);
        self
    }

    pub fn with_p2p_listen_address(mut self, p2p_listen_address: SocketAddr) -> Self {
        self.p2p_listen_address = Some(p2p_listen_address);
        self
    }

    pub fn with_network_key_pair(mut self, network_key_pair: Option<NetworkKeyPair>) -> Self {
        if let Some(network_key_pair) = network_key_pair {
            self.network_key_pair =
                Some(KeyPairWithPath::new(SuiKeyPair::Ed25519(network_key_pair)));
        }
        self
    }

    pub fn with_run_with_range(mut self, run_with_range: Option<RunWithRange>) -> Self {
        if let Some(run_with_range) = run_with_range {
            self.run_with_range = Some(run_with_range);
        }
        self
    }

    pub fn build<R: rand::RngCore + rand::CryptoRng>(
        self,
        rng: &mut R,
        validators: &[ValidatorInitializationConfig],
        sui_rpc_url: String,
        ika_package_id: ObjectID,
        ika_common_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        ika_system_package_id: ObjectID,
        ika_system_object_id: ObjectID,
        ika_dwallet_coordinator_object_id: ObjectID,
        notifier_client_key_pair: Option<SuiKeyPair>,
    ) -> NodeConfig {
        // Take advantage of ValidatorGenesisConfigBuilder to build the keypairs and addresses,
        // even though this is a fullnode.
        let validator_config_builder = ValidatorInitializationConfigBuilder::new();

        let validator_config = validator_config_builder.build(rng);

        let key_path = get_key_path(&validator_config.key_pair);
        let config_directory = self
            .config_directory
            .unwrap_or_else(|| tempfile::tempdir().unwrap().keep());

        let p2p_config = {
            let seed_peers = validators
                .iter()
                .map(|v| SeedPeer {
                    peer_id: Some(anemo::PeerId(v.network_key_pair.public().0.to_bytes())),
                    address: v.p2p_address.clone(),
                })
                .collect();

            P2pConfig {
                listen_address: self.p2p_listen_address.unwrap_or_else(|| {
                    validator_config.p2p_listen_address.unwrap_or_else(|| {
                        validator_config
                            .p2p_address
                            .udp_multiaddr_to_listen_address()
                            .unwrap()
                    })
                }),
                external_address: self
                    .p2p_external_address
                    .or(Some(validator_config.p2p_address.clone())),
                seed_peers,
                // Set a shorter timeout for checkpoint content download in tests, since
                // checkpoint pruning also happens much faster,
                // and the network is local.
                state_sync: Some(StateSyncConfig {
                    dwallet_checkpoint_content_timeout_ms: Some(10_000),
                    ..Default::default()
                }),
                ..Default::default()
            }
        };

        let localhost = local_ip_utils::localhost_for_testing();

        let notifier_client_key_pair = notifier_client_key_pair.map(KeyPairWithPath::new);

        NodeConfig {
            root_seed_key_pair: None,
            protocol_key_pair: AuthorityKeyPairWithPath::new(validator_config.key_pair),
            account_key_pair: KeyPairWithPath::new(validator_config.account_key_pair),
            consensus_key_pair: KeyPairWithPath::new(SuiKeyPair::Ed25519(
                validator_config.consensus_key_pair,
            )),
            network_key_pair: self.network_key_pair.unwrap_or(KeyPairWithPath::new(
                SuiKeyPair::Ed25519(validator_config.network_key_pair),
            )),
            db_path: self
                .db_path
                .unwrap_or(config_directory.join(FULL_NODE_DB_PATH).join(key_path)),
            network_address: self
                .network_address
                .unwrap_or(validator_config.network_address),
            sui_connector_config: SuiConnectorConfig {
                sui_rpc_url: sui_rpc_url.to_string(),
                sui_chain_identifier: SuiChainIdentifier::Custom,
                ika_package_id,
                ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id,
                ika_system_package_id,
                ika_system_object_id,
                ika_dwallet_coordinator_object_id,
                notifier_client_key_pair,
                sui_ika_system_module_last_processed_event_id_override: None,
            },
            metrics_address: self
                .metrics_address
                .unwrap_or(local_ip_utils::new_local_tcp_socket_for_testing()),
            admin_interface_port: self
                .admin_interface_port
                .unwrap_or(local_ip_utils::get_available_port(&localhost)),
            consensus_config: None,
            remove_deprecated_tables: false,
            p2p_config,
            end_of_epoch_broadcast_channel_capacity:
                default_end_of_epoch_broadcast_channel_capacity(),
            metrics: None,
            supported_protocol_versions: self.supported_protocol_versions,
            state_archive_write_config: StateArchiveConfig::default(),
            state_archive_read_config: vec![],
            authority_overload_config: Default::default(),
            run_with_range: self.run_with_range,
        }
    }
}

/// Given a validator keypair, return a path that can be used to identify the validator.
fn get_key_path(key_pair: &AuthorityKeyPair) -> String {
    let public_key: AuthorityPublicKeyBytes = key_pair.public().into();
    let mut key_path = Hex::encode(public_key);
    // 12 is rather arbitrary here, but it's a nice balance between being short and being unique.
    key_path.truncate(12);
    key_path
}
