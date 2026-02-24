// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::Node;
use anyhow::Result;
use futures::future::try_join_all;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::{
    ops,
    path::{Path, PathBuf},
};

use ika_config::NodeConfig;
use ika_config::node::{
    AuthorityOverloadConfig, LOCAL_DEFAULT_SUI_FAUCET_URL, RunWithRange,
    get_testing_sui_fullnode_rpc_url,
};
use ika_node::IkaNodeHandle;
use ika_protocol_config::ProtocolVersion;
use ika_swarm_config::network_config::NetworkConfig;
use ika_swarm_config::network_config_builder::{
    CommitteeConfig, ConfigBuilder, ProtocolVersionsConfig, SupportedProtocolVersionsCallback,
};
use ika_swarm_config::validator_initialization_config::ValidatorInitializationConfig;
use ika_types::crypto::AuthorityName;
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use sui_macros::nondeterministic;
use tempfile::TempDir;
use tracing::{error, info};

pub struct SwarmBuilder<R = OsRng> {
    rng: R,
    // template: NodeConfig,
    dir: Option<PathBuf>,
    committee: CommitteeConfig,
    network_config: Option<NetworkConfig>,
    epoch_duration_ms: Option<u64>,
    protocol_version: Option<ProtocolVersion>,
    fullnode_count: usize,
    supported_protocol_versions_config: ProtocolVersionsConfig,
    // Default to supported_protocol_versions_config, but can be overridden.
    fullnode_supported_protocol_versions_config: Option<ProtocolVersionsConfig>,
    authority_overload_config: Option<AuthorityOverloadConfig>,
    fullnode_run_with_range: Option<RunWithRange>,
    max_submit_position: Option<usize>,
    submit_delay_step_override_millis: Option<u64>,
}

impl SwarmBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            dir: None,
            committee: CommitteeConfig::Size(NonZeroUsize::new(1).unwrap()),
            network_config: None,
            epoch_duration_ms: None,
            protocol_version: None,
            fullnode_count: 0,
            supported_protocol_versions_config: ProtocolVersionsConfig::Default,
            fullnode_supported_protocol_versions_config: None,
            authority_overload_config: None,
            fullnode_run_with_range: None,
            max_submit_position: None,
            submit_delay_step_override_millis: None,
        }
    }
}

impl<R> SwarmBuilder<R> {
    pub fn rng<N: rand::RngCore + rand::CryptoRng>(self, rng: N) -> SwarmBuilder<N> {
        SwarmBuilder {
            rng,
            dir: self.dir,
            committee: self.committee,
            network_config: self.network_config,
            epoch_duration_ms: self.epoch_duration_ms,
            protocol_version: self.protocol_version,
            fullnode_count: self.fullnode_count,
            supported_protocol_versions_config: self.supported_protocol_versions_config,
            fullnode_supported_protocol_versions_config: self
                .fullnode_supported_protocol_versions_config,
            authority_overload_config: self.authority_overload_config,
            fullnode_run_with_range: self.fullnode_run_with_range,
            max_submit_position: self.max_submit_position,
            submit_delay_step_override_millis: self.submit_delay_step_override_millis,
        }
    }

    /// Set the directory that should be used by the Swarm for any on-disk data.
    ///
    /// If a directory is provided, it will not be cleaned up when the Swarm is dropped.
    ///
    /// Defaults to using a temporary directory that will be cleaned up when the Swarm is dropped.
    pub fn dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Set the committee size (the number of validators in the validator set).
    ///
    /// Defaults to 1.
    pub fn committee_size(mut self, committee_size: NonZeroUsize) -> Self {
        self.committee = CommitteeConfig::Size(committee_size);
        self
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorInitializationConfig>) -> Self {
        self.committee = CommitteeConfig::Validators(validators);
        self
    }
    pub fn with_network_config(mut self, network_config: NetworkConfig) -> Self {
        assert!(self.network_config.is_none());
        self.network_config = Some(network_config);
        self
    }

    pub fn with_fullnode_count(mut self, fullnode_count: usize) -> Self {
        self.fullnode_count = fullnode_count;
        self
    }

    pub fn with_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.epoch_duration_ms = Some(epoch_duration_ms);
        self
    }

    pub fn with_protocol_version(mut self, protocol_version: ProtocolVersion) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }

    pub fn with_supported_protocol_versions(mut self, c: SupportedProtocolVersions) -> Self {
        self.supported_protocol_versions_config = ProtocolVersionsConfig::Global(c);
        self
    }

    pub fn with_supported_protocol_version_callback(
        mut self,
        func: SupportedProtocolVersionsCallback,
    ) -> Self {
        self.supported_protocol_versions_config = ProtocolVersionsConfig::PerValidator(func);
        self
    }

    pub fn with_supported_protocol_versions_config(mut self, c: ProtocolVersionsConfig) -> Self {
        self.supported_protocol_versions_config = c;
        self
    }

    pub fn with_fullnode_supported_protocol_versions_config(
        mut self,
        c: ProtocolVersionsConfig,
    ) -> Self {
        self.fullnode_supported_protocol_versions_config = Some(c);
        self
    }

    pub fn with_authority_overload_config(
        mut self,
        authority_overload_config: AuthorityOverloadConfig,
    ) -> Self {
        assert!(self.network_config.is_none());
        self.authority_overload_config = Some(authority_overload_config);
        self
    }

    pub fn with_fullnode_run_with_range(mut self, run_with_range: Option<RunWithRange>) -> Self {
        if let Some(run_with_range) = run_with_range {
            self.fullnode_run_with_range = Some(run_with_range);
        }
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
}

impl<R: rand::RngCore + rand::CryptoRng> SwarmBuilder<R> {
    /// Create the configured Swarm.
    pub async fn build(self) -> Result<Swarm, anyhow::Error> {
        const SIXTEEN_MEGA_BYTES: usize = 16 * 1024 * 1024;
        if let Err(err) = rayon::ThreadPoolBuilder::new()
            .stack_size(SIXTEEN_MEGA_BYTES)
            .panic_handler(|err| error!("Rayon thread pool task panicked: {:?}", err))
            .build_global()
        {
            error!("Failed to create rayon thread pool: {:?}", err);
        }
        let dir = if let Some(dir) = self.dir {
            SwarmDirectory::Persistent(dir)
        } else {
            SwarmDirectory::new_temporary()
        };
        let network_config = if let Some(network_config) = self.network_config {
            network_config
        } else {
            let sui_fullnode_rpc_url = get_testing_sui_fullnode_rpc_url();
            let sui_faucet_url = LOCAL_DEFAULT_SUI_FAUCET_URL.to_string();
            let mut config_builder =
                ConfigBuilder::new(dir.as_ref(), sui_fullnode_rpc_url, sui_faucet_url);

            if let Some(epoch_duration_ms) = self.epoch_duration_ms {
                config_builder = config_builder.with_epoch_duration(epoch_duration_ms);
            }

            if let Some(protocol_version) = self.protocol_version {
                config_builder = config_builder.with_protocol_version(protocol_version);
            }

            if let Some(authority_overload_config) = self.authority_overload_config {
                config_builder =
                    config_builder.with_authority_overload_config(authority_overload_config);
            }

            if let Some(max_submit_position) = self.max_submit_position {
                config_builder = config_builder.with_max_submit_position(max_submit_position);
            }

            if let Some(submit_delay_step_override_millis) = self.submit_delay_step_override_millis
            {
                config_builder = config_builder
                    .with_submit_delay_step_override_millis(submit_delay_step_override_millis);
            }

            if let Some(fullnode_run_with_range) = self.fullnode_run_with_range {
                config_builder =
                    config_builder.with_fullnode_run_with_range(fullnode_run_with_range);
            }

            if let Some(fullnode_supported_protocol_versions_config) =
                self.fullnode_supported_protocol_versions_config
            {
                config_builder = config_builder.with_fullnode_supported_protocol_versions_config(
                    fullnode_supported_protocol_versions_config,
                );
            }

            config_builder
                .committee(self.committee)
                .rng(self.rng)
                .with_supported_protocol_versions_config(
                    self.supported_protocol_versions_config.clone(),
                )
                .with_fullnode_count(self.fullnode_count)
                .build()
                .await?
        };

        let mut nodes: HashMap<_, _> = network_config
            .validator_configs()
            .iter()
            .map(|config| {
                info!(
                    "SwarmBuilder configuring validator with name {}",
                    config.protocol_public_key()
                );
                (config.protocol_public_key(), Node::new(config.to_owned()))
            })
            .collect();

        for fullnode_config in &network_config.fullnode_configs {
            info!(
                "SwarmBuilder configuring fullnode with name {}",
                fullnode_config.protocol_public_key()
            );
            nodes.insert(
                fullnode_config.protocol_public_key(),
                Node::new(fullnode_config.to_owned()),
            );
        }

        Ok(Swarm {
            dir,
            network_config,
            nodes,
        })
    }
}

/// A handle to an in-memory Ika Network.
#[derive(Debug)]
pub struct Swarm {
    dir: SwarmDirectory,
    pub network_config: NetworkConfig,
    nodes: HashMap<AuthorityName, Node>,
}

impl Drop for Swarm {
    fn drop(&mut self) {
        self.nodes_iter_mut().for_each(|node| node.stop());
    }
}

impl Swarm {
    fn nodes_iter_mut(&mut self) -> impl Iterator<Item = &mut Node> {
        self.nodes.values_mut()
    }

    /// Return a new Builder
    pub fn builder() -> SwarmBuilder {
        SwarmBuilder::new()
    }

    /// Start all nodes associated with this Swarm
    pub async fn launch(&mut self) -> Result<()> {
        try_join_all(self.nodes_iter_mut().map(|node| node.start())).await?;
        tracing::info!("Successfully launched Swarm");
        Ok(())
    }

    /// Return the path to the directory where this Swarm's on-disk data is kept.
    pub fn dir(&self) -> &Path {
        self.dir.as_ref()
    }

    /// Return a reference to this Swarm's `NetworkConfig`.
    pub fn config(&self) -> &NetworkConfig {
        &self.network_config
    }

    /// Return a mutable reference to this Swarm's `NetworkConfig`.
    // TODO: It's not ideal to mutate network config. We should consider removing this.
    pub fn config_mut(&mut self) -> &mut NetworkConfig {
        &mut self.network_config
    }

    pub fn all_nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn node(&self, name: &AuthorityName) -> Option<&Node> {
        self.nodes.get(name)
    }

    pub fn node_mut(&mut self, name: &AuthorityName) -> Option<&mut Node> {
        self.nodes.get_mut(name)
    }

    /// Return an iterator over shared references of all nodes that are set up as validators.
    /// This means that they have a consensus config. This however doesn't mean this validator is
    /// currently active (i.e. it's not necessarily in the validator set at the moment).
    pub fn validator_nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .values()
            .filter(|node| node.config().consensus_config.is_some())
    }

    pub fn validator_node_handles(&self) -> Vec<IkaNodeHandle> {
        self.validator_nodes()
            .map(|node| node.get_node_handle().unwrap())
            .collect()
    }

    /// Returns an iterator over all currently active validators.
    pub fn active_validators(&self) -> impl Iterator<Item = &Node> {
        self.validator_nodes().filter(|node| {
            node.get_node_handle().is_some_and(|handle| {
                let state = handle.state();
                state.is_validator(&state.epoch_store_for_testing())
            })
        })
    }

    /// Return an iterator over shared references of all Fullnodes.
    pub fn fullnodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .values()
            .filter(|node| node.config().consensus_config.is_none())
    }

    pub async fn spawn_new_node(&mut self, config: NodeConfig) -> IkaNodeHandle {
        let name = config.protocol_public_key();
        let node = Node::new(config);
        node.start().await.unwrap();
        let handle = node.get_node_handle().unwrap();
        self.nodes.insert(name, node);
        handle
    }
}

#[derive(Debug)]
enum SwarmDirectory {
    Persistent(PathBuf),
    Temporary(TempDir),
}

impl SwarmDirectory {
    fn new_temporary() -> Self {
        SwarmDirectory::Temporary(nondeterministic!(TempDir::new().unwrap()))
    }
}

impl ops::Deref for SwarmDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        match self {
            SwarmDirectory::Persistent(dir) => dir.deref(),
            SwarmDirectory::Temporary(dir) => dir.path(),
        }
    }
}

impl AsRef<Path> for SwarmDirectory {
    fn as_ref(&self) -> &Path {
        match self {
            SwarmDirectory::Persistent(dir) => dir.as_ref(),
            SwarmDirectory::Temporary(dir) => dir.as_ref(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Swarm;
    use std::num::NonZeroUsize;

    #[tokio::test]
    #[ignore = "requires a running local Sui node"]
    async fn launch() {
        telemetry_subscribers::init_for_testing();
        let mut swarm = Swarm::builder()
            .committee_size(NonZeroUsize::new(4).unwrap())
            .with_fullnode_count(1)
            .build()
            .await
            .unwrap();

        swarm.launch().await.unwrap();

        for validator in swarm.validator_nodes() {
            validator.health_check(true).await.unwrap();
        }

        for fullnode in swarm.fullnodes() {
            fullnode.health_check(false).await.unwrap();
        }

        println!("hello");
    }
}
