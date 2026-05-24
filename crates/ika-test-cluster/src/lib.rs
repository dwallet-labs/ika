// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! In-process Ika test cluster: spins up Sui via `test_cluster::TestCluster`,
//! publishes the four Ika Move packages, initializes the on-chain system, and
//! launches an in-memory Ika [`Swarm`] pointed at the in-process Sui RPC.

use anyhow::Result;
use ika_config::initiation::InitiationParameters;
use ika_protocol_config::ProtocolVersion;
use ika_swarm::memory::{Swarm, SwarmBuilder};
use ika_swarm_config::network_config::NetworkConfig;
use ika_swarm_config::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use ika_swarm_config::sui_client::{ContractPaths, initialize_ika_system, publish_ika_packages};
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::supported_protocol_versions::SupportedProtocolVersions;
use rand::rngs::OsRng;
use sui_keys::keystore::AccountKeystore;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::SuiAddress;
use test_cluster::{TestCluster, TestClusterBuilder};

#[cfg(not(msim))]
use ika_protocol_config::Chain;
#[cfg(not(msim))]
use ika_swarm_config::sui_client::setup_contract_paths;

#[cfg(msim)]
use ika_swarm_config::sui_client::setup_contract_paths_for_simtest;

const DEFAULT_NUM_VALIDATORS: usize = 4;
/// SUI sent from publisher to each validator address so the validator can pay
/// gas for its own `request_add_validator_candidate` transaction. The amount is
/// orders of magnitude over what's needed; faucet calls fund similarly.
const VALIDATOR_FUNDING_MIST: u64 = 100_000_000_000;

pub struct IkaTestCluster {
    pub test_cluster: TestCluster,
    pub swarm: Swarm,
    /// Validator protocol public keys in the configured order. The i-th name
    /// is the authority name of the validator built from
    /// `validator_initialization_configs[i]`. Used by index-based test helpers
    /// (e.g. `upgrade_validator_supported_protocol_versions`) because the
    /// swarm stores nodes in a HashMap and `validator_nodes()` order is
    /// otherwise unspecified.
    pub validator_names: Vec<ika_types::crypto::AuthorityName>,
}

impl IkaTestCluster {
    pub fn builder() -> IkaTestClusterBuilder {
        IkaTestClusterBuilder::new()
    }

    /// Block until at least one validator node reports an in-memory epoch
    /// greater than or equal to `target_epoch`. Polls every 250ms.
    pub async fn wait_for_epoch(&self, target_epoch: u64) {
        let handle = self
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm must have at least one validator node");
        loop {
            let current = handle.with(|node| node.current_epoch_for_testing());
            if current >= target_epoch {
                tracing::info!(current, target_epoch, "wait_for_epoch reached target");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Current ika protocol version, read from the first validator's in-memory
    /// epoch store. Updated when the network reconfigures into a new epoch.
    pub fn current_protocol_version(&self) -> ProtocolVersion {
        let handle = self
            .swarm
            .validator_node_handles()
            .into_iter()
            .next()
            .expect("swarm must have at least one validator node");
        handle.with(|node| node.current_protocol_version_for_testing())
    }

    /// Simulate an in-place validator upgrade: stop the validator, mutate its
    /// `NodeConfig.supported_protocol_versions`, and restart it. The next
    /// `AuthorityCapabilitiesV1` notification (sent at the start of the next
    /// epoch the validator observes) carries the new range, which the
    /// end-of-epoch quorum vote uses to pick the next protocol version.
    ///
    /// Index is into `validator_names` (insertion order at build time).
    pub async fn upgrade_validator_supported_protocol_versions(
        &self,
        validator_index: usize,
        new_versions: SupportedProtocolVersions,
    ) -> Result<()> {
        let name = *self
            .validator_names
            .get(validator_index)
            .expect("validator_index out of range");
        let node = self
            .swarm
            .node(&name)
            .expect("validator node exists for the configured name");
        tracing::info!(
            ?validator_index,
            ?new_versions,
            "upgrading validator: stop -> mutate config -> start",
        );
        node.stop();
        node.config().supported_protocol_versions = Some(new_versions);
        node.start().await?;
        Ok(())
    }
}

pub struct IkaTestClusterBuilder {
    num_validators: usize,
    epoch_duration_ms: Option<u64>,
    protocol_version: Option<ProtocolVersion>,
    /// Per-validator `SupportedProtocolVersions` overrides (indexed). When
    /// `None`, every validator uses `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    /// `Some(v)` must have length `num_validators`.
    per_validator_supported_protocol_versions: Option<Vec<SupportedProtocolVersions>>,
}

impl IkaTestClusterBuilder {
    pub fn new() -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: None,
            protocol_version: None,
            per_validator_supported_protocol_versions: None,
        }
    }

    pub fn with_num_validators(mut self, num_validators: usize) -> Self {
        self.num_validators = num_validators;
        self
    }

    pub fn with_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.epoch_duration_ms = Some(epoch_duration_ms);
        self
    }

    /// Genesis protocol version. Defaults to `ProtocolVersion::MAX`. Use this
    /// to boot the cluster at an older version (e.g. v3) so an epoch
    /// transition will exercise the capability vote and advance to a newer
    /// version (e.g. v4) supported by `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    pub fn with_protocol_version(mut self, protocol_version: ProtocolVersion) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }

    /// Per-validator `SupportedProtocolVersions` overrides — vector length must
    /// equal `num_validators`. Use this to model a gradual upgrade scenario
    /// where some validators support a newer max than others. When unset,
    /// every validator gets `SupportedProtocolVersions::SYSTEM_DEFAULT`.
    pub fn with_per_validator_supported_protocol_versions(
        mut self,
        per_validator_versions: Vec<SupportedProtocolVersions>,
    ) -> Self {
        self.per_validator_supported_protocol_versions = Some(per_validator_versions);
        self
    }

    pub async fn build(self) -> Result<IkaTestCluster> {
        let mut test_cluster = TestClusterBuilder::new()
            .with_num_validators(self.num_validators)
            .build()
            .await;

        let sui_rpc_url = test_cluster.rpc_url().to_string();
        let publisher_address = test_cluster.get_address_0();

        let mut rng = OsRng;
        let validator_initialization_configs: Vec<ValidatorInitializationConfig> = (0..self
            .num_validators)
            .map(|i| {
                let mut cfg = ValidatorInitializationConfigBuilder::new().build(&mut rng);
                cfg.name = Some(format!("validator-{i}"));
                cfg
            })
            .collect();

        let mut validator_addresses = Vec::with_capacity(self.num_validators);
        for validator in &validator_initialization_configs {
            let address: SuiAddress = (&validator.account_key_pair.public()).into();
            test_cluster
                .wallet_mut()
                .add_account(validator.name.clone(), validator.account_key_pair.copy())
                .await;
            validator_addresses.push(address);
        }

        // Fund validator addresses from the publisher. `init_ika_on_sui` does this
        // via the Sui faucet; the in-process test cluster has no faucet, so we
        // transfer directly from a publisher gas object instead.
        for validator_address in &validator_addresses {
            let tx_data = test_cluster
                .test_transaction_builder_with_sender(publisher_address)
                .await
                .transfer_sui(Some(VALIDATOR_FUNDING_MIST), *validator_address)
                .build();
            test_cluster.sign_and_execute_transaction(&tx_data).await;
        }

        let contract_paths = build_contract_paths()?;
        let cwd = contract_paths.current_working_dir.clone();

        // Sui's publish flow writes `Pub.<env>.toml` to whatever cwd is when it
        // finishes; entries reference absolute paths to the unpacked package
        // dirs. The file is read on the next publish to resolve transitive
        // package addresses. If it lands in the workspace, stale entries from
        // a previous test run point to deleted temp dirs and break the next
        // run's publish with `InvalidEphemeralPath`. Park cwd inside the
        // contracts temp dir so the pubfile lives and dies with that TempDir.
        std::env::set_current_dir(contract_paths.contracts_dir.path())?;

        let client = SuiClientBuilder::default().build(&sui_rpc_url).await?;

        let packages = publish_ika_packages(
            test_cluster.wallet_mut(),
            client.clone(),
            publisher_address,
            &contract_paths,
        )
        .await?;

        let mut initiation_parameters = InitiationParameters::new();
        if let Some(epoch_duration_ms) = self.epoch_duration_ms {
            initiation_parameters.epoch_duration_ms = epoch_duration_ms;
        }
        if let Some(protocol_version) = self.protocol_version {
            initiation_parameters.protocol_version = protocol_version.as_u64();
        }

        let system = initialize_ika_system(
            test_cluster.wallet_mut(),
            client,
            publisher_address,
            &packages,
            &validator_initialization_configs,
            &validator_addresses,
            &initiation_parameters,
        )
        .await?;

        // `sui move build` inside publish_*_to_sui chdirs into the contract temp
        // dir; restore cwd so the caller's process state isn't mutated.
        std::env::set_current_dir(&cwd)?;

        // Validators must declare which protocol versions they support so they
        // send `AuthorityCapabilitiesV1` notifications — that's what the
        // end-of-epoch quorum vote reads to pick the next protocol version.
        // Without an override every validator gets `SYSTEM_DEFAULT`
        // (`ProtocolVersion::MIN..=MAX`); the per-validator override lets
        // tests model heterogeneous / gradual upgrade scenarios.
        if let Some(per_validator) = self.per_validator_supported_protocol_versions.as_ref() {
            anyhow::ensure!(
                per_validator.len() == validator_initialization_configs.len(),
                "per_validator_supported_protocol_versions has {} entries but cluster has {} validators",
                per_validator.len(),
                validator_initialization_configs.len(),
            );
        }
        let validator_configs: Vec<_> = validator_initialization_configs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let supported_versions = self
                    .per_validator_supported_protocol_versions
                    .as_ref()
                    .map(|per_validator| per_validator[i])
                    .unwrap_or(SupportedProtocolVersions::SYSTEM_DEFAULT);
                ValidatorConfigBuilder::new()
                    .with_supported_protocol_versions(supported_versions)
                    .build(
                        v,
                        sui_rpc_url.clone(),
                        packages.ika_package_id,
                        packages.ika_common_package_id,
                        packages.ika_dwallet_2pc_mpc_package_id,
                        packages.ika_system_package_id,
                        system.ika_system_object_id,
                        system.ika_dwallet_coordinator_object_id,
                    )
            })
            .collect();
        // Record the validators' protocol public keys in their configured
        // order so test helpers (e.g. `upgrade_validator_supported_protocol_versions`)
        // can address a specific validator by index.
        let validator_names: Vec<_> = validator_configs
            .iter()
            .map(|c| c.protocol_public_key())
            .collect();
        // The ika epoch only advances when a Notifier node submits the
        // `process_mid_epoch` / `request_advance_epoch` transactions to Sui (the
        // validators never do — `run_epoch_switch` is gated on a notifier key).
        // Without one the network is frozen at its genesis epoch, so any test that
        // calls `wait_for_epoch` hangs. Run one notifier (a fullnode carrying the
        // publisher's Sui key) so reconfiguration actually progresses.
        let publisher_keypair = test_cluster
            .wallet()
            .config
            .keystore
            .export(&publisher_address)?
            .copy();
        let mut notifier_rng = OsRng;
        let notifier_config = FullnodeConfigBuilder::new().build(
            &mut notifier_rng,
            &validator_initialization_configs,
            sui_rpc_url.clone(),
            packages.ika_package_id,
            packages.ika_common_package_id,
            packages.ika_dwallet_2pc_mpc_package_id,
            packages.ika_system_package_id,
            system.ika_system_object_id,
            system.ika_dwallet_coordinator_object_id,
            Some(publisher_keypair),
        );

        let network_config = NetworkConfig {
            validator_configs,
            fullnode_configs: vec![notifier_config],
            validator_initialization_configs,
            ika_package_id: packages.ika_package_id,
            ika_common_package_id: packages.ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id: packages.ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id: packages.ika_system_package_id,
            ika_system_object_id: system.ika_system_object_id,
            ika_dwallet_coordinator_object_id: system.ika_dwallet_coordinator_object_id,
        };

        let mut swarm = SwarmBuilder::new()
            .with_network_config(network_config)
            .build()
            .await?;
        swarm.launch().await?;

        Ok(IkaTestCluster {
            test_cluster,
            swarm,
            validator_names,
        })
    }
}

impl Default for IkaTestClusterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(msim))]
fn build_contract_paths() -> Result<ContractPaths> {
    setup_contract_paths(Chain::Devnet)
}

#[cfg(msim)]
fn build_contract_paths() -> Result<ContractPaths> {
    let (sui_framework, move_stdlib) = locate_sui_framework_and_move_stdlib()?;
    setup_contract_paths_for_simtest(&sui_framework, &move_stdlib)
}

/// Find the on-disk Move sources for `sui-framework` and `move-stdlib` so we can
/// rewrite ika `Move.toml` files to use local-path deps (msim cannot fetch via
/// git). We resolve the `sui-framework` Rust crate's manifest_path via
/// `cargo metadata`, then walk to its sibling Move-package layout
/// (`crates/sui-framework/packages/sui-framework` and `.../move-stdlib`).
#[cfg(msim)]
fn locate_sui_framework_and_move_stdlib() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(metadata_workspace_manifest()?)
        .exec()
        .map_err(|e| anyhow::anyhow!("cargo metadata failed: {e}"))?;

    let sui_framework_pkg = metadata
        .packages
        .iter()
        .find(|p| p.name.as_str() == "sui-framework")
        .ok_or_else(|| anyhow::anyhow!("sui-framework not found in cargo metadata"))?;
    // sui-framework's manifest sits at .../crates/sui-framework/Cargo.toml; the
    // Move package is its sibling at .../crates/sui-framework/packages/sui-framework.
    let sui_crate_dir = std::path::PathBuf::from(
        sui_framework_pkg
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("sui-framework manifest_path has no parent"))?,
    );
    let sui_framework_move = sui_crate_dir.join("packages").join("sui-framework");
    let move_stdlib_move = sui_crate_dir.join("packages").join("move-stdlib");
    if !sui_framework_move.join("Move.toml").is_file() {
        anyhow::bail!(
            "sui-framework Move package not found at {}",
            sui_framework_move.display()
        );
    }
    if !move_stdlib_move.join("Move.toml").is_file() {
        anyhow::bail!(
            "move-stdlib Move package not found at {}",
            move_stdlib_move.display()
        );
    }
    Ok((sui_framework_move, move_stdlib_move))
}

#[cfg(msim)]
fn metadata_workspace_manifest() -> Result<std::path::PathBuf> {
    // Walk up from this crate's manifest dir to find the workspace root Cargo.toml.
    let start = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("Cargo.toml");
        if candidate.is_file()
            && std::fs::read_to_string(&candidate)
                .map(|s| s.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Ok(candidate);
        }
    }
    anyhow::bail!("workspace Cargo.toml not found above {}", start.display())
}
