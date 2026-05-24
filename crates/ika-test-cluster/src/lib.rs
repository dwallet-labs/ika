// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! In-process Ika test cluster: spins up Sui via `test_cluster::TestCluster`,
//! publishes the four Ika Move packages, initializes the on-chain system, and
//! launches an in-memory Ika [`Swarm`] pointed at the in-process Sui RPC.

use anyhow::Result;
use ika_config::initiation::InitiationParameters;
use ika_node::IkaNodeHandle;
use ika_swarm::memory::{Swarm, SwarmBuilder};
use ika_swarm_config::network_config::NetworkConfig;
use ika_swarm_config::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use ika_swarm_config::sui_client::{
    ContractPaths, InitializedIkaSystem, PublishedIkaPackages, initialize_ika_system,
    publish_ika_packages, request_add_validator, request_add_validator_candidate, stake_ika,
};
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::crypto::{AuthorityPublicKeyBytes, KeypairTraits as _};
use rand::rngs::OsRng;
use sui_keys::keystore::AccountKeystore;
use sui_sdk::SuiClientBuilder;
use sui_types::base_types::{ObjectID, SuiAddress};
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
    /// State captured from the bootstrap so post-build helpers (joiner /
    /// remove flows) can compose new on-chain transactions without
    /// re-publishing or re-initializing.
    pub packages: PublishedIkaPackages,
    pub system: InitializedIkaSystem,
    pub sui_rpc_url: String,
    pub publisher_address: SuiAddress,
}

/// Handle to a validator that joined the network after the initial
/// bootstrap via [`IkaTestCluster::add_joiner_validator`].
pub struct JoinerHandle {
    pub address: SuiAddress,
    pub validator_id: ObjectID,
    pub validator_cap_id: ObjectID,
    pub node_handle: IkaNodeHandle,
    pub init_config: ValidatorInitializationConfig,
}

impl JoinerHandle {
    /// BLS authority name (committee identity) for this joiner.
    pub fn authority_name(&self) -> AuthorityPublicKeyBytes {
        self.init_config.key_pair.public().into()
    }
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
        wait_for_node_epoch(&handle, target_epoch).await;
    }

    /// Generate a fresh validator config, run the full candidate →
    /// staked → active flow on-chain, then spawn the joiner's in-memory
    /// `IkaNode` and attach it to the swarm. The returned [`JoinerHandle`]
    /// exposes the validator's identity + node handle so callers can
    /// wait for it to reach the next epoch or inspect committee state.
    ///
    /// The joiner becomes part of the active set at the next epoch
    /// boundary (the same lifecycle the bootstrap path drives for the
    /// initial set). Caller is responsible for `wait_for_epoch` after.
    pub async fn add_joiner_validator(&mut self) -> Result<JoinerHandle> {
        let mut rng = OsRng;
        let mut joiner_init = ValidatorInitializationConfigBuilder::new().build(&mut rng);
        joiner_init.name = Some(format!(
            "joiner-{}",
            self.swarm.validator_node_handles().len()
        ));
        let joiner_address: SuiAddress = (&joiner_init.account_key_pair.public()).into();

        // Add the joiner's account key to the wallet so the publisher's
        // `WalletContext` can sign transactions sent from the joiner.
        self.test_cluster
            .wallet_mut()
            .add_account(
                joiner_init.name.clone(),
                joiner_init.account_key_pair.copy(),
            )
            .await;

        // Fund the joiner address from the publisher — joiner needs SUI
        // gas to pay for its own candidate-registration tx.
        let tx_data = self
            .test_cluster
            .test_transaction_builder_with_sender(self.publisher_address)
            .await
            .transfer_sui(Some(VALIDATOR_FUNDING_MIST), joiner_address)
            .build();
        self.test_cluster
            .sign_and_execute_transaction(&tx_data)
            .await;

        let metadata = joiner_init.to_validator_info();
        let (validator_id, validator_cap_id) = request_add_validator_candidate(
            joiner_address,
            self.test_cluster.wallet_mut(),
            &metadata,
            self.packages.ika_system_package_id,
            self.packages.ika_common_package_id,
            self.system.ika_system_object_id,
            self.system.init_system_shared_version,
        )
        .await?;

        // Publisher stakes `MIN_VALIDATOR_JOINING_STAKE_INKU` into the
        // joiner's pool so `request_add_validator` doesn't abort with
        // insufficient-stake.
        stake_ika(
            self.publisher_address,
            self.test_cluster.wallet_mut(),
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.init_system_shared_version,
            self.packages.ika_supply_id,
            vec![validator_id],
        )
        .await?;

        let client = SuiClientBuilder::default().build(&self.sui_rpc_url).await?;
        request_add_validator(
            joiner_address,
            self.test_cluster.wallet_mut(),
            client,
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.init_system_shared_version,
            validator_cap_id,
        )
        .await?;

        let validator_config = ValidatorConfigBuilder::new().build(
            &joiner_init,
            self.sui_rpc_url.clone(),
            self.packages.ika_package_id,
            self.packages.ika_common_package_id,
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.ika_dwallet_coordinator_object_id,
        );
        let node_handle = self.swarm.spawn_new_node(validator_config).await;

        Ok(JoinerHandle {
            address: joiner_address,
            validator_id,
            validator_cap_id,
            node_handle,
            init_config: joiner_init,
        })
    }
}

/// Block until `node_handle`'s in-memory epoch reaches `target_epoch`.
/// Polls every 250ms — same cadence as `IkaTestCluster::wait_for_epoch`.
pub async fn wait_for_node_epoch(node_handle: &IkaNodeHandle, target_epoch: u64) {
    loop {
        let current = node_handle.with(|node| node.current_epoch_for_testing());
        if current >= target_epoch {
            tracing::info!(current, target_epoch, "wait_for_node_epoch reached target");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

pub struct IkaTestClusterBuilder {
    num_validators: usize,
    epoch_duration_ms: Option<u64>,
}

impl IkaTestClusterBuilder {
    pub fn new() -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: None,
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

        let validator_configs = validator_initialization_configs
            .iter()
            .map(|v| {
                ValidatorConfigBuilder::new().build(
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
            packages,
            system,
            sui_rpc_url,
            publisher_address,
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
