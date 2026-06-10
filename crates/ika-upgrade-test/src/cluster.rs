// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Bring up an out-of-process Ika cluster: an external Sui localnet, the four
//! Move packages published + system initialized against it, then N
//! `ika-validator` child processes plus one notifier fullnode.
//!
//! Config minting reuses `ika-swarm-config` exactly as the in-process
//! `ika-test-cluster` does (`init_ika_on_sui` for the chain bootstrap,
//! `ValidatorConfigBuilder` / `FullnodeConfigBuilder` for the per-node
//! `NodeConfig`s). The only difference is we serialize each `NodeConfig` to
//! YAML on a persistent data dir and hand it to a real binary via
//! `--config-path`, instead of starting `IkaNode` in-process.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ika_config::initiation::InitiationParameters;
use ika_config::node::NodeConfig;
use ika_protocol_config::ProtocolVersion;
use ika_sui_client::SuiClient as IkaClient;
use ika_sui_client::metrics::SuiClientMetrics;
use ika_swarm_config::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use ika_swarm_config::sui_client::{
    InitializedIkaSystem, PublishedIkaPackages, fund_address_from_faucet, init_ika_on_sui,
    request_add_validator, request_add_validator_candidate, request_remove_validator, stake_ika,
};
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use ika_types::sui::SystemInner;
use rand::rngs::OsRng;
use sui_sdk::SuiClient as SuiSdkClient;
use sui_sdk::SuiClientBuilder;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::SuiKeyPair;

use crate::process::ValidatorProcess;
use crate::sui::SuiLocalnet;
use crate::{DEFAULT_EPOCH_DURATION_MS, DEFAULT_NUM_VALIDATORS};

/// A running out-of-process cluster. Owns the Sui localnet, the validator
/// processes, and the notifier; tears everything down on `Drop` (each child has
/// `kill_on_drop`).
pub struct ClusterOfProcesses {
    pub sui: SuiLocalnet,
    pub validators: Vec<ValidatorProcess>,
    pub notifier: ValidatorProcess,
    network_config: IkaNetworkConfig,
    ika_client: IkaClient<SuiSdkClient>,
    rpc_url: String,
    /// The genesis publisher's Sui key — funded with SUI + the initial IKA
    /// supply. The workload driver reuses it as the user paying session fees.
    publisher_keypair: SuiKeyPair,
    /// On-chain registration of each validator slot, aligned with
    /// `validators` by index. Joiners append; removal leaves the slot in
    /// place (the cap stays valid, the process is just stopped).
    committee: Vec<ValidatorSlot>,
    /// Bootstrap package state (`ika_supply_id` funds joiner stakes).
    packages: PublishedIkaPackages,
    /// Bootstrap system state (`init_system_shared_version` is needed by
    /// every post-init system call).
    system: InitializedIkaSystem,
    /// The bootstrap wallet — publisher + all validator account keys
    /// imported, all addresses faucet-funded. Join/leave flows sign their
    /// transactions through it.
    wallet: WalletContext,
    publisher_address: SuiAddress,
    /// Root of the per-validator data dirs (joiners allocate
    /// `validator-{n}` under it).
    base: PathBuf,
    /// Kept alive so the persistent data dirs outlive the cluster.
    _base_dir: BaseDir,
}

/// On-chain identity of one validator slot.
#[derive(Clone, Debug)]
pub struct ValidatorSlot {
    pub address: SuiAddress,
    pub validator_id: ObjectID,
    pub validator_cap_id: ObjectID,
}

/// Either a caller-provided persistent dir or a harness-owned temp dir.
enum BaseDir {
    Owned(tempfile::TempDir),
    Borrowed(#[allow(dead_code)] PathBuf),
}

impl BaseDir {
    fn path(&self) -> &std::path::Path {
        match self {
            BaseDir::Owned(t) => t.path(),
            BaseDir::Borrowed(p) => p.as_path(),
        }
    }
}

pub struct ClusterBuilder {
    num_validators: usize,
    epoch_duration_ms: u64,
    genesis_protocol_version: Option<ProtocolVersion>,
    /// Genesis `min_validator_count`. The protocol default is 4; committee-
    /// churn scenarios that shrink below that set it lower at genesis.
    min_validator_count: Option<u64>,
    /// Resolved `ika-validator` binary every validator starts on.
    validator_binary: PathBuf,
    /// Resolved notifier binary (auto-detecting `ika-node` or `ika-notifier`).
    notifier_binary: PathBuf,
    /// Resolved `sui` binary for the localnet.
    sui_binary: PathBuf,
    base_dir: Option<PathBuf>,
}

impl ClusterBuilder {
    pub fn new(validator_binary: PathBuf, notifier_binary: PathBuf, sui_binary: PathBuf) -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: DEFAULT_EPOCH_DURATION_MS,
            genesis_protocol_version: None,
            min_validator_count: None,
            validator_binary,
            notifier_binary,
            sui_binary,
            base_dir: None,
        }
    }

    pub fn with_num_validators(mut self, n: usize) -> Self {
        // Every validator runs full class-groups crypto; past ~8 concurrent
        // processes a developer machine starves and epochs stop advancing.
        assert!(n <= 8, "harness caps validators at 8");
        self.num_validators = n;
        self
    }

    /// Genesis `min_validator_count` override (protocol default is 4).
    /// Required by scenarios that shrink the committee below the default.
    pub fn with_min_validator_count(mut self, n: u64) -> Self {
        self.min_validator_count = Some(n);
        self
    }

    pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
        self.epoch_duration_ms = ms;
        self
    }

    /// Genesis protocol version. Default `ProtocolVersion::MIN` so a vote can
    /// advance to a newer version supported by the new binary's `SYSTEM_DEFAULT`.
    pub fn with_genesis_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.genesis_protocol_version = Some(v);
        self
    }

    pub fn with_base_dir(mut self, dir: PathBuf) -> Self {
        self.base_dir = Some(dir);
        self
    }

    pub async fn build(self) -> Result<ClusterOfProcesses> {
        let base_dir = match &self.base_dir {
            Some(p) => {
                std::fs::create_dir_all(p)?;
                BaseDir::Borrowed(p.clone())
            }
            None => BaseDir::Owned(tempfile::tempdir()?),
        };
        let base = base_dir.path().to_path_buf();

        // 1. External Sui localnet. Keep Sui's own epochs effectively infinite;
        //    ika epochs are driven by the ika genesis epoch_duration_ms below.
        let sui = SuiLocalnet::start(
            self.sui_binary.clone(),
            base.join("sui.log"),
            180_000_000_000,
        )
        .await
        .context("start sui localnet")?;
        let rpc_url = sui.rpc_url().to_string();
        let faucet_url = sui.faucet_url().to_string();

        // 2. Validator init configs (keys + addresses + ports).
        let mut rng = OsRng;
        let validator_init_configs: Vec<ValidatorInitializationConfig> = (0..self.num_validators)
            .map(|i| {
                let mut cfg = ValidatorInitializationConfigBuilder::new().build(&mut rng);
                cfg.name = Some(format!("validator-{i}"));
                cfg
            })
            .collect();

        // 3. Chain bootstrap: faucet-fund, publish the four packages, init the
        //    on-chain system. Returns package/object ids + the publisher key
        //    (which the notifier needs to submit advance-epoch txns).
        let mut initiation_parameters = InitiationParameters::new();
        initiation_parameters.epoch_duration_ms = self.epoch_duration_ms;
        if let Some(v) = self.genesis_protocol_version {
            initiation_parameters.protocol_version = v.as_u64();
        }
        if let Some(n) = self.min_validator_count {
            initiation_parameters.min_validator_count = n;
        }
        // `sui move build`/publish writes `Pub.localnet.toml` into the cwd, keyed
        // to the chain id. Across runs a fresh `--force-regenesis` chain rejects
        // a stale pubfile. `init_ika_on_sui` (unlike `IkaTestClusterBuilder`)
        // does not park cwd in the contracts temp dir, so we chdir into the
        // per-run base (wiped each run) and restore afterwards. The single
        // process-global cwd is safe under `--test-threads=1`.
        let original_cwd = std::env::current_dir().ok();
        std::env::set_current_dir(&base).context("chdir to base dir for publish")?;
        let init_result = init_ika_on_sui(
            &validator_init_configs,
            rpc_url.clone(),
            faucet_url,
            initiation_parameters,
        )
        .await;
        if let Some(cwd) = &original_cwd {
            let _ = std::env::set_current_dir(cwd);
        }
        let bootstrap = init_result.context("init_ika_on_sui")?;
        let ika_package_id = bootstrap.packages.ika_package_id;
        let ika_common_package_id = bootstrap.packages.ika_common_package_id;
        let ika_dwallet_2pc_mpc_package_id = bootstrap.packages.ika_dwallet_2pc_mpc_package_id;
        let ika_system_package_id = bootstrap.packages.ika_system_package_id;
        let ika_system_object_id = bootstrap.system.ika_system_object_id;
        let ika_dwallet_coordinator_object_id = bootstrap.system.ika_dwallet_coordinator_object_id;
        let publisher_keypair = bootstrap.publisher_keypair;

        // On-chain identity per validator slot, aligned with the process vec
        // built below (bootstrap registration preserves config order).
        let committee: Vec<ValidatorSlot> = validator_init_configs
            .iter()
            .zip(bootstrap.system.validator_ids.iter())
            .zip(bootstrap.system.validator_cap_ids.iter())
            .map(|((init, validator_id), validator_cap_id)| ValidatorSlot {
                address: (&init.account_key_pair.public()).into(),
                validator_id: *validator_id,
                validator_cap_id: *validator_cap_id,
            })
            .collect();

        // 4. Per-validator NodeConfig on a persistent data dir, written to YAML.
        let mut validators = Vec::with_capacity(self.num_validators);
        for (i, init) in validator_init_configs.iter().enumerate() {
            let data_dir = base.join(format!("validator-{i}"));
            std::fs::create_dir_all(&data_dir)?;
            let node_config = ValidatorConfigBuilder::new()
                .with_config_directory(data_dir.clone())
                .build(
                    init,
                    rpc_url.clone(),
                    ika_package_id,
                    ika_common_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    ika_system_package_id,
                    ika_system_object_id,
                    ika_dwallet_coordinator_object_id,
                );
            let proc = spawn_node(
                i,
                self.validator_binary.clone(),
                &node_config,
                data_dir.clone(),
            )
            .await?;
            validators.push(proc);
        }

        // 5. Notifier fullnode — without it the ika epoch never advances
        //    (validators don't submit advance-epoch; that's gated on a notifier
        //    key). Carries the publisher's Sui key.
        let notifier_dir = base.join("notifier");
        std::fs::create_dir_all(&notifier_dir)?;
        let mut notifier_rng = OsRng;
        let notifier_config = FullnodeConfigBuilder::new()
            .with_config_directory(notifier_dir.clone())
            .build(
                &mut notifier_rng,
                &validator_init_configs,
                rpc_url.clone(),
                ika_package_id,
                ika_common_package_id,
                ika_dwallet_2pc_mpc_package_id,
                ika_system_package_id,
                ika_system_object_id,
                ika_dwallet_coordinator_object_id,
                Some(publisher_keypair.copy()),
            );
        let notifier = spawn_node(
            usize::MAX,
            self.notifier_binary.clone(),
            &notifier_config,
            notifier_dir,
        )
        .await?;

        let network_config = IkaNetworkConfig::new(
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            None,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
        );
        let ika_client = IkaClient::new(
            &rpc_url,
            SuiClientMetrics::new_for_testing(),
            network_config.clone(),
        )
        .await
        .context("construct ika sui client")?;

        Ok(ClusterOfProcesses {
            sui,
            validators,
            notifier,
            network_config,
            ika_client,
            rpc_url,
            publisher_keypair,
            committee,
            packages: bootstrap.packages,
            system: bootstrap.system,
            wallet: bootstrap.wallet_context,
            publisher_address: bootstrap.publisher_address,
            base,
            _base_dir: base_dir,
        })
    }
}

/// Retry a transaction-submitting expression on transient Sui
/// object-version contention.
///
/// The notifier process signs advance-epoch transactions with the same
/// publisher key this harness uses for staking, so the publisher's owned
/// objects (gas coins, the IKA supply coin) advance version under
/// concurrent submission. A tx built against a just-superseded version is
/// rejected by Sui as "non-retriable" for that exact version even though
/// rebuilding against the current version succeeds, so each retry
/// re-evaluates `$submit`, which re-resolves its object refs. Same
/// pattern as `ika-test-cluster`'s macro of the same name.
macro_rules! retry_on_object_contention {
    ($label:expr, $submit:expr) => {{
        let mut last_err: Option<anyhow::Error> = None;
        let mut out = None;
        for attempt in 0..10 {
            match $submit {
                Ok(value) => {
                    out = Some(value);
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let is_retriable_contention = msg.contains("unavailable for consumption")
                        || msg.contains("Transaction needs to be rebuilt")
                        || msg.contains("already locked by a different transaction");
                    tracing::warn!(
                        attempt,
                        is_retriable_contention,
                        "{} tx failed: {e}",
                        $label
                    );
                    if !is_retriable_contention {
                        return Err(anyhow::anyhow!("{} tx failed: {e}", $label));
                    }
                    last_err = Some(anyhow::anyhow!("{} tx failed: {e}", $label));
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        out.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow::anyhow!("{}: out of retries", $label))
        })?
    }};
}

impl ClusterOfProcesses {
    /// Current on-chain ika epoch (read from the system object).
    pub async fn current_epoch(&self) -> Result<u64> {
        let (_, SystemInner::V1(inner)) = self
            .ika_client
            .get_system_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_system_inner: {e}"))?;
        Ok(inner.epoch)
    }

    /// Current on-chain ika protocol version.
    pub async fn current_protocol_version(&self) -> Result<u64> {
        let (_, SystemInner::V1(inner)) = self
            .ika_client
            .get_system_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_system_inner: {e}"))?;
        Ok(inner.protocol_version)
    }

    /// Block until the on-chain ika epoch counter reaches `target`.
    ///
    /// The counter advancing to epoch N is itself the completion signal for
    /// epoch N-1: reconfiguration into a new epoch is gated on that epoch's
    /// network-key MPC (genesis DKG / reshare) finishing, so the epoch cannot
    /// advance until it does. Callers therefore wait for the epoch *after* the
    /// work they depend on — e.g. wait for epoch 2 to guarantee the genesis
    /// network DKG (which runs during epoch 1) has completed — rather than
    /// polling the network-key state directly.
    pub async fn wait_for_epoch(&self, target: u64, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // A failed read is treated as "not there yet" so a transient RPC
            // blip during boot/reconfig doesn't abort the wait — but log it, so
            // a persistently-down RPC isn't silently misreported as epoch 0
            // until the deadline.
            let current = match self.current_epoch().await {
                Ok(epoch) => epoch,
                Err(e) => {
                    tracing::debug!(error = %e, "wait_for_epoch: current_epoch read failed; retrying");
                    0
                }
            };
            if current >= target {
                tracing::info!(current, target, "wait_for_epoch reached target");
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("epoch {target} not reached within {timeout:?} (at {current})");
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    pub fn network_config(&self) -> &IkaNetworkConfig {
        &self.network_config
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn faucet_url(&self) -> &str {
        self.sui.faucet_url()
    }

    /// The funded genesis publisher key, reused by the workload driver as the
    /// fee-paying user.
    pub fn publisher_keypair(&self) -> &SuiKeyPair {
        &self.publisher_keypair
    }

    pub fn ika_client(&self) -> &IkaClient<SuiSdkClient> {
        &self.ika_client
    }

    /// Number of members in the on-chain active committee for the current
    /// epoch. Committee churn lands at epoch boundaries, so callers assert
    /// this right after a `wait_for_epoch`.
    pub async fn active_committee_size(&self) -> Result<usize> {
        let (_, SystemInner::V1(inner)) = self
            .ika_client
            .get_system_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_system_inner: {e}"))?;
        Ok(inner.validator_set.active_committee.members.len())
    }

    /// Run the full join flow for a brand-new validator: generate keys,
    /// faucet-fund its address, register it as a candidate (this puts its
    /// class-groups MPC data on chain), stake the minimum joining stake from
    /// the publisher's IKA supply, request activation, then spawn its node
    /// process on `binary`. The validator enters the active committee at the
    /// next epoch boundary — callers `wait_for_epoch` after.
    ///
    /// Returns the new validator's index in `validators`.
    pub async fn add_joiner_validator(&mut self, binary: PathBuf) -> Result<usize> {
        let index = self.validators.len();
        let mut rng = OsRng;
        let mut init = ValidatorInitializationConfigBuilder::new().build(&mut rng);
        init.name = Some(format!("validator-{index}"));
        let joiner_address: SuiAddress = (&init.account_key_pair.public()).into();

        // The wallet must hold the joiner's account key to sign its
        // candidate/activation transactions, and the address needs SUI gas.
        self.wallet
            .add_account(init.name.clone(), init.account_key_pair.copy())
            .await;
        fund_address_from_faucet(joiner_address, self.sui.faucet_url().to_string())
            .await
            .context("faucet-fund joiner")?;

        let metadata = init.to_validator_info();
        let (validator_id, validator_cap_id) = retry_on_object_contention!(
            "request_add_validator_candidate",
            request_add_validator_candidate(
                joiner_address,
                &mut self.wallet,
                &metadata,
                self.packages.ika_system_package_id,
                self.packages.ika_common_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
            )
            .await
        );

        retry_on_object_contention!(
            "stake_ika",
            stake_ika(
                self.publisher_address,
                &mut self.wallet,
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                self.packages.ika_supply_id,
                vec![validator_id],
            )
            .await
        );

        let client = SuiClientBuilder::default().build(&self.rpc_url).await?;
        retry_on_object_contention!(
            "request_add_validator",
            request_add_validator(
                joiner_address,
                &mut self.wallet,
                client.clone(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                validator_cap_id,
            )
            .await
        );
        tracing::info!(index, %joiner_address, %validator_id, "joiner registered on chain");

        let data_dir = self.base.join(format!("validator-{index}"));
        std::fs::create_dir_all(&data_dir)?;
        let node_config = ValidatorConfigBuilder::new()
            .with_config_directory(data_dir.clone())
            .build(
                &init,
                self.rpc_url.clone(),
                self.packages.ika_package_id,
                self.packages.ika_common_package_id,
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.ika_dwallet_coordinator_object_id,
            );
        let proc = spawn_node(index, binary, &node_config, data_dir).await?;
        self.validators.push(proc);
        self.committee.push(ValidatorSlot {
            address: joiner_address,
            validator_id,
            validator_cap_id,
        });
        Ok(index)
    }

    /// Submit `system::request_remove_validator` for the validator at
    /// `index`. The validator stays in the active set (and its process keeps
    /// running) until the next epoch boundary; pair with `wait_for_epoch`
    /// then [`Self::stop_validator`] to actually shrink the running cluster.
    pub async fn remove_validator(&mut self, index: usize) -> Result<()> {
        let slot = self
            .committee
            .get(index)
            .with_context(|| format!("validator index {index} out of range"))?
            .clone();
        let client = SuiClientBuilder::default().build(&self.rpc_url).await?;
        retry_on_object_contention!(
            "request_remove_validator",
            request_remove_validator(
                slot.address,
                &mut self.wallet,
                client.clone(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                slot.validator_cap_id,
            )
            .await
        );
        tracing::info!(index, address = %slot.address, "validator removal requested on chain");
        Ok(())
    }

    /// Stop the validator process at `index` (after it has left the
    /// committee — stopping a current committee member stalls consensus).
    pub async fn stop_validator(&mut self, index: usize) -> Result<()> {
        self.validators
            .get_mut(index)
            .with_context(|| format!("validator index {index} out of range"))?
            .stop()
            .await
    }
}

/// Serialize a `NodeConfig` to YAML in its data dir and spawn it as a child.
/// Keys serialize inline (the `*WithPath` types use in-place base64 variants),
/// so the child loads a self-contained config.
async fn spawn_node(
    index: usize,
    binary: PathBuf,
    node_config: &NodeConfig,
    data_dir: PathBuf,
) -> Result<ValidatorProcess> {
    let config_path = data_dir.join("node-config.yaml");
    let yaml = serde_yaml::to_string(node_config).context("serialize NodeConfig")?;
    std::fs::write(&config_path, yaml)
        .with_context(|| format!("write {}", config_path.display()))?;

    let admin_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        node_config.admin_interface_port,
    );
    let log_path = data_dir.join("node.log");
    let mut proc = ValidatorProcess::new(
        index,
        binary,
        config_path,
        data_dir,
        admin_addr,
        node_config.metrics_address.port(),
        log_path,
    );
    proc.start().await?;
    Ok(proc)
}
