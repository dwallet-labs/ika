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
use ika_swarm_config::sui_client::init_ika_on_sui;
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::messages_dwallet_mpc::IkaNetworkConfig;
use ika_types::sui::SystemInner;
use rand::rngs::OsRng;
use sui_sdk::SuiClient as SuiSdkClient;
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
    /// Kept alive so the persistent data dirs outlive the cluster.
    _base_dir: BaseDir,
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
            validator_binary,
            notifier_binary,
            sui_binary,
            base_dir: None,
        }
    }

    pub fn with_num_validators(mut self, n: usize) -> Self {
        assert!(n <= 4, "harness caps validators at 4");
        self.num_validators = n;
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
        let (
            ika_package_id,
            ika_common_package_id,
            ika_dwallet_2pc_mpc_package_id,
            ika_system_package_id,
            ika_system_object_id,
            ika_dwallet_coordinator_object_id,
            publisher_keypair,
        ) = init_result.context("init_ika_on_sui")?;

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
            _base_dir: base_dir,
        })
    }
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

    /// Block until the on-chain ika epoch reaches `target`. Polls the system
    /// object; epochs advance on the genesis `epoch_duration_ms` cadence.
    pub async fn wait_for_epoch(&self, target: u64, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let current = self.current_epoch().await.unwrap_or(0);
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

    /// The funded genesis publisher key, reused by the workload driver as the
    /// fee-paying user.
    pub fn publisher_keypair(&self) -> &SuiKeyPair {
        &self.publisher_keypair
    }

    pub fn ika_client(&self) -> &IkaClient<SuiSdkClient> {
        &self.ika_client
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
    let mut proc =
        ValidatorProcess::new(index, binary, config_path, data_dir, admin_addr, log_path);
    proc.start().await?;
    Ok(proc)
}
