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

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ika_config::initiation::InitiationParameters;
use ika_config::node::{NodeConfig, SuiDataSource};
use ika_protocol_config::ProtocolVersion;
use ika_sui_client::SuiBackend;
use ika_sui_client::SuiClient as IkaClient;
use ika_sui_client::metrics::SuiClientMetrics;
use ika_swarm_config::node_config_builder::{FullnodeConfigBuilder, ValidatorConfigBuilder};
use ika_swarm_config::sui_client::{
    GenesisGlobalPresignConfig, InitializedIkaSystem, PublishedIkaPackages,
    fund_address_from_faucet, init_ika_on_sui, request_add_validator,
    request_add_validator_candidate, request_remove_validator, set_global_presign_config,
    stake_ika,
};
use ika_swarm_config::validator_initialization_config::{
    ValidatorInitializationConfig, ValidatorInitializationConfigBuilder,
};
use ika_types::crypto::{AuthorityPublicKeyBytes, KeypairTraits};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyState, IkaNetworkConfig,
};
use ika_types::sui::{DWalletCoordinatorInner, SystemInner};
use rand::rngs::OsRng;
use sui_sdk::SuiClientBuilder;
use sui_sdk::wallet_context::WalletContext;
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::SuiKeyPair;

use crate::process::ValidatorProcess;
use crate::sui::SuiLocalnet;
use crate::{DEFAULT_EPOCH_DURATION_MS, DEFAULT_NUM_VALIDATORS};

// Must equal `NetworkEncryptionKeyReconfigurationData`'s `Display` in ika-core
// (`request_protocol_data.rs`), which labels the metrics scraped below. ika-core
// has no dep edge here, so a `mod tests` there anchors that string to its own
// `NETWORK_KEY_RECONFIGURATION_PROTOCOL_NAME` constant and trips if it drifts.
const NETWORK_KEY_RECONFIGURATION_PROTOCOL: &str = "Network Encryption Key Reconfiguration";

/// How long a fully-converged network-key output observation must hold
/// unchanged before `expect_network_key_output_converged` accepts it. The
/// observation set is open at first convergence (an output submitted to
/// consensus just before its author saw the quorum can still be propagating),
/// and no production watermark proves the set closed; the drain bounds that
/// propagation window with repeated re-validation instead. Consensus commit
/// latency in these clusters is well under a second, so ten seconds of
/// repeated scrapes is orders of magnitude past the in-flight window.
const NETWORK_KEY_OUTPUT_STABILIZATION: Duration = Duration::from_secs(10);

/// A running out-of-process cluster. Owns the Sui localnet, the validator
/// processes, and the notifier; tears everything down on `Drop` (each child has
/// `kill_on_drop`).
pub struct ClusterOfProcesses {
    pub sui: SuiLocalnet,
    pub validators: Vec<ValidatorProcess>,
    pub notifier: ValidatorProcess,
    network_config: IkaNetworkConfig,
    ika_client: IkaClient<SuiBackend>,
    rpc_url: String,
    /// The genesis publisher's Sui key — funded with SUI + the initial IKA
    /// supply. The workload driver reuses it as the user paying session fees.
    publisher_keypair: SuiKeyPair,
    /// On-chain registration of each validator slot, aligned with
    /// `validators` by index. Joiners append; removal leaves the slot in
    /// place (the cap stays valid, the process is just stopped).
    committee: Vec<ValidatorSlot>,
    /// hex-encoded anemo `PeerId` (network public key) of each validator,
    /// aligned with `validators` by index; joiners append. A mirrored
    /// validator's `sui_state_mirror_peers` is built from these.
    validator_peer_ids: Vec<String>,
    /// Protocol authorities aligned with `validators`. The convergence check
    /// compares exact identities, not just a count that a missing validator
    /// and an unexpected sender could accidentally satisfy.
    validator_authorities: Vec<AuthorityPublicKeyBytes>,
    /// The same validators named under the CONSENSUS-key basis. A
    /// validator's `AuthorityName` is its BLS protocol key below protocol
    /// v6 and its consensus key from v6, so a harness that knows only one
    /// basis compares a correctly-flipped cluster against the wrong
    /// expectation. Both are derived at construction from the init configs,
    /// which carry both keypairs.
    validator_consensus_authorities: Vec<AuthorityPublicKeyBytes>,
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
    /// What the genesis bootstrap writes into the on-chain
    /// `GlobalPresignConfig`. `Full` is only correct when no presign runs
    /// before protocol v4; genesis-at-v3 scenarios that exercise presigns
    /// pre-upgrade need `Empty` (the mainnet-v1.1.8 state) and apply the full
    /// config post-upgrade via [`ClusterOfProcesses::set_global_presign_config`].
    genesis_global_presign_config: GenesisGlobalPresignConfig,
    /// Boot every validator AND the notifier from an old-style (1.1.8-shape)
    /// config: `sui-rpc-url` only, no `sui-data-source`, no trust anchor —
    /// the deprecated JSON-RPC transport every mainnet node runs on rollout
    /// day. Rehearses the legacy path end-to-end on the new binary.
    legacy_sui_config: bool,
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
            genesis_global_presign_config: GenesisGlobalPresignConfig::Full,
            legacy_sui_config: false,
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

    /// Genesis protocol version. Default `ProtocolVersion::MIN` — the lowest
    /// version this binary supports; when MIN < MAX a capability vote can
    /// advance to a newer version supported by the binary's `SYSTEM_DEFAULT`.
    pub fn with_genesis_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.genesis_protocol_version = Some(v);
        self
    }

    pub fn with_base_dir(mut self, dir: PathBuf) -> Self {
        self.base_dir = Some(dir);
        self
    }

    /// Override the genesis on-chain `GlobalPresignConfig` (default `Full`).
    pub fn with_genesis_global_presign_config(
        mut self,
        config: GenesisGlobalPresignConfig,
    ) -> Self {
        self.genesis_global_presign_config = config;
        self
    }

    /// Boot the whole cluster (validators + notifier) from old-style
    /// (1.1.8-shape) configs — `sui-rpc-url` only, the legacy JSON-RPC path.
    pub fn with_legacy_sui_config(mut self) -> Self {
        self.legacy_sui_config = true;
        self
    }

    pub async fn build(self) -> Result<ClusterOfProcesses> {
        let genesis_version = self
            .genesis_protocol_version
            .unwrap_or(ProtocolVersion::MIN);
        tracing::info!(
            "[flow] bringing up {} validators (genesis v{})",
            self.num_validators,
            genesis_version.as_u64()
        );
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
            self.genesis_global_presign_config,
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

        // hex anemo PeerId of each validator (its network pubkey) — the same
        // derivation the p2p layer uses; a mirrored validator's
        // `sui_state_mirror_peers` is built from these.
        let validator_peer_ids: Vec<String> = validator_init_configs
            .iter()
            .map(|init| hex::encode(init.network_key_pair.public().0.to_bytes()))
            .collect();
        let validator_authorities = validator_init_configs
            .iter()
            .map(|init| init.key_pair.public().into())
            .collect();
        let validator_consensus_authorities = validator_init_configs
            .iter()
            .map(|init| {
                AuthorityPublicKeyBytes::from_consensus_key(init.consensus_key_pair.public())
            })
            .collect();

        // OCS verified-reads path (protocol v4): a validator with `sui-data-source`
        // set refuses to boot without a Sui trust anchor. Reconstruct the Sui
        // localnet's genesis blob over gRPC, write it into the run's base dir,
        // and seed every validator's `sui_genesis` with it, mirroring
        // IkaTestClusterBuilder. A legacy-config cluster gets NO anchor at all
        // — an old-style config with an anchor is one of the mixed shapes the
        // node rejects at boot.
        let sui_genesis_path = if self.legacy_sui_config {
            None
        } else {
            let sui_genesis = ika_sui_client::genesis::fetch_genesis_blob(&rpc_url)
                .await
                .map_err(|e| anyhow::anyhow!("fetch Sui genesis blob for OCS anchor: {e}"))?;
            let path = base.join("sui_genesis.blob");
            std::fs::write(
                &path,
                bcs::to_bytes(&sui_genesis).context("serialize Sui genesis blob")?,
            )
            .with_context(|| format!("write Sui genesis blob {}", path.display()))?;
            Some(path)
        };

        // 4. Per-validator NodeConfig on a persistent data dir, written to YAML.
        // Bound every co-located node's crypto rayon pool to a fair share of the
        // host so the validators + notifier don't oversubscribe the CPU (see
        // `rayon_threads_per_node`).
        let rayon_threads = rayon_threads_per_node(self.num_validators + 1);
        // Optional cap on each validator's concurrent dwallet-MPC computations
        // (NodeConfig.max_mpc_computation_cores). Set MAX_MPC_COMPUTATION_CORES
        // low to bound peak MEMORY when many validators are co-located on one CI
        // pod — the class-groups crypto state of concurrent computations, not
        // the thread count, is what OOMs the runner. Unset = node default.
        let max_mpc_computation_cores = std::env::var("MAX_MPC_COMPUTATION_CORES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        let mut validators = Vec::with_capacity(self.num_validators);
        for (i, init) in validator_init_configs.iter().enumerate() {
            let data_dir = base.join(format!("validator-{i}"));
            std::fs::create_dir_all(&data_dir)?;
            let mut builder = ValidatorConfigBuilder::new().with_config_directory(data_dir.clone());
            builder = match &sui_genesis_path {
                Some(path) => builder.with_sui_genesis(path.clone()),
                None => builder.with_legacy_sui_rpc_only(),
            };
            if let Some(cores) = max_mpc_computation_cores {
                builder = builder.with_max_mpc_computation_cores(cores);
            }
            let node_config = builder.build(
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
                rayon_threads,
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
        let mut notifier_builder =
            FullnodeConfigBuilder::new().with_config_directory(notifier_dir.clone());
        if self.legacy_sui_config {
            notifier_builder = notifier_builder.with_legacy_sui_rpc_only();
        }
        let notifier_config = notifier_builder.build(
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
            rayon_threads,
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
            validator_peer_ids,
            validator_authorities,
            validator_consensus_authorities,
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

/// Parses a label-less prometheus gauge line (`<metric> <value>`) into a u64.
/// Returns `None` if the metric is absent. Requires a space after the name so a
/// prefix collision with another metric (`<metric>_other`) does not match.
fn parse_labelless_gauge(body: &str, metric: &str) -> Option<u64> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let rest = line.strip_prefix(metric)?;
            if !rest.starts_with(' ') {
                return None;
            }
            rest.trim().parse::<f64>().ok().map(|v| v as u64)
        })
}

#[derive(Clone, Debug, PartialEq)]
struct PrometheusSample {
    labels: BTreeMap<String, String>,
    value: f64,
}

/// Parse exact Prometheus samples for one metric name. Prefix collisions are
/// rejected (`metric_other` is not `metric`); labels used by this harness are
/// hex/identifier strings and therefore never contain escaped commas.
fn parse_metric_samples(body: &str, metric: &str) -> Result<Vec<PrometheusSample>> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let rest = line.strip_prefix(metric)?;
            if !rest.starts_with(' ') && !rest.starts_with('{') {
                return None;
            }
            Some(rest)
        })
        .map(|rest| {
            let (labels, value) = if let Some(rest) = rest.strip_prefix('{') {
                let (raw_labels, value) = rest
                    .split_once("} ")
                    .with_context(|| format!("malformed labeled sample for {metric}: {rest}"))?;
                let labels = raw_labels
                    .split(',')
                    .map(|pair| {
                        let (name, value) = pair.split_once('=').with_context(|| {
                            format!("malformed label in sample for {metric}: {pair}")
                        })?;
                        let value = value
                            .strip_prefix('"')
                            .and_then(|value| value.strip_suffix('"'))
                            .with_context(|| {
                                format!("unquoted label in sample for {metric}: {pair}")
                            })?;
                        Ok((name.to_string(), value.to_string()))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                (labels, value)
            } else {
                (BTreeMap::new(), rest.trim())
            };
            let value = value
                .parse::<f64>()
                .with_context(|| format!("non-numeric sample for {metric}: {value}"))?;
            Ok(PrometheusSample { labels, value })
        })
        .collect()
}

fn required_unlabeled_metric(
    body: &str,
    metric_names: &[&str],
    validator: &ValidatorProcess,
) -> Result<u64> {
    for metric in metric_names {
        let samples = parse_metric_samples(body, metric)?;
        if samples.is_empty() {
            continue;
        }
        if samples.len() != 1 || !samples[0].labels.is_empty() {
            bail!(
                "validator {} metrics endpoint {} returned {} non-canonical samples for {}",
                validator.index,
                validator.metrics_endpoint(),
                samples.len(),
                metric
            );
        }
        let value = samples[0].value;
        if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
            bail!(
                "validator {} metrics endpoint {} returned invalid {} value {}",
                validator.index,
                validator.metrics_endpoint(),
                metric,
                value
            );
        }
        return Ok(value as u64);
    }
    bail!(
        "validator {} metrics endpoint {} is missing required metric (accepted names: {})",
        validator.index,
        validator.metrics_endpoint(),
        metric_names.join(", ")
    )
}

fn required_labeled_metric(
    body: &str,
    metric: &str,
    expected_labels: &[(&str, &str)],
    validator: &ValidatorProcess,
) -> Result<u64> {
    let samples = parse_metric_samples(body, metric)?;
    let matching = samples
        .into_iter()
        .filter(|sample| {
            expected_labels.iter().all(|(name, value)| {
                sample
                    .labels
                    .get(*name)
                    .is_some_and(|actual| actual == value)
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "validator {} metrics endpoint {} returned {} samples for {metric} with labels {expected_labels:?}; expected exactly one",
        validator.index,
        validator.metrics_endpoint(),
        matching.len()
    );
    let value = matching[0].value;
    ensure!(
        value.is_finite() && value >= 0.0 && value.fract() == 0.0,
        "validator {} metrics endpoint {} returned invalid {metric} value {value} with labels {expected_labels:?}",
        validator.index,
        validator.metrics_endpoint()
    );
    Ok(value as u64)
}

fn metric_samples_for_protocol(
    body: &str,
    metric: &str,
    protocol_name: &str,
) -> Result<Vec<PrometheusSample>> {
    parse_metric_samples(body, metric)?
        .into_iter()
        .map(|sample| {
            let sample_protocol = sample
                .labels
                .get("protocol_name")
                .with_context(|| format!("{metric} sample missing protocol_name label"))?;
            Ok((sample_protocol == protocol_name).then_some(sample))
        })
        .filter_map(Result::transpose)
        .collect()
}

/// Outcome of inspecting one observer's network-key output metrics.
///
/// `Incomplete` means the observer has not recorded enough yet and the caller
/// should keep polling; a hard `Err` (divergent digests, a malicious/rejected
/// report, or malformed metrics) is release-blocking and must not be retried.
/// Distinguishing the two by type keeps the retry/fail decision off fragile
/// error-string matching.
#[derive(Debug)]
enum NetworkKeyOutputConvergence {
    Incomplete(String),
    Converged {
        /// Canonical (converged) submitted-output digest per session.
        canonical: BTreeMap<String, String>,
        /// Sessions where the validator under test neither appeared in the
        /// converged submitted-output set nor recorded matching
        /// late-computation evidence. Quorum convergence alone cannot prove
        /// this validator's cross-version compatibility, so the caller keeps
        /// polling for evidence and, failing that, reports the boundary
        /// inconclusive rather than passing it silently.
        sessions_without_candidate_evidence: Vec<String>,
    },
}

/// Per-authority byte-equality evidence from one
/// `expect_network_key_output_converged` boundary. Tracked per validator
/// under test (not as a boundary-wide verdict) so a scenario whose observer
/// set changes across boundaries can still require that EVERY validator
/// under test demonstrated byte-equality somewhere.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkKeyBoundaryEvidence {
    /// Validators under test that demonstrated byte-equality at this
    /// boundary: a submitted output inside the converged quorum, or a
    /// discarded late computation whose raw output bytes match the
    /// quorum-agreed output.
    pub evidenced_authorities: BTreeSet<String>,
    /// Validators under test with no comparable output at this boundary,
    /// with the sessions/reasons. Legitimate per boundary — production
    /// finalizes at a Byzantine quorum and discards a computation finishing
    /// afterwards — but it proves nothing about output compatibility, so
    /// the scenario requires each such validator to be evidenced at some
    /// other boundary.
    pub unevidenced_authorities: BTreeMap<String, String>,
}

impl NetworkKeyBoundaryEvidence {
    pub fn is_conclusive(&self) -> bool {
        self.unevidenced_authorities.is_empty()
    }
}

fn canonical_network_key_outputs(
    body: &str,
    committee_authorities: &BTreeSet<String>,
    // The candidate under both identity bases; the cluster uses one of them
    // depending on its protocol version.
    candidate_authority: &BTreeSet<String>,
    quorum: usize,
    observer: &str,
) -> Result<NetworkKeyOutputConvergence> {
    let output_samples = metric_samples_for_protocol(
        body,
        "ika_dwallet_mpc_session_output_info",
        NETWORK_KEY_RECONFIGURATION_PROTOCOL,
    )?;
    if output_samples.is_empty() {
        return Ok(NetworkKeyOutputConvergence::Incomplete(format!(
            "{observer} is missing network-key output observations"
        )));
    }

    // An absent envelope gauge means the observer has not recorded the full
    // report yet (retry). Malformed or duplicated samples are hard failures.
    let envelope_values = |metric: &str| -> Result<Option<BTreeMap<(String, String), u64>>> {
        let samples =
            metric_samples_for_protocol(body, metric, NETWORK_KEY_RECONFIGURATION_PROTOCOL)?;
        if samples.is_empty() {
            return Ok(None);
        }
        let mut values = BTreeMap::new();
        for sample in samples {
            let session = sample
                .labels
                .get("session_id")
                .cloned()
                .with_context(|| format!("{metric} sample missing session_id label"))?;
            let authority = sample
                .labels
                .get("authority")
                .cloned()
                .with_context(|| format!("{metric} sample missing authority label"))?;
            ensure!(
                sample.value.is_finite() && sample.value >= 0.0 && sample.value.fract() == 0.0,
                "{metric} sample for session {session} authority {authority} has invalid value {}",
                sample.value
            );
            ensure!(
                values
                    .insert((session.clone(), authority.clone()), sample.value as u64)
                    .is_none(),
                "{observer} has duplicate {metric} samples for session {session} authority {authority}"
            );
        }
        Ok(Some(values))
    };
    let (Some(malicious), Some(rejected)) = (
        envelope_values("ika_dwallet_mpc_session_reported_malicious_actors")?,
        envelope_values("ika_dwallet_mpc_session_output_rejected")?,
    ) else {
        return Ok(NetworkKeyOutputConvergence::Incomplete(format!(
            "{observer} is missing required network-key envelope samples"
        )));
    };

    // Late-computation evidence: a local output the observer computed after
    // the quorum already completed the session. Production discards it
    // without submission and exports its raw-output-bytes digest next to the
    // quorum output's raw-output-bytes digest. Both label values live in the
    // raw-bytes domain — comparable with each other, deliberately NOT with
    // the envelope `output_digest` labels parsed above. Every sample is
    // validated fail-closed regardless of whether it ends up used as
    // evidence: a divergent or malicious-reporting late output is
    // release-blocking information wherever it appears.
    let late_samples = metric_samples_for_protocol(
        body,
        "ika_dwallet_mpc_session_late_output_info",
        NETWORK_KEY_RECONFIGURATION_PROTOCOL,
    )?;
    let late_malicious = envelope_values("ika_dwallet_mpc_session_late_output_malicious_actors")?;
    // Accumulated per (session, authority): the locally computed digest all
    // samples must agree on, and whether any sample carries a known (and,
    // enforced below, equal) quorum digest. Superseded gauge children survive
    // in the registry until the epoch reset, so one key can legitimately
    // expose an early `unknown`-quorum pair next to the later compared pair —
    // samples only conflict when their locally computed digests differ.
    let mut late_outputs: BTreeMap<(String, String), (String, bool)> = BTreeMap::new();
    for sample in late_samples {
        ensure!(
            sample.value == 1.0,
            "{observer} late-output sample has value {}, expected 1",
            sample.value
        );
        let label = |name: &str| -> Result<String> {
            sample
                .labels
                .get(name)
                .cloned()
                .with_context(|| format!("late-output sample missing {name} label"))
        };
        let session = label("session_id")?;
        let authority = label("authority")?;
        let output_digest = label("output_digest")?;
        let quorum_output_digest = label("quorum_output_digest")?;
        if quorum_output_digest != "unknown" {
            ensure!(
                output_digest == quorum_output_digest,
                "{observer}: authority {authority} computed a late network-key output for session {session} that DIVERGES from the quorum-agreed output: local raw-output digest {output_digest} vs quorum raw-output digest {quorum_output_digest}"
            );
        }
        let malicious_count = late_malicious
            .as_ref()
            .and_then(|values| values.get(&(session.clone(), authority.clone())))
            .copied();
        match malicious_count {
            // The info and malicious gauges are exported together; a scrape
            // can only race the refresh, so retry rather than failing.
            None => {
                return Ok(NetworkKeyOutputConvergence::Incomplete(format!(
                    "{observer} has a late-output sample for session {session} authority {authority} without its malicious-actor gauge yet"
                )));
            }
            Some(0) => {}
            Some(count) => bail!(
                "{observer}: authority {authority}'s late network-key output for session {session} reported {count} malicious actors"
            ),
        }
        let (recorded_output_digest, matched_quorum) = late_outputs
            .entry((session.clone(), authority.clone()))
            .or_insert_with(|| (output_digest.clone(), false));
        ensure!(
            *recorded_output_digest == output_digest,
            "{observer} has conflicting late-output samples for session {session} authority {authority}: the validator computed {recorded_output_digest} and {output_digest} across attempts"
        );
        *matched_quorum |= quorum_output_digest != "unknown";
    }

    let mut outputs_by_session: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for sample in output_samples {
        ensure!(
            sample.value == 1.0,
            "{observer} output-info sample has value {}, expected 1",
            sample.value
        );
        let session = sample
            .labels
            .get("session_id")
            .cloned()
            .context("output-info sample missing session_id label")?;
        let authority = sample
            .labels
            .get("authority")
            .cloned()
            .context("output-info sample missing authority label")?;
        let digest = sample
            .labels
            .get("output_digest")
            .cloned()
            .context("output-info sample missing output_digest label")?;
        let previous = outputs_by_session
            .entry(session.clone())
            .or_default()
            .insert(authority.clone(), digest.clone());
        ensure!(
            previous.as_ref().is_none_or(|previous| previous == &digest),
            "{observer} observed conflicting digests for session {session} authority {authority}"
        );
    }

    ensure!(
        candidate_authority
            .iter()
            .any(|name| committee_authorities.contains(name)),
        "validator under test {candidate_authority:?} is not a committee member: \
         {committee_authorities:?}"
    );

    let mut canonical = BTreeMap::new();
    let mut sessions_without_candidate_evidence = Vec::new();
    for (session, outputs) in outputs_by_session {
        let observed_authorities = outputs.keys().cloned().collect::<BTreeSet<_>>();
        // A validator submitting a network-key output for a session whose
        // committee it isn't in is a real fault, not a propagation delay.
        ensure!(
            observed_authorities.is_subset(committee_authorities),
            "{observer} observed out-of-committee authorities for network-key session {session}: observed={observed_authorities:?}, committee={committee_authorities:?}"
        );
        // Reconfiguration finalizes at a Byzantine quorum and does not wait:
        // a validator still computing when quorum forms marks its session
        // complete (on seeing the quorum in consensus) and discards its own
        // still-in-flight output, so ANY honest validator — including the
        // one under test — legitimately never submits. Completeness therefore
        // requires only a finalizing quorum; the validator under test's
        // byte-equality is tracked separately below, via its submitted
        // output when present or its discarded late computation's digest
        // otherwise, and the boundary is reported inconclusive (never
        // silently passed, never failed) when neither exists.
        if observed_authorities.len() < quorum {
            return Ok(NetworkKeyOutputConvergence::Incomplete(format!(
                "{observer} has not yet observed a finalizing quorum for network-key session {session}: observed={observed_authorities:?}, quorum={quorum}"
            )));
        }
        let digests: BTreeSet<_> = outputs.values().cloned().collect();
        ensure!(
            digests.len() == 1,
            "{observer} observed divergent per-authority outputs for network-key session {session}: {outputs:?}"
        );
        for authority in outputs.keys() {
            let key = (session.clone(), authority.clone());
            ensure!(
                malicious.get(&key) == Some(&0),
                "{observer} observed authority {authority} report a non-zero or missing malicious set for session {session}: {:?}",
                malicious.get(&key)
            );
            ensure!(
                rejected.get(&key) == Some(&0),
                "{observer} observed authority {authority} submit a rejected or missing output for session {session}: {:?}",
                rejected.get(&key)
            );
        }
        if !candidate_authority
            .iter()
            .any(|name| outputs.contains_key(name))
        {
            match candidate_authority
                .iter()
                .find_map(|name| late_outputs.get(&(session.clone(), name.clone())))
            {
                // Validated above: digest equals the quorum digest and the
                // late malicious count is zero — byte-level evidence that the
                // candidate computed the same output the quorum agreed on.
                Some((_, matched_quorum)) if *matched_quorum => {}
                Some(_) => sessions_without_candidate_evidence.push(format!(
                    "{session} (late output recorded without a quorum digest to compare against)"
                )),
                None => sessions_without_candidate_evidence.push(format!(
                    "{session} (no submitted output and no late-computation digest yet)"
                )),
            }
        }
        canonical.insert(
            session,
            digests
                .into_iter()
                .next()
                .expect("one digest after length check"),
        );
    }
    Ok(NetworkKeyOutputConvergence::Converged {
        canonical,
        sessions_without_candidate_evidence,
    })
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

    async fn coordinator_snapshot(
        &self,
    ) -> Result<(
        ika_types::sui::system_inner_v1::DWalletCoordinatorInnerV1,
        BTreeMap<ObjectID, DWalletNetworkEncryptionKey>,
    )> {
        let (_, coordinator) = self
            .ika_client
            .get_dwallet_coordinator_inner()
            .await
            .map_err(|error| anyhow::anyhow!("get_dwallet_coordinator_inner: {error}"))?;
        let keys = self
            .ika_client
            .get_dwallet_mpc_network_keys(&coordinator)
            .await
            .map_err(|error| anyhow::anyhow!("get_dwallet_mpc_network_keys: {error}"))?;
        let DWalletCoordinatorInner::V1(inner) = coordinator;
        Ok((inner, keys.into_iter().collect()))
    }

    /// Assert every expected validator process is still running and its admin
    /// endpoint is reachable. This intentionally does not filter to running
    /// processes: a dead expected validator is the failure being tested.
    pub async fn expect_all_validators_healthy(&self) -> Result<()> {
        for validator in &self.validators {
            validator.expect_healthy().await?;
        }
        Ok(())
    }

    /// Wait until every validator's local epoch-store has entered `target`.
    /// On-chain epoch progress is insufficient: a quorum can advance while one
    /// validator remains on the previous epoch. v1.1.8 exported
    /// `current_epoch`; current builds export the renamed `ika_current_epoch`.
    pub async fn wait_for_all_validators_local_epoch(
        &self,
        target: u64,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut lagging = Vec::new();
            for validator in &self.validators {
                if !validator.is_running() {
                    bail!(
                        "validator {} is not running while waiting for local epoch {} (metrics endpoint {})",
                        validator.index,
                        target,
                        validator.metrics_endpoint()
                    );
                }
                let body = validator.metrics().await?;
                let epoch = required_unlabeled_metric(
                    &body,
                    &["ika_current_epoch", "current_epoch"],
                    validator,
                )?;
                if epoch != target {
                    lagging.push((validator.index, validator.metrics_endpoint(), epoch));
                }
            }
            if lagging.is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "validators did not all enter local epoch {target} within {timeout:?}: {lagging:?}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Fail if any validator locally reports a protocol version above the
    /// supplied ceiling. The metric exists under the same name in v1.1.8 and
    /// current builds.
    pub async fn expect_all_validators_protocol_version_at_most(&self, ceiling: u64) -> Result<()> {
        for validator in &self.validators {
            let body = validator.metrics().await?;
            let version =
                required_unlabeled_metric(&body, &["ika_current_protocol_version"], validator)?;
            if version > ceiling {
                bail!(
                    "validator {} at {} reports protocol version {}, above ceiling {}",
                    validator.index,
                    validator.metrics_endpoint(),
                    version,
                    ceiling
                );
            }
        }
        Ok(())
    }

    /// Assert the epoch's mid-epoch network-key reconfiguration has not been
    /// initiated yet. A key may still be `NetworkReconfigurationCompleted`
    /// from the previous epoch, so the epoch-scoped next-committee marker and
    /// completion counter are the deterministic witnesses.
    pub async fn expect_network_key_reconfiguration_not_started(&self, epoch: u64) -> Result<()> {
        let (coordinator, keys) = self.coordinator_snapshot().await?;
        ensure!(
            coordinator.current_epoch == epoch,
            "expected coordinator epoch {epoch} before network-key reconfiguration, got {}",
            coordinator.current_epoch
        );
        ensure!(
            !keys.is_empty(),
            "coordinator epoch {epoch} has no network encryption keys"
        );
        ensure!(
            coordinator.next_epoch_active_committee.is_none(),
            "epoch {epoch} mid-epoch reconfiguration was already initiated"
        );
        ensure!(
            coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed == 0,
            "epoch {epoch} already reports {} completed network-key reconfigurations",
            coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed
        );
        Ok(())
    }

    /// Wait until the requested epoch's network keys are visibly in the
    /// `AwaitingNetworkReconfiguration` state. This makes the mixed-version
    /// overlap deterministic: the binary swap is complete before the harness
    /// witnesses the real on-chain reshare request.
    pub async fn wait_for_network_key_reconfiguration_started(
        &self,
        epoch: u64,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (coordinator, keys) = self.coordinator_snapshot().await?;
            ensure!(
                coordinator.current_epoch == epoch,
                "expected coordinator epoch {epoch} while waiting for network-key reconfiguration start, got {}",
                coordinator.current_epoch
            );
            ensure!(
                !keys.is_empty(),
                "coordinator epoch {epoch} has no network encryption keys"
            );
            let awaiting = keys
                .values()
                .filter(|key| {
                    key.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration
                })
                .count();
            if awaiting == keys.len() {
                tracing::info!(
                    epoch,
                    keys = keys.len(),
                    "network-key reconfiguration started"
                );
                return Ok(());
            }
            if coordinator.next_epoch_active_committee.is_some()
                && coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed > 0
            {
                bail!(
                    "network-key reconfiguration in epoch {epoch} completed before the harness observed every key in the started state"
                );
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "network-key reconfiguration did not start in epoch {epoch} within {timeout:?}; states={:?}",
                    keys.values().map(|key| &key.state).collect::<Vec<_>>()
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Wait for the same epoch's on-chain network-key reconfiguration and all
    /// system sessions to complete. Observing this before the epoch boundary
    /// prevents quorum progress in the next epoch from masking a stranded
    /// minority validator.
    pub async fn wait_for_network_key_reconfiguration_completed(
        &self,
        epoch: u64,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (coordinator, keys) = self.coordinator_snapshot().await?;
            ensure!(
                coordinator.current_epoch == epoch,
                "coordinator advanced to epoch {} before the harness observed epoch {epoch} network-key reconfiguration completion",
                coordinator.current_epoch
            );
            let all_keys_completed = !keys.is_empty()
                && keys.values().all(|key| {
                    key.state == DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
                });
            let expected = coordinator.dwallet_network_encryption_keys.size;
            let completed =
                coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed;
            let system = &coordinator.sessions_manager.system_sessions_keeper;
            if all_keys_completed
                && completed == expected
                && system.started_sessions_count == system.completed_sessions_count
            {
                tracing::info!(
                    epoch,
                    completed,
                    system_sessions = system.completed_sessions_count,
                    "network-key reconfiguration completed"
                );
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "network-key reconfiguration did not complete in epoch {epoch} within {timeout:?}: key_states={:?}, completed={completed}/{expected}, system_sessions={}/{}",
                    keys.values().map(|key| &key.state).collect::<Vec<_>>(),
                    system.completed_sessions_count,
                    system.started_sessions_count
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Assert the malicious-actor gauge exactly on the specified validator
    /// observers. Historical v1.1.8 does not export this gauge, so callers name
    /// the current-binary observer(s); missing metrics still fail closed.
    pub async fn expect_malicious_actors_exactly(
        &self,
        observer_indices: &[usize],
        expected: u64,
    ) -> Result<()> {
        ensure!(
            !observer_indices.is_empty(),
            "no malicious-metric observers supplied"
        );
        for index in observer_indices {
            let validator = self
                .validators
                .get(*index)
                .with_context(|| format!("validator index {index} out of range"))?;
            let body = validator.metrics().await?;
            let actual = required_unlabeled_metric(
                &body,
                &["ika_dwallet_mpc_malicious_actors_count"],
                validator,
            )?;
            ensure!(
                actual == expected,
                "validator {} at {} reports {} malicious actors; expected exactly {}",
                validator.index,
                validator.metrics_endpoint(),
                actual,
                expected
            );
        }
        Ok(())
    }

    pub async fn expect_malicious_actors_at_least(
        &self,
        observer_indices: &[usize],
        minimum: u64,
    ) -> Result<()> {
        ensure!(
            !observer_indices.is_empty(),
            "no malicious-metric observers supplied"
        );
        let mut maximum = 0;
        for index in observer_indices {
            let validator = self
                .validators
                .get(*index)
                .with_context(|| format!("validator index {index} out of range"))?;
            let body = validator.metrics().await?;
            let actual = required_unlabeled_metric(
                &body,
                &["ika_dwallet_mpc_malicious_actors_count"],
                validator,
            )?;
            maximum = maximum.max(actual);
        }
        ensure!(
            maximum >= minimum,
            "malicious-metric observers {observer_indices:?} reported maximum {maximum}; expected at least {minimum}"
        );
        Ok(())
    }

    /// Assert every authority that submitted a network-key reconfiguration
    /// output submitted the same canonical bytes for every observed session.
    /// The current-binary observer records individual consensus reports from
    /// all committee members, including literal historical binaries; this
    /// catches a 3-vs-1 split even when the majority result lets the chain
    /// keep advancing.
    ///
    /// Completeness requires a finalizing quorum, not the whole committee:
    /// production finalizes at a Byzantine quorum and discards a local
    /// computation that finishes afterwards, so ANY honest validator —
    /// including the one under test — can legitimately end a session with no
    /// submitted output. The validator under test's byte-equality is
    /// therefore evidenced either by its submitted output inside the
    /// converged set, or by the raw-bytes digest production records when it
    /// discards that validator's late `Finalize` result. When neither exists
    /// by the deadline the boundary returns
    /// [`NetworkKeyCompatibilityEvidence::Inconclusive`] — it neither fails
    /// (the ordering is legitimate) nor counts as compatibility proof (the
    /// scenario requires at least one conclusive boundary).
    ///
    /// The observation set is open when convergence is first reached:
    /// finalization happens at a Byzantine quorum, so a validator's output
    /// submitted to consensus just before it saw the quorum can still be
    /// propagating. Observers keep recording (and exporting) such late
    /// outputs after session completion, so instead of returning on the
    /// first converged scrape this holds the converged result through a
    /// stabilization window, re-validating every scrape — a late-arriving
    /// divergent output fails the run instead of landing after success.
    pub async fn expect_network_key_output_converged(
        &self,
        observer_indices: &[usize],
        timeout: Duration,
    ) -> Result<NetworkKeyBoundaryEvidence> {
        ensure!(
            !observer_indices.is_empty(),
            "no output-convergence observers supplied"
        );
        // Both bases: the cluster names its authorities under whichever one
        // its protocol version selects, and this check exists to catch a
        // FOREIGN authority submitting an output — which either naming still
        // catches, since a non-member appears in neither set.
        let committee_authorities: BTreeSet<_> = self
            .validator_authorities
            .iter()
            .chain(self.validator_consensus_authorities.iter())
            .map(ToString::to_string)
            .collect();
        // Byzantine quorum of the committee. These scenarios run an
        // equal-weight committee, so a plain member count matches the
        // access-structure threshold (n - floor((n-1)/3)). Counted from the
        // VALIDATORS, not from `committee_authorities`: that set holds each
        // member under both identity bases, so its length is twice the
        // committee size and would demand a quorum no run can reach.
        let members = self.validator_authorities.len();
        let quorum = members - members.saturating_sub(1) / 3;
        let expected_epoch = self.current_epoch().await?;
        let deadline = tokio::time::Instant::now() + timeout;
        // First fully-converged canonical result and when it was first
        // observed; success requires it to survive unchanged for the whole
        // stabilization window below.
        let mut stable: Option<(BTreeMap<String, String>, tokio::time::Instant)> = None;
        // The last evidence observed AFTER the converged result already held
        // through the full stabilization window. Once set, an epoch advance
        // is normal scenario progress ending the observation window (the
        // next epoch's metrics reset wipes these series), not a failure —
        // return this evidence instead of racing the boundary.
        let mut stabilized_evidence: Option<NetworkKeyBoundaryEvidence> = None;
        loop {
            if self.current_epoch().await? != expected_epoch {
                if let Some(evidence) = stabilized_evidence {
                    return Ok(evidence);
                }
                bail!(
                    "coordinator advanced beyond epoch {expected_epoch} before network-key output observations converged"
                );
            }
            let mut canonical_by_session: Option<BTreeMap<String, String>> = None;
            let mut incomplete = Vec::new();
            let mut evidence = NetworkKeyBoundaryEvidence::default();
            for index in observer_indices {
                let validator = self
                    .validators
                    .get(*index)
                    .with_context(|| format!("validator index {index} out of range"))?;
                let body = validator.metrics().await?;
                let observer = format!(
                    "validator {} metrics endpoint {}",
                    validator.index,
                    validator.metrics_endpoint()
                );
                // Each observer is a validator under test (the upgraded
                // binary); its own authority is the candidate whose
                // byte-equality with the v1.1.8 quorum this boundary tries
                // to witness.
                let candidate_authority: BTreeSet<String> = [
                    self.validator_authorities.get(*index),
                    self.validator_consensus_authorities.get(*index),
                ]
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect();
                ensure!(
                    !candidate_authority.is_empty(),
                    "validator index {index} out of range"
                );
                let (observer_canonical, observer_missing) = match canonical_network_key_outputs(
                    &body,
                    &committee_authorities,
                    &candidate_authority,
                    quorum,
                    &observer,
                )
                .with_context(|| format!("validate network-key convergence from {observer}"))?
                {
                    NetworkKeyOutputConvergence::Converged {
                        canonical,
                        sessions_without_candidate_evidence,
                    } => (canonical, sessions_without_candidate_evidence),
                    NetworkKeyOutputConvergence::Incomplete(reason) => {
                        incomplete.push(reason);
                        continue;
                    }
                };
                let candidate_label = candidate_authority
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_default();
                if observer_missing.is_empty() {
                    evidence.evidenced_authorities.insert(candidate_label);
                } else {
                    evidence.unevidenced_authorities.insert(
                        candidate_label,
                        format!(
                            "validator {}: {}",
                            validator.index,
                            observer_missing.join(", ")
                        ),
                    );
                }

                if let Some(expected) = &canonical_by_session {
                    ensure!(
                        expected == &observer_canonical,
                        "network-key observers disagree: expected {expected:?}, validator {} at {} reported {observer_canonical:?}",
                        validator.index,
                        validator.metrics_endpoint()
                    );
                } else {
                    canonical_by_session = Some(observer_canonical);
                }
            }
            if incomplete.is_empty() {
                let canonical = canonical_by_session
                    .context("converged with no observers — observer list cannot be empty here")?;
                match &stable {
                    Some((expected, since)) => {
                        // Late outputs that agree grow the observed set without
                        // changing the canonical digests; a late divergent
                        // output already failed hard inside
                        // `canonical_network_key_outputs` (digest-equality is a
                        // hard error). A changed canonical map here means a
                        // session appeared or changed mid-drain — fail closed.
                        ensure!(
                            expected == &canonical,
                            "canonical network-key outputs changed during the stabilization window: first {expected:?}, now {canonical:?}"
                        );
                        if since.elapsed() >= NETWORK_KEY_OUTPUT_STABILIZATION {
                            if evidence.is_conclusive() {
                                return Ok(evidence);
                            }
                            // Candidate evidence can still arrive — the
                            // straggler's computation may still be running
                            // and its discarded-output digest is recorded the
                            // moment it finishes. Keep polling (re-validating
                            // the converged result each scrape) until the
                            // deadline before returning the boundary with
                            // unevidenced validators.
                            if tokio::time::Instant::now() >= deadline {
                                return Ok(evidence);
                            }
                            stabilized_evidence = Some(evidence);
                        }
                    }
                    None => stable = Some((canonical, tokio::time::Instant::now())),
                }
            } else {
                // A fresh incomplete observation after convergence means a new
                // network-key session surfaced; its outputs must converge and
                // stabilize too — the previously stabilized evidence no longer
                // covers the full session set.
                stable = None;
                stabilized_evidence = None;
                if tokio::time::Instant::now() >= deadline {
                    bail!(
                        "network-key output observations did not become complete within {timeout:?}: {}",
                        incomplete.join("; ")
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Assert both chain and local-observer views have no stranded network-key
    /// work for `epoch`. The chain checks system-session accounting and every
    /// key state; the current observer checks always-present pending and
    /// instantiation gauges.
    pub async fn expect_no_pending_network_key_reconfiguration(
        &self,
        epoch: u64,
        observer_indices: &[usize],
        timeout: Duration,
    ) -> Result<()> {
        ensure!(
            !observer_indices.is_empty(),
            "no network-key pending-state observers supplied"
        );
        let (coordinator, keys) = self.coordinator_snapshot().await?;
        ensure!(
            coordinator.current_epoch == epoch,
            "expected coordinator epoch {epoch}, got {}",
            coordinator.current_epoch
        );
        ensure!(
            !keys.is_empty(),
            "coordinator epoch {epoch} has no network encryption keys"
        );
        ensure!(
            keys.values().all(|key| key.state
                == DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted),
            "epoch {epoch} has non-completed network-key states: {:?}",
            keys.values().map(|key| &key.state).collect::<Vec<_>>()
        );
        ensure!(
            coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed
                == coordinator.dwallet_network_encryption_keys.size,
            "epoch {epoch} completed network-key count {}/{}",
            coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed,
            coordinator.dwallet_network_encryption_keys.size
        );
        let system = &coordinator.sessions_manager.system_sessions_keeper;
        ensure!(
            system.started_sessions_count == system.completed_sessions_count,
            "epoch {epoch} has stranded immediate/system sessions: completed {}/started {}",
            system.completed_sessions_count,
            system.started_sessions_count
        );

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut pending = Vec::new();
            for index in observer_indices {
                let validator = self
                    .validators
                    .get(*index)
                    .with_context(|| format!("validator index {index} out of range"))?;
                let body = validator.metrics().await?;
                let protocol_pending = required_labeled_metric(
                    &body,
                    "ika_dwallet_mpc_protocol_sessions_pending",
                    &[("protocol_name", NETWORK_KEY_RECONFIGURATION_PROTOCOL)],
                    validator,
                )?;
                let instantiations = required_unlabeled_metric(
                    &body,
                    &["ika_dwallet_mpc_network_key_instantiations_in_flight"],
                    validator,
                )?;
                for (metric, value) in [
                    (
                        "network-key reconfiguration sessions pending",
                        protocol_pending,
                    ),
                    ("network-key instantiations in flight", instantiations),
                ] {
                    if value != 0 {
                        pending.push(format!(
                            "validator {} at {} reports {metric}={value}",
                            validator.index,
                            validator.metrics_endpoint()
                        ));
                    }
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            // Check the epoch guard AFTER computing pending so the diagnostic
            // names the gauge that never drained, not just "advanced".
            let current_epoch = self.current_epoch().await?;
            ensure!(
                current_epoch == epoch,
                "coordinator advanced to epoch {current_epoch} before epoch {epoch} local network-key work drained; still pending: {}",
                pending.join("; ")
            );
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "network-key reconfiguration remained pending within {timeout:?}: {}",
                    pending.join("; ")
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// The minimum canonical network DKG output version reported across all
    /// running validators' `/metrics`. Returns 0 if a running validator has not
    /// reported the gauge yet (or is unreachable), so a poller keeps waiting
    /// until the whole committee has migrated. The off-chain handoff carries the
    /// migrated version; the on-chain copy stays V2, so this metric — not a Sui
    /// read — is how the V2->V3 migration is observed.
    pub async fn min_canonical_network_dkg_output_version(&self) -> u64 {
        let http = reqwest::Client::new();
        let mut min: Option<u64> = None;
        for proc in self.validators.iter().filter(|p| p.is_running()) {
            let url = format!("http://127.0.0.1:{}/metrics", proc.metrics_port());
            let version = match http.get(&url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(body) => parse_labelless_gauge(
                        &body,
                        "ika_dwallet_mpc_network_encryption_key_canonical_dkg_output_version",
                    )
                    .unwrap_or(0),
                    Err(_) => 0,
                },
                Err(_) => 0,
            };
            min = Some(min.map_or(version, |m| m.min(version)));
        }
        min.unwrap_or(0)
    }

    /// The minimum installed network-key reconfiguration output version
    /// reported across all running validators' `/metrics` (3 =
    /// pre-aggregation, 4 = aggregated, 0 = not installed / unreachable).
    /// Same polling semantics as
    /// [`Self::min_canonical_network_dkg_output_version`].
    pub async fn min_latest_reconfiguration_output_version(&self) -> u64 {
        let http = reqwest::Client::new();
        let mut min: Option<u64> = None;
        for proc in self.validators.iter().filter(|p| p.is_running()) {
            let url = format!("http://127.0.0.1:{}/metrics", proc.metrics_port());
            let version = match http.get(&url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(body) => parse_labelless_gauge(
                        &body,
                        "ika_dwallet_mpc_network_encryption_key_latest_reconfiguration_output_version",
                    )
                    .unwrap_or(0),
                    Err(_) => 0,
                },
                Err(_) => 0,
            };
            min = Some(min.map_or(version, |m| m.min(version)));
        }
        min.unwrap_or(0)
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
        tracing::info!("[flow] waiting for epoch {target} (timeout {timeout:?})");
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

    pub fn ika_client(&self) -> &IkaClient<SuiBackend> {
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
        self.add_joiner_validator_inner(binary, None).await
    }

    /// Like [`Self::add_joiner_validator`], but the joiner boots peer-only
    /// `SuiStateMirrored`, reading verified Sui state through the validators at
    /// `direct_indices` (the relay servers) instead of a direct uplink. It has
    /// no static p2p seed peers: the running validators continuously feed the
    /// on-chain `pending_active_set` into their trusted peers, so a direct
    /// validator dials this registered-but-not-yet-active joiner (inbound),
    /// which is what its `wait_for_specific_peers` boot gate needs.
    pub async fn add_joiner_validator_mirrored(
        &mut self,
        binary: PathBuf,
        direct_indices: &[usize],
    ) -> Result<usize> {
        let mirror_peers = self.peer_ids_of(direct_indices)?;
        self.add_joiner_validator_inner(binary, Some(mirror_peers))
            .await
    }

    async fn add_joiner_validator_inner(
        &mut self,
        binary: PathBuf,
        mirror_peers: Option<Vec<String>>,
    ) -> Result<usize> {
        tracing::info!("[flow] joining new validator (candidate -> stake -> activate)");
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
        // Same OCS v4 trust anchor as the genesis validators (see `build`): the
        // genesis checkpoint is immutable, so re-fetch the blob for the joiner
        // (a legacy-config cluster wrote none at build time) and write it into
        // the joiner's own data dir.
        let sui_genesis = ika_sui_client::genesis::fetch_genesis_blob(&self.rpc_url)
            .await
            .map_err(|e| anyhow::anyhow!("fetch Sui genesis blob for joiner OCS anchor: {e}"))?;
        let sui_genesis_path = data_dir.join("sui_genesis.blob");
        std::fs::write(
            &sui_genesis_path,
            bcs::to_bytes(&sui_genesis).context("serialize Sui genesis blob")?,
        )
        .with_context(|| format!("write Sui genesis blob {}", sui_genesis_path.display()))?;
        // Same MPC-computation-core cap as the genesis validators (see `build`).
        let max_mpc_computation_cores = std::env::var("MAX_MPC_COMPUTATION_CORES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        let mut builder = ValidatorConfigBuilder::new()
            .with_config_directory(data_dir.clone())
            .with_sui_genesis(sui_genesis_path);
        if let Some(cores) = max_mpc_computation_cores {
            builder = builder.with_max_mpc_computation_cores(cores);
        }
        // A mirrored joiner reads Sui peer-only over the relay (no direct
        // uplink) from the given direct validators, instead of the default
        // `SuiStateDirect` path.
        if let Some(mirror_peers) = &mirror_peers {
            builder = builder
                .with_sui_data_source(SuiDataSource::SuiStateMirrored {
                    fallback_grpc_url: None,
                })
                .with_sui_state_mirror_peers(mirror_peers.clone());
        }
        let node_config = builder.build(
            &init,
            self.rpc_url.clone(),
            self.packages.ika_package_id,
            self.packages.ika_common_package_id,
            self.packages.ika_dwallet_2pc_mpc_package_id,
            self.packages.ika_system_package_id,
            self.system.ika_system_object_id,
            self.system.ika_dwallet_coordinator_object_id,
        );
        let proc = spawn_node(
            index,
            binary,
            &node_config,
            data_dir,
            // existing validators (`index`) + this joiner + the notifier.
            rayon_threads_per_node(index + 2),
        )
        .await?;
        self.validators.push(proc);
        self.committee.push(ValidatorSlot {
            address: joiner_address,
            validator_id,
            validator_cap_id,
        });
        self.validator_peer_ids
            .push(hex::encode(init.network_key_pair.public().0.to_bytes()));
        self.validator_authorities
            .push(init.key_pair.public().into());
        Ok(index)
    }

    /// The hex anemo PeerIds of the validators at `indices` — used as a
    /// mirrored validator's `sui_state_mirror_peers` (its set of relay
    /// servers).
    pub fn peer_ids_of(&self, indices: &[usize]) -> Result<Vec<String>> {
        indices
            .iter()
            .map(|&i| {
                self.validator_peer_ids
                    .get(i)
                    .cloned()
                    .with_context(|| format!("peer id for validator {i} out of range"))
            })
            .collect()
    }

    /// Swap the validator at `index` to `new_binary` AND rewrite its config to
    /// read Sui peer-only over the verified relay from `mirror_peers`. Flips a
    /// validator direct -> mirrored at an upgrade swap (see
    /// [`ValidatorProcess::swap_binary_mirrored`]).
    pub async fn swap_and_mirror(
        &mut self,
        index: usize,
        new_binary: PathBuf,
        mirror_peers: Vec<String>,
    ) -> Result<()> {
        self.validators
            .get_mut(index)
            .with_context(|| format!("validator index {index} out of range"))?
            .swap_binary_mirrored(new_binary, mirror_peers)
            .await
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

    /// Write the production (`Full`) curve/algorithm set into the on-chain
    /// `GlobalPresignConfig`, routing those presigns to the validators'
    /// internal pool. Only call once the network runs protocol v4+ (the pool
    /// only fills with `internal_presign_sessions` on) — the same ordering a
    /// real mainnet rollout from v1.1.8 must follow.
    pub async fn set_global_presign_config(&mut self) -> Result<()> {
        let client = SuiClientBuilder::default().build(&self.rpc_url).await?;
        let (curve_to_signature_algorithms_for_dkg, curve_to_signature_algorithms_for_imported_key) =
            GenesisGlobalPresignConfig::Full.curve_to_signature_algorithm_maps();
        retry_on_object_contention!(
            "set_global_presign_config",
            set_global_presign_config(
                self.publisher_address,
                &mut self.wallet,
                client.clone(),
                self.packages.ika_system_package_id,
                self.system.ika_system_object_id,
                self.system.init_system_shared_version,
                self.system
                    .dwallet_2pc_mpc_coordinator_initial_shared_version,
                self.system.protocol_cap_id,
                self.packages.ika_dwallet_2pc_mpc_package_id,
                self.system.ika_dwallet_coordinator_object_id,
                curve_to_signature_algorithms_for_dkg.clone(),
                curve_to_signature_algorithms_for_imported_key.clone(),
            )
            .await
        );
        tracing::info!("global presign config set on chain (full production config)");
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
    rayon_threads: usize,
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
        rayon_threads,
    );
    proc.start().await?;
    Ok(proc)
}

/// `RAYON_NUM_THREADS` budget for each spawned node, given how many node
/// processes will share this host. The harness co-locates every validator
/// (plus the notifier) on one machine, and no node enforces the minimum-CPU
/// core reserve here (old binaries are built `--no-default-features`; current
/// ones runtime-gate it to the ika testnet/mainnet networks) — so each one's
/// rayon pool otherwise defaults to ALL
/// cores (`ika-core`'s `runtime.rs`). With the parallel crypto feature active
/// that oversubscribes the CPU by the node count, starving the async runtimes
/// (and, on CI, the runner agent itself → "runner lost communication"). Hand
/// each node a fair slice of ~75% of the cores, reserving the rest for the
/// async/IO work across all the processes — the out-of-process analogue of the
/// in-process swarm's core reserve.
fn rayon_threads_per_node(node_count: usize) -> usize {
    // The pod's REAL CPU budget is the cgroup v2 CFS quota (`cpu.max` =
    // "<quota> <period>"); on a throttled CI runner this is below the host core
    // count that `available_parallelism()` reports, and sizing the per-node
    // thread bound off host cores oversubscribes the pod. Prefer the quota.
    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4);
    let cgroup_quota = std::fs::read_to_string("/sys/fs/cgroup/cpu.max")
        .ok()
        .and_then(|raw| {
            let mut parts = raw.split_whitespace();
            let quota = parts.next()?;
            let period: usize = parts.next()?.parse().ok()?;
            if quota == "max" || period == 0 {
                return None;
            }
            Some((quota.parse::<usize>().ok()? / period).max(1))
        });
    let cores = cgroup_quota.map_or(available, |q| q.min(available));
    let threads = ((cores * 3 / 4) / node_count.max(1)).max(1);
    // Log both so the cores-vs-quota gap is visible in CI. Fires at cluster
    // build (early), before the heavy crypto / any runner death.
    tracing::warn!(
        available_parallelism = available,
        cgroup_cpu_quota = ?cgroup_quota,
        effective_cores = cores,
        node_count,
        rayon_threads_per_node = threads,
        "upgrade-test rayon budget: available_parallelism vs cgroup cpu.max"
    );
    threads
}

#[cfg(test)]
mod tests {
    /// The candidate under both identity bases; these fixtures use one name.
    fn candidate(name: &str) -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::from([name.to_string()])
    }
    use super::*;

    fn stopped_validator() -> ValidatorProcess {
        ValidatorProcess::new(
            2,
            PathBuf::from("validator"),
            PathBuf::from("config.yaml"),
            PathBuf::from("data"),
            "127.0.0.1:9002".parse().unwrap(),
            0,
            PathBuf::from("node.log"),
            1,
        )
    }

    fn network_key_metrics(outputs: &[(&str, &str)]) -> String {
        outputs
            .iter()
            .flat_map(|(authority, digest)| {
                [
                    format!(
                        "ika_dwallet_mpc_session_output_info{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"{authority}\",output_digest=\"{digest}\"}} 1\n"
                    ),
                    format!(
                        "ika_dwallet_mpc_session_reported_malicious_actors{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"{authority}\"}} 0\n"
                    ),
                    format!(
                        "ika_dwallet_mpc_session_output_rejected{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"{authority}\"}} 0\n"
                    ),
                ]
            })
            .collect()
    }

    #[test]
    fn parses_exact_labeled_metric_without_prefix_collision() {
        let body = concat!(
            "# TYPE ika_output_info gauge\n",
            "ika_output_info{session_id=\"abc\",authority=\"k#01\",output_digest=\"deadbeef\"} 1\n",
            "ika_output_info_extra{session_id=\"wrong\"} 7\n",
        );
        let samples = parse_metric_samples(body, "ika_output_info").unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].labels["session_id"], "abc");
        assert_eq!(samples[0].labels["authority"], "k#01");
        assert_eq!(samples[0].labels["output_digest"], "deadbeef");
        assert_eq!(samples[0].value, 1.0);
    }

    #[test]
    fn rejects_malformed_labeled_metric() {
        let body = "ika_output_info{session_id=abc} 1\n";
        assert!(parse_metric_samples(body, "ika_output_info").is_err());
    }

    #[test]
    fn missing_required_metric_names_validator_and_endpoint() {
        let validator = stopped_validator();
        let error = required_unlabeled_metric("", &["ika_required"], &validator)
            .expect_err("missing metric must fail closed");
        let error = error.to_string();
        assert!(error.contains("validator 2"));
        assert!(error.contains("http://127.0.0.1:0/metrics"));
    }

    #[test]
    fn labeled_metric_requires_the_requested_protocol() {
        let validator = stopped_validator();
        let body = "ika_dwallet_mpc_protocol_sessions_pending{protocol_name=\"Sign\"} 0\n";
        let error = required_labeled_metric(
            body,
            "ika_dwallet_mpc_protocol_sessions_pending",
            &[("protocol_name", NETWORK_KEY_RECONFIGURATION_PROTOCOL)],
            &validator,
        )
        .expect_err("missing requested protocol must fail closed")
        .to_string();
        assert!(error.contains("validator 2"));
        assert!(error.contains("http://127.0.0.1:0/metrics"));
    }

    #[tokio::test]
    async fn stopped_validator_health_and_metrics_fail_closed() {
        let validator = stopped_validator();
        let health = validator
            .expect_healthy()
            .await
            .expect_err("stopped validator must be unhealthy")
            .to_string();
        assert!(health.contains("validator 2"));
        assert!(health.contains("http://127.0.0.1:9002"));

        let metrics = validator
            .metrics()
            .await
            .expect_err("unreachable metrics endpoint must fail")
            .to_string();
        assert!(metrics.contains("validator 2"));
        assert!(metrics.contains("http://127.0.0.1:0/metrics"));
    }

    #[test]
    fn parses_historical_and_current_labelless_gauges_exactly() {
        let body = "current_epoch 3\nika_current_epoch 4\nika_current_epoch_extra 9\n";
        assert_eq!(parse_labelless_gauge(body, "current_epoch"), Some(3));
        assert_eq!(parse_labelless_gauge(body, "ika_current_epoch"), Some(4));
    }

    fn committee_of(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// One late-output info sample: the digest pair production exports when a
    /// local computation returned after the quorum completed the session.
    fn late_output_info_sample(
        authority: &str,
        output_digest: &str,
        quorum_output_digest: &str,
    ) -> String {
        format!(
            "ika_dwallet_mpc_session_late_output_info{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"{authority}\",output_digest=\"{output_digest}\",quorum_output_digest=\"{quorum_output_digest}\"}} 1\n"
        )
    }

    /// Late-computation evidence samples: the info digest pair plus the
    /// late-output malicious gauge (one series per session/authority).
    fn late_output_metrics(
        authority: &str,
        output_digest: &str,
        quorum_output_digest: &str,
        malicious: u64,
    ) -> String {
        format!(
            "{}ika_dwallet_mpc_session_late_output_malicious_actors{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"{authority}\"}} {malicious}\n",
            late_output_info_sample(authority, output_digest, quorum_output_digest)
        )
    }

    #[test]
    fn accepts_four_authority_network_key_output_convergence() {
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body =
            network_key_metrics(&[("a", "same"), ("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(
            "ika_dwallet_mpc_session_output_info{protocol_name=\"Sign\",session_id=\"unrelated\",authority=\"a\",output_digest=\"different\"} 1\n",
        );
        let NetworkKeyOutputConvergence::Converged {
            canonical,
            sessions_without_candidate_evidence,
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("four matching authorities must converge");
        };
        assert_eq!(canonical["session"], "same");
        assert!(
            sessions_without_candidate_evidence.is_empty(),
            "a submitted candidate output is conclusive evidence"
        );
    }

    #[test]
    fn accepts_quorum_when_non_candidate_straggler_absent() {
        // The 4th validator finalized on quorum before its own output was
        // submitted (it discards a post-quorum result). A 3-of-4 converged
        // quorum that includes the validator under test still passes — the
        // full-committee requirement would race that finalization.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let body = network_key_metrics(&[("a", "same"), ("b", "same"), ("c", "same")]);
        let NetworkKeyOutputConvergence::Converged {
            canonical,
            sessions_without_candidate_evidence,
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("a converged quorum including the validator under test must pass");
        };
        assert_eq!(canonical["session"], "same");
        assert!(sessions_without_candidate_evidence.is_empty());
    }

    #[test]
    fn candidate_straggler_without_late_evidence_converges_but_is_flagged() {
        // The exact release-gate flake ordering: three v1.1.8 authorities
        // finalize with identical outputs, the quorum closes the session, and
        // the upgraded validator's own computation has produced nothing
        // comparable yet. The quorum itself converged (this must NOT fail),
        // but the session is flagged so the boundary can only be conclusive
        // once evidence arrives — or reported inconclusive, never silently
        // passed as compatibility proof.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        let NetworkKeyOutputConvergence::Converged {
            canonical,
            sessions_without_candidate_evidence,
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("a clean 3-of-4 quorum without the candidate must still converge");
        };
        assert_eq!(canonical["session"], "same");
        assert_eq!(sessions_without_candidate_evidence.len(), 1);
        assert!(sessions_without_candidate_evidence[0].contains("no submitted output"));
    }

    #[test]
    fn candidate_straggler_with_matching_late_evidence_is_conclusive() {
        // Same ordering, ~200ms later: the upgraded validator's computation
        // returned `finalize` after the session completed; production
        // discarded the output but recorded its raw-bytes digest, which
        // matches the quorum's raw-bytes digest. That is byte-level
        // compatibility evidence — the boundary is conclusive.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_metrics("a", "rawdigest", "rawdigest", 0));
        let NetworkKeyOutputConvergence::Converged {
            canonical,
            sessions_without_candidate_evidence,
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("matching late-computation evidence must converge");
        };
        assert_eq!(canonical["session"], "same");
        assert!(
            sessions_without_candidate_evidence.is_empty(),
            "a matching late-output digest is conclusive candidate evidence"
        );
    }

    #[test]
    fn candidate_late_evidence_with_divergent_bytes_fails_closed() {
        // The upgraded validator really did compute different bytes — the
        // quorum discarding its output must not hide the divergence.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_metrics("a", "localdigest", "quorumdigest", 0));
        let error =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .expect_err("a divergent late output must fail closed");
        let error = error.to_string();
        assert!(error.contains("DIVERGES"));
        assert!(error.contains("localdigest"));
        assert!(error.contains("quorumdigest"));
    }

    #[test]
    fn candidate_late_evidence_reporting_malicious_actors_fails_closed() {
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_metrics("a", "rawdigest", "rawdigest", 2));
        let error =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .expect_err("a late output reporting malicious actors must fail closed");
        assert!(error.to_string().contains("2 malicious actors"));
    }

    #[test]
    fn superseded_unknown_quorum_sample_next_to_compared_sample_is_conclusive() {
        // A late output recorded before the quorum digest was stashed leaves
        // a superseded `unknown`-quorum gauge child in the registry until the
        // epoch reset; the later compared pair for the SAME locally computed
        // bytes lands as a second child. That is one honest validator, not a
        // conflict — evidence comes from the compared pair.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_info_sample("a", "rawdigest", "unknown"));
        body.push_str(&late_output_metrics("a", "rawdigest", "rawdigest", 0));
        let NetworkKeyOutputConvergence::Converged {
            sessions_without_candidate_evidence,
            ..
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("a superseded unknown-quorum child must not block convergence");
        };
        assert!(sessions_without_candidate_evidence.is_empty());
    }

    #[test]
    fn late_samples_with_conflicting_local_digests_fail_closed() {
        // Two attempts of the same computation produced DIFFERENT bytes —
        // nondeterministic output is release-blocking however it surfaces.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_info_sample("a", "firstdigest", "unknown"));
        body.push_str(&late_output_metrics("a", "seconddigest", "seconddigest", 0));
        let error =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .expect_err("cross-attempt output disagreement must fail closed");
        assert!(error.to_string().contains("across attempts"));
    }

    #[test]
    fn candidate_late_evidence_without_quorum_digest_is_not_evidence() {
        // "unknown" means production had no quorum digest to compare against
        // (the session left Active through a non-quorum path). The digest
        // alone proves nothing — the session stays flagged, the boundary can
        // at best be inconclusive, and nothing fails.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&late_output_metrics("a", "rawdigest", "unknown", 0));
        let NetworkKeyOutputConvergence::Converged {
            sessions_without_candidate_evidence,
            ..
        } = canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
            .unwrap()
        else {
            panic!("an unverifiable late output must not block convergence");
        };
        assert_eq!(sessions_without_candidate_evidence.len(), 1);
        assert!(sessions_without_candidate_evidence[0].contains("without a quorum digest"));
    }

    #[test]
    fn late_evidence_missing_malicious_gauge_is_incomplete() {
        // The info sample and the malicious gauge are exported in the same
        // refresh; only a scrape racing that refresh can see one without the
        // other — retry, don't fail and don't accept.
        let committee = committee_of(&["a", "b", "c", "d"]);
        let mut body = network_key_metrics(&[("b", "same"), ("c", "same"), ("d", "same")]);
        body.push_str(&format!(
            "ika_dwallet_mpc_session_late_output_info{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"a\",output_digest=\"rawdigest\",quorum_output_digest=\"rawdigest\"}} 1\n"
        ));
        let NetworkKeyOutputConvergence::Incomplete(reason) =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .unwrap()
        else {
            panic!("a late-output sample without its malicious gauge must be incomplete");
        };
        assert!(reason.contains("malicious-actor gauge"));
    }

    #[test]
    fn incomplete_below_quorum() {
        let committee = committee_of(&["a", "b", "c", "d"]);
        let body = network_key_metrics(&[("a", "same"), ("b", "same")]);
        let NetworkKeyOutputConvergence::Incomplete(_) =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .unwrap()
        else {
            panic!("a below-quorum observation must be incomplete");
        };
    }

    #[test]
    fn rejects_out_of_committee_authority() {
        // A non-member submitting a network-key output is a hard fault, not a
        // propagation delay.
        let committee = committee_of(&["a", "b", "c"]);
        let body = network_key_metrics(&[
            ("a", "same"),
            ("b", "same"),
            ("c", "same"),
            ("rogue", "same"),
        ]);
        let error =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .expect_err("an out-of-committee authority must fail closed");
        assert!(error.to_string().contains("out-of-committee"));
    }

    #[test]
    fn rejects_one_divergent_network_key_output() {
        let committee = committee_of(&["a", "b", "c", "d"]);
        let body = network_key_metrics(&[
            ("a", "different"),
            ("b", "majority"),
            ("c", "majority"),
            ("d", "majority"),
        ]);
        let error =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 3, "validator 0")
                .expect_err("3-vs-1 output split must fail closed");
        assert!(
            error
                .to_string()
                .contains("divergent per-authority outputs")
        );
    }

    #[test]
    fn missing_network_key_envelope_metric_is_incomplete_not_converged() {
        let committee = committee_of(&["a"]);
        let body = format!(
            "ika_dwallet_mpc_session_output_info{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"a\",output_digest=\"same\"}} 1\nika_dwallet_mpc_session_output_rejected{{protocol_name=\"{NETWORK_KEY_RECONFIGURATION_PROTOCOL}\",session_id=\"session\",authority=\"a\"}} 0\n"
        );
        // A missing malicious-actor envelope is a not-yet-recorded observation:
        // the observer keeps polling (and the caller ultimately times out —
        // still fail-closed), rather than declaring a hard divergence.
        let NetworkKeyOutputConvergence::Incomplete(reason) =
            canonical_network_key_outputs(&body, &committee, &candidate("a"), 1, "validator 0")
                .unwrap()
        else {
            panic!("a missing envelope metric must be reported as incomplete");
        };
        assert!(reason.contains("missing required"));
    }
}
