// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::consensus_adapter::{BlockStatusReceiver, ConsensusClient};
use crate::consensus_handler::{ConsensusHandlerInitializer, MysticetiConsensusHandler};
use crate::consensus_validator::IkaTxValidator;
use crate::mysticeti_adapter::LazyMysticetiClient;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use consensus_config::{
    ChainType, Committee, ConsensusProtocolConfig, NetworkKeyPair, Parameters, ProtocolKeyPair,
};
use consensus_core::{
    Clock, CommitConsumerArgs, CommitConsumerMonitor, CommitIndex, ConsensusAuthority, NetworkType,
};
use fastcrypto::traits::KeyPair as _;
use ika_config::{ConsensusConfig, NodeConfig};
use ika_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use ika_types::error::IkaResult;
use ika_types::messages_consensus::{ConsensusPosition, ConsensusTransaction};
use ika_types::sui::epoch_start_system::EpochStartSystemTrait;
use mysten_metrics::{RegistryID, RegistryService};
use prometheus::{IntGauge, Registry, register_int_gauge_with_registry};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sui_types::committee::EpochId;
use tokio::sync::{Mutex, broadcast};
use tokio::time::sleep;
use tracing::{error, info};

mod boot_replay;

#[derive(PartialEq)]
enum Running {
    True(EpochId, ProtocolVersion),
    False,
}

/// The commit-consumer monitor created by one `start()`, paired with the commit
/// index the boot replay had already folded when it was created.
///
/// Both halves are needed to answer "did this consumer handle a live commit?",
/// because the monitor's initial reading is the replay floor, not zero.
struct StartedCommitConsumer {
    monitor: Arc<CommitConsumerMonitor>,
    replay_floor: CommitIndex,
}

/// Build the consensus-core [`ConsensusProtocolConfig`] from ika's
/// [`ProtocolConfig`].
///
/// **Keep this in lockstep with Sui's `to_consensus_protocol_config`**
/// (`sui-core/src/consensus_manager/mod.rs`). Every value consensus reads is
/// sourced from the protocol config (so it is version-gated and changes only via
/// a protocol upgrade, never an ad-hoc constant), in the same order and from the
/// same getters as upstream. On every Sui version bump, diff this against
/// upstream and wire through any field consensus newly reads — see
/// `dev-docs/conventions/sui-version-bump.md`. The lone exception is the inline
/// constant noted below, which mirrors what upstream itself hardcodes at the
/// pinned version.
fn to_consensus_protocol_config(config: &ProtocolConfig, chain: Chain) -> ConsensusProtocolConfig {
    let chain_type = match chain {
        Chain::Mainnet => ChainType::Mainnet,
        Chain::Testnet => ChainType::Testnet,
        Chain::Devnet | Chain::Unknown => ChainType::Unknown,
    };
    ConsensusProtocolConfig::new(
        config.version.as_u64(),
        chain_type,
        config.consensus_max_transaction_size_bytes(),
        config.consensus_max_transactions_in_block_bytes(),
        config.consensus_max_num_transactions_in_block(),
        config.gc_depth(),
        // `transaction_voting_enabled`: ika runs this OFF (false at every
        // supported protocol version), unlike Sui, which hardcodes `true`.
        // Keep it flag-sourced rather than adopting upstream's constant:
        // flipping it on changes the DAG that consensus builds, and a node
        // replaying a backlog of certified commits then panics in
        // consensus-core's `linearizer::calculate_commit_timestamp` ("We
        // should have all blocks in dag state") — the commit-sync path does
        // not accept a leader's uncommitted round-1 ancestors, which the
        // median-timestamp computation `expect`s. Reproduced 2/2 in the
        // upgrade test. Enabling voting is a deliberate, version-gated
        // protocol change, never a side effect of a Sui bump.
        config.transaction_voting_enabled(),
        config.mysticeti_num_leaders_per_round(),
        config.consensus_bad_nodes_stake_threshold(),
        // `enable_v3`: hardcoded `false` to match upstream exactly. At the
        // pinned mainnet-v1.77.2, Sui's own `to_consensus_protocol_config` also
        // hardcodes `/* enable_v3 */ false` — it is NOT yet exposed by
        // `sui_protocol_config::ProtocolConfig`, so there is no version-gated
        // getter to source it from. When Sui gates it behind the protocol config
        // (watch for it on the next version bump), or if we want to enable v3 via
        // an ika protocol upgrade first, add a version-gated getter to ika's
        // protocol config and source it here — do NOT just flip this constant,
        // since an un-gated change would fork consensus mid-epoch.
        false,
        // `leader_schedule_window_size` / `leader_schedule_update_interval`:
        // hardcoded to match upstream's `to_consensus_protocol_config` at the
        // pinned mainnet-v1.77.2 (300 / 12). These only take effect under the
        // Mysticeti v3 leader schedule, which is gated off above (`enable_v3 =
        // false`), so they are inert today; mirror upstream exactly so enabling
        // v3 later (via a version-gated getter) does not silently fork.
        300,
        12,
    )
}

/// Used by Ika validator to start consensus protocol for each epoch.
pub struct ConsensusManager {
    consensus_config: ConsensusConfig,
    protocol_keypair: ProtocolKeyPair,
    network_keypair: NetworkKeyPair,
    storage_base_path: PathBuf,
    metrics: Arc<ConsensusManagerMetrics>,
    registry_service: RegistryService,
    authority: ArcSwapOption<(ConsensusAuthority, RegistryID)>,

    // Use a shared lazy Mysticeti client so we can update the internal Mysticeti
    // client that gets created for every new epoch.
    client: Arc<LazyMysticetiClient>,
    consensus_client: Arc<UpdatableConsensusClient>,

    consensus_handler: Mutex<Option<MysticetiConsensusHandler>>,

    consumer_monitor: ArcSwapOption<StartedCommitConsumer>,
    consumer_monitor_sender: broadcast::Sender<Arc<CommitConsumerMonitor>>,

    running: Mutex<Running>,
    boot_counter: Mutex<u64>,
}

impl ConsensusManager {
    pub fn new(
        node_config: &NodeConfig,
        consensus_config: &ConsensusConfig,
        registry_service: &RegistryService,
        consensus_client: Arc<UpdatableConsensusClient>,
    ) -> Self {
        let metrics = Arc::new(ConsensusManagerMetrics::new(
            &registry_service.default_registry(),
        ));
        let client = Arc::new(LazyMysticetiClient::new());
        let (consumer_monitor_sender, _) = broadcast::channel(1);
        Self {
            consensus_config: consensus_config.clone(),
            protocol_keypair: ProtocolKeyPair::new(node_config.consensus_key_pair().copy()),
            network_keypair: NetworkKeyPair::new(node_config.network_key_pair().copy()),
            storage_base_path: consensus_config.db_path().to_path_buf(),
            metrics,
            registry_service: registry_service.clone(),
            authority: ArcSwapOption::empty(),
            client,
            consensus_client,
            consensus_handler: Mutex::new(None),
            consumer_monitor: ArcSwapOption::empty(),
            consumer_monitor_sender,
            running: Mutex::new(Running::False),
            boot_counter: Mutex::new(0),
        }
    }

    pub async fn start(
        &self,
        node_config: &NodeConfig,
        epoch_store: Arc<AuthorityPerEpochStore>,
        consensus_handler_initializer: ConsensusHandlerInitializer,
        tx_validator: IkaTxValidator,
    ) {
        let system_state = epoch_store.epoch_start_state();
        let committee: Committee = system_state.get_consensus_committee();
        let epoch = epoch_store.epoch();
        let ika_protocol_config = epoch_store.protocol_config();

        // Ensure start() is not called twice.
        let start_time = Instant::now();
        let mut running = self.running.lock().await;
        if let Running::True(running_epoch, running_version) = *running {
            error!(
                "Consensus is already Running for epoch {running_epoch:?} & protocol version {running_version:?} - shutdown first before starting",
            );
            return;
        }
        *running = Running::True(epoch, ika_protocol_config.version);

        info!(
            "Starting up consensus for epoch {epoch:?} & protocol version {:?}",
            ika_protocol_config.version
        );

        self.consensus_client.set(self.client.clone());

        let consensus_config = node_config
            .consensus_config()
            .expect("consensus_config should exist");

        let node_parameters = consensus_config.parameters.clone().unwrap_or_default();
        // `commit_sync_batch_size × commit_sync_batches_ahead` is what bounds
        // this node's memory while the fold is parked on a slow MPC drain, so
        // the number is ika's business and is pinned here rather than
        // inherited: the commit syncer stops scheduling fetches once the
        // consumer trails by that many unhandled commits
        // (`consensus/core/src/commit_syncer.rs`), which is the only thing
        // keeping a deep backlog on peers' disks instead of in this process's
        // commit channel. Upstream's defaults are tuned for Sui's consumer,
        // which never blocks; ours does, deliberately (see
        // `dev-docs/specs/event-sourced-epoch.md`), so a retune upstream must
        // not move our ceiling without us noticing.
        //
        // Held at upstream's current values — 100 × 32 = 3,200 unhandled
        // commits — because lowering them also slows a legitimately-behind
        // node's catch-up, and that trade should follow the real-payload
        // measurement in ika #2064 rather than precede it. THIS is the lever
        // if that measurement comes back badly: the resident cost is
        // 3,200 × the size of a `CommittedSubDag`, which carries every
        // validator's blocks for its round.
        const UNHANDLED_COMMIT_CEILING_BATCH_SIZE: u32 = 100;
        const UNHANDLED_COMMIT_CEILING_BATCHES_AHEAD: usize = 32;
        let parameters = Parameters {
            db_path: self.get_store_path(epoch),
            commit_sync_batch_size: UNHANDLED_COMMIT_CEILING_BATCH_SIZE,
            commit_sync_batches_ahead: UNHANDLED_COMMIT_CEILING_BATCHES_AHEAD,
            ..node_parameters
        };

        let own_protocol_key = self.protocol_keypair.public();
        // `own_index` is no longer passed to `ConsensusAuthority::start`
        // (dropped in mainnet-v1.73.2), but we keep this lookup for its
        // side-effect: asserting our authority is in the committee.
        let (_own_index, _) = committee
            .authorities()
            .find(|(_, a)| a.protocol_key == own_protocol_key)
            .expect("Own authority should be among the consensus authorities!");

        // consensus-core's metrics are re-exported under this prefix, which
        // must NOT start with `ika`: `ika_*` is ika's own namespace, and a
        // shared prefix is exactly what let an upstream metric and an ika one
        // collide in #2022. `RegistryService` merges the two registries at
        // /metrics, prometheus's duplicate check is per-registry, and the
        // prefix is applied at `gather()` — so the two names never meet
        // anywhere the collision could be caught. Keeping the vendored
        // namespace outside `ika_` makes the rule a clean bipartition: ika's
        // metrics start with `ika_`, vendored ones never do, and neither side
        // needs a list of the other's names. `consensus_ika_*` does sit inside
        // sui's own `consensus_*` namespace, which is safe in a way this
        // arrangement was not: sui will never register a metric named
        // `ika_<something>`. Enforced by scripts/check-metric-names.sh.
        let registry = Registry::new_custom(Some("consensus_ika".to_string()), None).unwrap();

        let mut consensus_handler = consensus_handler_initializer.new_consensus_handler();

        // Rebuild this epoch's derived state before consensus starts. The
        // per-epoch store was opened with its derived tables deleted, so the
        // handler begins from nothing and folds every finalized commit the
        // consensus store holds. `replay_after` is then the store's own last
        // finalized commit — not a watermark kept beside it — which is what
        // makes `CommitObserver::recover_and_send_commits` unable to find the
        // two out of order (ika #2057).
        let replayed_through = boot_replay::replay_epoch_commits(
            &parameters.db_path,
            &mut consensus_handler,
            &self.metrics,
        )
        .await;

        let (commit_consumer, commit_receiver) =
            CommitConsumerArgs::new(replayed_through, replayed_through);
        let monitor = commit_consumer.monitor();

        let handler =
            MysticetiConsensusHandler::new(consensus_handler, commit_receiver, monitor.clone());

        let mut consensus_handler = self.consensus_handler.lock().await;
        *consensus_handler = Some(handler);

        // If there is a previous consumer monitor, it indicates that the consensus engine has been restarted, due to an epoch change. However, that on its
        // own doesn't tell us much whether it participated on an active epoch or an old one. We need to check if it has handled any commits to determine this.
        // If indeed any commits did happen, then we assume that node did participate on previous run.
        //
        // "Any commits" means any commit beyond the one the boot replay had
        // already folded when that consumer was created: the monitor starts at
        // the replay floor, so comparing against zero would report every node
        // that merely replayed an existing store as having participated, and
        // suppress the amnesia recovery a node that handled nothing live needs.
        let started_consumer = Arc::new(StartedCommitConsumer {
            monitor: monitor.clone(),
            replay_floor: replayed_through,
        });
        let participated_on_previous_run =
            if let Some(previous) = self.consumer_monitor.swap(Some(started_consumer)) {
                previous.monitor.highest_handled_commit() > previous.replay_floor
            } else {
                false
            };

        // Increment the boot counter only if the consensus successfully participated in the previous run.
        // This is typical during normal epoch changes, where the node restarts as expected, and the boot counter is incremented to prevent amnesia recovery on the next start.
        // If the node is recovering from a restore process and catching up across multiple epochs, it won't handle any commits until it reaches the last active epoch.
        // In this scenario, we do not increment the boot counter, as we need amnesia recovery to run.
        let mut boot_counter = self.boot_counter.lock().await;
        if participated_on_previous_run {
            *boot_counter += 1;
        } else {
            info!(
                "Node has not participated in previous epoch consensus. Boot counter ({}) will not increment.",
                *boot_counter
            );
        }

        let chain = epoch_store.get_chain_identifier().chain();

        let authority = ConsensusAuthority::start(
            NetworkType::Tonic,
            epoch_store.epoch_start_config().epoch_start_timestamp_ms(),
            // `own_index` was dropped from `ConsensusAuthority::start` in
            // mainnet-v1.73.2 (the node derives it from the committee +
            // protocol keypair). `protocol_keypair` is now optional
            // (observer nodes pass `None`); validators pass `Some`.
            committee.clone(),
            parameters.clone(),
            to_consensus_protocol_config(ika_protocol_config, chain),
            Some(self.protocol_keypair.clone()),
            self.network_keypair.clone(),
            Arc::new(Clock::default()),
            Arc::new(tx_validator.clone()),
            // ika submits via `TransactionClient`; it has no in-process pool to
            // feed the proposer. `None` means fall back to the client path.
            None,
            commit_consumer,
            registry.clone(),
            *boot_counter,
            // Sui's randomness-beacon signature handler; ika runs no
            // randomness protocol, so there is nothing to sign.
            None,
        )
        .await;
        let client = authority.transaction_client();
        // The store handle, taken BEFORE the authority is sealed into its Arc:
        // `shutdown` does `Arc::try_unwrap` on that and panics on a surviving
        // reference, so the head publisher must hold the store rather than the
        // authority. Feeds the catch-up gate the one backlog measure the fold
        // cannot supply — see `spawn_observed_head_publisher`.
        let consensus_store = authority.store();

        let registry_id = self.registry_service.add(registry.clone());

        let registered_authority = Arc::new((authority, registry_id));
        self.authority.swap(Some(registered_authority.clone()));

        // Initialize the client to send transactions to this Mysticeti instance.
        self.client.set(client);

        if let Some(handler) = consensus_handler.as_mut() {
            handler.spawn_observed_head_publisher(consensus_store, epoch_store.clone());
        }

        // Send the consumer monitor to the replay waiter.
        let _ = self.consumer_monitor_sender.send(monitor);

        let elapsed = start_time.elapsed().as_secs_f64();
        self.metrics.start_latency.set(elapsed as i64);

        tracing::info!(
            "Started consensus for epoch {} & protocol version {:?} completed - took {} seconds",
            epoch,
            ika_protocol_config.version,
            elapsed
        );
    }

    pub async fn shutdown(&self) {
        info!("Shutting down consensus ...");

        // Ensure shutdown() is called on a running consensus and get the epoch/version info.
        let start_time = Instant::now();
        let mut running = self.running.lock().await;
        let (shutdown_epoch, shutdown_version) = match *running {
            Running::True(epoch, version) => {
                tracing::info!(
                    "Shutting down consensus for epoch {epoch:?} & protocol version {version:?}"
                );
                *running = Running::False;
                (epoch, version)
            }
            Running::False => {
                error!("Consensus shutdown was called but consensus is not running");
                return;
            }
        };

        // Stop consensus submissions.
        self.client.clear();

        // swap with empty to ensure there is no other reference to authority and we can safely do Arc unwrap
        let r = self.authority.swap(None).unwrap();
        let Ok((authority, registry_id)) = Arc::try_unwrap(r) else {
            panic!("Failed to retrieve the Mysticeti authority");
        };

        // shutdown the authority and wait for it
        authority.stop().await;

        // drop the old consensus handler to force stop any underlying task running.
        let mut consensus_handler = self.consensus_handler.lock().await;
        if let Some(mut handler) = consensus_handler.take() {
            handler.abort().await;
        }

        // unregister the registry id
        self.registry_service.remove(registry_id);

        self.consensus_client.clear();

        let elapsed = start_time.elapsed().as_secs_f64();
        self.metrics.shutdown_latency.set(elapsed as i64);

        tracing::info!(
            "Consensus stopped for epoch {shutdown_epoch:?} & protocol version {shutdown_version:?} is complete - took {} seconds",
            elapsed
        );
    }

    pub async fn is_running(&self) -> bool {
        let running = self.running.lock().await;
        matches!(*running, Running::True(_, _))
    }

    pub fn replay_waiter(&self) -> ReplayWaiter {
        let consumer_monitor_receiver = self.consumer_monitor_sender.subscribe();
        ReplayWaiter::new(consumer_monitor_receiver)
    }

    pub fn get_storage_base_path(&self) -> PathBuf {
        self.consensus_config.db_path().to_path_buf()
    }

    fn get_store_path(&self, epoch: EpochId) -> PathBuf {
        let mut store_path = self.storage_base_path.clone();
        store_path.push(format!("{}", epoch));
        store_path
    }
}

/// A ConsensusClient that can be updated internally at any time. This usually happening during epoch
/// change where a client is set after the new consensus is started for the new epoch.
#[derive(Default)]
pub struct UpdatableConsensusClient {
    // An extra layer of Arc<> is needed as required by ArcSwapAny.
    client: ArcSwapOption<Arc<dyn ConsensusClient>>,
}

impl UpdatableConsensusClient {
    pub fn new() -> Self {
        Self {
            client: ArcSwapOption::empty(),
        }
    }

    /// Waits until consensus has started for the current epoch.
    ///
    /// Deliberately unbounded, and deliberately not fatal. A submission that
    /// arrives before consensus is up is a normal boot state, not a defect:
    /// the node rebuilds the epoch's derived state by replaying the consensus
    /// store before consensus starts
    /// (`dev-docs/specs/event-sourced-epoch.md`), and on an old epoch that
    /// legitimately takes tens of minutes, while the epoch tasks and the
    /// capability notification submit on their own timers from the moment the
    /// components exist. This used to abort the process after 300 seconds —
    /// and with `panic = "abort"` in the release profile, one such submission
    /// would take a healthy, recovering node down.
    ///
    /// The wait cannot leak: every caller reaches this through
    /// `ConsensusAdapter::submit_and_wait`, which runs inside
    /// `within_alive_epoch` and is dropped at the epoch boundary. The warning
    /// below is what a genuinely stuck start looks like now.
    async fn get(&self) -> Arc<Arc<dyn ConsensusClient>> {
        const RETRY_INTERVAL: Duration = Duration::from_millis(100);
        const SLOW_START_WARN_INTERVAL: Duration = Duration::from_secs(300);

        let waiting_since = Instant::now();
        let mut warnings = 0_u32;
        loop {
            if let Some(client) = self.client.load_full() {
                return client;
            }
            let waited = waiting_since.elapsed();
            if waited >= SLOW_START_WARN_INTERVAL * (warnings + 1) {
                warnings += 1;
                error!(
                    waited_secs = waited.as_secs(),
                    "a consensus submission has been waiting for consensus to start; this is \
                     expected while the node replays an old epoch to rebuild its derived state, \
                     and a defect if `ika_consensus_boot_replay_folded_commit_index` is not \
                     advancing",
                );
            }
            sleep(RETRY_INTERVAL).await;
        }
    }

    pub fn set(&self, client: Arc<dyn ConsensusClient>) {
        self.client.store(Some(Arc::new(client)));
    }

    pub fn clear(&self) {
        self.client.store(None);
    }
}

#[async_trait]
impl ConsensusClient for UpdatableConsensusClient {
    async fn submit(
        &self,
        transactions: &[ConsensusTransaction],
        epoch_store: &Arc<AuthorityPerEpochStore>,
    ) -> IkaResult<(Vec<ConsensusPosition>, BlockStatusReceiver)> {
        let client = self.get().await;
        client.submit(transactions, epoch_store).await
    }
}

/// Waits for consensus to finish replaying at consensus handler.
pub struct ReplayWaiter {
    consumer_monitor_receiver: broadcast::Receiver<Arc<CommitConsumerMonitor>>,
}

impl ReplayWaiter {
    pub(crate) fn new(
        consumer_monitor_receiver: broadcast::Receiver<Arc<CommitConsumerMonitor>>,
    ) -> Self {
        Self {
            consumer_monitor_receiver,
        }
    }

    pub(crate) async fn wait_for_replay(mut self) {
        loop {
            info!("Waiting for consensus to start replaying ...");
            let Ok(monitor) = self.consumer_monitor_receiver.recv().await else {
                continue;
            };
            info!("Waiting for consensus handler to finish replaying ...");
            monitor
                .replay_to_consumer_last_processed_commit_complete()
                .await;
            break;
        }
    }
}

impl Clone for ReplayWaiter {
    fn clone(&self) -> Self {
        Self {
            consumer_monitor_receiver: self.consumer_monitor_receiver.resubscribe(),
        }
    }
}

pub struct ConsensusManagerMetrics {
    start_latency: IntGauge,
    shutdown_latency: IntGauge,
    /// The commit index the boot replay set out to reach — the consensus
    /// store's last finalized commit for this epoch.
    pub(crate) boot_replay_target_commit_index: IntGauge,
    /// How far the boot replay has folded. Equal to the target once the node
    /// is live; the distance between the two is the remaining boot work, which
    /// on an old epoch is the dominant term in time-to-live.
    pub(crate) boot_replay_folded_commit_index: IntGauge,
    /// Wall-clock seconds the boot replay took. Compared against the epoch's
    /// age, this is the number the restart-latency budget is set from.
    pub(crate) boot_replay_latency_seconds: IntGauge,
}

impl ConsensusManagerMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            start_latency: register_int_gauge_with_registry!(
                "ika_consensus_manager_start_latency",
                "The latency of starting up consensus nodes",
                registry,
            )
            .unwrap(),
            shutdown_latency: register_int_gauge_with_registry!(
                "ika_consensus_manager_shutdown_latency",
                "The latency of shutting down consensus nodes",
                registry,
            )
            .unwrap(),
            boot_replay_target_commit_index: register_int_gauge_with_registry!(
                "ika_consensus_boot_replay_target_commit_index",
                "Last finalized consensus commit index this boot's derived-state replay must reach",
                registry,
            )
            .unwrap(),
            boot_replay_folded_commit_index: register_int_gauge_with_registry!(
                "ika_consensus_boot_replay_folded_commit_index",
                "Consensus commit index this boot's derived-state replay has folded so far",
                registry,
            )
            .unwrap(),
            boot_replay_latency_seconds: register_int_gauge_with_registry!(
                "ika_consensus_boot_replay_latency_seconds",
                "Seconds the derived-state replay took to reach the consensus store head",
                registry,
            )
            .unwrap(),
        }
    }
}
