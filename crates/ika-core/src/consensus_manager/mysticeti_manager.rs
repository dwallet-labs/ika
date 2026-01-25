// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{path::PathBuf, sync::Arc};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use consensus_config::{Committee, NetworkKeyPair, Parameters, ProtocolKeyPair};
use consensus_core::{
    Clock, CommitConsumerArgs, CommitConsumerMonitor, CommitIndex, ConsensusAuthority, NetworkType,
};
use fastcrypto::ed25519;
use ika_config::NodeConfig;
use ika_types::{committee::EpochId, sui::epoch_start_system::EpochStartSystemTrait};
use mysten_metrics::{RegistryID, RegistryService};
use prometheus::Registry;
use tokio::sync::{Mutex, broadcast};
use tracing::info;

use crate::consensus_manager::ReplayWaiter;
use crate::{
    authority::authority_per_epoch_store::AuthorityPerEpochStore,
    consensus_handler::{ConsensusHandlerInitializer, MysticetiConsensusHandler},
    consensus_manager::{
        ConsensusManagerMetrics, ConsensusManagerTrait, Running, RunningLockGuard,
    },
    consensus_validator::IkaTxValidator,
    mysticeti_adapter::LazyMysticetiClient,
};

pub struct MysticetiManager {
    protocol_keypair: ProtocolKeyPair,
    network_keypair: NetworkKeyPair,
    storage_base_path: PathBuf,
    // TODO: switch to parking_lot::Mutex.
    running: Mutex<Running>,
    metrics: Arc<ConsensusManagerMetrics>,
    registry_service: RegistryService,
    authority: ArcSwapOption<(ConsensusAuthority, RegistryID)>,
    boot_counter: Mutex<u64>,
    // Use a shared lazy mysticeti client so we can update the internal mysticeti
    // client that gets created for every new epoch.
    client: Arc<LazyMysticetiClient>,
    // TODO: switch to parking_lot::Mutex.
    consensus_handler: Mutex<Option<MysticetiConsensusHandler>>,
    consumer_monitor: ArcSwapOption<CommitConsumerMonitor>,
    consumer_monitor_sender: broadcast::Sender<Arc<CommitConsumerMonitor>>,
}

impl MysticetiManager {
    /// NOTE: Mysticeti protocol key uses Ed25519 instead of BLS.
    /// But for security, the protocol keypair must be different from the network keypair.
    pub fn new(
        protocol_keypair: ed25519::Ed25519KeyPair,
        network_keypair: ed25519::Ed25519KeyPair,
        storage_base_path: PathBuf,
        registry_service: RegistryService,
        metrics: Arc<ConsensusManagerMetrics>,
        client: Arc<LazyMysticetiClient>,
    ) -> Self {
        let (consumer_monitor_sender, _) = broadcast::channel(1);
        Self {
            protocol_keypair: ProtocolKeyPair::new(protocol_keypair),
            network_keypair: NetworkKeyPair::new(network_keypair),
            storage_base_path,
            running: Mutex::new(Running::False),
            metrics,
            registry_service,
            authority: ArcSwapOption::empty(),
            client,
            consensus_handler: Mutex::new(None),
            boot_counter: Mutex::new(0),
            consumer_monitor: ArcSwapOption::empty(),
            consumer_monitor_sender,
        }
    }

    fn get_store_path(&self, epoch: EpochId) -> PathBuf {
        let mut store_path = self.storage_base_path.clone();
        store_path.push(format!("{epoch}"));
        store_path
    }
}

#[async_trait]
impl ConsensusManagerTrait for MysticetiManager {
    async fn start(
        &self,
        config: &NodeConfig,
        epoch_store: Arc<AuthorityPerEpochStore>,
        consensus_handler_initializer: ConsensusHandlerInitializer,
        tx_validator: IkaTxValidator,
    ) {
        let system_state = epoch_store.epoch_start_state();
        let committee: Committee = system_state.get_consensus_committee();
        let epoch = epoch_store.epoch();
        let ika_protocol_config = epoch_store.protocol_config();

        let Some(_guard) = RunningLockGuard::acquire_start(
            &self.metrics,
            &self.running,
            epoch,
            ika_protocol_config.version,
        )
        .await
        else {
            return;
        };

        let consensus_config = config
            .consensus_config()
            .expect("consensus_config should exist");

        let parameters = Parameters {
            db_path: self.get_store_path(epoch),
            ..consensus_config.parameters.clone().unwrap_or_default()
        };

        let own_protocol_key = self.protocol_keypair.public();
        let (own_index, _) = committee
            .authorities()
            .find(|(_, a)| a.protocol_key == own_protocol_key)
            .expect("Own authority should be among the consensus authorities!");

        let registry = Registry::new_custom(Some("consensus".to_string()), None).unwrap();

        let consensus_handler = consensus_handler_initializer.new_consensus_handler();

        let last_processed_commit_index =
            consensus_handler.last_processed_subdag_index() as CommitIndex;
        let (commit_consumer, commit_receiver, _block_receiver) =
            CommitConsumerArgs::new(last_processed_commit_index, last_processed_commit_index);
        let monitor = commit_consumer.monitor();

        let handler =
            MysticetiConsensusHandler::new(consensus_handler, commit_receiver, monitor.clone());

        let mut consensus_handler = self.consensus_handler.lock().await;
        *consensus_handler = Some(handler);

        // If there is a previous consumer monitor, it indicates that the consensus engine has been restarted, due to an epoch change. However, that on its
        // own doesn't tell us much whether it participated on an active epoch or an old one. We need to check if it has handled any commits to determine this.
        // If indeed any commits did happen, then we assume that node did participate on previous run.
        let participated_on_previous_run =
            if let Some(previous_monitor) = self.consumer_monitor.swap(Some(monitor.clone())) {
                previous_monitor.highest_handled_commit() > 0
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

        // This can only be changed for all validators together at the same epoch
        // IMPORTANT: DONT CHANGE THIS VALUE UNLESS YOU KNOW WHAT YOU ARE DOING
        // MAKE SURE TO CHECK WE MANUALLY SET EVERY CONSENSUS CONFIG FROM OUR PROTOCOL CONFIG
        // AND THAT WE OVERRIDE THE SUI PROTOCOL CONFIG VALUES
        let mut protocol_config = sui_protocol_config::ProtocolConfig::get_for_version(
            // Version 84 was taken from Sui, DO NOT CHANGE IT.
            sui_protocol_config::ProtocolVersion::new(ika_protocol_config.sui_protocol_version()),
            sui_protocol_config::Chain::Mainnet,
        );

        protocol_config.set_consensus_max_transaction_size_bytes_for_testing(
            ika_protocol_config.consensus_max_transaction_size_bytes(),
        );
        protocol_config.set_consensus_max_transactions_in_block_bytes_for_testing(
            ika_protocol_config.consensus_max_transactions_in_block_bytes(),
        );

        protocol_config.set_consensus_max_num_transactions_in_block_for_testing(
            ika_protocol_config.consensus_max_num_transactions_in_block(),
        );

        protocol_config.set_consensus_gc_depth_for_testing(ika_protocol_config.gc_depth());

        protocol_config
            .set_consensus_round_prober_for_testing(ika_protocol_config.consensus_round_prober());

        protocol_config
            .set_mysticeti_fastpath_for_testing(ika_protocol_config.mysticeti_fastpath());

        protocol_config.set_mysticeti_num_leaders_per_round_for_testing(
            ika_protocol_config.mysticeti_num_leaders_per_round(),
        );

        // TODO: Do not remove this, this will be set once there is a "set" function for it.
        // protocol_config.set_consensus_zstd_compression_for_testing(
        //     ika_protocol_config.consensus_zstd_compression(),
        // );

        protocol_config.set_consensus_batched_block_sync_for_testing(
            ika_protocol_config.consensus_batched_block_sync(),
        );

        // protocol_config.set_consensus_skip_gced_blocks_in_direct_finalization_for_testing(
        //     ika_protocol_config.consensus_skip_gced_blocks_in_direct_finalization(),
        // );

        // TODO: Do not remove this, this will be set once there is a "set" function for it.
        // protocol_config.set_enforce_checkpoint_timestamp_monotonicity_for_testing(
        //     ika_protocol_config.enforce_checkpoint_timestamp_monotonicity(),
        // );

        let authority = ConsensusAuthority::start(
            NetworkType::Tonic,
            epoch_store.epoch_start_config().epoch_start_timestamp_ms(),
            own_index,
            committee.clone(),
            parameters.clone(),
            protocol_config.clone(),
            self.protocol_keypair.clone(),
            self.network_keypair.clone(),
            Arc::new(Clock::default()),
            Arc::new(tx_validator.clone()),
            commit_consumer,
            registry.clone(),
            *boot_counter,
        )
        .await;
        let client = authority.transaction_client();

        let registry_id = self.registry_service.add(registry.clone());

        let registered_authority = Arc::new((authority, registry_id));
        self.authority.swap(Some(registered_authority.clone()));

        // Initialize the client to send transactions to this Mysticeti instance.
        self.client.set(client);

        // Send the consumer monitor to the replay waiter.
        let _ = self.consumer_monitor_sender.send(monitor);
    }

    async fn shutdown(&self) {
        let Some(_guard) = RunningLockGuard::acquire_shutdown(&self.metrics, &self.running).await
        else {
            return;
        };

        // Stop consensus submissions.
        self.client.clear();

        // swap with empty to ensure there is no other reference to authority and we can safely do Arc unwrap
        let r = self.authority.swap(None).unwrap();
        let Ok((authority, registry_id)) = Arc::try_unwrap(r) else {
            panic!("Failed to retrieve the mysticeti authority");
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
    }

    async fn is_running(&self) -> bool {
        Running::False != *self.running.lock().await
    }

    fn replay_waiter(&self) -> ReplayWaiter {
        let consumer_monitor_receiver = self.consumer_monitor_sender.subscribe();
        ReplayWaiter::new(consumer_monitor_receiver)
    }
}
