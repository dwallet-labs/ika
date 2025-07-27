// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The SuiSyncer module handles synchronizing Events emitted
//! on the Sui blockchain from concerned modules of `ika_system` package.
use crate::sui_connector::metrics::SuiConnectorMetrics;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use ika_sui_client::{SuiClient, SuiClientInner, retry_with_max_elapsed_time};
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee, StakeUnit};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaResult;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use ika_types::sui::{DWalletCoordinatorInner, SystemInner, SystemInnerTrait};
use mysten_metrics::spawn_logged_monitored_task;
use std::{collections::HashMap, sync::Arc};
use sui_json_rpc_types::SuiEvent;
use sui_types::base_types::ObjectID;
use sui_types::{Identifier, event::EventID};
use tokio::sync::watch::Sender;
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{self, Duration},
};
use tracing::{debug, error, info, warn};

pub struct SuiSyncer<C> {
    sui_client: Arc<SuiClient<C>>,
    // The last transaction that the syncer has fully processed.
    // Syncer will resume posting this transaction (i.e., exclusive) when it starts.
    modules: Vec<Identifier>,
    metrics: Arc<SuiConnectorMetrics>,
}

impl<C> SuiSyncer<C>
where
    C: SuiClientInner + 'static,
{
    pub fn new(
        sui_client: Arc<SuiClient<C>>,
        modules: Vec<Identifier>,
        metrics: Arc<SuiConnectorMetrics>,
    ) -> Self {
        Self {
            sui_client,
            modules,
            metrics,
        }
    }

    pub async fn run(
        self,
        query_interval: Duration,
        next_epoch_committee_sender: Sender<Committee>,
        is_validator: bool,
        network_keys_sender: Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        new_events_sender: tokio::sync::broadcast::Sender<Vec<SuiEvent>>,
        end_of_publish_sender: Sender<Option<u64>>,
    ) -> IkaResult<Vec<JoinHandle<()>>> {
        info!("Starting SuiSyncer");
        let mut task_handles = vec![];
        let sui_client_clone = self.sui_client.clone();
        // The notifier needs the network keys, not only on the validator nodes.
        info!("Starting network keys sync task");
        tokio::spawn(Self::sync_dwallet_network_keys(
            sui_client_clone.clone(),
            network_keys_sender,
        ));
        if is_validator {
            info!("Starting next epoch committee sync task");
            tokio::spawn(Self::sync_next_committee(
                sui_client_clone.clone(),
                next_epoch_committee_sender,
            ));
            info!("Starting end of publish sync task");
            tokio::spawn(Self::sync_dwallet_end_of_publish(
                sui_client_clone,
                end_of_publish_sender,
            ));
        }

        for module in self.modules {
            let metrics = self.metrics.clone();
            let sui_client_clone = self.sui_client.clone();
            let new_events_sender_clone = new_events_sender.clone();
            task_handles.push(spawn_logged_monitored_task!(
                Self::run_event_listening_task(
                    module,
                    sui_client_clone,
                    query_interval,
                    metrics,
                    new_events_sender_clone,
                )
            ));
        }
        Ok(task_handles)
    }

    async fn sync_next_committee(
        sui_client: Arc<SuiClient<C>>,
        next_epoch_committee_sender: Sender<Committee>,
    ) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let system_inner = sui_client.must_get_system_inner_object().await;
            let SystemInner::V1(system_inner) = system_inner;
            let Some(new_next_bls_committee) = system_inner.get_ika_next_epoch_committee() else {
                debug!("ika next epoch active committee not found, retrying...");
                continue;
            };

            let new_next_committee = system_inner.read_bls_committee(&new_next_bls_committee);

            let committee = match Self::new_committee(
                sui_client.clone(),
                new_next_committee.clone(),
                system_inner.epoch() + 1,
                new_next_bls_committee.quorum_threshold,
                new_next_bls_committee.validity_threshold,
                true,
            )
            .await
            {
                Ok(committee) => committee,
                Err(e) => {
                    error!("failed to initiate the next committee: {e}");
                    continue;
                }
            };
            let committee_epoch = committee.epoch();
            if let Err(err) = next_epoch_committee_sender.send(committee) {
                error!(error=?err, committee_epoch=?committee_epoch, "failed to send the next epoch committee to the channel");
            } else {
                info!(committee_epoch=?committee_epoch, "The next epoch committee was sent successfully");
            }
        }
    }

    async fn new_committee(
        sui_client: Arc<SuiClient<C>>,
        committee: Vec<(ObjectID, (AuthorityName, StakeUnit))>,
        epoch: u64,
        quorum_threshold: u64,
        validity_threshold: u64,
        read_next_epoch_class_groups_keys: bool,
    ) -> DwalletMPCResult<Committee> {
        let validator_ids: Vec<_> = committee.iter().map(|(id, _)| *id).collect();

        let validators = sui_client
            .get_validators_info_by_ids(validator_ids)
            .await
            .map_err(DwalletMPCError::IkaError)?;

        let committee_mpc_data = sui_client
            .get_mpc_data_from_validators_pool(&validators, read_next_epoch_class_groups_keys)
            .await
            .map_err(DwalletMPCError::IkaError)?;

        let class_group_encryption_keys_and_proofs = committee
            .iter()
            .filter_map(|(id, (name, _))| {
                let mpc_data = committee_mpc_data.get(id);

                mpc_data.and_then(|mpc_data| {
                    let class_groups_public_key_and_proof =
                        bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(
                            &mpc_data.class_groups_public_key_and_proof(),
                        );

                    match class_groups_public_key_and_proof {
                        Ok(key_and_proof) => Some((*name, key_and_proof)),
                        Err(e) => {
                            error!(
                                "Failed to deserialize class groups public key and proof: {}",
                                e
                            );
                            None
                        }
                    }
                })
            })
            .collect::<HashMap<_, _>>();

        Ok(Committee::new(
            epoch,
            committee
                .iter()
                .map(|(_, (name, stake))| (*name, *stake))
                .collect(),
            class_group_encryption_keys_and_proofs,
            quorum_threshold,
            validity_threshold,
        ))
    }

    /// Sync the DwalletMPC network keys from the Sui client to the local store.
    async fn sync_dwallet_network_keys(
        sui_client: Arc<SuiClient<C>>,
        network_keys_sender: Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
    ) {
        // Last fetched network keys (id to epoch) to avoid fetching the same keys repeatedly.
        let mut last_fetched_network_keys: HashMap<ObjectID, u64> = HashMap::new();
        'sync_network_keys: loop {
            time::sleep(Duration::from_secs(5)).await;

            let system_inner = sui_client.must_get_system_inner_object().await;
            let current_epoch = system_inner.epoch();

            let network_encryption_keys = sui_client
                .get_dwallet_mpc_network_keys()
                .await
                .unwrap_or_else(|e| {
                    warn!("failed to fetch dwallet MPC network keys: {e}");
                    HashMap::new()
                });

            let keys_to_fetch: HashMap<ObjectID, DWalletNetworkEncryptionKey> =
                network_encryption_keys
                    .into_iter()
                    .filter(|(id, key)| {
                        if let Some(last_fetched_epoch) = last_fetched_network_keys.get(id) {
                            // If the key is cached, check if it is in the awaiting state.
                            current_epoch > *last_fetched_epoch
                        } else {
                            // If the key is not cached, we need to fetch it.
                            key.state != DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                        }
                    })
                    .collect();

            if keys_to_fetch.is_empty() {
                info!("No new network keys to fetch");
                continue;
            }

            let mut all_fetched_network_keys_data = HashMap::new();
            for (key_id, network_dec_key_shares) in keys_to_fetch.into_iter() {
                match sui_client
                    .get_network_encryption_key_with_full_data_by_epoch(
                        &network_dec_key_shares,
                        current_epoch,
                    )
                    .await
                {
                    Ok(key_full_data) => {
                        all_fetched_network_keys_data.insert(key_id, key_full_data.clone());
                        last_fetched_network_keys.insert(key_id, current_epoch);
                    }
                    Err(err) => {
                        error!(
                            key=?key_id,
                            current_epoch=?current_epoch,
                            error=?err,
                            "failed to get network decryption key data, retrying...",
                        );
                        continue 'sync_network_keys;
                    }
                }
            }
            if let Err(err) = network_keys_sender.send(Arc::new(all_fetched_network_keys_data)) {
                error!(error=?err, "failed to send network keys data to the channel",);
            }
        }
    }

    async fn sync_dwallet_end_of_publish(
        sui_client: Arc<SuiClient<C>>,
        end_of_publish_sender: Sender<Option<u64>>,
    ) {
        loop {
            time::sleep(Duration::from_secs(10)).await;

            let system_inner = sui_client.must_get_system_inner_object().await;
            let SystemInner::V1(system_inner_v1) = system_inner;
            let coordinator_inner = sui_client.must_get_dwallet_coordinator_inner().await;
            let DWalletCoordinatorInner::V1(coordinator) = coordinator_inner;
            // Check if we can advance the epoch.
            let all_epoch_sessions_finished = coordinator
                .sessions_manager
                .user_sessions_keeper
                .completed_sessions_count
                == coordinator
                    .sessions_manager
                    .last_user_initiated_session_to_complete_in_current_epoch;
            let all_immediate_sessions_completed = coordinator
                .sessions_manager
                .system_sessions_keeper
                .started_sessions_count
                == coordinator
                    .sessions_manager
                    .system_sessions_keeper
                    .completed_sessions_count;
            let next_epoch_committee_exists =
                system_inner_v1.validator_set.next_epoch_committee.is_some();
            let all_network_encryption_keys_reconfiguration_completed =
                coordinator.dwallet_network_encryption_keys.size
                    == coordinator.epoch_dwallet_network_encryption_keys_reconfiguration_completed;
            if coordinator
                .sessions_manager
                .locked_last_user_initiated_session_to_complete_in_current_epoch
                && all_epoch_sessions_finished
                && all_immediate_sessions_completed
                && next_epoch_committee_exists
                && all_network_encryption_keys_reconfiguration_completed
                && coordinator
                    .pricing_and_fee_management
                    .calculation_votes
                    .is_none()
            {
                if let Err(err) = end_of_publish_sender.send(Some(system_inner_v1.epoch)) {
                    error!(error=?err, "failed to send end of publish epoch to the channel");
                }
            }
        }
    }

    async fn run_event_listening_task(
        // The module where interested events are defined.
        // Module is always of ika system package.
        module: Identifier,
        sui_client: Arc<SuiClient<C>>,
        query_interval: Duration,
        metrics: Arc<SuiConnectorMetrics>,
        new_events_sender: tokio::sync::broadcast::Sender<Vec<SuiEvent>>,
    ) {
        info!(?module, "Starting sui events listening task");
        let mut interval = time::interval(query_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        // Create a task to update metrics
        let notify = Arc::new(Notify::new());
        let notify_clone = notify.clone();
        let sui_client_clone = sui_client.clone();
        let last_synced_sui_checkpoints_metric = metrics
            .last_synced_sui_checkpoints
            .with_label_values(&[&module.to_string()]);
        spawn_logged_monitored_task!(async move {
            loop {
                notify_clone.notified().await;
                let Ok(Ok(latest_checkpoint_sequence_number)) = retry_with_max_elapsed_time!(
                    sui_client_clone.get_latest_checkpoint_sequence_number(),
                    Duration::from_secs(120)
                ) else {
                    error!(
                        "failed to query the latest checkpoint sequence number from the sui client after retry"
                    );
                    continue;
                };
                last_synced_sui_checkpoints_metric.set(latest_checkpoint_sequence_number as i64);
            }
        });
        let mut cursor: Option<EventID> = None;
        let mut start_epoch_cursor: Option<EventID> = None;
        let mut loop_index: usize = 0;
        loop {
            // Fetching the epoch start TX digest less frequently
            // as it is unexpected to change often.
            if loop_index % 10 == 0 {
                debug!("Querying epoch start cursor from Sui");
                let SystemInner::V1(system_inner) = sui_client.must_get_system_inner_object().await;
                let Ok(epoch_start_tx_digest) = system_inner.epoch_start_tx_digest.try_into()
                else {
                    // This should not happen, but if it does, we need to know about it.
                    error!("cloud not parse `epoch_start_tx_digest` - wrong length");
                    continue;
                };
                let start_epoch_event = EventID::from((epoch_start_tx_digest, 0));
                if start_epoch_cursor != Some(start_epoch_event) {
                    start_epoch_cursor = Some(start_epoch_event);
                    cursor = start_epoch_cursor;
                }
            }
            loop_index += 1;

            interval.tick().await;
            let Ok(Ok(events)) = retry_with_max_elapsed_time!(
                sui_client.query_events_by_module(module.clone(), cursor),
                Duration::from_secs(120)
            ) else {
                // todo(zeev): alert.
                warn!("sui client failed to query events from the sui network — retrying");
                continue;
            };

            let len = events.data.len();
            if len != 0 {
                if !events.has_next_page {
                    // If this is the last page, it means we have processed all
                    // events up to the latest checkpoint
                    // We can then update the latest checkpoint metric.
                    notify.notify_one();
                }
                if let Err(e) = new_events_sender.send(events.data) {
                    error!(error=?e, ?module, "failed to send new events to the channel");
                }

                if let Some(next) = events.next_cursor {
                    cursor = Some(next);
                }
                info!(
                    ?module,
                    ?cursor,
                    "Observed {len} new events from Sui network"
                );
            }
        }
    }
}
