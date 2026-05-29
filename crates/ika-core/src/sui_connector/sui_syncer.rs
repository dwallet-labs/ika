// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The SuiSyncer module handles synchronizing Events emitted
//! on the Sui blockchain from concerned modules of `ika_system` package.
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::sui_connector::metrics::SuiConnectorMetrics;
use crate::sui_connector::sui_event_into_request::sui_event_into_session_request;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use ika_config::node::NodeMode;
use ika_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use ika_sui_client::{SuiClient, SuiClientInner, retry_with_max_elapsed_time};
use ika_types::committee::{Committee, EpochId, StakeUnit, decode_validator_encryption_keys};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::IkaResult;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use ika_types::sui::{
    DWalletCoordinator, DWalletCoordinatorInner, System, SystemInner, SystemInnerTrait,
};
use mysten_metrics::spawn_logged_monitored_task;
use std::{collections::HashMap, sync::Arc};
use sui_types::base_types::ObjectID;
use sui_types::{Identifier, event::EventID};
use tokio::sync::watch::{Receiver, Sender};
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
        chain_next_committee_sender: Sender<Committee>,
        mode: NodeMode,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        network_keys_sender: Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        new_requests_sender: tokio::sync::broadcast::Sender<Vec<DWalletSessionRequest>>,
        end_of_publish_sender: Sender<Option<u64>>,
        last_session_to_complete_in_current_epoch_sender: Sender<(EpochId, u64)>,
        uncompleted_requests_sender: Sender<(Vec<DWalletSessionRequest>, EpochId)>,
        noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync>,
        network_key_blob_source: Arc<
            arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::NetworkKeyBlobSource>>,
        >,
        class_groups_source: Arc<
            arc_swap::ArcSwapOption<
                Box<dyn crate::validator_metadata::OffChainCommitteeClassGroupsSource>,
            >,
        >,
    ) -> IkaResult<Vec<JoinHandle<()>>> {
        info!(?mode, "Starting SuiSyncer");
        let mut task_handles = vec![];
        let sui_client_clone = self.sui_client.clone();

        // All modes need network keys (for mid-epoch reconfiguration)
        info!("Starting network keys sync task");
        tokio::spawn(Self::sync_dwallet_network_keys(
            sui_client_clone.clone(),
            system_object_receiver.clone(),
            dwallet_coordinator_object_receiver.clone(),
            network_keys_sender,
            network_key_blob_source,
        ));

        // Validator-only tasks: committee sync, end of publish, session tracking, uncompleted events
        if mode.is_validator() {
            info!("Starting next epoch committee sync task");
            tokio::spawn(Self::sync_next_committee(
                sui_client_clone.clone(),
                system_object_receiver.clone(),
                next_epoch_committee_sender.clone(),
                chain_next_committee_sender.clone(),
                class_groups_source.clone(),
            ));
            info!("Starting end of publish sync task");
            tokio::spawn(Self::sync_dwallet_end_of_publish(
                system_object_receiver.clone(),
                dwallet_coordinator_object_receiver.clone(),
                end_of_publish_sender,
                noa_checkpoints_finalized,
            ));
            info!("Syncing last session to complete in current epoch");
            tokio::spawn(Self::sync_last_session_to_complete_in_current_epoch(
                dwallet_coordinator_object_receiver.clone(),
                last_session_to_complete_in_current_epoch_sender,
            ));
            info!("Syncing uncompleted events");
            tokio::spawn(Self::sync_uncompleted_events(
                sui_client_clone,
                dwallet_coordinator_object_receiver.clone(),
                uncompleted_requests_sender,
            ));
        }

        // Event listening: only validators need to listen to events to process MPC sessions
        // Fullnodes sync state via P2P, notifiers only submit checkpoints
        if mode.is_validator() {
            let ika_dwallet_2pc_mpc_package_id = self
                .sui_client
                .ika_network_config
                .packages
                .ika_dwallet_2pc_mpc_package_id;
            let ika_dwallet_2pc_mpc_package_id_v2 = self
                .sui_client
                .ika_network_config
                .packages
                .ika_dwallet_2pc_mpc_package_id_v2;
            let mut package_ids = vec![ika_dwallet_2pc_mpc_package_id];
            if let Some(ika_dwallet_2pc_mpc_package_id_v2) = ika_dwallet_2pc_mpc_package_id_v2 {
                package_ids.push(ika_dwallet_2pc_mpc_package_id_v2);
            }
            for package_id in package_ids {
                for module in self.modules.clone() {
                    let metrics = self.metrics.clone();
                    let sui_client_clone = self.sui_client.clone();
                    let new_requests_sender_clone = new_requests_sender.clone();
                    let system_object_receiver_clone = system_object_receiver.clone();
                    task_handles.push(spawn_logged_monitored_task!(
                        Self::run_event_listening_task(
                            system_object_receiver_clone,
                            module,
                            package_id,
                            sui_client_clone,
                            query_interval,
                            metrics,
                            new_requests_sender_clone,
                        )
                    ));
                }
            }
        } else {
            info!(?mode, "Skipping event listening task");
        }

        Ok(task_handles)
    }

    async fn sync_last_session_to_complete_in_current_epoch(
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        last_session_to_complete_in_current_epoch_sender: Sender<(EpochId, u64)>,
    ) {
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            let Some((_, coordinator_inner)) = dwallet_coordinator_object_receiver
                .borrow()
                .as_ref()
                .cloned()
            else {
                warn!("DWalletCoordinator object not available, retrying...");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };

            let DWalletCoordinatorInner::V1(inner) = coordinator_inner;
            if let Err(err) = last_session_to_complete_in_current_epoch_sender.send((
                inner.current_epoch,
                inner
                    .sessions_manager
                    .last_user_initiated_session_to_complete_in_current_epoch,
            )) {
                error!(
                    error=?err,
                    epoch=?inner.current_epoch,
                    last_session_to_complete_in_current_epoch=?inner.sessions_manager.last_user_initiated_session_to_complete_in_current_epoch,
                    "failed to send last session to complete in current epoch",
                )
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn sync_uncompleted_events(
        sui_client: Arc<SuiClient<C>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        uncompleted_requests_sender: Sender<(Vec<DWalletSessionRequest>, EpochId)>,
    ) {
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            let Some((_, coordinator_inner)) = dwallet_coordinator_object_receiver
                .borrow()
                .as_ref()
                .cloned()
            else {
                warn!("DWalletCoordinator object not available, retrying...");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };

            match sui_client
                .pull_dwallet_mpc_uncompleted_events(&coordinator_inner)
                .await
            {
                Ok((events, epoch)) => {
                    let requests = events.iter().filter_map(|event| {
                        debug!(
                            event_type=?event.type_.clone(),
                            current_epoch=?epoch,
                            contents=?event.contents.clone(),
                            "Processing an uncompleted event from Sui"
                        );

                        match sui_event_into_session_request(
                            &sui_client.ika_network_config,
                            event.type_.clone(),
                            &event.contents,
                            true,
                        ) {
                            Ok(Some(event)) => {
                                Some(event)
                            }
                            Ok(None) => None,
                            Err(e) => {
                                error!(error=?e, event_type =? event.type_, "failed to parse Sui event");
                                None
                            }
                        }
                    }).collect::<Vec<_>>();

                    if let Err(err) = uncompleted_requests_sender.send((requests, epoch)) {
                        error!(
                            error=?err,
                            current_epoch=?epoch,
                            "failed to send uncompleted events to the channel"
                        );
                    };
                }
                Err(err) => {
                    warn!(
                        error=?err,
                         "failed to load missed events from Sui"
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn sync_next_committee(
        sui_client: Arc<SuiClient<C>>,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        next_epoch_committee_sender: Sender<Committee>,
        chain_next_committee_sender: Sender<Committee>,
        class_groups_source: Arc<
            arc_swap::ArcSwapOption<
                Box<dyn crate::validator_metadata::OffChainCommitteeClassGroupsSource>,
            >,
        >,
    ) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let Some((_, system_inner)) = system_object_receiver.borrow().as_ref().cloned() else {
                warn!("System object not available, retrying...");
                continue;
            };
            let SystemInner::V1(system_inner) = system_inner;
            let Some(new_next_bls_committee) = system_inner.get_ika_next_epoch_committee() else {
                debug!("ika next epoch active committee not found, retrying...");
                continue;
            };

            let new_next_committee = system_inner.read_bls_committee(&new_next_bls_committee);

            // Publish the CHAIN view of the next-epoch committee
            // (members + stake, no class-groups) as soon as Sui has it
            // — independent of the off-chain class-groups assembly
            // below. The off-chain assembly can't `Complete` for a
            // committee containing a not-yet-announced joiner, and the
            // joiner only learns it's a joiner (to fan out its mpc_data)
            // from this signal — so gating the joiner watcher / freeze
            // emit-gate on the *assembled* committee would deadlock
            // (assembled-needs-joiner-mpc_data ↔ joiner-fanout-needs-
            // assembled). This chain signal breaks that cycle. It
            // carries only membership + stake (empty class-groups maps)
            // — all the freeze emit-gate and joiner watcher read.
            let chain_committee = Committee::new(
                system_inner.epoch() + 1,
                new_next_committee
                    .iter()
                    .map(|(_, (name, stake))| (*name, *stake))
                    .collect(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                new_next_bls_committee.quorum_threshold,
                new_next_bls_committee.validity_threshold,
            );
            let _ = chain_next_committee_sender.send(chain_committee);

            let off_chain_on = ProtocolConfig::get_for_version(
                ProtocolVersion::new(system_inner.protocol_version()),
                Chain::Unknown,
            )
            .off_chain_validator_metadata_enabled();
            let committee = match Self::new_committee(
                sui_client.clone(),
                new_next_committee.clone(),
                system_inner.epoch() + 1,
                new_next_bls_committee.quorum_threshold,
                new_next_bls_committee.validity_threshold,
                true,
                class_groups_source.clone(),
                off_chain_on,
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
        class_groups_source: Arc<
            arc_swap::ArcSwapOption<
                Box<dyn crate::validator_metadata::OffChainCommitteeClassGroupsSource>,
            >,
        >,
        off_chain_on: bool,
    ) -> DwalletMPCResult<Committee> {
        // Try the off-chain assembly first. The strict
        // `Complete`/`Incomplete` gate inside the source means we
        // only use the off-chain map when every (non-excluded)
        // committee member resolved successfully. Under off-chain
        // mode (`off_chain_on == true`) an `Incomplete` result
        // returns `OffChainAssemblyIncomplete` and the outer sync
        // loop retries on the next tick — there is no chain
        // fallback for validator mpc_data; chain is write-only.
        // Under legacy mode (`off_chain_on == false`) we fall
        // through to the chain read below so existing clusters
        // keep working.
        if let Some(source) = class_groups_source.load_full() {
            let authorities: Vec<AuthorityName> =
                committee.iter().map(|(_, (name, _))| *name).collect();
            match source.try_assemble_class_groups(&authorities) {
                crate::validator_metadata::OffChainClassGroupsAssembly::Complete(bundles) => {
                    info!(
                        epoch,
                        members = bundles.class_groups.len(),
                        secp256k1_pvss = bundles.secp256k1_pvss.len(),
                        secp256r1_pvss = bundles.secp256r1_pvss.len(),
                        ristretto_pvss = bundles.ristretto_pvss.len(),
                        "assembled committee class-groups off-chain"
                    );
                    return Ok(Committee::new(
                        epoch,
                        committee
                            .iter()
                            .map(|(_, (name, stake))| (*name, *stake))
                            .collect(),
                        bundles.class_groups,
                        bundles.secp256k1_pvss,
                        bundles.secp256r1_pvss,
                        bundles.ristretto_pvss,
                        quorum_threshold,
                        validity_threshold,
                    ));
                }
                crate::validator_metadata::OffChainClassGroupsAssembly::Incomplete { missing } => {
                    if off_chain_on {
                        // Under v4 there is NO chain fallback. The
                        // off-chain pipeline (consensus
                        // announcements + P2P blob delivery +
                        // attestation-tally freeze) is the only
                        // path; missing entries here are transient
                        // (P2P hasn't converged yet) and the
                        // outer sync loop should retry on the next
                        // tick. Return a typed error rather than
                        // silently reading from chain.
                        warn!(
                            epoch,
                            missing = missing.len(),
                            ?missing,
                            "off_chain mode: off-chain class-groups assembly incomplete; \
                             no chain fallback — retrying on next sync tick"
                        );
                        return Err(DwalletMPCError::OffChainAssemblyIncomplete {
                            epoch,
                            missing: missing.len(),
                        });
                    } else {
                        debug!(
                            epoch,
                            missing = missing.len(),
                            "off-chain class-groups assembly incomplete; falling back to chain"
                        );
                    }
                }
            }
        }

        let validator_ids: Vec<_> = committee.iter().map(|(id, _)| *id).collect();

        let validators = sui_client
            .get_validators_info_by_ids(validator_ids)
            .await
            .map_err(DwalletMPCError::IkaError)?;

        let committee_mpc_data = sui_client
            .get_mpc_data_from_validators_pool(&validators, read_next_epoch_class_groups_keys)
            .await
            .map_err(DwalletMPCError::IkaError)?;

        // Shape-tolerant decode per validator. PVSS HashMaps gain an entry only
        // when the validator published the post-PR-#1707 bundle shape;
        // mainnet-v1.1.8-shape validators contribute only their class-groups key.
        let decoded_per_validator: Vec<_> = committee
            .iter()
            .filter_map(|(id, (name, _))| {
                let mpc_data = committee_mpc_data.get(id)?;
                let decoded = decode_validator_encryption_keys(
                    &mpc_data.class_groups_public_key_and_proof(),
                );
                if decoded.is_none() {
                    warn!(
                        authority = ?name,
                        "Failed to decode validator encryption keys (neither mainnet-v1.1.8 nor post-PR-#1707 shape)"
                    );
                }
                decoded.map(|d| (*name, d))
            })
            .collect();

        let class_group_encryption_keys_and_proofs: HashMap<_, _> = decoded_per_validator
            .iter()
            .map(|(n, v)| (*n, v.class_groups.clone()))
            .collect();
        let secp256k1_pvss_public_keys_and_proofs: HashMap<_, _> = decoded_per_validator
            .iter()
            .filter_map(|(n, v)| v.secp256k1_pvss.clone().map(|k| (*n, k)))
            .collect();
        let secp256r1_pvss_public_keys_and_proofs: HashMap<_, _> = decoded_per_validator
            .iter()
            .filter_map(|(n, v)| v.secp256r1_pvss.clone().map(|k| (*n, k)))
            .collect();
        let ristretto_pvss_public_keys_and_proofs: HashMap<_, _> = decoded_per_validator
            .iter()
            .filter_map(|(n, v)| v.ristretto_pvss.clone().map(|k| (*n, k)))
            .collect();

        Ok(Committee::new(
            epoch,
            committee
                .iter()
                .map(|(_, (name, stake))| (*name, *stake))
                .collect(),
            class_group_encryption_keys_and_proofs,
            secp256k1_pvss_public_keys_and_proofs,
            secp256r1_pvss_public_keys_and_proofs,
            ristretto_pvss_public_keys_and_proofs,
            quorum_threshold,
            validity_threshold,
        ))
    }

    /// Sync the DwalletMPC network keys from the Sui client to the local store.
    async fn sync_dwallet_network_keys(
        sui_client: Arc<SuiClient<C>>,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        network_keys_sender: Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        network_key_blob_source: Arc<
            arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::NetworkKeyBlobSource>>,
        >,
    ) {
        // Last fetched network keys (id -> (epoch, state)). The
        // state is part of the cache key because chain-side state
        // transitions within an epoch (e.g. NetworkReconfigurationStarted
        // -> NetworkReconfigurationCompleted) change the protocol-output
        // blobs we hand to downstream consumers. Caching by epoch
        // alone would freeze a stale snapshot for the rest of the
        // epoch, causing the handoff items list to diverge across
        // validators depending on first-fetch timing.
        let mut last_fetched_network_keys: HashMap<
            ObjectID,
            (u64, DWalletNetworkEncryptionKeyState),
        > = HashMap::new();
        'sync_network_keys: loop {
            time::sleep(Duration::from_secs(5)).await;

            let Some((_, system_inner)) = system_object_receiver.borrow().as_ref().cloned() else {
                warn!("System object not available, retrying...");
                continue;
            };
            let Some((_, dwallet_coordinator_inner)) = dwallet_coordinator_object_receiver
                .borrow()
                .as_ref()
                .cloned()
            else {
                warn!("DWalletCoordinator object not available, retrying...");
                continue;
            };
            let current_epoch = system_inner.epoch();
            let protocol_version = ProtocolVersion::new(system_inner.protocol_version());
            // Off-chain mode: validator mpc_data, network-key DKG
            // outputs, and reconfiguration outputs are sourced from
            // consensus + P2P + the local producer cache. Chain is
            // write-only for these blob fields. The
            // off_chain_validator_metadata flag is detected from
            // chain state so the behavior tracks protocol-version
            // upgrades automatically.
            let off_chain_on = ProtocolConfig::get_for_version(protocol_version, Chain::Unknown)
                .off_chain_validator_metadata_enabled();

            let network_encryption_keys = sui_client
                .get_dwallet_mpc_network_keys(&dwallet_coordinator_inner)
                .await
                .unwrap_or_else(|e| {
                    warn!("failed to fetch dwallet MPC network keys: {e}");
                    HashMap::new()
                });

            let keys_to_fetch: HashMap<ObjectID, DWalletNetworkEncryptionKey> =
                network_encryption_keys
                    .into_iter()
                    .filter(|(id, key)| {
                        if let Some((last_epoch, last_state)) = last_fetched_network_keys.get(id) {
                            // Refetch when either the epoch has
                            // advanced or the chain-side state has
                            // progressed since the last cached
                            // snapshot.
                            current_epoch > *last_epoch || key.state != *last_state
                        } else {
                            // Not cached yet — fetch if the key has
                            // moved past initial DKG.
                            key.state != DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG
                        }
                    })
                    .collect();

            if keys_to_fetch.is_empty() {
                info!("No new network keys to fetch");
                continue;
            }
            let mut all_fetched_network_keys_data: HashMap<_, _> =
                (*network_keys_sender.borrow().clone()).clone();
            for (key_id, network_dec_key_shares) in keys_to_fetch.into_iter() {
                // In off-chain mode, synthesize a metadata-only
                // `DWalletNetworkEncryptionKeyData` from the
                // lightweight chain object so we skip the heavy
                // `read_table_vec_as_raw_bytes` chain reads. The
                // overlay below substitutes the actual blob bytes
                // from the local producer cache (which all honest
                // validators populate from their own MPC outputs).
                let chain_fetched = if off_chain_on {
                    Ok(
                        ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData {
                            id: network_dec_key_shares.id,
                            current_epoch,
                            dkg_at_epoch: network_dec_key_shares.dkg_at_epoch,
                            network_dkg_public_output: vec![],
                            current_reconfiguration_public_output: vec![],
                            state: network_dec_key_shares.state.clone(),
                        },
                    )
                } else {
                    sui_client
                        .get_network_encryption_key_with_full_data_by_epoch(
                            &network_dec_key_shares,
                            current_epoch,
                        )
                        .await
                };
                match chain_fetched {
                    Ok(key_full_data) => {
                        // Off-chain overlay: prefer locally-cached
                        // protocol-output blobs (populated by the
                        // producer-side caching path on MPC output)
                        // over the chain blobs. The lightweight
                        // metadata (id, epoch, state, dkg_at_epoch)
                        // always comes from chain. If no source is
                        // installed or the source has neither blob,
                        // the merged value equals the chain copy
                        // byte-for-byte.
                        let merged = match network_key_blob_source.load_full() {
                            Some(source) => {
                                crate::validator_metadata::fetch_network_key_data_with_off_chain_blobs(
                                    key_full_data,
                                    source.as_ref().as_ref(),
                                )
                            }
                            None => key_full_data,
                        };
                        // Under off-chain mode the chain copy carries
                        // empty blob bytes; the overlay above fills
                        // them from the local producer cache. Every
                        // fetched key is past `AwaitingNetworkDKG`, so
                        // a non-empty `network_dkg_public_output` is
                        // the invariant for a usable entry. If it's
                        // still empty — the blob source wasn't
                        // installed yet (startup race) or this
                        // validator hasn't cached its DKG output yet —
                        // publish the partial value to the channel but
                        // do NOT record it in `last_fetched_network_keys`,
                        // so a later tick re-merges once the overlay
                        // has the bytes. Without this, the
                        // `(epoch, state)` cache key would pin the
                        // empty blobs for the rest of the epoch.
                        let overlay_incomplete =
                            off_chain_on && merged.network_dkg_public_output.is_empty();
                        let merged_state = merged.state.clone();
                        all_fetched_network_keys_data.insert(key_id, merged);
                        if overlay_incomplete {
                            warn!(
                                key = ?key_id,
                                current_epoch,
                                "off-chain network-key overlay has no DKG output yet \
                                 (blob source not installed or output not cached); \
                                 will retry next tick"
                            );
                        } else {
                            last_fetched_network_keys
                                .insert(key_id, (current_epoch, merged_state));
                        }
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
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        end_of_publish_sender: Sender<Option<u64>>,
        noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync>,
    ) {
        loop {
            time::sleep(Duration::from_secs(10)).await;

            let Some((_, system_inner)) = system_object_receiver.borrow().as_ref().cloned() else {
                warn!("System object not available, retrying...");
                continue;
            };
            let SystemInner::V1(system_inner_v1) = system_inner;
            let Some((_, coordinator_inner)) = dwallet_coordinator_object_receiver
                .borrow()
                .as_ref()
                .cloned()
            else {
                warn!("DWalletCoordinator object not available, retrying...");
                continue;
            };
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
            let all_noa_checkpoints_finalized = noa_checkpoints_finalized();
            if coordinator
                .sessions_manager
                .locked_last_user_initiated_session_to_complete_in_current_epoch
                && all_epoch_sessions_finished
                && all_immediate_sessions_completed
                && next_epoch_committee_exists
                && all_network_encryption_keys_reconfiguration_completed
                && all_noa_checkpoints_finalized
                && coordinator
                    .pricing_and_fee_management
                    .calculation_votes
                    .is_none()
                && let Err(err) = end_of_publish_sender.send(Some(system_inner_v1.epoch))
            {
                error!(error=?err, "failed to send end of publish epoch to the channel");
            }
        }
    }

    async fn run_event_listening_task(
        // The module where interested events are defined.
        // Module is always of ika system package.
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        module: Identifier,
        package_id: ObjectID,
        sui_client: Arc<SuiClient<C>>,
        query_interval: Duration,
        metrics: Arc<SuiConnectorMetrics>,
        new_requests_sender: tokio::sync::broadcast::Sender<Vec<DWalletSessionRequest>>,
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
            if loop_index.is_multiple_of(10) {
                debug!("Querying epoch start cursor from Sui");
                let Some((_, system_inner)) = system_object_receiver.borrow().as_ref().cloned()
                else {
                    warn!("System object not available, retrying...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                };
                let SystemInner::V1(system_inner) = system_inner;
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
                sui_client.query_events_by_module(module.clone(), package_id, cursor),
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

                let requests = events
                    .data
                    .iter()
                    .filter_map(|event| {
                        match sui_event_into_session_request(
                            &sui_client.ika_network_config,
                            event.type_.clone(),
                            event.bcs.bytes(),
                            false,
                        ) {
                            Ok(Some(request)) => Some(request),
                            Ok(None) => None,
                            Err(e) => {
                                error!(error=?e, ?module, event_type =? event.type_, "failed to parse Sui event");
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>();

                if let Err(e) = new_requests_sender.send(requests) {
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
