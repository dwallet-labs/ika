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
use ika_types::committee::{
    Committee, CommitteeMembership, EpochId, StakeUnit, decode_validator_encryption_keys,
};
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

/// Per-loop dedup/latch state for `new_committee`'s assembly logging,
/// carried across `sync_next_committee` ticks so the per-tick
/// re-assembly doesn't re-log identical outcomes at info/error.
#[derive(Default)]
struct AssemblyLogState {
    /// Last `(epoch, frozen, members, secp256k1, secp256r1, ristretto)`
    /// assembly summary logged at info — identical repeats demote to debug.
    last_logged_assembly: Option<(EpochId, bool, usize, usize, usize, usize)>,
    /// Epoch for which the PERMANENT `EverythingExcluded` wedge was
    /// already logged at error — repeats demote to debug (the
    /// `off_chain_assembly_wedged` gauge carries the ongoing state).
    wedge_logged_for_epoch: Option<EpochId>,
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
        chain_next_committee_sender: Sender<CommitteeMembership>,
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
                Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>,
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
            mode,
            self.metrics.clone(),
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
                self.metrics.clone(),
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
                system_object_receiver.clone(),
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
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
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
            // Epoch-scale the re-poll so a restarted validator re-discovers
            // in-flight session requests (system + reconfiguration) fast
            // enough to drive them to completion before the epoch's
            // end-of-publish window. Without this, a mid-epoch restart at a
            // short epoch leaves those sessions `WaitingForSessionRequest`
            // (never re-advanced) and the epoch can't advance. A no-op at
            // production epoch lengths (clamps back to 30s). Mirrors the
            // epoch-scaling already done by `sync_next_committee`.
            let epoch_duration_ms = system_object_receiver
                .borrow()
                .as_ref()
                .map(|(_, system_inner)| system_inner.epoch_duration_ms());
            let poll_interval = epoch_duration_ms
                .map(|ms| {
                    crate::validator_metadata::epoch_scaled_poll_interval(
                        ms,
                        Duration::from_secs(30),
                    )
                })
                .unwrap_or(Duration::from_secs(30));
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn sync_next_committee(
        sui_client: Arc<SuiClient<C>>,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        next_epoch_committee_sender: Sender<Committee>,
        chain_next_committee_sender: Sender<CommitteeMembership>,
        class_groups_source: Arc<
            arc_swap::ArcSwapOption<
                Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>,
            >,
        >,
        metrics: Arc<SuiConnectorMetrics>,
    ) {
        let mut poll_interval = Duration::from_secs(10);
        // Epoch for which a post-freeze (final) committee was already
        // sent. Post-freeze, the off-chain assembly is a pure function
        // of the immutable frozen set, so re-assembling and re-sending
        // every tick is pure waste — skip until the epoch advances.
        let mut final_committee_sent_for_epoch: Option<EpochId> = None;
        // Consecutive ticks the off-chain assembly returned Incomplete —
        // expected benign retry while announcements/blobs converge, so
        // the per-tick log is debug; escalate to warn every 30th
        // consecutive tick so a genuine stall still surfaces.
        let mut consecutive_incomplete_ticks: u64 = 0;
        // Dedup/latch state for the assembly logging inside `new_committee`.
        let mut assembly_log_state = AssemblyLogState::default();
        // Last `(epoch, frozen)` committee send logged at info — the
        // pre-freeze window re-sends every tick, so intermediate
        // re-sends demote to debug.
        let mut last_logged_committee_send: Option<(EpochId, bool)> = None;
        loop {
            time::sleep(poll_interval).await;
            let Some((_, system_inner)) = system_object_receiver.borrow().as_ref().cloned() else {
                warn!("System object not available, retrying...");
                continue;
            };
            // Observe a newly-published `V_{e+1}` promptly enough that a
            // joiner can fan its mpc_data out inside the freeze window in
            // short (test) epochs; a no-op at production epoch lengths.
            poll_interval = crate::validator_metadata::epoch_scaled_poll_interval(
                system_inner.epoch_duration_ms(),
                Duration::from_secs(10),
            );
            let SystemInner::V1(system_inner) = system_inner;
            let Some(new_next_bls_committee) = system_inner.get_ika_next_epoch_committee() else {
                debug!("ika next epoch active committee not found, retrying...");
                continue;
            };

            let new_next_committee = system_inner.read_bls_committee(&new_next_bls_committee);

            // Publish the CHAIN view of the next-epoch committee
            // (members + stake, no class-groups) as soon as Sui has it
            // — independent of the off-chain validator-mpc_data assembly
            // below. The off-chain assembly can't `Complete` for a
            // committee containing a not-yet-announced joiner, and the
            // joiner only learns it's a joiner (to fan out its mpc_data)
            // from this signal — so gating the joiner watcher / freeze
            // emit-gate on the *assembled* committee would deadlock
            // (assembled-needs-joiner-mpc_data ↔ joiner-fanout-needs-
            // assembled). This chain signal breaks that cycle. It
            // carries only membership + stake (empty mpc_data crypto maps)
            // — all the freeze emit-gate and joiner watcher read.
            let next_epoch = system_inner.epoch() + 1;
            let chain_committee = CommitteeMembership {
                epoch: next_epoch,
                voting_rights: new_next_committee
                    .iter()
                    .map(|(_, (name, stake))| (*name, *stake))
                    .collect(),
                quorum_threshold: new_next_bls_committee.quorum_threshold,
                validity_threshold: new_next_bls_committee.validity_threshold,
            };
            // Only wake receivers when the chain view actually changed;
            // an unconditional `send` marks the watch changed every tick.
            chain_next_committee_sender.send_if_modified(|current| {
                if *current != chain_committee {
                    *current = chain_committee;
                    true
                } else {
                    false
                }
            });

            if final_committee_sent_for_epoch == Some(next_epoch) {
                continue;
            }

            let off_chain_on = ProtocolConfig::get_for_version(
                ProtocolVersion::new(system_inner.protocol_version()),
                Chain::Unknown,
            )
            .off_chain_validator_metadata_enabled();
            // Snapshot the source once so the freeze probe and the
            // assembly read the SAME per-epoch store: the freeze flag is
            // monotonic within a store, so `is_frozen == true` here
            // guarantees the assembly below used the frozen pairs.
            let class_groups_snapshot = class_groups_source.load_full();
            let frozen_at_assembly = class_groups_snapshot
                .as_ref()
                .is_some_and(|source| source.is_frozen());
            let committee = match Self::new_committee(
                sui_client.clone(),
                new_next_committee.clone(),
                next_epoch,
                new_next_bls_committee.quorum_threshold,
                new_next_bls_committee.validity_threshold,
                true,
                class_groups_snapshot,
                off_chain_on,
                frozen_at_assembly,
                &mut assembly_log_state,
                &metrics,
            )
            .await
            {
                Ok(committee) => {
                    consecutive_incomplete_ticks = 0;
                    committee
                }
                Err(e @ DwalletMPCError::OffChainAssemblyIncomplete { .. }) => {
                    // Expected per-tick retry while the off-chain pipeline
                    // converges (every epoch, even with zero churn) — the
                    // assembly outcome was already logged inside
                    // `new_committee`. Demote the per-tick wrapper to
                    // debug; escalate every 30th consecutive tick so a
                    // genuine stall still surfaces at warn.
                    consecutive_incomplete_ticks += 1;
                    metrics.off_chain_assembly_incomplete_ticks_total.inc();
                    if consecutive_incomplete_ticks.is_multiple_of(30) {
                        warn!(
                            consecutive_incomplete_ticks,
                            "off-chain validator-mpc_data assembly still incomplete after \
                             many consecutive sync ticks: {e}"
                        );
                    } else {
                        debug!(
                            consecutive_incomplete_ticks,
                            "failed to initiate the next committee: {e}"
                        );
                    }
                    continue;
                }
                Err(e) => {
                    error!("failed to initiate the next committee: {e}");
                    continue;
                }
            };
            let committee_epoch = committee.epoch();
            if let Err(err) = next_epoch_committee_sender.send(committee) {
                error!(error=?err, committee_epoch=?committee_epoch, "failed to send the next epoch committee to the channel");
            } else {
                // The committee is re-sent every pre-freeze tick; log the
                // first send for the epoch and the final (frozen) send at
                // info, intermediate identical re-sends at debug.
                let send_log_key = (committee_epoch, frozen_at_assembly);
                if last_logged_committee_send != Some(send_log_key) {
                    info!(
                        committee_epoch=?committee_epoch,
                        frozen = frozen_at_assembly,
                        "The next epoch committee was sent successfully"
                    );
                    last_logged_committee_send = Some(send_log_key);
                } else {
                    debug!(
                        committee_epoch=?committee_epoch,
                        frozen = frozen_at_assembly,
                        "re-sent the next epoch committee (unchanged)"
                    );
                }
                if frozen_at_assembly {
                    final_committee_sent_for_epoch = Some(next_epoch);
                }
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
        class_groups_source: Option<
            Arc<Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>>,
        >,
        off_chain_on: bool,
        frozen_at_assembly: bool,
        log_state: &mut AssemblyLogState,
        metrics: &SuiConnectorMetrics,
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
        if let Some(source) = class_groups_source {
            let authorities: Vec<AuthorityName> =
                committee.iter().map(|(_, (name, _))| *name).collect();
            match source.try_assemble_mpc_data(&authorities) {
                crate::validator_metadata::OffChainMpcDataAssembly::Complete(bundles) => {
                    metrics.off_chain_assembly_wedged.set(0);
                    // Pre-freeze, the assembly re-runs (and re-succeeds)
                    // every sync tick; log at info only when the assembled
                    // membership/counts change or on the final (frozen)
                    // assembly, debug otherwise.
                    let assembly_summary = (
                        epoch,
                        frozen_at_assembly,
                        bundles.class_groups.len(),
                        bundles.secp256k1_pvss.len(),
                        bundles.secp256r1_pvss.len(),
                        bundles.ristretto_pvss.len(),
                    );
                    if log_state.last_logged_assembly != Some(assembly_summary) {
                        info!(
                            epoch,
                            members = bundles.class_groups.len(),
                            secp256k1_pvss = bundles.secp256k1_pvss.len(),
                            secp256r1_pvss = bundles.secp256r1_pvss.len(),
                            ristretto_pvss = bundles.ristretto_pvss.len(),
                            frozen = frozen_at_assembly,
                            "assembled committee mpc_data off-chain"
                        );
                        log_state.last_logged_assembly = Some(assembly_summary);
                    } else {
                        debug!(
                            epoch,
                            members = bundles.class_groups.len(),
                            frozen = frozen_at_assembly,
                            "re-assembled identical committee mpc_data off-chain"
                        );
                    }
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
                crate::validator_metadata::OffChainMpcDataAssembly::Incomplete { missing } => {
                    if off_chain_on {
                        // Under v4 there is NO chain fallback. The
                        // off-chain pipeline (consensus
                        // announcements + P2P blob delivery +
                        // attestation-tally freeze) is the only
                        // path; missing entries here are transient
                        // (P2P hasn't converged yet) and the
                        // outer sync loop should retry on the next
                        // tick — expected every epoch during the
                        // convergence window, so the per-tick log is
                        // debug (the caller escalates a persistent
                        // stall). Return a typed error rather than
                        // silently reading from chain.
                        debug!(
                            epoch,
                            missing = missing.len(),
                            ?missing,
                            "off_chain mode: off-chain validator-mpc_data assembly incomplete; \
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
                            "off-chain validator-mpc_data assembly incomplete; falling back to chain"
                        );
                    }
                }
                crate::validator_metadata::OffChainMpcDataAssembly::EverythingExcluded => {
                    if off_chain_on {
                        // PERMANENT, not transient: the freeze excluded
                        // EVERY requested committee member, so there is no
                        // attested mpc_data to assemble from — the off-chain
                        // assembly can never converge this epoch and
                        // reconfiguration into it is WEDGED. Escalate to
                        // `error!` (vs the transient `Incomplete` retry) so
                        // an operator is alerted; the likely cause is no
                        // next-committee member's announcement landing
                        // before the freeze (joiner relay / propagation
                        // failure, or a misfrozen set). The state is a fixed
                        // point for the rest of the epoch, so the error is
                        // latched once per epoch (repeats at debug); the
                        // `off_chain_assembly_wedged` gauge carries the
                        // ongoing state for alerting.
                        metrics.off_chain_assembly_wedged.set(1);
                        if log_state.wedge_logged_for_epoch != Some(epoch) {
                            error!(
                                epoch,
                                members = authorities.len(),
                                "off_chain mode: off-chain validator-mpc_data assembly is \
                                 PERMANENTLY incomplete — the freeze excluded EVERY committee \
                                 member, so reconfiguration into this epoch is WEDGED (no attested \
                                 mpc_data). Investigate next-committee announcement propagation."
                            );
                            log_state.wedge_logged_for_epoch = Some(epoch);
                        } else {
                            debug!(
                                epoch,
                                members = authorities.len(),
                                "off-chain validator-mpc_data assembly still wedged \
                                 (EverythingExcluded)"
                            );
                        }
                        return Err(DwalletMPCError::OffChainAssemblyIncomplete {
                            epoch,
                            missing: authorities.len(),
                        });
                    } else {
                        debug!(
                            epoch,
                            "off-chain assembly EverythingExcluded; falling back to chain"
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
        mode: NodeMode,
        metrics: Arc<SuiConnectorMetrics>,
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
        // Consecutive 5s ticks each key's overlay has been incomplete.
        // An incomplete overlay is the designed steady state on a
        // notifier/fullnode (whose overlay is legitimately empty for
        // keys it didn't compute) and a normal transient on validators
        // (fresh-key DKG window, chain-state flip before the local
        // cache write), so the per-tick log is debug; a committee
        // validator stuck incomplete escalates to warn every 60th
        // consecutive tick (~5 min).
        let mut consecutive_overlay_incomplete_ticks: HashMap<ObjectID, u64> = HashMap::new();
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
            let mut incomplete_overlay_keys_this_pass: i64 = 0;
            for (key_id, network_dec_key_shares) in keys_to_fetch.into_iter() {
                // In off-chain mode, synthesize a metadata-only
                // `DWalletNetworkEncryptionKeyData` from the
                // lightweight chain object so we skip the heavy
                // `read_table_vec_as_raw_bytes` chain reads. The
                // overlay below substitutes the actual blob bytes
                // from the local producer cache (which all honest
                // validators populate from their own MPC outputs).
                // ===================================================================
                // TODO(v3->v4 migration): REMOVE this temporary branch after the
                // upgrade is complete and every network key has been reconfigured
                // under v4 (i.e. all keys are in the off-chain handoff plane).
                //
                // A network key whose DKG / last reconfiguration ran while
                // off-chain metadata was disabled (protocol v3) has its
                // authoritative blobs only on chain — they were never written to
                // the off-chain handoff plane. The off-chain fast path below
                // synthesizes metadata-only data with EMPTY blobs (the overlay
                // normally fills them from the local cache), which would leave
                // such a pre-v4 key unrepresented and wedge the first v4
                // reconfiguration on an undecryptable share. So when the key's
                // DKG output isn't in the handoff yet, fall back to the full
                // chain read to import its real blobs; the overlay then adopts
                // the chain copy until the key has migrated off-chain.
                //
                // The gate is whether this key's DKG output is present in the
                // off-chain handoff plane. The DKG output is the stable,
                // one-time anchor of a network key: a v4-native key always has
                // it in the handoff (cached and durably mirrored to perpetual
                // when the key was DKG'd under v4), whereas a pre-v4 key whose
                // DKG ran while off-chain metadata was disabled never put it
                // there. We deliberately gate on the DKG blob rather than the
                // reconfiguration blob: the per-epoch reconfiguration output is
                // absent at the start of every epoch until that epoch's
                // reconfiguration finalizes locally, so gating on it would leak
                // a transient chain read on every healthy reconfiguration and
                // break the v4-native "no steady-state chain blob reads"
                // invariant. The DKG digest is durable, so this gate is stable:
                // true throughout steady-state v4 (no chain reads), false only
                // for a not-yet-migrated pre-v4 key, whose real blobs the full
                // chain read below then imports.
                //
                // TODO(v3->v4 migration): once all keys are off-chain, delete this
                // whole `key_blobs_already_cached` branch and collapse
                // `chain_fetched` back to the unconditional `off_chain_on`
                // synthesize-empty fast path — a v4-native key carries empty
                // on-chain blobs, so the import would read empty and the cache
                // path already covers it.
                // ===================================================================
                let dkg_in_handoff = network_key_blob_source
                    .load_full()
                    .as_ref()
                    .and_then(|s| s.network_dkg_output_blob(&network_dec_key_shares.id))
                    .is_some();
                // A key DKG'd in the CURRENT epoch is a fresh v4-native key still
                // converging its own off-chain DKG blob (the producer caches it
                // a beat after the on-chain key appears) — it has no pre-v4,
                // chain-only data to import, so we must never chain-read for it.
                // Without this exception the DKG-presence gate would otherwise
                // leak a chain read during every fresh key's DKG-bootstrap window
                // and break the v4-native no-chain-read invariant. Only a key
                // DKG'd in a PRIOR epoch whose DKG output is absent from the
                // handoff is a genuine not-yet-migrated pre-v4 key.
                let freshly_dkgd_this_epoch = network_dec_key_shares.dkg_at_epoch == current_epoch;
                let key_blobs_already_cached =
                    off_chain_on && (dkg_in_handoff || freshly_dkgd_this_epoch);
                let chain_fetched = if off_chain_on && key_blobs_already_cached {
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
                        // empty blob bytes; the overlay above fills them
                        // from the local producer cache. A usable entry
                        // needs every blob its chain state implies: a
                        // non-empty `network_dkg_public_output` for every
                        // fetched key (all are past `AwaitingNetworkDKG`),
                        // AND — once the key reaches
                        // `NetworkReconfigurationCompleted` — a non-empty
                        // `current_reconfiguration_public_output` too. If
                        // either required blob is still empty (the blob
                        // source wasn't installed yet, or this validator's
                        // own MPC hasn't cached the output yet) publish
                        // the partial value to the channel but do NOT
                        // record it in `last_fetched_network_keys`, so a
                        // later tick re-merges once the overlay has the
                        // bytes. Without this the `(epoch, state)` cache
                        // key pins the empty blob for the rest of the
                        // epoch — and for the reconfiguration output that
                        // permanently withholds this validator's
                        // EndOfPublish vote (`snapshot_ready_for_signing`
                        // requires a non-empty reconfiguration output),
                        // stalling reconfiguration.
                        let reconfiguration_output_missing =
                            matches!(
                                merged.state,
                                DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
                            ) && merged.current_reconfiguration_public_output.is_empty();
                        let overlay_incomplete = off_chain_on
                            && (merged.network_dkg_public_output.is_empty()
                                || reconfiguration_output_missing);
                        // Publish the entry even when the overlay is
                        // incomplete (empty DKG / reconfiguration output).
                        // The epoch-switch reconfiguration gate counts the
                        // channel entries against the on-chain key count
                        // (`SuiConnectorExecutor::run_epoch_switch`:
                        // `dwallet_network_encryption_keys.size == network_encryption_keys.len()`),
                        // so dropping an incomplete key here would make that
                        // count mismatch on the notifier node — whose
                        // overlay is legitimately empty for a key it didn't
                        // compute — and the mid-epoch reconfiguration would
                        // never be requested, wedging the epoch advance.
                        // Decode-side consumers already guard `is_empty`.
                        // `last_fetched_network_keys` stays un-updated while
                        // incomplete, so the next tick re-merges until the
                        // output is cached.
                        let merged_state = merged.state.clone();
                        all_fetched_network_keys_data.insert(key_id, merged);
                        if overlay_incomplete {
                            incomplete_overlay_keys_this_pass += 1;
                            let incomplete_ticks = consecutive_overlay_incomplete_ticks
                                .entry(key_id)
                                .or_insert(0);
                            *incomplete_ticks += 1;
                            // Expected-empty on notifier/fullnode overlays and
                            // during validator convergence windows — per-tick
                            // log at debug. A committee validator persistently
                            // incomplete is a real stall: escalate every 60th
                            // consecutive tick (~5 min at the 5s cadence).
                            if mode.is_validator() && incomplete_ticks.is_multiple_of(60) {
                                warn!(
                                    key = ?key_id,
                                    current_epoch,
                                    consecutive_incomplete_ticks = *incomplete_ticks,
                                    "off-chain network-key overlay still missing a required \
                                     output (DKG or reconfiguration) after many consecutive \
                                     sync ticks — blob source not installed or output never \
                                     cached; investigate the local producer cache"
                                );
                            } else {
                                debug!(
                                    key = ?key_id,
                                    current_epoch,
                                    consecutive_incomplete_ticks = *incomplete_ticks,
                                    "off-chain network-key overlay missing a required output \
                                     (DKG or reconfiguration) — blob source not installed or \
                                     output not cached yet; will retry next tick"
                                );
                            }
                        } else {
                            consecutive_overlay_incomplete_ticks.remove(&key_id);
                            last_fetched_network_keys.insert(key_id, (current_epoch, merged_state));
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
            metrics
                .network_key_overlay_incomplete
                .set(incomplete_overlay_keys_this_pass);
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
            let session_locked = coordinator
                .sessions_manager
                .locked_last_user_initiated_session_to_complete_in_current_epoch;
            let no_pricing_calculation_votes = coordinator
                .pricing_and_fee_management
                .calculation_votes
                .is_none();
            let ready_to_end_publish = session_locked
                && all_epoch_sessions_finished
                && all_immediate_sessions_completed
                && next_epoch_committee_exists
                && all_network_encryption_keys_reconfiguration_completed
                && all_noa_checkpoints_finalized
                && no_pricing_calculation_votes;
            if !ready_to_end_publish {
                // The epoch cannot end-of-publish (and therefore cannot
                // advance) until every condition below holds. Logging the
                // breakdown each tick pinpoints a stuck reconfiguration —
                // e.g. a restarted validator that left a system session
                // started-but-not-completed.
                debug!(
                    epoch = system_inner_v1.epoch,
                    session_locked,
                    all_epoch_sessions_finished,
                    all_immediate_sessions_completed,
                    next_epoch_committee_exists,
                    all_network_encryption_keys_reconfiguration_completed,
                    all_noa_checkpoints_finalized,
                    no_pricing_calculation_votes,
                    "end-of-publish gate not yet satisfied; epoch cannot advance",
                );
            } else if let Err(err) = end_of_publish_sender.send(Some(system_inner_v1.epoch)) {
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
