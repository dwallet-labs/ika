// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The SuiSyncer module handles synchronizing Events emitted
//! on the Sui blockchain from concerned modules of `ika_system` package.
use crate::dwallet_checkpoints::DWalletCheckpointStore;
use crate::dwallet_session_request::DWalletSessionRequest;
use crate::sui_connector::metrics::SuiConnectorMetrics;
use crate::sui_connector::sui_event_into_request::sui_event_into_session_request;
use crate::validator_metadata::OffChainAssemblyMissingReason;
use dwallet_mpc_types::dwallet_mpc::MPCDataTrait;
use ika_config::node::NodeMode;
use ika_sui_client::{SuiClient, SuiClientInner, retry_with_max_elapsed_time};
use ika_types::committee::{
    ClassGroupsEncryptionKeyAndProof, Committee, CommitteeMembership, EpochId, StakeUnit,
};
use ika_types::crypto::{AuthorityName, AuthorityPublicKeyBytes, NetworkPublicKey};
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::{IkaError, IkaResult};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use ika_types::sui::{
    DWalletCoordinator, DWalletCoordinatorInner, System, SystemInner, SystemInnerTrait,
};
use mysten_metrics::spawn_logged_monitored_task;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
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
    last_logged_assembly: Option<(EpochId, bool, usize, usize, usize, usize, usize)>,
    /// Epoch for which the PERMANENT `EverythingExcluded` wedge was
    /// already logged at error — repeats demote to debug (the
    /// `off_chain_assembly_wedged` gauge carries the ongoing state).
    wedge_logged_for_epoch: Option<EpochId>,
    /// Latest incomplete outcome passed back to the outer retry loop without
    /// retaining any authority identifier.
    last_incomplete: Option<(usize, OffChainAssemblyMissingReason)>,
}

const ASSEMBLY_STALL_WARN_AFTER: Duration = Duration::from_secs(300);
const ASSEMBLY_STALL_WARN_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Eq, PartialEq)]
enum AssemblyHealthAction {
    None,
    Warn {
        duration_seconds: u64,
        consecutive_ticks: u64,
        missing: usize,
        reason: OffChainAssemblyMissingReason,
        post_deadline: bool,
    },
    Recovered {
        duration_seconds: u64,
        consecutive_ticks: u64,
    },
}

#[derive(Default)]
struct AssemblyHealthState {
    incomplete_since: Option<time::Instant>,
    consecutive_ticks: u64,
    warning_active: bool,
    last_warning: Option<time::Instant>,
}

impl AssemblyHealthState {
    fn record_incomplete(
        &mut self,
        now: time::Instant,
        missing: usize,
        reason: OffChainAssemblyMissingReason,
        post_deadline: bool,
    ) -> AssemblyHealthAction {
        let incomplete_since = *self.incomplete_since.get_or_insert(now);
        self.consecutive_ticks += 1;
        let duration = now.duration_since(incomplete_since);
        let warning_due = post_deadline || duration >= ASSEMBLY_STALL_WARN_AFTER;
        let interval_elapsed = self
            .last_warning
            .is_none_or(|last| now.duration_since(last) >= ASSEMBLY_STALL_WARN_INTERVAL);
        if warning_due && interval_elapsed {
            self.warning_active = true;
            self.last_warning = Some(now);
            AssemblyHealthAction::Warn {
                duration_seconds: duration.as_secs(),
                consecutive_ticks: self.consecutive_ticks,
                missing,
                reason,
                post_deadline,
            }
        } else {
            AssemblyHealthAction::None
        }
    }

    fn record_success(&mut self, now: time::Instant) -> AssemblyHealthAction {
        let action = if self.warning_active {
            AssemblyHealthAction::Recovered {
                duration_seconds: self
                    .incomplete_since
                    .map_or(0, |started| now.duration_since(started).as_secs()),
                consecutive_ticks: self.consecutive_ticks,
            }
        } else {
            AssemblyHealthAction::None
        };
        self.incomplete_since = None;
        self.consecutive_ticks = 0;
        self.warning_active = false;
        self.last_warning = None;
        action
    }

    fn duration_seconds(&self, now: time::Instant) -> u64 {
        self.incomplete_since
            .map_or(0, |started| now.duration_since(started).as_secs())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConditionTransition {
    Unchanged,
    Entered,
    Recovered,
}

#[derive(Default)]
struct PersistentConditionState {
    active: bool,
}

impl PersistentConditionState {
    fn observe(&mut self, active: bool) -> ConditionTransition {
        let transition = match (self.active, active) {
            (false, true) => ConditionTransition::Entered,
            (true, false) => ConditionTransition::Recovered,
            _ => ConditionTransition::Unchanged,
        };
        self.active = active;
        transition
    }
}

#[derive(Default)]
struct NetworkKeyRegistryHealthState {
    registry_read_empty: PersistentConditionState,
    stranded_key_missing: PersistentConditionState,
}

fn set_assembly_missing_metrics(
    metrics: &SuiConnectorMetrics,
    current: Option<(OffChainAssemblyMissingReason, usize)>,
) {
    for reason in OffChainAssemblyMissingReason::ALL {
        let count = current
            .filter(|(current_reason, _)| *current_reason == reason)
            .map_or(0, |(_, count)| count as i64);
        metrics
            .off_chain_assembly_missing
            .with_label_values(&[reason.label()])
            .set(count);
    }
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
        current_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        next_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        mode: NodeMode,
        // When `true` (protocol v≤3, OCS off), this syncer runs the legacy
        // JSON-RPC event-ingestion path (`run_event_listening_task` +
        // `sync_uncompleted_events`). When `false` (v4, OCS on), the
        // `BagEventPump` feeds the MPC engine instead and these tasks are
        // skipped. The two event senders are `None` in the latter case
        // because they are handed to the pump (and `watch::Sender` is not
        // `Clone`, so they can only belong to one path).
        run_legacy_event_ingestion: bool,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        network_keys_sender: Sender<Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>>,
        new_requests_sender: Option<tokio::sync::broadcast::Sender<Vec<DWalletSessionRequest>>>,
        end_of_publish_sender: Sender<Option<u64>>,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        last_session_to_complete_in_current_epoch_sender: Sender<(EpochId, u64)>,
        uncompleted_requests_sender: Option<Sender<(Vec<DWalletSessionRequest>, EpochId)>>,
        noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync>,
        network_key_blob_source: Arc<
            arc_swap::ArcSwapOption<Box<dyn crate::validator_metadata::NetworkKeyBlobSource>>,
        >,
        // Network keys the MPC manager flagged as stranded by a mid-epoch
        // restart (adoption's produced-this-epoch guard skipping a key the
        // validator holds nothing for). Read by `sync_dwallet_network_keys`:
        // a flagged key gets a chain-sourced current-epoch reconfiguration
        // output instead of the off-chain overlay; empty in healthy flows.
        stranded_network_keys: Arc<arc_swap::ArcSwap<HashSet<ObjectID>>>,
        off_chain_mpc_data_source: Arc<
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
            stranded_network_keys,
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
                current_epoch_mpc_keys_sender.clone(),
                next_epoch_mpc_keys_sender.clone(),
                off_chain_mpc_data_source.clone(),
                self.metrics.clone(),
            ));
            info!("Starting end of publish sync task");
            tokio::spawn(Self::sync_dwallet_end_of_publish(
                sui_client_clone.clone(),
                system_object_receiver.clone(),
                dwallet_coordinator_object_receiver.clone(),
                end_of_publish_sender,
                dwallet_checkpoint_store,
                noa_checkpoints_finalized,
                self.metrics.clone(),
            ));
            info!("Syncing last session to complete in current epoch");
            tokio::spawn(Self::sync_last_session_to_complete_in_current_epoch(
                dwallet_coordinator_object_receiver.clone(),
                last_session_to_complete_in_current_epoch_sender,
            ));
            // Legacy (v≤3) uncompleted-events poller. Under v4 the
            // BagEventPump emits the recovery snapshot instead.
            if run_legacy_event_ingestion
                && let Some(uncompleted_requests_sender) = uncompleted_requests_sender
            {
                info!("Syncing uncompleted events");
                tokio::spawn(Self::sync_uncompleted_events(
                    sui_client_clone,
                    dwallet_coordinator_object_receiver.clone(),
                    system_object_receiver.clone(),
                    uncompleted_requests_sender,
                    self.metrics.clone(),
                ));
            }
        }

        // Legacy (v≤3) event listening: validators poll Sui events over
        // JSON-RPC to drive MPC sessions. Under v4 the BagEventPump replaces
        // this, so the block is skipped and `new_requests_sender` is `None`
        // (it was handed to the pump instead).
        if run_legacy_event_ingestion && mode.is_validator() {
            let new_requests_sender = new_requests_sender
                .expect("run_legacy_event_ingestion implies new_requests_sender is Some");
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
            info!(
                ?mode,
                run_legacy_event_ingestion, "Skipping legacy event listening task"
            );
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
        metrics: Arc<SuiConnectorMetrics>,
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
                    // Expose the backlog as a single gauge so operators can see "chain
                    // has N uncompleted sessions from this validator's perspective" at
                    // a glance.
                    metrics.uncompleted_events_backlog.set(events.len() as i64);
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
        current_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        next_epoch_mpc_keys_sender: Sender<
            Option<(EpochId, crate::validator_metadata::OffChainCommitteeBundles)>,
        >,
        off_chain_mpc_data_source: Arc<
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
        let mut assembly_health = AssemblyHealthState::default();
        // Dedup/latch state for the assembly logging inside `new_committee`.
        let mut assembly_log_state = AssemblyLogState::default();
        // Last `(epoch, frozen)` committee send logged at info — the
        // pre-freeze window re-sends every tick, so intermediate
        // re-sends demote to debug.
        let mut last_logged_committee_send: Option<(EpochId, bool)> = None;
        // Epoch whose CURRENT-committee off-chain keys we've already delivered;
        // the keys are deterministic and the current committee is fixed within
        // an epoch, so one successful send per epoch is enough.
        let mut current_keys_sent_for_epoch: Option<EpochId> = None;
        // `validator_id -> consensus pubkey`, populated on first sight and
        // dropped at every epoch change. Keeps the consensus-basis re-keying
        // below off the per-tick chain path (see
        // `committee_names_for_basis`) WITHOUT outliving the value's own
        // validity: a consensus key is not fixed at registration —
        // `set_next_epoch_consensus_pubkey_bytes` is an operator-callable
        // entry point and `rotate_next_epoch_info` effectuates it at epoch
        // advance. Caching across epochs would keep naming a rotated
        // validator under its old key indefinitely, and from protocol v6 —
        // where the consensus key IS the `AuthorityName` — that is a stale
        // IDENTITY, fleet-wide. Per-epoch is exactly right: rotation lands
        // only at boundaries, so within an epoch the value cannot change.
        let mut consensus_key_cache: HashMap<ObjectID, NetworkPublicKey> = HashMap::new();
        let mut consensus_key_cache_epoch: Option<EpochId> = None;
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
            // Drop keys cached for a previous epoch before anything reads
            // them: a rotation effectuated at the boundary must be picked up
            // this epoch, not inherited from the last one.
            if consensus_key_cache_epoch != Some(system_inner.epoch()) {
                consensus_key_cache.clear();
                consensus_key_cache_epoch = Some(system_inner.epoch());
            }
            // Deliver the CURRENT epoch's off-chain validator MPC keys (3 PVSS +
            // VSS HPKE) to the MPC manager. The within-epoch network DKG needs
            // them, and at genesis they were never assembled as a prior epoch's
            // "next". Current committee members self-announce for the current
            // epoch, so the live (current-epoch) source's frozen set covers them
            // — assemble directly for the current committee, not by borrowing
            // the next committee's keys. Runs before the next-committee check so
            // it still fires when Sui hasn't selected a next committee yet.
            //
            // NOTE: this channel is the manager's FALLBACK source only — for
            // the chain-true no-cert epochs (genesis, the first
            // off-chain-enabled epoch). Whenever the prior epoch produced a
            // handoff certificate, the manager sources the bundle from that
            // cert instead (`try_ingest_current_epoch_keys_from_prior_handoff_cert`,
            // issue #1879) and ignores this delivery: the cert set is the
            // boundary set the committee latched, while this post-freeze
            // assembly is the CURRENT epoch's frozen set, a possible strict
            // superset in a joiner-churn epoch.
            let current_epoch = system_inner.epoch();
            // Only deliver once the set is FROZEN — the frozen set is the
            // consensus-agreed validator-key set (a stake-quorum of ready
            // signals decided it). Delivering a pre-freeze assembly could ship a
            // non-final subset that the manager would then ingest as the agreed
            // set. `try_assemble_mpc_data` post-freeze returns exactly the frozen
            // set (which may omit offline/withholding validators — that's fine,
            // the DKG deals only to parties that have keys).
            if current_keys_sent_for_epoch != Some(current_epoch)
                && let Some(source) = off_chain_mpc_data_source.load_full()
                && source.is_frozen()
            {
                let current_committee = match Self::rekey_committee_to_consensus_names(
                    &sui_client,
                    system_inner.read_bls_committee(&system_inner.get_ika_active_committee()),
                    &mut consensus_key_cache,
                )
                .await
                {
                    Ok(members) => members,
                    Err(e) => {
                        warn!(
                            error = ?e,
                            "failed to re-key the current committee to consensus-basis \
                             names; retrying next tick"
                        );
                        continue;
                    }
                };
                let current_members: Vec<AuthorityName> = current_committee
                    .into_iter()
                    .map(|(_, (name, _))| name)
                    .collect();
                if let crate::validator_metadata::OffChainMpcDataAssembly::Complete(bundles) =
                    source.try_assemble_mpc_data(&current_members)
                    && current_epoch_mpc_keys_sender
                        .send(Some((current_epoch, *bundles)))
                        .is_ok()
                {
                    current_keys_sent_for_epoch = Some(current_epoch);
                    info!(
                        current_epoch,
                        "delivered current-epoch off-chain validator MPC keys to the manager \
                         (frozen agreed set)"
                    );
                }
            }

            let Some(new_next_bls_committee) = system_inner.get_ika_next_epoch_committee() else {
                debug!("ika next epoch active committee not found, retrying...");
                continue;
            };

            let new_next_committee = match Self::rekey_committee_to_consensus_names(
                &sui_client,
                system_inner.read_bls_committee(&new_next_bls_committee),
                &mut consensus_key_cache,
            )
            .await
            {
                Ok(members) => members,
                Err(e) => {
                    warn!(
                        error = ?e,
                        "failed to re-key the next-epoch committee to consensus-basis \
                         names; retrying next tick"
                    );
                    continue;
                }
            };

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

            // Snapshot the source once so the freeze probe and the
            // assembly read the SAME per-epoch store: the freeze flag is
            // monotonic within a store, so `is_frozen == true` here
            // guarantees the assembly below used the frozen pairs.
            let off_chain_mpc_data_snapshot = off_chain_mpc_data_source.load_full();
            let frozen_at_assembly = off_chain_mpc_data_snapshot
                .as_ref()
                .is_some_and(|source| source.is_frozen());
            let assembly_backstop_ms = system_inner
                .epoch_start_timestamp_ms()
                .saturating_add(system_inner.epoch_duration_ms().saturating_mul(3) / 4);
            let post_deadline = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                >= u128::from(assembly_backstop_ms);
            let (committee, next_epoch_bundles) = match Self::new_committee(
                sui_client.clone(),
                new_next_committee.clone(),
                next_epoch,
                new_next_bls_committee.quorum_threshold,
                new_next_bls_committee.validity_threshold,
                true,
                off_chain_mpc_data_snapshot,
                frozen_at_assembly,
                &mut assembly_log_state,
                &metrics,
            )
            .await
            {
                Ok(committee_and_bundles) => {
                    let now = time::Instant::now();
                    metrics.off_chain_assembly_incomplete.set(0);
                    metrics
                        .off_chain_assembly_consecutive_incomplete_ticks
                        .set(0);
                    metrics
                        .off_chain_assembly_incomplete_duration_seconds
                        .set(0);
                    set_assembly_missing_metrics(&metrics, None);
                    if committee_and_bundles.1.is_some() {
                        metrics
                            .off_chain_assembly_last_success_timestamp_seconds
                            .set(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64,
                            );
                    }
                    if let AssemblyHealthAction::Recovered {
                        duration_seconds,
                        consecutive_ticks,
                    } = assembly_health.record_success(now)
                    {
                        info!(
                            duration_seconds,
                            consecutive_ticks, "off-chain validator-mpc_data assembly recovered"
                        );
                    }
                    committee_and_bundles
                }
                Err(DwalletMPCError::OffChainAssemblyIncomplete { .. }) => {
                    let now = time::Instant::now();
                    let (missing, reason) = assembly_log_state
                        .last_incomplete
                        .unwrap_or((0, OffChainAssemblyMissingReason::NoInput));
                    let action = assembly_health.record_incomplete(
                        now,
                        missing,
                        reason,
                        post_deadline || frozen_at_assembly,
                    );
                    metrics.off_chain_assembly_incomplete_ticks_total.inc();
                    metrics.off_chain_assembly_incomplete.set(1);
                    metrics
                        .off_chain_assembly_consecutive_incomplete_ticks
                        .set(assembly_health.consecutive_ticks as i64);
                    metrics
                        .off_chain_assembly_incomplete_duration_seconds
                        .set(assembly_health.duration_seconds(now) as i64);
                    set_assembly_missing_metrics(&metrics, Some((reason, missing)));
                    if let AssemblyHealthAction::Warn {
                        duration_seconds,
                        consecutive_ticks,
                        missing,
                        reason,
                        post_deadline,
                    } = action
                        && reason != OffChainAssemblyMissingReason::EverythingExcluded
                    {
                        warn!(
                            duration_seconds,
                            consecutive_incomplete_ticks = consecutive_ticks,
                            missing,
                            reason = reason.label(),
                            post_deadline,
                            "off-chain validator-mpc_data assembly is persistently incomplete"
                        );
                    } else {
                        debug!(
                            consecutive_incomplete_ticks = assembly_health.consecutive_ticks,
                            missing,
                            reason = reason.label(),
                            "off-chain validator-mpc_data assembly incomplete; retrying"
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
            // Deliver the next epoch's off-chain validator MPC keys alongside
            // its committee — network reconfiguration encrypts under the
            // upcoming parties' PVSS keys. Only once FROZEN, so the manager
            // ingests the consensus-agreed next-epoch set (not a pre-freeze
            // subset). `None` only on the bootstrap-window chain read (no
            // off-chain bundle assembled yet).
            if frozen_at_assembly && let Some(bundles) = next_epoch_bundles {
                let _ = next_epoch_mpc_keys_sender.send(Some((committee_epoch, bundles)));
            }
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

    /// Re-key a chain-read committee (BLS-basis names, as
    /// `read_bls_committee` mints them) to consensus-basis names — the
    /// committee identity at every supported protocol version. The consensus
    /// keys are not in the on-chain `BlsCommittee` (it carries `validator_id`
    /// and BLS `protocol_pubkey` only), so a member's validator record must
    /// be fetched by id.
    ///
    /// Only ids not already cached for THIS epoch are fetched. The cache is
    /// per-epoch rather than permanent because a consensus key can be
    /// rotated (`set_next_epoch_consensus_pubkey_bytes`, effectuated at the
    /// next epoch advance); within an epoch it cannot change. That matters
    /// beyond latency: this runs on every sync tick,
    /// and its caller skips the tick (and with it the next-committee send)
    /// when it returns `Err`. A per-tick chain fetch in exactly this spot
    /// wedged reconfiguration once before — `get_validators_info_by_ids`
    /// fails transiently while validators restart during a rollout, which
    /// is precisely when the committee must still be assembled (see
    /// `dev-docs/plans/authority-name-consensus-key.md`). With the cache,
    /// steady-state ticks perform no chain read at all, so a committee
    /// whose members are already known can never be starved by RPC flake.
    async fn rekey_committee_to_consensus_names(
        sui_client: &Arc<SuiClient<C>>,
        members: Vec<(ObjectID, (AuthorityPublicKeyBytes, StakeUnit))>,
        consensus_key_cache: &mut HashMap<ObjectID, NetworkPublicKey>,
    ) -> IkaResult<Vec<(ObjectID, (AuthorityName, StakeUnit))>> {
        let unknown_ids: Vec<ObjectID> = members
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !consensus_key_cache.contains_key(id))
            .collect();
        let validators = if unknown_ids.is_empty() {
            Vec::new()
        } else {
            sui_client.get_validators_info_by_ids(unknown_ids).await?
        };
        for validator in &validators {
            let info = validator.verified_validator_info().map_err(|code| {
                IkaError::InvalidCommittee(format!(
                    "validator {} has unparsable on-chain metadata (Move error code {code})",
                    validator.id
                ))
            })?;
            consensus_key_cache.insert(validator.id, info.consensus_pubkey.clone());
        }
        members
            .into_iter()
            .map(|(validator_id, (_, stake))| {
                let consensus_pubkey = consensus_key_cache.get(&validator_id).ok_or_else(|| {
                    IkaError::InvalidCommittee(format!(
                        "validator {validator_id} missing from the fetched validator \
                             records while re-keying to consensus-basis names"
                    ))
                })?;
                Ok((
                    validator_id,
                    (AuthorityName::from_consensus_key(consensus_pubkey), stake),
                ))
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_committee(
        sui_client: Arc<SuiClient<C>>,
        committee: Vec<(ObjectID, (AuthorityName, StakeUnit))>,
        epoch: u64,
        quorum_threshold: u64,
        validity_threshold: u64,
        read_next_epoch_class_groups_keys: bool,
        off_chain_mpc_data_source: Option<
            Arc<Box<dyn crate::validator_metadata::OffChainCommitteeMpcDataSource>>,
        >,
        frozen_at_assembly: bool,
        log_state: &mut AssemblyLogState,
        metrics: &SuiConnectorMetrics,
    ) -> DwalletMPCResult<(
        Committee,
        Option<crate::validator_metadata::OffChainCommitteeBundles>,
    )> {
        // Try the off-chain assembly first. The strict
        // `Complete`/`Incomplete` gate inside the source means we
        // only use the off-chain map when every (non-excluded)
        // committee member resolved successfully. An `Incomplete`
        // result returns `OffChainAssemblyIncomplete` and the outer
        // sync loop retries on the next tick — there is no chain
        // fallback for validator mpc_data; chain is write-only. The
        // chain read below serves only the bootstrap window before
        // the off-chain source is installed (`source == None`).
        if let Some(source) = off_chain_mpc_data_source {
            let authorities: Vec<AuthorityName> =
                committee.iter().map(|(_, (name, _))| *name).collect();
            match source.try_assemble_mpc_data(&authorities) {
                crate::validator_metadata::OffChainMpcDataAssembly::Complete(bundles) => {
                    log_state.last_incomplete = None;
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
                        bundles.vss_hpke.len(),
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
                    // class_groups stays on `Committee` (the bare on-chain key).
                    // The PVSS + VSS HPKE keys travel out-of-band: return the
                    // full bundle so the caller delivers them to the MPC manager
                    // via the off-chain key channels, never on `Committee`.
                    let committee = Committee::new(
                        epoch,
                        committee
                            .iter()
                            .map(|(_, (name, stake))| (*name, *stake))
                            .collect(),
                        bundles.class_groups.clone(),
                        // Empty: this assembled committee feeds only the
                        // reconfiguration MPC input, which never reads consensus
                        // keys. Handoff verification uses the epoch store's
                        // committee (`get_ika_committee`), which carries them.
                        HashMap::new(),
                        quorum_threshold,
                        validity_threshold,
                    );
                    return Ok((committee, Some(*bundles)));
                }
                crate::validator_metadata::OffChainMpcDataAssembly::Incomplete {
                    missing,
                    reason,
                } => {
                    log_state.last_incomplete = Some((missing.len(), reason));
                    // There is NO chain fallback. The off-chain pipeline
                    // (consensus announcements + P2P blob delivery +
                    // attestation-tally freeze) is the only path; missing
                    // entries here are transient (P2P hasn't converged yet)
                    // and the outer sync loop should retry on the next
                    // tick — expected every epoch during the convergence
                    // window, so the per-tick log is debug (the caller
                    // escalates a persistent stall).
                    debug!(
                        epoch,
                        missing = missing.len(),
                        reason = reason.label(),
                        "off-chain validator-mpc_data assembly incomplete; \
                         no chain fallback — retrying on next sync tick"
                    );
                    return Err(DwalletMPCError::OffChainAssemblyIncomplete {
                        epoch,
                        missing: missing.len(),
                    });
                }
                crate::validator_metadata::OffChainMpcDataAssembly::EverythingExcluded => {
                    {
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
                        log_state.last_incomplete = Some((
                            authorities.len(),
                            OffChainAssemblyMissingReason::EverythingExcluded,
                        ));
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

        // Chain reads are the mainnet-v1.1.8 shape always: the Move-side
        // `MPCDataV1::mpc_data_bytes` field stores bare
        // `ClassGroupsEncryptionKeyAndProof`. The full bundle (PVSS + VSS HPKE)
        // arrives via the off-chain validator-metadata pipeline (see PR #1721)
        // and is overlaid onto Committee through a separate path. No
        // try-then-fallback decode — one shape per path.
        //
        // A member's record is written at candidate registration and never
        // emptied on chain, so a missing or undecodable record is always a
        // read defect. Dropping the member would hand the reconfiguration MPC
        // a locally-shrunken party set that peers with healthier reads don't
        // agree on — divergent public inputs; exclusion decisions belong to
        // the consensus-agreed freeze, never to a local read. Error instead;
        // the sync loop retries on the next tick.
        let class_group_encryption_keys_and_proofs: HashMap<_, _> = committee
            .iter()
            .map(|(id, (name, _))| {
                let mpc_data = committee_mpc_data.get(id).ok_or_else(|| {
                    ika_types::report_invariant_violation!(
                        "chain_fallback_mpc_data_missing",
                        authority = ?name,
                        validator_id = ?id,
                        "committee member has no decodable on-chain mpc_data record; \
                         failing the chain-fallback committee build for retry"
                    );
                    DwalletMPCError::MissingOnChainMpcData {
                        epoch,
                        authority: *name,
                    }
                })?;
                let key_and_proof =
                    bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(&mpc_data.mpc_data_bytes())
                        .map_err(|e| {
                            ika_types::report_invariant_violation!(
                                "chain_fallback_mpc_data_decode",
                                authority = ?name,
                                validator_id = ?id,
                                error = ?e,
                                "failed to decode on-chain class-groups encryption key and proof; \
                                 failing the chain-fallback committee build for retry"
                            );
                            DwalletMPCError::MissingOnChainMpcData {
                                epoch,
                                authority: *name,
                            }
                        })?;
                Ok((*name, key_and_proof))
            })
            .collect::<DwalletMPCResult<HashMap<_, _>>>()?;

        // Bootstrap-window chain read (off-chain source not yet installed):
        // only the bare class-groups key is on chain, so there are no
        // off-chain PVSS/VSS bundles to deliver.
        Ok((
            Committee::new(
                epoch,
                committee
                    .iter()
                    .map(|(_, (name, stake))| (*name, *stake))
                    .collect(),
                class_group_encryption_keys_and_proofs,
                // Empty: the assembled committee feeds only the reconfiguration
                // MPC input, which never reads consensus keys.
                HashMap::new(),
                quorum_threshold,
                validity_threshold,
            ),
            None,
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
        stranded_network_keys: Arc<arc_swap::ArcSwap<HashSet<ObjectID>>>,
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
        // Pointer identity of the blob source the previous pass merged
        // with. Installing (or per-epoch replacing) the source changes
        // which bytes a merge produces for the SAME chain state, so the
        // `(epoch, state)` fetch memo below is stale the moment the
        // source flips: an overlay published from a source-less
        // chain-read pass right after a restart carries the chain's
        // original pre-V3 DKG anchor, and with no re-merge it would sit
        // in the watch channel for the rest of the epoch — where the
        // end-of-epoch hydration pass can cache it over the canonical
        // mirror (the never-instantiated variant of issue #1852). Clear
        // the memo whenever the source identity changes so the next
        // pass re-merges every key through the new source.
        let mut last_blob_source_ptr: Option<usize> = None;
        // Consecutive 5s ticks each key's overlay has been incomplete.
        // An incomplete overlay is the designed steady state on a
        // notifier/fullnode (whose overlay is legitimately empty for
        // keys it didn't compute) and a normal transient on validators
        // (fresh-key DKG window, chain-state flip before the local
        // cache write), so the per-tick log is debug; a committee
        // validator stuck incomplete escalates to warn every 60th
        // consecutive tick (~5 min).
        let mut consecutive_overlay_incomplete_ticks: HashMap<ObjectID, u64> = HashMap::new();
        let mut registry_health = NetworkKeyRegistryHealthState::default();
        loop {
            time::sleep(Duration::from_secs(5)).await;

            let blob_source_ptr = network_key_blob_source
                .load_full()
                .map(|source| Arc::as_ptr(&source) as *const () as usize);
            if blob_source_ptr != last_blob_source_ptr {
                // Inequality implies at least one side is Some, so this
                // always concerns a real install/replacement.
                info!(
                    source_installed = blob_source_ptr.is_some(),
                    "network-key blob source changed; re-merging all network keys"
                );
                last_fetched_network_keys.clear();
                last_blob_source_ptr = blob_source_ptr;
            }

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

            let network_encryption_keys = match sui_client
                .get_dwallet_mpc_network_keys(&dwallet_coordinator_inner)
                .await
            {
                Ok(network_encryption_keys) => network_encryption_keys,
                Err(error) => {
                    // A transport failure is not proof that the registry is
                    // empty and must not start or recover an invariant episode.
                    // Preserve the last observed condition state and retry.
                    warn!(?error, "failed to fetch dwallet MPC network keys");
                    continue;
                }
            };

            // Silence-proofing (#1952): an empty registry read while the
            // coordinator itself reports existing keys is indistinguishable
            // from the healthy "no keys yet" state at every layer above this
            // one — empty-success is legal everywhere downstream, so without
            // this marker the condition is invisible until sessions stop.
            // The loop keeps retrying on its own cadence either way.
            {
                let DWalletCoordinatorInner::V1(coordinator_inner_v1) = &dwallet_coordinator_inner;
                let on_chain_registry_size =
                    coordinator_inner_v1.dwallet_network_encryption_keys.size;
                let condition_active =
                    network_encryption_keys.is_empty() && on_chain_registry_size > 0;
                metrics
                    .network_key_registry_read_empty_condition_active
                    .set(i64::from(condition_active));
                match registry_health
                    .registry_read_empty
                    .observe(condition_active)
                {
                    ConditionTransition::Entered => {
                        ika_types::report_invariant_violation!(
                            "network_key_registry_read_empty",
                            on_chain_registry_size,
                            current_epoch,
                            "network-key registry read returned an empty map while the \
                             coordinator reports existing keys — retrying next tick",
                        );
                    }
                    ConditionTransition::Recovered => {
                        info!(
                            on_chain_registry_size,
                            current_epoch,
                            "network-key registry read recovered after returning an empty map"
                        );
                    }
                    ConditionTransition::Unchanged => {}
                }
            }

            // Recovery widening (#1952/#1852): the stranded-key chain-read
            // recovery below can only run for keys PRESENT in the fetched
            // registry map. A stranded key the registry read failed to return
            // means the audited recovery is silently pinned — surface it
            // instead of falling through to the healthy-looking
            // "No new network keys to fetch" line.
            {
                let stranded_snapshot = stranded_network_keys.load();
                let mut missing_stranded_keys: Vec<ObjectID> = stranded_snapshot
                    .iter()
                    .filter(|stranded_id| !network_encryption_keys.contains_key(stranded_id))
                    .copied()
                    .collect();
                missing_stranded_keys.sort_unstable();
                let condition_active = !missing_stranded_keys.is_empty();
                metrics
                    .stranded_network_key_missing_from_registry_read_condition_active
                    .set(i64::from(condition_active));
                match registry_health
                    .stranded_key_missing
                    .observe(condition_active)
                {
                    ConditionTransition::Entered => {
                        ika_types::report_invariant_violation!(
                            "stranded_network_key_missing_from_registry_read",
                            missing_key_ids = ?missing_stranded_keys,
                            missing_key_count = missing_stranded_keys.len(),
                            current_epoch,
                            "network keys flagged for chain-sourced recovery are absent \
                             from the registry read — recovery cannot run this tick",
                        );
                    }
                    ConditionTransition::Recovered => {
                        info!(
                            current_epoch,
                            "all stranded network keys are present in the registry read again"
                        );
                    }
                    ConditionTransition::Unchanged => {}
                }
            }

            let keys_to_fetch: HashMap<ObjectID, DWalletNetworkEncryptionKey> =
                network_encryption_keys
                    .into_iter()
                    .filter(|(id, key)| {
                        // A key the MPC manager flagged as stranded (mid-epoch
                        // restart, #1852) is re-fetched regardless of the
                        // cache: the flag is raised AFTER the overlay entry
                        // that revealed the strand was already recorded here,
                        // so without this the chain-sourced recovery read
                        // below would never run.
                        if stranded_network_keys.load().contains(id) {
                            return true;
                        }
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
                // Synthesize a metadata-only
                // `DWalletNetworkEncryptionKeyData` from the
                // lightweight chain object so we skip the heavy
                // `read_table_vec_as_raw_bytes` chain reads. The
                // overlay below substitutes the actual blob bytes
                // from the local producer cache (which all honest
                // validators populate from their own MPC outputs).
                // (The chain still HOLDS the real DKG/reconfiguration
                // blobs — they are written on-chain at
                // DKG/reconfiguration regardless of protocol version —
                // but no steady-state chain read is needed: every
                // off-chain key's blobs live in the handoff plane. This
                // is also why the stranded-key recovery chain read
                // below reliably yields the real current-epoch output
                // rather than empty bytes.)
                //
                // Whether the MPC manager flagged this key as STRANDED by a
                // mid-epoch restart (#1852): the validator holds nothing for
                // the key while the off-chain overlay serves only this epoch's
                // just-produced reconfiguration output R(M) — encrypted to the
                // NEXT committee, which the adoption pass's produced-this-epoch
                // guard then skips forever, parking every session on the key.
                // A flagged key must NOT take the fast path: it falls
                // through to the full chain read and installs the canonical
                // current-epoch output R(M-1); a confirmed instantiation
                // un-flags it. The set is empty in every healthy flow —
                // including a fresh key's DKG-bootstrap window and the
                // first-instantiation-in-flight window — so the v4
                // no-steady-state-chain-read invariant is preserved exactly.
                let key_is_stranded = stranded_network_keys
                    .load()
                    .contains(&network_dec_key_shares.id);
                let chain_fetched = if !key_is_stranded {
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
                        let source_snapshot = network_key_blob_source.load_full();
                        let merged = overlay_network_key_data(
                            key_is_stranded,
                            key_full_data,
                            source_snapshot.as_deref().map(|source| source.as_ref()),
                        );
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
                        // Validators only: a non-validator (notifier/fullnode)
                        // has no producer cache, so under off-chain mode its
                        // fast-path entry stays metadata-only FOREVER — that
                        // is its complete, by-design shape (no non-validator
                        // consumer reads the blob bytes; the epoch-switch gate
                        // counts entries, and decode-side consumers guard
                        // `is_empty`). Treating it as incomplete would pin the
                        // incomplete gauge at the key count and re-merge every
                        // tick for blobs that can never arrive.
                        let overlay_incomplete = mode.is_validator()
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
                        // Skip only THIS key: it stays out of
                        // `last_fetched_network_keys`, so the next tick
                        // re-selects it. Aborting the whole outer pass would
                        // also skip the channel send below — and a sibling key
                        // that merged COMPLETE earlier in this same pass was
                        // already recorded as fetched, so its data would never
                        // be published: absent from the overlay, never
                        // adopted, never instantiated until the next epoch's
                        // refetch. The stranded-key recovery chain read makes
                        // this arm hot on exactly that recovery path.
                        continue;
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
        sui_client: Arc<SuiClient<C>>,
        system_object_receiver: Receiver<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_receiver: Receiver<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        end_of_publish_sender: Sender<Option<u64>>,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        noa_checkpoints_finalized: Arc<dyn Fn() -> bool + Send + Sync>,
        metrics: Arc<SuiConnectorMetrics>,
    ) {
        // Consecutive ticks the end-of-publish gate has stayed unsatisfied. A
        // healthy epoch boundary clears it in 1-2 ticks; a wedged reconfiguration
        // (the #1736 genuine-laggard variant: an epoch's network-key
        // reconfiguration output, or the tail of locked sessions, never reaching
        // on-chain quorum) stays stuck indefinitely. This drives the WARN
        // escalation below so the stall is loud — and names the blocking
        // condition — at the default log level instead of silent.
        let mut consecutive_unsatisfied: u64 = 0;
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

            // Mirror raw chain state on the validator so an operator can see it
            // from a dashboard without a Sui RPC round-trip. Exposed every tick,
            // regardless of whether the gate below is satisfied.
            metrics
                .chain_received_end_of_publish
                .with_label_values(&["system"])
                .set(system_inner_v1.received_end_of_publish as i64);
            metrics
                .chain_received_end_of_publish
                .with_label_values(&["coordinator"])
                .set(coordinator.received_end_of_publish as i64);
            metrics.chain_active_user_sessions_count.set(
                coordinator
                    .sessions_manager
                    .user_sessions_keeper
                    .sessions
                    .size as i64,
            );
            metrics.chain_active_system_sessions_count.set(
                coordinator
                    .sessions_manager
                    .system_sessions_keeper
                    .sessions
                    .size as i64,
            );

            // user_sessions_lag = target - completed; can be negative if completed >
            // target (which would itself be a bug, hence the signed gauge).
            let lock_target = coordinator
                .sessions_manager
                .last_user_initiated_session_to_complete_in_current_epoch
                as i64;
            let completed_user_sessions = coordinator
                .sessions_manager
                .user_sessions_keeper
                .completed_sessions_count as i64;
            metrics
                .chain_user_sessions_lag
                .set(lock_target - completed_user_sessions);

            // Writer lag: completions this validator has already CERTIFIED
            // (they sit in local certified dwallet checkpoints) that have not
            // been processed by the coordinator on Sui. `user_sessions_lag`
            // alone cannot distinguish "MPC hasn't completed the sessions"
            // from "the sole checkpoint writer isn't landing them on chain";
            // both 2026-07 epoch-close outages lost their first debugging
            // phase to exactly that ambiguity.
            let local_certified_head = dwallet_checkpoint_store
                .get_latest_certified_checkpoint()
                .unwrap_or_else(|err| {
                    warn!(error=?err, "failed to read latest certified dwallet checkpoint");
                    None
                })
                .map(|checkpoint| checkpoint.sequence_number);
            let chain_checkpoint_cursor = coordinator.last_processed_checkpoint_sequence_number;
            let checkpoint_writer_lag =
                local_certified_head.map_or(0, |head| head.saturating_sub(chain_checkpoint_cursor));
            metrics.chain_dwallet_checkpoint_writer_lag.set(
                local_certified_head.map_or(0, |head| head as i64 - chain_checkpoint_cursor as i64),
            );

            // chain_epoch_overdue_seconds — best effort; if the clock fetch fails we
            // leave the previous value in place rather than zeroing it (zero is
            // meaningful here).
            if let Ok(clock) = sui_client.get_clock().await {
                let epoch_end_ms = system_inner_v1
                    .epoch_start_timestamp_ms
                    .saturating_add(system_inner_v1.epoch_duration_ms);
                let overdue_ms = clock.timestamp_ms.saturating_sub(epoch_end_ms);
                metrics
                    .chain_epoch_overdue_seconds
                    .set((overdue_ms / 1000) as i64);
            }

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
            // The lock flag belongs to the coordinator's OWN epoch. Right
            // after an epoch advance the syncer can observe the system
            // object's bumped epoch while this coordinator snapshot still
            // predates the coordinator's advance — its lock flag is then the
            // PREVIOUS epoch's close-lock, and counting it produced spurious
            // "gate STUCK" warns for the first minutes of every epoch. The
            // epoch-agreement check gates ONLY the stall-warn accounting
            // below — never `ready_to_end_publish`: the gate's other
            // conditions are read from the same possibly-skewed snapshots,
            // and blocking the EndOfPublish send on cross-object read
            // alignment can hold a legitimate close hostage.
            let lock_belongs_to_current_epoch = coordinator.current_epoch == system_inner_v1.epoch;
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
            // Scrapable mirror of the gate breakdown: 1 = this condition is
            // currently blocking end-of-publish. Set every tick (also when the
            // gate is satisfied) so all reasons read 0 once the gate clears.
            let blocked_by = [
                ("not_locked", !session_locked),
                ("user_sessions_lag", !all_epoch_sessions_finished),
                ("system_sessions_lag", !all_immediate_sessions_completed),
                ("next_committee_missing", !next_epoch_committee_exists),
                (
                    "network_keys_reconfig_lag",
                    !all_network_encryption_keys_reconfiguration_completed,
                ),
                (
                    "noa_checkpoints_unfinalized",
                    !all_noa_checkpoints_finalized,
                ),
                ("pricing_votes_open", !no_pricing_calculation_votes),
                // Names the WRITER when session lag is (at least partly) a
                // submission problem: sessions are unfinished on chain while
                // certified checkpoints sit unlanded. Lights up alongside
                // `user_sessions_lag`, pointing the operator at the notifier
                // instead of the MPC pipeline.
                (
                    "checkpoint_writer_lag",
                    !all_epoch_sessions_finished && checkpoint_writer_lag > 0,
                ),
            ];
            for (reason, is_blocking) in blocked_by {
                metrics
                    .end_of_publish_blocked_reason
                    .with_label_values(&[reason])
                    .set(is_blocking as i64);
            }
            if !ready_to_end_publish {
                // The breakdown each tick pinpoints a stuck reconfiguration
                // or session lag. Info on purpose: one line per 10s tick per
                // validator only while unsatisfied, and every epoch-close
                // stall investigation this month needed exactly this
                // breakdown and did not have it at the default level.
                info!(
                    epoch = system_inner_v1.epoch,
                    session_locked,
                    all_epoch_sessions_finished,
                    all_immediate_sessions_completed,
                    next_epoch_committee_exists,
                    all_network_encryption_keys_reconfiguration_completed,
                    all_noa_checkpoints_finalized,
                    no_pricing_calculation_votes,
                    checkpoint_writer_lag,
                    "end-of-publish gate not yet satisfied; epoch cannot advance",
                );
                // Escalate to WARN only once the epoch has COMMITTED to closing
                // (the last user-initiated session is locked) yet the gate still
                // won't satisfy. Before the lock the gate is legitimately
                // unsatisfied for most of the epoch, so counting that would be
                // pure noise; a post-lock stall is the actual wedge — "locked but
                // can't close" (the #1736 signature) — and the false condition(s)
                // below name what is blocking advance, at the default log level,
                // with no debug-level logging to perturb the boundary timing this
                // race is sensitive to.
                if session_locked && lock_belongs_to_current_epoch {
                    consecutive_unsatisfied += 1;
                    const STALE_GATE_WARN_TICKS: u64 = 6; // 6 * 10s = 60s post-lock
                    if consecutive_unsatisfied.is_multiple_of(STALE_GATE_WARN_TICKS) {
                        warn!(
                            epoch = system_inner_v1.epoch,
                            stuck_secs = consecutive_unsatisfied * 10,
                            all_epoch_sessions_finished,
                            all_immediate_sessions_completed,
                            next_epoch_committee_exists,
                            all_network_encryption_keys_reconfiguration_completed,
                            all_noa_checkpoints_finalized,
                            no_pricing_calculation_votes,
                            checkpoint_writer_lag,
                            "end-of-publish gate STUCK after the epoch locked to close: the \
                             false condition(s) above are blocking advance (a persistent \
                             reconfiguration/session-output stall — see issue #1736; if \
                             checkpoint_writer_lag > 0 the checkpoint WRITER is not landing \
                             locally-certified completions on Sui — check the notifier)",
                        );
                    }
                } else {
                    // Not committed to closing yet (normal mid-epoch) — don't
                    // accumulate a stall against the gate.
                    consecutive_unsatisfied = 0;
                }
            } else {
                consecutive_unsatisfied = 0;
                if let Err(err) = end_of_publish_sender.send(Some(system_inner_v1.epoch)) {
                    error!(error=?err, "failed to send end of publish epoch to the channel");
                }
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

/// Chooses how to overlay locally-cached off-chain blobs onto chain-fetched
/// network-key data, based on whether the MPC manager flagged the key as
/// stranded by a mid-epoch restart (#1852).
///
/// - **Not stranded** (every healthy flow): prefer the off-chain source for
///   both blobs — the steady-state v4 read path (the chain copy may even be
///   metadata-only with empty blobs, synthesized by the fast path).
/// - **Stranded** (restart-recovery chain read): keep the chain's canonical
///   current-epoch reconfiguration output. Overlaying the off-chain
///   source's reconfiguration blob would re-override it with the output
///   this epoch's reconfiguration just produced — encrypted to the NEXT
///   committee, which the adoption pass's produced-this-epoch guard then
///   skips forever, keeping the key un-instantiated for the rest of the
///   epoch (every session parks on it). The DKG blob is the one field
///   still preferred from the off-chain source: it is the stable per-key
///   anchor, and the locally-mirrored copy is the CANONICAL representation
///   whose digest the prior epoch's handoff cert pins — after the V2→V3
///   canonical migration the chain's original anchor no longer matches the
///   cert, and adoption would reject the key on the DKG-digest gate.
///
/// With no source installed the chain copy flows through unchanged.
fn overlay_network_key_data(
    key_is_stranded: bool,
    chain_data: DWalletNetworkEncryptionKeyData,
    source: Option<&dyn crate::validator_metadata::NetworkKeyBlobSource>,
) -> DWalletNetworkEncryptionKeyData {
    let Some(source) = source else {
        return chain_data;
    };
    if key_is_stranded {
        let network_dkg_public_output = source
            .network_dkg_output_blob(&chain_data.id)
            .unwrap_or(chain_data.network_dkg_public_output);
        DWalletNetworkEncryptionKeyData {
            network_dkg_public_output,
            ..chain_data
        }
    } else {
        crate::validator_metadata::fetch_network_key_data_with_off_chain_blobs(chain_data, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_metadata::StaticNetworkKeyBlobSource;

    #[test]
    fn persistent_condition_reports_once_per_episode_and_recovers_once() {
        let mut state = PersistentConditionState::default();
        assert_eq!(state.observe(false), ConditionTransition::Unchanged);
        assert_eq!(state.observe(true), ConditionTransition::Entered);
        assert_eq!(state.observe(true), ConditionTransition::Unchanged);
        assert_eq!(state.observe(true), ConditionTransition::Unchanged);
        assert_eq!(state.observe(false), ConditionTransition::Recovered);
        assert_eq!(state.observe(false), ConditionTransition::Unchanged);
        assert_eq!(state.observe(true), ConditionTransition::Entered);
    }

    #[test]
    fn assembly_health_warns_on_sustained_incompleteness_and_recovers_once() {
        let start = time::Instant::now();
        let mut state = AssemblyHealthState::default();
        assert_eq!(
            state.record_incomplete(start, 1, OffChainAssemblyMissingReason::Announcement, false,),
            AssemblyHealthAction::None
        );
        assert_eq!(
            state.record_incomplete(
                start + ASSEMBLY_STALL_WARN_AFTER,
                2,
                OffChainAssemblyMissingReason::BlobMissingOrInvalid,
                false,
            ),
            AssemblyHealthAction::Warn {
                duration_seconds: ASSEMBLY_STALL_WARN_AFTER.as_secs(),
                consecutive_ticks: 2,
                missing: 2,
                reason: OffChainAssemblyMissingReason::BlobMissingOrInvalid,
                post_deadline: false,
            }
        );
        assert_eq!(
            state.record_incomplete(
                start + ASSEMBLY_STALL_WARN_AFTER + Duration::from_secs(1),
                2,
                OffChainAssemblyMissingReason::BlobMissingOrInvalid,
                false,
            ),
            AssemblyHealthAction::None
        );
        assert_eq!(
            state.record_success(start + ASSEMBLY_STALL_WARN_AFTER + Duration::from_secs(2)),
            AssemblyHealthAction::Recovered {
                duration_seconds: ASSEMBLY_STALL_WARN_AFTER.as_secs() + 2,
                consecutive_ticks: 3,
            }
        );
        assert_eq!(
            state.record_success(start + ASSEMBLY_STALL_WARN_AFTER + Duration::from_secs(3)),
            AssemblyHealthAction::None
        );
    }

    #[test]
    fn assembly_health_escalates_post_deadline_without_warning_on_normal_convergence() {
        let start = time::Instant::now();
        let mut state = AssemblyHealthState::default();
        assert_eq!(
            state.record_incomplete(start, 1, OffChainAssemblyMissingReason::Announcement, false,),
            AssemblyHealthAction::None
        );
        assert_eq!(
            state.record_success(start + Duration::from_secs(1)),
            AssemblyHealthAction::None
        );
        assert_eq!(
            state.record_incomplete(
                start + Duration::from_secs(2),
                1,
                OffChainAssemblyMissingReason::BlobMissingOrInvalid,
                true,
            ),
            AssemblyHealthAction::Warn {
                duration_seconds: 0,
                consecutive_ticks: 1,
                missing: 1,
                reason: OffChainAssemblyMissingReason::BlobMissingOrInvalid,
                post_deadline: true,
            }
        );
    }

    #[test]
    fn assembly_missing_metrics_keep_fixed_categories_and_reset() {
        let metrics = SuiConnectorMetrics::new_for_testing();
        set_assembly_missing_metrics(
            &metrics,
            Some((OffChainAssemblyMissingReason::BlobMissingOrInvalid, 3)),
        );
        for reason in OffChainAssemblyMissingReason::ALL {
            assert_eq!(
                metrics
                    .off_chain_assembly_missing
                    .with_label_values(&[reason.label()])
                    .get(),
                if reason == OffChainAssemblyMissingReason::BlobMissingOrInvalid {
                    3
                } else {
                    0
                }
            );
        }
        set_assembly_missing_metrics(&metrics, None);
        for reason in OffChainAssemblyMissingReason::ALL {
            assert_eq!(
                metrics
                    .off_chain_assembly_missing
                    .with_label_values(&[reason.label()])
                    .get(),
                0
            );
        }
    }

    fn chain_data(key_id: ObjectID) -> DWalletNetworkEncryptionKeyData {
        DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch: 7,
            dkg_at_epoch: 0,
            network_dkg_public_output: b"chain dkg anchor".to_vec(),
            current_reconfiguration_public_output: b"chain current-epoch reconfiguration output"
                .to_vec(),
            state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
        }
    }

    /// The restart-recovery contract (#1852): for a key the manager flagged
    /// as stranded, the off-chain source must never override the chain's
    /// current-epoch reconfiguration output (the source serves the output
    /// this epoch's reconfiguration just produced, encrypted to the next
    /// committee), while the DKG blob still prefers the source's canonical
    /// mirror (the digest the handoff cert pins).
    #[test]
    fn stranded_key_keeps_chain_reconfiguration_output_and_canonical_dkg() {
        let key_id = ObjectID::random();
        let mut source = StaticNetworkKeyBlobSource::new();
        source.insert_dkg(key_id, b"canonical mirrored dkg output".to_vec());
        source.insert_reconfig(
            key_id,
            b"this epoch's output for the next committee".to_vec(),
        );

        let merged = overlay_network_key_data(true, chain_data(key_id), Some(&source));
        assert_eq!(
            merged.current_reconfiguration_public_output,
            b"chain current-epoch reconfiguration output".to_vec(),
            "a stranded key must keep the chain's current-epoch output"
        );
        assert_eq!(
            merged.network_dkg_public_output,
            b"canonical mirrored dkg output".to_vec(),
            "the DKG blob must still prefer the canonical off-chain mirror"
        );

        // A non-stranded key keeps the steady-state behavior: both blobs
        // prefer the off-chain source.
        let merged = overlay_network_key_data(false, chain_data(key_id), Some(&source));
        assert_eq!(
            merged.current_reconfiguration_public_output,
            b"this epoch's output for the next committee".to_vec(),
            "a non-stranded key keeps the off-chain overlay for the reconfiguration output"
        );
        assert_eq!(
            merged.network_dkg_public_output,
            b"canonical mirrored dkg output".to_vec(),
        );

        // No source installed: the chain copy flows through unchanged in
        // both states.
        for key_is_stranded in [false, true] {
            let merged = overlay_network_key_data(key_is_stranded, chain_data(key_id), None);
            assert_eq!(merged, chain_data(key_id));
        }
    }
}
