// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The SuiExecutor module handles executing transactions
//! on Sui blockchain for `ika_system` package.

use crate::dwallet_checkpoints::DWalletCheckpointStore;
use crate::sui_connector::SuiNotifier;
use crate::sui_connector::metrics::SuiConnectorMetrics;
use crate::system_checkpoints::SystemCheckpointStore;
use fastcrypto::traits::ToFromBytes;
use ika_config::node::RunWithRange;
use ika_sui_client::{SuiClient, SuiClientInner, retry_with_max_elapsed_time};
use ika_types::committee::EpochId;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::error::{IkaError, IkaResult};
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointMessage;
use ika_types::messages_dwallet_mpc::{
    DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME, DWalletNetworkEncryptionKeyData,
    DWalletNetworkEncryptionKeyState,
};
use ika_types::messages_system_checkpoints::SystemCheckpointMessage;
use ika_types::sui::epoch_start_system::EpochStartSystem;
use ika_types::sui::system_inner_v1::BlsCommittee;
use ika_types::sui::{
    ADVANCE_EPOCH_FUNCTION_NAME, APPEND_VECTOR_FUNCTION_NAME,
    CREATE_SYSTEM_CURRENT_STATUS_INFO_FUNCTION_NAME, DWalletCoordinator, DWalletCoordinatorInner,
    INITIATE_ADVANCE_EPOCH_FUNCTION_NAME, INITIATE_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME,
    PROCESS_CHECKPOINT_MESSAGE_BY_QUORUM_FUNCTION_NAME, PricingInfoKey,
    REQUEST_LOCK_EPOCH_SESSIONS_FUNCTION_NAME,
    REQUEST_NETWORK_ENCRYPTION_KEY_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME, SYSTEM_MODULE_NAME,
    System, SystemInner, SystemInnerTrait, VECTOR_MODULE_NAME,
};
use itertools::Itertools;
use move_core_types::ident_str;
use move_core_types::language_storage::TypeTag;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::sync::Arc;
use sui_json_rpc_types::SuiTransactionBlockEffectsAPI;
use sui_json_rpc_types::{SuiExecutionStatus, SuiTransactionBlockResponse};
use sui_macros::fail_point_async;
use sui_types::MOVE_STDLIB_PACKAGE_ID;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{Argument, CallArg, Transaction};
use tokio::sync::watch;
use tokio::sync::watch::Sender;
use tokio::time::{self, Duration};
use tracing::{debug, error, info, warn};

#[derive(PartialEq, Eq, Debug)]
pub enum StopReason {
    EpochComplete(Box<SystemInner>, EpochStartSystem),
    RunWithRangeCondition,
}

const ONE_HOUR_IN_SECONDS: u64 = 60 * 60;

/// Submission state for the notifier's single Sui address.
///
/// `gas_coins` caches the gas `ObjectRef` carried by the previous tx's effects
/// so the next tx is built against the *authoritative* post-tx gas version
/// rather than the notifier fullnode's `get_gas_objects` view, which lags the
/// validators by hundreds of versions under checkpoint-heavy load and otherwise
/// produces "transaction needs to be rebuilt (stale object version)" rejections
/// that stall epoch advance. Submission is serial (the lock is held across each
/// `submit_tx_to_sui`), so the cached ref is always the exact current version
/// when the next tx is built — the prior tx is also already finalized on the
/// validators by then (every caller awaits its `WaitForEffectsCert`/finalized
/// response), so no separate fullnode observability wait is needed.
#[derive(Default)]
struct NotifierSubmitState {
    /// SIP-58 mode (mirrors `SuiNotifier::gas_from_address_balance`): the
    /// writer pays gas from its address balance, transactions carry no gas
    /// `ObjectRef`, and ALL of the caching/recovery below is bypassed — the
    /// stale-gas-version failure class does not exist without gas objects.
    gas_from_address_balance: bool,
    gas_coins: Option<Vec<ObjectRef>>,
    /// The gas ref(s) handed to the most recent submission, so a failure can
    /// learn which version was rejected without threading it back through the
    /// callers. Submission is serial, so this is unambiguous.
    last_used_gas: Option<Vec<ObjectRef>>,
    /// When a tx is rejected for a stale gas version, the rejected version is
    /// recorded here as a floor: the next `get_gas_objects` re-fetch must
    /// return a version strictly greater before it is trusted. This stops the
    /// re-fetch from reusing the same stale version the lagging notifier
    /// fullnode keeps serving (e.g. after another holder of this address — in
    /// the in-process test cluster, the shared publisher coin — advanced it),
    /// which would otherwise re-reject in a tight loop and wedge epoch advance.
    min_gas_version: Option<SequenceNumber>,
}

impl NotifierSubmitState {
    /// Inspect a submission failure and, if it is a stale-gas rejection,
    /// drop the cached gas ref and record the rejected version as the
    /// re-fetch floor. Only a stale-gas rejection means the cached gas ref
    /// is bad; any other error leaves the cache intact — the gas was fine,
    /// the tx failed for an unrelated reason, and clearing it would force
    /// an unnecessary (and possibly stale) fullnode re-fetch.
    fn handle_possible_stale_gas_rejection(&mut self, error_message: &str) {
        if self.gas_from_address_balance {
            return;
        }
        let is_stale_gas = error_message.contains("unavailable for consumption")
            || error_message.contains("needs to be rebuilt");
        if is_stale_gas {
            if let Some(used) = &self.last_used_gas {
                self.min_gas_version = used.iter().map(|gas_ref| gas_ref.1).max();
            }
            self.gas_coins = None;
        }
    }
}

/// Cap on how long `next_gas_coins` waits for the fullnode to catch up past a
/// rejected gas version before giving up and using whatever it returns (the
/// outer `retry_with_max_elapsed_time!` re-attempts). 60 × 500ms = 30s.
const MAX_GAS_REFETCH_ATTEMPTS: u32 = 60;

/// Backoff for the mandatory verified inner reads: 1s, 2s, 4s, 8s, 16s, then
/// capped at 30s. These reads are not optional (the MPC pipeline needs the
/// current System / Coordinator inner), so they can't degrade to a fallback the
/// way the per-read currency gate does — but a sustained failure is the
/// finding-17 retention gap (the object's last-modifying checkpoint was pruned
/// upstream and isn't in the verified cache), so back off and escalate the log
/// instead of spinning at 1/s and flooding the logs while the operator acts.
fn verified_read_retry_backoff(attempts: u32) -> Duration {
    Duration::from_secs((1u64 << attempts.saturating_sub(1).min(5)).min(30))
}

pub struct SuiExecutor<C> {
    system_object_sender: Sender<Option<(System, SystemInner)>>,
    dwallet_coordinator_object_sender:
        Sender<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>,
    dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
    system_checkpoint_store: Arc<SystemCheckpointStore>,
    sui_notifier: Option<SuiNotifier>,
    sui_client: Arc<SuiClient<C>>,
    /// OCS-verified reader for coordinator/system polls. `Some` on
    /// validators (where OCS is required); `None` on notifier-only nodes
    /// that don't run an OCS verifier — they fall back to the legacy
    /// JSON-RPC path on `sui_client`.
    reader: Option<Arc<crate::sui_connector::verified_reader::OcsVerifiedReader>>,
    metrics: Arc<SuiConnectorMetrics>,
    notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
}

struct EpochSwitchState {
    ran_mid_epoch: bool,
    ran_lock_last_session: bool,
    ran_request_advance_epoch: bool,
    network_encryption_key_mid_epoch_reconfiguration: bool,
    calculated_protocol_pricing: bool,
}

/// Label values for `SuiConnectorMetrics::epoch_switch_step_done`. The set is closed and shared
/// with dashboards/alerts — adding a step here means updating the dashboard too.
const EPOCH_SWITCH_STEP_MID_EPOCH: &str = "mid_epoch";
const EPOCH_SWITCH_STEP_NETWORK_KEY_RECONFIG: &str =
    "network_encryption_key_mid_epoch_reconfiguration";
const EPOCH_SWITCH_STEP_CALC_PRICING: &str = "calculate_protocols_pricing";
const EPOCH_SWITCH_STEP_LOCK_LAST_SESSION: &str = "lock_last_session";
const EPOCH_SWITCH_STEP_REQUEST_ADVANCE_EPOCH: &str = "request_advance_epoch";
const EPOCH_SWITCH_STEPS: &[&str] = &[
    EPOCH_SWITCH_STEP_MID_EPOCH,
    EPOCH_SWITCH_STEP_NETWORK_KEY_RECONFIG,
    EPOCH_SWITCH_STEP_CALC_PRICING,
    EPOCH_SWITCH_STEP_LOCK_LAST_SESSION,
    EPOCH_SWITCH_STEP_REQUEST_ADVANCE_EPOCH,
];

impl<C> SuiExecutor<C>
where
    C: SuiClientInner + 'static,
{
    pub fn new(
        system_object_sender: Sender<Option<(System, SystemInner)>>,
        dwallet_coordinator_object_sender: Sender<
            Option<(DWalletCoordinator, DWalletCoordinatorInner)>,
        >,
        dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        sui_notifier: Option<SuiNotifier>,
        sui_client: Arc<SuiClient<C>>,
        reader: Option<Arc<crate::sui_connector::verified_reader::OcsVerifiedReader>>,
        metrics: Arc<SuiConnectorMetrics>,
    ) -> Self {
        Self {
            system_object_sender,
            dwallet_coordinator_object_sender,
            dwallet_checkpoint_store,
            system_checkpoint_store,
            notifier_tx_lock: Arc::new(tokio::sync::Mutex::new(NotifierSubmitState {
                gas_from_address_balance: sui_notifier
                    .as_ref()
                    .is_some_and(SuiNotifier::gas_from_address_balance),
                ..Default::default()
            })),
            sui_notifier,
            sui_client,
            reader,
            metrics,
        }
    }

    /// Retrieve the System wrapper + its inner. OCS-verified when a
    /// reader is wired in; falls back to the legacy JSON-RPC read on
    /// validators without OCS (notifier nodes). Retries forever — same
    /// semantics as the underlying `SuiClient::must_get_system_inner_object`.
    async fn must_get_system_inner(&self) -> (System, SystemInner) {
        if let Some(reader) = &self.reader {
            let id = self
                .sui_client
                .ika_network_config
                .objects
                .ika_system_object_id;
            let mut attempts: u32 = 0;
            loop {
                match reader.verified_system_inner(id).await {
                    Ok(v) => return v,
                    Err(e) => {
                        // A compiled-in/chain identity mismatch can never be
                        // fixed by retrying — the constant is baked into this
                        // build. Refuse to run rather than spin: silently
                        // retrying forever is the very failure mode this
                        // check exists to replace.
                        if e.is_terminal() {
                            panic!("{e}");
                        }
                        attempts += 1;
                        let backoff = verified_read_retry_backoff(attempts);
                        if attempts <= 3 {
                            warn!(error = ?e, attempts, "verified_system_inner failed; retrying");
                        } else {
                            warn!(
                                error = ?e,
                                attempts,
                                backoff_secs = backoff.as_secs(),
                                "verified_system_inner still failing — likely a pruned-and-uncached \
                                 anchor (Sui-fullnode retention gap); raise fullnode retention or re-anchor"
                            );
                        }
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }
        self.sui_client.must_get_system_inner_object().await
    }

    /// Retrieve the DWalletCoordinator wrapper + its inner. OCS-verified
    /// when a reader is wired in; falls back to legacy on notifiers.
    async fn must_get_dwallet_coordinator_inner(
        &self,
    ) -> (DWalletCoordinator, DWalletCoordinatorInner) {
        if let Some(reader) = &self.reader {
            let id = self
                .sui_client
                .ika_network_config
                .objects
                .ika_dwallet_coordinator_object_id;
            let mut attempts: u32 = 0;
            loop {
                match reader.verified_dwallet_coordinator_inner(id).await {
                    Ok(v) => return v,
                    Err(e) => {
                        // See `must_get_system_inner`: an identity mismatch is
                        // permanent, so fail loudly instead of retrying.
                        if e.is_terminal() {
                            panic!("{e}");
                        }
                        attempts += 1;
                        let backoff = verified_read_retry_backoff(attempts);
                        if attempts <= 3 {
                            warn!(error = ?e, attempts, "verified_dwallet_coordinator_inner failed; retrying");
                        } else {
                            warn!(
                                error = ?e,
                                attempts,
                                backoff_secs = backoff.as_secs(),
                                "verified_dwallet_coordinator_inner still failing — likely a \
                                 pruned-and-uncached anchor (Sui-fullnode retention gap); raise \
                                 fullnode retention or re-anchor"
                            );
                        }
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }
        self.sui_client.must_get_dwallet_coordinator_inner().await
    }

    /// Single-shot variant of [`Self::must_get_dwallet_coordinator_inner`].
    /// Used by `run_epoch_switch` where blocking the caller on retries
    /// would interfere with timing-sensitive epoch logic; the caller
    /// returns early on Err and the next tick retries the whole flow.
    async fn try_get_dwallet_coordinator_inner(
        &self,
    ) -> anyhow::Result<(DWalletCoordinator, DWalletCoordinatorInner)> {
        if let Some(reader) = &self.reader {
            let id = self
                .sui_client
                .ika_network_config
                .objects
                .ika_dwallet_coordinator_object_id;
            return reader
                .verified_dwallet_coordinator_inner(id)
                .await
                .map_err(|e| anyhow::anyhow!("verified_dwallet_coordinator_inner: {e}"));
        }
        self.sui_client
            .get_dwallet_coordinator_inner()
            .await
            .map_err(|e| anyhow::anyhow!("get_dwallet_coordinator_inner: {e}"))
    }

    /// Checks whether `process_mid_epoch`, `lock_last_active_session_sequence_number`, or
    /// `request_advance_epoch` can be called, and calls them if so.
    ///
    /// Anyone can call these functions based on the epoch and Sui's clock times.
    ///
    /// We don't use Sui's previous epoch switch mechanism as it assumes checkpoints are
    /// being created all the time, and in Ika,
    /// checkpoints are created only when there are new completed MPC sessions to write to Sui.
    async fn run_epoch_switch(
        &self,
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        ika_system_state_inner: &SystemInner,
        network_encryption_keys: HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
        epoch_switch_state: &mut EpochSwitchState,
    ) {
        let Ok(clock) = self.sui_client.get_clock().await else {
            error!("failed to get clock when running epoch switch");
            return;
        };
        let SystemInner::V1(system_inner_v1) = &ika_system_state_inner;

        let mid_epoch_time = ika_system_state_inner.epoch_start_timestamp_ms()
            + (ika_system_state_inner.epoch_duration_ms() / 2);
        let next_epoch_committee_is_empty =
            system_inner_v1.validator_set.next_epoch_committee.is_none();
        if clock.timestamp_ms > mid_epoch_time
            && next_epoch_committee_is_empty
            && !epoch_switch_state.ran_mid_epoch
        {
            info!("Calling `process_mid_epoch()`");
            // After mid-epoch reconfiguration, the next epoch committee is set, and
            // we can't call request dkg for the network encryption keys for the epoch.
            let response = retry_with_max_elapsed_time!(
                Self::process_mid_epoch(
                    ika_system_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    sui_notifier,
                    &self.sui_client,
                    self.notifier_tx_lock.clone(),
                ),
                Duration::from_secs(ONE_HOUR_IN_SECONDS)
            );
            if response.is_err() {
                panic!(
                    "failed to submit mid-epoch for over an hour: {:?}",
                    response.err()
                );
            }
            info!("Successfully processed mid-epoch");
            epoch_switch_state.ran_mid_epoch = true;
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[EPOCH_SWITCH_STEP_MID_EPOCH])
                .set(1);
        }
        let Ok((dwallet_coordinator, dwallet_coordinator_inner)) =
            self.try_get_dwallet_coordinator_inner().await
        else {
            error!("failed to get dwallet coordinator inner when running epoch switch");
            return;
        };

        let _ = self.dwallet_coordinator_object_sender.send(Some((
            dwallet_coordinator,
            dwallet_coordinator_inner.clone(),
        )));

        let DWalletCoordinatorInner::V1(coordinator_inner) = dwallet_coordinator_inner;

        if clock.timestamp_ms > mid_epoch_time
            && coordinator_inner.next_epoch_active_committee.is_some()
            // network_encryption_key_ids holds only keys that finished dkg
            && coordinator_inner.dwallet_network_encryption_keys.size == network_encryption_keys.len() as u64
            // check not all already completed
            && coordinator_inner.epoch_dwallet_network_encryption_keys_reconfiguration_completed != coordinator_inner.dwallet_network_encryption_keys.size
            && !epoch_switch_state.network_encryption_key_mid_epoch_reconfiguration
        {
            info!("Running network encryption key mid-epoch reconfiguration");

            let network_encryption_for_reconfiguration_key_ids = network_encryption_keys
                .iter()
                .filter(|(_, v)| {
                    v.state != DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration
                })
                .map(|(k, _)| *k)
                .collect_vec();

            if !network_encryption_for_reconfiguration_key_ids.is_empty() {
                let result = retry_with_max_elapsed_time!(
                    Self::request_mid_epoch_reconfiguration(
                        &self.sui_client,
                        ika_dwallet_2pc_mpc_package_id,
                        network_encryption_for_reconfiguration_key_ids.clone(),
                        sui_notifier,
                        self.notifier_tx_lock.clone(),
                    ),
                    Duration::from_secs(ONE_HOUR_IN_SECONDS)
                );
                if result.is_err() {
                    panic!(
                        "failed to network encryption key mid-epoch reconfiguration for over an hour: {:?}",
                        result.err()
                    );
                }
                info!("Successfully network encryption key mid-epoch reconfiguration");
            }
            epoch_switch_state.network_encryption_key_mid_epoch_reconfiguration = true;
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[EPOCH_SWITCH_STEP_NETWORK_KEY_RECONFIG])
                .set(1);
        }

        if clock.timestamp_ms > mid_epoch_time
            && let Some(calculation_votes) = coordinator_inner
                .pricing_and_fee_management
                .calculation_votes
                .as_ref()
            && coordinator_inner.next_epoch_active_committee.is_some()
            && !epoch_switch_state.calculated_protocol_pricing
        {
            info!("Running calculating protocol pricing");

            let default_pricing_keys = calculation_votes
                .default_pricing
                .pricing_map
                .contents
                .iter()
                .map(|c| c.key.clone())
                .collect_vec();

            let working_pricing = calculation_votes
                .working_pricing
                .pricing_map
                .contents
                .iter()
                .map(|c| c.key.clone())
                .collect_vec();

            let filtered_default_pricing_keys = default_pricing_keys
                .into_iter()
                .filter(|p| !working_pricing.contains(p))
                .collect_vec();

            let default_pricing_keys_chunked =
                filtered_default_pricing_keys.chunks(5).collect_vec();
            for default_pricing_keys_chunk in default_pricing_keys_chunked {
                let result = retry_with_max_elapsed_time!(
                    Self::calculate_protocols_pricing(
                        &self.sui_client,
                        ika_dwallet_2pc_mpc_package_id,
                        sui_notifier,
                        self.notifier_tx_lock.clone(),
                        default_pricing_keys_chunk
                    ),
                    Duration::from_secs(ONE_HOUR_IN_SECONDS)
                );
                if result.is_err() {
                    panic!(
                        "failed to calculate protocols' pricing for over an hour: {:?}",
                        result.err()
                    );
                }
            }
            info!("Successfully calculated protocols pricing");
            epoch_switch_state.calculated_protocol_pricing = true;
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[EPOCH_SWITCH_STEP_CALC_PRICING])
                .set(1);
        }

        let SystemInner::V1(system_inner_v1) = &ika_system_state_inner;

        let next_epoch_committee_is_some =
            system_inner_v1.validator_set.next_epoch_committee.is_some();

        // The Epoch was finished.
        let epoch_finish_time = ika_system_state_inner.epoch_start_timestamp_ms()
            + ika_system_state_inner.epoch_duration_ms();
        let epoch_not_locked = !coordinator_inner
            .sessions_manager
            .locked_last_user_initiated_session_to_complete_in_current_epoch;
        if clock.timestamp_ms > epoch_finish_time
            && next_epoch_committee_is_some
            && epoch_not_locked
            && !epoch_switch_state.ran_lock_last_session
        {
            info!("Calling `lock_last_active_session_sequence_number()`");
            let response = retry_with_max_elapsed_time!(
                Self::lock_last_session_to_complete_in_current_epoch(
                    ika_system_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    sui_notifier,
                    &self.sui_client,
                    self.notifier_tx_lock.clone(),
                ),
                Duration::from_secs(ONE_HOUR_IN_SECONDS)
            );
            if response.is_err() {
                panic!(
                    "failed to submit lock-last session for over an hour: {:?}",
                    response.err()
                );
            }
            epoch_switch_state.ran_lock_last_session = true;
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[EPOCH_SWITCH_STEP_LOCK_LAST_SESSION])
                .set(1);
            info!("Successfully locked last session in current epoch");
        }
        // Mirror the on-chain `all_current_epoch_sessions_completed` assertion in
        // `sessions_manager::advance_epoch`: the locked user-session batch must be
        // fully completed AND every system session (network-key DKG/reconfiguration)
        // must have finished. `received_end_of_publish` is set from a quorum snapshot
        // and can momentarily precede a freshly-initiated system session (a
        // `respond_*` on a network-key session chains a new `initiate_system_session`),
        // so we re-check against the just-synced coordinator state before submitting.
        // Submitting `advance_epoch` while this is false MoveAborts with
        // `ENotAllCurrentEpochSessionsCompleted` (code 6); the outer hour-long retry
        // would then burn out and `panic!` the validator over a transient,
        // self-clearing condition — dropping the committee below quorum mid-transition
        // and risking a network-wide wedge. Gating the submission keeps the panic for
        // genuinely fatal submission failures only.
        let sessions_manager = &coordinator_inner.sessions_manager;
        let all_current_epoch_sessions_completed =
            sessions_manager.all_current_epoch_sessions_completed();
        let advance_gate_open = coordinator_inner.received_end_of_publish
            && system_inner_v1.received_end_of_publish
            && !epoch_switch_state.ran_request_advance_epoch;
        if advance_gate_open && all_current_epoch_sessions_completed {
            info!("Calling `process_request_advance_epoch()`");
            let response = retry_with_max_elapsed_time!(
                Self::process_request_advance_epoch(
                    ika_system_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    sui_notifier,
                    &self.sui_client.clone(),
                    self.notifier_tx_lock.clone(),
                ),
                Duration::from_secs(ONE_HOUR_IN_SECONDS)
            );
            if response.is_err() {
                panic!(
                    "failed to submit request advance epoch for over an hour: {:?}",
                    response.err()
                );
            }
            info!("Successfully requested advance epoch");
            epoch_switch_state.ran_request_advance_epoch = true;
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[EPOCH_SWITCH_STEP_REQUEST_ADVANCE_EPOCH])
                .set(1);
        } else if advance_gate_open {
            // End-of-publish is in, but sessions are still draining. Hold this
            // tick (do NOT submit a doomed `advance_epoch`); re-check next tick.
            debug!(
                epoch = coordinator_inner.current_epoch,
                locked = sessions_manager
                    .locked_last_user_initiated_session_to_complete_in_current_epoch,
                user_completed = sessions_manager
                    .user_sessions_keeper
                    .completed_sessions_count,
                user_target =
                    sessions_manager.last_user_initiated_session_to_complete_in_current_epoch,
                system_started = sessions_manager
                    .system_sessions_keeper
                    .started_sessions_count,
                system_completed = sessions_manager
                    .system_sessions_keeper
                    .completed_sessions_count,
                "end-of-publish received but current-epoch sessions are still completing; \
                 holding advance_epoch this tick",
            );
        }

        // The per-step assignments above are process-local memos: each is set when
        // THIS process performs a step, and all of them zero on restart. During a
        // rolling upgrade every validator restarts and the whole fleet reports 0
        // even for steps long completed on chain. Re-derive every step with an
        // on-chain "done" predicate (the negation of the guard that triggers it)
        // and OR it with the memo each tick, so a restarted validator converges on
        // its next tick. `request_advance_epoch` stays memo-only: its chain effect
        // is the epoch switch itself, which replaces this state and re-zeros the
        // gauges.
        let mid_epoch_done_on_chain = system_inner_v1.validator_set.next_epoch_committee.is_some();
        let keys_total = coordinator_inner.dwallet_network_encryption_keys.size;
        // Every key is either not-yet-requested, parked awaiting reconfiguration
        // (requested, incomplete), or counted in the per-epoch completed counter
        // (keys leave the awaiting state on completion; `advance_epoch` asserts
        // completed == total before zeroing, so the counter cannot leak across
        // epochs). completed + awaiting == total therefore holds exactly when
        // every key has been requested this epoch — including the mixed window
        // where some completions already landed while others are still awaiting.
        let awaiting_keys = network_encryption_keys
            .values()
            .filter(|key| {
                key.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration
            })
            .count() as u64;
        // The bare completed-counter arm stays independent of the local key map
        // so a lagging map read cannot suppress a fully-completed epoch.
        let reconfig_done_on_chain = keys_total > 0
            && (coordinator_inner.epoch_dwallet_network_encryption_keys_reconfiguration_completed
                == keys_total
                || (network_encryption_keys.len() as u64 == keys_total
                    && coordinator_inner
                        .epoch_dwallet_network_encryption_keys_reconfiguration_completed
                        + awaiting_keys
                        == keys_total));
        // Votes are opened at mid-epoch (alongside the next active committee) and
        // consumed by the pricing calculation, so Some(committee) + no open votes
        // means the calculation already ran this epoch.
        let pricing_done_on_chain = coordinator_inner.next_epoch_active_committee.is_some()
            && coordinator_inner
                .pricing_and_fee_management
                .calculation_votes
                .is_none();
        let lock_done_on_chain =
            sessions_manager.locked_last_user_initiated_session_to_complete_in_current_epoch;
        for (step, done) in [
            (
                EPOCH_SWITCH_STEP_MID_EPOCH,
                epoch_switch_state.ran_mid_epoch || mid_epoch_done_on_chain,
            ),
            (
                EPOCH_SWITCH_STEP_NETWORK_KEY_RECONFIG,
                epoch_switch_state.network_encryption_key_mid_epoch_reconfiguration
                    || reconfig_done_on_chain,
            ),
            (
                EPOCH_SWITCH_STEP_CALC_PRICING,
                epoch_switch_state.calculated_protocol_pricing || pricing_done_on_chain,
            ),
            (
                EPOCH_SWITCH_STEP_LOCK_LAST_SESSION,
                epoch_switch_state.ran_lock_last_session || lock_done_on_chain,
            ),
        ] {
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[step])
                .set(i64::from(done));
        }
    }

    pub async fn run_epoch(
        &self,
        epoch: EpochId,
        run_with_range: Option<RunWithRange>,
        mut network_keys_receiver: watch::Receiver<
            Arc<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>>,
        >,
    ) -> StopReason {
        info!(?epoch, "Starting sui connector SuiExecutor run_epoch");
        // Check if we want to run this epoch based on RunWithRange condition value
        // we want to be inclusive of the defined RunWithRangeEpoch::Epoch
        // i.e Epoch(N) means we will execute the epoch N and stop when reaching N+1.
        if run_with_range.is_some_and(|rwr| rwr.is_epoch_gt(epoch)) {
            info!(
                "RunWithRange condition satisfied at {:?}, run_epoch={:?}",
                run_with_range, epoch
            );
            return StopReason::RunWithRangeCondition;
        };

        let mut interval = time::interval(Duration::from_millis(120));

        let mut last_submitted_dwallet_checkpoint: Option<u64> = None;
        let mut last_submitted_system_checkpoint: Option<u64> = None;

        let mut epoch_switch_state = EpochSwitchState {
            ran_mid_epoch: false,
            ran_lock_last_session: false,
            ran_request_advance_epoch: false,
            network_encryption_key_mid_epoch_reconfiguration: false,
            calculated_protocol_pricing: false,
        };
        // Zero every step at the start of the epoch so a stale `1` from the previous epoch's run
        // can't mislead an operator into thinking we already advanced for this epoch.
        for step in EPOCH_SWITCH_STEPS {
            self.metrics
                .epoch_switch_step_done
                .with_label_values(&[step])
                .set(0);
        }

        loop {
            interval.tick().await;
            let (system, system_inner) = self.must_get_system_inner().await;
            let ika_system_package_id = system.package_id;
            let _ = self
                .system_object_sender
                .send(Some((system, system_inner.clone())));
            let epoch_on_sui: u64 = system_inner.epoch();
            if epoch_on_sui > epoch {
                fail_point_async!("crash");
                info!(epoch, "Finished epoch");
                let epoch_start_system_state = self
                    .sui_client
                    .must_get_epoch_start_system(&system_inner)
                    .await;
                return StopReason::EpochComplete(Box::new(system_inner), epoch_start_system_state);
            }
            if epoch_on_sui < epoch {
                error!("epoch_on_sui cannot be less than epoch");
            }
            let (dwallet_coordinator, dwallet_coordinator_inner) =
                self.must_get_dwallet_coordinator_inner().await;
            let ika_dwallet_2pc_mpc_package_id = dwallet_coordinator.package_id;
            let _ = self.dwallet_coordinator_object_sender.send(Some((
                dwallet_coordinator,
                dwallet_coordinator_inner.clone(),
            )));
            let DWalletCoordinatorInner::V1(dwallet_coordinator_inner) = dwallet_coordinator_inner;
            let last_processed_dwallet_checkpoint_sequence_number: u64 =
                dwallet_coordinator_inner.last_processed_checkpoint_sequence_number;
            let next_dwallet_checkpoint_sequence_number =
                last_processed_dwallet_checkpoint_sequence_number + 1;

            let last_processed_system_checkpoint_sequence_number: u64 =
                system_inner.last_processed_checkpoint_sequence_number();
            let next_system_checkpoint_sequence_number =
                last_processed_system_checkpoint_sequence_number + 1;

            if let Some(sui_notifier) = self.sui_notifier.as_ref() {
                let network_encryption_keys =
                    { network_keys_receiver.borrow_and_update().as_ref().clone() };
                self.run_epoch_switch(
                    ika_system_package_id,
                    ika_dwallet_2pc_mpc_package_id,
                    sui_notifier,
                    &system_inner,
                    network_encryption_keys,
                    &mut epoch_switch_state,
                )
                .await;
                if Some(next_dwallet_checkpoint_sequence_number) > last_submitted_dwallet_checkpoint
                {
                    match self
                        .dwallet_checkpoint_store
                        .get_dwallet_checkpoint_by_sequence_number(
                            next_dwallet_checkpoint_sequence_number,
                        ) {
                        Ok(Some(dwallet_checkpoint_message)) => {
                            debug!(
                                ?next_dwallet_checkpoint_sequence_number,
                                "Processing checkpoint sequence number"
                            );
                            self.metrics.dwallet_checkpoint_write_requests_total.inc();
                            self.metrics
                                .dwallet_checkpoint_sequence
                                .set(next_dwallet_checkpoint_sequence_number as i64);

                            let active_members: BlsCommittee =
                                system_inner.validator_set().clone().active_committee;
                            let auth_sig = dwallet_checkpoint_message.auth_sig();
                            let signature = auth_sig.signature.as_bytes().to_vec();
                            let signers_bitmap = Self::calculate_signers_bitmap(
                                &auth_sig.signers_map,
                                &active_members,
                            );
                            let signers_len = auth_sig.signers_map.len();
                            let message = bcs::to_bytes::<DWalletCheckpointMessage>(
                                &dwallet_checkpoint_message.into_message(),
                            )
                            .expect("Serializing checkpoint message cannot fail");

                            debug!(
                                signers_len=?signers_len,
                                ?signers_bitmap,
                                "Processing checkpoint with signers"
                            );

                            let response = retry_with_max_elapsed_time!(
                                Self::handle_dwallet_checkpoint_execution_task(
                                    ika_dwallet_2pc_mpc_package_id,
                                    signature.clone(),
                                    signers_bitmap.clone(),
                                    message.clone(),
                                    sui_notifier,
                                    &self.sui_client.clone(),
                                    &self.metrics.clone(),
                                    self.notifier_tx_lock.clone().clone(),
                                ),
                                Duration::from_secs(ONE_HOUR_IN_SECONDS)
                            );
                            if response.is_err() {
                                panic!(
                                    "failed to submit dwallet checkpoint for over an hour, err: {:?}",
                                    response.err()
                                );
                            }
                            debug!(
                                ?next_dwallet_checkpoint_sequence_number,
                                "Successfully submitted dwallet checkpoint"
                            );
                            self.metrics.dwallet_checkpoint_writes_success_total.inc();
                            self.metrics
                                .last_written_dwallet_checkpoint_sequence
                                .set(next_dwallet_checkpoint_sequence_number as i64);
                            last_submitted_dwallet_checkpoint =
                                Some(next_dwallet_checkpoint_sequence_number);
                        }
                        Err(e) => {
                            error!(
                                sequence_number=?next_dwallet_checkpoint_sequence_number,
                                error=?e,
                                "failed to get checkpoint"
                            );
                        }
                        Ok(None) => {}
                    }
                }

                if Some(next_system_checkpoint_sequence_number) > last_submitted_system_checkpoint
                    && let Ok(Some(system_checkpoint)) = self
                        .system_checkpoint_store
                        .get_system_checkpoint_by_sequence_number(
                            next_system_checkpoint_sequence_number,
                        )
                {
                    self.metrics
                        .system_checkpoint_sequence
                        .set(next_system_checkpoint_sequence_number as i64);

                    let active_members: BlsCommittee =
                        system_inner.validator_set().clone().active_committee;
                    let auth_sig = system_checkpoint.auth_sig();
                    let signature = auth_sig.signature.as_bytes().to_vec();
                    let signers_bitmap =
                        Self::calculate_signers_bitmap(&auth_sig.signers_map, &active_members);
                    let message =
                        bcs::to_bytes::<SystemCheckpointMessage>(&system_checkpoint.into_message())
                            .expect("Serializing `system_checkpoint` message cannot fail");

                    debug!("Signers_bitmap: {:?}", signers_bitmap);
                    self.metrics.system_checkpoint_write_requests_total.inc();
                    let response = retry_with_max_elapsed_time!(
                        Self::handle_system_checkpoint_execution_task(
                            ika_system_package_id,
                            signature.clone(),
                            signers_bitmap.clone(),
                            message.clone(),
                            sui_notifier,
                            &self.sui_client.clone(),
                            &self.metrics.clone(),
                            self.notifier_tx_lock.clone(),
                        ),
                        Duration::from_secs(ONE_HOUR_IN_SECONDS)
                    );
                    if response.is_err() {
                        panic!(
                            "failed to submit system checkpoint for over an hour, err: {:?}",
                            response.err()
                        );
                    }
                    self.metrics.system_checkpoint_writes_success_total.inc();
                    self.metrics
                        .last_written_system_checkpoint_sequence
                        .set(next_system_checkpoint_sequence_number as i64);
                    last_submitted_system_checkpoint = Some(next_system_checkpoint_sequence_number);
                    debug!(
                        "Sui transaction successfully executed for system_checkpoint sequence number: {}",
                        next_system_checkpoint_sequence_number
                    );
                }
            }
        }
    }

    fn calculate_signers_bitmap(
        signers_map: &RoaringBitmap,
        active_committee: &BlsCommittee,
    ) -> Vec<u8> {
        let committee_size = active_committee.members.len();
        let mut signers_bitmap = vec![0u8; committee_size.div_ceil(8)];
        for singer in signers_map.iter() {
            // Set the i-th bit to 1,
            let byte_index = (singer / 8) as usize;
            let bit_index = singer % 8;
            signers_bitmap[byte_index] |= 1u8 << bit_index;
        }
        signers_bitmap
    }

    /// Break down the message to slices because of chain transaction size limits.
    /// Limit 16 KB per Tx `pure` argument.
    fn break_down_checkpoint_message_into_vector_arg(
        ptb: &mut ProgrammableTransactionBuilder,
        message: Vec<u8>,
    ) -> DwalletMPCResult<Argument> {
        // Set to 15 because the limit is up to 16 (smaller than).
        let messages = message.chunks(15 * 1024).collect_vec();
        if messages.is_empty() {
            return Err(DwalletMPCError::CheckpointMessageIsEmpty);
        }
        let vector_arg = ptb
            .input(CallArg::Pure(bcs::to_bytes(messages.first().unwrap())?))
            .map_err(|e| {
                IkaError::SuiConnectorSerializationError(format!("can't serialize ptb input: {e}"))
            })?;

        messages[1..].iter().try_for_each(|message| {
            let message_arg = ptb
                .input(CallArg::Pure(bcs::to_bytes(*message)?))
                .map_err(|e| {
                    IkaError::SuiConnectorSerializationError(format!(
                        "can't serialize ptb input: {e}"
                    ))
                })?;
            ptb.programmable_move_call(
                MOVE_STDLIB_PACKAGE_ID,
                VECTOR_MODULE_NAME.into(),
                APPEND_VECTOR_FUNCTION_NAME.into(),
                vec![TypeTag::U8],
                vec![vector_arg, message_arg],
            );
            Ok::<(), DwalletMPCError>(())
        })?;

        Ok(vector_arg)
    }

    async fn request_mid_epoch_reconfiguration(
        sui_client: &Arc<SuiClient<C>>,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        network_encryption_key_ids: Vec<ObjectID>,
        sui_notifier: &SuiNotifier,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> anyhow::Result<SuiTransactionBlockResponse> {
        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;
        let mut ptb = ProgrammableTransactionBuilder::new();
        let dwallet_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        let dwallet_coordinator_ptb_arg = ptb.input(CallArg::Object(dwallet_coordinator_arg))?;

        for network_encryption_key_id in network_encryption_key_ids {
            let network_encryption_key_id_arg =
                ptb.input(CallArg::Pure(bcs::to_bytes(&network_encryption_key_id)?))?;
            ptb.programmable_move_call(
                ika_dwallet_2pc_mpc_package_id,
                DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
                REQUEST_NETWORK_ENCRYPTION_KEY_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME.into(),
                vec![],
                vec![dwallet_coordinator_ptb_arg, network_encryption_key_id_arg],
            );
        }

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn calculate_protocols_pricing(
        sui_client: &Arc<SuiClient<C>>,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
        default_pricing_keys: &[PricingInfoKey],
    ) -> anyhow::Result<SuiTransactionBlockResponse> {
        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;
        let mut ptb = ProgrammableTransactionBuilder::new();
        let dwallet_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        let dwallet_coordinator_ptb_arg = ptb.input(CallArg::Object(dwallet_coordinator_arg))?;

        for PricingInfoKey {
            curve,
            signature_algorithm,
            protocol,
        } in default_pricing_keys
        {
            let curve_arg = ptb.input(CallArg::Pure(bcs::to_bytes(curve)?))?;
            let signature_algorithm_arg =
                ptb.input(CallArg::Pure(bcs::to_bytes(signature_algorithm)?))?;
            let protocol_arg = ptb.input(CallArg::Pure(bcs::to_bytes(protocol)?))?;

            ptb.programmable_move_call(
                ika_dwallet_2pc_mpc_package_id,
                DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
                ident_str!("calculate_pricing_votes").into(),
                vec![],
                vec![
                    dwallet_coordinator_ptb_arg,
                    curve_arg,
                    signature_algorithm_arg,
                    protocol_arg,
                ],
            );
        }

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    /// Returns the gas coins to fund the next notifier tx. Prefers the
    /// cached `ObjectRef` carried by the previous tx's effects (the
    /// authoritative post-tx version); falls back to a fresh
    /// `get_gas_objects` fetch only when nothing is cached yet (first tx
    /// of the process). See [`NotifierSubmitState`] for why the fullnode
    /// fetch is avoided on the steady-state path.
    async fn next_gas_coins(
        notifier_tx_lock: &Arc<tokio::sync::Mutex<NotifierSubmitState>>,
        sui_client: &Arc<SuiClient<C>>,
        address: SuiAddress,
    ) -> Vec<ObjectRef> {
        // Fast path: the authoritative ref carried by the prior tx's effects.
        {
            let mut state = notifier_tx_lock.lock().await;
            // SIP-58 address-balance gas: transactions carry no gas objects.
            if state.gas_from_address_balance {
                return vec![];
            }
            if let Some(gas) = state.gas_coins.clone() {
                state.last_used_gas = Some(gas.clone());
                return gas;
            }
        }
        // Slow path (first tx of the process, or after a stale-gas rejection
        // cleared the cache): re-fetch from the fullnode. If a prior rejection
        // recorded a `min_gas_version` floor, wait for the fullnode to catch up
        // past it before trusting the result — the notifier fullnode lags the
        // validators, so an immediate re-fetch keeps serving the same stale
        // version that was just rejected.
        let mut attempts = 0u32;
        loop {
            let gas = sui_client.get_gas_objects(address).await;
            let mut state = notifier_tx_lock.lock().await;
            let highest = gas.iter().map(|gas_ref| gas_ref.1).max();
            let acceptable = match state.min_gas_version {
                Some(floor) => highest.is_some_and(|version| version > floor),
                None => true,
            };
            if acceptable || attempts >= MAX_GAS_REFETCH_ATTEMPTS {
                state.min_gas_version = None;
                state.last_used_gas = Some(gas.clone());
                return gas;
            }
            drop(state);
            attempts += 1;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn submit_tx_to_sui(
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
        transaction: Transaction,
        sui_client: &Arc<SuiClient<C>>,
    ) -> DwalletMPCResult<SuiTransactionBlockResponse> {
        let mut state = notifier_tx_lock.lock().await;
        // No pre-wait on the prior tx's observability. `execute_transaction`
        // below drives the tx through the validator transaction-driver and
        // returns only on FINALIZED effects, and every caller awaits that before
        // building the next tx — so the prior tx is already final on the
        // validators (the authoritative source) when this one is submitted, and
        // the gas ref this tx carries is the cached post-prior-tx ref from those
        // effects. The previous gate spun on `get_events_by_tx_digest` (a
        // `get_transaction_checkpoint` read) against the notifier's own fullnode,
        // which lags the validators by minutes under sustained checkpoint load
        // and is itself prune-prone — throttling write-back to <1/min, which
        // freezes dwallet advancement under heavy sequential load. The stale-gas
        // recovery below stays as the safety net for a rare cached-ref miss.
        debug!(
            transaction_digest = ?transaction.digest(),
            "Submitting a transaction to Sui"
        );

        let tx_response = match sui_client
            .execute_transaction_block_with_effects(transaction)
            .await
        {
            Ok(tx_response) => tx_response,
            Err(err) => {
                // The fullnode can also reject the tx at submission with a
                // JSON-RPC error instead of returning a response carrying
                // `errors` — input-object check failures ("needs to be
                // rebuilt" / "unavailable for consumption") surface this
                // way, wrapped in `SuiClientTxFailureGeneric`. Apply the same
                // stale-gas recovery as the `errors` branch below; otherwise
                // the cached gas ref survives the failure and every retry
                // rebuilds the identical stale tx until the one-hour panic,
                // wedging checkpoint submission.
                //
                // Match the variant payload — do NOT pass `err.to_string()`
                // and especially not clippy's `unnecessary_to_owned`
                // "simplification" of it, `err.as_ref()`: `IkaError` derives
                // strum's `AsRefStr`, so `as_ref()` returns only the variant
                // name ("SuiClientTxFailureGeneric"), which never contains
                // the rejection markers — it compiles fine and silently
                // disables this recovery.
                if let IkaError::SuiClientTxFailureGeneric(_, message) = &err {
                    state.handle_possible_stale_gas_rejection(message);
                }
                return Err(err.into());
            }
        };

        if !tx_response.errors.is_empty() {
            let errors = format!("{:?}", tx_response.errors);
            // A stale-gas rejection drops the cached gas ref AND records the
            // rejected version as a floor — so the caller's
            // `retry_with_max_elapsed_time!` re-fetch waits for the notifier
            // fullnode to advance past it instead of re-serving the same
            // stale version in a tight loop (which wedged epoch advance).
            state.handle_possible_stale_gas_rejection(&errors);
            return Err(IkaError::SuiClientTxFailureGeneric(tx_response.digest, errors).into());
        }

        let Some(tx_effects) = tx_response.effects.clone() else {
            // No effects to derive the post-tx gas version from; treat the
            // cached ref as unreliable and re-fetch on retry.
            state.gas_coins = None;
            return Err(IkaError::SuiClientTxFailureGeneric(
                tx_response.digest,
                "Transaction effects are missing".to_string(),
            )
            .into());
        };

        if !state.gas_from_address_balance {
            // The tx executed (effects are present), so the gas coin advanced
            // to a new version regardless of move success/abort. Cache that
            // authoritative ref for the next tx instead of re-reading the
            // notifier fullnode, which lags under load and yields stale gas
            // versions that get rejected and stall epoch advance. (Under
            // address-balance gas there is no gas object; the effects'
            // gas_object is a placeholder and must not be cached.)
            state.gas_coins = Some(vec![tx_effects.gas_object().reference.to_object_ref()]);
            // The cached ref is now authoritative again; drop any stale-version
            // floor a prior rejection left so a future re-fetch isn't over-gated.
            state.min_gas_version = None;
        }

        if let SuiExecutionStatus::Failure { error } = tx_effects.status() {
            return Err(IkaError::SuiClientTxFailureGeneric(
                tx_response.digest,
                format!(
                    "Transaction executed successfully, but it failed with an error: {error:?}",
                ),
            )
            .into());
        };

        Ok(tx_response)
    }

    async fn process_mid_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Running `process_mid_epoch()`");
        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;

        let mut ptb = ProgrammableTransactionBuilder::new();

        let ika_system_state_arg = sui_client.get_mutable_system_arg_must_succeed().await;
        let clock_arg = sui_client.get_clock_arg_must_succeed().await;
        let dwallet_2pc_mpc_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        let system_arg = ptb
            .input(CallArg::Object(ika_system_state_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on system_arg: {e}"))
            })?;

        let coordinator_arg = ptb
            .input(CallArg::Object(dwallet_2pc_mpc_coordinator_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on coordinator_arg: {e}"))
            })?;

        let clock_arg = ptb.input(CallArg::Object(clock_arg)).map_err(|e| {
            IkaError::SuiConnectorInternalError(format!("failed on clock_arg: {e}"))
        })?;

        ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            INITIATE_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME.into(),
            vec![],
            vec![system_arg, clock_arg],
        );

        let system_current_status_info = ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            CREATE_SYSTEM_CURRENT_STATUS_INFO_FUNCTION_NAME.into(),
            vec![],
            vec![system_arg, clock_arg],
        );

        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            INITIATE_MID_EPOCH_RECONFIGURATION_FUNCTION_NAME.into(),
            vec![],
            vec![coordinator_arg, system_current_status_info],
        );

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn lock_last_session_to_complete_in_current_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Process `lock_last_active_session_sequence_number()`");
        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;

        let mut ptb = ProgrammableTransactionBuilder::new();

        let ika_system_state_arg = sui_client.get_mutable_system_arg_must_succeed().await;
        let clock_arg = sui_client.get_clock_arg_must_succeed().await;

        let dwallet_2pc_mpc_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        let system_arg = ptb
            .input(CallArg::Object(ika_system_state_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on system_arg: {e}"))
            })?;

        let coordinator_arg = ptb
            .input(CallArg::Object(dwallet_2pc_mpc_coordinator_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on coordinator_arg: {e}"))
            })?;

        let clock_arg = ptb.input(CallArg::Object(clock_arg)).map_err(|e| {
            IkaError::SuiConnectorInternalError(format!("failed on clock_arg: {e}"))
        })?;

        let system_current_status_info = ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            CREATE_SYSTEM_CURRENT_STATUS_INFO_FUNCTION_NAME.into(),
            vec![],
            vec![system_arg, clock_arg],
        );

        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            REQUEST_LOCK_EPOCH_SESSIONS_FUNCTION_NAME.into(),
            vec![],
            vec![coordinator_arg, system_current_status_info],
        );

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn process_request_advance_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Running `process_request_advance_epoch()`");
        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;

        let mut ptb = ProgrammableTransactionBuilder::new();

        let ika_system_state_arg = sui_client.get_mutable_system_arg_must_succeed().await;
        let clock_arg = sui_client.get_clock_arg_must_succeed().await;

        let dwallet_2pc_mpc_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        let system_arg = ptb
            .input(CallArg::Object(ika_system_state_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on system_arg: {e}"))
            })?;

        let coordinator_arg = ptb
            .input(CallArg::Object(dwallet_2pc_mpc_coordinator_arg))
            .map_err(|e| {
                IkaError::SuiConnectorInternalError(format!("failed on coordinator_arg: {e}"))
            })?;

        let clock_arg = ptb.input(CallArg::Object(clock_arg)).map_err(|e| {
            IkaError::SuiConnectorInternalError(format!("failed on clock_arg: {e}"))
        })?;

        let advance_epoch_approver = ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            INITIATE_ADVANCE_EPOCH_FUNCTION_NAME.into(),
            vec![],
            vec![system_arg, clock_arg],
        );

        ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            ADVANCE_EPOCH_FUNCTION_NAME.into(),
            vec![],
            vec![coordinator_arg, advance_epoch_approver],
        );

        ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            ADVANCE_EPOCH_FUNCTION_NAME.into(),
            vec![],
            vec![system_arg, advance_epoch_approver, clock_arg],
        );

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn handle_dwallet_checkpoint_execution_task(
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        signature: Vec<u8>,
        signers_bitmap: Vec<u8>,
        message: Vec<u8>,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        metrics: &Arc<SuiConnectorMetrics>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        let mut ptb = ProgrammableTransactionBuilder::new();

        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;
        //merge_gas_coins(&mut ptb, &gas_coins)?;

        let dwallet_2pc_mpc_coordinator_arg = sui_client
            .get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed()
            .await;

        info!(
            "`signers_bitmap` @ handle_execution_task: {:?}",
            signers_bitmap
        );

        let args = vec![
            CallArg::Object(dwallet_2pc_mpc_coordinator_arg),
            CallArg::Pure(bcs::to_bytes(&signature).map_err(|e| {
                IkaError::SuiConnectorSerializationError(format!(
                    "can't serialize `signature`: {e}"
                ))
            })?),
            CallArg::Pure(bcs::to_bytes(&signers_bitmap).map_err(|e| {
                IkaError::SuiConnectorSerializationError(format!(
                    "can't serialize `signers_bitmap`: {e}"
                ))
            })?),
        ];

        let mut args = args
            .into_iter()
            .map(|arg| {
                ptb.input(arg).map_err(|e| {
                    IkaError::SuiConnectorSerializationError(format!("can't serialize `arg`: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let message_arg =
            Self::break_down_checkpoint_message_into_vector_arg(&mut ptb, message.clone());
        args.push(message_arg?);

        let gas_fee_reimbursement_sui = ptb.programmable_move_call(
            ika_dwallet_2pc_mpc_package_id,
            DWALLET_2PC_MPC_COORDINATOR_MODULE_NAME.into(),
            PROCESS_CHECKPOINT_MESSAGE_BY_QUORUM_FUNCTION_NAME.into(),
            vec![],
            args,
        );

        if sui_notifier.gas_from_address_balance() {
            // No gas coin object exists to merge into (SIP-58 balance gas):
            // send the reimbursement to the writer's address as an owned coin
            // instead. It accumulates as small coins the operator can sweep
            // into the address balance.
            ptb.transfer_arg(sui_notifier.sui_address(), gas_fee_reimbursement_sui);
        } else {
            ptb.command(sui_types::transaction::Command::MergeCoins(
                Argument::GasCoin,
                vec![gas_fee_reimbursement_sui],
            ));
        }

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        match Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await {
            Ok(result) => Ok(result),
            Err(err) => {
                error!(error=?err, "failed to submit dwallet checkpoint to sui",);
                metrics.dwallet_checkpoint_writes_failure_total.inc();
                Err(err.into())
            }
        }
    }

    async fn handle_system_checkpoint_execution_task(
        ika_system_package_id: ObjectID,
        signature: Vec<u8>,
        signers_bitmap: Vec<u8>,
        message: Vec<u8>,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        metrics: &Arc<SuiConnectorMetrics>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<NotifierSubmitState>>,
    ) -> IkaResult<()> {
        let mut ptb = ProgrammableTransactionBuilder::new();

        let gas_coins =
            Self::next_gas_coins(&notifier_tx_lock, sui_client, sui_notifier.sui_address).await;
        // merge_gas_coins(&mut ptb, &gas_coins)?;

        info!(
            "`signers_bitmap` @ handle_execution_task: {:?}",
            signers_bitmap
        );
        let ika_system_state_arg = sui_client.get_mutable_system_arg_must_succeed().await;

        let args = vec![
            CallArg::Object(ika_system_state_arg),
            CallArg::Pure(bcs::to_bytes(&signature).map_err(|e| {
                IkaError::SuiConnectorSerializationError(format!(
                    "can't serialize `signature`: {e}"
                ))
            })?),
            CallArg::Pure(bcs::to_bytes(&signers_bitmap).map_err(|e| {
                IkaError::SuiConnectorSerializationError(format!(
                    "can't serialize `signers_bitmap`: {e}"
                ))
            })?),
        ];

        let mut args = args
            .into_iter()
            .map(|arg| {
                ptb.input(arg).map_err(|e| {
                    IkaError::SuiConnectorSerializationError(format!("can't serialize `arg`: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let message_arg =
            Self::break_down_checkpoint_message_into_vector_arg(&mut ptb, message.clone());
        args.push(message_arg?);

        ptb.programmable_move_call(
            ika_system_package_id,
            SYSTEM_MODULE_NAME.into(),
            PROCESS_CHECKPOINT_MESSAGE_BY_QUORUM_FUNCTION_NAME.into(),
            vec![],
            args,
        );

        let transaction =
            super::build_sui_transaction(sui_notifier, ptb.finish(), sui_client, gas_coins).await;

        match Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await {
            Ok(_) => Ok(()),
            Err(err) => {
                error!(error=?err, "failed to submit a system checkpoint to consensus");
                metrics.system_checkpoint_writes_failure_total.inc();
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_read_backoff_doubles_then_caps_at_30s() {
        assert_eq!(verified_read_retry_backoff(1), Duration::from_secs(1));
        assert_eq!(verified_read_retry_backoff(2), Duration::from_secs(2));
        assert_eq!(verified_read_retry_backoff(3), Duration::from_secs(4));
        assert_eq!(verified_read_retry_backoff(4), Duration::from_secs(8));
        assert_eq!(verified_read_retry_backoff(5), Duration::from_secs(16));
        // 1<<5 == 32, capped to 30, and stays capped for all higher attempts.
        assert_eq!(verified_read_retry_backoff(6), Duration::from_secs(30));
        assert_eq!(verified_read_retry_backoff(1000), Duration::from_secs(30));
    }
}
