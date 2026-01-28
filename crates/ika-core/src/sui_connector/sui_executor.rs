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
use sui_types::base_types::{ObjectID, TransactionDigest};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{Argument, CallArg, Transaction};
use tokio::sync::watch;
use tokio::sync::watch::Sender;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};

#[derive(PartialEq, Eq, Debug)]
pub enum StopReason {
    EpochComplete(Box<SystemInner>, EpochStartSystem),
    RunWithRangeCondition,
}

const ONE_HOUR_IN_SECONDS: u64 = 60 * 60;

pub struct SuiExecutor<C> {
    system_object_sender: Sender<Option<(System, SystemInner)>>,
    dwallet_coordinator_object_sender:
        Sender<Option<(DWalletCoordinator, DWalletCoordinatorInner)>>,
    dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
    system_checkpoint_store: Arc<SystemCheckpointStore>,
    sui_notifier: Option<SuiNotifier>,
    sui_client: Arc<SuiClient<C>>,
    metrics: Arc<SuiConnectorMetrics>,
    notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
}

struct EpochSwitchState {
    ran_mid_epoch: bool,
    ran_lock_last_session: bool,
    ran_request_advance_epoch: bool,
    network_encryption_key_mid_epoch_reconfiguration: bool,
    calculated_protocol_pricing: bool,
}

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
        metrics: Arc<SuiConnectorMetrics>,
    ) -> Self {
        Self {
            system_object_sender,
            dwallet_coordinator_object_sender,
            dwallet_checkpoint_store,
            system_checkpoint_store,
            sui_notifier,
            sui_client,
            metrics,
            notifier_tx_lock: Arc::new(tokio::sync::Mutex::new(None)),
        }
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
        }
        let Ok((dwallet_coordinator, dwallet_coordinator_inner)) =
            self.sui_client.get_dwallet_coordinator_inner().await
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
            info!("Successfully locked last session in current epoch");
        }
        if coordinator_inner.received_end_of_publish
            && system_inner_v1.received_end_of_publish
            && !epoch_switch_state.ran_request_advance_epoch
        {
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

        loop {
            interval.tick().await;
            let (system, system_inner) = self.sui_client.must_get_system_inner_object().await;
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
                self.sui_client.must_get_dwallet_coordinator_inner().await;
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
                            info!(
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

                            info!(
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
                            info!(
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
                        .set(next_dwallet_checkpoint_sequence_number as i64);

                    let active_members: BlsCommittee =
                        system_inner.validator_set().clone().active_committee;
                    let auth_sig = system_checkpoint.auth_sig();
                    let signature = auth_sig.signature.as_bytes().to_vec();
                    let signers_bitmap =
                        Self::calculate_signers_bitmap(&auth_sig.signers_map, &active_members);
                    let message =
                        bcs::to_bytes::<SystemCheckpointMessage>(&system_checkpoint.into_message())
                            .expect("Serializing `system_checkpoint` message cannot fail");

                    info!("Signers_bitmap: {:?}", signers_bitmap);
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
                        .set(next_dwallet_checkpoint_sequence_number as i64);
                    last_submitted_system_checkpoint = Some(next_system_checkpoint_sequence_number);
                    info!(
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
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> anyhow::Result<SuiTransactionBlockResponse> {
        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;
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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn calculate_protocols_pricing(
        sui_client: &Arc<SuiClient<C>>,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
        default_pricing_keys: &[PricingInfoKey],
    ) -> anyhow::Result<SuiTransactionBlockResponse> {
        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;
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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn submit_tx_to_sui(
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
        transaction: Transaction,
        sui_client: &Arc<SuiClient<C>>,
    ) -> DwalletMPCResult<SuiTransactionBlockResponse> {
        let mut last_submitted_tx_digest = notifier_tx_lock.lock().await;
        if let Some(prev_digest) = *last_submitted_tx_digest {
            while sui_client
                .get_events_by_tx_digest(prev_digest)
                .await
                .is_err()
            {
                info!(
                    transaction_digest = ?prev_digest,
                    "The last submitted transaction has not been processed yet, retrying..."
                );
                // Small delay to avoid spamming the node.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            info!(
            transaction_digest = ?prev_digest,
            "The last submitted transaction has been processed, submitting the next one",
                        );
        }

        info!(
            transaction_digest = ?transaction.digest(),
            "Submitting a transaction to Sui"
        );

        let tx_response = sui_client
            .execute_transaction_block_with_effects(transaction)
            .await?;

        if !tx_response.errors.is_empty() {
            return Err(IkaError::SuiClientTxFailureGeneric(
                tx_response.digest,
                format!("{:?}", tx_response.errors),
            )
            .into());
        }

        let Some(tx_effects) = tx_response.effects.clone() else {
            return Err(IkaError::SuiClientTxFailureGeneric(
                tx_response.digest,
                "Transaction effects are missing".to_string(),
            )
            .into());
        };

        if let SuiExecutionStatus::Failure { error } = tx_effects.status() {
            return Err(IkaError::SuiClientTxFailureGeneric(
                tx_response.digest,
                format!(
                    "Transaction executed successfully, but it failed with an error: {error:?}",
                ),
            )
            .into());
        };

        *last_submitted_tx_digest = Some(tx_response.digest);
        Ok(tx_response)
    }

    async fn process_mid_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Running `process_mid_epoch()`");
        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;

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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn lock_last_session_to_complete_in_current_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Process `lock_last_active_session_sequence_number()`");
        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;

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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

        Ok(Self::submit_tx_to_sui(notifier_tx_lock, transaction, sui_client).await?)
    }

    async fn process_request_advance_epoch(
        ika_system_package_id: ObjectID,
        ika_dwallet_2pc_mpc_package_id: ObjectID,
        sui_notifier: &SuiNotifier,
        sui_client: &Arc<SuiClient<C>>,
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        info!("Running `process_request_advance_epoch()`");
        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;

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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

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
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        let mut ptb = ProgrammableTransactionBuilder::new();

        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        //merge_gas_coins(&mut ptb, &gas_coins)?;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;

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

        ptb.command(sui_types::transaction::Command::MergeCoins(
            Argument::GasCoin,
            vec![gas_fee_reimbursement_sui],
        ));

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

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
        notifier_tx_lock: Arc<tokio::sync::Mutex<Option<TransactionDigest>>>,
    ) -> IkaResult<()> {
        let mut ptb = ProgrammableTransactionBuilder::new();

        let gas_coins = sui_client.get_gas_objects(sui_notifier.sui_address).await;
        // merge_gas_coins(&mut ptb, &gas_coins)?;
        // let gas_coin = gas_coins
        //     .first()
        //     .ok_or_else(|| IkaError::SuiConnectorInternalError("no gas coin found".to_string()))?;

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

        let transaction = super::build_sui_transaction(
            sui_notifier.sui_address,
            ptb.finish(),
            sui_client,
            gas_coins,
            &sui_notifier.sui_key,
        )
        .await;

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
