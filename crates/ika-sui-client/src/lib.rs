// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::metrics::SuiClientMetrics;
use anyhow::anyhow;
use async_trait::async_trait;
use core::panic;
use dwallet_mpc_types::dwallet_mpc::VersionedMPCData;
use ika_types::error::{IkaError, IkaResult};
use ika_types::messages_consensus::MovePackageDigest;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData, IkaNetworkConfig,
    IkaObjectsConfig, IkaPackageConfig,
};
use ika_types::sui::epoch_start_system::{EpochStartSystem, EpochStartValidatorInfoV1};
use ika_types::sui::staking::StakingPool;
use ika_types::sui::system_inner_v1::{DWalletCoordinatorInnerV1, SystemInnerV1};
use ika_types::sui::{
    DWalletCoordinator, DWalletCoordinatorInner, PricingInfoKey, PricingInfoValue, System,
    SystemInner, SystemInnerTrait, Validator,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sui_json_rpc_types::{EventFilter, Page, SuiEvent};
use sui_json_rpc_types::{
    EventPage, SuiObjectDataOptions, SuiTransactionBlockResponse,
    SuiTransactionBlockResponseOptions,
};
use sui_json_rpc_types::{SuiData, SuiObjectDataFilter, SuiObjectResponseQuery};
use sui_sdk::error::Error;
use sui_sdk::{SuiClient as SuiSdkClient, SuiClientBuilder};
use sui_types::TypeTag;
use sui_types::base_types::{EpochId, ObjectRef};
use sui_types::clock::Clock;
use sui_types::collection_types::{Entry, Table};
use sui_types::dynamic_field::Field;
use sui_types::gas_coin::GasCoin;
use sui_types::object::Owner;
use sui_types::transaction::ObjectArg;
use sui_types::transaction::Transaction;
use sui_types::{
    Identifier,
    base_types::{ObjectID, SuiAddress},
    digests::TransactionDigest,
    event::EventID,
};
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};

#[cfg(feature = "protocol-commands")]
pub mod ika_protocol_transactions;
pub mod ika_validator_transactions;
pub mod metrics;

#[macro_export]
macro_rules! retry_with_max_elapsed_time {
    ($func:expr, $max_elapsed_time:expr) => {{
        // The following delay sequence (in secs) will be used, applied with jitter
        // 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6, 30, 60, 120, 120 ...
        let backoff = backoff::ExponentialBackoff {
            initial_interval: Duration::from_millis(400),
            randomization_factor: 0.1,
            multiplier: 2.0,
            max_interval: Duration::from_secs(120),
            max_elapsed_time: Some($max_elapsed_time),
            ..Default::default()
        };
        backoff::future::retry(backoff, || {
            let fut = async {
                let result = $func.await;
                match result {
                    Ok(_) => {
                        return Ok(result);
                    }
                    Err(err) => {
          // For simplicity we treat every error as transient so we can retry until max_elapsed_time
          warn!(error=?err, "retrying with max elapsed time");
                        return Err(backoff::Error::transient(err));
                    }
                }
            };
            std::boxed::Box::pin(fut)
        })
        .await
    }};
}

pub struct SuiClient<P> {
    inner: P,
    sui_client_metrics: Arc<SuiClientMetrics>,
    pub ika_network_config: IkaNetworkConfig,
}

pub type SuiConnectorClient = SuiClient<SuiSdkClient>;

impl SuiConnectorClient {
    pub async fn new(
        rpc_url: &str,
        sui_client_metrics: Arc<SuiClientMetrics>,
        ika_network_config: IkaNetworkConfig,
    ) -> anyhow::Result<Self> {
        let inner = SuiClientBuilder::default()
            .build(rpc_url)
            .await
            .map_err(|e| {
                anyhow!("Can't establish connection with Sui Rpc {rpc_url}. Error: {e}")
            })?;
        let self_ = Self {
            inner,
            sui_client_metrics,
            ika_network_config,
        };
        self_.describe().await?;
        Ok(self_)
    }

    pub fn sui_client(&self) -> &SuiSdkClient {
        &self.inner
    }
}

impl<P> SuiClient<P>
where
    P: SuiClientInner,
{
    pub async fn get_pricing_info(
        &self,
        coordinator_inner: DWalletCoordinatorInner,
    ) -> Vec<Entry<PricingInfoKey, PricingInfoValue>> {
        let DWalletCoordinatorInner::V1(coordinator_inner) = coordinator_inner;
        coordinator_inner
            .pricing_and_fee_management
            .current
            .pricing_map
            .contents
    }

    pub async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> anyhow::Result<Vec<SuiEvent>> {
        Ok(self.inner.get_events_by_tx_digest(tx_digest).await?)
    }

    /// Remaining sessions not processed during previous Epochs.
    pub async fn pull_dwallet_mpc_uncompleted_events(
        &self,
        coordinator_inner: &DWalletCoordinatorInner,
    ) -> IkaResult<(Vec<DBSuiEvent>, EpochId)> {
        let DWalletCoordinatorInner::V1(coordinator_inner) = coordinator_inner;
        let user_missed_events = self
            .inner
            .get_uncompleted_events(
                coordinator_inner
                    .sessions_manager
                    .user_sessions_keeper
                    .session_events
                    .id
                    .id
                    .bytes,
            )
            .await
            .map_err(|e| {
                error!("failed to get missed events: {e}");
                IkaError::SuiClientInternalError(format!("failed to get missed events: {e}"))
            })?;

        let system_missed_events = self
            .inner
            .get_uncompleted_events(
                coordinator_inner
                    .sessions_manager
                    .system_sessions_keeper
                    .session_events
                    .id
                    .id
                    .bytes,
            )
            .await
            .map_err(|e| {
                error!("failed to get missed events: {e}");
                IkaError::SuiClientInternalError(format!("failed to get missed events: {e}"))
            })?;

        if !user_missed_events.is_empty() || !system_missed_events.is_empty() {
            info!(
                number_of_user_missed_events = user_missed_events.len(),
                number_of_system_missed_events = system_missed_events.len(),
                "retrieved missed events from Sui successfully"
            );
        } else {
            debug!("retrieved zero missed events from Sui");
        }

        Ok((
            user_missed_events
                .into_iter()
                .chain(system_missed_events.into_iter())
                .collect(),
            coordinator_inner.current_epoch,
        ))
    }

    pub fn new_for_testing(inner: P) -> Self {
        // TODO(omersadika) fix that random
        let ika_network_config = IkaNetworkConfig {
            packages: IkaPackageConfig {
                ika_package_id: ObjectID::random(),
                ika_common_package_id: ObjectID::random(),
                ika_dwallet_2pc_mpc_package_id: ObjectID::random(),
                ika_dwallet_2pc_mpc_package_id_v2: None,
                ika_system_package_id: ObjectID::random(),
            },
            objects: IkaObjectsConfig {
                ika_system_object_id: ObjectID::random(),
                ika_dwallet_coordinator_object_id: ObjectID::random(),
            },
        };

        Self {
            inner,
            sui_client_metrics: SuiClientMetrics::new_for_testing(),
            ika_network_config,
        }
    }

    // TODO assert chain identifier
    async fn describe(&self) -> anyhow::Result<()> {
        let chain_id = self.inner.get_chain_identifier().await?;
        let checkpoint_sequence_number = self.inner.get_latest_checkpoint_sequence_number().await?;
        tracing::info!(
            "SuiClient is connected to chain {chain_id}, current checkpoint sequence number: {checkpoint_sequence_number}"
        );
        Ok(())
    }

    pub async fn get_dwallet_coordinator_inner(
        &self,
    ) -> IkaResult<(DWalletCoordinator, DWalletCoordinatorInner)> {
        let result = self
            .inner
            .get_dwallet_coordinator(
                self.ika_network_config
                    .objects
                    .ika_dwallet_coordinator_object_id,
            )
            .await
            .map_err(|e| IkaError::SuiClientInternalError(format!("Can't get Coordinator: {e}")))?;
        let wrapper = bcs::from_bytes::<DWalletCoordinator>(&result).map_err(|e| {
            IkaError::SuiClientSerializationError(format!("Can't serialize Coordinator: {e}"))
        })?;

        match wrapper.version {
            1 | 2 => {
                let result = self
                    .inner
                    .get_dwallet_coordinator_inner(
                        self.ika_network_config
                            .objects
                            .ika_dwallet_coordinator_object_id,
                        wrapper.version,
                    )
                    .await
                    .map_err(|e| {
                        IkaError::SuiClientInternalError(format!(
                            "Can't get DWalletCoordinatorInner v1: {e}"
                        ))
                    })?;
                let dynamic_field_inner = bcs::from_bytes::<Field<u64, DWalletCoordinatorInnerV1>>(
                    &result,
                )
                .map_err(|e| {
                    IkaError::SuiClientSerializationError(format!(
                        "Can't serialize DWalletCoordinatorInner v1: {e}"
                    ))
                })?;
                let ika_system_state_inner = dynamic_field_inner.value;

                Ok((wrapper, DWalletCoordinatorInner::V1(ika_system_state_inner)))
            }
            _ => Err(IkaError::SuiClientInternalError(format!(
                "Unsupported DWalletCoordinatorInner version: {}",
                wrapper.version
            ))),
        }
    }

    pub async fn get_system_inner(&self) -> IkaResult<(System, SystemInner)> {
        let result = self
            .inner
            .get_system(self.ika_network_config.objects.ika_system_object_id)
            .await
            .map_err(|e| IkaError::SuiClientInternalError(format!("Can't get System: {e}")))?;
        let wrapper = bcs::from_bytes::<System>(&result).map_err(|e| {
            IkaError::SuiClientSerializationError(format!("Can't serialize System: {e}"))
        })?;

        match wrapper.version {
            1 | 2 => {
                let result = self
                    .inner
                    .get_system_inner(
                        self.ika_network_config.objects.ika_system_object_id,
                        wrapper.version,
                    )
                    .await
                    .map_err(|e| {
                        IkaError::SuiClientInternalError(format!("Can't get SystemInner v1: {e}"))
                    })?;
                let dynamic_field_inner = bcs::from_bytes::<Field<u64, SystemInnerV1>>(&result)
                    .map_err(|e| {
                        IkaError::SuiClientSerializationError(format!(
                            "Can't serialize SystemInner v1: {e}"
                        ))
                    })?;
                let ika_system_state_inner = dynamic_field_inner.value;

                Ok((wrapper, SystemInner::V1(ika_system_state_inner)))
            }
            _ => Err(IkaError::SuiClientInternalError(format!(
                "Unsupported SystemInner version: {}",
                wrapper.version
            ))),
        }
    }

    /// Retrieves Sui's System clock object.
    pub async fn get_clock(&self) -> IkaResult<Clock> {
        let sui_clock_address = "0x6";
        let result = self
            .inner
            .get_clock(ObjectID::from_hex_literal(sui_clock_address).unwrap())
            .await
            .map_err(|e| {
                IkaError::SuiClientInternalError(format!(
                    "Can't get the System clock from Sui: {e}"
                ))
            })?;
        bcs::from_bytes::<Clock>(&result).map_err(|e| {
            IkaError::SuiClientSerializationError(format!(
                "Can't deserialize Sui System clock: {e}"
            ))
        })
    }

    pub async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_mpc_data: bool,
    ) -> IkaResult<HashMap<ObjectID, VersionedMPCData>> {
        self.inner
            .get_mpc_data_from_validators_pool(validators, read_next_mpc_data)
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_mpc_data_from_validators_pool"])
                    .inc();
                IkaError::SuiClientInternalError(format!(
                    "Can't get_mpc_data_from_validators_pool: {e}"
                ))
            })
    }

    pub async fn get_epoch_start_system(
        &self,
        ika_system_state_inner: &SystemInner,
    ) -> IkaResult<EpochStartSystem> {
        match ika_system_state_inner {
            SystemInner::V1(ika_system_state_inner) => {
                let validator_ids = ika_system_state_inner
                    .validator_set
                    .active_committee
                    .members
                    .iter()
                    .map(|m| m.validator_id)
                    .collect::<Vec<_>>();

                let validators = self
                    .inner
                    .get_validators(validator_ids)
                    .await
                    .map_err(|e| {
                        self.sui_client_metrics
                            .sui_rpc_errors
                            .with_label_values(&["get_epoch_start_system"])
                            .inc();
                        IkaError::SuiClientInternalError(format!(
                            "Can't get_validators_from_object_table: {e}"
                        ))
                    })?;
                let validators = validators
                    .iter()
                    .map(|v| {
                        bcs::from_bytes::<StakingPool>(v).map_err(|e| {
                            self.sui_client_metrics
                                .sui_rpc_errors
                                .with_label_values(&["get_epoch_start_system"])
                                .inc();
                            IkaError::SuiClientSerializationError(format!(
                                "Can't serialize StakingPool: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let validators_mpc_data = self
                    .inner
                    .get_mpc_data_from_validators_pool(&validators, false)
                    .await
                    .map_err(|e| {
                        self.sui_client_metrics
                            .sui_rpc_errors
                            .with_label_values(&["get_epoch_start_system"])
                            .inc();
                        IkaError::SuiClientInternalError(format!(
                            "can't get_mpc_data_from_validators_pool: {e}"
                        ))
                    })?;

                let validators = ika_system_state_inner
                    .validator_set
                    .active_committee
                    .members
                    .iter()
                    .map(|m| {
                        let validator = validators
                            .iter()
                            .find(|v| v.id == m.validator_id)
                            .ok_or_else(|| {
                                self.sui_client_metrics
                                    .sui_rpc_errors
                                    .with_label_values(&["get_epoch_start_system"])
                                    .inc();
                                IkaError::InvalidCommittee(format!(
                                    "Validator with ID {} not found in the active committee",
                                    m.validator_id
                                ))
                            })?;
                        let info = validator.verified_validator_info();
                        Ok(EpochStartValidatorInfoV1 {
                            name: info.name.clone(),
                            validator_id: validator.id,
                            protocol_pubkey: info.protocol_pubkey.clone(),
                            network_pubkey: info.network_pubkey.clone(),
                            consensus_pubkey: info.consensus_pubkey.clone(),
                            mpc_data: validators_mpc_data.get(&validator.id).cloned(),
                            network_address: info.network_address.clone(),
                            p2p_address: info.p2p_address.clone(),
                            consensus_address: info.consensus_address.clone(),
                            voting_power: 1,
                            hostname: info.name.clone(),
                        })
                    })
                    .collect::<IkaResult<Vec<_>>>()?;

                let epoch_start_system_state = EpochStartSystem::new_v1(
                    ika_system_state_inner.epoch,
                    ika_system_state_inner.protocol_version,
                    ika_system_state_inner.epoch_start_timestamp_ms,
                    ika_system_state_inner.epoch_duration_ms(),
                    validators,
                    ika_system_state_inner
                        .validator_set
                        .active_committee
                        .quorum_threshold,
                    ika_system_state_inner
                        .validator_set
                        .active_committee
                        .validity_threshold,
                );

                Ok(epoch_start_system_state)
            }
        }
    }

    /// Get the validators' info by their IDs.
    pub async fn get_validators_info_by_ids(
        &self,
        validator_ids: Vec<ObjectID>,
    ) -> Result<Vec<StakingPool>, IkaError> {
        let validators = self
            .inner
            .get_validators(validator_ids)
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_validators_info_by_ids"])
                    .inc();
                IkaError::SuiClientInternalError(format!(
                    "failure in `get_validators_from_object_table()`: {e}"
                ))
            })?;
        validators
            .iter()
            .map(|v| {
                bcs::from_bytes::<StakingPool>(v).map_err(|e| {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["get_validators_info_by_ids"])
                        .inc();
                    IkaError::SuiClientSerializationError(format!(
                        "failed to de-serialize Validator info: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Get the mutable system object arg on chain.
    // We retry a few times in case of errors. If it fails eventually, we panic.
    // In general it's safe to call in the beginning of the program.
    // After the first call, the result is cached since the value should never change.
    pub async fn get_mutable_system_arg_must_succeed(&self) -> ObjectArg {
        static ARG: OnceCell<ObjectArg> = OnceCell::const_new();
        *ARG.get_or_init(|| async move {
            let Ok(Ok(system_arg)) = retry_with_max_elapsed_time!(
                self.inner
                    .get_mutable_shared_arg(self.ika_network_config.objects.ika_system_object_id),
                Duration::from_secs(30)
            ) else {
                panic!("Failed to get system object arg after retries");
            };
            system_arg
        })
        .await
    }

    /// Get the clock object arg for the shared system object on the chain.
    pub async fn get_clock_arg_must_succeed(&self) -> ObjectArg {
        static ARG: OnceCell<ObjectArg> = OnceCell::const_new();
        *ARG.get_or_init(|| async move {
            let Ok(Ok(system_arg)) = retry_with_max_elapsed_time!(
                self.inner.get_shared_arg(ObjectID::from_single_byte(6)),
                Duration::from_secs(30)
            ) else {
                panic!("failed to get system object arg after retries");
            };
            system_arg
        })
        .await
    }

    /// Retrieves the dwallet_2pc_mpc_coordinator_id object arg from the Sui chain.
    pub async fn get_mutable_dwallet_2pc_mpc_coordinator_arg_must_succeed(&self) -> ObjectArg {
        static ARG: OnceCell<ObjectArg> = OnceCell::const_new();
        *ARG.get_or_init(|| async move {
            let Ok(Ok(system_arg)) = retry_with_max_elapsed_time!(
                self.inner.get_mutable_shared_arg(
                    self.ika_network_config
                        .objects
                        .ika_dwallet_coordinator_object_id
                ),
                Duration::from_secs(30)
            ) else {
                panic!("Failed to get dwallet_2pc_mpc_coordinator_id object arg after retries");
            };
            system_arg
        })
        .await
    }

    pub async fn get_available_move_packages(
        &self,
    ) -> IkaResult<Vec<(ObjectID, MovePackageDigest)>> {
        self.inner
            .get_available_move_packages(
                self.ika_network_config.packages.ika_package_id,
                self.ika_network_config.packages.ika_system_package_id,
            )
            .await
            .map_err(|e| {
                IkaError::SuiClientInternalError(format!("Can't get_available_move_packages: {e}"))
            })
    }

    /// Query emitted Events that are defined in the given Move Module.
    pub async fn query_events_by_module(
        &self,
        module: Identifier,
        package_id: ObjectID,
        // cursor is exclusive
        cursor: Option<EventID>,
    ) -> IkaResult<Page<SuiEvent, EventID>> {
        let filter = EventFilter::MoveEventModule {
            package: package_id,
            module: module.clone(),
        };
        let events = self
            .inner
            .query_events(filter.clone(), cursor)
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["query_events_by_module"])
                    .inc();
                IkaError::SuiClientInternalError(format!("Can't query_events: {e}"))
            })?;

        // Safeguard check that all events are emitted from requested package and module
        assert!(events.data.iter().all(|event| {
            event.type_.address.as_ref() == package_id.as_ref() && event.type_.module == module
        }));
        Ok(events)
    }

    pub async fn get_chain_identifier(&self) -> IkaResult<String> {
        self.inner.get_chain_identifier().await.map_err(|e| {
            self.sui_client_metrics
                .sui_rpc_errors
                .with_label_values(&["get_validators_info_by_ids"])
                .inc();
            IkaError::SuiClientInternalError(format!("Can't get_chain_identifier: {e}"))
        })
    }

    pub async fn get_reference_gas_price_until_success(&self) -> u64 {
        loop {
            let Ok(Ok(rgp)) = retry_with_max_elapsed_time!(
                self.inner.get_reference_gas_price(),
                Duration::from_secs(30)
            ) else {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_reference_gas_price_until_success"])
                    .inc();
                error!("Failed to get gas price per unit size");
                continue;
            };
            return rgp;
        }
    }

    pub async fn get_latest_checkpoint_sequence_number(&self) -> IkaResult<u64> {
        self.inner
            .get_latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_latest_checkpoint_sequence_number"])
                    .inc();
                IkaError::SuiClientInternalError(format!(
                    "Can't get_latest_checkpoint_sequence_number: {e}"
                ))
            })
    }

    pub async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> IkaResult<SuiTransactionBlockResponse> {
        self.inner.execute_transaction_block_with_effects(tx).await
    }

    pub async fn must_get_system_inner_object(&self) -> (System, SystemInner) {
        loop {
            match retry_with_max_elapsed_time!(self.get_system_inner(), Duration::from_secs(30)) {
                Ok(Ok(ika_system_state)) => return ika_system_state,
                Ok(Err(err)) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_system_inner_object"])
                        .inc();
                    warn!(
                        error=?err,
                        "Received error from `get_system_inner()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_system_inner_object"])
                        .inc();
                    warn!(
                        error=?err,
                        system_object_id=%self.ika_network_config.objects.ika_system_object_id,
                        "failed to get ika system inner object",
                    );
                }
            }
        }
    }

    pub async fn get_dwallet_mpc_network_keys(
        &self,
        coordinator_inner: &DWalletCoordinatorInner,
    ) -> IkaResult<HashMap<ObjectID, DWalletNetworkEncryptionKey>> {
        let DWalletCoordinatorInner::V1(coordinator_inner) = coordinator_inner;
        self.inner
            .get_network_encryption_keys(coordinator_inner)
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_dwallet_mpc_network_keys"])
                    .inc();
                IkaError::SuiClientInternalError(format!("can't get_network_encryption_keys: {e}"))
            })
    }

    pub async fn get_network_encryption_key_with_full_data_by_epoch(
        &self,
        network_decryption_key: &DWalletNetworkEncryptionKey,
        epoch: EpochId,
    ) -> IkaResult<DWalletNetworkEncryptionKeyData> {
        self.inner
            .get_network_encryption_key_with_full_data_by_epoch(network_decryption_key, epoch)
            .await
            .map_err(|e| {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_network_encryption_key_with_full_data_by_epoch"])
                    .inc();
                IkaError::SuiClientInternalError(format!(
                    "Can't get_network_encryption_key_with_full_data_by_epoch: {e}"
                ))
            })
    }

    pub async fn must_get_dwallet_coordinator_inner(
        &self,
    ) -> (DWalletCoordinator, DWalletCoordinatorInner) {
        loop {
            match retry_with_max_elapsed_time!(
                self.get_dwallet_coordinator_inner(),
                Duration::from_secs(30)
            ) {
                Ok(Ok(ika_system_state)) => return ika_system_state,
                Ok(Err(err)) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_dwallet_coordinator_inner"])
                        .inc();
                    warn!(
                        error=?err,
                        "Received error from `get_dwallet_coordinator_inner()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_dwallet_coordinator_inner"])
                        .inc();
                    warn!(
                        error=?err,
                        system_object_id=%self.ika_network_config.objects.ika_system_object_id,
                        "Failed to get dwallet coordinator inner object",
                    );
                }
            }
        }
    }

    pub async fn must_get_epoch_start_system(
        &self,
        system_inner: &SystemInner,
    ) -> EpochStartSystem {
        loop {
            match retry_with_max_elapsed_time!(
                self.get_epoch_start_system(system_inner),
                Duration::from_secs(30)
            ) {
                Ok(Ok(ika_system_state)) => return ika_system_state,
                Ok(Err(err)) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_epoch_start_system"])
                        .inc();
                    warn!(
                        error=?err,
                        "Received error from `get_epoch_start_system()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .sui_rpc_errors
                        .with_label_values(&["must_get_epoch_start_system"])
                        .inc();
                    warn!(
                        error=?err,
                        "Received error from `get_epoch_start_system` retry wrapper. Retrying...",
                    );
                }
            }
        }
    }

    pub async fn get_gas_objects(&self, address: SuiAddress) -> Vec<ObjectRef> {
        self.inner.get_gas_objects(address).await
    }
}

/// Use a trait to abstract over the SuiSDKClient and SuiMockClient for testing.
#[async_trait]
pub trait SuiClientInner: Send + Sync {
    type Error: Into<anyhow::Error> + Send + Sync + std::error::Error + 'static;
    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error>;

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<SuiEvent>, Self::Error>;

    async fn get_chain_identifier(&self) -> Result<String, Self::Error>;

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error>;

    async fn get_latest_checkpoint_sequence_number(&self) -> Result<u64, Self::Error>;

    async fn get_system(&self, ika_system_object_id: ObjectID) -> Result<Vec<u8>, Self::Error>;

    async fn get_clock(&self, clock_obj_id: ObjectID) -> Result<Vec<u8>, Self::Error>;

    async fn get_dwallet_coordinator(
        &self,
        dwallet_coordinator_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error>;

    #[allow(clippy::ptr_arg)]
    async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_epoch_mpc_data: bool,
    ) -> Result<HashMap<ObjectID, VersionedMPCData>, self::Error>;

    #[allow(clippy::ptr_arg)]
    async fn get_network_encryption_keys(
        &self,
        dwallet_coordinator_inner: &DWalletCoordinatorInnerV1,
    ) -> Result<HashMap<ObjectID, DWalletNetworkEncryptionKey>, self::Error>;

    async fn get_network_encryption_key_with_full_data_by_epoch(
        &self,
        network_decryption_key: &DWalletNetworkEncryptionKey,
        epoch: EpochId,
    ) -> Result<DWalletNetworkEncryptionKeyData, self::Error>;

    async fn get_current_reconfiguration_public_output(
        &self,
        epoch_id: EpochId,
        table_id: ObjectID,
    ) -> Result<ObjectID, Self::Error>;

    async fn read_table_vec_as_raw_bytes(&self, table_id: ObjectID)
    -> Result<Vec<u8>, self::Error>;

    async fn get_system_inner(
        &self,
        ika_system_object_id: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, Self::Error>;

    async fn get_dwallet_coordinator_inner(
        &self,
        dwallet_coordinator_id: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, Self::Error>;

    async fn get_validators(
        &self,
        validator_ids: Vec<ObjectID>,
    ) -> Result<Vec<Vec<u8>>, Self::Error>;

    async fn get_validator_inners(
        &self,
        validators: Vec<Validator>,
    ) -> Result<Vec<Vec<u8>>, Self::Error>;

    async fn get_mutable_shared_arg(
        &self,
        ika_system_object_id: ObjectID,
    ) -> Result<ObjectArg, Self::Error>;

    async fn get_shared_arg(&self, obj_id: ObjectID) -> Result<ObjectArg, Self::Error>;

    async fn get_available_move_packages(
        &self,
        //chain: sui_protocol_config::Chain,
        ika_package_id: ObjectID,
        ika_system_package_id: ObjectID,
    ) -> Result<Vec<(ObjectID, MovePackageDigest)>, Self::Error>;

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<SuiTransactionBlockResponse, IkaError>;

    async fn get_gas_objects(&self, address: SuiAddress) -> Vec<ObjectRef>;

    /// Fetch events for which no output was received (weren't completed.)
    /// Completed events are removed from the SessionManagement in Move,
    /// so querying all the values assures we query uncompleted events exclusively.
    async fn get_uncompleted_events(
        &self,
        events_bag_id: ObjectID,
    ) -> Result<Vec<DBSuiEvent>, self::Error>;
}

#[async_trait]
impl SuiClientInner for SuiSdkClient {
    type Error = sui_sdk::error::Error;

    async fn query_events(
        &self,
        query: EventFilter,
        cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error> {
        self.event_api()
            .query_events(query, cursor, None, false)
            .await
    }

    async fn get_events_by_tx_digest(
        &self,
        tx_digest: TransactionDigest,
    ) -> Result<Vec<SuiEvent>, Self::Error> {
        self.event_api().get_events(tx_digest).await
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
        self.read_api().get_chain_identifier().await
    }

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
        self.governance_api().get_reference_gas_price().await
    }

    async fn get_latest_checkpoint_sequence_number(&self) -> Result<u64, Self::Error> {
        self.read_api()
            .get_latest_checkpoint_sequence_number()
            .await
    }

    async fn get_system(&self, ika_system_object_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
        self.read_api()
            .get_move_object_bcs(ika_system_object_id)
            .await
    }

    async fn get_clock(&self, clock_obj_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
        self.read_api().get_move_object_bcs(clock_obj_id).await
    }

    async fn get_dwallet_coordinator(
        &self,
        dwallet_coordinator_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error> {
        self.read_api()
            .get_move_object_bcs(dwallet_coordinator_id)
            .await
    }

    /// Fetch events for which no output was received (weren't completed.)
    async fn get_uncompleted_events(
        &self,
        coordinator_events_bag_id: ObjectID,
    ) -> Result<Vec<DBSuiEvent>, self::Error> {
        let mut events = vec![];
        let mut next_cursor = None;
        loop {
            let dynamic_fields = self
                .read_api()
                .get_dynamic_fields(coordinator_events_bag_id, next_cursor, None)
                .await?;
            for df in dynamic_fields.data.iter() {
                let object_id = df.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                let move_object = resp.bcs.ok_or(Error::DataError(format!(
                    "object {object_id:?} has no bcs data"
                )))?;
                let raw_move_obj = move_object.try_into_move().ok_or(Error::DataError(format!(
                    "object {object_id:?} is not a MoveObject"
                )))?;

                let Some(TypeTag::Struct(event_tag)) = raw_move_obj.type_.type_params.get(1) else {
                    continue;
                };
                let event = DBSuiEvent {
                    type_: *event_tag.clone(),
                    contents: raw_move_obj.bcs_bytes,
                    pulled: true,
                };
                events.push(event);
            }
            if !dynamic_fields.has_next_page {
                break;
            }
            next_cursor = dynamic_fields.next_cursor;
        }

        Ok(events)
    }

    async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_mpc_data: bool,
    ) -> Result<HashMap<ObjectID, VersionedMPCData>, self::Error> {
        let mut mpc_data_from_all_validators: HashMap<ObjectID, VersionedMPCData> = HashMap::new();
        for validator in validators {
            let info = validator.verified_validator_info();
            let mpc_data_id = if read_next_mpc_data
                && let Some(next_epoch_mpc_data_bytes) = info.next_epoch_mpc_data_bytes.as_ref()
                && info.previous_mpc_data_bytes.is_none()
            {
                next_epoch_mpc_data_bytes.contents.id
            } else {
                if info.next_epoch_mpc_data_bytes.is_some()
                    && info.previous_mpc_data_bytes.is_some()
                {
                    error!(
                        should_never_happen=true,
                        validator_id=?validator.id,
                        "Validator can't have both previous and next epoch MPC data bytes, using current data from epoch",
                    );
                }

                info.mpc_data_bytes.contents.id
            };

            let mpc_data_bytes = self.read_table_vec_as_raw_bytes(mpc_data_id).await?;

            let validator_mpc_data: bcs::Result<VersionedMPCData> =
                bcs::from_bytes(&mpc_data_bytes);

            match validator_mpc_data {
                Ok(validator_mpc_data) => {
                    mpc_data_from_all_validators.insert(validator.id, validator_mpc_data);
                }
                Err(e) => {
                    error!(
                        validator_id=?validator.id,
                        error=?e,
                        "Failed to deserialize MPC data for a validator"
                    );
                    continue;
                }
            }
        }
        Ok(mpc_data_from_all_validators)
    }

    async fn get_network_encryption_keys(
        &self,
        dwallet_coordinator_inner: &DWalletCoordinatorInnerV1,
    ) -> Result<HashMap<ObjectID, DWalletNetworkEncryptionKey>, self::Error> {
        let mut network_encryption_keys = HashMap::new();

        let mut cursor = None;
        loop {
            let dynamic_fields = self
                .read_api()
                .get_dynamic_fields(dwallet_coordinator_inner.dwallet_network_encryption_keys.id, cursor, None)
                .await
                .map_err(|e| {
                    Error::DataError(format!(
                        "can't get dynamic fields of `dwallet_coordinator_inner.dwallet_network_encryption_keys` table {:?}: {:?}",
                        dwallet_coordinator_inner.dwallet_network_encryption_keys.id, e
                    ))
                })?;
            let object_ids: Vec<ObjectID> =
                dynamic_fields.data.iter().map(|df| df.object_id).collect();
            let objects = self
                .read_api()
                .multi_get_object_with_options(object_ids, SuiObjectDataOptions::bcs_lossless())
                .await?;

            for resp in objects {
                if let Some(data) = resp.data {
                    let object_id = data.object_id;
                    let raw_data = data.bcs.ok_or(Error::DataError(format!(
                        "object {object_id:?} has no bcs data"
                    )))?;
                    let raw_move_obj = raw_data.try_into_move().ok_or(Error::DataError(
                        format!("object {object_id:?} is not a MoveObject"),
                    ))?;
                    let value =
                        bcs::from_bytes::<DWalletNetworkEncryptionKey>(&raw_move_obj.bcs_bytes)?;
                    network_encryption_keys.insert(object_id, value);
                }
            }

            cursor = dynamic_fields.next_cursor;
            if !dynamic_fields.has_next_page {
                break;
            }
        }
        Ok(network_encryption_keys)
    }

    async fn get_network_encryption_key_with_full_data_by_epoch(
        &self,
        key: &DWalletNetworkEncryptionKey,
        epoch: EpochId,
    ) -> Result<DWalletNetworkEncryptionKeyData, self::Error> {
        let network_dkg_public_output = self
            .read_table_vec_as_raw_bytes(key.network_dkg_public_output.contents.id)
            .await?;

        let mut current_reconfiguration_public_output = vec![];

        // Note that if we try to read the reconfiguration public output during the first epoch,
        // where we only had NetworkDKG, `get_current_reconfiguration_public_output()` function will error.
        // In this case, the validator will be stuck in a loop where it can't process events
        // until the epoch is switched, since it will be endlessly waiting for the network key.
        if key.dkg_at_epoch == epoch {
            info!(
                key_id = ?key.id,
                ?epoch,
                "Network encryption key created at current epoch, getting key data from DKG output",
            );
        } else {
            let current_reconfiguration_public_output_id = self
                .get_current_reconfiguration_public_output(
                    epoch,
                    key.reconfiguration_public_outputs.id,
                )
                .await?;
            current_reconfiguration_public_output = self
                .read_table_vec_as_raw_bytes(current_reconfiguration_public_output_id)
                .await?;
        };

        Ok(DWalletNetworkEncryptionKeyData {
            id: key.id,
            current_epoch: epoch,
            dkg_at_epoch: key.dkg_at_epoch,
            current_reconfiguration_public_output,
            network_dkg_public_output,
            state: key.state.clone(),
        })
    }

    async fn get_current_reconfiguration_public_output(
        &self,
        epoch_id: EpochId,
        table_id: ObjectID,
    ) -> Result<ObjectID, Self::Error> {
        let mut cursor = None;
        loop {
            let dynamic_fields = self
                .read_api()
                .get_dynamic_fields(table_id, cursor, None)
                .await
                .map_err(|e| {
                    Error::DataError(format!(
                        "can't get dynamic fields of table {table_id:?}: {e:?}"
                    ))
                })?;

            for df in dynamic_fields.data.iter() {
                let object_id = df.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                let raw_data = resp.bcs.ok_or(Error::DataError(format!(
                    "object {object_id:?} has no bcs data"
                )))?;
                let raw_move_obj = raw_data.try_into_move().ok_or(Error::DataError(format!(
                    "object {object_id:?} is not a MoveObject"
                )))?;
                let reconfig_public_output =
                    bcs::from_bytes::<Field<u64, Table>>(&raw_move_obj.bcs_bytes)?;
                if reconfig_public_output.name == epoch_id {
                    return Ok(reconfig_public_output.value.id);
                }
            }

            cursor = dynamic_fields.next_cursor;
            if !dynamic_fields.has_next_page {
                break;
            }
        }
        Err(Error::DataError(format!(
            "failed to load current reconfiguration public output for epoch {epoch_id:?} from table {table_id:?}"
        )))
    }

    async fn read_table_vec_as_raw_bytes(
        &self,
        table_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut full_output: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut cursor = None;
        loop {
            let dynamic_fields = self
                .read_api()
                .get_dynamic_fields(table_id, cursor, None)
                .await
                .map_err(|e| {
                    Error::DataError(format!(
                        "can't get dynamic fields of table {table_id:?}: {e:?}"
                    ))
                })?;

            for df in dynamic_fields.data.iter() {
                let object_id = df.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                let raw_data = resp.bcs.ok_or(Error::DataError(format!(
                    "object {object_id:?} has no bcs data"
                )))?;
                let raw_move_obj = raw_data.try_into_move().ok_or(Error::DataError(format!(
                    "object {object_id:?} is not a MoveObject"
                )))?;
                let bytes_chunk = bcs::from_bytes::<Field<u64, Vec<u8>>>(&raw_move_obj.bcs_bytes)?;
                full_output.insert(bytes_chunk.name as usize, bytes_chunk.value.clone());
            }

            cursor = dynamic_fields.next_cursor;
            if !dynamic_fields.has_next_page {
                break;
            }
        }

        Ok(full_output
            .into_iter()
            .sorted()
            .fold(Vec::new(), |mut acc, (_, mut v)| {
                acc.append(&mut v);
                acc
            }))
    }

    async fn get_system_inner(
        &self,
        ika_system_object_id: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let dynamic_fields = self
            .read_api()
            .get_dynamic_fields(ika_system_object_id, None, None)
            .await?;
        let dynamic_field = dynamic_fields.data.iter().find(|df| {
            df.name.type_ == TypeTag::U64
                && df
                    .name
                    .value
                    .as_str()
                    .map(|v| v == version.to_string().as_str())
                    .unwrap_or(false)
        });
        if let Some(dynamic_field) = dynamic_field {
            let result = self
                .read_api()
                .get_dynamic_field_object(ika_system_object_id, dynamic_field.name.clone())
                .await?;

            if let Some(dynamic_field) = result.data {
                let object_id = dynamic_field.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("Can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                // unwrap: requested bcs data
                let move_object = resp.bcs.unwrap();
                let raw_move_obj = move_object.try_into_move().ok_or(Error::DataError(format!(
                    "Object {object_id:?} is not a MoveObject"
                )))?;
                return Ok(raw_move_obj.bcs_bytes);
            }
        }
        Err(Error::DataError(format!(
            "Failed to load ika system state inner object with ID {ika_system_object_id:?} and version {version:?}"
        )))
    }

    async fn get_dwallet_coordinator_inner(
        &self,
        dwallet_coordinator_id: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let dynamic_fields = self
            .read_api()
            .get_dynamic_fields(dwallet_coordinator_id, None, None)
            .await?;
        let dynamic_field = dynamic_fields.data.iter().find(|df| {
            df.name.type_ == TypeTag::U64
                && df
                    .name
                    .value
                    .as_str()
                    .map(|v| v == version.to_string().as_str())
                    .unwrap_or(false)
        });
        if let Some(dynamic_field) = dynamic_field {
            let result = self
                .read_api()
                .get_dynamic_field_object(dwallet_coordinator_id, dynamic_field.name.clone())
                .await?;

            if let Some(dynamic_field) = result.data {
                let object_id = dynamic_field.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("Can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                // unwrap: requested bcs data
                let move_object = resp.bcs.unwrap();
                let raw_move_obj = move_object.try_into_move().ok_or(Error::DataError(format!(
                    "Object {object_id:?} is not a MoveObject"
                )))?;
                return Ok(raw_move_obj.bcs_bytes);
            }
        }
        Err(Error::DataError(format!(
            "Failed to load DWalletCoordinatorInner object with ID {dwallet_coordinator_id:?} and version {version:?}"
        )))
    }

    async fn get_validators(
        &self,
        validator_ids: Vec<ObjectID>,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let mut dynamic_fields_agg = Vec::new();
        // There is a limit in sui called "DEFAULT_RPC_QUERY_MAX_RESULT_LIMIT" which is set to 50.
        for chunk in validator_ids.chunks(50) {
            let objects = self
                .read_api()
                .multi_get_object_with_options(chunk.to_vec(), SuiObjectDataOptions::bcs_lossless())
                .await?;

            dynamic_fields_agg.extend(objects);
        }

        let mut validators = Vec::new();
        for (dynamic_field, object_id) in dynamic_fields_agg.iter().zip(validator_ids.iter()) {
            let resp = dynamic_field.object().map_err(|e| {
                Error::DataError(format!("Can't get bcs of object {object_id:?}: {e:?}"))
            })?;
            // unwrap: requested bcs data
            let move_object = resp.bcs.as_ref().unwrap();
            let raw_move_obj =
                move_object
                    .clone()
                    .try_into_move()
                    .ok_or(Error::DataError(format!(
                        "Object {object_id:?} is not a MoveObject"
                    )))?;
            validators.push(raw_move_obj.bcs_bytes);
        }
        Ok(validators)
    }

    async fn get_validator_inners(
        &self,
        validators: Vec<Validator>,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let mut validator_inners = Vec::new();

        for validator in validators {
            let dynamic_fields = self
                .read_api()
                .get_dynamic_fields(validator.inner.id.id.bytes, None, None)
                .await?;

            let dynamic_field = dynamic_fields.data.iter().find(|df| {
                df.name.type_ == TypeTag::U64
                    && df
                        .name
                        .value
                        .as_str()
                        .map(|v| v == validator.inner.version.to_string().as_str())
                        .unwrap_or(false)
            });

            if let Some(dynamic_field) = dynamic_field {
                let object_id = dynamic_field.object_id;
                let dynamic_field_response = self
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless())
                    .await?;
                let resp = dynamic_field_response.into_object().map_err(|e| {
                    Error::DataError(format!("Can't get bcs of object {object_id:?}: {e:?}"))
                })?;
                // unwrap: requested bcs data
                let move_object = resp.bcs.unwrap();
                let raw_move_obj = move_object.try_into_move().ok_or(Error::DataError(format!(
                    "Object {object_id:?} is not a MoveObject"
                )))?;
                validator_inners.push(raw_move_obj.bcs_bytes);
            }
        }
        Ok(validator_inners)
    }

    async fn get_mutable_shared_arg(
        &self,
        ika_system_object_id: ObjectID,
    ) -> Result<ObjectArg, Self::Error> {
        let response = self
            .read_api()
            .get_object_with_options(
                ika_system_object_id,
                SuiObjectDataOptions::new().with_owner(),
            )
            .await?;
        let Some(Owner::Shared {
            initial_shared_version,
        }) = response.owner()
        else {
            return Err(Self::Error::DataError(format!(
                "Failed to load ika system state owner {ika_system_object_id:?}"
            )));
        };
        Ok(ObjectArg::SharedObject {
            id: ika_system_object_id,
            initial_shared_version,
            mutability: sui_types::transaction::SharedObjectMutability::Mutable,
        })
    }

    /// Get the shared object arg for the shared system object on the chain.
    async fn get_shared_arg(&self, obj_id: ObjectID) -> Result<ObjectArg, Self::Error> {
        let response = self
            .read_api()
            .get_object_with_options(obj_id, SuiObjectDataOptions::new().with_owner())
            .await?;
        let Some(Owner::Shared {
            initial_shared_version,
        }) = response.owner()
        else {
            return Err(Self::Error::DataError(format!(
                "Failed to load ika system state owner {obj_id:?}"
            )));
        };
        Ok(ObjectArg::SharedObject {
            id: obj_id,
            initial_shared_version,
            mutability: sui_types::transaction::SharedObjectMutability::Immutable,
        })
    }

    async fn get_available_move_packages(
        &self,
        //chain: sui_protocol_config::Chain,
        _ika_package_id: ObjectID,
        _ika_system_package_id: ObjectID,
    ) -> Result<Vec<(ObjectID, MovePackageDigest)>, Self::Error> {
        let results = vec![];
        //let protocol_config_response = self.read_api().get_protocol_config(None).await?;
        //let protocol_config = sui_protocol_config::ProtocolConfig::get_for_version(protocol_config_response.protocol_version, chain);
        //let binary_config = sui_types::execution_config_utils::to_binary_config(&protocol_config);

        // let ika_packages = vec![
        //     ("ika".to_string(), ika_package_id),
        //     ("ika_system".to_string(), ika_system_package_id),
        // ];
        // for (name, package_id) in ika_packages.clone() {
        //     //let object_response = self.read_api().get_object_with_options(package_id, SuiObjectDataOptions::full_content()).await?;
        //     //let object_data = object_response.data.expect("Package object should have data.");
        //     //let object: Object = object_data.try_into().map_err(|e: anyhow::Error| Self::Error::DataError(e.to_string()))?;
        //     let move_package = BuiltInIkaMovePackages::get_package_by_name(&name);
        //     //let modules = move_package.modules_with_deps(ika_packages.clone().into_iter().collect()).map_err(|e: anyhow::Error| Self::Error::DataError(e.to_string()))?;
        //     let bytes = move_package
        //         .bytes_with_deps(ika_packages.clone().into_iter().collect())
        //         .map_err(|e: anyhow::Error| Self::Error::DataError(e.to_string()))?;
        //     let full_deps = move_package
        //         .full_deps(ika_packages.clone().into_iter().collect())
        //         .map_err(|e: anyhow::Error| Self::Error::DataError(e.to_string()))?;
        //     let digest = MovePackage::compute_digest_for_modules_and_deps(
        //         bytes.iter(),
        //         full_deps.iter(),
        //         true,
        //     );
        //     results.push((package_id, digest))
        // }

        Ok(results)
    }

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<SuiTransactionBlockResponse, IkaError> {
        let tx_digest = *tx.digest();
        match self.quorum_driver_api().execute_transaction_block(
            tx,
            SuiTransactionBlockResponseOptions::new().with_effects().with_events(),
            Some(sui_types::transaction_driver_types::ExecuteTransactionRequestType::WaitForEffectsCert),
        ).await {
            Ok(response) => Ok(response),
            Err(e) => Err(IkaError::SuiClientTxFailureGeneric(tx_digest, e.to_string())),
        }
    }

    async fn get_gas_objects(&self, address: SuiAddress) -> Vec<ObjectRef> {
        loop {
            let results = self
                .read_api()
                .get_owned_objects(
                    address,
                    Some(SuiObjectResponseQuery::new(
                        Some(SuiObjectDataFilter::StructType(GasCoin::type_())),
                        Some(SuiObjectDataOptions::full_content()),
                    )),
                    None,
                    None,
                )
                .await
                .map(|o| {
                    o.data
                        .into_iter()
                        .filter_map(|r| r.data.map(|o| o.object_ref()))
                        .collect::<Vec<_>>()
                });

            match results {
                Ok(gas_objs) => return gas_objs,
                Err(err) => {
                    warn!("can't get gas objects for address {}: {}", address, err);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}
