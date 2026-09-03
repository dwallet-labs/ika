// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::metrics::{SuiClientMetrics, SuiResponseErrorKind};
use crate::rate_limit::RateLimitGate;
use async_trait::async_trait;
use core::panic;
use dwallet_mpc_types::dwallet_mpc::VersionedMPCData;
use ika_config::node::SuiGrpcHeaders;
use ika_types::chain_mirror::{DWALLET_COORDINATOR_INNER_V1, SYSTEM_INNER_V1, decode_chain_mirror};
use ika_types::error::{IkaError, IkaResult};
use ika_types::messages_consensus::MovePackageDigest;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData, IkaNetworkConfig,
    IkaObjectsConfig, IkaPackageConfig,
};
use ika_types::sui::epoch_start_system::{EpochStartSystem, EpochStartValidatorInfoV1};
use ika_types::sui::pending_active_set::PendingActiveSet;
use ika_types::sui::staking::StakingPool;
use ika_types::sui::system_inner_v1::{DWalletCoordinatorInnerV1, SystemInnerV1};
use ika_types::sui::{
    DWalletCoordinator, DWalletCoordinatorInner, PricingInfoKey, PricingInfoValue, System,
    SystemInner, SystemInnerTrait, Validator,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sui_types::base_types::{EpochId, ObjectRef};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::clock::Clock;
use sui_types::collection_types::Entry;
use sui_types::digests::ChainIdentifier as SuiNetworkChainIdentifier;
use sui_types::dynamic_field::Field;
use sui_types::transaction::ObjectArg;
use sui_types::transaction::Transaction;
use tokio::sync::OnceCell;
use tracing::{error, warn};

pub mod archive;
pub mod faucet;
pub mod genesis;
pub mod grpc;
pub mod grpc_backend;
pub mod ika_dwallet_transactions;
#[cfg(feature = "protocol-commands")]
pub mod ika_protocol_transactions;
pub mod ika_validator_transactions;
pub mod metrics;
pub mod node_info;
pub mod rate_limit;
pub mod transaction_builder;
pub mod transaction_context;
pub mod transport;
pub use transport::{SubmittedTransaction, SuiFundsBreakdown};
// Re-exported so `retry_with_max_elapsed_time!` can reach it as `$crate::error_chain`
// from any expansion site, without requiring the caller to depend on ika-types.
pub use ika_types::error::error_chain;

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
          warn!(error = %$crate::error_chain(&err), "retrying with max elapsed time");
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
    /// Cache the chain-fetched `ObjectArg`s for the three shared
    /// system objects. The values don't change for a given chain
    /// (shared-object `initial_shared_version` is set at creation
    /// and is immutable), so one fetch per `SuiClient` instance is
    /// enough. Scoped to the instance — NOT a process-wide
    /// `static` — so two test clusters in the same process don't
    /// alias each other's chain state.
    system_arg_cache: OnceCell<ObjectArg>,
    clock_arg_cache: OnceCell<ObjectArg>,
    dwallet_coordinator_arg_cache: OnceCell<ObjectArg>,
    /// Keeps `ika_sui_client_sui_node_info` current for as long as this client
    /// exists — the handle aborts the refresh task on drop, so a short-lived
    /// CLI client does not leave a timer behind. `None` on clients built for
    /// tests, which have no registry anyone scrapes.
    _node_info_refresh: Option<node_info::SuiNodeInfoRefresh>,
}

pub type SuiBackend = grpc_backend::GrpcSuiClient;
pub type SuiConnectorClient = SuiClient<SuiBackend>;

impl SuiConnectorClient {
    /// Build a connector whose I/O goes through a direct Sui gRPC endpoint.
    /// Opens its own rate-limit gate. Use this only where there is no other
    /// client against the same endpoint to share one with — the one-shot CLI
    /// paths. A node builds one gate and passes it to
    /// [`Self::new_grpc_with_headers`] and to the connector stack.
    pub async fn new_grpc(
        grpc_url: &str,
        sui_client_metrics: Arc<SuiClientMetrics>,
        ika_network_config: IkaNetworkConfig,
    ) -> anyhow::Result<Self> {
        let gate = Arc::new(RateLimitGate::with_metrics(sui_client_metrics.clone()));
        Self::new_grpc_with_headers(
            grpc_url,
            &SuiGrpcHeaders::new(),
            sui_client_metrics,
            gate,
            ika_network_config,
        )
        .await
    }

    /// `rate_limit_gate` must be the SAME gate every other client against this
    /// endpoint holds — see [`crate::rate_limit::RateLimitGate`]. On a node
    /// that means the gate the connector stack was built with, so the
    /// notifier's read/write client and the connector's read client back off
    /// as one instead of retrying through each other's cooldown.
    pub async fn new_grpc_with_headers(
        grpc_url: &str,
        headers: &SuiGrpcHeaders,
        sui_client_metrics: Arc<SuiClientMetrics>,
        rate_limit_gate: Arc<RateLimitGate>,
        ika_network_config: IkaNetworkConfig,
    ) -> anyhow::Result<Self> {
        let inner =
            grpc_backend::GrpcSuiClient::new_with_headers(grpc_url, headers, rate_limit_gate)
                .await?;
        // Spawned, never awaited: identifying the fullnode must not add a
        // round trip to node boot, least of all on the wedged-uplink nodes
        // this metric exists to describe.
        let node_info_refresh =
            node_info::spawn_sui_node_info_refresh(inner.transport(), sui_client_metrics.clone());
        let self_ = Self {
            inner,
            sui_client_metrics,
            ika_network_config,
            system_arg_cache: OnceCell::new(),
            clock_arg_cache: OnceCell::new(),
            dwallet_coordinator_arg_cache: OnceCell::new(),
            _node_info_refresh: Some(node_info_refresh),
        };
        self_.describe().await?;
        Ok(self_)
    }

    /// Build a gRPC-backed connector over an already-constructed transport
    /// instead of opening a fresh gRPC connection. Used by a *peer-only*
    /// validator, whose transport is a verified relay reader
    /// (`VerifiedSuiTransport`) rather than a direct gRPC client.
    pub async fn new_grpc_with_transport(
        transport: Arc<dyn crate::transport::SuiTransport>,
        sui_client_metrics: Arc<SuiClientMetrics>,
        ika_network_config: IkaNetworkConfig,
    ) -> anyhow::Result<Self> {
        let inner = grpc_backend::GrpcSuiClient::with_transport(transport);
        // The relay transport has no service-info RPC, so this settles on
        // `server_version="unsupported"` after one probe and stops — which is
        // the honest answer for a node with no fullnode of its own.
        let node_info_refresh =
            node_info::spawn_sui_node_info_refresh(inner.transport(), sui_client_metrics.clone());
        let self_ = Self {
            inner,
            sui_client_metrics,
            ika_network_config,
            system_arg_cache: OnceCell::new(),
            clock_arg_cache: OnceCell::new(),
            dwallet_coordinator_arg_cache: OnceCell::new(),
            _node_info_refresh: Some(node_info_refresh),
        };
        self_.describe().await?;
        Ok(self_)
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
            system_arg_cache: OnceCell::new(),
            clock_arg_cache: OnceCell::new(),
            dwallet_coordinator_arg_cache: OnceCell::new(),
            // Not spawned for tests: `new_for_testing` is called from
            // synchronous contexts with no runtime, and nothing scrapes the
            // throwaway registry it builds.
            _node_info_refresh: None,
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
                let dynamic_field_inner: Field<u64, DWalletCoordinatorInnerV1> =
                    decode_chain_mirror(&result, DWALLET_COORDINATOR_INNER_V1)
                        .map_err(IkaError::SuiClientSerializationError)?;
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
                let dynamic_field_inner: Field<u64, SystemInnerV1> =
                    decode_chain_mirror(&result, SYSTEM_INNER_V1)
                        .map_err(IkaError::SuiClientSerializationError)?;
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

    /// See [`SuiClientInner::get_mpc_data_from_validators_pool`]: this reads the
    /// deprecated on-chain `mpc_data_bytes` field (#2119), and
    /// `read_next_mpc_data` is ignored.
    pub async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_mpc_data: bool,
    ) -> IkaResult<HashMap<ObjectID, VersionedMPCData>> {
        // Same instrumentation as the network-key full-data fetch:
        // every chain-side `mpc_data` table read shows up here so
        // tests can assert the off-chain pipeline doesn't trigger it.
        self.sui_client_metrics
            .chain_blob_reads
            .with_label_values(&["get_mpc_data_from_validators_pool"])
            .inc();
        crate::metrics::CHAIN_BLOB_READ_MPC_DATA_FROM_VALIDATORS_POOL
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                            // The RPC answered; the bytes it answered with are
                            // what is wrong. Not an uplink failure.
                            self.sui_client_metrics.record_response_error(
                                "get_epoch_start_system",
                                SuiResponseErrorKind::Decode,
                            );
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
                                self.sui_client_metrics.record_response_error(
                                    "get_epoch_start_system",
                                    SuiResponseErrorKind::NotFound,
                                );
                                IkaError::InvalidCommittee(format!(
                                    "Validator with ID {} not found in the active committee",
                                    m.validator_id
                                ))
                            })?;
                        // The stored key bytes are only length-checked on
                        // chain, so parsing them can fail. Fail the read and
                        // let it be retried.
                        let info = validator.verified_validator_info().map_err(|code| {
                            self.sui_client_metrics.record_response_error(
                                "get_epoch_start_system",
                                SuiResponseErrorKind::ValidatorInfoParse,
                            );
                            IkaError::InvalidCommittee(format!(
                                "validator {} has unparsable on-chain metadata (Move error code {code})",
                                validator.id
                            ))
                        })?;
                        // An active member's mpc_data record is written at candidate
                        // registration and never emptied on chain, so a gap here is
                        // always a read defect (fullnode lag, table-walk race, or a
                        // decode failure the fetch already logged). Skipping the
                        // member would install a committee whose class-groups map
                        // silently diverges from peers with healthier reads — an
                        // unagreed party-set exclusion in MPC public inputs — and
                        // the degraded `EpochStartSystem` would be persisted and
                        // rebuilt on every restart. Fail the whole read instead;
                        // `must_get_epoch_start_system` retries until it completes.
                        //
                        // Since #2119 this gate is about the record's PRESENCE
                        // and decodability, not its contents: a validator
                        // registered after #2119 carries
                        // `deprecated_on_chain_mpc_data_placeholder` here, which
                        // is shaped precisely so it still decodes as a
                        // `VersionedMPCData` and keeps this check meaningful.
                        let Some(mpc_data) = validators_mpc_data.get(&validator.id) else {
                            self.sui_client_metrics.record_response_error(
                                "get_epoch_start_system",
                                SuiResponseErrorKind::MissingField,
                            );
                            ika_types::report_invariant_violation!(
                                "epoch_start_mpc_data_missing",
                                validator_id = ?validator.id,
                                validator_name = %info.name,
                                "active committee member has no decodable on-chain \
                                 mpc_data record at epoch start; failing the read for retry"
                            );
                            return Err(IkaError::InvalidCommittee(format!(
                                "missing on-chain mpc_data record for active committee \
                                 member {} ({})",
                                info.name, validator.id
                            )));
                        };
                        // Take the BLS protocol key from the FROZEN committee
                        // member rather than from the validator record. The
                        // committee is snapshotted mid-epoch from the key that
                        // was current then, while `rotate_next_epoch_info`
                        // installs a staged rotation into the record at the
                        // epoch boundary — so for a validator that rotated, the
                        // record holds a different key than the committee this
                        // epoch is actually verified against, and the node's
                        // per-signature check would disagree with the on-chain
                        // aggregate check for a full epoch.
                        let protocol_pubkey = m.parsed_protocol_pubkey().map_err(|e| {
                            self.sui_client_metrics.record_response_error(
                                "get_epoch_start_system",
                                SuiResponseErrorKind::InvalidCommitteePubkeyParse,
                            );
                            IkaError::InvalidCommittee(format!(
                                "active committee member {} has an unparsable BLS protocol \
                                 public key: {e}",
                                m.validator_id
                            ))
                        })?;
                        Ok(EpochStartValidatorInfoV1 {
                            name: info.name.clone(),
                            validator_id: validator.id,
                            protocol_pubkey,
                            network_pubkey: info.network_pubkey.clone(),
                            consensus_pubkey: info.consensus_pubkey.clone(),
                            mpc_data: Some(mpc_data.clone()),
                            network_address: info.network_address.clone(),
                            p2p_address: info.p2p_address.clone(),
                            consensus_address: info.consensus_address.clone(),
                            voting_power: 1,
                            hostname: info.name.clone(),
                        })
                    })
                    .collect::<IkaResult<Vec<_>>>()?;

                let epoch_start_system_state = EpochStartSystem::new_v2(
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

    /// The `validator_id`s currently in the on-chain `pending_active_set` — the
    /// staging set for the next epoch, updated continuously as validators
    /// join/leave (so a freshly-registered joiner appears here before it reaches
    /// `next_epoch_committee`). `pending_active_set_id` is
    /// `SystemInner.validator_set.pending_active_set.id` (the `ExtendedField`
    /// wrapper); the value lives at its deterministically-derived child, keyed
    /// by the empty `extended_field::Key()` (no name bytes).
    pub async fn get_pending_active_set_ids(
        &self,
        pending_active_set_id: ObjectID,
    ) -> Result<Vec<ObjectID>, IkaError> {
        // Read the wrapper's single dynamic field by LISTING it (not by
        // deriving the child id) — robust to the `Key()` encoding.
        let bytes = self
            .inner
            .get_extended_field_value_bcs(pending_active_set_id)
            .await
            .map_err(|e| {
                IkaError::SuiClientInternalError(format!("read pending_active_set: {e}"))
            })?;
        let pending = decode_pending_active_set(&bytes).map_err(|e| {
            IkaError::SuiClientSerializationError(format!(
                "decode pending_active_set ({} bytes): {e}",
                bytes.len()
            ))
        })?;
        Ok(pending.validator_ids())
    }

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
                    // `get_validators` above succeeded — the fetch is fine and
                    // the bytes are not.
                    self.sui_client_metrics.record_response_error(
                        "get_validators_info_by_ids",
                        SuiResponseErrorKind::Decode,
                    );
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
        *self
            .system_arg_cache
            .get_or_init(|| async move {
                let Ok(Ok(system_arg)) = retry_with_max_elapsed_time!(
                    self.inner.get_mutable_shared_arg(
                        self.ika_network_config.objects.ika_system_object_id
                    ),
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
        *self
            .clock_arg_cache
            .get_or_init(|| async move {
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
        *self
            .dwallet_coordinator_arg_cache
            .get_or_init(|| async move {
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

    pub async fn get_chain_identifier(&self) -> IkaResult<String> {
        self.inner.get_chain_identifier().await.map_err(|e| {
            self.sui_client_metrics
                .sui_rpc_errors
                .with_label_values(&["get_chain_identifier"])
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

    /// Current SUI epoch, retried until it succeeds — the `ValidDuring`
    /// anchor for address-balance-gas submissions (same retry-forever
    /// contract as `get_reference_gas_price_until_success`; both feed
    /// transaction construction on the writer path).
    pub async fn get_sui_epoch_until_success(&self) -> u64 {
        loop {
            let Ok(Ok(epoch)) =
                retry_with_max_elapsed_time!(self.inner.get_sui_epoch(), Duration::from_secs(30))
            else {
                self.sui_client_metrics
                    .sui_rpc_errors
                    .with_label_values(&["get_sui_epoch_until_success"])
                    .inc();
                error!("Failed to get the current SUI epoch");
                continue;
            };
            return epoch;
        }
    }

    /// The chain's genesis-rooted `ChainIdentifier` (full identifier, as
    /// `ValidDuring` requires).
    pub async fn get_sui_chain_identifier(&self) -> IkaResult<SuiNetworkChainIdentifier> {
        self.inner.get_sui_chain_identifier().await.map_err(|e| {
            self.sui_client_metrics
                .sui_rpc_errors
                .with_label_values(&["get_sui_chain_identifier"])
                .inc();
            IkaError::SuiClientInternalError(format!("Can't get_sui_chain_identifier: {e}"))
        })
    }

    /// SUI held by `address`, split into address balance vs. coin objects.
    pub async fn get_sui_funds(&self, address: SuiAddress) -> IkaResult<SuiFundsBreakdown> {
        self.inner.get_sui_funds(address).await.map_err(|e| {
            self.sui_client_metrics
                .sui_rpc_errors
                .with_label_values(&["get_sui_funds"])
                .inc();
            IkaError::SuiClientInternalError(format!("Can't get_sui_funds: {e}"))
        })
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
    ) -> IkaResult<SubmittedTransaction> {
        self.inner.execute_transaction_block_with_effects(tx).await
    }

    pub async fn must_get_system_inner_object(&self) -> (System, SystemInner) {
        loop {
            match retry_with_max_elapsed_time!(self.get_system_inner(), Duration::from_secs(30)) {
                Ok(Ok(ika_system_state)) => return ika_system_state,
                Ok(Err(err)) => {
                    self.sui_client_metrics
                        .record_read_error("must_get_system_inner_object", &err);
                    warn!(
                        error=?err,
                        "Received error from `get_system_inner()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .record_read_error("must_get_system_inner_object", &err);
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
        // Count every chain-side fetch of the heavy blob fields so
        // off-chain-mode tests can assert this path is not hit when
        // the off-chain pipeline is active.
        self.sui_client_metrics
            .chain_blob_reads
            .with_label_values(&["get_network_encryption_key_with_full_data_by_epoch"])
            .inc();
        crate::metrics::CHAIN_BLOB_READ_NETWORK_KEY_FULL_DATA
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                        .record_read_error("must_get_dwallet_coordinator_inner", &err);
                    warn!(
                        error=?err,
                        "Received error from `get_dwallet_coordinator_inner()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .record_read_error("must_get_dwallet_coordinator_inner", &err);
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
                        .record_read_error("must_get_epoch_start_system", &err);
                    warn!(
                        error=?err,
                        "Received error from `get_epoch_start_system()`. Retrying...",
                    );
                }
                Err(err) => {
                    self.sui_client_metrics
                        .record_read_error("must_get_epoch_start_system", &err);
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

/// Abstract the Sui client for connector tests.
#[async_trait]
pub trait SuiClientInner: Send + Sync {
    type Error: Into<anyhow::Error> + Send + Sync + std::error::Error + 'static;
    async fn get_chain_identifier(&self) -> Result<String, Self::Error>;

    /// Current SUI epoch — the `ValidDuring` window anchor for
    /// address-balance-gas transactions (SIP-58).
    async fn get_sui_epoch(&self) -> Result<u64, Self::Error>;

    /// The chain's genesis-rooted `ChainIdentifier`. `ValidDuring` carries it
    /// verbatim and validators compare the FULL identifier, so the 4-byte
    /// short id alone is not enough on chains without a compiled-in constant.
    async fn get_sui_chain_identifier(&self) -> Result<SuiNetworkChainIdentifier, Self::Error>;

    /// SUI held by `address`, split into its ADDRESS BALANCE (SIP-58 — what
    /// address-balance-gas submissions draw on) and its owned coin objects.
    async fn get_sui_funds(&self, address: SuiAddress) -> Result<SuiFundsBreakdown, Self::Error>;

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error>;

    async fn get_latest_checkpoint_sequence_number(&self) -> Result<u64, Self::Error>;

    async fn get_system(&self, ika_system_object_id: ObjectID) -> Result<Vec<u8>, Self::Error>;

    /// Read the single value stored in an `ExtendedField` wrapper at `ef_id` by
    /// LISTING its one dynamic field and returning that child's BCS (a
    /// `Field<Key, V>`). Robust to the wrapper's empty-`Key()` encoding — no
    /// manual dynamic-field-id derivation (used for `pending_active_set`).
    async fn get_extended_field_value_bcs(&self, ef_id: ObjectID) -> Result<Vec<u8>, Self::Error>;

    async fn get_clock(&self, clock_obj_id: ObjectID) -> Result<Vec<u8>, Self::Error>;

    async fn get_dwallet_coordinator(
        &self,
        dwallet_coordinator_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Read the validators' **deprecated** on-chain `mpc_data_bytes` records
    /// (issue #2119). Validators registered after #2119 carry only
    /// [`crate::ika_validator_transactions::deprecated_on_chain_mpc_data_placeholder`]
    /// here; the real key material travels off chain.
    ///
    /// `read_next_epoch_mpc_data` is retained for source compatibility with the
    /// existing call sites and is IGNORED — the on-chain rotation slots it
    /// selected (`next_epoch_mpc_data_bytes` / `previous_mpc_data_bytes`) have
    /// no writer left in this repo.
    #[allow(clippy::ptr_arg)]
    async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_epoch_mpc_data: bool,
    ) -> Result<HashMap<ObjectID, VersionedMPCData>, Self::Error>;

    #[allow(clippy::ptr_arg)]
    async fn get_network_encryption_keys(
        &self,
        dwallet_coordinator_inner: &DWalletCoordinatorInnerV1,
    ) -> Result<HashMap<ObjectID, DWalletNetworkEncryptionKey>, Self::Error>;

    async fn get_network_encryption_key_with_full_data_by_epoch(
        &self,
        network_decryption_key: &DWalletNetworkEncryptionKey,
        epoch: EpochId,
    ) -> Result<DWalletNetworkEncryptionKeyData, Self::Error>;

    async fn get_current_reconfiguration_public_output(
        &self,
        epoch_id: EpochId,
        table_id: ObjectID,
    ) -> Result<ObjectID, Self::Error>;

    async fn read_table_vec_as_raw_bytes(&self, table_id: ObjectID)
    -> Result<Vec<u8>, Self::Error>;

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
    ) -> Result<SubmittedTransaction, IkaError>;

    async fn get_gas_objects(&self, address: SuiAddress) -> Vec<ObjectRef>;
}

/// Decode a `pending_active_set` from the BCS bytes of its backing
/// `Field<Key, PendingActiveSet>` dynamic-field object.
///
/// The object is `id: UID` (32 bytes) ++ `name: Key` ++ `value:
/// PendingActiveSet`. On-chain `ika_common::extended_field::Key` serializes to a
/// SINGLE byte (an "empty" Move struct still carries a `bool` dummy field), so
/// the value lives behind a 33-byte header — `Field<u8, _>`, NOT `Field<(), _>`.
/// The unit-name and bare-value framings are tried as fallbacks so the decode
/// also survives a backend that resolves the dynamic field differently.
fn decode_pending_active_set(bytes: &[u8]) -> Result<PendingActiveSet, bcs::Error> {
    bcs::from_bytes::<Field<u8, PendingActiveSet>>(bytes)
        .map(|f| f.value)
        .or_else(|_| bcs::from_bytes::<Field<(), PendingActiveSet>>(bytes).map(|f| f.value))
        .or_else(|_| bcs::from_bytes::<PendingActiveSet>(bytes))
}

#[cfg(test)]
mod pending_active_set_tests {
    use super::decode_pending_active_set;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Real BCS bytes of the `pending_active_set` child object captured from a
    /// 4-validator localnet (`SystemInner.validator_set.pending_active_set`).
    /// Guards the dynamic-field framing: `id: UID`(32) ++ `name: Key`(1) ++
    /// `value`. Decoding it as `Field<(), _>` (a 0-byte name) short-reads with
    /// "unexpected end of input" — the bug this regression test pins.
    #[test]
    fn decodes_field_wrapped_pending_active_set_from_chain_bytes() {
        let bytes = unhex(concat!(
            "cd469f28ea7d4a66faf34ca44e2a32ca12717e39d79af89d7169dda9dcd8d563",
            "00040000000000000066000000000000000000434fd7946a000a00000000000000",
            "0492d17c3bbc37c855e47d311f73be413d953e8792429765ff899f40d185072baa",
            "0000434fd7946a0042cb3e9037f05a5a312d539469e59a91da2f9ed6dddf7e197f",
            "1803dbf6222d9b0000434fd7946a0035e3903f1cb93fde2005ee4983091879bfa2",
            "1c193ba5ac7cf112bb0c7b77021f0000434fd7946a00a183df56e91f88e839d8da",
            "3ca3c83a42a70c3897dfe8af7545c37875c09d5b990000434fd7946a0000000c3d",
            "5d53aa0100",
        ));
        let pending = decode_pending_active_set(&bytes).expect("decode failed");
        let ids: Vec<String> = pending
            .validator_ids()
            .iter()
            .map(|id| id.to_string())
            .collect();
        assert_eq!(
            ids,
            vec![
                "0x92d17c3bbc37c855e47d311f73be413d953e8792429765ff899f40d185072baa",
                "0x42cb3e9037f05a5a312d539469e59a91da2f9ed6dddf7e197f1803dbf6222d9b",
                "0x35e3903f1cb93fde2005ee4983091879bfa21c193ba5ac7cf112bb0c7b77021f",
                "0xa183df56e91f88e839d8da3ca3c83a42a70c3897dfe8af7545c37875c09d5b99",
            ]
        );
    }
}

/// The split between `ika_sui_client_sui_rpc_errors` (Sui did not answer) and
/// `ika_sui_client_sui_response_errors_total` (Sui answered, the answer was
/// unusable). The fleet alerts on the former, so a decoding or data defect
/// landing there reads as an operator's fullnode outage.
#[cfg(test)]
mod rpc_vs_response_error_tests {
    use super::*;
    use prometheus::core::Collector;

    /// A backend whose only live method is `get_validators`, set to either
    /// fail at the transport or answer with bytes that are not a
    /// `StakingPool`. Every other method is unreachable from the two reads
    /// under test.
    struct ValidatorsStub {
        /// `Ok` — the RPC answered with these per-validator BCS blobs;
        /// `Err` — it never answered.
        validators: Result<Vec<Vec<u8>>, ()>,
    }

    impl ValidatorsStub {
        fn client(validators: Result<Vec<Vec<u8>>, ()>) -> SuiClient<Self> {
            SuiClient::new_for_testing(Self { validators })
        }
    }

    #[async_trait]
    impl SuiClientInner for ValidatorsStub {
        type Error = std::io::Error;

        async fn get_validators(
            &self,
            _validator_ids: Vec<ObjectID>,
        ) -> Result<Vec<Vec<u8>>, Self::Error> {
            self.validators.clone().map_err(|()| {
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "sui rpc unreachable")
            })
        }

        async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_sui_epoch(&self) -> Result<u64, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_sui_chain_identifier(&self) -> Result<SuiNetworkChainIdentifier, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_sui_funds(
            &self,
            _address: SuiAddress,
        ) -> Result<SuiFundsBreakdown, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_latest_checkpoint_sequence_number(&self) -> Result<u64, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_system(&self, _id: ObjectID) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_extended_field_value_bcs(
            &self,
            _ef_id: ObjectID,
        ) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_clock(&self, _clock_obj_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_dwallet_coordinator(&self, _id: ObjectID) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_mpc_data_from_validators_pool(
            &self,
            _validators: &Vec<StakingPool>,
            _read_next_epoch_mpc_data: bool,
        ) -> Result<HashMap<ObjectID, VersionedMPCData>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_network_encryption_keys(
            &self,
            _dwallet_coordinator_inner: &DWalletCoordinatorInnerV1,
        ) -> Result<HashMap<ObjectID, DWalletNetworkEncryptionKey>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_network_encryption_key_with_full_data_by_epoch(
            &self,
            _network_decryption_key: &DWalletNetworkEncryptionKey,
            _epoch: EpochId,
        ) -> Result<DWalletNetworkEncryptionKeyData, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_current_reconfiguration_public_output(
            &self,
            _epoch_id: EpochId,
            _table_id: ObjectID,
        ) -> Result<ObjectID, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn read_table_vec_as_raw_bytes(
            &self,
            _table_id: ObjectID,
        ) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_system_inner(
            &self,
            _id: ObjectID,
            _version: u64,
        ) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_dwallet_coordinator_inner(
            &self,
            _id: ObjectID,
            _version: u64,
        ) -> Result<Vec<u8>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_validator_inners(
            &self,
            _validators: Vec<Validator>,
        ) -> Result<Vec<Vec<u8>>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_mutable_shared_arg(&self, _id: ObjectID) -> Result<ObjectArg, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_shared_arg(&self, _obj_id: ObjectID) -> Result<ObjectArg, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn get_available_move_packages(
            &self,
            _ika_package_id: ObjectID,
            _ika_system_package_id: ObjectID,
        ) -> Result<Vec<(ObjectID, MovePackageDigest)>, Self::Error> {
            unimplemented!("not exercised")
        }
        async fn execute_transaction_block_with_effects(
            &self,
            _tx: Transaction,
        ) -> Result<SubmittedTransaction, IkaError> {
            unimplemented!("not exercised")
        }
        async fn get_gas_objects(&self, _address: SuiAddress) -> Vec<ObjectRef> {
            unimplemented!("not exercised")
        }
    }

    /// Every child of `vec` summed — "this family recorded nothing at all",
    /// which is the assertion that matters here and which a per-label read
    /// cannot make.
    fn family_total(vec: &prometheus::IntCounterVec) -> u64 {
        vec.collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_counter().value() as u64)
            .sum()
    }

    /// `get_validators` answers; the bytes it answers with are 4 long, and a
    /// `StakingPool` opens with a 32-byte `UID`. The uplink is healthy.
    #[tokio::test]
    async fn a_decode_failure_on_a_successful_rpc_is_not_an_rpc_error() {
        let client = ValidatorsStub::client(Ok(vec![vec![0xff; 4]]));

        let err = client
            .get_validators_info_by_ids(vec![ObjectID::random()])
            .await
            .expect_err("4 bytes cannot decode as a StakingPool");
        assert!(
            matches!(err, IkaError::SuiClientSerializationError(_)),
            "expected a serialization error, got {err:?}"
        );

        let metrics = &client.sui_client_metrics;
        assert_eq!(
            metrics
                .sui_response_errors
                .with_label_values(&["get_validators_info_by_ids", "decode"])
                .get(),
            1,
            "the decode failure belongs to the response counter"
        );
        assert_eq!(
            family_total(&metrics.sui_rpc_errors),
            0,
            "a decoding bug must not show up as a Sui uplink failure"
        );
    }

    /// The mirror case: the call never came back, which is exactly what
    /// `ika_sui_client_sui_rpc_errors` is for.
    #[tokio::test]
    async fn a_transport_failure_is_an_rpc_error_only() {
        let client = ValidatorsStub::client(Err(()));

        let err = client
            .get_validators_info_by_ids(vec![ObjectID::random()])
            .await
            .expect_err("the stubbed transport refuses the connection");
        assert!(
            matches!(err, IkaError::SuiClientInternalError(_)),
            "expected an internal/transport error, got {err:?}"
        );

        let metrics = &client.sui_client_metrics;
        assert_eq!(
            metrics
                .sui_rpc_errors
                .with_label_values(&["get_validators_info_by_ids"])
                .get(),
            1,
        );
        assert_eq!(
            family_total(&metrics.sui_response_errors),
            0,
            "nothing was decoded, so nothing can be a response failure"
        );
    }

    /// The `must_get_*` wrappers see only the terminal error, and they fire
    /// once per exhausted retry round — the backoff runs
    /// 0.4+0.8+1.6+3.2+6.4+12.8s and the 7th check exceeds the 30s budget, so
    /// a round is ~25.2s and a persistent failure yields ~143 wrapper
    /// increments/hour, above the fleet's RPC-error alert threshold on their
    /// own. Routing them by error variant is what keeps a persistent decoding
    /// bug off that alert.
    #[test]
    fn the_retry_wrappers_route_by_error_variant() {
        let metrics = SuiClientMetrics::new_for_testing();
        let method = "must_get_epoch_start_system";

        metrics.record_read_error(
            method,
            &IkaError::SuiClientInternalError("uplink refused".to_string()),
        );
        metrics.record_read_error(
            method,
            &IkaError::SuiClientSerializationError("short read".to_string()),
        );
        metrics.record_read_error(
            method,
            &IkaError::InvalidCommittee("member missing from the fetched set".to_string()),
        );

        assert_eq!(
            metrics.sui_rpc_errors.with_label_values(&[method]).get(),
            1,
            "only the transport failure belongs to the RPC counter"
        );
        assert_eq!(
            metrics
                .sui_response_errors
                .with_label_values(&[method, "decode"])
                .get(),
            1,
        );
        assert_eq!(
            metrics
                .sui_response_errors
                .with_label_values(&[method, "invalid_committee"])
                .get(),
            1,
        );
    }

    /// The stability guarantee `SuiResponseErrorKind::classify` documents: a
    /// variant it does not list falls through to `sui_rpc_errors`, i.e. the
    /// behaviour every site had before the split. Without this, adding an
    /// `IkaError` variant could quietly move traffic off the counter the
    /// fleet alert reads, and nothing would say so.
    #[test]
    fn an_unlisted_error_variant_stays_on_the_rpc_counter() {
        let metrics = SuiClientMetrics::new_for_testing();
        let method = "must_get_system_inner_object";

        metrics.record_read_error(method, &IkaError::Unknown("something new".to_string()));

        assert_eq!(
            metrics.sui_rpc_errors.with_label_values(&[method]).get(),
            1,
            "an unclassified variant keeps its historical counter"
        );
        assert_eq!(
            family_total(&metrics.sui_response_errors),
            0,
            "classify() must not guess a response kind it was never taught"
        );
    }
}
