// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! gRPC implementation of [`SuiClientInner`].
//!
//! Mirrors the Ika-domain decode/aggregate logic of the JSON-RPC
//! `impl SuiClientInner for SuiSdkClient` (in `lib.rs`) but reads/writes
//! Sui exclusively over the gRPC [`SuiTransport`] surface. Used in OCS
//! mode where the node must not depend on the JSON-RPC fullnode API.
//!
//! Object reads return BCS by pulling the Move object's `contents()`.
//! Versioned-inner reads derive the dynamic-field child id deterministically
//! (same `derive_dynamic_field_id(parent, U64, version)` scheme the OCS
//! verified reader uses) rather than trusting a server-side field listing.

use std::collections::HashMap;

use async_trait::async_trait;
use dwallet_mpc_types::dwallet_mpc::VersionedMPCData;
use ika_types::error::IkaError;
use ika_types::messages_consensus::MovePackageDigest;
use ika_types::messages_dwallet_mpc::{
    DBSuiEvent, DWalletNetworkEncryptionKey, DWalletNetworkEncryptionKeyData,
};
use ika_types::sui::Validator;
use ika_types::sui::staking::StakingPool;
use ika_types::sui::system_inner_v1::DWalletCoordinatorInnerV1;
use itertools::Itertools;
use sui_json_rpc_types::{
    EventFilter, EventPage, SuiTransactionBlockEffects, SuiTransactionBlockResponse,
};
use sui_types::base_types::{EpochId, ObjectID, ObjectRef, SuiAddress};
use sui_types::collection_types::Table;
use sui_types::dynamic_field::Field;
use sui_types::event::EventID;
use sui_types::object::{Object, Owner};
use sui_types::transaction::{ObjectArg, SharedObjectMutability, Transaction};

use crate::SuiClientInner;
use crate::grpc::SuiGrpcClient;
use crate::transport::{SuiTransport, SuiWriter, TransportError, dynamic_field_child_owned_by};
use sui_types::digests::{ChainIdentifier as SuiNetworkChainIdentifier, CheckpointDigest};

/// Error surface of the gRPC backend. Satisfies the
/// `SuiClientInner::Error` bound (`Into<anyhow::Error> + Send + Sync +
/// std::error::Error + 'static`).
#[derive(thiserror::Error, Debug)]
pub enum GrpcSuiClientError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(String),
    #[error("{0}")]
    Other(String),
}

impl GrpcSuiClientError {
    fn decode(msg: impl std::fmt::Display) -> Self {
        Self::Decode(msg.to_string())
    }
}

pub struct GrpcSuiClient {
    transport: std::sync::Arc<dyn SuiTransport>,
    /// Writer uplink: gas price, gas-coin selection, and transaction
    /// submission. `Some` only when this client was opened against a direct
    /// fullnode (`new`); `None` on a read-only node built over a relay
    /// transport (`with_transport`). Writes are notifier-gated to a direct
    /// uplink, so a read-only mirrored/peer-only node legitimately has none.
    writer: Option<std::sync::Arc<dyn SuiWriter>>,
}

impl GrpcSuiClient {
    /// Connect to a Sui fullnode over gRPC at `grpc_url`. The same direct
    /// client backs both the read transport and the writer uplink.
    pub async fn new(grpc_url: &str) -> anyhow::Result<Self> {
        let grpc = std::sync::Arc::new(SuiGrpcClient::new(grpc_url).await?);
        Ok(Self {
            transport: grpc.clone(),
            writer: Some(grpc),
        })
    }

    /// Build over an arbitrary transport. Lets a caller reuse an existing
    /// (e.g. fallback-decorated) transport instead of opening a new gRPC
    /// connection. Used by a *peer-only* node, which is read-only — so it has
    /// no writer uplink.
    pub fn with_transport(transport: std::sync::Arc<dyn SuiTransport>) -> Self {
        Self {
            transport,
            writer: None,
        }
    }

    /// The writer uplink, or a clear error on a read-only node. Transaction
    /// building/submission (and the gas-price / gas-coin reads that only serve
    /// it) are notifier-gated to a direct fullnode connection.
    fn writer(&self) -> Result<&std::sync::Arc<dyn SuiWriter>, TransportError> {
        self.writer.as_ref().ok_or_else(|| {
            TransportError::Network(
                "no writer uplink on this node: transaction building/submission is \
                 notifier-gated to a direct gRPC connection"
                    .into(),
            )
        })
    }

    /// BCS contents of the Move object `id`.
    async fn object_bcs(&self, id: ObjectID) -> Result<Vec<u8>, GrpcSuiClientError> {
        let object = self.transport.get_object(id).await?;
        move_object_contents(&object, id)
    }

    /// Deterministically-derived `Field<u64, _>` child id for `(parent, version)`.
    fn versioned_child_id(parent: ObjectID, version: u64) -> Result<ObjectID, GrpcSuiClientError> {
        crate::transport::derive_versioned_child_id(parent, version)
            .map_err(GrpcSuiClientError::decode)
    }

    /// BCS of the versioned inner object backing `(parent, version)`.
    async fn versioned_inner_bcs(
        &self,
        parent: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, GrpcSuiClientError> {
        let child_id = Self::versioned_child_id(parent, version)?;
        self.object_bcs(child_id).await
    }

    /// Walk every dynamic field of `parent`, fetch each child object, and
    /// hand its `(object_id, bcs_contents)` to `handle`. Reproduces the
    /// paginated table walk the JSON-RPC backend performs. Children are
    /// fetched one batch round-trip per page rather than one per entry —
    /// on the relay transport a page is one RPC instead of `page.len()`.
    async fn for_each_dynamic_child<F>(
        &self,
        parent: ObjectID,
        mut handle: F,
    ) -> Result<(), GrpcSuiClientError>
    where
        F: FnMut(ObjectID, Vec<u8>) -> Result<(), GrpcSuiClientError>,
    {
        let mut page_token = None;
        loop {
            let page = self
                .transport
                .list_dynamic_fields(parent, None, page_token)
                .await?;
            let ids: Vec<ObjectID> = page.entries.iter().map(|entry| entry.object_id).collect();
            if !ids.is_empty() {
                let objects = self.transport.batch_get_objects(&ids).await?;
                for (object, id) in objects.iter().zip(ids.iter()) {
                    let contents = move_object_contents(object, *id)?;
                    handle(*id, contents)?;
                }
            }
            match page.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        Ok(())
    }

    /// Shared-object [`ObjectArg`] for `id` with the given mutability.
    async fn shared_object_arg(
        &self,
        id: ObjectID,
        mutability: SharedObjectMutability,
    ) -> Result<ObjectArg, GrpcSuiClientError> {
        let object = self.transport.get_object(id).await?;
        let Owner::Shared {
            initial_shared_version,
        } = object.owner().clone()
        else {
            return Err(GrpcSuiClientError::Other(format!(
                "object {id:?} is not a shared object"
            )));
        };
        Ok(ObjectArg::SharedObject {
            id,
            initial_shared_version,
            mutability,
        })
    }
}

fn move_object_contents(object: &Object, id: ObjectID) -> Result<Vec<u8>, GrpcSuiClientError> {
    crate::transport::move_object_contents(object)
        .map(|contents| contents.to_vec())
        .ok_or_else(|| GrpcSuiClientError::Decode(format!("object {id:?} is not a MoveObject")))
}

#[async_trait]
impl SuiClientInner for GrpcSuiClient {
    type Error = GrpcSuiClientError;

    /// Unsupported on the gRPC backend. OCS mode ingests events via the
    /// `BagEventPump`, never `query_events`, so this is never reached there.
    async fn query_events(
        &self,
        _query: EventFilter,
        _cursor: Option<EventID>,
    ) -> Result<EventPage, Self::Error> {
        Err(GrpcSuiClientError::Other(
            "query_events is unsupported on the gRPC backend; OCS mode \
             ingests events via BagEventPump"
                .into(),
        ))
    }

    async fn get_chain_identifier(&self) -> Result<String, Self::Error> {
        Ok(self.transport.get_chain_identifier().await?)
    }

    async fn get_sui_epoch(&self) -> Result<u64, Self::Error> {
        Ok(self.transport.get_current_epoch().await?)
    }

    async fn get_sui_chain_identifier(&self) -> Result<SuiNetworkChainIdentifier, Self::Error> {
        // The gRPC service-info chain id IS the full genesis checkpoint
        // digest (Base58) — parse it back into the typed identifier.
        let chain_id = self.transport.get_chain_identifier().await?;
        let digest: CheckpointDigest = chain_id.parse().map_err(|e| {
            TransportError::Encoding(format!(
                "service-info chain id {chain_id:?} is not a checkpoint digest: {e}"
            ))
        })?;
        Ok(SuiNetworkChainIdentifier::from(digest))
    }

    async fn get_reference_gas_price(&self) -> Result<u64, Self::Error> {
        Ok(self.writer()?.get_reference_gas_price().await?)
    }

    async fn get_latest_checkpoint_sequence_number(&self) -> Result<u64, Self::Error> {
        let checkpoint = self.transport.get_latest_checkpoint().await?;
        Ok(*checkpoint.sequence_number())
    }

    async fn get_system(&self, ika_system_object_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
        self.object_bcs(ika_system_object_id).await
    }

    async fn get_extended_field_value_bcs(&self, ef_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
        // The ExtendedField wrapper has exactly one dynamic field (`Key()` ->
        // value). List it (don't derive the child id) and read that child's BCS
        // (a `Field<Key, V>`).
        let page = self
            .transport
            .list_dynamic_fields(ef_id, None, None)
            .await?;
        let entry = page.entries.first().ok_or_else(|| {
            GrpcSuiClientError::decode(format!("ExtendedField {ef_id} has no dynamic field"))
        })?;
        // Bind the listed child to the wrapper. The list is untrusted: on the
        // verified relay path a malicious peer could point us at a validly-proven
        // `Field<Key, V>` owned by a DIFFERENT ExtendedField. `get_object`'s owner
        // is proof-bound (verified-read) on a peer-only node, so checking it ==
        // the wrapper id closes the substitution. (No-op on a direct uplink — the
        // owner is then the fullnode's own authoritative answer.)
        let object = self.transport.get_object(entry.object_id).await?;
        if !dynamic_field_child_owned_by(
            object.owner(),
            ef_id,
            &entry.name_type,
            &entry.name_value_bcs,
        ) {
            return Err(GrpcSuiClientError::decode(format!(
                "ExtendedField {ef_id} child {} is owned by {:?}, not the wrapper",
                entry.object_id,
                object.owner()
            )));
        }
        move_object_contents(&object, entry.object_id)
    }

    async fn get_clock(&self, clock_obj_id: ObjectID) -> Result<Vec<u8>, Self::Error> {
        self.object_bcs(clock_obj_id).await
    }

    async fn get_dwallet_coordinator(
        &self,
        dwallet_coordinator_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error> {
        self.object_bcs(dwallet_coordinator_id).await
    }

    /// Unsupported on the gRPC backend: OCS ingests session events via the
    /// `BagEventPump` (`verified_dynamic_fields_page`), which binds every entry to its
    /// parent bag (spec invariant 5). The recovery walk this replaced read each
    /// entry with an inclusion-only `get_object` and SKIPPED that
    /// collection-membership binding, so a relay could have injected a
    /// validly-proven event from a foreign bag. It was already dead here — the
    /// only caller runs solely on the legacy JSON-RPC path (`reader.is_none()`),
    /// which dispatches to the JSON-RPC backend, never this one — so erroring
    /// kills the latent footgun: an accidental future wiring fails loudly rather
    /// than ingesting collection-unbound events. Mirrors `query_events`.
    async fn get_uncompleted_events(
        &self,
        _coordinator_events_bag_id: ObjectID,
    ) -> Result<Vec<DBSuiEvent>, Self::Error> {
        Err(GrpcSuiClientError::Other(
            "get_uncompleted_events is unsupported on the gRPC backend; OCS mode \
             ingests events via BagEventPump (which binds each entry to its bag)"
                .into(),
        ))
    }

    async fn get_mpc_data_from_validators_pool(
        &self,
        validators: &Vec<StakingPool>,
        read_next_mpc_data: bool,
    ) -> Result<HashMap<ObjectID, VersionedMPCData>, Self::Error> {
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
                    tracing::error!(
                        should_never_happen = true,
                        validator_id=?validator.id,
                        "Validator can't have both previous and next epoch MPC data bytes, using current data from epoch",
                    );
                }

                info.mpc_data_bytes.contents.id
            };

            let mpc_data_bytes = self.read_table_vec_as_raw_bytes(mpc_data_id).await?;

            match bcs::from_bytes::<VersionedMPCData>(&mpc_data_bytes) {
                Ok(validator_mpc_data) => {
                    mpc_data_from_all_validators.insert(validator.id, validator_mpc_data);
                }
                Err(e) => {
                    tracing::error!(
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
    ) -> Result<HashMap<ObjectID, DWalletNetworkEncryptionKey>, Self::Error> {
        let mut network_encryption_keys = HashMap::new();
        self.for_each_dynamic_child(
            dwallet_coordinator_inner.dwallet_network_encryption_keys.id,
            |object_id, contents| {
                let value = bcs::from_bytes::<DWalletNetworkEncryptionKey>(&contents)
                    .map_err(GrpcSuiClientError::decode)?;
                network_encryption_keys.insert(object_id, value);
                Ok(())
            },
        )
        .await?;
        Ok(network_encryption_keys)
    }

    async fn get_network_encryption_key_with_full_data_by_epoch(
        &self,
        key: &DWalletNetworkEncryptionKey,
        epoch: EpochId,
    ) -> Result<DWalletNetworkEncryptionKeyData, Self::Error> {
        let network_dkg_public_output = self
            .read_table_vec_as_raw_bytes(key.network_dkg_public_output.contents.id)
            .await?;

        let mut current_reconfiguration_public_output = vec![];

        // Reading the reconfiguration public output during the DKG epoch
        // would error (there's only the NetworkDKG output then), so skip it
        // and serve the DKG output instead.
        if key.dkg_at_epoch == epoch {
            tracing::info!(
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
        let mut found = None;
        self.for_each_dynamic_child(table_id, |_object_id, contents| {
            if found.is_some() {
                return Ok(());
            }
            let reconfig_public_output = bcs::from_bytes::<Field<u64, Table>>(&contents)
                .map_err(GrpcSuiClientError::decode)?;
            if reconfig_public_output.name == epoch_id {
                found = Some(reconfig_public_output.value.id);
            }
            Ok(())
        })
        .await?;
        found.ok_or_else(|| {
            GrpcSuiClientError::Other(format!(
                "failed to load current reconfiguration public output for epoch {epoch_id:?} from table {table_id:?}"
            ))
        })
    }

    async fn read_table_vec_as_raw_bytes(
        &self,
        table_id: ObjectID,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut full_output: HashMap<usize, Vec<u8>> = HashMap::new();
        self.for_each_dynamic_child(table_id, |_object_id, contents| {
            let bytes_chunk = bcs::from_bytes::<Field<u64, Vec<u8>>>(&contents)
                .map_err(GrpcSuiClientError::decode)?;
            full_output.insert(bytes_chunk.name as usize, bytes_chunk.value);
            Ok(())
        })
        .await?;

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
        self.versioned_inner_bcs(ika_system_object_id, version)
            .await
    }

    async fn get_dwallet_coordinator_inner(
        &self,
        dwallet_coordinator_id: ObjectID,
        version: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.versioned_inner_bcs(dwallet_coordinator_id, version)
            .await
    }

    async fn get_validators(
        &self,
        validator_ids: Vec<ObjectID>,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let objects = self.transport.batch_get_objects(&validator_ids).await?;
        objects
            .iter()
            .zip(validator_ids.iter())
            .map(|(object, id)| move_object_contents(object, *id))
            .collect()
    }

    async fn get_validator_inners(
        &self,
        validators: Vec<Validator>,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        // The inner child ids are derivable locally from (parent, version),
        // so the whole validator set is one batch round-trip instead of one
        // per validator.
        let child_ids = validators
            .iter()
            .map(|validator| {
                Self::versioned_child_id(validator.inner.id.id.bytes, validator.inner.version)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let objects = self.transport.batch_get_objects(&child_ids).await?;
        objects
            .iter()
            .zip(child_ids.iter())
            .map(|(object, id)| move_object_contents(object, *id))
            .collect()
    }

    async fn get_mutable_shared_arg(
        &self,
        ika_system_object_id: ObjectID,
    ) -> Result<ObjectArg, Self::Error> {
        self.shared_object_arg(ika_system_object_id, SharedObjectMutability::Mutable)
            .await
    }

    async fn get_shared_arg(&self, obj_id: ObjectID) -> Result<ObjectArg, Self::Error> {
        self.shared_object_arg(obj_id, SharedObjectMutability::Immutable)
            .await
    }

    async fn get_available_move_packages(
        &self,
        _ika_package_id: ObjectID,
        _ika_system_package_id: ObjectID,
    ) -> Result<Vec<(ObjectID, MovePackageDigest)>, Self::Error> {
        // Matches the JSON-RPC backend: this returns an empty set today.
        Ok(vec![])
    }

    async fn execute_transaction_block_with_effects(
        &self,
        tx: Transaction,
    ) -> Result<SuiTransactionBlockResponse, IkaError> {
        let tx_digest = *tx.digest();
        let executed = self
            .writer()
            .map_err(|e| IkaError::SuiClientTxFailureGeneric(tx_digest, e.to_string()))?
            .execute_transaction(&tx)
            .await
            .map_err(|e| IkaError::SuiClientTxFailureGeneric(tx_digest, e.to_string()))?;

        let effects = SuiTransactionBlockEffects::try_from(executed.effects).map_err(|e| {
            IkaError::SuiClientTxFailureGeneric(
                tx_digest,
                format!("can't convert transaction effects: {e}"),
            )
        })?;

        Ok(SuiTransactionBlockResponse {
            digest: tx_digest,
            effects: Some(effects),
            ..Default::default()
        })
    }

    async fn get_gas_objects(&self, address: SuiAddress) -> Vec<ObjectRef> {
        let Ok(writer) = self.writer() else {
            tracing::warn!(
                "get_gas_objects on a read-only node with no writer uplink; returning no gas coins"
            );
            return Vec::new();
        };
        loop {
            match writer.list_owned_gas_coins(address).await {
                Ok(gas_objs) => return gas_objs,
                Err(err) => {
                    tracing::warn!("can't get gas objects for address {address}: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}
