// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A [`SuiTransport`] decorator that splits operations between a primary
//! transport (typically the relayed [`SuiMirrorTransport`]) and a direct gRPC
//! fallback for the four methods that cannot be relayed:
//!
//! - `get_committee` — only used by the OCS ratchet's prune fallback path.
//! - `get_transaction` — returns `sui_rpc_api::client::ExecutedTransaction`,
//!   which is `Serialize`-only (not `Deserialize`), so the relay can't carry
//!   it back over the wire.
//! - `execute_transaction` — same `ExecutedTransaction` constraint.
//! - `list_owned_gas_coins` — owned coins aren't in the OCS-mirrored set, and
//!   gas selection is a tx-submission concern (routes with the writer).
//!
//! Trust is preserved: the OCS verifier validates everything either path
//! returns. The fallback is simply a different uplink for the operator.
//!
//! When no `fallback_grpc_url` is configured, the operator can still run
//! sui-state-mirrored; the relay's errors on those four methods just propagate. The
//! ratchet keeps working as long as the upstream isn't pruned past our
//! committee head, and sui-state-mirrored validators don't submit transactions through
//! the OCS path anyway.

use std::sync::Arc;

use async_trait::async_trait;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;

use ika_sui_client::transport::{
    DynamicFieldPage, ExecutedTransaction, SubmittedTransaction, SuiTransport, TransportError,
};

pub struct FallbackTransport {
    /// Primary transport. In sui-state-mirrored this is `SuiMirrorTransport`.
    primary: Arc<dyn SuiTransport>,
    /// Direct-gRPC fallback used for the four un-relayable methods.
    fallback: Arc<dyn SuiTransport>,
}

impl FallbackTransport {
    pub fn new(primary: Arc<dyn SuiTransport>, fallback: Arc<dyn SuiTransport>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl SuiTransport for FallbackTransport {
    // -- relayed (primary) ----------------------------------------------------------------
    async fn get_chain_identifier(&self) -> Result<String, TransportError> {
        self.primary.get_chain_identifier().await
    }
    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        self.primary.get_current_epoch().await
    }
    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        self.primary.get_reference_gas_price().await
    }
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.primary.get_latest_checkpoint().await
    }
    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        self.primary.get_full_checkpoint(seq).await
    }
    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: sui_types::digests::CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.primary.get_checkpoint_summary_by_digest(digest).await
    }
    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.primary.last_checkpoint_of_epoch(epoch).await
    }
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
        self.primary.get_object(id).await
    }
    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        self.primary.get_object_with_version(id, version).await
    }
    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        self.primary.batch_get_objects(ids).await
    }
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        self.primary
            .list_dynamic_fields(parent, page_size, page_token)
            .await
    }
    async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.primary.get_transaction_checkpoint(tx).await
    }

    // -- direct-gRPC fallback (un-relayable) ----------------------------------------------
    async fn get_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        self.fallback.get_committee(epoch).await
    }
    async fn get_transaction(
        &self,
        tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        self.fallback.get_transaction(tx).await
    }
    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        self.fallback.execute_transaction(tx).await
    }
    async fn list_owned_gas_coins(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        // Gas selection is a tx-submission concern; route to the direct-gRPC
        // fallback for the same reason `execute_transaction` does.
        self.fallback.list_owned_gas_coins(address).await
    }
}
