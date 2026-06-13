// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Source-agnostic Sui read/write surface.
//!
//! Two implementations exist:
//! - [`crate::grpc::SuiGrpcClient`]: direct gRPC to a Sui fullnode.
//! - `SuiMirrorTransport` (in `ika-network`): peer-relayed reads via Ika p2p.
//!
//! `CheckpointCache` (in `ika-core::sui_connector`) decorates either of these
//! with an L1 in-memory cache and an L2 backed by `AuthorityPerpetualTables`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
pub use sui_rpc_api::client::ExecutedTransaction;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::digests::CheckpointDigest;
use sui_types::effects::TransactionEffects;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;

/// Minimal, transport-agnostic result of submitting a transaction: the tx
/// digest plus its committed [`TransactionEffects`]. Unlike
/// `sui_rpc_api::client::ExecutedTransaction` (which has private fields and a
/// `Serialize`-only shape), this is constructible *and* `Deserialize`-able, so
/// it can be carried back over the anemo relay for a peer-only validator. The
/// only field any caller reads is `effects` (status / object changes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmittedTransaction {
    pub digest: TransactionDigest,
    pub effects: TransactionEffects,
}

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("transport: {0}")]
    Network(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Deterministically-derived `Field<u64, _>` child id for `(parent, version)`.
/// This is how Sui's versioned-object pattern stores the inner struct: a
/// dynamic field on the wrapper keyed by the wrapper's `version`.
pub fn derive_versioned_child_id(parent: ObjectID, version: u64) -> Result<ObjectID, String> {
    let name_bytes = bcs::to_bytes(&version).map_err(|e| format!("encode u64 name: {e}"))?;
    sui_types::dynamic_field::derive_dynamic_field_id(parent, &sui_types::TypeTag::U64, &name_bytes)
        .map_err(|e| format!("derive child id: {e}"))
}

/// Borrowed BCS contents of a Move object; `None` when the object is a
/// package. Callers attach their own error context.
pub fn move_object_contents(object: &Object) -> Option<&[u8]> {
    object.data.try_as_move().map(|m| m.contents())
}

/// Lean view of a single dynamic-field entry. Independent of any specific
/// transport encoding (proto, JSON-RPC, anemo) so that consumers don't bind
/// to one source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicFieldEntry {
    pub object_id: ObjectID,
    /// Stringified `TypeTag` of the field's name. Use this to interpret
    /// `name_value_bcs` correctly.
    pub name_type: String,
    /// BCS-encoded name value. For a `u64`-named field decode with
    /// `bcs::from_bytes::<u64>(&name_value_bcs)`.
    pub name_value_bcs: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicFieldPage {
    pub entries: Vec<DynamicFieldEntry>,
    pub next_page_token: Option<Vec<u8>>,
}

#[async_trait]
pub trait SuiTransport: Send + Sync {
    // -- chain metadata ---------------------------------------------------------------------
    async fn get_chain_identifier(&self) -> Result<String, TransportError>;
    async fn get_current_epoch(&self) -> Result<u64, TransportError>;
    async fn get_reference_gas_price(&self) -> Result<u64, TransportError>;
    /// Sui [`Committee`] for the given epoch (or current if `None`). Used as
    /// a fallback when the committee ratchet's BLS proof chain is broken
    /// by upstream pruning of end-of-epoch checkpoints.
    async fn get_committee(&self, epoch: Option<u64>) -> Result<Committee, TransportError>;

    // -- checkpoints ------------------------------------------------------------------------
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError>;
    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError>;
    /// Look up a `CertifiedCheckpointSummary` by its digest. Used at
    /// boot for the trust-anchor verification: caller's pinned digest
    /// is the lookup key *and* the trust gate.
    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError>;
    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError>;

    // -- objects ----------------------------------------------------------------------------
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError>;
    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError>;
    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError>;
    /// Owned SUI gas-coin object refs for `address`. Mirrors the JSON-RPC
    /// `get_gas_objects` selection: filters owned objects to the SUI
    /// `GasCoin` struct type and returns their `ObjectRef`s. Used to pick
    /// gas for transaction submission.
    async fn list_owned_gas_coins(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError>;

    // -- dynamic fields ---------------------------------------------------------------------
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError>;

    // -- transactions -----------------------------------------------------------------------
    async fn get_transaction(
        &self,
        tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError>;
    /// Convenience: returns the checkpoint sequence in which `tx` was committed.
    /// Errors if the tx isn't yet finalized in any checkpoint.
    async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError>;
    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError>;
}
