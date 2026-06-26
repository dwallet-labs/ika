// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Source-agnostic Sui read/write surface.
//!
//! Two implementations exist:
//! - [`crate::grpc::SuiGrpcClient`]: direct gRPC to a Sui fullnode.
//! - `SuiMirrorTransport` (in `ika-network`): peer-relayed reads via Ika p2p.

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
pub use sui_rpc_api::client::ExecutedTransaction;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::digests::CheckpointDigest;
use sui_types::effects::TransactionEffects;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::{Object, Owner};
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

/// Deterministically-derived `Field` wrapper id for a dynamic *object* field
/// `(parent, name)`, given the stringified `TypeTag` of the unwrapped key and
/// its BCS-encoded value. Returns `None` if the key type doesn't parse.
///
/// Used to bind a relay-walked collection entry to its parent: in an
/// `ObjectTable`/`ObjectBag` the resolved entry is the wrapped value object,
/// which is owned by its `Field<Wrapper<K>, ID>` wrapper — and that wrapper's
/// id is this derivation. The on-chain key is *not* the bare `K`; it is
/// `0x2::dynamic_object_field::Wrapper<K>`. The gRPC `list_dynamic_fields`
/// reports the *unwrapped* inner key type (its field visitor strips the
/// wrapper), so we re-wrap before deriving. The key *bytes* need no change: a
/// single-field `Wrapper` BCS-encodes identically to its inner value.
///
/// Since the derivation is collision-resistant and the value object's owner is
/// committee-proven, a relay cannot supply a name that derives to a foreign
/// object's owner.
pub fn derive_object_field_wrapper_id(
    parent: ObjectID,
    name_type: &str,
    name_value_bcs: &[u8],
) -> Option<ObjectID> {
    let inner = sui_types::TypeTag::from_str(name_type).ok()?;
    let wrapper = sui_types::TypeTag::Struct(Box::new(
        sui_types::dynamic_field::DynamicFieldInfo::dynamic_object_field_wrapper(inner),
    ));
    sui_types::dynamic_field::derive_dynamic_field_id(parent, &wrapper, name_value_bcs).ok()
}

/// True iff a *proof-bound* `owner` proves the object is a genuine dynamic-field
/// child of `parent` — the single binding check for every "listed, then read"
/// dynamic field, so a relay can't substitute a validly-proven field of a
/// *different* collection (the list itself is untrusted).
///
/// - A plain `Field<K, V>` — a `Bag`/`Table` entry, or the value of an
///   `ExtendedField` — is owned directly by the parent UID
///   (`Owner::ObjectOwner(parent)`).
/// - A dynamic OBJECT field (`ObjectTable`/`ObjectBag`) resolves to the wrapped
///   value, owned by its derived `Field<Wrapper<K>, ID>` id; the entry's
///   (untrusted) `name_type` / `name_value_bcs` are accepted only because the
///   derivation is collision-resistant against the proven owner.
///
/// Any non-`ObjectOwner` owner is rejected: a genuine dynamic field is always
/// object-owned by its parent.
pub fn dynamic_field_child_owned_by(
    owner: &Owner,
    parent: ObjectID,
    name_type: &str,
    name_value_bcs: &[u8],
) -> bool {
    match owner {
        Owner::ObjectOwner(addr) => {
            let owner_id = ObjectID::from(*addr);
            owner_id == parent
                || derive_object_field_wrapper_id(parent, name_type, name_value_bcs)
                    .is_some_and(|field_id| owner_id == field_id)
        }
        _ => false,
    }
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

/// A live stream of certified checkpoint summaries (summary + BLS signature
/// only — no contents/objects). `'static` and `Send` so it can be driven from
/// a spawned task.
pub type CheckpointSummaryStream =
    BoxStream<'static, Result<CertifiedCheckpointSummary, TransportError>>;

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
    /// Subscribe to the live tail of certified checkpoint summaries (summary +
    /// signature only, carrying `end_of_epoch_data.next_epoch_committee` on
    /// boundary checkpoints). Served from the fullnode's in-memory checkpoint
    /// broadcast, so — unlike a reach-back [`Self::get_full_checkpoint`] — it is
    /// **independent of object pruning**: the OCS committee chain can capture
    /// `committee[E+1]` live as the end-of-epoch summary streams by, before the
    /// fullnode prunes that checkpoint's objects.
    ///
    /// Live-tail only: yields checkpoints from subscribe-time forward, with no
    /// historical backfill. Catching up across a gap (cold start / restart) is
    /// the committee ratchet's job, not this stream's.
    ///
    /// Only the direct gRPC transport implements this; every other transport
    /// (peer-relay mirror, decorators, mocks) returns the default unsupported
    /// error, since only sui-state-direct nodes follow the Sui stream.
    async fn subscribe_checkpoint_summaries(
        &self,
    ) -> Result<CheckpointSummaryStream, TransportError> {
        Err(TransportError::Network(
            "checkpoint summary subscription is only supported by the direct gRPC transport"
                .to_string(),
        ))
    }

    // -- objects ----------------------------------------------------------------------------
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError>;
    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError>;
    /// Fetch all of `ids` in one round-trip. **Same-order, same-length,
    /// all-or-nothing:** on success the returned vec has exactly one object per
    /// id, positionally aligned with `ids` (callers correlate by `.zip(ids)`).
    /// If *any* id is missing or deleted the whole call fails with a
    /// [`TransportError`] rather than returning a short or reordered vec — so a
    /// successful result is always `len() == ids.len()` in input order, and
    /// callers never silently mis-correlate. (The gRPC backend gets this from
    /// the underlying client's all-or-nothing collect; the mirror surface
    /// doesn't serve it — use `ProofProvider::batch_verified_objects`.)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sui_types::dynamic_field::{DynamicFieldInfo, derive_dynamic_field_id};

    fn wrapper_tag(inner: sui_types::TypeTag) -> sui_types::TypeTag {
        sui_types::TypeTag::Struct(Box::new(DynamicFieldInfo::dynamic_object_field_wrapper(
            inner,
        )))
    }

    /// The dynamic *object* field id derives from `Wrapper<K>`, not the bare
    /// `K` — re-wrapping must change the id, and the result must equal the
    /// canonical `Wrapper<K>` derivation Sui's `dynamic_object_field::add`
    /// uses on-chain. This is what binds an ObjectTable/ObjectBag entry to its
    /// parent in `verified_dynamic_fields_page`; a regression that dropped the wrapper
    /// would silently let a relay substitute a foreign-owned entry.
    #[test]
    fn wrapper_id_re_wraps_and_matches_the_object_field_layout() {
        let parent = ObjectID::from_single_byte(0x42);
        let name_bcs = bcs::to_bytes(&7u64).unwrap();

        let wrapped = derive_object_field_wrapper_id(parent, "u64", &name_bcs).unwrap();
        let bare = derive_dynamic_field_id(parent, &sui_types::TypeTag::U64, &name_bcs).unwrap();
        assert_ne!(wrapped, bare, "must derive from Wrapper<K>, not bare K");

        let canonical =
            derive_dynamic_field_id(parent, &wrapper_tag(sui_types::TypeTag::U64), &name_bcs)
                .unwrap();
        assert_eq!(wrapped, canonical);
    }

    /// The `dwallet_network_encryption_keys` ObjectTable is keyed by `ID`;
    /// the gRPC reports the unwrapped inner type as a canonical string.
    #[test]
    fn wrapper_id_works_for_an_id_keyed_object_table() {
        let parent = ObjectID::from_single_byte(0x11);
        let key_id = ObjectID::from_single_byte(0x99);
        let name_bcs = bcs::to_bytes(&key_id).unwrap();
        let id_type =
            "0x0000000000000000000000000000000000000000000000000000000000000002::object::ID";

        let wrapped = derive_object_field_wrapper_id(parent, id_type, &name_bcs).unwrap();
        let inner = sui_types::TypeTag::from_str(id_type).unwrap();
        assert_eq!(
            wrapped,
            derive_dynamic_field_id(parent, &wrapper_tag(inner), &name_bcs).unwrap()
        );
    }

    #[test]
    fn wrapper_id_rejects_an_unparseable_type() {
        let parent = ObjectID::from_single_byte(0x01);
        assert!(derive_object_field_wrapper_id(parent, "not a valid type", &[]).is_none());
    }

    /// The dynamic-field binding accepts ONLY a proof-bound owner that is the
    /// parent UID (plain `Field<K,V>` / `ExtendedField` value) or the derived
    /// `Wrapper<K>` id (dynamic object field). A child owned by a *different*
    /// collection — the relay-substitution attack — is rejected.
    #[test]
    fn dynamic_field_binding_accepts_only_the_parent_or_wrapper_owner() {
        let parent = ObjectID::from_single_byte(0x42);
        let foreign = ObjectID::from_single_byte(0x99);
        let name_bcs = bcs::to_bytes(&7u64).unwrap();

        // Plain Field<K, V> (Bag/Table entry, ExtendedField value): owned by the
        // parent UID directly.
        assert!(dynamic_field_child_owned_by(
            &Owner::ObjectOwner(parent.into()),
            parent,
            "u64",
            &name_bcs,
        ));

        // Dynamic OBJECT field: owned by the derived Wrapper<K> id.
        let wrapper = derive_object_field_wrapper_id(parent, "u64", &name_bcs).unwrap();
        assert!(dynamic_field_child_owned_by(
            &Owner::ObjectOwner(wrapper.into()),
            parent,
            "u64",
            &name_bcs,
        ));

        // SUBSTITUTION: a validly-proven child owned by a different collection.
        assert!(!dynamic_field_child_owned_by(
            &Owner::ObjectOwner(foreign.into()),
            parent,
            "u64",
            &name_bcs,
        ));

        // A non-object owner is never a dynamic-field child of `parent`.
        assert!(!dynamic_field_child_owned_by(
            &Owner::AddressOwner(parent.into()),
            parent,
            "u64",
            &name_bcs,
        ));
        assert!(!dynamic_field_child_owned_by(
            &Owner::Immutable,
            parent,
            "u64",
            &name_bcs,
        ));
    }
}
