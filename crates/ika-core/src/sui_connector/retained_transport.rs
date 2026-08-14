// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A [`SuiTransport`] decorator a sui-state-direct node puts in front of its
//! mirror server's gRPC transport, so it serves the committee-ratchet
//! primitives — `last_checkpoint_of_epoch` and the end-of-epoch
//! `get_full_checkpoint` — from this node's *retained* store before reaching the
//! (prune-prone) Sui fullnode.
//!
//! A mirrored peer's committee ratchet then advances even after the direct
//! node's fullnode has pruned the end-of-epoch checkpoint it needs, because the
//! pusher captured and persisted that checkpoint (the eager-capture path) when it
//! streamed past — `sui_end_of_epoch_seqs` and `sui_end_of_epoch_checkpoints` in
//! the perpetual tables. Every other method delegates straight to the inner
//! transport. The mirrored peer re-verifies the committee-signed summary it gets
//! back, so this is a serving optimization, not a trust change.

use std::sync::Arc;

use async_trait::async_trait;
use sui_types::base_types::{ObjectID, SequenceNumber, TransactionDigest};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;

use ika_sui_client::transport::{
    DynamicFieldPage, ExecutedTransaction, SuiTransport, TransportError,
};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;

pub struct RetainedFullnodeTransport {
    inner: Arc<dyn SuiTransport>,
    perpetual: Arc<AuthorityPerpetualTables>,
}

impl RetainedFullnodeTransport {
    pub fn new(inner: Arc<dyn SuiTransport>, perpetual: Arc<AuthorityPerpetualTables>) -> Self {
        Self { inner, perpetual }
    }
}

#[async_trait]
impl SuiTransport for RetainedFullnodeTransport {
    // -- served from the retained store first, then the fullnode ---------------------------
    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        if let Ok(Some(seq)) = self.perpetual.get_sui_end_of_epoch_seq(epoch) {
            return Ok(seq);
        }
        self.inner.last_checkpoint_of_epoch(epoch).await
    }
    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        if let Ok(Some(checkpoint)) = self.perpetual.get_sui_end_of_epoch_checkpoint(seq) {
            return Ok(checkpoint);
        }
        self.inner.get_full_checkpoint(seq).await
    }

    // -- delegated -------------------------------------------------------------------------
    async fn get_chain_identifier(&self) -> Result<String, TransportError> {
        self.inner.get_chain_identifier().await
    }
    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        self.inner.get_current_epoch().await
    }
    async fn get_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        self.inner.get_committee(epoch).await
    }
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.inner.get_latest_checkpoint().await
    }
    async fn get_latest_checkpoint_sequence(
        &self,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        // Forward explicitly (see the fallback transport) so a direct
        // inner transport keeps its pruning-immune probe through this
        // wrapper.
        self.inner.get_latest_checkpoint_sequence().await
    }
    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: sui_types::digests::CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.inner.get_checkpoint_summary_by_digest(digest).await
    }
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
        self.inner.get_object(id).await
    }
    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        self.inner.get_object_with_version(id, version).await
    }
    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        self.inner.batch_get_objects(ids).await
    }
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        self.inner
            .list_dynamic_fields(parent, page_size, page_token)
            .await
    }
    async fn get_transaction(
        &self,
        tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        self.inner.get_transaction(tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_types::committee::Committee;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{CheckpointContents, CheckpointSummary};

    fn checkpoint_at(seq: u64) -> CheckpointData {
        let (committee, keys) = Committee::new_simple_test_committee();
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: 0,
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: None,
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, &keys, &committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    /// An inner transport that panics on the two primitives the wrapper is
    /// supposed to serve from the retained store — so a delegation is a test
    /// failure. Everything else is unused.
    struct PanicTransport;
    #[async_trait]
    impl SuiTransport for PanicTransport {
        async fn get_full_checkpoint(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            panic!("delegated to the fullnode despite a retained checkpoint")
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            panic!("delegated to the fullnode despite a retained end-of-epoch seq")
        }
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(
            &self,
            _epoch: Option<u64>,
        ) -> Result<sui_types::committee::Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: sui_types::digests::CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn serves_committee_primitives_from_the_retained_store() {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let checkpoint = checkpoint_at(42);
        perpetual
            .put_sui_end_of_epoch_checkpoint(42, &checkpoint)
            .unwrap();
        perpetual.put_sui_end_of_epoch_seq(7, 42).unwrap();

        let wrapper = RetainedFullnodeTransport::new(Arc::new(PanicTransport), perpetual.clone());

        // Both served from the retained store — PanicTransport panics on delegation.
        let got = wrapper.get_full_checkpoint(42).await.unwrap();
        assert_eq!(*got.checkpoint_summary.sequence_number(), 42);
        assert_eq!(wrapper.last_checkpoint_of_epoch(7).await.unwrap(), 42);

        // Retention prune drops it below the floor; a later read would then
        // delegate (here there's nothing below 42 to keep, so 42 is dropped).
        perpetual.retain_sui_end_of_epoch_checkpoints(43).unwrap();
        assert!(
            perpetual
                .get_sui_end_of_epoch_checkpoint(42)
                .unwrap()
                .is_none()
        );
    }

    /// An inner transport that *answers* the two retained primitives with
    /// sentinel values — so a successful delegation is observable (the opposite
    /// of `PanicTransport`).
    struct DelegateTransport;
    #[async_trait]
    impl SuiTransport for DelegateTransport {
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            Ok(checkpoint_at(seq))
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            Ok(999)
        }
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unimplemented!()
        }
        async fn get_committee(
            &self,
            _epoch: Option<u64>,
        ) -> Result<sui_types::committee::Committee, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: sui_types::digests::CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// When the retained store yields no value for the two committee-ratchet
    /// primitives, the wrapper delegates to the inner transport rather than
    /// surfacing the absence as an error.
    ///
    /// Note on the literal "DB error" case: the wrapper's guard is
    /// `if let Ok(Some(..)) = self.perpetual.get_*()`, so a getter returning
    /// `Err(_)` falls through to `self.inner` on *exactly the same branch* as
    /// `Ok(None)`. `RetainedFullnodeTransport` holds a concrete
    /// `AuthorityPerpetualTables` (not a trait), and its end-of-epoch columns
    /// are `pub(crate)` — so there is no in-crate seam to inject a `TypedStore`
    /// error from this module without a production refactor or a corrupted DB.
    /// This test drives the delegation via the observable `Ok(None)` path, which
    /// covers the identical fall-through the `Err(_)` arm would take.
    #[tokio::test]
    async fn db_error_on_retained_lookup_delegates_to_inner() {
        let dir = tempfile::tempdir().unwrap();
        // An EMPTY perpetual store: every retained-store lookup returns
        // `Ok(None)`, so both primitives must fall through to the inner transport.
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let wrapper = RetainedFullnodeTransport::new(Arc::new(DelegateTransport), perpetual);

        // Nothing retained → delegate. The inner transport's sentinels prove the
        // delegation happened (rather than an error or a retained-store hit).
        assert_eq!(wrapper.last_checkpoint_of_epoch(7).await.unwrap(), 999);
        let got = wrapper.get_full_checkpoint(55).await.unwrap();
        assert_eq!(*got.checkpoint_summary.sequence_number(), 55);
    }
}
