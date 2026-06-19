// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! [`SuiTransport`] for a *peer-only* validator: one running sui-state-mirrored
//! with **no** `fallback_grpc_url`, i.e. with no direct full-node uplink at all.
//!
//! Such a node has to serve its `sui_client` reads — including the boot-time
//! bootstrap of the IKA committee / epoch state — entirely over the OCS relay,
//! and every one of those reads must be verified against the committee (there's
//! no trusted direct connection to fall back on).
//!
//! This adapter bridges the two existing relay surfaces into the one
//! [`SuiTransport`] the gRPC backend expects:
//!
//! - **objects + dynamic fields** are served by [`OcsVerifiedReader`], whose
//!   `verified_object` / `verified_bag_page` check each object against the
//!   committee via an inclusion proof. Object reads are *version-tracked*
//!   (the reader's per-object high-water mark): an inclusion proof only shows
//!   the object existed at *some* checkpoint, so without monotonicity a
//!   malicious relay could replay an older proof-valid state — and the
//!   high-water mark is the reader's designated freshness defense (no
//!   checkpoint-distance bound is configured; see the reader construction in
//!   `setup.rs`). Tracking is memory-safe here because every id on this path
//!   is long-lived (the System/Coordinator wrappers, their versioned inners,
//!   validator objects, table entries); the short-lived session-event bag
//!   children never flow through `get_object` — the legacy uncompleted-events
//!   walk that would fetch them is gated off whenever the OCS stack (and thus
//!   this transport) exists. The gRPC backend's high-level reads
//!   (`get_system_inner`, `get_dwallet_coordinator_inner`, the table walks)
//!   decompose into exactly `get_object` + `list_dynamic_fields` +
//!   `batch_get_objects`, so layering the stock backend over this transport
//!   yields verified high-level reads for free.
//! - **chain metadata + checkpoints** (`get_chain_identifier`,
//!   `get_reference_gas_price`, the checkpoint lookups, `get_transaction_checkpoint`)
//!   pass through to the relay transport (`SuiMirrorTransport`), which already
//!   serves them.
//!
//! A peer-only validator never submits transactions (the writer path is
//! notifier-gated — only the notifier, which is *not* peer-only, holds gas and
//! writes) and holds no gas, so `execute_transaction`, `list_owned_gas_coins`,
//! `get_committee` (the ratchet's prune fallback), `get_transaction`, and
//! pinned-version object reads are unreachable on this node and return a
//! descriptive error rather than silently wrong data.

use std::sync::Arc;

use async_trait::async_trait;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::digests::CheckpointDigest;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;

use ika_sui_client::transport::{
    DynamicFieldEntry, DynamicFieldPage, ExecutedTransaction, SubmittedTransaction, SuiTransport,
    TransportError,
};

use crate::sui_connector::verified_reader::OcsVerifiedReader;

pub struct VerifiedSuiTransport {
    /// Verified object / dynamic-field reads (committee-checked per read).
    reader: Arc<OcsVerifiedReader>,
    /// Relay transport (`SuiMirrorTransport`) for chain-metadata + checkpoint
    /// reads the verified reader doesn't cover.
    relay: Arc<dyn SuiTransport>,
}

impl VerifiedSuiTransport {
    pub fn new(reader: Arc<OcsVerifiedReader>, relay: Arc<dyn SuiTransport>) -> Self {
        Self { reader, relay }
    }

    /// Error for a method that cannot be served on a peer-only validator.
    fn unreachable(method: &str) -> TransportError {
        TransportError::Network(format!(
            "{method} is unreachable on a peer-only validator (sui-state-mirrored, no \
             fallback_grpc_url): it has no direct Sui uplink and submits no transactions"
        ))
    }

    fn read_err(e: impl std::fmt::Display) -> TransportError {
        TransportError::Network(format!("verified relay read failed: {e}"))
    }
}

#[async_trait]
impl SuiTransport for VerifiedSuiTransport {
    // -- chain metadata: relay ----------------------------------------------------------------
    async fn get_chain_identifier(&self) -> Result<String, TransportError> {
        self.relay.get_chain_identifier().await
    }
    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        self.relay.get_current_epoch().await
    }
    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        self.relay.get_reference_gas_price().await
    }
    async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
        // The ratchet's prune fallback. A peer-only node has no direct uplink,
        // so a broken proof chain surfaces as OcsError::ProofChainBroken
        // instead of an unverified committee fetch.
        Err(Self::unreachable("get_committee"))
    }

    // -- checkpoints: relay -------------------------------------------------------------------
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.relay.get_latest_checkpoint().await
    }
    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        self.relay.get_full_checkpoint(seq).await
    }
    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.relay.get_checkpoint_summary_by_digest(digest).await
    }
    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.relay.last_checkpoint_of_epoch(epoch).await
    }

    // -- objects: verified reader (version-tracked; see module docs) ---------------------------
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
        self.reader
            .verified_object(id)
            .await
            .map(|verified| verified.object)
            .map_err(Self::read_err)
    }
    async fn get_object_with_version(
        &self,
        _id: ObjectID,
        _version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        // The verified surface serves the latest verified version; a
        // pinned-version read isn't on the peer-only read path. Erroring
        // (rather than returning the latest) avoids silently substituting a
        // different version than the caller asked for.
        Err(Self::unreachable("get_object_with_version"))
    }
    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        self.reader
            .verified_objects(ids)
            .await
            .map(|verified| verified.into_iter().map(|v| v.object).collect())
            .map_err(Self::read_err)
    }
    async fn list_owned_gas_coins(
        &self,
        _address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        Err(Self::unreachable("list_owned_gas_coins"))
    }

    // -- dynamic fields: verified bag page ----------------------------------------------------
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        let page = self
            .reader
            .verified_bag_page(parent, page_size, page_token)
            .await
            .map_err(Self::read_err)?;
        // The verified bag surface carries object identity, not the field-name
        // metadata. That's sufficient here: every consumer of the backend's
        // dynamic-field walk uses only `object_id` and parses the field name
        // out of the child object's own BCS contents (`Field<u64, _>`).
        let entries = page
            .entries
            .iter()
            .map(|verified| DynamicFieldEntry {
                object_id: verified.object.id(),
                name_type: String::new(),
                name_value_bcs: Vec::new(),
            })
            .collect();
        Ok(DynamicFieldPage {
            entries,
            next_page_token: page.next_page_token,
        })
    }

    // -- transactions -------------------------------------------------------------------------
    async fn get_transaction(
        &self,
        _tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        Err(Self::unreachable("get_transaction"))
    }
    async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        self.relay.get_transaction_checkpoint(tx).await
    }
    async fn execute_transaction(
        &self,
        _tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        Err(Self::unreachable("execute_transaction"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ika_network::proof_provider::{
        BatchVerifiedObjectsResponse, ProofProvider, VerifiedBagPageRequest,
        VerifiedBagPageResponse, VerifiedObjectResponse,
    };
    use sui_types::committee::Committee as SuiCommittee;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::{CommitteeBootstrap, CommitteeStore};
    use crate::sui_connector::ocs_metrics::OcsMetrics;
    use crate::sui_connector::verified_state_cache::VerifiedStateCache;

    /// A proof provider whose every read fails with a `Network` error. Lets us
    /// prove `get_object` / `batch_get_objects` map a reader-layer failure to a
    /// transport `Network` error (fail closed — never silently return data).
    struct FailingProvider;

    #[async_trait]
    impl ProofProvider for FailingProvider {
        async fn verified_object(
            &self,
            _id: ObjectID,
        ) -> Result<VerifiedObjectResponse, TransportError> {
            Err(TransportError::Network("provider down".into()))
        }
        async fn batch_verified_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<BatchVerifiedObjectsResponse, TransportError> {
            Err(TransportError::Network("provider down".into()))
        }
        async fn verified_bag_page(
            &self,
            _request: VerifiedBagPageRequest,
        ) -> Result<VerifiedBagPageResponse, TransportError> {
            Err(TransportError::Network("provider down".into()))
        }
    }

    /// A relay that panics on every call: the peer-only-unreachable methods and
    /// the reader-delegating object reads must never touch the relay, so any
    /// call here is a test failure.
    struct PanickingRelay;

    #[async_trait]
    impl SuiTransport for PanickingRelay {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_full_checkpoint(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn list_owned_gas_coins(
            &self,
            _address: SuiAddress,
        ) -> Result<Vec<ObjectRef>, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn get_transaction_checkpoint(
            &self,
            _tx: TransactionDigest,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
        async fn execute_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<SubmittedTransaction, TransportError> {
            unreachable!("relay must not be hit by this test")
        }
    }

    fn transport_over_stubs() -> (tempfile::TempDir, VerifiedSuiTransport) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let (committee, _keys) = SuiCommittee::new_simple_test_committee_of_size(4);
        let committees = Arc::new(
            CommitteeStore::open(tables, Some(CommitteeBootstrap::UnsafeGenesis(committee)))
                .unwrap(),
        );
        let reader = Arc::new(OcsVerifiedReader::new(
            Arc::new(FailingProvider),
            committees,
            OcsMetrics::new_for_testing(),
            None,
            Arc::new(VerifiedStateCache::new()),
            false,
            None,
        ));
        let transport = VerifiedSuiTransport::new(reader, Arc::new(PanickingRelay));
        (dir, transport)
    }

    fn network_message(err: TransportError) -> String {
        match err {
            TransportError::Network(msg) => msg,
            other => panic!("expected TransportError::Network, got {other:?}"),
        }
    }

    /// Invariant 6 (fail closed, never silently return data): every method a
    /// peer-only validator can't serve returns a `Network` error whose message
    /// names the method and says it's unreachable on a peer-only validator —
    /// rather than silently returning wrong or stale data.
    #[tokio::test]
    async fn unreachable_methods_error_with_descriptive_message() {
        let (_dir, transport) = transport_over_stubs();
        let id = ObjectID::random();

        // The genuinely-unreachable methods: descriptive, method-naming errors.
        let cases: Vec<(&str, TransportError)> = vec![
            (
                "get_committee",
                transport.get_committee(None).await.unwrap_err(),
            ),
            (
                "get_object_with_version",
                transport
                    .get_object_with_version(id, SequenceNumber::from(1u64))
                    .await
                    .unwrap_err(),
            ),
            (
                "list_owned_gas_coins",
                transport
                    .list_owned_gas_coins(SuiAddress::ZERO)
                    .await
                    .unwrap_err(),
            ),
            (
                "get_transaction",
                transport
                    .get_transaction(TransactionDigest::random())
                    .await
                    .unwrap_err(),
            ),
            (
                "execute_transaction",
                transport
                    .execute_transaction(&dummy_transaction())
                    .await
                    .unwrap_err(),
            ),
        ];
        for (method, err) in cases {
            let msg = network_message(err);
            assert!(
                msg.contains(method),
                "{method} error must name the method, got: {msg}"
            );
            assert!(
                msg.contains("unreachable on a peer-only validator"),
                "{method} error must say it's unreachable on a peer-only validator, got: {msg}"
            );
        }

        // get_object / batch_get_objects delegate to the reader and map a reader
        // failure to a `Network` error — fail closed, never silently empty.
        let object_err = network_message(transport.get_object(id).await.unwrap_err());
        assert!(
            object_err.contains("verified relay read failed"),
            "get_object must map a reader failure to a descriptive Network error, got: {object_err}"
        );
        let batch_err = network_message(transport.batch_get_objects(&[id]).await.unwrap_err());
        assert!(
            batch_err.contains("verified relay read failed"),
            "batch_get_objects must map a reader failure to a descriptive Network error, \
             got: {batch_err}"
        );
    }

    /// A syntactically-valid but empty transaction, only as an
    /// `execute_transaction` argument — the method errors before inspecting it.
    fn dummy_transaction() -> Transaction {
        use sui_types::base_types::ObjectDigest;
        use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
        use sui_types::transaction::{TransactionData, TransactionKind};

        let pt = ProgrammableTransactionBuilder::new().finish();
        let data = TransactionData::new(
            TransactionKind::ProgrammableTransaction(pt),
            SuiAddress::ZERO,
            (
                ObjectID::ZERO,
                SequenceNumber::from(0u64),
                ObjectDigest::MIN,
            ),
            0,
            0,
        );
        Transaction::from_data(data, vec![])
    }
}
