// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! A [`SuiTransport`] decorator that splits operations between a primary
//! transport (typically the relayed [`SuiMirrorTransport`]) and a direct gRPC
//! fallback for the two read methods it routes directly:
//!
//! - `get_committee` — not served as a verified read; only the OCS ratchet's
//!   prune fallback path needs it.
//! - `get_transaction` — returns Ika's `ExecutedTransaction` compatibility
//!   view, which is `Serialize`-only (not `Deserialize`), so the relay can't
//!   carry it back over the wire — genuinely un-relayable.
//!
//! (Transaction *writing* — submission, gas price, gas-coin selection — is not
//! a `SuiTransport` concern at all: it lives on `SuiWriter`, implemented only by
//! a direct gRPC client. A read-only mirrored node simply has no writer.)
//!
//! Trust is preserved: the OCS verifier validates everything either path
//! returns. The fallback is simply a different uplink for the operator.
//!
//! When no `fallback_grpc_url` is configured, the operator can still run
//! sui-state-mirrored: the relay errors on `get_committee` / `get_transaction`,
//! which is fine — the ratchet keeps working as long as the upstream isn't
//! pruned past our committee head, and sui-state-mirrored validators don't
//! submit transactions through the OCS path anyway (writes are notifier-gated).

use std::sync::Arc;

use async_trait::async_trait;
use sui_types::base_types::{ObjectID, SequenceNumber, TransactionDigest};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;

use ika_sui_client::transport::{
    DynamicFieldPage, ExecutedTransaction, SuiTransport, TransportError,
};

pub struct FallbackTransport {
    /// Primary transport. In sui-state-mirrored this is `SuiMirrorTransport`.
    primary: Arc<dyn SuiTransport>,
    /// Direct-gRPC fallback used for the two directly-routed read methods.
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
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        self.primary.get_latest_checkpoint().await
    }
    async fn get_latest_checkpoint_sequence(
        &self,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        // Forward explicitly so a DIRECT primary keeps its pruning-immune
        // probe through this wrapper; the trait default would substitute the
        // window-bound summary fetch even when the primary implements one.
        // (Behind a mirror relay there is no watermark RPC to reach, so the
        // default is what runs — see the trait method's doc.)
        self.primary.get_latest_checkpoint_sequence().await
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

    // -- direct-gRPC fallback (routed directly, not over the relay) -----------------------
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use sui_types::committee::Committee;
    use sui_types::digests::CheckpointDigest;

    /// A recording `SuiTransport` whose every method appends its name to a
    /// shared log and returns a `NotFound` carrying its own name (so a caller
    /// can also confirm which uplink answered). No method returns `Ok`, which is
    /// fine here: the test asserts on *which* uplink was called, not on the
    /// payload — and `NotFound` is the one error variant we can return without
    /// constructing any of the hard-to-build success types (`ExecutedTransaction`
    /// has private fields, `CheckpointData` is heavy, etc.).
    struct RecordingTransport {
        label: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingTransport {
        fn new(label: &'static str) -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
            let log = Arc::new(Mutex::new(Vec::new()));
            (
                Arc::new(Self {
                    label,
                    log: log.clone(),
                }),
                log,
            )
        }

        fn record<T>(&self, method: &str) -> Result<T, TransportError> {
            self.log.lock().unwrap().push(method.to_string());
            Err(TransportError::NotFound(format!("{}:{method}", self.label)))
        }
    }

    #[async_trait]
    impl SuiTransport for RecordingTransport {
        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            self.record("get_chain_identifier")
        }
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            self.record("get_current_epoch")
        }
        async fn get_committee(&self, _epoch: Option<u64>) -> Result<Committee, TransportError> {
            self.record("get_committee")
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            self.record("get_latest_checkpoint")
        }
        async fn get_latest_checkpoint_sequence(
            &self,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.record("get_latest_checkpoint_sequence")
        }
        async fn get_full_checkpoint(
            &self,
            _seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            self.record("get_full_checkpoint")
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            self.record("get_checkpoint_summary_by_digest")
        }
        async fn last_checkpoint_of_epoch(
            &self,
            _epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            self.record("last_checkpoint_of_epoch")
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            self.record("get_object")
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            self.record("get_object_with_version")
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            self.record("batch_get_objects")
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            self.record("list_dynamic_fields")
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            self.record("get_transaction")
        }
    }

    /// The decorator routes each *relayed* read to the primary (never the
    /// fallback) and each *directly-routed* write/submission method to the
    /// fallback (never the primary); a `NotFound` the primary returns on a
    /// relayed read is surfaced unchanged through the decorator.
    #[tokio::test]
    async fn routes_relayed_reads_to_primary_and_direct_reads_to_fallback() {
        let (primary, primary_log) = RecordingTransport::new("primary");
        let (fallback, fallback_log) = RecordingTransport::new("fallback");
        let transport = FallbackTransport::new(primary, fallback);

        // -- relayed reads: each must hit the primary, not the fallback --------
        let _ = transport.get_chain_identifier().await;
        let _ = transport.get_current_epoch().await;
        let _ = transport.get_latest_checkpoint().await;
        // Explicitly forwarded, not inherited: a dropped forward would fall
        // through to the trait default and record `get_latest_checkpoint`
        // instead, which this ordered log catches.
        let _ = transport.get_latest_checkpoint_sequence().await;
        let _ = transport.get_full_checkpoint(7).await;
        let _ = transport
            .get_checkpoint_summary_by_digest(CheckpointDigest::random())
            .await;
        let _ = transport.last_checkpoint_of_epoch(3).await;
        let _ = transport.get_object(ObjectID::random()).await;
        let _ = transport
            .get_object_with_version(ObjectID::random(), SequenceNumber::from(1u64))
            .await;
        let _ = transport.batch_get_objects(&[ObjectID::random()]).await;
        let _ = transport
            .list_dynamic_fields(ObjectID::random(), None, None)
            .await;

        let relayed: Vec<&str> = vec![
            "get_chain_identifier",
            "get_current_epoch",
            "get_latest_checkpoint",
            "get_latest_checkpoint_sequence",
            "get_full_checkpoint",
            "get_checkpoint_summary_by_digest",
            "last_checkpoint_of_epoch",
            "get_object",
            "get_object_with_version",
            "batch_get_objects",
            "list_dynamic_fields",
        ];
        assert_eq!(*primary_log.lock().unwrap(), relayed);
        assert!(
            fallback_log.lock().unwrap().is_empty(),
            "a relayed read must never touch the fallback uplink"
        );

        // -- directly-routed reads: each must hit the fallback, not primary --
        let _ = transport.get_committee(None).await;
        let _ = transport.get_transaction(TransactionDigest::random()).await;

        let directly_routed: Vec<&str> = vec!["get_committee", "get_transaction"];
        assert_eq!(*fallback_log.lock().unwrap(), directly_routed);
        // The primary log is unchanged — the directly-routed methods added nothing.
        assert_eq!(*primary_log.lock().unwrap(), relayed);

        // -- a NotFound from the primary on a relayed read stays NotFound ------
        let err = transport.get_full_checkpoint(99).await.unwrap_err();
        match err {
            TransportError::NotFound(msg) => assert!(
                msg.starts_with("primary:"),
                "the relayed NotFound must come from the primary, got: {msg}"
            ),
            other => panic!("expected NotFound through the decorator, got {other:?}"),
        }
    }
}
