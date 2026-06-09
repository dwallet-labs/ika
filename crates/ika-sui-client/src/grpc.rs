// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Direct gRPC implementation of [`SuiTransport`].
//!
//! Wraps [`sui_rpc_api::Client`]. Many of its methods take `&mut self`
//! internally so we hold the client behind a [`tokio::sync::Mutex`].

use std::sync::Arc;

use async_trait::async_trait;
use sui_rpc_api::Client as SuiRpcClient;
use sui_rpc_api::client::ExecutedTransaction;
use sui_rpc_api::proto::sui::rpc::v2 as proto;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::gas_coin::GasCoin;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;
use tokio::sync::Mutex;

use crate::transport::{
    DynamicFieldEntry, DynamicFieldPage, SubmittedTransaction, SuiTransport, TransportError,
};

pub struct SuiGrpcClient {
    rpc: Arc<Mutex<SuiRpcClient>>,
    endpoint: String,
}

impl SuiGrpcClient {
    /// Connects (lazily) and probes the endpoint by fetching the chain id.
    pub async fn new(endpoint: impl Into<String>) -> Result<Self, TransportError> {
        let endpoint = endpoint.into();
        let rpc = SuiRpcClient::new(endpoint.as_str())
            .map_err(|e| TransportError::Network(format!("connect {endpoint}: {e}")))?;
        let client = Self {
            rpc: Arc::new(Mutex::new(rpc)),
            endpoint,
        };
        let _ = client.get_chain_identifier().await?;
        Ok(client)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn rpc_err(s: impl ToString) -> TransportError {
        TransportError::Network(s.to_string())
    }

    /// Map a `tonic::Status` to the right `TransportError` variant so
    /// callers can distinguish "the upstream returned NotFound" from
    /// generic transport errors. Used for the read methods that have
    /// "object/transaction/checkpoint not found" as a meaningful — and
    /// frequently transient — outcome.
    fn rpc_status_err(status: tonic::Status) -> TransportError {
        if status.code() == tonic::Code::NotFound {
            TransportError::NotFound(status.message().to_string())
        } else {
            TransportError::Network(status.to_string())
        }
    }
}

fn parse_object_id(s: &str) -> Result<ObjectID, TransportError> {
    s.parse::<ObjectID>()
        .map_err(|e| TransportError::Encoding(format!("invalid ObjectID `{s}`: {e}")))
}

fn convert_dynamic_field(
    proto: proto::DynamicField,
) -> Result<Option<DynamicFieldEntry>, TransportError> {
    // Match JSON-RPC `get_dynamic_fields` `object_id` semantics: for a dynamic
    // *object* field (ObjectTable/ObjectBag) the resolved id is the wrapped
    // value object (`child_id`), not the `Field<K, ID>` wrapper (`field_id`).
    // Consumers that decode a bare value (e.g. the network encryption keys
    // ObjectTable) need the value object; plain dynamic fields (table-vec
    // chunks, bag entries) have no `child_id`, so they keep resolving to
    // `field_id` as before.
    let Some(object_id_str) = proto.child_id.or(proto.field_id) else {
        return Ok(None);
    };
    let object_id = parse_object_id(&object_id_str)?;
    let Some(name) = proto.name else {
        // Without the name we can't filter by name; skip the entry.
        return Ok(None);
    };
    let name_type = name.name.unwrap_or_default();
    let name_value_bcs = name.value.map(|b| b.to_vec()).unwrap_or_default();
    Ok(Some(DynamicFieldEntry {
        object_id,
        name_type,
        name_value_bcs,
    }))
}

#[async_trait]
impl SuiTransport for SuiGrpcClient {
    // -- chain metadata ---------------------------------------------------------------------
    async fn get_chain_identifier(&self) -> Result<String, TransportError> {
        let rpc = self.rpc.lock().await;
        rpc.get_chain_identifier()
            .await
            .map(|c| c.to_string())
            .map_err(Self::rpc_err)
    }

    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        let rpc = self.rpc.lock().await;
        rpc.get_current_epoch().await.map_err(Self::rpc_err)
    }

    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        let rpc = self.rpc.lock().await;
        rpc.get_reference_gas_price().await.map_err(Self::rpc_err)
    }

    async fn get_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        let rpc = self.rpc.lock().await;
        rpc.get_committee(epoch).await.map_err(Self::rpc_err)
    }

    // -- checkpoints ------------------------------------------------------------------------
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        let mut rpc = self.rpc.lock().await;
        rpc.get_latest_checkpoint().await.map_err(Self::rpc_err)
    }

    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        let mut rpc = self.rpc.lock().await;
        let checkpoint = rpc
            .get_full_checkpoint(seq)
            .await
            .map_err(Self::rpc_status_err)?;
        Ok(CheckpointData::from(checkpoint))
    }

    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: sui_types::digests::CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        use sui_rpc_api::proto::sui::rpc::v2::{GetCheckpointRequest, get_checkpoint_request};
        let mut rpc = self.rpc.lock().await;
        // sui-rpc-api's Client only exposes seq-based lookup at the high
        // level; drop down to the proto for digest-based lookup. Field
        // mask narrowed to summary+signature — we don't need the full
        // body.
        let mut request = GetCheckpointRequest::default();
        request.checkpoint_id = Some(get_checkpoint_request::CheckpointId::Digest(
            digest.to_string(),
        ));
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["summary.bcs".into(), "signature".into()],
        });
        let response = rpc
            .inner_mut()
            .clone()
            .ledger_client()
            .get_checkpoint(request)
            .await
            .map_err(Self::rpc_status_err)?
            .into_inner();
        let proto_checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound(format!("checkpoint {digest:?} not found")))?;
        let summary_data: sui_types::messages_checkpoint::CheckpointSummary = proto_checkpoint
            .summary
            .as_ref()
            .and_then(|s| s.bcs.as_ref())
            .ok_or_else(|| TransportError::Encoding("missing summary.bcs".into()))?
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode CheckpointSummary: {e}")))?;
        let proto_sig = proto_checkpoint.signature.as_ref().ok_or_else(|| {
            TransportError::Encoding("signature missing on get_checkpoint response".into())
        })?;
        let signature = sui_types::crypto::AuthorityStrongQuorumSignInfo::from(
            sui_sdk_types::ValidatorAggregatedSignature::try_from(proto_sig)
                .map_err(|e| TransportError::Encoding(format!("decode signature: {e}")))?,
        );
        Ok(CertifiedCheckpointSummary::new_from_data_and_sig(
            summary_data,
            signature,
        ))
    }

    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        let mut rpc = self.rpc.lock().await;
        let mut request = proto::GetEpochRequest::default();
        request.epoch = Some(epoch);
        let response = rpc
            .inner_mut()
            .clone()
            .ledger_client()
            .get_epoch(request)
            .await
            .map_err(Self::rpc_err)?
            .into_inner();
        let info = response
            .epoch
            .ok_or_else(|| TransportError::NotFound(format!("epoch {epoch} not found")))?;
        info.last_checkpoint.ok_or_else(|| {
            TransportError::NotFound(format!("last_checkpoint not yet set for epoch {epoch}"))
        })
    }

    // -- objects ----------------------------------------------------------------------------
    async fn get_object(&self, id: ObjectID) -> Result<Object, TransportError> {
        let mut rpc = self.rpc.lock().await;
        rpc.get_object(id).await.map_err(Self::rpc_status_err)
    }

    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        let mut rpc = self.rpc.lock().await;
        rpc.get_object_with_version(id, version)
            .await
            .map_err(Self::rpc_status_err)
    }

    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        let rpc = self.rpc.lock().await;
        rpc.batch_get_objects(ids)
            .await
            .map_err(Self::rpc_status_err)
    }

    async fn list_owned_gas_coins(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        let rpc = self.rpc.lock().await;
        let mut refs = Vec::new();
        let mut page_token = None;
        loop {
            let page = rpc
                .get_owned_objects(address, Some(GasCoin::type_()), None, page_token)
                .await
                .map_err(Self::rpc_err)?;
            refs.extend(
                page.items
                    .iter()
                    .map(|object| object.compute_object_reference()),
            );
            match page.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        Ok(refs)
    }

    // -- dynamic fields ---------------------------------------------------------------------
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        let rpc = self.rpc.lock().await;
        let page_token = page_token.map(bytes::Bytes::from);
        let response = rpc
            .get_dynamic_fields(parent, page_size, page_token)
            .await
            .map_err(Self::rpc_err)?;
        let mut entries = Vec::with_capacity(response.dynamic_fields.len());
        for proto_df in response.dynamic_fields {
            if let Some(entry) = convert_dynamic_field(proto_df)? {
                entries.push(entry);
            }
        }
        Ok(DynamicFieldPage {
            entries,
            next_page_token: response.next_page_token.map(|b| b.to_vec()),
        })
    }

    // -- transactions -----------------------------------------------------------------------
    async fn get_transaction(
        &self,
        tx: TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        let mut rpc = self.rpc.lock().await;
        rpc.get_transaction(&tx).await.map_err(Self::rpc_status_err)
    }

    async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        let mut rpc = self.rpc.lock().await;
        let executed = rpc
            .get_transaction(&tx)
            .await
            .map_err(Self::rpc_status_err)?;
        executed.checkpoint.ok_or_else(|| {
            TransportError::NotFound(format!("tx {tx} not yet committed in any checkpoint"))
        })
    }

    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        let mut rpc = self.rpc.lock().await;
        let executed = rpc.execute_transaction(tx).await.map_err(Self::rpc_err)?;
        Ok(SubmittedTransaction {
            digest: *tx.digest(),
            effects: executed.effects,
        })
    }
}
