// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Direct gRPC implementation of [`SuiTransport`].
//!
//! Wraps [`sui_rpc_api::Client`]. Many of its methods take `&mut self`, but
//! the client is a cheap `Clone` over a tonic channel (clone-per-request is
//! tonic's intended concurrency model), so each call clones its own handle.
//! Do NOT put the client behind a Mutex held across the call — that would
//! serialize every Sui read/write on the node behind one in-flight RPC.

use std::env::{self, VarError};
use std::fmt::Display;
use std::fs;
use std::path::Path;

use async_trait::async_trait;
use futures::StreamExt;
use ika_config::node::{SuiGrpcHeaderValue, SuiGrpcHeaders};
use sui_rpc_api::Client as SuiRpcClient;
use sui_rpc_api::client::ExecutedTransaction;
use sui_rpc_api::client::HeadersInterceptor;
use sui_rpc_api::proto::sui::rpc::v2 as proto;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::gas_coin::{GAS, GasCoin};
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::transaction::Transaction;
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

use crate::transport::{
    CheckpointSummaryStream, DynamicFieldEntry, DynamicFieldPage, SubmittedTransaction,
    SuiFundsBreakdown, SuiTransport, SuiWriter, TransportError,
};

/// Sui rejects a transaction whose gas payment names more than
/// `max_gas_payment_objects` objects — 256 on every live network. Selecting
/// every coin the address owns therefore stops working, for every submission,
/// as soon as it accumulates more than that; and the whole set is not needed
/// in the first place. Stop paging at the cap.
const MAX_GAS_PAYMENT_OBJECTS: usize = 256;

/// Deadline for a transaction submission.
const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub struct SuiGrpcClient {
    rpc: SuiRpcClient,
    endpoint: String,
}

impl SuiGrpcClient {
    /// Connects (lazily) and probes the endpoint by fetching the chain id.
    pub async fn new(endpoint: impl Into<String>) -> Result<Self, TransportError> {
        Self::new_with_headers(endpoint, &SuiGrpcHeaders::new()).await
    }

    /// Connects with configured metadata attached to every request, then
    /// probes the endpoint by fetching the chain id.
    pub async fn new_with_headers(
        endpoint: impl Into<String>,
        headers: &SuiGrpcHeaders,
    ) -> Result<Self, TransportError> {
        let endpoint = endpoint.into();
        let headers = resolve_grpc_headers(headers)?;
        let rpc = SuiRpcClient::new(endpoint.as_str())
            .map_err(|e| TransportError::Network(format!("connect {endpoint}: {e}")))?
            .with_headers(headers);
        let client = Self { rpc, endpoint };
        let _ = client.get_chain_identifier().await?;
        Ok(client)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the checkpoint sequence in which `tx` was committed; errors if
    /// the tx isn't yet finalized in any checkpoint. Deliberately *not* part of
    /// [`SuiTransport`] — a relay can't meaningfully serve it, and the only
    /// caller is the direct proof builder (`LocalProofProvider`), which locates
    /// an object's last-modifying checkpoint from its `previous_transaction`.
    pub async fn get_transaction_checkpoint(
        &self,
        tx: TransactionDigest,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        let mut rpc = self.rpc.clone();
        let executed = rpc
            .get_transaction(&tx)
            .await
            .map_err(Self::rpc_status_err)?;
        executed.checkpoint.ok_or_else(|| {
            TransportError::NotFound(format!("tx {tx} not yet committed in any checkpoint"))
        })
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

    /// Decode a proto checkpoint carrying the narrow `summary.bcs` + `signature`
    /// field mask into a `CertifiedCheckpointSummary`. Shared by the digest
    /// lookup and the live subscription stream — both request exactly these two
    /// fields, and `summary.bcs` is the full BCS-encoded `CheckpointSummary`, so
    /// `end_of_epoch_data.next_epoch_committee` rides along inside it.
    fn decode_certified_summary(
        proto_checkpoint: &proto::Checkpoint,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        let summary_data: sui_types::messages_checkpoint::CheckpointSummary = proto_checkpoint
            .summary
            .as_ref()
            .and_then(|s| s.bcs.as_ref())
            .ok_or_else(|| TransportError::Encoding("missing summary.bcs".into()))?
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode CheckpointSummary: {e}")))?;
        let proto_sig = proto_checkpoint.signature.as_ref().ok_or_else(|| {
            TransportError::Encoding("signature missing on checkpoint response".into())
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
}

fn resolve_grpc_headers(headers: &SuiGrpcHeaders) -> Result<HeadersInterceptor, TransportError> {
    resolve_grpc_headers_with(
        headers,
        |variable| match env::var(variable) {
            Ok(value) => Ok(value),
            Err(VarError::NotPresent) => {
                Err(format!("environment variable `{variable}` is not set"))
            }
            Err(VarError::NotUnicode(_)) => Err(format!(
                "environment variable `{variable}` is not valid UTF-8"
            )),
        },
        |path| {
            fs::read_to_string(path).map_err(|e| format!("cannot read `{}`: {e}", path.display()))
        },
    )
}

fn resolve_grpc_headers_with(
    headers: &SuiGrpcHeaders,
    read_env: impl Fn(&str) -> Result<String, String>,
    read_file: impl Fn(&Path) -> Result<String, String>,
) -> Result<HeadersInterceptor, TransportError> {
    let mut resolved = HeadersInterceptor::new();
    for (name, source) in headers {
        let value = match source {
            SuiGrpcHeaderValue::FromEnv(variable) => read_env(variable),
            SuiGrpcHeaderValue::FromFile(path) => read_file(path).map(strip_one_line_ending),
            SuiGrpcHeaderValue::Literal(value) => Ok(value.clone()),
        }
        .map_err(|reason| grpc_header_config_error(name, reason))?;
        if value.is_empty() {
            return Err(grpc_header_config_error(name, "value is empty"));
        }
        let key = MetadataKey::<Ascii>::from_bytes(name.as_bytes())
            .map_err(|_| grpc_header_config_error(name, "name is not valid ASCII metadata"))?;
        let mut value = MetadataValue::<Ascii>::try_from(value.as_str()).map_err(|_| {
            grpc_header_config_error(name, "value contains invalid ASCII metadata bytes")
        })?;
        value.set_sensitive(true);
        resolved.headers_mut().insert(key, value);
    }
    Ok(resolved)
}

fn strip_one_line_ending(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.truncate(value.len() - 1);
    }
    value
}

fn grpc_header_config_error(name: &str, reason: impl Display) -> TransportError {
    TransportError::Network(format!(
        "invalid Sui gRPC header configuration for `{name}`: {reason}"
    ))
}

fn parse_object_id(s: &str) -> Result<ObjectID, TransportError> {
    s.parse::<ObjectID>()
        .map_err(|e| TransportError::Encoding(format!("invalid ObjectID `{s}`: {e}")))
}

fn convert_dynamic_field(
    proto: proto::DynamicField,
) -> Result<Option<DynamicFieldEntry>, TransportError> {
    // For a dynamic *object* field (ObjectTable/ObjectBag), the resolved id is the wrapped
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
        let rpc = self.rpc.clone();
        rpc.get_chain_identifier()
            .await
            .map(|c| c.to_string())
            .map_err(Self::rpc_err)
    }

    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        let rpc = self.rpc.clone();
        rpc.get_current_epoch().await.map_err(Self::rpc_err)
    }

    async fn get_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        let rpc = self.rpc.clone();
        rpc.get_committee(epoch).await.map_err(Self::rpc_err)
    }

    // -- checkpoints ------------------------------------------------------------------------
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        let mut rpc = self.rpc.clone();
        // NotFound must stay distinguishable: a fullnode pruning AT head
        // empties the availability window and NotFounds its OWN latest, and
        // callers (the boot artifacts-digest probe) treat that transient
        // state differently from a real transport failure.
        rpc.get_latest_checkpoint()
            .await
            .map_err(Self::rpc_status_err)
    }

    async fn get_latest_checkpoint_sequence(
        &self,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        // `GetServiceInfo.checkpoint_height` reads the store's latest
        // watermark WITHOUT the availability-window check that makes
        // `GetCheckpoint` NotFound a just-pruned latest — the probe keeps
        // working while the fullnode prunes at head.
        let mut rpc = self.rpc.clone();
        let response = rpc
            .inner_mut()
            .clone()
            .ledger_client()
            .get_service_info(proto::GetServiceInfoRequest::default())
            .await
            .map_err(Self::rpc_status_err)?
            .into_inner();
        response.checkpoint_height.ok_or_else(|| {
            TransportError::Network(
                "GetServiceInfo response carried no checkpoint_height".to_string(),
            )
        })
    }

    async fn get_full_checkpoint(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        let mut rpc = self.rpc.clone();
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
        let mut rpc = self.rpc.clone();
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
        Self::decode_certified_summary(&proto_checkpoint)
    }

    async fn subscribe_checkpoint_summaries(
        &self,
    ) -> Result<CheckpointSummaryStream, TransportError> {
        use sui_rpc_api::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
        // Summary + signature only: served from the fullnode's live checkpoint
        // broadcast, so this never touches the object-pruning watermark that
        // gates `get_full_checkpoint`. `summary.bcs` carries
        // `end_of_epoch_data.next_epoch_committee` for boundary checkpoints.
        let mut request = SubscribeCheckpointsRequest::default();
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["summary.bcs".into(), "signature".into()],
        });
        let mut rpc = self.rpc.clone();
        let mut inner = rpc.inner_mut().clone();
        let streaming = inner
            .subscription_client()
            .subscribe_checkpoints(request)
            .await
            .map_err(Self::rpc_status_err)?
            .into_inner();
        // Map each streamed response to a decoded summary; a per-item decode or
        // transport error becomes a stream item error (the follower resubscribes
        // on the first error rather than tearing the node down).
        let summaries = streaming.map(|item| {
            let response = item.map_err(Self::rpc_status_err)?;
            let proto_checkpoint = response.checkpoint.ok_or_else(|| {
                TransportError::Encoding("subscription response missing checkpoint".into())
            })?;
            Self::decode_certified_summary(&proto_checkpoint)
        });
        Ok(Box::pin(summaries))
    }

    async fn last_checkpoint_of_epoch(
        &self,
        epoch: u64,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetEpochRequest::default();
        request.epoch = Some(epoch);
        // NotFound must stay distinguishable (`rpc_status_err`, not `rpc_err`):
        // a source that no longer serves this epoch's record ("Epoch N not
        // found" — a pruned fullnode, or sui-state-direct serving current state
        // only) is a determinate condition the committee ratchet routes to its
        // pruned-boundary fallback chain. Collapsing it into `Network` made the
        // ratchet retry it forever, invisibly.
        let response = rpc
            .inner_mut()
            .clone()
            .ledger_client()
            .get_epoch(request)
            .await
            .map_err(Self::rpc_status_err)?
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
        let mut rpc = self.rpc.clone();
        rpc.get_object(id).await.map_err(Self::rpc_status_err)
    }

    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        let mut rpc = self.rpc.clone();
        rpc.get_object_with_version(id, version)
            .await
            .map_err(Self::rpc_status_err)
    }

    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        let rpc = self.rpc.clone();
        rpc.batch_get_objects(ids)
            .await
            .map_err(Self::rpc_status_err)
    }

    // -- dynamic fields ---------------------------------------------------------------------
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        let rpc = self.rpc.clone();
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
        let mut rpc = self.rpc.clone();
        rpc.get_transaction(&tx).await.map_err(Self::rpc_status_err)
    }
}

#[async_trait]
impl SuiWriter for SuiGrpcClient {
    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        let rpc = self.rpc.clone();
        rpc.get_reference_gas_price().await.map_err(Self::rpc_err)
    }

    async fn list_owned_gas_coins(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        let rpc = self.rpc.clone();
        let mut refs = Vec::new();
        let mut page_token = None;
        loop {
            if refs.len() >= MAX_GAS_PAYMENT_OBJECTS {
                break;
            }
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
        refs.truncate(MAX_GAS_PAYMENT_OBJECTS);
        Ok(refs)
    }

    async fn get_sui_funds(
        &self,
        address: SuiAddress,
    ) -> Result<SuiFundsBreakdown, TransportError> {
        let rpc = self.rpc.clone();
        // NB: GetBalance takes the COIN type (`0x2::sui::SUI`, `GAS::type_()`),
        // not the coin OBJECT type (`Coin<SUI>`, `GasCoin::type_()`) — the
        // latter silently reads as a zero balance of a nonexistent coin type.
        let balance = rpc
            .get_balance(address, &GAS::type_())
            .await
            .map_err(Self::rpc_err)?;
        Ok(SuiFundsBreakdown {
            in_address_balance: balance.address_balance.unwrap_or(0),
            in_coin_objects: balance.coin_balance.unwrap_or(0),
        })
    }

    async fn get_sui_chain_identifier(
        &self,
    ) -> Result<sui_types::digests::ChainIdentifier, TransportError> {
        let rpc = self.rpc.clone();
        // The inner client already returns the typed, full identifier
        // (service-info chain id parsed as the genesis checkpoint digest).
        rpc.get_chain_identifier().await.map_err(Self::rpc_err)
    }

    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        let mut rpc = self.rpc.clone();
        // Bounded because the notifier holds its serial submission lock across
        // this call: the underlying client configures a connect timeout and
        // keepalives but no per-request deadline, so an upstream that accepts
        // the request and never answers would stall every notifier write
        // behind it, with no watchdog able to fire.
        let executed = tokio::time::timeout(SUBMIT_TIMEOUT, rpc.execute_transaction(tx))
            .await
            .map_err(|_| {
                TransportError::Network(format!(
                    "execute_transaction exceeded {SUBMIT_TIMEOUT:?} with no response"
                ))
            })?
            .map_err(Self::rpc_err)?;
        Ok(SubmittedTransaction {
            digest: *tx.digest(),
            effects: executed.effects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_headers_resolve_all_sources_and_are_sensitive() {
        let headers = SuiGrpcHeaders::from([
            (
                "authorization".to_string(),
                SuiGrpcHeaderValue::FromEnv("SUI_AUTH".to_string()),
            ),
            (
                "x-api-key".to_string(),
                SuiGrpcHeaderValue::FromFile("/run/secrets/sui-api-key".into()),
            ),
            (
                "x-client-name".to_string(),
                SuiGrpcHeaderValue::Literal("ika-validator".to_string()),
            ),
        ]);
        let resolved = resolve_grpc_headers_with(
            &headers,
            |variable| {
                assert_eq!(variable, "SUI_AUTH");
                Ok("Bearer token".to_string())
            },
            |path| {
                assert_eq!(path, Path::new("/run/secrets/sui-api-key"));
                Ok("file-token\r\n".to_string())
            },
        )
        .expect("valid headers must resolve");

        for (name, expected) in [
            ("authorization", "Bearer token"),
            ("x-api-key", "file-token"),
            ("x-client-name", "ika-validator"),
        ] {
            let value = resolved.headers().get(name).expect("header must exist");
            assert_eq!(value.to_str().expect("ASCII value"), expected);
            assert!(value.is_sensitive(), "{name} must be marked sensitive");
        }
    }

    #[test]
    fn configured_header_errors_never_expose_values() {
        let invalid_value = "private-token\nsecond-line";
        let headers = SuiGrpcHeaders::from([(
            "authorization".to_string(),
            SuiGrpcHeaderValue::Literal(invalid_value.to_string()),
        )]);
        let err = resolve_grpc_headers_with(
            &headers,
            |_| unreachable!("literal source must not read the environment"),
            |_| unreachable!("literal source must not read a file"),
        )
        .expect_err("newline is not valid ASCII metadata");
        let message = err.to_string();
        assert!(message.contains("authorization"));
        assert!(!message.contains("private-token"));

        let missing_env = SuiGrpcHeaders::from([(
            "x-api-key".to_string(),
            SuiGrpcHeaderValue::FromEnv("MISSING_SUI_KEY".to_string()),
        )]);
        let err = resolve_grpc_headers_with(
            &missing_env,
            |variable| Err(format!("environment variable `{variable}` is not set")),
            |_| unreachable!("environment source must not read a file"),
        )
        .expect_err("missing environment variable must fail");
        assert!(err.to_string().contains("MISSING_SUI_KEY"));
    }

    /// A gRPC `NotFound` must map to `TransportError::NotFound` (carrying the
    /// message), and every other status code to `TransportError::Network`. This
    /// is the source classification the committee ratchet's prune-fallback
    /// decision keys on (it falls back ONLY on a genuine NotFound), so a 404
    /// misclassified as Network — or the reverse — is a real bug.
    #[test]
    fn rpc_status_err_maps_not_found_distinctly_from_network() {
        match SuiGrpcClient::rpc_status_err(tonic::Status::not_found("checkpoint 42 pruned")) {
            TransportError::NotFound(msg) => assert_eq!(msg, "checkpoint 42 pruned"),
            other => panic!("not_found must map to NotFound, got {other:?}"),
        }
        for status in [
            tonic::Status::unavailable("backend down"),
            tonic::Status::internal("boom"),
            tonic::Status::deadline_exceeded("slow"),
            tonic::Status::unknown("?"),
            tonic::Status::unauthenticated("nope"),
            tonic::Status::resource_exhausted("busy"),
        ] {
            let code = status.code();
            match SuiGrpcClient::rpc_status_err(status) {
                TransportError::Network(_) => {}
                other => panic!("{code:?} must map to Network, got {other:?}"),
            }
        }
    }
}
