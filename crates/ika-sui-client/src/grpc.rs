// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Direct gRPC implementation of [`SuiTransport`].
//!
//! Wraps [`sui_rpc::Client`] from the standalone Sui Rust SDK. The client is a
//! cheap `Clone` over a tonic channel (clone-per-request is tonic's intended
//! concurrency model), so each call clones its own handle.
//! Do NOT put the client behind a Mutex held across the call — that would
//! serialize every Sui read/write on the node behind one in-flight RPC.

use std::env::{self, VarError};
use std::fmt::Display;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use fastcrypto::traits::ToFromBytes;
use futures::StreamExt;
use ika_config::node::{SuiGrpcHeaderValue, SuiGrpcHeaders};
use prost_types::value::Kind as ProtoValueKind;
use sui_rpc::Client as SuiRpcClient;
use sui_rpc::client::{ExecuteAndWaitError, HeadersInterceptor};
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::effects::TransactionEvents;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::gas_coin::{GAS, GasCoin};
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSequenceNumber};
use sui_types::object::Object;
use sui_types::signature::GenericSignature;
use sui_types::transaction::{Transaction, TransactionData};
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

use crate::rate_limit::RateLimitGate;
use crate::transport::{
    CheckpointSummaryStream, DynamicFieldEntry, DynamicFieldPage, ExecutedTransaction,
    SubmittedTransaction, SuiFundsBreakdown, SuiTransport, SuiWriter, TransportError,
};

/// Sui rejects a transaction whose gas payment names more than
/// `max_gas_payment_objects` objects — 256 on every live network. Selecting
/// every coin the address owns therefore stops working, for every submission,
/// as soon as it accumulates more than that; and the whole set is not needed
/// in the first place. Stop paging at the cap.
const MAX_GAS_PAYMENT_OBJECTS: usize = 256;

/// Deadline for a transaction submission.
const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone)]
pub struct SuiGrpcClient {
    rpc: SuiRpcClient,
    endpoint: String,
    /// Rate-limit state shared by every client that talks to this endpoint.
    gate: Arc<RateLimitGate>,
}

pub struct ObjectPage {
    pub items: Vec<Object>,
    pub next_page_token: Option<bytes::Bytes>,
}

impl SuiGrpcClient {
    /// Creates a lazy standalone SDK client without probing the endpoint.
    ///
    /// Wallet-backed transaction builders use this when they already know the
    /// active environment and want to resolve inputs or submit a transaction
    /// without constructing Sui main's compatibility client.
    pub fn connect(endpoint: impl Into<String>) -> Result<Self, TransportError> {
        Self::connect_with_headers(endpoint, &SuiGrpcHeaders::new())
    }

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
        let client = Self::connect_with_headers(endpoint, headers)?;
        let _ = client.get_chain_identifier().await?;
        Ok(client)
    }

    fn connect_with_headers(
        endpoint: impl Into<String>,
        headers: &SuiGrpcHeaders,
    ) -> Result<Self, TransportError> {
        let endpoint = endpoint.into();
        let headers = resolve_grpc_headers(headers)?;
        let rpc = SuiRpcClient::new(endpoint.as_str())
            .map_err(|e| TransportError::Network(format!("connect {endpoint}: {e}")))?
            .with_headers(headers);
        Ok(Self {
            rpc,
            endpoint,
            gate: Arc::new(RateLimitGate::unmetered()),
        })
    }

    /// Put this client behind the endpoint's shared rate-limit gate.
    pub fn with_gate(mut self, gate: Arc<RateLimitGate>) -> Self {
        self.gate = gate;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Run one upstream call under the shared rate-limit gate while preserving
    /// `NotFound` as a distinct transport outcome.
    async fn gated<T>(
        &self,
        call: impl Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, TransportError> {
        self.gated_with(call, Self::rpc_status_err).await
    }

    /// Run one upstream call under the shared gate and map every failure to a
    /// generic network error.
    async fn gated_network<T>(
        &self,
        call: impl Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, TransportError> {
        self.gated_with(call, Self::rpc_err).await
    }

    async fn gated_with<T>(
        &self,
        call: impl Future<Output = Result<T, tonic::Status>>,
        map_err: impl FnOnce(tonic::Status) -> TransportError,
    ) -> Result<T, TransportError> {
        self.gate.wait_for_capacity().await;
        match call.await {
            Ok(value) => {
                self.gate.note_success();
                Ok(value)
            }
            Err(status) => {
                self.gate.note_status(&status);
                Err(map_err(status))
            }
        }
    }

    /// Resolves a standalone SDK transaction builder against this client's
    /// endpoint, including object metadata, gas selection, and simulation.
    pub async fn build_transaction(
        &self,
        builder: sui_transaction_builder::TransactionBuilder,
    ) -> Result<sui_sdk_types::Transaction, TransportError> {
        self.gate.wait_for_capacity().await;
        let transaction = builder
            .build(&mut self.rpc.clone())
            .await
            .map_err(|error| TransportError::Encoding(format!("build transaction: {error}")))?;
        self.gate.note_success();
        Ok(transaction)
    }

    pub async fn get_chain_identifier(
        &self,
    ) -> Result<sui_types::digests::ChainIdentifier, TransportError> {
        SuiWriter::get_sui_chain_identifier(self).await
    }

    pub async fn get_full_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        SuiTransport::get_full_checkpoint(self, sequence_number).await
    }

    pub async fn get_object(&self, object_id: ObjectID) -> Result<Object, TransportError> {
        SuiTransport::get_object(self, object_id).await
    }

    pub async fn get_object_ref(&self, object_id: ObjectID) -> Result<ObjectRef, TransportError> {
        self.get_object(object_id)
            .await
            .map(|object| object.compute_object_reference())
    }

    pub async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        SuiWriter::get_reference_gas_price(self).await
    }

    pub async fn list_owned_gas_coins(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        SuiWriter::list_owned_gas_coins(self, address).await
    }

    pub async fn select_gas_coins(
        &self,
        address: SuiAddress,
        amount: u64,
    ) -> Result<Vec<ObjectRef>, TransportError> {
        let address = address
            .to_string()
            .parse()
            .map_err(|e| TransportError::Encoding(format!("decode gas owner: {e}")))?;
        let gas_type = GAS::type_()
            .to_canonical_string(true)
            .parse()
            .map_err(|e| TransportError::Encoding(format!("decode SUI type: {e}")))?;
        let rpc = self.rpc.clone();
        let objects = self
            .gated(async move {
                rpc.select_coins(&address, &gas_type, amount, &[])
                    .await
            })
            .await?;
        if objects.len() > MAX_GAS_PAYMENT_OBJECTS {
            return Err(TransportError::Network(format!(
                "gas selection requires {} objects, exceeding Sui's limit of {MAX_GAS_PAYMENT_OBJECTS}",
                objects.len()
            )));
        }
        objects
            .into_iter()
            .map(|object| {
                Ok((
                    object.object_id().parse().map_err(|e| {
                        TransportError::Encoding(format!("decode gas object id: {e}"))
                    })?,
                    object.version().into(),
                    object.digest().parse().map_err(|e| {
                        TransportError::Encoding(format!("decode gas object digest: {e}"))
                    })?,
                ))
            })
            .collect()
    }

    pub async fn execute_transaction_and_wait(
        &self,
        transaction: &Transaction,
    ) -> Result<ExecutedTransaction, TransportError> {
        let mut rpc = self.rpc.clone();
        let request = Self::execute_transaction_request(transaction)?;
        // Admission happens before the request deadline starts, so a shared
        // cooldown does not consume the submission's own timeout.
        self.gate.wait_for_capacity().await;
        let response = match rpc
            .execute_transaction_and_wait_for_checkpoint(request, SUBMIT_TIMEOUT)
            .await
        {
            Ok(response) => {
                self.gate.note_success();
                response.into_inner()
            }
            Err(ExecuteAndWaitError::RpcError(status)) => {
                self.gate.note_status(&status);
                return Err(Self::rpc_err(status));
            }
            Err(ExecuteAndWaitError::CheckpointStreamError { error, .. }) => {
                self.gate.note_status(&error);
                return Err(TransportError::Network(format!(
                    "execute transaction and wait for checkpoint: {error}"
                )));
            }
            Err(error) => {
                return Err(TransportError::Network(format!(
                    "execute transaction and wait for checkpoint: {error}"
                )));
            }
        };
        Self::decode_executed_transaction(response.transaction())
    }

    pub async fn simulate_transaction(
        &self,
        transaction: &TransactionData,
        do_gas_selection: bool,
    ) -> Result<ExecutedTransaction, TransportError> {
        let mut request = proto::SimulateTransactionRequest::default();
        request.set_checks(proto::simulate_transaction_request::TransactionChecks::Enabled);
        request.set_do_gas_selection(do_gas_selection);
        let mut transaction_proto = proto::Transaction::default();
        transaction_proto.bcs = Some(
            proto::Bcs::serialize(transaction)
                .map_err(|e| TransportError::Encoding(format!("encode transaction: {e}")))?,
        );
        request.transaction = Some(transaction_proto);
        request.read_mask = Some(Self::executed_transaction_read_mask());

        let mut rpc = self.rpc.clone();
        self.gated(async move {
            rpc.execution_client()
                .simulate_transaction(request)
                .await
        })
        .await
        .and_then(|response| {
            Self::decode_executed_transaction(response.into_inner().transaction())
        })
    }

    pub async fn get_object_with_json(
        &self,
        object_id: ObjectID,
    ) -> Result<(Object, Option<serde_json::Value>), TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetObjectRequest::default();
        request.object_id = Some(object_id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["bcs".into(), "json".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_object(request).await })
            .await?
            .into_inner();
        let object = response
            .object
            .ok_or_else(|| TransportError::NotFound(format!("object {object_id} not found")))?;
        Ok((
            Self::decode_object(&object)?,
            object.json.as_deref().map(proto_value_to_json_value),
        ))
    }

    pub async fn get_transaction(
        &self,
        digest: &TransactionDigest,
    ) -> Result<ExecutedTransaction, TransportError> {
        SuiTransport::get_transaction(self, *digest).await
    }

    pub async fn get_owned_objects(
        &self,
        owner: SuiAddress,
        object_type: Option<move_core_types::language_storage::StructTag>,
        page_size: Option<u32>,
        page_token: Option<bytes::Bytes>,
    ) -> Result<ObjectPage, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::ListOwnedObjectsRequest::default();
        request.owner = Some(owner.to_string());
        request.object_type = object_type.map(|type_| type_.to_canonical_string(true));
        request.page_size = page_size;
        request.page_token = page_token;
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["bcs".into()],
        });
        let response = self
            .gated(async move { rpc.state_client().list_owned_objects(request).await })
            .await?
            .into_inner();
        let items = response
            .objects
            .iter()
            .map(Self::decode_object)
            .collect::<Result<_, _>>()?;
        Ok(ObjectPage {
            items,
            next_page_token: response.next_page_token,
        })
    }

    pub async fn get_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<bytes::Bytes>,
    ) -> Result<proto::ListDynamicFieldsResponse, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::ListDynamicFieldsRequest::default();
        request.parent = Some(parent.to_string());
        request.page_size = page_size;
        request.page_token = page_token;
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["*".into()],
        });
        self.gated(async move { rpc.state_client().list_dynamic_fields(request).await })
            .await
            .map(|response| response.into_inner())
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
        let mut request = proto::GetTransactionRequest::default();
        request.digest = Some(tx.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["checkpoint".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_transaction(request).await })
            .await?
            .into_inner();
        response.transaction().checkpoint.ok_or_else(|| {
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

    fn decode_object(proto_object: &proto::Object) -> Result<Object, TransportError> {
        proto_object
            .bcs
            .as_ref()
            .ok_or_else(|| TransportError::Encoding("missing object.bcs".into()))?
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode Object: {e}")))
    }

    fn executed_transaction_read_mask() -> prost_types::FieldMask {
        prost_types::FieldMask {
            paths: vec![
                "transaction.bcs".into(),
                "signatures.bcs".into(),
                "effects.bcs".into(),
                "effects.status.error.abort.clever_error".into(),
                "effects.changed_objects".into(),
                "events.bcs".into(),
                "events.events.json".into(),
                "balance_changes".into(),
                "checkpoint".into(),
                "timestamp".into(),
            ],
        }
    }

    fn decode_executed_transaction(
        executed: &proto::ExecutedTransaction,
    ) -> Result<ExecutedTransaction, TransportError> {
        let transaction: TransactionData = executed
            .transaction()
            .bcs()
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode transaction.bcs: {e}")))?;
        let effects = executed
            .effects()
            .bcs()
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode effects.bcs: {e}")))?;
        let signatures = executed
            .signatures()
            .iter()
            .map(|signature| {
                GenericSignature::from_bytes(signature.bcs().value())
                    .map_err(|e| TransportError::Encoding(format!("decode signatures.bcs: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let events: Option<TransactionEvents> = executed
            .events
            .as_ref()
            .and_then(|events| events.bcs.as_ref())
            .map(|bcs| bcs.deserialize())
            .transpose()
            .map_err(|e| TransportError::Encoding(format!("decode events.bcs: {e}")))?;
        let event_json = executed
            .events_opt()
            .map(|events| {
                events
                    .events()
                    .iter()
                    .map(|event| event.json_opt().map(proto_value_to_json_value))
                    .collect()
            })
            .unwrap_or_default();
        let balance_changes = executed
            .balance_changes
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()
            .map_err(|e| TransportError::Encoding(format!("decode balance_changes: {e}")))?;
        let clever_error = executed
            .effects()
            .status()
            .error()
            .abort()
            .clever_error_opt()
            .cloned();
        let timestamp_ms = executed
            .timestamp
            .and_then(|timestamp| sui_rpc::proto::proto_to_timestamp_ms(timestamp).ok());

        Ok(ExecutedTransaction {
            transaction,
            signatures,
            effects,
            clever_error,
            events,
            event_json,
            changed_objects: executed.effects().changed_objects().to_owned(),
            balance_changes,
            checkpoint: executed.checkpoint,
            timestamp_ms,
        })
    }

    fn execute_transaction_request(
        transaction: &Transaction,
    ) -> Result<proto::ExecuteTransactionRequest, TransportError> {
        let signatures = transaction
            .inner()
            .tx_signatures
            .iter()
            .map(|signature| {
                let mut message = proto::UserSignature::default();
                message.bcs = Some(signature.as_ref().to_vec().into());
                message
            })
            .collect();
        let mut tx = proto::Transaction::default();
        tx.bcs = Some(
            proto::Bcs::serialize(&transaction.inner().intent_message.value)
                .map_err(|e| TransportError::Encoding(format!("encode transaction: {e}")))?,
        );
        let mut request = proto::ExecuteTransactionRequest::new(tx).with_signatures(signatures);
        request.read_mask = Some(Self::executed_transaction_read_mask());
        Ok(request)
    }
}

fn proto_value_to_json_value(proto: &prost_types::Value) -> serde_json::Value {
    match proto.kind.as_ref() {
        Some(ProtoValueKind::NullValue(_)) | None => serde_json::Value::Null,
        Some(ProtoValueKind::NumberValue(number)) => serde_json::Value::from(*number),
        Some(ProtoValueKind::StringValue(string)) => serde_json::Value::from(string.clone()),
        Some(ProtoValueKind::BoolValue(boolean)) => serde_json::Value::from(*boolean),
        Some(ProtoValueKind::StructValue(map)) => serde_json::Value::Object(
            map.fields
                .iter()
                .map(|(key, value)| (key.clone(), proto_value_to_json_value(value)))
                .collect(),
        ),
        Some(ProtoValueKind::ListValue(list)) => {
            serde_json::Value::Array(list.values.iter().map(proto_value_to_json_value).collect())
        }
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
        SuiGrpcClient::get_chain_identifier(self)
            .await
            .map(|chain_identifier| chain_identifier.to_string())
    }

    async fn get_current_epoch(&self) -> Result<u64, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetEpochRequest::default();
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["epoch".into()],
        });
        self.gated_network(async move { rpc.ledger_client().get_epoch(request).await })
            .await
            .map(|response| response.into_inner().epoch().epoch())
    }

    async fn get_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<sui_types::committee::Committee, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetEpochRequest::default();
        request.epoch = epoch;
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["epoch".into(), "committee".into()],
        });
        let response = self
            .gated_network(async move { rpc.ledger_client().get_epoch(request).await })
            .await?
            .into_inner();
        response
            .epoch()
            .committee()
            .try_into()
            .map_err(|e| TransportError::Encoding(format!("decode committee: {e}")))
    }

    // -- checkpoints ------------------------------------------------------------------------
    async fn get_latest_checkpoint(&self) -> Result<CertifiedCheckpointSummary, TransportError> {
        let mut rpc = self.rpc.clone();
        // NotFound must stay distinguishable: a fullnode pruning AT head
        // empties the availability window and NotFounds its OWN latest, and
        // callers (the boot artifacts-digest probe) treat that transient
        // state differently from a real transport failure.
        let mut request = proto::GetCheckpointRequest::latest();
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["summary.bcs".into(), "signature".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_checkpoint(request).await })
            .await?
            .into_inner();
        let checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound("latest checkpoint not found".into()))?;
        Self::decode_certified_summary(&checkpoint)
    }

    async fn get_latest_checkpoint_sequence(
        &self,
    ) -> Result<CheckpointSequenceNumber, TransportError> {
        // `GetServiceInfo.checkpoint_height` reads the store's latest
        // watermark WITHOUT the availability-window check that makes
        // `GetCheckpoint` NotFound a just-pruned latest — the probe keeps
        // working while the fullnode prunes at head.
        let mut rpc = self.rpc.clone();
        let response = self
            .gated(async move {
                rpc.ledger_client()
                    .get_service_info(proto::GetServiceInfoRequest::default())
                    .await
            })
            .await?
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
        let mut request = proto::GetCheckpointRequest::by_sequence_number(seq);
        request.read_mask =
            Some(sui_types::full_checkpoint_content::Checkpoint::proto_field_mask());
        let response = self
            .gated(async move {
                rpc.ledger_client()
                    .max_decoding_message_size(128 * 1024 * 1024)
                    .get_checkpoint(request)
                    .await
            })
            .await?
            .into_inner();
        let checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} not found")))?;
        sui_types::full_checkpoint_content::Checkpoint::try_from(&checkpoint)
            .map(CheckpointData::from)
            .map_err(|e| TransportError::Encoding(format!("decode full checkpoint: {e}")))
    }

    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: sui_types::digests::CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetCheckpointRequest::default();
        request.checkpoint_id = Some(proto::get_checkpoint_request::CheckpointId::Digest(
            digest.to_string(),
        ));
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["summary.bcs".into(), "signature".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_checkpoint(request).await })
            .await?
            .into_inner();
        let proto_checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound(format!("checkpoint {digest:?} not found")))?;
        Self::decode_certified_summary(&proto_checkpoint)
    }

    async fn subscribe_checkpoint_summaries(
        &self,
    ) -> Result<CheckpointSummaryStream, TransportError> {
        // Summary + signature only: served from the fullnode's live checkpoint
        // broadcast, so this never touches the object-pruning watermark that
        // gates `get_full_checkpoint`. `summary.bcs` carries
        // `end_of_epoch_data.next_epoch_committee` for boundary checkpoints.
        let mut request = proto::SubscribeCheckpointsRequest::default();
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["summary.bcs".into(), "signature".into()],
        });
        let mut rpc = self.rpc.clone();
        // Gate only the subscription handshake; stream-item errors trigger a
        // resubscribe and must not hold admission for the stream's lifetime.
        let streaming = self
            .gated(async move {
                rpc.subscription_client()
                    .subscribe_checkpoints(request)
                    .await
            })
            .await?
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
        let response = self
            .gated(async move { rpc.ledger_client().get_epoch(request).await })
            .await?
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
        let mut request = proto::GetObjectRequest::default();
        request.object_id = Some(id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["bcs".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_object(request).await })
            .await?
            .into_inner();
        let object = response
            .object
            .ok_or_else(|| TransportError::NotFound(format!("object {id} not found")))?;
        Self::decode_object(&object)
    }

    async fn get_object_with_version(
        &self,
        id: ObjectID,
        version: SequenceNumber,
    ) -> Result<Object, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetObjectRequest::default();
        request.object_id = Some(id.to_string());
        request.version = Some(version.value());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["bcs".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_object(request).await })
            .await?
            .into_inner();
        let object = response.object.ok_or_else(|| {
            TransportError::NotFound(format!("object {id} at version {version} not found"))
        })?;
        Self::decode_object(&object)
    }

    async fn batch_get_objects(&self, ids: &[ObjectID]) -> Result<Vec<Object>, TransportError> {
        let mut rpc = self.rpc.clone();
        let request = proto::BatchGetObjectsRequest::default()
            .with_requests(
                ids.iter()
                    .map(|id| {
                        let mut request = proto::GetObjectRequest::default();
                        request.object_id = Some(id.to_string());
                        request
                    })
                    .collect(),
            )
            .with_read_mask(prost_types::FieldMask {
                paths: vec!["bcs".into()],
            });
        let response = self
            .gated(async move { rpc.ledger_client().batch_get_objects(request).await })
            .await?
            .into_inner();
        response
            .objects
            .into_iter()
            .map(|result| {
                result
                    .to_result()
                    .map_err(|status| TransportError::NotFound(status.message))
                    .and_then(|object| Self::decode_object(&object))
            })
            .collect()
    }

    // -- dynamic fields ---------------------------------------------------------------------
    async fn list_dynamic_fields(
        &self,
        parent: ObjectID,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<DynamicFieldPage, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::ListDynamicFieldsRequest::default();
        request.parent = Some(parent.to_string());
        request.page_size = page_size;
        request.page_token = page_token.map(bytes::Bytes::from);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["*".into()],
        });
        let response = self
            .gated_network(async move { rpc.state_client().list_dynamic_fields(request).await })
            .await?
            .into_inner();
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
        let mut request = proto::GetTransactionRequest::default();
        request.digest = Some(tx.to_string());
        request.read_mask = Some(Self::executed_transaction_read_mask());
        let response = self
            .gated(async move { rpc.ledger_client().get_transaction(request).await })
            .await?
            .into_inner();
        let transaction = response
            .transaction
            .ok_or_else(|| TransportError::NotFound(format!("transaction {tx} not found")))?;
        Self::decode_executed_transaction(&transaction)
    }
}

#[async_trait]
impl SuiWriter for SuiGrpcClient {
    async fn get_reference_gas_price(&self) -> Result<u64, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetEpochRequest::default();
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["reference_gas_price".into()],
        });
        self.gated_network(async move { rpc.ledger_client().get_epoch(request).await })
            .await
            .map(|response| response.into_inner().epoch().reference_gas_price())
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
            let mut request = proto::ListOwnedObjectsRequest::default();
            request.owner = Some(address.to_string());
            request.object_type = Some(GasCoin::type_().to_canonical_string(true));
            request.page_token = page_token;
            request.read_mask = Some(prost_types::FieldMask {
                paths: vec!["bcs".into()],
            });
            let mut page_rpc = rpc.clone();
            let page = self
                .gated_network(async move {
                    page_rpc.state_client().list_owned_objects(request).await
                })
                .await?
                .into_inner();
            let objects = page
                .objects
                .iter()
                .map(Self::decode_object)
                .collect::<Result<Vec<_>, _>>()?;
            refs.extend(
                objects
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
        let mut rpc = self.rpc.clone();
        // NB: GetBalance takes the COIN type (`0x2::sui::SUI`, `GAS::type_()`),
        // not the coin OBJECT type (`Coin<SUI>`, `GasCoin::type_()`) — the
        // latter silently reads as a zero balance of a nonexistent coin type.
        let mut request = proto::GetBalanceRequest::default();
        request.owner = Some(address.to_string());
        request.coin_type = Some(GAS::type_().to_canonical_string(true));
        let balance = self
            .gated_network(async move { rpc.state_client().get_balance(request).await })
            .await?
            .into_inner()
            .balance
            .unwrap_or_default();
        Ok(SuiFundsBreakdown {
            in_address_balance: balance.address_balance.unwrap_or(0),
            in_coin_objects: balance.coin_balance.unwrap_or(0),
        })
    }

    async fn get_sui_chain_identifier(
        &self,
    ) -> Result<sui_types::digests::ChainIdentifier, TransportError> {
        let mut rpc = self.rpc.clone();
        let response = self
            .gated_network(async move {
                rpc.ledger_client()
                    .get_service_info(proto::GetServiceInfoRequest::default())
                    .await
            })
            .await?
            .into_inner();
        let digest = response
            .chain_id()
            .parse::<sui_sdk_types::Digest>()
            .map_err(|e| TransportError::Encoding(format!("decode chain identifier: {e}")))?;
        Ok(sui_types::digests::ChainIdentifier::from(
            sui_types::digests::CheckpointDigest::from(digest),
        ))
    }

    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        // Bounded by `execute_transaction_and_wait` because the notifier holds
        // its serial submission lock across this call.
        let executed = self.execute_transaction_and_wait(tx).await?;
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
    fn sdk_proto_object_bcs_decodes_to_core_object() {
        let object = Object::immutable_with_id_for_testing(ObjectID::random());
        let mut proto_object = proto::Object::default();
        proto_object.bcs = Some(proto::Bcs::serialize(&object).expect("object must serialize"));

        let decoded = SuiGrpcClient::decode_object(&proto_object).expect("object must decode");
        assert_eq!(
            decoded.compute_object_reference(),
            object.compute_object_reference()
        );
    }

    #[test]
    fn sdk_proto_object_without_bcs_is_rejected() {
        let err = SuiGrpcClient::decode_object(&proto::Object::default())
            .expect_err("missing BCS must fail");
        assert!(matches!(err, TransportError::Encoding(_)));
        assert!(err.to_string().contains("object.bcs"));
    }

    #[test]
    fn sdk_proto_json_conversion_preserves_nested_values() {
        let value = prost_types::Value {
            kind: Some(ProtoValueKind::StructValue(prost_types::Struct {
                fields: [(
                    "items".to_string(),
                    prost_types::Value {
                        kind: Some(ProtoValueKind::ListValue(prost_types::ListValue {
                            values: vec![
                                prost_types::Value {
                                    kind: Some(ProtoValueKind::NumberValue(7.0)),
                                },
                                prost_types::Value {
                                    kind: Some(ProtoValueKind::BoolValue(true)),
                                },
                            ],
                        })),
                    },
                )]
                .into(),
            })),
        };

        assert_eq!(
            proto_value_to_json_value(&value),
            serde_json::json!({ "items": [7.0, true] })
        );
    }

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
