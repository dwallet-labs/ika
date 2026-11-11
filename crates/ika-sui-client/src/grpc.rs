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
use std::time::Duration;

use async_trait::async_trait;
use fastcrypto::traits::ToFromBytes;
use futures::StreamExt;
use futures::stream;
use ika_config::node::{SuiGrpcHeaderValue, SuiGrpcHeaders};
use move_core_types::language_storage::StructTag;
use prost_types::value::Kind as ProtoValueKind;
use sui_rpc::Client as SuiRpcClient;
use sui_rpc::client::{ExecuteAndWaitError, HeadersInterceptor};
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_sdk_types::{
    Digest as SdkDigest, Transaction as SdkTransaction, ValidatorAggregatedSignature,
};
use sui_transaction_builder::{Error as TransactionBuilderError, TransactionBuilder};
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::crypto::AuthorityStrongQuorumSignInfo;
use sui_types::digests::{ChainIdentifier, CheckpointDigest};
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI, TransactionEvents};
use sui_types::full_checkpoint_content::{Checkpoint as FullCheckpoint, CheckpointData};
use sui_types::gas_coin::{GAS, GasCoin};
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointSequenceNumber, CheckpointSummary,
};
use sui_types::object::{MoveObject, Object};
use sui_types::signature::GenericSignature;
use sui_types::sui_sdk_types_conversions::struct_tag_core_to_sdk;
use sui_types::transaction::{Transaction, TransactionData};
use tokio::time::sleep;
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

use crate::rate_limit::RateLimitGate;
use crate::transport::{
    CheckpointObjectStates, CheckpointSummaryStream, DynamicFieldEntry, DynamicFieldPage,
    ExecutedTransaction, SubmittedTransaction, SuiFundsBreakdown, SuiNodeInfo, SuiTransport,
    SuiWriter, TransportError, fold_written_object_states,
};

/// Sui rejects a transaction whose gas payment names more than
/// `max_gas_payment_objects` objects — 256 on every live network. Selecting
/// every coin the address owns therefore stops working, for every submission,
/// as soon as it accumulates more than that; and the whole set is not needed
/// in the first place. Stop paging at the cap.
const MAX_GAS_PAYMENT_OBJECTS: usize = 256;

/// The most bytes a whole-checkpoint read decodes.
pub const FULL_CHECKPOINT_DECODE_LIMIT: usize = 128 * 1024 * 1024;

/// The most bytes one read of
/// [`SuiGrpcClient::get_checkpoint_object_states_in_parts`] decodes. Its largest read is one transaction's effects. Sui's executor
/// refuses a transaction whose estimated effects pass 512 KiB, or 8 MiB for a
/// system transaction (`max_serialized_tx_effects_size_bytes` and
/// `max_serialized_tx_effects_size_bytes_system_tx`); a refused transaction
/// commits small failure effects instead. That bound holds from Sui protocol
/// version 141 on, which Sui mainnet runs: 141 turns on
/// `complete_effects_size_estimate`, and before it the estimate left out
/// accumulator writes, so older effects could be larger. The other read
/// carries the summary and the digests. An honest checkpoint lists at most
/// about 225,000: `max_transactions_per_checkpoint` (20,000) scheduled
/// transactions, plus the accumulator settlement transactions, at most
/// 20,000 × 1,025 accumulator updates (`max_num_accumulator_events` 1,024,
/// plus one from gas charging) ÷ `max_updates_per_settlement_txn` (100) =
/// 205,000, plus a few system transactions. At about 48 bytes each that is
/// about 11 MiB. Twice the system-transaction cap leaves room for the
/// protobuf framing.
pub const CHECKPOINT_PART_DECODE_LIMIT: usize = 16 * 1024 * 1024;

/// How many per-transaction effects reads one checkpoint keeps in flight.
const CHECKPOINT_PART_CONCURRENCY: usize = 16;

/// How many times one part read is tried when it fails as `Network`.
const PART_READ_ATTEMPTS: u32 = 4;

/// The wait before a part read's first retry. It doubles before each later
/// retry, so one part read waits at most 1.75 s in all.
const PART_READ_FIRST_DELAY: Duration = Duration::from_millis(250);

/// Run one part read, and run it again, up to [`PART_READ_ATTEMPTS`] times
/// in all, while it fails as `Network`, waiting `first_delay` and then twice
/// as long before each retry. Any other outcome is returned at once.
async fn retry_part_read<T, F, Fut>(first_delay: Duration, mut read: F) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, TransportError>>,
{
    let mut delay = first_delay;
    for _ in 1..PART_READ_ATTEMPTS {
        match read().await {
            Err(TransportError::Network(reason)) => {
                tracing::debug!(reason, ?delay, "part read failed; retrying it");
                sleep(delay).await;
                delay *= 2;
            }
            other => return other,
        }
    }
    read().await
}

/// Refuse a digest list whose length is not the number of transactions the
/// summary says its checkpoint holds: its `network_total_transactions` minus
/// the previous checkpoint's, or all of them for checkpoint 0. Only
/// checkpoint 0 may come without a previous summary.
fn check_transaction_count(
    summary: &CheckpointSummary,
    previous: Option<&CheckpointSummary>,
    count: usize,
) -> Result<(), TransportError> {
    if previous.is_none() && summary.sequence_number > 0 {
        return Err(TransportError::Encoding(format!(
            "checkpoint {} names no previous checkpoint",
            summary.sequence_number
        )));
    }
    let before = previous.map_or(0, |previous| previous.network_total_transactions);
    let expected = summary
        .network_total_transactions
        .checked_sub(before)
        .ok_or_else(|| {
            TransportError::Encoding(format!(
                "checkpoint {} counts {} transactions in all, fewer than the {before} before it",
                summary.sequence_number, summary.network_total_transactions
            ))
        })?;
    if count as u64 != expected {
        return Err(TransportError::Encoding(format!(
            "checkpoint {} holds {expected} transactions, but {count} digests were listed",
            summary.sequence_number
        )));
    }
    Ok(())
}

/// Deadline for a transaction submission.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Total deadline for execution plus the SDK's checkpoint-inclusion wait.
const EXECUTE_AND_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

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

    /// Creates a lazy client using the `username:password` value from a Sui
    /// CLI environment.
    pub fn connect_with_basic_auth(
        endpoint: impl Into<String>,
        basic_auth: Option<&str>,
    ) -> Result<Self, TransportError> {
        let mut headers = HeadersInterceptor::new();
        if let Some(basic_auth) = basic_auth {
            let fields = basic_auth.split(':').collect::<Vec<_>>();
            if fields.len() != 2 {
                return Err(TransportError::Encoding(
                    "basic auth must use the `username:password` format".into(),
                ));
            }
            headers.basic_auth(fields[0], Some(fields[1]));
        }
        Self::connect_with_interceptor(endpoint.into(), headers)
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
        Self::connect_with_interceptor(endpoint, headers)
    }

    fn connect_with_interceptor(
        endpoint: String,
        headers: HeadersInterceptor,
    ) -> Result<Self, TransportError> {
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
                // A response over this client's decode limit is refused by
                // the client itself, not by the endpoint, so it says nothing
                // about the endpoint's rate limit. The decompression variant
                // carries `ResourceExhausted`, which the gate would otherwise
                // read as a rate-limit answer and slow every read on it.
                if !Self::is_over_decode_limit(&status) {
                    self.gate.note_status(&status);
                }
                Err(map_err(status))
            }
        }
    }

    /// Resolves a standalone SDK transaction builder against this client's
    /// endpoint, including object metadata, gas selection, and simulation.
    pub async fn build_transaction(
        &self,
        builder: TransactionBuilder,
    ) -> Result<SdkTransaction, TransactionBuilderError> {
        self.gate.wait_for_capacity().await;
        let transaction = builder.build(&mut self.rpc.clone()).await;
        if transaction.is_ok() {
            self.gate.note_success();
        }
        transaction
    }

    pub async fn get_chain_identifier(&self) -> Result<ChainIdentifier, TransportError> {
        SuiWriter::get_sui_chain_identifier(self).await
    }

    fn decode_full_checkpoint(
        checkpoint: &proto::Checkpoint,
    ) -> Result<CheckpointData, TransportError> {
        Self::check_move_object_ids(checkpoint)?;
        FullCheckpoint::try_from(checkpoint)
            .map(CheckpointData::from)
            .map_err(|e| TransportError::Encoding(format!("decode full checkpoint: {e}")))
    }

    /// Refuse a checkpoint holding a Move object whose contents are too
    /// short to start with its 32-byte id.
    ///
    /// Sui's conversion of the checkpoint's object set calls
    /// `MoveObject::id()`, which unwraps `MoveObject::id_opt`, and BCS accepts
    /// contents of any length. A failed unwrap ends the process. So each Move
    /// object is decoded and its id read with `id_opt` first.
    fn check_move_object_ids(checkpoint: &proto::Checkpoint) -> Result<(), TransportError> {
        checkpoint
            .objects
            .iter()
            .flat_map(|set| set.objects.iter())
            .filter_map(|object| object.bcs.as_ref())
            .try_for_each(|bcs| {
                let object: Object = bcs
                    .deserialize()
                    .map_err(|e| TransportError::Encoding(format!("decode Object: {e}")))?;
                object
                    .data
                    .try_as_move()
                    .map_or(Ok(()), |move_object| {
                        MoveObject::id_opt(move_object.contents()).map(|_| ())
                    })
                    .map_err(|e| {
                        TransportError::Encoding(format!("Move object contents hold no id: {e}"))
                    })
            })
    }

    pub async fn get_full_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<CheckpointData, TransportError> {
        SuiTransport::get_full_checkpoint(self, sequence_number).await
    }

    /// The certified summary of checkpoint `seq` and the latest written state
    /// of each object its transactions wrote, read in parts instead of as one
    /// whole checkpoint. Built for a checkpoint whose whole read is over
    /// [`FULL_CHECKPOINT_DECODE_LIMIT`]: these states are all an object
    /// inclusion proof needs from it, through Sui's
    /// `CheckpointArtifacts::from_object_states`.
    ///
    /// The first read returns the summary, its signature and the transaction
    /// digests. A summary past checkpoint 0 must name its previous
    /// checkpoint, and the number of digests must equal the summary's
    /// `network_total_transactions` minus the previous checkpoint's, read
    /// with the small summary read by the summary's `previous_digest`. Then
    /// each transaction's effects come in a read of their own. Every read
    /// decodes at most [`CHECKPOINT_PART_DECODE_LIMIT`], and a read that
    /// fails as `Network` is retried on its own (see [`retry_part_read`]).
    ///
    /// The effects reads run [`CHECKPOINT_PART_CONCURRENCY`] at a time, and
    /// their results are taken in checkpoint order. Each result is folded
    /// into the object states (see [`fold_written_object_states`]) and then
    /// dropped, so no more than the reads in flight are held at once. The
    /// first result, in checkpoint order, that is an error once its retries
    /// are spent stops the reads.
    ///
    /// Nothing read here is trusted: a proof built from these states is
    /// checked against the certified summary by whoever verifies it.
    pub async fn get_checkpoint_object_states_in_parts(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<(CertifiedCheckpointSummary, CheckpointObjectStates), TransportError> {
        let (summary, digests) =
            retry_part_read(PART_READ_FIRST_DELAY, || self.get_checkpoint_digests(seq)).await?;
        let previous = match summary.data().previous_digest {
            Some(previous_digest) => Some(
                retry_part_read(PART_READ_FIRST_DELAY, || {
                    self.get_previous_checkpoint_summary(previous_digest)
                })
                .await?,
            ),
            None => None,
        };
        check_transaction_count(
            summary.data(),
            previous.as_ref().map(|previous| previous.data()),
            digests.len(),
        )?;
        let mut reads = stream::iter(digests)
            .map(|digest| {
                retry_part_read(PART_READ_FIRST_DELAY, move || {
                    self.get_transaction_effects(digest)
                })
            })
            .buffered(CHECKPOINT_PART_CONCURRENCY);
        let mut states = CheckpointObjectStates::new();
        while let Some(read) = reads.next().await {
            fold_written_object_states(seq, &mut states, &read?)?;
        }
        Ok((summary, states))
    }

    /// The certified summary of checkpoint `seq` and its transaction digests,
    /// under [`CHECKPOINT_PART_DECODE_LIMIT`].
    async fn get_checkpoint_digests(
        &self,
        seq: CheckpointSequenceNumber,
    ) -> Result<(CertifiedCheckpointSummary, Vec<TransactionDigest>), TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetCheckpointRequest::by_sequence_number(seq);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec![
                "summary.bcs".into(),
                "signature".into(),
                "transactions.digest".into(),
            ],
        });
        let response = self
            .gated(async move {
                rpc.ledger_client()
                    .max_decoding_message_size(CHECKPOINT_PART_DECODE_LIMIT)
                    .get_checkpoint(request)
                    .await
            })
            .await?
            .into_inner();
        let checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} not found")))?;
        let summary = Self::decode_certified_summary(&checkpoint)?;
        let digests = checkpoint
            .transactions
            .iter()
            .map(|executed| {
                executed
                    .digest
                    .as_deref()
                    .ok_or_else(|| TransportError::Encoding("missing transaction digest".into()))?
                    .parse::<TransactionDigest>()
                    .map_err(|e| {
                        TransportError::Encoding(format!("decode transaction digest: {e}"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((summary, digests))
    }

    /// The summary whose digest is `digest`, refused unless it hashes to it.
    async fn get_previous_checkpoint_summary(
        &self,
        digest: CheckpointDigest,
    ) -> Result<CertifiedCheckpointSummary, TransportError> {
        let summary = self.get_checkpoint_summary_by_digest(digest).await?;
        if *summary.digest() != digest {
            return Err(TransportError::Encoding(format!(
                "summary returned for checkpoint digest {digest} hashes to {}",
                summary.digest()
            )));
        }
        Ok(summary)
    }

    /// The effects of `digest`, alone, under [`CHECKPOINT_PART_DECODE_LIMIT`].
    async fn get_transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<TransactionEffects, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetTransactionRequest::default();
        request.digest = Some(digest.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["effects.bcs".into()],
        });
        let response = self
            .gated(async move {
                rpc.ledger_client()
                    .max_decoding_message_size(CHECKPOINT_PART_DECODE_LIMIT)
                    .get_transaction(request)
                    .await
            })
            .await?
            .into_inner();
        let effects: TransactionEffects = response
            .transaction
            .ok_or_else(|| TransportError::NotFound(format!("transaction {digest} not found")))?
            .effects()
            .bcs()
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode effects.bcs: {e}")))?;
        if *effects.transaction_digest() != digest {
            return Err(TransportError::Encoding(format!(
                "effects returned for transaction {digest} belong to {}",
                effects.transaction_digest()
            )));
        }
        Ok(effects)
    }

    pub async fn get_object(&self, object_id: ObjectID) -> Result<Object, TransportError> {
        SuiTransport::get_object(self, object_id).await
    }

    pub async fn get_object_ref(&self, object_id: ObjectID) -> Result<ObjectRef, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::GetObjectRequest::default();
        request.object_id = Some(object_id.to_string());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["object_id".into(), "version".into(), "digest".into()],
        });
        let response = self
            .gated(async move { rpc.ledger_client().get_object(request).await })
            .await?
            .into_inner();
        let object = response
            .object
            .ok_or_else(|| TransportError::NotFound(format!("object {object_id} not found")))?;
        Self::decode_object_ref(&object)
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
        let address = address.into();
        let gas_type = struct_tag_core_to_sdk(GAS::type_())
            .map_err(|error| TransportError::Encoding(format!("convert SUI type: {error}")))?
            .into();
        let rpc = self.rpc.clone();
        let objects = self
            .gated(async move { rpc.select_coins(&address, &gas_type, amount, &[]).await })
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
        let mut request = tonic::Request::new(Self::execute_transaction_request(transaction)?);
        request.set_timeout(EXECUTE_AND_WAIT_TIMEOUT);
        // Admission happens before the request deadline starts, so a shared
        // cooldown does not consume the execution timeout.
        self.gate.wait_for_capacity().await;
        let result = tokio::time::timeout(
            EXECUTE_AND_WAIT_TIMEOUT,
            rpc.execute_transaction_and_wait_for_checkpoint(request, SUBMIT_TIMEOUT),
        )
        .await
        .map_err(|_| {
            TransportError::Network(format!(
                "execute transaction and checkpoint wait exceeded {EXECUTE_AND_WAIT_TIMEOUT:?}"
            ))
        })?;
        let response = match result {
            Ok(response) => {
                self.gate.note_success();
                response
            }
            Err(ExecuteAndWaitError::CheckpointTimeout(response)) => {
                self.gate.note_success();
                tracing::warn!(
                    "transaction executed successfully, but checkpoint inclusion timed out"
                );
                response
            }
            Err(ExecuteAndWaitError::CheckpointStreamError { response, error }) => {
                self.gate.note_status(&error);
                tracing::warn!(%error, "transaction executed successfully, but checkpoint stream failed");
                response
            }
            Err(ExecuteAndWaitError::RpcError(status)) => {
                self.gate.note_status(&status);
                return Err(Self::rpc_err(status));
            }
            Err(error) => {
                return Err(TransportError::Network(format!(
                    "execute transaction and wait for checkpoint: {error}"
                )));
            }
        };
        Self::decode_executed_transaction(response.into_inner().transaction())
    }

    async fn execute_transaction_immediate(
        &self,
        transaction: &Transaction,
    ) -> Result<ExecutedTransaction, TransportError> {
        let mut request = tonic::Request::new(Self::execute_transaction_request(transaction)?);
        request.set_timeout(SUBMIT_TIMEOUT);
        let mut rpc = self.rpc.clone();
        let response = self
            .gated(async move { rpc.execution_client().execute_transaction(request).await })
            .await?
            .into_inner();
        Self::decode_executed_transaction(response.transaction())
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
        object_type: Option<StructTag>,
        page_size: Option<u32>,
        page_token: Option<bytes::Bytes>,
    ) -> Result<ObjectPage, TransportError> {
        let response = self
            .list_owned_objects_page(
                owner,
                object_type.map(|type_| type_.to_canonical_string(true)),
                page_size,
                page_token,
                vec!["bcs".into()],
            )
            .await?;
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
        self.list_dynamic_fields_page(parent, page_size, page_token)
            .await
    }

    async fn list_owned_objects_page(
        &self,
        owner: SuiAddress,
        object_type: Option<String>,
        page_size: Option<u32>,
        page_token: Option<bytes::Bytes>,
        read_mask: Vec<String>,
    ) -> Result<proto::ListOwnedObjectsResponse, TransportError> {
        let mut rpc = self.rpc.clone();
        let mut request = proto::ListOwnedObjectsRequest::default();
        request.owner = Some(owner.to_string());
        request.object_type = object_type;
        request.page_size = page_size;
        request.page_token = page_token;
        request.read_mask = Some(prost_types::FieldMask { paths: read_mask });
        self.gated(async move { rpc.state_client().list_owned_objects(request).await })
            .await
            .map(|response| response.into_inner())
    }

    async fn list_dynamic_fields_page(
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
        } else if Self::is_over_decode_limit(&status) {
            TransportError::TooLarge(status.message().to_string())
        } else {
            TransportError::Network(status.to_string())
        }
    }

    /// Whether `status` is tonic's own refusal of a response larger than the
    /// call's `max_decoding_message_size`. tonic 0.14 raises two statuses for
    /// it (`codec/decode.rs`): `OutOfRange` when the frame's declared length
    /// is over the limit, and `ResourceExhausted` when a zstd-compressed frame
    /// passes the limit while it is decompressed. Both the code and tonic's
    /// message are matched, so an endpoint's own `OutOfRange` or
    /// `ResourceExhausted` answer keeps its usual meaning.
    fn is_over_decode_limit(status: &tonic::Status) -> bool {
        match status.code() {
            tonic::Code::OutOfRange => status
                .message()
                .starts_with("Error, decoded message length too large"),
            tonic::Code::ResourceExhausted => status
                .message()
                .starts_with("Error decompressing: size limit"),
            _ => false,
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
        let summary_data: CheckpointSummary = proto_checkpoint
            .summary
            .as_ref()
            .and_then(|s| s.bcs.as_ref())
            .ok_or_else(|| TransportError::Encoding("missing summary.bcs".into()))?
            .deserialize()
            .map_err(|e| TransportError::Encoding(format!("decode CheckpointSummary: {e}")))?;
        let proto_sig = proto_checkpoint.signature.as_ref().ok_or_else(|| {
            TransportError::Encoding("signature missing on checkpoint response".into())
        })?;
        let signature = AuthorityStrongQuorumSignInfo::from(
            ValidatorAggregatedSignature::try_from(proto_sig)
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

    fn decode_object_ref(proto_object: &proto::Object) -> Result<ObjectRef, TransportError> {
        let object_id = proto_object
            .object_id_opt()
            .ok_or_else(|| TransportError::Encoding("missing object.object_id".into()))?
            .parse()
            .map_err(|error| TransportError::Encoding(format!("decode object id: {error}")))?;
        let version = proto_object
            .version_opt()
            .ok_or_else(|| TransportError::Encoding("missing object.version".into()))?
            .into();
        let digest = proto_object
            .digest_opt()
            .ok_or_else(|| TransportError::Encoding("missing object.digest".into()))?
            .parse()
            .map_err(|error| TransportError::Encoding(format!("decode object digest: {error}")))?;
        Ok((object_id, version, digest))
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
            .and_then(|timestamp| proto_to_timestamp_ms(timestamp).ok());

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
        Some(ProtoValueKind::NumberValue(number))
            if number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0 =>
        {
            if *number >= 0.0 {
                serde_json::Value::from(*number as u64)
            } else {
                serde_json::Value::from(*number as i64)
            }
        }
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

    async fn get_sui_node_info(&self) -> Result<Option<SuiNodeInfo>, TransportError> {
        // Same `GetServiceInfo` call `get_latest_checkpoint_sequence` and
        // `get_sui_chain_identifier` already use; we read two different
        // fields off it. It takes no arguments and touches no store beyond
        // the node's own watermarks, so it is the cheapest call the fullnode
        // serves — which is what makes it safe to poll on a timer.
        let mut rpc = self.rpc.clone();
        let response = self
            .gated_network(async move {
                rpc.ledger_client()
                    .get_service_info(proto::GetServiceInfoRequest::default())
                    .await
            })
            .await?
            .into_inner();
        Ok(Some(SuiNodeInfo {
            server_version: response.server_opt().map(str::to_owned),
            chain_identifier: response.chain_id_opt().map(str::to_owned),
        }))
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

    async fn get_committee(&self, epoch: Option<u64>) -> Result<Committee, TransportError> {
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
        request.read_mask = Some(FullCheckpoint::proto_field_mask());
        let response = self
            .gated(async move {
                rpc.ledger_client()
                    .max_decoding_message_size(FULL_CHECKPOINT_DECODE_LIMIT)
                    .get_checkpoint(request)
                    .await
            })
            .await?
            .into_inner();
        let checkpoint = response
            .checkpoint
            .ok_or_else(|| TransportError::NotFound(format!("checkpoint {seq} not found")))?;
        Self::decode_full_checkpoint(&checkpoint)
    }

    async fn get_checkpoint_summary_by_digest(
        &self,
        digest: CheckpointDigest,
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
        let response = self
            .list_dynamic_fields_page(parent, page_size, page_token.map(bytes::Bytes::from))
            .await?;
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
        let mut refs = Vec::new();
        let mut page_token = None;
        loop {
            if refs.len() >= MAX_GAS_PAYMENT_OBJECTS {
                break;
            }
            let page = self
                .list_owned_objects_page(
                    address,
                    Some(GasCoin::type_().to_canonical_string(true)),
                    None,
                    page_token,
                    vec!["object_id".into(), "version".into(), "digest".into()],
                )
                .await?;
            let object_refs = page
                .objects
                .iter()
                .map(Self::decode_object_ref)
                .collect::<Result<Vec<_>, _>>()?;
            refs.extend(object_refs);
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

    async fn get_sui_chain_identifier(&self) -> Result<ChainIdentifier, TransportError> {
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
            .parse::<SdkDigest>()
            .map_err(|e| TransportError::Encoding(format!("decode chain identifier: {e}")))?;
        Ok(ChainIdentifier::from(CheckpointDigest::from(digest)))
    }

    async fn execute_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<SubmittedTransaction, TransportError> {
        // The notifier holds its serial submission lock across this call. Stop
        // at executed effects; checkpoint observation is a read-side concern
        // and must not couple writer throughput or turn a committed tx into a
        // reported failure.
        let executed = self.execute_transaction_immediate(tx).await?;
        Ok(SubmittedTransaction {
            digest: *tx.digest(),
            effects: executed.effects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use proto::get_checkpoint_request::CheckpointId;
    use proto::ledger_service_server::{LedgerService, LedgerServiceServer};
    use sui_rpc::field::FieldMaskTree;
    use sui_rpc::merge::Merge;
    use sui_types::digests::CheckpointContentsDigest;
    use sui_types::effects::EffectsObjectChange;
    use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
    use sui_types::execution_status::ExecutionStatus;
    use sui_types::full_checkpoint_content::{ExecutedTransaction, ObjectSet};
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::CheckpointContents;
    use sui_types::test_checkpoint_data_builder::TestCheckpointBuilder;
    use sui_types::transaction::{
        AllowedProposers, GasData, ProgrammableTransaction, TransactionDataV1,
        TransactionExpiration, TransactionKind,
    };
    use tokio::net::TcpListener;
    use tonic::transport::Server;

    #[test]
    fn validity_checkpoint_preserves_transaction_bytes_and_certified_contents() {
        let transaction = TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs: vec![],
                commands: vec![],
            }),
            sender: SuiAddress::ZERO,
            gas_data: GasData {
                payment: vec![],
                owner: SuiAddress::ZERO,
                price: 1,
                budget: 1_000_000,
            },
            expiration: TransactionExpiration::Validity {
                min_epoch: Some(0),
                max_epoch: Some(1),
                min_timestamp: None,
                max_timestamp: None,
                chain: ChainIdentifier::from(CheckpointDigest::default()),
                nonce: 42,
                allowed_proposers: Some(AllowedProposers {
                    epoch: 0,
                    proposers: vec![0, 1].try_into().unwrap(),
                }),
            },
        });
        let bytes = bcs::to_bytes(&transaction).unwrap();
        // Exercise the standalone SDK as well as the core decoder used below.
        let sdk: SdkTransaction = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(bcs::to_bytes(&sdk).unwrap(), bytes);
        let mut effects = TransactionEffects::default();
        *effects.transaction_digest_mut_for_testing() = transaction.digest();
        let contents =
            CheckpointContents::new_with_digests_only_for_tests([effects.execution_digests()]);
        let (committee, keys) = Committee::new_simple_test_committee();
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: 1,
            network_total_transactions: 1,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: None,
            version_specific_data: vec![],
        };
        let checkpoint = FullCheckpoint {
            summary: CertifiedCheckpointSummary::new_from_keypairs_for_testing(
                summary, &keys, &committee,
            ),
            contents,
            transactions: vec![ExecutedTransaction {
                transaction,
                signatures: vec![],
                effects,
                events: None,
                unchanged_loaded_runtime_objects: vec![],
            }],
            object_set: ObjectSet::default(),
        };
        let mask = FieldMaskTree::from(FullCheckpoint::proto_field_mask());
        let encoded = proto::Checkpoint::merge_from(&checkpoint, &mask);
        let decoded = SuiGrpcClient::decode_full_checkpoint(&encoded).unwrap();
        assert_eq!(decoded.transactions.len(), 1);
        let persisted = bcs::to_bytes(&decoded).unwrap();
        let restored: CheckpointData = bcs::from_bytes(&persisted).unwrap();
        assert_eq!(bcs::to_bytes(&restored).unwrap(), persisted);
        assert_eq!(
            bcs::to_bytes(&decoded.transactions[0].transaction.intent_message().value).unwrap(),
            bytes
        );
        assert_eq!(
            *decoded.transactions[0].transaction.digest(),
            checkpoint.transactions[0].transaction.digest()
        );
        decoded
            .checkpoint_summary
            .verify_with_contents(&committee, Some(&decoded.checkpoint_contents))
            .unwrap();

        // The signature must still reject a modified commitment after decoding.
        let wrong_contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        assert!(
            decoded
                .checkpoint_summary
                .verify_with_contents(&committee, Some(&wrong_contents))
                .is_err()
        );
    }

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
            serde_json::json!({ "items": [7, true] })
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

    /// tonic's two refusals of a response over the decode limit map to
    /// `TooLarge`, with the exact texts tonic 0.14 writes. The same codes
    /// with any other message stay `Network`.
    #[test]
    fn rpc_status_err_maps_a_response_over_the_decode_limit_to_too_large() {
        for status in [
            tonic::Status::out_of_range(
                "Error, decoded message length too large: found 140000000 bytes, \
                 the limit is: 134217728 bytes",
            ),
            tonic::Status::resource_exhausted(
                "Error decompressing: size limit, of 134217728 bytes, exceeded while \
                 decompressing message",
            ),
        ] {
            let code = status.code();
            assert!(SuiGrpcClient::is_over_decode_limit(&status));
            match SuiGrpcClient::rpc_status_err(status) {
                TransportError::TooLarge(_) => {}
                other => {
                    panic!("{code:?} over the decode limit must map to TooLarge, got {other:?}")
                }
            }
        }
        for status in [
            tonic::Status::out_of_range("checkpoint sequence out of range"),
            tonic::Status::resource_exhausted("busy"),
        ] {
            let code = status.code();
            assert!(!SuiGrpcClient::is_over_decode_limit(&status));
            match SuiGrpcClient::rpc_status_err(status) {
                TransportError::Network(_) => {}
                other => panic!("{code:?} from the endpoint must map to Network, got {other:?}"),
            }
        }
    }

    fn summary_counting(
        sequence_number: CheckpointSequenceNumber,
        network_total_transactions: u64,
    ) -> CheckpointSummary {
        CheckpointSummary {
            epoch: 0,
            sequence_number,
            network_total_transactions,
            content_digest: CheckpointContentsDigest::new([0; 32]),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: None,
            version_specific_data: vec![],
        }
    }

    /// The digest count must equal the summary's total minus the previous
    /// checkpoint's total. The first checkpoint has no previous one, so its
    /// count is its total. A list one short or one long is refused.
    #[test]
    fn the_digest_count_must_match_the_summaries() {
        let previous = summary_counting(9, 100);
        let summary = summary_counting(10, 103);
        assert!(check_transaction_count(&summary, Some(&previous), 3).is_ok());
        for count in [2, 4] {
            assert!(matches!(
                check_transaction_count(&summary, Some(&previous), count),
                Err(TransportError::Encoding(_))
            ));
        }
        let first = summary_counting(0, 1);
        assert!(check_transaction_count(&first, None, 1).is_ok());
        assert!(matches!(
            check_transaction_count(&first, None, 0),
            Err(TransportError::Encoding(_))
        ));
        assert!(matches!(
            check_transaction_count(&summary_counting(10, 50), Some(&previous), 0),
            Err(TransportError::Encoding(_))
        ));
    }

    /// A part read that fails as `Network` is tried again, up to the cap,
    /// and its later success is returned. Any other failure is returned at
    /// once, and a read that keeps failing stops at the cap.
    #[tokio::test]
    async fn a_part_read_is_retried_on_network_errors_only() {
        let calls = AtomicU32::new(0);
        let read = || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call < 2 {
                    Err(TransportError::Network("refused".into()))
                } else {
                    Ok(call)
                }
            }
        };
        assert_eq!(retry_part_read(Duration::ZERO, read).await.unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let calls = AtomicU32::new(0);
        let read = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(TransportError::NotFound("pruned".into())) }
        };
        assert!(matches!(
            retry_part_read(Duration::ZERO, read).await,
            Err(TransportError::NotFound(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let calls = AtomicU32::new(0);
        let read = || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(TransportError::Network("refused".into())) }
        };
        assert!(matches!(
            retry_part_read(Duration::ZERO, read).await,
            Err(TransportError::Network(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), PART_READ_ATTEMPTS);
    }

    /// An in-process Sui ledger service holding one checkpoint, its previous
    /// checkpoint's summary, and per-transaction effects. It records the read
    /// mask of every call and the order in which effects reads finish.
    struct MockLedger {
        current: CertifiedCheckpointSummary,
        previous: CertifiedCheckpointSummary,
        digests: Vec<TransactionDigest>,
        /// The effects each digest's read answers with.
        answers: HashMap<TransactionDigest, TransactionEffects>,
        /// How long each digest's read waits before it answers.
        delays: HashMap<TransactionDigest, Duration>,
        /// A digest whose first read is refused as `Unavailable`.
        refused_once: Option<TransactionDigest>,
        reads: Mutex<HashMap<TransactionDigest, u32>>,
        masks: Mutex<Vec<(String, Vec<String>)>>,
        finished: Mutex<Vec<TransactionDigest>>,
    }

    impl MockLedger {
        fn record_mask(&self, call: String, mask: Option<prost_types::FieldMask>) {
            self.masks
                .lock()
                .unwrap()
                .push((call, mask.map(|mask| mask.paths).unwrap_or_default()));
        }

        fn summary_proto(summary: &CertifiedCheckpointSummary) -> proto::Checkpoint {
            let mask = FieldMaskTree::from(prost_types::FieldMask {
                paths: vec!["summary.bcs".into(), "signature".into()],
            });
            let mut checkpoint = proto::Checkpoint::default();
            checkpoint.merge(summary.data(), &mask);
            checkpoint.merge(summary.auth_sig().clone(), &mask);
            checkpoint
        }
    }

    #[async_trait]
    impl LedgerService for MockLedger {
        async fn get_checkpoint(
            &self,
            request: tonic::Request<proto::GetCheckpointRequest>,
        ) -> Result<tonic::Response<proto::GetCheckpointResponse>, tonic::Status> {
            let request = request.into_inner();
            match request.checkpoint_id {
                Some(CheckpointId::SequenceNumber(seq))
                    if seq == self.current.data().sequence_number =>
                {
                    self.record_mask(format!("checkpoint {seq}"), request.read_mask);
                    let mut checkpoint = Self::summary_proto(&self.current);
                    checkpoint.transactions = self
                        .digests
                        .iter()
                        .map(|digest| {
                            let mut transaction = proto::ExecutedTransaction::default();
                            transaction.digest = Some(digest.to_string());
                            transaction
                        })
                        .collect();
                    Ok(tonic::Response::new(proto::GetCheckpointResponse::new(
                        checkpoint,
                    )))
                }
                Some(CheckpointId::Digest(digest))
                    if digest == self.previous.digest().to_string() =>
                {
                    self.record_mask("previous summary".into(), request.read_mask);
                    Ok(tonic::Response::new(proto::GetCheckpointResponse::new(
                        Self::summary_proto(&self.previous),
                    )))
                }
                _ => Err(tonic::Status::not_found("no such checkpoint")),
            }
        }

        async fn get_transaction(
            &self,
            request: tonic::Request<proto::GetTransactionRequest>,
        ) -> Result<tonic::Response<proto::GetTransactionResponse>, tonic::Status> {
            let request = request.into_inner();
            let digest: TransactionDigest =
                request
                    .digest
                    .as_deref()
                    .unwrap_or_default()
                    .parse()
                    .map_err(|_| tonic::Status::invalid_argument("bad digest"))?;
            self.record_mask(format!("transaction {digest}"), request.read_mask);
            let read = {
                let mut reads = self.reads.lock().unwrap();
                let read = reads.entry(digest).or_insert(0);
                *read += 1;
                *read
            };
            if self.refused_once == Some(digest) && read == 1 {
                return Err(tonic::Status::unavailable("busy"));
            }
            sleep(self.delays.get(&digest).copied().unwrap_or_default()).await;
            let effects = self
                .answers
                .get(&digest)
                .ok_or_else(|| tonic::Status::not_found("no such transaction"))?;
            let mut effects_proto = proto::TransactionEffects::default();
            effects_proto.bcs = Some(proto::Bcs::serialize(effects).unwrap());
            let mut transaction = proto::ExecutedTransaction::default();
            transaction.effects = Some(effects_proto);
            self.finished.lock().unwrap().push(digest);
            Ok(tonic::Response::new(proto::GetTransactionResponse::new(
                transaction,
            )))
        }
    }

    /// Three transactions in checkpoint 1, whose previous checkpoint 0 counted
    /// five transactions in all. In checkpoint order, the transactions write
    /// one object at versions 1, 2 and 3.
    fn mock_ledger() -> MockLedger {
        mock_ledger_naming_previous(true)
    }

    /// The object the mock ledger's transactions write.
    fn mock_object() -> Object {
        Object::immutable_with_id_for_testing(ObjectID::from_single_byte(0x0B))
    }

    /// As [`mock_ledger`], with checkpoint 1's summary naming its previous
    /// checkpoint only when `names_previous`. A summary that names none
    /// counts exactly its own three transactions, so the count alone would
    /// accept it.
    fn mock_ledger_naming_previous(names_previous: bool) -> MockLedger {
        let (committee, keys) = Committee::new_simple_test_committee();
        let certify = |summary| {
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, &keys, &committee)
        };
        let previous = certify(summary_counting(0, 5));
        let current = if names_previous {
            certify(CheckpointSummary {
                previous_digest: Some(*previous.digest()),
                ..summary_counting(1, 8)
            })
        } else {
            certify(summary_counting(1, 3))
        };
        let mut digests: Vec<TransactionDigest> =
            (0..3).map(|_| TransactionDigest::random()).collect();
        digests.sort();
        let object = mock_object();
        let answers: HashMap<TransactionDigest, TransactionEffects> = digests
            .iter()
            .zip(1u64..)
            .map(|(digest, version)| {
                let effects = TransactionEffects::new_from_execution_v2(
                    ExecutionStatus::Success,
                    0,
                    GasCostSummary::default(),
                    vec![],
                    *digest,
                    SequenceNumber::from_u64(version),
                    BTreeMap::from([(
                        object.id(),
                        EffectsObjectChange::new(None, Some(&object), true, false),
                    )]),
                    None,
                    None,
                    vec![],
                );
                (*digest, effects)
            })
            .collect();
        MockLedger {
            current,
            previous,
            digests,
            answers,
            delays: HashMap::new(),
            refused_once: None,
            reads: Mutex::new(HashMap::new()),
            masks: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
        }
    }

    /// Serve `ledger` on a local port and connect a client to it.
    async fn serve(ledger: Arc<MockLedger>) -> SuiGrpcClient {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = stream::unfold(listener, |listener| async move {
            let accepted = listener.accept().await.map(|(socket, _)| socket);
            Some((accepted, listener))
        });
        tokio::spawn(
            Server::builder()
                .add_service(LedgerServiceServer::from_arc(ledger))
                .serve_with_incoming(incoming),
        );
        SuiGrpcClient::connect(format!("http://{address}")).unwrap()
    }

    /// The part reader against a ledger service: it sends the narrow read
    /// masks, checks the digest count against the two summaries, retries a
    /// refused effects read, and folds the effects in checkpoint order
    /// although the reads finish in another order. Folded in the order they
    /// finished, the versions would go down and be refused.
    #[tokio::test]
    async fn the_part_reader_reads_narrow_parts_in_order_with_retries() {
        let mut ledger = mock_ledger();
        let digests = ledger.digests.clone();
        ledger.delays.insert(digests[0], Duration::from_millis(300));
        ledger.refused_once = Some(digests[1]);
        let ledger = Arc::new(ledger);
        let client = serve(ledger.clone()).await;

        let (summary, states) = client
            .get_checkpoint_object_states_in_parts(1)
            .await
            .expect("the parts are read");

        assert_eq!(summary.digest(), ledger.current.digest());
        let object = mock_object();
        assert_eq!(
            states,
            CheckpointObjectStates::from([(
                object.id(),
                (SequenceNumber::from_u64(3), object.digest())
            )])
        );
        let finished = ledger.finished.lock().unwrap().clone();
        assert_eq!(finished.len(), 3);
        assert_ne!(finished, digests, "the reads finished out of order");
        assert_eq!(ledger.reads.lock().unwrap()[&digests[1]], 2);

        let masks = ledger.masks.lock().unwrap().clone();
        let mask_of = |call: &str| {
            masks
                .iter()
                .filter(|(name, _)| name == call)
                .map(|(_, paths)| paths.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            mask_of("checkpoint 1"),
            vec![vec!["summary.bcs", "signature", "transactions.digest"]]
        );
        assert_eq!(
            mask_of("previous summary"),
            vec![vec!["summary.bcs", "signature"]]
        );
        for digest in &digests {
            let masks = mask_of(&format!("transaction {digest}"));
            assert!(!masks.is_empty());
            assert!(masks.iter().all(|paths| paths == &["effects.bcs"]));
        }
    }

    /// An effects read answered with another transaction's effects is
    /// refused, and so is a digest list whose length the summaries do not
    /// allow.
    #[tokio::test]
    async fn the_part_reader_refuses_wrong_effects_and_a_wrong_count() {
        let mut ledger = mock_ledger();
        let digests = ledger.digests.clone();
        let other = ledger.answers[&digests[0]].clone();
        ledger.answers.insert(digests[2], other);
        let client = serve(Arc::new(ledger)).await;
        assert!(matches!(
            client.get_checkpoint_object_states_in_parts(1).await,
            Err(TransportError::Encoding(_))
        ));

        let mut ledger = mock_ledger();
        ledger.digests.pop();
        let client = serve(Arc::new(ledger)).await;
        assert!(matches!(
            client.get_checkpoint_object_states_in_parts(1).await,
            Err(TransportError::Encoding(_))
        ));
    }

    /// BCS accepts a Move object whose contents are shorter than its 32-byte
    /// id. In an otherwise valid checkpoint, which decodes, such an object
    /// makes the whole-checkpoint decode refuse the checkpoint as `Encoding`,
    /// where Sui's object-set conversion would abort the process.
    #[test]
    fn a_move_object_too_short_for_its_id_is_refused() {
        let object = Object::immutable_with_id_for_testing(ObjectID::random());
        let contents = object.data.try_as_move().unwrap().contents().to_vec();
        let bytes = bcs::to_bytes(&object).unwrap();
        let length = u8::try_from(contents.len()).unwrap();
        let at = bytes
            .windows(contents.len() + 1)
            .position(|window| window[0] == length && window[1..] == contents[..])
            .expect("the contents appear in the object's BCS");
        let short = [
            &bytes[..at],
            &[16u8][..],
            &contents[..16],
            &bytes[at + 1 + contents.len()..],
        ]
        .concat();
        let short: Object = bcs::from_bytes(&short).expect("BCS accepts short contents");
        assert_eq!(short.data.try_as_move().unwrap().contents().len(), 16);

        let mut builder = TestCheckpointBuilder::new(1)
            .start_transaction(0)
            .create_owned_object(1)
            .finish_transaction();
        let checkpoint = builder.build_checkpoint();
        let mask = FieldMaskTree::from(FullCheckpoint::proto_field_mask());
        let mut encoded = proto::Checkpoint::merge_from(&checkpoint, &mask);
        SuiGrpcClient::decode_full_checkpoint(&encoded).expect("the valid checkpoint decodes");

        let objects = encoded
            .objects
            .as_mut()
            .expect("the checkpoint carries its objects");
        assert!(!objects.objects.is_empty());
        objects.objects[0].bcs = Some(proto::Bcs::serialize(&short).unwrap());
        match SuiGrpcClient::decode_full_checkpoint(&encoded) {
            Err(TransportError::Encoding(reason)) => assert!(
                reason.contains("Move object contents hold no id"),
                "{reason}"
            ),
            Err(other) => panic!("a short object must be refused by the id check, got {other:?}"),
            Ok(_) => panic!("a short object must be refused"),
        }
    }

    /// The first effects read that fails without a retry stops the part read
    /// at once, without waiting for the reads still in flight.
    #[tokio::test]
    async fn the_first_refused_effects_read_stops_the_part_read() {
        let mut ledger = mock_ledger();
        let digests = ledger.digests.clone();
        let other = ledger.answers[&digests[0]].clone();
        ledger.answers.insert(digests[1], other);
        ledger.delays.insert(digests[2], Duration::from_secs(3));
        let client = serve(Arc::new(ledger)).await;
        let started = Instant::now();
        assert!(matches!(
            client.get_checkpoint_object_states_in_parts(1).await,
            Err(TransportError::Encoding(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A summary past checkpoint 0 that names no previous checkpoint is
    /// refused, even when its own total equals the listed count.
    #[tokio::test]
    async fn a_summary_naming_no_previous_checkpoint_is_refused() {
        let client = serve(Arc::new(mock_ledger_naming_previous(false))).await;
        match client.get_checkpoint_object_states_in_parts(1).await {
            Err(TransportError::Encoding(reason)) => {
                assert!(reason.contains("names no previous checkpoint"), "{reason}")
            }
            other => panic!(
                "a summary naming no previous checkpoint must be refused, got {:?}",
                other.map(|(summary, _)| *summary.digest())
            ),
        }
    }
}
