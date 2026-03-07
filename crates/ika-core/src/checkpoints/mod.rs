// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod checkpoint_metrics;
pub mod checkpoint_output;

use std::collections::HashMap;

use crate::authority::AuthorityState;
pub use crate::checkpoints::checkpoint_metrics::CheckpointMetrics;
use crate::checkpoints::checkpoint_output::{CertifiedCheckpointOutput, CheckpointOutput};
pub use crate::checkpoints::checkpoint_output::{
    CheckpointConsensusAdapter, CheckpointStateSyncAdapter, LogCheckpointOutput,
    SendCheckpointToStateSync, SubmitCheckpointToConsensus,
};
use crate::stake_aggregator::{InsertResult, MultiStakeAggregator};
use ika_types::checkpoint::{
    CertifiedCheckpointMessage, CheckpointKind, CheckpointMessage, CheckpointSequenceNumber,
    CheckpointSignatureMessage, SignedCheckpointMessage, TrustedCheckpointMessage,
    VerifiedCheckpointMessage,
};
use ika_types::crypto::AuthorityStrongQuorumSignInfo;
use ika_types::error::{IkaError, IkaResult};
use ika_types::message_envelope::Message;
use ika_types::sui::EpochStartSystemTrait;
use itertools::Itertools;
use mysten_metrics::{monitored_future, monitored_scope};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::{sync::Notify, task::JoinSet, time::timeout};
use tracing::{debug, error, info, instrument, warn};
use typed_store::Map;
use typed_store::rocksdb;
use typed_store::{
    TypedStoreError,
    rocks::{DBMap, MetricConf, ReadWriteOptions, open_cf_opts},
};

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;

// ── Pending checkpoint types ────────────────────────────────────────────────

pub type CheckpointHeight = u64;
pub type CheckpointSignatureKey = (CheckpointSequenceNumber, u64);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PendingCheckpointInfo {
    pub checkpoint_height: CheckpointHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound(
    serialize = "K::MessageKind: Serialize",
    deserialize = "K::MessageKind: serde::de::DeserializeOwned"
))]
pub enum PendingCheckpoint<K: CheckpointKind> {
    V1(PendingCheckpointV1<K>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound(
    serialize = "K::MessageKind: Serialize",
    deserialize = "K::MessageKind: serde::de::DeserializeOwned"
))]
pub struct PendingCheckpointV1<K: CheckpointKind> {
    pub messages: Vec<K::MessageKind>,
    pub details: PendingCheckpointInfo,
}

impl<K: CheckpointKind> PendingCheckpoint<K> {
    pub fn as_v1(&self) -> &PendingCheckpointV1<K> {
        match self {
            PendingCheckpoint::V1(contents) => contents,
        }
    }

    pub fn into_v1(self) -> PendingCheckpointV1<K> {
        match self {
            PendingCheckpoint::V1(contents) => contents,
        }
    }

    pub fn messages(&self) -> &Vec<K::MessageKind> {
        &self.as_v1().messages
    }

    pub fn details(&self) -> &PendingCheckpointInfo {
        &self.as_v1().details
    }

    pub fn height(&self) -> CheckpointHeight {
        self.details().checkpoint_height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K::MessageKind: Serialize",
    deserialize = "K::MessageKind: serde::de::DeserializeOwned"
))]
pub struct BuilderCheckpointMessage<K: CheckpointKind> {
    pub checkpoint_message: CheckpointMessage<K>,
    pub checkpoint_height: Option<CheckpointHeight>,
    pub position_in_commit: usize,
}

// ── Watermark ───────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum CheckpointHighestWatermark {
    Verified,
    Synced,
    Executed,
    Pruned,
}

// ── CheckpointStore ─────────────────────────────────────────────────────────

/// Column family names used by CheckpointStore. These MUST match the field names
/// from the old `DWalletCheckpointStore` / `SystemCheckpointStore` structs that used
/// `#[derive(DBMapUtils)]`, which generates CF names from struct field names.
///
/// DB migration safety:
/// - CF names are identical to the old per-kind stores → RocksDB opens existing DBs seamlessly.
/// - BCS serialization is layout-based, not name-based → `CheckpointMessage<DWallet>` serializes
///   identically to the old `DWalletCheckpointMessage` since field types and order match.
/// - The `CheckpointHighestWatermark` enum has the same variants in the same order as
///   `DWalletCheckpointHighestWatermark` / `SystemCheckpointHighestWatermark`.
/// - The `Envelope` type uses `serde_name` adapters which are no-ops for BCS (non-human-readable).
///
/// DO NOT reorder these CF names, rename them, or change the field order in value types
/// without a proper DB migration strategy.
const CF_CHECKPOINT_MESSAGE_SEQUENCE_BY_DIGEST: &str = "checkpoint_message_sequence_by_digest";
const CF_CERTIFIED_CHECKPOINTS: &str = "certified_checkpoints";
const CF_LOCALLY_COMPUTED_CHECKPOINTS: &str = "locally_computed_checkpoints";
const CF_WATERMARKS: &str = "watermarks";

const ALL_CF_NAMES: &[&str] = &[
    CF_CHECKPOINT_MESSAGE_SEQUENCE_BY_DIGEST,
    CF_CERTIFIED_CHECKPOINTS,
    CF_LOCALLY_COMPUTED_CHECKPOINTS,
    CF_WATERMARKS,
];

pub struct CheckpointStore<K: CheckpointKind> {
    pub(crate) checkpoint_message_sequence_by_digest:
        DBMap<K::MessageDigest, CheckpointSequenceNumber>,
    pub(crate) certified_checkpoints: DBMap<CheckpointSequenceNumber, TrustedCheckpointMessage<K>>,
    pub(crate) locally_computed_checkpoints: DBMap<CheckpointSequenceNumber, CheckpointMessage<K>>,
    pub(crate) watermarks:
        DBMap<CheckpointHighestWatermark, (CheckpointSequenceNumber, K::MessageDigest)>,
}

impl<K: CheckpointKind> CheckpointStore<K> {
    pub fn new(path: &Path) -> Arc<Self> {
        Arc::new(Self::open_tables_read_write(path, MetricConf::new(K::NAME)))
    }

    fn open_tables_read_write(path: &Path, metric_conf: MetricConf) -> Self {
        let opt_cfs: Vec<(&str, rocksdb::Options)> = ALL_CF_NAMES
            .iter()
            .map(|name| (*name, rocksdb::Options::default()))
            .collect();
        let db = open_cf_opts(path, None, metric_conf, &opt_cfs)
            .unwrap_or_else(|e| panic!("Cannot open DB at {:?}: {e}", path));
        let rw = ReadWriteOptions::default();
        Self {
            checkpoint_message_sequence_by_digest: DBMap::reopen(
                &db,
                Some(CF_CHECKPOINT_MESSAGE_SEQUENCE_BY_DIGEST),
                &rw,
                false,
            )
            .expect("Cannot open checkpoint_message_sequence_by_digest CF"),
            certified_checkpoints: DBMap::reopen(&db, Some(CF_CERTIFIED_CHECKPOINTS), &rw, false)
                .expect("Cannot open certified_checkpoints CF"),
            locally_computed_checkpoints: DBMap::reopen(
                &db,
                Some(CF_LOCALLY_COMPUTED_CHECKPOINTS),
                &rw,
                false,
            )
            .expect("Cannot open locally_computed_checkpoints CF"),
            watermarks: DBMap::reopen(&db, Some(CF_WATERMARKS), &rw, false)
                .expect("Cannot open watermarks CF"),
        }
    }

    pub fn get_checkpoint_by_digest(
        &self,
        digest: &K::MessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        let sequence = self.checkpoint_message_sequence_by_digest.get(digest)?;
        if let Some(sequence) = sequence {
            self.certified_checkpoints
                .get(&sequence)
                .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
        } else {
            Ok(None)
        }
    }

    pub fn get_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        self.certified_checkpoints
            .get(&sequence_number)
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
    }

    pub fn get_locally_computed_checkpoint(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<CheckpointMessage<K>>, TypedStoreError> {
        self.locally_computed_checkpoints.get(&sequence_number)
    }

    pub fn get_latest_certified_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        Ok(self
            .certified_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v.into()))
    }

    pub fn get_latest_locally_computed_checkpoint(
        &self,
    ) -> Result<Option<CheckpointMessage<K>>, TypedStoreError> {
        Ok(self
            .locally_computed_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v))
    }

    pub fn multi_get_checkpoint_by_sequence_number(
        &self,
        sequence_numbers: &[CheckpointSequenceNumber],
    ) -> Result<Vec<Option<VerifiedCheckpointMessage<K>>>, TypedStoreError> {
        let checkpoints = self
            .certified_checkpoints
            .multi_get(sequence_numbers)?
            .into_iter()
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
            .collect();

        Ok(checkpoints)
    }

    pub fn get_highest_verified_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        let highest_verified = if let Some(highest_verified) =
            self.watermarks.get(&CheckpointHighestWatermark::Verified)?
        {
            highest_verified
        } else {
            return Ok(None);
        };
        self.get_checkpoint_by_digest(&highest_verified.1)
    }

    pub fn get_highest_synced_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        let highest_synced = if let Some(highest_synced) =
            self.watermarks.get(&CheckpointHighestWatermark::Synced)?
        {
            highest_synced
        } else {
            return Ok(None);
        };
        self.get_checkpoint_by_digest(&highest_synced.1)
    }

    pub fn get_highest_executed_checkpoint_seq_number(
        &self,
    ) -> Result<Option<CheckpointSequenceNumber>, TypedStoreError> {
        if let Some(highest_executed) =
            self.watermarks.get(&CheckpointHighestWatermark::Executed)?
        {
            Ok(Some(highest_executed.0))
        } else {
            Ok(None)
        }
    }

    pub fn get_highest_executed_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<K>>, TypedStoreError> {
        let highest_executed = if let Some(highest_executed) =
            self.watermarks.get(&CheckpointHighestWatermark::Executed)?
        {
            highest_executed
        } else {
            return Ok(None);
        };
        self.get_checkpoint_by_digest(&highest_executed.1)
    }

    pub fn get_highest_pruned_checkpoint_seq_number(
        &self,
    ) -> Result<CheckpointSequenceNumber, TypedStoreError> {
        Ok(self
            .watermarks
            .get(&CheckpointHighestWatermark::Pruned)?
            .unwrap_or((1, Default::default()))
            .0)
    }

    pub fn insert_certified_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<K>,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Inserting certified {} checkpoint",
            K::NAME,
        );
        let mut batch = self.certified_checkpoints.batch();
        batch.insert_batch(
            &self.checkpoint_message_sequence_by_digest,
            [(*checkpoint.digest(), checkpoint.sequence_number())],
        )?;
        batch.insert_batch(
            &self.certified_checkpoints,
            [(checkpoint.sequence_number(), checkpoint.serializable_ref())],
        )?;
        batch.write()?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn insert_verified_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<K>,
    ) -> Result<(), TypedStoreError> {
        self.insert_certified_checkpoint(checkpoint)?;
        self.update_highest_verified_checkpoint(checkpoint)
    }

    pub fn update_highest_verified_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<K>,
    ) -> Result<(), TypedStoreError> {
        if Some(*checkpoint.sequence_number())
            > self
                .get_highest_verified_checkpoint()?
                .map(|x| *x.sequence_number())
        {
            debug!(
                checkpoint_seq = checkpoint.sequence_number(),
                "Updating highest verified {} checkpoint",
                K::NAME,
            );
            self.watermarks.insert(
                &CheckpointHighestWatermark::Verified,
                &(*checkpoint.sequence_number(), *checkpoint.digest()),
            )?;
        }

        Ok(())
    }

    pub fn update_highest_synced_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<K>,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Updating highest synced {} checkpoint",
            K::NAME,
        );
        self.watermarks.insert(
            &CheckpointHighestWatermark::Synced,
            &(*checkpoint.sequence_number(), *checkpoint.digest()),
        )
    }

    pub fn delete_highest_executed_checkpoint_test_only(&self) -> Result<(), TypedStoreError> {
        let mut wb = self.watermarks.batch();
        wb.delete_batch(
            &self.watermarks,
            std::iter::once(CheckpointHighestWatermark::Executed),
        )?;
        wb.write()?;
        Ok(())
    }
}

// ── Epoch store bridge trait ────────────────────────────────────────────────

/// Trait that bridges the generic checkpoint infrastructure to the epoch store's
/// per-kind DB tables. Each checkpoint kind has separate tables in the epoch store
/// (required by `DBMapUtils`), so this trait dispatches to the correct ones.
pub trait CheckpointEpochTables<K: CheckpointKind> {
    fn get_pending_checkpoints(
        &self,
        last: Option<CheckpointHeight>,
    ) -> IkaResult<Vec<(CheckpointHeight, PendingCheckpoint<K>)>>;

    fn last_built_checkpoint_message_builder(
        &self,
    ) -> IkaResult<Option<BuilderCheckpointMessage<K>>>;

    fn last_built_checkpoint_message(
        &self,
    ) -> IkaResult<Option<(CheckpointSequenceNumber, CheckpointMessage<K>)>>;

    fn get_built_checkpoint_message(
        &self,
        sequence: CheckpointSequenceNumber,
    ) -> IkaResult<Option<CheckpointMessage<K>>>;

    fn process_pending_checkpoint(
        &self,
        height: CheckpointHeight,
        messages: Vec<CheckpointMessage<K>>,
    ) -> IkaResult;

    fn get_last_checkpoint_signature_index(&self) -> IkaResult<u64>;

    fn insert_checkpoint_signature(
        &self,
        seq: CheckpointSequenceNumber,
        index: u64,
        info: &CheckpointSignatureMessage<K>,
    ) -> IkaResult;

    fn record_epoch_first_checkpoint_creation_time_metric(&self);

    /// Collect pending checkpoint signatures starting from the given key.
    fn collect_pending_checkpoint_signatures(
        &self,
        start: Option<CheckpointSignatureKey>,
    ) -> IkaResult<Vec<(CheckpointSignatureKey, CheckpointSignatureMessage<K>)>>;
}

// ── Builder ─────────────────────────────────────────────────────────────────

pub struct CheckpointBuilder<K: CheckpointKind> {
    #[allow(dead_code)]
    state: Arc<AuthorityState>,
    tables: Arc<CheckpointStore<K>>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    output: Box<dyn CheckpointOutput<K>>,
    metrics: Arc<CheckpointMetrics>,
    max_messages_per_checkpoint: usize,
    max_checkpoint_size_bytes: usize,
    previous_epoch_last_checkpoint_sequence_number: u64,
}

impl<K: CheckpointKind> CheckpointBuilder<K>
where
    AuthorityPerEpochStore: CheckpointEpochTables<K>,
{
    fn new(
        state: Arc<AuthorityState>,
        tables: Arc<CheckpointStore<K>>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn CheckpointOutput<K>>,
        notify_aggregator: Arc<Notify>,
        metrics: Arc<CheckpointMetrics>,
        max_messages_per_checkpoint: usize,
        max_checkpoint_size_bytes: usize,
        previous_epoch_last_checkpoint_sequence_number: u64,
    ) -> Self {
        Self {
            state,
            tables,
            epoch_store,
            notify,
            output,
            notify_aggregator,
            metrics,
            max_messages_per_checkpoint,
            max_checkpoint_size_bytes,
            previous_epoch_last_checkpoint_sequence_number,
        }
    }

    async fn run(mut self) {
        info!("Starting {}Builder", K::NAME);

        let checkpoint_message = self
            .epoch_store
            .last_built_checkpoint_message_builder()
            .expect("epoch should not have ended");
        if let Some(last_height) = checkpoint_message.clone().and_then(|s| s.checkpoint_height) {
            self.metrics
                .last_checkpoint_pending_height
                .set(last_height as i64);
        }

        loop {
            self.maybe_build_checkpoints().await;
            self.notify.notified().await;
        }
    }

    async fn maybe_build_checkpoints(&mut self) {
        let _scope = monitored_scope(Box::leak(
            format!("Build{}Checkpoints", K::NAME).into_boxed_str(),
        ));

        let checkpoint_message = self
            .epoch_store
            .last_built_checkpoint_message_builder()
            .expect("epoch should not have ended");
        let mut last_height = checkpoint_message.clone().and_then(|s| s.checkpoint_height);

        let checkpoints_iter = self
            .epoch_store
            .get_pending_checkpoints(last_height)
            .expect("unexpected epoch store error")
            .into_iter()
            .peekable();
        for (height, pending) in checkpoints_iter {
            last_height = Some(height);
            debug!(
                checkpoint_commit_height = height,
                "Making {} at commit height",
                K::NAME,
            );
            self.metrics
                .last_checkpoint_pending_height
                .set(height as i64);

            if let Err(e) = self.make_checkpoint(vec![pending.clone()]).await {
                error!(
                    ?e,
                    last_height,
                    ?pending,
                    "Error while making {}, will retry in 1s",
                    K::NAME,
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.metrics.checkpoint_errors.inc();
                return;
            }
        }
    }

    #[instrument(level = "debug", skip_all, fields(last_height = pending_checkpoints.last().unwrap().details().checkpoint_height))]
    async fn make_checkpoint(
        &self,
        pending_checkpoints: Vec<PendingCheckpoint<K>>,
    ) -> anyhow::Result<()> {
        let last_details = pending_checkpoints.last().unwrap().details().clone();

        let mut pending_v1_messages = Vec::new();
        for pending_checkpoint in pending_checkpoints.into_iter() {
            let pending = pending_checkpoint.into_v1();
            pending_v1_messages.extend(pending.messages);
        }
        let new_checkpoint = self
            .create_checkpoints(pending_v1_messages, &last_details)
            .await?;
        self.write_checkpoints(last_details.checkpoint_height, new_checkpoint)
            .await?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn write_checkpoints(
        &self,
        height: CheckpointHeight,
        new_checkpoints: Vec<CheckpointMessage<K>>,
    ) -> IkaResult {
        let _scope = monitored_scope(Box::leak(
            format!("{}Builder::write_checkpoints", K::NAME).into_boxed_str(),
        ));

        for checkpoint_message in &new_checkpoints {
            debug!(
                checkpoint_commit_height = height,
                checkpoint_seq = checkpoint_message.sequence_number,
                checkpoint_digest = ?checkpoint_message.digest(),
                "writing {}", K::NAME,
            );

            self.output
                .checkpoint_created(checkpoint_message, &self.epoch_store, &self.tables)
                .await?;

            self.metrics
                .messages_included_in_checkpoint
                .inc_by(checkpoint_message.messages.len() as u64);
            let sequence_number = checkpoint_message.sequence_number;
            self.metrics
                .last_constructed_checkpoint
                .set(sequence_number as i64);

            self.tables
                .locally_computed_checkpoints
                .insert(&sequence_number, checkpoint_message)?;
        }

        self.notify_aggregator.notify_one();
        self.epoch_store
            .process_pending_checkpoint(height, new_checkpoints)?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn split_checkpoint_chunks(
        &self,
        messages: Vec<K::MessageKind>,
    ) -> anyhow::Result<Vec<Vec<K::MessageKind>>> {
        let _guard = monitored_scope(Box::leak(
            format!("{}Builder::split_checkpoint_chunks", K::NAME).into_boxed_str(),
        ));
        let mut chunks = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_size: usize = 0;
        for message in messages {
            let size = bcs::serialized_size(&message)?;
            if chunk.len() == self.max_messages_per_checkpoint
                || (chunk_size + size) > self.max_checkpoint_size_bytes
            {
                if chunk.is_empty() {
                    warn!(
                        "Size of single transaction ({size}) exceeds max {} size ({}); allowing excessively large checkpoint to go through.",
                        K::NAME,
                        self.max_checkpoint_size_bytes
                    );
                } else {
                    chunks.push(chunk);
                    chunk = Vec::new();
                    chunk_size = 0;
                }
            }

            chunk.push(message);
            chunk_size += size;
        }

        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        Ok(chunks)
    }

    #[instrument(level = "debug", skip_all)]
    async fn create_checkpoints(
        &self,
        all_messages: Vec<K::MessageKind>,
        details: &PendingCheckpointInfo,
    ) -> anyhow::Result<Vec<CheckpointMessage<K>>> {
        let _scope = monitored_scope(Box::leak(
            format!("{}Builder::create_checkpoints", K::NAME).into_boxed_str(),
        ));
        let epoch = self.epoch_store.epoch();
        let total = all_messages.len();
        let last_checkpoint = self.epoch_store.last_built_checkpoint_message()?;
        let mut last_checkpoint_seq = last_checkpoint.as_ref().map(|(seq, _)| *seq).unwrap_or(0);
        if epoch != 1 && self.previous_epoch_last_checkpoint_sequence_number > last_checkpoint_seq {
            last_checkpoint_seq = self.previous_epoch_last_checkpoint_sequence_number;
        }

        if !all_messages.is_empty() {
            info!(
                height = details.checkpoint_height,
                next_sequence_number = last_checkpoint_seq + 1,
                number_of_messages = all_messages.len(),
                "Creating {}(s) for messages",
                K::NAME,
            );
        }

        let chunks = self.split_checkpoint_chunks(all_messages)?;
        let chunks_count = chunks.len();

        let mut checkpoints = Vec::with_capacity(chunks_count);
        debug!(
            ?last_checkpoint_seq,
            chunks_count,
            total_messages = total,
            "Creating chunked {}s with total messages",
            K::NAME,
        );

        for (index, messages) in chunks.into_iter().enumerate() {
            let first_checkpoint_of_epoch = index == 0
                && (last_checkpoint_seq == self.previous_epoch_last_checkpoint_sequence_number);
            if first_checkpoint_of_epoch {
                self.epoch_store
                    .record_epoch_first_checkpoint_creation_time_metric();
            }

            let sequence_number = last_checkpoint_seq + 1;
            last_checkpoint_seq = sequence_number;

            info!(
                sequence_number,
                messages_count = messages.len(),
                "Creating a {}",
                K::NAME,
            );

            let checkpoint_message = CheckpointMessage::<K>::new(epoch, sequence_number, messages);
            checkpoints.push(checkpoint_message);
            tokio::task::yield_now().await;
        }

        Ok(checkpoints)
    }
}

// ── Aggregator ──────────────────────────────────────────────────────────────

pub struct CheckpointAggregator<K: CheckpointKind> {
    tables: Arc<CheckpointStore<K>>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    current: Option<CheckpointSignatureAggregator<K>>,
    output: Box<dyn CertifiedCheckpointOutput<K>>,
    previous_epoch_last_checkpoint_sequence_number: u64,
    state: Arc<AuthorityState>,
    metrics: Arc<CheckpointMetrics>,
}

struct CheckpointSignatureAggregator<K: CheckpointKind> {
    next_index: u64,
    checkpoint_message: CheckpointMessage<K>,
    digest: K::MessageDigest,
    signatures_by_digest: MultiStakeAggregator<K::MessageDigest, CheckpointMessage<K>, true>,
    state: Arc<AuthorityState>,
    metrics: Arc<CheckpointMetrics>,
}

impl<K: CheckpointKind> CheckpointAggregator<K>
where
    AuthorityPerEpochStore: CheckpointEpochTables<K>,
{
    fn new(
        tables: Arc<CheckpointStore<K>>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn CertifiedCheckpointOutput<K>>,
        previous_epoch_last_checkpoint_sequence_number: u64,
        state: Arc<AuthorityState>,
        metrics: Arc<CheckpointMetrics>,
    ) -> Self {
        Self {
            tables,
            epoch_store,
            notify,
            current: None,
            output,
            previous_epoch_last_checkpoint_sequence_number,
            state,
            metrics,
        }
    }

    async fn run(mut self) {
        info!("Starting {}Aggregator", K::NAME);
        loop {
            if let Err(e) = self.run_and_notify().await {
                error!(
                    "Error while aggregating {}, will retry in 1s: {:?}",
                    K::NAME,
                    e
                );
                self.metrics.checkpoint_errors.inc();
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            let _ = timeout(Duration::from_secs(1), self.notify.notified()).await;
        }
    }

    async fn run_and_notify(&mut self) -> IkaResult {
        let checkpoint_messages = self.run_inner().await?;
        for checkpoint_message in checkpoint_messages {
            self.output
                .certified_checkpoint_created(&checkpoint_message)
                .await?;
        }
        Ok(())
    }

    async fn run_inner(&mut self) -> IkaResult<Vec<CertifiedCheckpointMessage<K>>> {
        let _scope = monitored_scope(Box::leak(format!("{}Aggregator", K::NAME).into_boxed_str()));
        let mut result = vec![];
        'outer: loop {
            let next_to_certify = self.next_checkpoint_to_certify()?;
            let current = if let Some(current) = &mut self.current {
                if current.checkpoint_message.sequence_number < next_to_certify {
                    debug!(
                        next_index = current.next_index,
                        digest = ?current.digest,
                        checkpoint_message = ?current.checkpoint_message,
                        signatures_by_digest = ?current.signatures_by_digest,
                        next_to_certify,
                        "Resetting (current = None) current {} signature aggregator", K::NAME,
                    );
                    self.current = None;
                    continue;
                }
                debug!(
                    next_index = current.next_index,
                    digest = ?current.digest,
                    checkpoint_message = ?current.checkpoint_message,
                    signatures_by_digest = ?current.signatures_by_digest,
                    next_to_certify,
                    "Returned current {} signature aggregator", K::NAME,
                );
                current
            } else {
                let Some(checkpoint_message) = self
                    .epoch_store
                    .get_built_checkpoint_message(next_to_certify)?
                else {
                    debug!(
                        next_to_certify,
                        "No current and no built {} message found for sequence number - returning empty",
                        K::NAME,
                    );
                    return Ok(result);
                };
                self.current = Some(CheckpointSignatureAggregator {
                    next_index: 0,
                    digest: checkpoint_message.digest(),
                    checkpoint_message,
                    signatures_by_digest: MultiStakeAggregator::new(
                        self.epoch_store.committee().clone(),
                    ),
                    state: self.state.clone(),
                    metrics: self.metrics.clone(),
                });
                debug!(
                    next_index = 0,
                    digest = ?self.current.as_ref().unwrap().digest,
                    checkpoint_message = ?self.current.as_ref().unwrap().checkpoint_message,
                    signatures_by_digest = ?self.current.as_ref().unwrap().signatures_by_digest,
                    next_to_certify,
                    "Created new {} signature aggregator", K::NAME,
                );
                self.current.as_mut().unwrap()
            };

            let signatures = self
                .epoch_store
                .collect_pending_checkpoint_signatures(Some((
                    current.checkpoint_message.sequence_number,
                    current.next_index,
                )))?;
            for (key, received_data) in signatures {
                let (seq, index) = key;
                if seq != current.checkpoint_message.sequence_number {
                    debug!(
                        checkpoint_seq =? current.checkpoint_message.sequence_number,
                        "Not enough {} signatures", K::NAME,
                    );
                    return Ok(result);
                }
                debug!(
                    current_sequence_number = current.checkpoint_message.sequence_number,
                    received_sequence_number=?received_data.checkpoint_message.sequence_number,
                    current_digest=?current.checkpoint_message.digest(),
                    received_digest=?received_data.checkpoint_message.digest(),
                    received_from=?received_data.checkpoint_message.auth_sig().authority,
                    "Processing signature for {}.", K::NAME,
                );
                self.metrics
                    .checkpoint_participation
                    .with_label_values(&[&format!(
                        "{:?}",
                        received_data.checkpoint_message.auth_sig().authority
                    )])
                    .inc();
                if let Ok(auth_signature) = current.try_aggregate(received_data) {
                    let checkpoint_message = VerifiedCheckpointMessage::new_unchecked(
                        CertifiedCheckpointMessage::<K>::new_from_data_and_sig(
                            current.checkpoint_message.clone(),
                            auth_signature,
                        ),
                    );

                    self.tables
                        .insert_certified_checkpoint(&checkpoint_message)?;
                    self.metrics
                        .last_certified_checkpoint
                        .set(current.checkpoint_message.sequence_number as i64);
                    result.push(checkpoint_message.into_inner());
                    self.current = None;
                    continue 'outer;
                } else {
                    current.next_index = index + 1;
                }
            }
            tokio::task::yield_now().await;
            break;
        }
        Ok(result)
    }

    fn next_checkpoint_to_certify(&self) -> IkaResult<CheckpointSequenceNumber> {
        let default_next_checkpoint_to_certify =
            self.previous_epoch_last_checkpoint_sequence_number + 1;
        debug!(
            default_next_checkpoint_to_certify,
            "Getting next {} to certify",
            K::NAME,
        );
        Ok(self
            .tables
            .certified_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(seq, _)| seq + 1)
            .unwrap_or(default_next_checkpoint_to_certify))
    }
}

impl<K: CheckpointKind> CheckpointSignatureAggregator<K> {
    #[allow(clippy::result_unit_err)]
    pub fn try_aggregate(
        &mut self,
        data: CheckpointSignatureMessage<K>,
    ) -> Result<AuthorityStrongQuorumSignInfo, ()> {
        let their_digest = *data.checkpoint_message.digest();
        let (_, signature) = data.checkpoint_message.into_data_and_sig();
        let author = signature.authority;
        let envelope = SignedCheckpointMessage::<K>::new_from_data_and_sig(
            self.checkpoint_message.clone(),
            signature,
        );
        match self.signatures_by_digest.insert(their_digest, envelope) {
            InsertResult::Failed {
                error:
                    IkaError::StakeAggregatorRepeatedSigner {
                        conflicting_sig: false,
                        ..
                    },
            } => Err(()),
            InsertResult::Failed { error } => {
                warn!(
                    checkpoint_seq = self.checkpoint_message.sequence_number,
                    ?author,
                    ?error,
                    "Failed to aggregate new {} signature from validator",
                    K::NAME,
                );
                self.check_for_split_brain();
                Err(())
            }
            InsertResult::QuorumReached(cert) => {
                if their_digest != self.digest {
                    self.metrics.remote_checkpoint_forks.inc();
                    warn!(
                        checkpoint_seq = self.checkpoint_message.sequence_number,
                        from=?author,
                        ?their_digest,
                        our_digest=?self.digest,
                        "Validator has mismatching {} digest than what we have.", K::NAME,
                    );
                    return Err(());
                }
                Ok(cert)
            }
            InsertResult::NotEnoughVotes {
                bad_votes: _,
                bad_authorities: _,
            } => {
                self.check_for_split_brain();
                Err(())
            }
        }
    }

    fn check_for_split_brain(&self) {
        debug!(
            checkpoint_seq = self.checkpoint_message.sequence_number,
            "Checking for split brain condition for {}",
            K::NAME,
        );
        let all_unique_values = self.signatures_by_digest.get_all_unique_values();
        if all_unique_values.keys().len() > 1 {
            let quorum_unreachable = self.signatures_by_digest.quorum_unreachable();
            let local_checkpoint_message = self.checkpoint_message.clone();
            let epoch_store = self.state.load_epoch_store_one_call_per_task();
            let committee = epoch_store
                .epoch_start_state()
                .get_ika_committee_with_network_metadata();

            let all_unique_values = self.signatures_by_digest.get_all_unique_values();
            let digests_by_stake_messages = all_unique_values
                .iter()
                .map(|(digest, (_, authorities))| {
                    let stake = authorities.len();
                    (digest, stake as u64)
                })
                .sorted_by_key(|(_, stake)| -(*stake as i64))
                .collect::<Vec<_>>();

            let time = SystemTime::now();
            let digest_to_validators = all_unique_values
                .iter()
                .filter(|(digest, _)| *digest != &local_checkpoint_message.digest())
                .collect::<HashMap<_, _>>();

            error!(
                sequence_number=local_checkpoint_message.sequence_number,
                ?digests_by_stake_messages,
                remaining_stake=self.signatures_by_digest.uncommitted_stake(),
                local_validator=?self.state.name,
                ?digest_to_validators,
                ?local_checkpoint_message,
                ?committee,
                system_time=?time,
                quorum_unreachable,
                "split brain detected in {} signature aggregation", K::NAME,
            );
            self.metrics.split_brain_checkpoint_forks.inc();
        }
    }
}

// ── Service ─────────────────────────────────────────────────────────────────

pub trait CheckpointServiceNotify<K: CheckpointKind> {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &CheckpointSignatureMessage<K>,
    ) -> IkaResult;

    fn notify_checkpoint(&self) -> IkaResult;
}

pub struct CheckpointService<K: CheckpointKind> {
    tables: Arc<CheckpointStore<K>>,
    notify_builder: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    last_signature_index: Mutex<u64>,
    metrics: Arc<CheckpointMetrics>,
}

impl<K: CheckpointKind> CheckpointService<K>
where
    AuthorityPerEpochStore: CheckpointEpochTables<K>,
{
    pub fn spawn(
        state: Arc<AuthorityState>,
        checkpoint_store: Arc<CheckpointStore<K>>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_output: Box<dyn CheckpointOutput<K>>,
        certified_checkpoint_output: Box<dyn CertifiedCheckpointOutput<K>>,
        metrics: Arc<CheckpointMetrics>,
        max_messages_per_checkpoint: usize,
        max_checkpoint_size_bytes: usize,
        previous_epoch_last_checkpoint_sequence_number: u64,
    ) -> (Arc<Self>, JoinSet<()>) {
        info!(
            max_messages_per_checkpoint,
            max_checkpoint_size_bytes,
            "Starting {} service",
            K::NAME,
        );
        let notify_builder = Arc::new(Notify::new());
        let notify_aggregator = Arc::new(Notify::new());

        let mut tasks = JoinSet::new();

        let builder = CheckpointBuilder::new(
            state.clone(),
            checkpoint_store.clone(),
            epoch_store.clone(),
            notify_builder.clone(),
            checkpoint_output,
            notify_aggregator.clone(),
            metrics.clone(),
            max_messages_per_checkpoint,
            max_checkpoint_size_bytes,
            previous_epoch_last_checkpoint_sequence_number,
        );
        tasks.spawn(monitored_future!(builder.run()));

        let aggregator = CheckpointAggregator::new(
            checkpoint_store.clone(),
            epoch_store.clone(),
            notify_aggregator.clone(),
            certified_checkpoint_output,
            previous_epoch_last_checkpoint_sequence_number,
            state.clone(),
            metrics.clone(),
        );
        tasks.spawn(monitored_future!(aggregator.run()));

        let last_signature_index = epoch_store
            .get_last_checkpoint_signature_index()
            .expect("should not cross end of epoch");
        let last_signature_index = Mutex::new(last_signature_index);

        let service = Arc::new(Self {
            tables: checkpoint_store,
            notify_builder,
            notify_aggregator,
            last_signature_index,
            metrics,
        });

        (service, tasks)
    }
}

impl<K: CheckpointKind> CheckpointServiceNotify<K> for CheckpointService<K>
where
    AuthorityPerEpochStore: CheckpointEpochTables<K>,
{
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &CheckpointSignatureMessage<K>,
    ) -> IkaResult {
        let sequence = info.checkpoint_message.sequence_number;
        let signer = info.checkpoint_message.auth_sig().authority;

        if let Some(highest_verified_checkpoint) = self
            .tables
            .get_highest_verified_checkpoint()?
            .map(|x| *x.sequence_number())
            && sequence <= highest_verified_checkpoint
        {
            debug!(
                checkpoint_seq = sequence,
                ?signer,
                "Ignore {} signature — already certified",
                K::NAME,
            );
            self.metrics
                .last_ignored_checkpoint_signature_received
                .set(sequence as i64);
            return Ok(());
        }
        debug!(
            checkpoint_seq = sequence,
            checkpoint_digest=?info.checkpoint_message.digest(),
            ?signer,
            "Received a {} signature", K::NAME,
        );
        self.metrics
            .last_received_checkpoint_signatures
            .with_label_values(&[&signer.to_string()])
            .set(sequence as i64);
        let mut index = self.last_signature_index.lock();
        *index += 1;
        CheckpointEpochTables::<K>::insert_checkpoint_signature(
            epoch_store,
            sequence,
            *index,
            info,
        )?;
        self.notify_aggregator.notify_one();
        Ok(())
    }

    fn notify_checkpoint(&self) -> IkaResult {
        self.notify_builder.notify_one();
        Ok(())
    }
}
