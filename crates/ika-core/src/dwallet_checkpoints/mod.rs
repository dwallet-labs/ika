// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::sui::EpochStartSystemTrait;
mod dwallet_checkpoint_metrics;
mod dwallet_checkpoint_output;

use std::collections::HashMap;

use crate::authority::AuthorityState;
pub use crate::dwallet_checkpoints::dwallet_checkpoint_metrics::DWalletCheckpointMetrics;
use crate::dwallet_checkpoints::dwallet_checkpoint_output::{
    CertifiedDWalletCheckpointMessageOutput, DWalletCheckpointOutput,
};
pub use crate::dwallet_checkpoints::dwallet_checkpoint_output::{
    LogDWalletCheckpointOutput, SendDWalletCheckpointToStateSync,
    SubmitDWalletCheckpointToConsensus,
};
use crate::stake_aggregator::{InsertResult, MultiStakeAggregator};
use mysten_metrics::{monitored_future, monitored_scope};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;

use ika_types::crypto::AuthorityStrongQuorumSignInfo;
use ika_types::digests::DWalletCheckpointMessageDigest;
use ika_types::error::{IkaError, IkaResult};
use ika_types::message::DWalletCheckpointMessageKind;
use ika_types::message_envelope::Message;
use ika_types::messages_dwallet_checkpoint::{
    CertifiedDWalletCheckpointMessage, DWalletCheckpointMessage, DWalletCheckpointSequenceNumber,
    DWalletCheckpointSignatureMessage, SignedDWalletCheckpointMessage,
    TrustedDWalletCheckpointMessage, VerifiedDWalletCheckpointMessage,
};
use itertools::Itertools;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::{sync::Notify, task::JoinSet, time::timeout};
use tracing::{debug, error, info, instrument, warn};
use typed_store::DBMapUtils;
use typed_store::Map;
use typed_store::{
    TypedStoreError,
    rocks::{DBMap, MetricConf},
};

pub type DWalletCheckpointHeight = u64;

pub struct EpochStats {
    pub dwallet_checkpoint_count: u64,
    pub transaction_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDWalletCheckpointInfo {
    pub checkpoint_height: DWalletCheckpointHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PendingDWalletCheckpoint {
    // This is an enum for future upgradability, though at the moment there is only one variant.
    V1(PendingDWalletCheckpointV1),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDWalletCheckpointV1 {
    pub messages: Vec<DWalletCheckpointMessageKind>,
    pub details: PendingDWalletCheckpointInfo,
}

impl PendingDWalletCheckpoint {
    pub fn as_v1(&self) -> &PendingDWalletCheckpointV1 {
        match self {
            PendingDWalletCheckpoint::V1(contents) => contents,
        }
    }

    pub fn into_v1(self) -> PendingDWalletCheckpointV1 {
        match self {
            PendingDWalletCheckpoint::V1(contents) => contents,
        }
    }

    pub fn messages(&self) -> &Vec<DWalletCheckpointMessageKind> {
        &self.as_v1().messages
    }

    pub fn details(&self) -> &PendingDWalletCheckpointInfo {
        &self.as_v1().details
    }

    pub fn height(&self) -> DWalletCheckpointHeight {
        self.details().checkpoint_height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderDWalletCheckpointMessage {
    pub checkpoint_message: DWalletCheckpointMessage,
    // The Height at which this `dwallet_checkpoint` message was built.
    // None for genesis dwallet_checkpoint.
    pub checkpoint_height: Option<DWalletCheckpointHeight>,
    pub position_in_commit: usize,
}

#[derive(DBMapUtils)]
pub struct DWalletCheckpointStore {
    // /// Maps dwallet_checkpoint contents digest to dwallet_checkpoint contents
    // pub(crate) dwallet_checkpoint_content: DBMap<DWalletCheckpointContentsDigest, DWalletCheckpointContents>,
    /// Maps dwallet_checkpoint message digest to dwallet_checkpoint sequence number
    pub(crate) checkpoint_message_sequence_by_digest:
        DBMap<DWalletCheckpointMessageDigest, DWalletCheckpointSequenceNumber>,

    // /// Stores entire dwallet_checkpoint contents from state sync, indexed by sequence number, for
    // /// efficient reads of full dwallet_checkpoints. Entries from this table are deleted after state
    // /// accumulation has completed.
    // full_dwallet_checkpoint_content: DBMap<DWalletCheckpointSequenceNumber, FullDWalletCheckpointContents>,
    /// Stores certified dwallet_checkpoints
    pub(crate) certified_checkpoints:
        DBMap<DWalletCheckpointSequenceNumber, TrustedDWalletCheckpointMessage>,
    // /// Map from dwallet_checkpoint digest to certified dwallet_checkpoint
    // pub(crate) dwallet_checkpoint_by_digest: DBMap<DWalletCheckpointMessageDigest, TrustedDWalletCheckpointMessage>,
    /// Store locally computed dwallet_checkpoint summaries so that we can detect forks and log useful
    /// information. Can be pruned as soon as we verify that we are in agreement with the latest
    /// certified dwallet_checkpoint.
    pub(crate) locally_computed_checkpoints:
        DBMap<DWalletCheckpointSequenceNumber, DWalletCheckpointMessage>,

    /// Watermarks used to determine the highest verified, fully synced, and
    /// fully executed dwallet_checkpoints
    pub(crate) watermarks: DBMap<
        DWalletCheckpointHighestWatermark,
        (
            DWalletCheckpointSequenceNumber,
            DWalletCheckpointMessageDigest,
        ),
    >,
}

impl DWalletCheckpointStore {
    pub fn new(path: &Path) -> Arc<Self> {
        Arc::new(Self::open_tables_read_write(
            path.to_path_buf(),
            MetricConf::new("dwallet_checkpoint"),
            None,
            None,
        ))
    }

    pub fn open_readonly(path: &Path) -> DWalletCheckpointStoreReadOnly {
        Self::get_read_only_handle(
            path.to_path_buf(),
            None,
            None,
            MetricConf::new("dwallet_checkpoint_readonly"),
        )
    }

    pub fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        let sequence = self.checkpoint_message_sequence_by_digest.get(digest)?;
        if let Some(sequence) = sequence {
            self.certified_checkpoints
                .get(&sequence)
                .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
        } else {
            Ok(None)
        }
    }

    pub fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        self.certified_checkpoints
            .get(&sequence_number)
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
    }

    pub fn get_locally_computed_checkpoint(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) -> Result<Option<DWalletCheckpointMessage>, TypedStoreError> {
        self.locally_computed_checkpoints.get(&sequence_number)
    }

    pub fn get_latest_certified_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        Ok(self
            .certified_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v.into()))
    }

    pub fn get_latest_locally_computed_checkpoint(
        &self,
    ) -> Result<Option<DWalletCheckpointMessage>, TypedStoreError> {
        Ok(self
            .locally_computed_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v))
    }

    pub fn multi_get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_numbers: &[DWalletCheckpointSequenceNumber],
    ) -> Result<Vec<Option<VerifiedDWalletCheckpointMessage>>, TypedStoreError> {
        let checkpoints = self
            .certified_checkpoints
            .multi_get(sequence_numbers)?
            .into_iter()
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
            .collect();

        Ok(checkpoints)
    }

    pub fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        let highest_verified = if let Some(highest_verified) = self
            .watermarks
            .get(&DWalletCheckpointHighestWatermark::Verified)?
        {
            highest_verified
        } else {
            return Ok(None);
        };
        self.get_dwallet_checkpoint_by_digest(&highest_verified.1)
    }

    pub fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        let highest_synced = if let Some(highest_synced) = self
            .watermarks
            .get(&DWalletCheckpointHighestWatermark::Synced)?
        {
            highest_synced
        } else {
            return Ok(None);
        };
        self.get_dwallet_checkpoint_by_digest(&highest_synced.1)
    }

    pub fn get_highest_executed_dwallet_checkpoint_seq_number(
        &self,
    ) -> Result<Option<DWalletCheckpointSequenceNumber>, TypedStoreError> {
        if let Some(highest_executed) = self
            .watermarks
            .get(&DWalletCheckpointHighestWatermark::Executed)?
        {
            Ok(Some(highest_executed.0))
        } else {
            Ok(None)
        }
    }

    pub fn get_highest_executed_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, TypedStoreError> {
        let highest_executed = if let Some(highest_executed) = self
            .watermarks
            .get(&DWalletCheckpointHighestWatermark::Executed)?
        {
            highest_executed
        } else {
            return Ok(None);
        };
        self.get_dwallet_checkpoint_by_digest(&highest_executed.1)
    }

    pub fn get_highest_pruned_dwallet_checkpoint_seq_number(
        &self,
    ) -> Result<DWalletCheckpointSequenceNumber, TypedStoreError> {
        Ok(self
            .watermarks
            .get(&DWalletCheckpointHighestWatermark::Pruned)?
            .unwrap_or((1, Default::default()))
            .0)
    }

    // Called by consensus (ConsensusAggregator).
    // Different from `insert_verified_checkpoint`, it does not touch
    // the highest_verified_checkpoint watermark such that state sync
    // will have a chance to process this checkpoint and perform some
    // state-sync only things.
    pub fn insert_certified_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Inserting certified dwallet checkpoint",
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

    // Called by state sync, apart from inserting the checkpoint and updating
    // related tables, it also bumps the highest_verified_checkpoint watermark.
    #[instrument(level = "debug", skip_all)]
    pub fn insert_verified_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        self.insert_certified_checkpoint(checkpoint)?;
        self.update_highest_verified_checkpoint(checkpoint)
    }

    pub fn update_highest_verified_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        if Some(*checkpoint.sequence_number())
            > self
                .get_highest_verified_dwallet_checkpoint()?
                .map(|x| *x.sequence_number())
        {
            debug!(
                checkpoint_seq = checkpoint.sequence_number(),
                "Updating highest verified dwallet checkpoint",
            );
            self.watermarks.insert(
                &DWalletCheckpointHighestWatermark::Verified,
                &(*checkpoint.sequence_number(), *checkpoint.digest()),
            )?;
        }

        Ok(())
    }

    pub fn update_highest_synced_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Updating highest synced dwallet checkpoint",
        );
        self.watermarks.insert(
            &DWalletCheckpointHighestWatermark::Synced,
            &(*checkpoint.sequence_number(), *checkpoint.digest()),
        )
    }

    pub fn delete_highest_executed_dwallet_checkpoint_test_only(
        &self,
    ) -> Result<(), TypedStoreError> {
        let mut wb = self.watermarks.batch();
        wb.delete_batch(
            &self.watermarks,
            std::iter::once(DWalletCheckpointHighestWatermark::Executed),
        )?;
        wb.write()?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum DWalletCheckpointHighestWatermark {
    Verified,
    Synced,
    Executed,
    Pruned,
}

pub struct DWalletCheckpointBuilder {
    // todo(zeev): why is it not used?
    #[allow(dead_code)]
    state: Arc<AuthorityState>,
    tables: Arc<DWalletCheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    output: Box<dyn DWalletCheckpointOutput>,
    metrics: Arc<DWalletCheckpointMetrics>,
    max_messages_per_dwallet_checkpoint: usize,
    max_dwallet_checkpoint_size_bytes: usize,
    previous_epoch_last_checkpoint_sequence_number: u64,
}

pub struct DWalletCheckpointAggregator {
    tables: Arc<DWalletCheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    current: Option<DWalletCheckpointSignatureAggregator>,
    output: Box<dyn CertifiedDWalletCheckpointMessageOutput>,
    previous_epoch_last_checkpoint_sequence_number: u64,
    state: Arc<AuthorityState>,
    metrics: Arc<DWalletCheckpointMetrics>,
}

// This holds information to aggregate signatures for one dwallet_checkpoint.
pub struct DWalletCheckpointSignatureAggregator {
    next_index: u64,
    checkpoint_message: DWalletCheckpointMessage,
    digest: DWalletCheckpointMessageDigest,
    /// Aggregates voting stake for each signed dwallet_checkpoint proposal by authority.
    signatures_by_digest:
        MultiStakeAggregator<DWalletCheckpointMessageDigest, DWalletCheckpointMessage, true>,
    state: Arc<AuthorityState>,
    metrics: Arc<DWalletCheckpointMetrics>,
}

impl DWalletCheckpointBuilder {
    fn new(
        state: Arc<AuthorityState>,
        tables: Arc<DWalletCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn DWalletCheckpointOutput>,
        notify_aggregator: Arc<Notify>,
        metrics: Arc<DWalletCheckpointMetrics>,
        max_messages_per_dwallet_checkpoint: usize,
        max_dwallet_checkpoint_size_bytes: usize,
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
            max_messages_per_dwallet_checkpoint,
            max_dwallet_checkpoint_size_bytes,
            previous_epoch_last_checkpoint_sequence_number,
        }
    }

    async fn run(mut self) {
        info!("Starting DWalletCheckpointBuilder");

        // Collect info about the most recently built dwallet checkpoint for metrics.
        let checkpoint_message = self
            .epoch_store
            .last_built_dwallet_checkpoint_message_builder()
            .expect("epoch should not have ended");
        if let Some(last_height) = checkpoint_message.clone().and_then(|s| s.checkpoint_height) {
            self.metrics
                .last_dwallet_checkpoint_pending_height
                .set(last_height as i64);
        }

        loop {
            self.maybe_build_dwallet_checkpoints().await;

            self.notify.notified().await;
        }
    }

    async fn maybe_build_dwallet_checkpoints(&mut self) {
        let _scope = monitored_scope("BuildDWalletCheckpoints");

        // Collect info about the most recently built dwallet checkpoint.
        let checkpoint_message = self
            .epoch_store
            .last_built_dwallet_checkpoint_message_builder()
            .expect("epoch should not have ended");
        let mut last_height = checkpoint_message.clone().and_then(|s| s.checkpoint_height);

        let checkpoints_iter = self
            .epoch_store
            .get_pending_dwallet_checkpoints(last_height)
            .expect("unexpected epoch store error")
            .into_iter()
            .peekable();
        for (height, pending) in checkpoints_iter {
            last_height = Some(height);
            debug!(
                checkpoint_commit_height = height,
                "Making dwallet checkpoint at commit height"
            );
            self.metrics
                .last_dwallet_checkpoint_pending_height
                .set(height as i64);

            if let Err(e) = self.make_checkpoint(vec![pending.clone()]).await {
                error!(
                    ?e,
                    last_height,
                    ?pending,
                    "Error while making dwallet checkpoint, will retry in 1s",
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.metrics.dwallet_checkpoint_errors.inc();
                return;
            }
        }
    }

    #[instrument(level = "debug", skip_all, fields(last_height = pending_checkpoints.last().unwrap().details().checkpoint_height))]
    async fn make_checkpoint(
        &self,
        pending_checkpoints: Vec<PendingDWalletCheckpoint>,
    ) -> anyhow::Result<()> {
        let last_details = pending_checkpoints.last().unwrap().details().clone();

        // Keeps track of the effects that are already included in the current checkpoint.
        // This is used when there are multiple pending checkpoints to create a single checkpoint
        // because in such scenarios, dependencies of a transaction may in earlier created checkpoints,
        // or in earlier pending checkpoints.
        //let mut effects_in_current_checkpoint = BTreeSet::new();

        // Stores the transactions that should be included in the checkpoint.
        // Transactions will be recorded in the checkpoint in this order.
        let mut pending_dwallet_checkpoints_v1 = Vec::new();
        for pending_checkpoint in pending_checkpoints.into_iter() {
            let pending = pending_checkpoint.into_v1();
            pending_dwallet_checkpoints_v1.extend(pending.messages);
        }
        let new_checkpoint = self
            .create_checkpoints(pending_dwallet_checkpoints_v1, &last_details)
            .await?;
        self.write_checkpoints(last_details.checkpoint_height, new_checkpoint)
            .await?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn write_checkpoints(
        &self,
        height: DWalletCheckpointHeight,
        new_checkpoints: Vec<DWalletCheckpointMessage>,
    ) -> IkaResult {
        let _scope = monitored_scope("DWalletCheckpointBuilder::write_checkpoints");
        //let mut batch = self.tables.checkpoint_content.batch();
        // let mut all_tx_digests =
        //     Vec::with_capacity(new_checkpoints.iter().map(|(_, c)| c.size()).sum());

        for checkpoint_message in &new_checkpoints {
            debug!(
                checkpoint_commit_height = height,
                checkpoint_seq = checkpoint_message.sequence_number,
                checkpoint_digest = ?checkpoint_message.digest(),
                "writing dwallet checkpoint",
            );
            //all_tx_digests.extend(contents.iter().map(|digest| digest));

            self.output
                .dwallet_checkpoint_created(checkpoint_message, &self.epoch_store, &self.tables)
                .await?;

            self.metrics
                .messages_included_in_dwallet_checkpoint
                .inc_by(checkpoint_message.messages.len() as u64);
            let sequence_number = checkpoint_message.sequence_number;
            self.metrics
                .last_constructed_dwallet_checkpoint
                .set(sequence_number as i64);

            // batch.insert_batch(
            //     &self.tables.checkpoint_content,
            //     [(contents.digest(), contents)],
            // )?;

            self.tables
                .locally_computed_checkpoints
                .insert(&sequence_number, checkpoint_message)?;

            // batch.insert_batch(
            //     &self.tables.locally_computed_checkpoints,
            //     [(sequence_number, summary)],
            // )?;
        }

        self.notify_aggregator.notify_one();
        self.epoch_store
            .process_pending_dwallet_checkpoint(height, new_checkpoints)?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn split_checkpoint_chunks(
        &self,
        messages: Vec<DWalletCheckpointMessageKind>,
    ) -> anyhow::Result<Vec<Vec<DWalletCheckpointMessageKind>>> {
        let _guard = monitored_scope("DWalletCheckpointBuilder::split_checkpoint_chunks");
        let mut chunks = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_size: usize = 0;
        for message in messages {
            // Roll over to a new chunk after either max count or max size is reached.
            // The size calculation here is intended to estimate the size of the
            // FullDWalletCheckpointContents struct. If this code is modified, that struct
            // should also be updated accordingly.
            let size = bcs::serialized_size(&message)?;
            if chunk.len() == self.max_messages_per_dwallet_checkpoint
                || (chunk_size + size) > self.max_dwallet_checkpoint_size_bytes
            {
                if chunk.is_empty() {
                    // Always allow at least one tx in a checkpoint.
                    warn!(
                        "Size of single transaction ({size}) exceeds max dwallet checkpoint size ({}); allowing excessively large checkpoint to go through.",
                        self.max_dwallet_checkpoint_size_bytes
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
            // We intentionally create an empty chunk if there is no content provided
            // and `last_of_epoch` or `mid_of_epoch` to make an end of epoch message.
            // Important: if some conditions are added here later, we need to make sure we always
            // have at least one chunk if last_pending_of_epoch is set
            chunks.push(chunk);
            // Note: empty checkpoints are ok - they shouldn't happen at all on a network with even
            // modest load.
        }
        Ok(chunks)
    }

    #[instrument(level = "debug", skip_all)]
    async fn create_checkpoints(
        &self,
        all_messages: Vec<DWalletCheckpointMessageKind>,
        details: &PendingDWalletCheckpointInfo,
    ) -> anyhow::Result<Vec<DWalletCheckpointMessage>> {
        let _scope = monitored_scope("DWalletCheckpointBuilder::create_checkpoints");
        let epoch = self.epoch_store.epoch();
        let total = all_messages.len();
        let last_checkpoint = self.epoch_store.last_built_dwallet_checkpoint_message()?;
        // if last_checkpoint.is_none() {
        //     let epoch = self.epoch_store.epoch();
        //     if epoch > 0 {
        //         let previous_epoch = epoch - 1;
        //         let last_verified = self.tables.get_epoch_last_checkpoint(previous_epoch)?;
        //         last_checkpoint = last_verified.map(VerifiedCheckpointMessage::into_summary_and_sequence);
        //         if let Some((ref seq, _)) = last_checkpoint {
        //             debug!("No checkpoints in builder DB, taking checkpoint from previous epoch with sequence {seq}");
        //         } else {
        //             // This is some serious bug with when CheckpointBuilder started so surfacing it via panic
        //             panic!("Can not find last checkpoint for previous epoch {previous_epoch}");
        //         }
        //     }
        // }
        let mut last_checkpoint_seq = last_checkpoint.as_ref().map(|(seq, _)| *seq).unwrap_or(0);
        // Epoch 0 is where we create the validator set (we are not running Epoch 0).
        // Once we initialize, the active committee starts in Epoch 1.
        // So there is no previous committee in epoch 1.
        if epoch != 1 && self.previous_epoch_last_checkpoint_sequence_number > last_checkpoint_seq {
            last_checkpoint_seq = self.previous_epoch_last_checkpoint_sequence_number;
        }

        if !all_messages.is_empty() {
            info!(
                height = details.checkpoint_height,
                next_sequence_number = last_checkpoint_seq + 1,
                number_of_messages = all_messages.len(),
                "Creating dwallet checkpoint(s) for messages"
            );
        }

        let chunks = self.split_checkpoint_chunks(all_messages)?;
        let chunks_count = chunks.len();

        let mut checkpoints = Vec::with_capacity(chunks_count);
        debug!(
            ?last_checkpoint_seq,
            chunks_count,
            total_messages = total,
            "Creating chunked dwallet checkpoints with total messages",
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
                "Creating a dwallet checkpoint"
            );

            let checkpoint_message =
                DWalletCheckpointMessage::new(epoch, sequence_number, messages);
            checkpoints.push(checkpoint_message);
            tokio::task::yield_now().await;
        }

        Ok(checkpoints)
    }

    // This function is used to check the invariants of the consensus commit prologue transactions in the checkpoint
    // in simtest.
    #[cfg(msim)]
    fn expensive_consensus_commit_prologue_invariants_check(
        &self,
        root_digests: &[TransactionDigest],
        sorted: &[TransactionEffects],
    ) {
        if !self
            .epoch_store
            .protocol_config()
            .prepend_prologue_tx_in_consensus_commit_in_checkpoints()
        {
            return;
        }

        // Gets all the consensus commit prologue transactions from the roots.
        let root_txs = self
            .state
            .get_transaction_cache_reader()
            .multi_get_transaction_blocks(root_digests)
            .unwrap();
        let ccps = root_txs
            .iter()
            .filter_map(|tx| {
                if let Some(tx) = tx {
                    if matches!(
                        tx.transaction_data().kind(),
                        TransactionKind::ConsensusCommitPrologue(_)
                            | TransactionKind::ConsensusCommitPrologueV2(_)
                            | TransactionKind::ConsensusCommitPrologueV3(_)
                    ) {
                        Some(tx)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // There should be at most one consensus commit prologue transaction in the roots.
        assert!(ccps.len() <= 1);

        // Get all the transactions in the checkpoint.
        let txs = self
            .state
            .get_transaction_cache_reader()
            .multi_get_transaction_blocks(
                &sorted
                    .iter()
                    .map(|tx| tx.transaction_digest().clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        if ccps.len() == 0 {
            // If there is no consensus commit prologue transaction in the roots, then there should be no
            // consensus commit prologue transaction in the checkpoint.
            for tx in txs.iter() {
                if let Some(tx) = tx {
                    assert!(!matches!(
                        tx.transaction_data().kind(),
                        TransactionKind::ConsensusCommitPrologue(_)
                            | TransactionKind::ConsensusCommitPrologueV2(_)
                            | TransactionKind::ConsensusCommitPrologueV3(_)
                    ));
                }
            }
        } else {
            // If there is one consensus commit prologue, it must be the first one in the checkpoint.
            assert!(matches!(
                txs[0].as_ref().unwrap().transaction_data().kind(),
                TransactionKind::ConsensusCommitPrologue(_)
                    | TransactionKind::ConsensusCommitPrologueV2(_)
                    | TransactionKind::ConsensusCommitPrologueV3(_)
            ));

            assert_eq!(ccps[0].digest(), txs[0].as_ref().unwrap().digest());

            for tx in txs.iter().skip(1) {
                if let Some(tx) = tx {
                    assert!(!matches!(
                        tx.transaction_data().kind(),
                        TransactionKind::ConsensusCommitPrologue(_)
                            | TransactionKind::ConsensusCommitPrologueV2(_)
                            | TransactionKind::ConsensusCommitPrologueV3(_)
                    ));
                }
            }
        }
    }
}

impl DWalletCheckpointAggregator {
    fn new(
        tables: Arc<DWalletCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn CertifiedDWalletCheckpointMessageOutput>,
        previous_epoch_last_checkpoint_sequence_number: u64,
        state: Arc<AuthorityState>,
        metrics: Arc<DWalletCheckpointMetrics>,
    ) -> Self {
        let current = None;
        Self {
            tables,
            epoch_store,
            notify,
            current,
            output,
            previous_epoch_last_checkpoint_sequence_number,
            state,
            metrics,
        }
    }

    async fn run(mut self) {
        info!("Starting CheckpointDWalletAggregator");
        loop {
            if let Err(e) = self.run_and_notify().await {
                error!(
                    "Error while aggregating dwallet checkpoint, will retry in 1s: {:?}",
                    e
                );
                self.metrics.dwallet_checkpoint_errors.inc();
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
                .certified_dwallet_checkpoint_message_created(&checkpoint_message)
                .await?;
        }
        Ok(())
    }

    async fn run_inner(&mut self) -> IkaResult<Vec<CertifiedDWalletCheckpointMessage>> {
        let _scope = monitored_scope("DWalletCheckpointAggregator");
        let mut result = vec![];
        'outer: loop {
            let next_to_certify = self.next_checkpoint_to_certify()?;
            let current = if let Some(current) = &mut self.current {
                // It's possible that the checkpoint was already certified by
                // the rest of the network, and we've already received the
                // certified checkpoint via StateSync. In this case, we reset
                // the current signature aggregator to the next checkpoint to
                // be certified.
                if current.checkpoint_message.sequence_number < next_to_certify {
                    debug!(
                        next_index = current.next_index,
                        digest = ?current.digest,
                        checkpoint_message = ?current.checkpoint_message,
                        signatures_by_digest = ?current.signatures_by_digest,
                        next_to_certify,
                        "Resetting (current = None) current dwallet checkpoint signature aggregator",
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
                    "Returned current dwallet checkpoint signature aggregator",
                );
                current
            } else {
                let Some(checkpoint_message) = self
                    .epoch_store
                    .get_built_dwallet_checkpoint_message(next_to_certify)?
                else {
                    debug!(
                        next_to_certify,
                        "No current and no built dwallet checkpoint message found for sequence number - returning empty",
                    );
                    return Ok(result);
                };
                self.current = Some(DWalletCheckpointSignatureAggregator {
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
                    "Created new dwallet checkpoint signature aggregator",
                );
                self.current.as_mut().unwrap()
            };

            let epoch_tables = self
                .epoch_store
                .tables()
                .expect("should not run past end of epoch");
            let iter = epoch_tables
                .pending_dwallet_checkpoint_signatures
                .safe_iter_with_bounds(
                    Some((
                        current.checkpoint_message.sequence_number,
                        current.next_index,
                    )),
                    None,
                );
            for item in iter {
                let ((seq, index), received_data) = item?;
                if seq != current.checkpoint_message.sequence_number {
                    debug!(
                        checkpoint_seq =? current.checkpoint_message.sequence_number,
                        "Not enough dwallet checkpoint signatures",
                    );
                    // No more signatures (yet) for this checkpoint
                    return Ok(result);
                }
                debug!(
                    current_sequnce_number = current.checkpoint_message.sequence_number,
                    received_sequence_number=?received_data.checkpoint_message.sequence_number,
                    current_digest=?current.checkpoint_message.digest(),
                    received_digest=?received_data.checkpoint_message.digest(),
                    received_messages=?received_data.checkpoint_message.messages,
                    received_epoch=?received_data.checkpoint_message.epoch,
                    received_from=?received_data.checkpoint_message.auth_sig().authority,
                    "Processing signature for dwallet checkpoint.",
                );
                self.metrics
                    .dwallet_checkpoint_participation
                    .with_label_values(&[&format!(
                        "{:?}",
                        received_data.checkpoint_message.auth_sig().authority
                    )])
                    .inc();
                if let Ok(auth_signature) = current.try_aggregate(received_data) {
                    let checkpoint_message = VerifiedDWalletCheckpointMessage::new_unchecked(
                        CertifiedDWalletCheckpointMessage::new_from_data_and_sig(
                            current.checkpoint_message.clone(),
                            auth_signature,
                        ),
                    );

                    self.tables
                        .insert_certified_checkpoint(&checkpoint_message)?;
                    self.metrics
                        .last_certified_dwallet_checkpoint
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

    fn next_checkpoint_to_certify(&self) -> IkaResult<DWalletCheckpointSequenceNumber> {
        let default_next_checkpoint_to_certify =
            self.previous_epoch_last_checkpoint_sequence_number + 1;
        debug!(
            default_next_checkpoint_to_certify,
            "Getting next dwallet checkpoint to certify",
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

impl DWalletCheckpointSignatureAggregator {
    #[allow(clippy::result_unit_err)]
    pub fn try_aggregate(
        &mut self,
        data: DWalletCheckpointSignatureMessage,
    ) -> Result<AuthorityStrongQuorumSignInfo, ()> {
        let their_digest = *data.checkpoint_message.digest();
        let (_, signature) = data.checkpoint_message.into_data_and_sig();
        let author = signature.authority;
        let envelope = SignedDWalletCheckpointMessage::new_from_data_and_sig(
            self.checkpoint_message.clone(),
            signature,
        );
        match self.signatures_by_digest.insert(their_digest, envelope) {
            // ignore repeated signatures
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
                    "Failed to aggregate new dwallet checkpoint signature from validator",
                );
                self.check_for_split_brain();
                Err(())
            }
            InsertResult::QuorumReached(cert) => {
                // It is not guaranteed that signature.authority == narwhal_cert.author, but we do verify
                // the signature so we know that the author signed the message at some point.
                if their_digest != self.digest {
                    self.metrics.remote_dwallet_checkpoint_forks.inc();
                    warn!(
                        checkpoint_seq = self.checkpoint_message.sequence_number,
                        from=?author,
                        ?their_digest,
                        our_digest=?self.digest,
                        "Validator has mismatching dwallet checkpoint digest than what we have.",
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

    /// Check if there is a split brain condition in checkpoint signature aggregation, defined
    /// as any state wherein it is no longer possible to achieve quorum on a checkpoint proposal,
    /// irrespective of the outcome of any outstanding votes.
    fn check_for_split_brain(&self) {
        debug!(
            checkpoint_seq = self.checkpoint_message.sequence_number,
            "Checking for split brain condition for dwallet checkpoint"
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
                "split brain detected in dwallet checkpoint signature aggregation",
            );
            self.metrics.split_brain_dwallet_checkpoint_forks.inc();
        }
    }
}

pub trait DWalletCheckpointServiceNotify {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &DWalletCheckpointSignatureMessage,
    ) -> IkaResult;

    fn notify_checkpoint(&self) -> IkaResult;
}

/// This is a service used to communicate with other pieces of ika(for ex. authority)
pub struct DWalletCheckpointService {
    tables: Arc<DWalletCheckpointStore>,
    notify_builder: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    last_signature_index: Mutex<u64>,
    metrics: Arc<DWalletCheckpointMetrics>,
}

impl DWalletCheckpointService {
    pub fn spawn(
        state: Arc<AuthorityState>,
        checkpoint_store: Arc<DWalletCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_output: Box<dyn DWalletCheckpointOutput>,
        certified_checkpoint_output: Box<dyn CertifiedDWalletCheckpointMessageOutput>,
        metrics: Arc<DWalletCheckpointMetrics>,
        max_messages_per_checkpoint: usize,
        max_checkpoint_size_bytes: usize,
        previous_epoch_last_checkpoint_sequence_number: u64,
    ) -> (Arc<Self>, JoinSet<()> /* Handle to tasks */) {
        info!(
            max_messages_per_checkpoint,
            max_checkpoint_size_bytes, "Starting dwallet checkpoint service"
        );
        let notify_builder = Arc::new(Notify::new());
        let notify_aggregator = Arc::new(Notify::new());

        let mut tasks = JoinSet::new();

        let builder = DWalletCheckpointBuilder::new(
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

        let aggregator = DWalletCheckpointAggregator::new(
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
            .get_last_dwallet_checkpoint_signature_index()
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

impl DWalletCheckpointServiceNotify for DWalletCheckpointService {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &DWalletCheckpointSignatureMessage,
    ) -> IkaResult {
        let sequence = info.checkpoint_message.sequence_number;
        let signer = info.checkpoint_message.auth_sig().authority;

        if let Some(highest_verified_checkpoint) = self
            .tables
            .get_highest_verified_dwallet_checkpoint()?
            .map(|x| *x.sequence_number())
        {
            if sequence <= highest_verified_checkpoint {
                debug!(
                    checkpoint_seq = sequence,
                    signer=?signer,
                    "Ignore dwallet checkpoint signature from a signer — already certified",
                );
                self.metrics
                    .last_ignored_dwallet_checkpoint_signature_received
                    .set(sequence as i64);
                return Ok(());
            }
        }
        debug!(
            checkpoint_seq=sequence,
            checkpoint_digest=?info.checkpoint_message.digest(),
            ?signer,
            "Received a dwallet checkpoint signature",
        );
        self.metrics
            .last_received_dwallet_checkpoint_signatures
            .with_label_values(&[&signer.to_string()])
            .set(sequence as i64);
        // While it can be tempting to make last_signature_index into AtomicU64, this won't work
        // We need to make sure we write to `pending_signatures`
        // and trigger `notify_aggregator` without race conditions.
        let mut index = self.last_signature_index.lock();
        *index += 1;
        epoch_store.insert_checkpoint_signature(sequence, *index, info)?;
        self.notify_aggregator.notify_one();
        Ok(())
    }

    fn notify_checkpoint(&self) -> IkaResult {
        self.notify_builder.notify_one();
        Ok(())
    }
}
