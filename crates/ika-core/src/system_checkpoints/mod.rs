// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use ika_types::sui::EpochStartSystemTrait;
mod system_checkpoint_metrics;
mod system_checkpoint_output;

use std::collections::HashMap;

use crate::authority::AuthorityState;
use crate::stake_aggregator::{InsertResult, MultiStakeAggregator};
pub use crate::system_checkpoints::system_checkpoint_metrics::SystemCheckpointMetrics;
use crate::system_checkpoints::system_checkpoint_output::{
    CertifiedSystemCheckpointOutput, SystemCheckpointOutput,
};
pub use crate::system_checkpoints::system_checkpoint_output::{
    LogSystemCheckpointOutput, SendSystemCheckpointToStateSync, SubmitSystemCheckpointToConsensus,
};
use mysten_metrics::{monitored_future, monitored_scope};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sui_types::base_types::ConciseableName;

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use ika_types::crypto::AuthorityStrongQuorumSignInfo;
use ika_types::error::{IkaError, IkaResult};
use ika_types::message_envelope::Message;
use ika_types::messages_system_checkpoints::{
    CertifiedSystemCheckpointMessage, SignedSystemCheckpointMessage, SystemCheckpointMessage,
    SystemCheckpointMessageDigest, SystemCheckpointMessageKind, SystemCheckpointSequenceNumber,
    SystemCheckpointSignatureMessage, TrustedSystemCheckpointMessage,
    VerifiedSystemCheckpointMessage,
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

pub type SystemCheckpointHeight = u64;

pub struct EpochStats {
    pub system_checkpoint_count: u64,
    pub transaction_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSystemCheckpointInfo {
    pub checkpoint_height: SystemCheckpointHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PendingSystemCheckpoint {
    // This is an enum for future updatability, though at the moment there is only one variant.
    V1(PendingSystemCheckpointV1),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSystemCheckpointV1 {
    pub messages: Vec<SystemCheckpointMessageKind>,
    pub details: PendingSystemCheckpointInfo,
}

impl PendingSystemCheckpoint {
    pub fn as_v1(&self) -> &PendingSystemCheckpointV1 {
        match self {
            PendingSystemCheckpoint::V1(contents) => contents,
        }
    }

    pub fn into_v1(self) -> PendingSystemCheckpointV1 {
        match self {
            PendingSystemCheckpoint::V1(contents) => contents,
        }
    }

    pub fn messages(&self) -> &Vec<SystemCheckpointMessageKind> {
        &self.as_v1().messages
    }

    pub fn details(&self) -> &PendingSystemCheckpointInfo {
        &self.as_v1().details
    }

    pub fn height(&self) -> SystemCheckpointHeight {
        self.details().checkpoint_height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderSystemCheckpoint {
    pub checkpoint_message: SystemCheckpointMessage,
    // Height at which this system_checkpoint message was built. None for genesis system_checkpoint
    pub checkpoint_height: Option<SystemCheckpointHeight>,
    pub position_in_commit: usize,
}

#[derive(DBMapUtils)]
pub struct SystemCheckpointStore {
    // /// Maps system_checkpoint contents digest to system_checkpoint contents
    // pub(crate) system_checkpoint_content: DBMap<SystemCheckpointContentsDigest, SystemCheckpointContents>,
    /// Maps system_checkpoint system_checkpoint message digest to system_checkpoint sequence number
    pub(crate) checkpoint_message_sequence_by_digest:
        DBMap<SystemCheckpointMessageDigest, SystemCheckpointSequenceNumber>,

    // /// Stores entire system_checkpoint contents from state sync, indexed by sequence number, for
    // /// efficient reads of full system_checkpoints. Entries from this table are deleted after state
    // /// accumulation has completed.
    // full_system_checkpoint_content: DBMap<SystemCheckpointSequenceNumber, FullSystemCheckpointContents>,
    /// Stores certified system_checkpoints
    pub(crate) certified_checkpoints:
        DBMap<SystemCheckpointSequenceNumber, TrustedSystemCheckpointMessage>,
    // /// Map from system_checkpoint digest to certified system_checkpoint
    // pub(crate) system_checkpoint_by_digest: DBMap<SystemCheckpointDigest, TrustedSystemCheckpoint>,
    /// Store locally computed system_checkpoint summaries so that we can detect forks and log useful
    /// information. Can be pruned as soon as we verify that we are in agreement with the latest
    /// certified system_checkpoint.
    pub(crate) locally_computed_checkpoints:
        DBMap<SystemCheckpointSequenceNumber, SystemCheckpointMessage>,

    /// Watermarks used to determine the highest verified, fully synced, and
    /// fully executed system_checkpoints
    pub(crate) watermarks: DBMap<
        SystemCheckpointHighestWatermark,
        (
            SystemCheckpointSequenceNumber,
            SystemCheckpointMessageDigest,
        ),
    >,
}

impl SystemCheckpointStore {
    pub fn new(path: &Path) -> Arc<Self> {
        Arc::new(Self::open_tables_read_write(
            path.to_path_buf(),
            MetricConf::new("system_checkpoint"),
            None,
            None,
        ))
    }

    pub fn open_readonly(path: &Path) -> SystemCheckpointStoreReadOnly {
        Self::get_read_only_handle(
            path.to_path_buf(),
            None,
            None,
            MetricConf::new("system_checkpoint_readonly"),
        )
    }

    pub fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        let sequence = self.checkpoint_message_sequence_by_digest.get(digest)?;
        if let Some(sequence) = sequence {
            self.certified_checkpoints
                .get(&sequence)
                .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
        } else {
            Ok(None)
        }
    }

    pub fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        self.certified_checkpoints
            .get(&sequence_number)
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
    }

    pub fn get_locally_computed_system_checkpoint(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) -> Result<Option<SystemCheckpointMessage>, TypedStoreError> {
        self.locally_computed_checkpoints.get(&sequence_number)
    }

    pub fn get_latest_certified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        Ok(self
            .certified_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v.into()))
    }

    pub fn get_latest_locally_computed_system_checkpoint(
        &self,
    ) -> Result<Option<SystemCheckpointMessage>, TypedStoreError> {
        Ok(self
            .locally_computed_checkpoints
            .reversed_safe_iter_with_bounds(None, None)?
            .next()
            .transpose()?
            .map(|(_, v)| v))
    }

    pub fn multi_get_system_checkpoint_by_sequence_number(
        &self,
        sequence_numbers: &[SystemCheckpointSequenceNumber],
    ) -> Result<Vec<Option<VerifiedSystemCheckpointMessage>>, TypedStoreError> {
        let system_checkpoints = self
            .certified_checkpoints
            .multi_get(sequence_numbers)?
            .into_iter()
            .map(|maybe_checkpoint| maybe_checkpoint.map(|c| c.into()))
            .collect();

        Ok(system_checkpoints)
    }

    pub fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        let highest_verified = if let Some(highest_verified) = self
            .watermarks
            .get(&SystemCheckpointHighestWatermark::Verified)?
        {
            highest_verified
        } else {
            return Ok(None);
        };
        self.get_system_checkpoint_by_digest(&highest_verified.1)
    }

    pub fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        let highest_synced = if let Some(highest_synced) = self
            .watermarks
            .get(&SystemCheckpointHighestWatermark::Synced)?
        {
            highest_synced
        } else {
            return Ok(None);
        };
        self.get_system_checkpoint_by_digest(&highest_synced.1)
    }

    pub fn get_highest_executed_system_checkpoint_seq_number(
        &self,
    ) -> Result<Option<SystemCheckpointSequenceNumber>, TypedStoreError> {
        if let Some(highest_executed) = self
            .watermarks
            .get(&SystemCheckpointHighestWatermark::Executed)?
        {
            Ok(Some(highest_executed.0))
        } else {
            Ok(None)
        }
    }

    pub fn get_highest_executed_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>, TypedStoreError> {
        let highest_executed = if let Some(highest_executed) = self
            .watermarks
            .get(&SystemCheckpointHighestWatermark::Executed)?
        {
            highest_executed
        } else {
            return Ok(None);
        };
        self.get_system_checkpoint_by_digest(&highest_executed.1)
    }

    pub fn get_highest_pruned_system_checkpoint_seq_number(
        &self,
    ) -> Result<SystemCheckpointSequenceNumber, TypedStoreError> {
        Ok(self
            .watermarks
            .get(&SystemCheckpointHighestWatermark::Pruned)?
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
        checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Inserting certified system checkpoint",
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

    // Called by state sync, apart from inserting the system_checkpoint and updating
    // related tables, it also bumps the highest_verified_system_checkpoint watermark.
    #[instrument(level = "debug", skip_all)]
    pub fn insert_verified_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        self.insert_certified_checkpoint(system_checkpoint)?;
        self.update_highest_verified_system_checkpoint(system_checkpoint)
    }

    pub fn update_highest_verified_system_checkpoint(
        &self,
        checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        if Some(*checkpoint.sequence_number())
            > self
                .get_highest_verified_system_checkpoint()?
                .map(|x| *x.sequence_number())
        {
            debug!(
                checkpoint_seq = checkpoint.sequence_number(),
                "Updating highest verified system checkpoint",
            );
            self.watermarks.insert(
                &SystemCheckpointHighestWatermark::Verified,
                &(*checkpoint.sequence_number(), *checkpoint.digest()),
            )?;
        }

        Ok(())
    }

    pub fn update_highest_synced_system_checkpoint(
        &self,
        checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<(), TypedStoreError> {
        debug!(
            checkpoint_seq = checkpoint.sequence_number(),
            "Updating highest synced system checkpoint",
        );
        self.watermarks.insert(
            &SystemCheckpointHighestWatermark::Synced,
            &(*checkpoint.sequence_number(), *checkpoint.digest()),
        )
    }

    pub fn delete_highest_executed_system_checkpoint_test_only(
        &self,
    ) -> Result<(), TypedStoreError> {
        let mut wb = self.watermarks.batch();
        wb.delete_batch(
            &self.watermarks,
            std::iter::once(SystemCheckpointHighestWatermark::Executed),
        )?;
        wb.write()?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum SystemCheckpointHighestWatermark {
    Verified,
    Synced,
    Executed,
    Pruned,
}

pub struct SystemCheckpointBuilder {
    #[allow(dead_code)]
    state: Arc<AuthorityState>,
    tables: Arc<SystemCheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    output: Box<dyn SystemCheckpointOutput>,
    metrics: Arc<SystemCheckpointMetrics>,
    max_messages_per_system_checkpoint: usize,
    max_system_checkpoint_size_bytes: usize,
    previous_epoch_last_checkpoint_sequence_number: u64,
}

pub struct SystemCheckpointAggregator {
    tables: Arc<SystemCheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    notify: Arc<Notify>,
    current: Option<SystemCheckpointSignatureAggregator>,
    output: Box<dyn CertifiedSystemCheckpointOutput>,
    previous_epoch_last_checkpoint_sequence_number: u64,
    state: Arc<AuthorityState>,
    metrics: Arc<SystemCheckpointMetrics>,
}

// todo(zeev): see why some fields are not used.
// This holds information to aggregate signatures for one system_checkpoint
pub struct SystemCheckpointSignatureAggregator {
    next_index: u64,
    checkpoint_message: SystemCheckpointMessage,
    digest: SystemCheckpointMessageDigest,
    /// Aggregates voting stake for each signed system_checkpoint proposal by authority
    signatures_by_digest:
        MultiStakeAggregator<SystemCheckpointMessageDigest, SystemCheckpointMessage, true>,
    state: Arc<AuthorityState>,
    metrics: Arc<SystemCheckpointMetrics>,
}

impl SystemCheckpointBuilder {
    fn new(
        state: Arc<AuthorityState>,
        tables: Arc<SystemCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn SystemCheckpointOutput>,
        notify_aggregator: Arc<Notify>,
        metrics: Arc<SystemCheckpointMetrics>,
        max_messages_per_system_checkpoint: usize,
        max_system_checkpoint_size_bytes: usize,
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
            max_messages_per_system_checkpoint,
            max_system_checkpoint_size_bytes,
            previous_epoch_last_checkpoint_sequence_number,
        }
    }

    // overkill
    async fn run(mut self) {
        info!("Starting SystemCheckpointBuilder");

        // Collect info about the most recently built system checkpoint for metrics.
        let checkpoint_message = self
            .epoch_store
            .last_built_system_checkpoint_message_builder()
            .expect("epoch should not have ended");
        if let Some(last_height) = checkpoint_message.clone().and_then(|s| s.checkpoint_height) {
            self.metrics
                .last_system_checkpoint_pending_height
                .set(last_height as i64);
        }

        loop {
            self.maybe_build_system_checkpoints().await;

            self.notify.notified().await;
        }
    }

    async fn maybe_build_system_checkpoints(&mut self) {
        let _scope = monitored_scope("BuildSystemCheckpoints");

        // Collect info about the most recently built system checkpoint.
        let checkpoint_message = self
            .epoch_store
            .last_built_system_checkpoint_message_builder()
            .expect("epoch should not have ended");
        let mut last_height = checkpoint_message.clone().and_then(|s| s.checkpoint_height);

        let checkpoints_iter = self
            .epoch_store
            .get_pending_system_checkpoints(last_height)
            .expect("unexpected epoch store error")
            .into_iter()
            .peekable();
        for (height, pending) in checkpoints_iter {
            last_height = Some(height);
            debug!(
                checkpoint_commit_height = height,
                "Making system checkpoint at commit height"
            );
            self.metrics
                .last_system_checkpoint_pending_height
                .set(height as i64);

            if let Err(e) = self.make_checkpoint(vec![pending.clone()]).await {
                error!(
                    ?e,
                    last_height,
                    ?pending,
                    "Error while making system checkpoint, will retry in 1s"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.metrics.system_checkpoint_errors.inc();
                return;
            }
        }
    }

    #[instrument(level = "debug", skip_all, fields(last_height = pendings.last().unwrap().details().checkpoint_height))]
    async fn make_checkpoint(&self, pendings: Vec<PendingSystemCheckpoint>) -> anyhow::Result<()> {
        let last_details = pendings.last().unwrap().details().clone();

        // Keeps track of the effects that are already included in the current checkpoint.
        // This is used when there are multiple pending checkpoints to create a single checkpoint
        // because in such scenarios, dependencies of a transaction may in earlier created checkpoints,
        // or in earlier pending checkpoints.
        //let mut effects_in_current_checkpoint = BTreeSet::new();

        // Stores the transactions that should be included in the checkpoint. Transactions will be recorded in the checkpoint
        // in this order.
        let mut pending_system_checkpoints_v1 = Vec::new();
        for pending_checkpoint in pendings.into_iter() {
            let pending = pending_checkpoint.into_v1();
            pending_system_checkpoints_v1.extend(pending.messages);
        }
        let new_checkpoint = self
            .create_checkpoints(pending_system_checkpoints_v1, &last_details)
            .await?;
        self.write_checkpoints(last_details.checkpoint_height, new_checkpoint)
            .await?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn write_checkpoints(
        &self,
        height: SystemCheckpointHeight,
        new_checkpoints: Vec<SystemCheckpointMessage>,
    ) -> IkaResult {
        let _scope = monitored_scope("SystemCheckpointBuilder::write_system_checkpoints");
        //let mut batch = self.tables.system_checkpoint_content.batch();
        // let mut all_tx_digests =
        //     Vec::with_capacity(new_system_checkpoints.iter().map(|(_, c)| c.size()).sum());

        for checkpoint_message in &new_checkpoints {
            debug!(
                checkpoint_commit_height = height,
                checkpoint_seq = checkpoint_message.sequence_number,
                checkpoint_digest = ?checkpoint_message.digest(),
                "writing system checkpoint",
            );
            //all_tx_digests.extend(contents.iter().map(|digest| digest));

            self.output
                .system_checkpoint_created(checkpoint_message, &self.epoch_store, &self.tables)
                .await?;

            self.metrics
                .messages_included_in_system_checkpoint
                .inc_by(checkpoint_message.messages.len() as u64);
            let sequence_number = checkpoint_message.sequence_number;
            self.metrics
                .last_constructed_system_checkpoint
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
            .process_pending_system_checkpoint(height, new_checkpoints)?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn split_checkpoint_chunks(
        &self,
        messages: Vec<SystemCheckpointMessageKind>,
    ) -> anyhow::Result<Vec<Vec<SystemCheckpointMessageKind>>> {
        let _guard = monitored_scope("SystemCheckpointBuilder::split_checkpoint_chunks");
        let mut chunks = Vec::new();
        let mut chunk = Vec::new();
        let mut chunk_size: usize = 0;
        for message in messages {
            // Roll over to a new chunk after either max count or max size is reached.
            // The size calculation here is intended to estimate the size of the
            // FullSystemCheckpointContents struct. If this code is modified, that struct
            // should also be updated accordingly.
            let size = bcs::serialized_size(&message)?;
            if chunk.len() == self.max_messages_per_system_checkpoint
                || (chunk_size + size) > self.max_system_checkpoint_size_bytes
            {
                if chunk.is_empty() {
                    // Always allow at least one tx in a checkpoint.
                    warn!(
                        "Size of single transaction ({size}) exceeds max system checkpoint size ({}); allowing excessively large system checkpoint to go through.",
                        self.max_system_checkpoint_size_bytes
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
        all_messages: Vec<SystemCheckpointMessageKind>,
        details: &PendingSystemCheckpointInfo,
    ) -> anyhow::Result<Vec<SystemCheckpointMessage>> {
        let _scope = monitored_scope("SystemCheckpointBuilder::create_checkpoints");
        let epoch = self.epoch_store.epoch();
        let total = all_messages.len();
        let last_checkpoint = self.epoch_store.last_built_system_checkpoint_message()?;
        // if last_checkpoint.is_none() {
        //     let epoch = self.epoch_store.epoch();
        //     if epoch > 0 {
        //         let previous_epoch = epoch - 1;
        //         let last_verified = self.tables.get_epoch_last_system_checkpoint(previous_epoch)?;
        //         last_checkpoint = last_verified.map(VerifiedSystemCheckpoint::into_summary_and_sequence);
        //         if let Some((ref seq, _)) = last_system_checkpoint {
        //             debug!("No last_checkpoint in builder DB, taking system_checkpoint from previous epoch with sequence {seq}");
        //         } else {
        //             // This is some serious bug with when SystemCheckpointBuilder started so surfacing it via panic
        //             panic!("Can not find last system_checkpoint for previous epoch {previous_epoch}");
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
                "Creating system checkpoint(s) for messages",
            );
        }

        let chunks = self.split_checkpoint_chunks(all_messages)?;
        let chunks_count = chunks.len();

        let mut checkpoints = Vec::with_capacity(chunks_count);
        debug!(
            ?last_checkpoint_seq,
            chunks_count,
            total_messages = total,
            "Creating chunked system checkpoints with total messages",
        );

        for (index, messages) in chunks.into_iter().enumerate() {
            let first_checkpoint_of_epoch = index == 0
                && (last_checkpoint_seq == self.previous_epoch_last_checkpoint_sequence_number);
            if first_checkpoint_of_epoch {
                self.epoch_store
                    .record_epoch_first_system_checkpoint_creation_time_metric();
            }

            let sequence_number = last_checkpoint_seq + 1;
            last_checkpoint_seq = sequence_number;

            info!(
                sequence_number,
                messages_count = messages.len(),
                "Creating a system checkpoint"
            );

            let checkpoint_message = SystemCheckpointMessage::new(epoch, sequence_number, messages);

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

impl SystemCheckpointAggregator {
    fn new(
        tables: Arc<SystemCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        notify: Arc<Notify>,
        output: Box<dyn CertifiedSystemCheckpointOutput>,
        previous_epoch_last_checkpoint_sequence_number: u64,
        state: Arc<AuthorityState>,
        metrics: Arc<SystemCheckpointMetrics>,
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
        info!("Starting SystemCheckpointAggregator");
        loop {
            if let Err(e) = self.run_and_notify().await {
                error!(
                    "Error while aggregating system checkpoint, will retry in 1s: {:?}",
                    e
                );
                self.metrics.system_checkpoint_errors.inc();
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
                .certified_system_checkpoint_message_created(&checkpoint_message)
                .await?;
        }
        Ok(())
    }

    async fn run_inner(&mut self) -> IkaResult<Vec<CertifiedSystemCheckpointMessage>> {
        let _scope = monitored_scope("SystemCheckpointAggregator");
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
                        "Resetting (current = None) current system checkpoint signature aggregator",
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
                    "Returned current system checkpoint signature aggregator",
                );
                current
            } else {
                let Some(checkpoint_message) = self
                    .epoch_store
                    .get_built_system_checkpoint_message(next_to_certify)?
                else {
                    debug!(
                        next_to_certify,
                        "No current and no built system checkpoint message found for sequence number - returning empty",
                    );
                    return Ok(result);
                };
                self.current = Some(SystemCheckpointSignatureAggregator {
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
                    "Created new system checkpoint signature aggregator",
                );
                self.current.as_mut().unwrap()
            };

            let epoch_tables = self
                .epoch_store
                .tables()
                .expect("should not run past end of epoch");
            let iter = epoch_tables
                .pending_system_checkpoint_signatures
                .safe_iter_with_bounds(
                    Some((
                        current.checkpoint_message.sequence_number,
                        current.next_index,
                    )),
                    None,
                );
            for item in iter {
                let ((seq, index), data) = item?;
                if seq != current.checkpoint_message.sequence_number {
                    debug!(
                        checkpoint_seq =? current.checkpoint_message.sequence_number,
                        "Not enough system checkpoint signatures",
                    );
                    // No more signatures (yet) for this checkpoint
                    return Ok(result);
                }
                debug!(
                    checkpoint_seq = current.checkpoint_message.sequence_number,
                    digest=?current.checkpoint_message.digest(),
                    from=?data.checkpoint_message.auth_sig().authority.concise(),
                    "Processing signature for system checkpoint.",
                );
                self.metrics
                    .system_checkpoint_participation
                    .with_label_values(&[&format!(
                        "{:?}",
                        data.checkpoint_message.auth_sig().authority.concise()
                    )])
                    .inc();
                if let Ok(auth_signature) = current.try_aggregate(data) {
                    let checkpoint_message = VerifiedSystemCheckpointMessage::new_unchecked(
                        CertifiedSystemCheckpointMessage::new_from_data_and_sig(
                            current.checkpoint_message.clone(),
                            auth_signature,
                        ),
                    );

                    self.tables
                        .insert_certified_checkpoint(&checkpoint_message)?;
                    self.metrics
                        .last_certified_system_checkpoint
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

    fn next_checkpoint_to_certify(&self) -> IkaResult<SystemCheckpointSequenceNumber> {
        let default_next_checkpoint_to_certify =
            self.previous_epoch_last_checkpoint_sequence_number + 1;
        debug!(
            default_next_checkpoint_to_certify,
            "Getting next system checkpoint to certify",
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

impl SystemCheckpointSignatureAggregator {
    #[allow(clippy::result_unit_err)]
    pub fn try_aggregate(
        &mut self,
        data: SystemCheckpointSignatureMessage,
    ) -> Result<AuthorityStrongQuorumSignInfo, ()> {
        let their_digest = *data.checkpoint_message.digest();
        let (_, signature) = data.checkpoint_message.into_data_and_sig();
        let author = signature.authority;
        let envelope = SignedSystemCheckpointMessage::new_from_data_and_sig(
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
                    "Failed to aggregate new system checkpoint signature from validator {:?}: {:?}",
                    author.concise(),
                    error
                );
                self.check_for_split_brain();
                Err(())
            }
            InsertResult::QuorumReached(cert) => {
                // It is not guaranteed that signature.authority == narwhal_cert.author, but we do verify
                // the signature so we know that the author signed the message at some point.
                if their_digest != self.digest {
                    self.metrics.remote_system_checkpoint_forks.inc();
                    warn!(
                        checkpoint_seq = self.checkpoint_message.sequence_number,
                        from=?author.concise(),
                        ?their_digest,
                        our_digest=?self.digest,
                        "Validator has mismatching system checkpoint digest than what we have.",
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
            "Checking for split brain condition for system checkpoint"
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
                "split brain detected in system checkpoint signature aggregation",
            );
            self.metrics.split_brain_system_checkpoint_forks.inc();
        }
    }
}

pub trait SystemCheckpointServiceNotify {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &SystemCheckpointSignatureMessage,
    ) -> IkaResult;

    fn notify_checkpoint(&self) -> IkaResult;
}

/// This is a service used to communicate with other pieces of ika(for ex. authority)
pub struct SystemCheckpointService {
    tables: Arc<SystemCheckpointStore>,
    notify_builder: Arc<Notify>,
    notify_aggregator: Arc<Notify>,
    last_signature_index: Mutex<u64>,
    metrics: Arc<SystemCheckpointMetrics>,
}

impl SystemCheckpointService {
    pub fn spawn(
        state: Arc<AuthorityState>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
        epoch_store: Arc<AuthorityPerEpochStore>,
        system_checkpoint_output: Box<dyn SystemCheckpointOutput>,
        certified_system_checkpoint_output: Box<dyn CertifiedSystemCheckpointOutput>,
        metrics: Arc<SystemCheckpointMetrics>,
        max_messages_per_system_checkpoint: usize,
        max_system_checkpoint_size_bytes: usize,
        previous_epoch_last_checkpoint_sequence_number: u64,
    ) -> (Arc<Self>, JoinSet<()> /* Handle to tasks */) {
        info!(
            max_messages_per_system_checkpoint,
            max_system_checkpoint_size_bytes, "Starting system checkpoint service"
        );
        let notify_builder = Arc::new(Notify::new());
        let notify_aggregator = Arc::new(Notify::new());

        let mut tasks = JoinSet::new();

        let builder = SystemCheckpointBuilder::new(
            state.clone(),
            system_checkpoint_store.clone(),
            epoch_store.clone(),
            notify_builder.clone(),
            system_checkpoint_output,
            notify_aggregator.clone(),
            metrics.clone(),
            max_messages_per_system_checkpoint,
            max_system_checkpoint_size_bytes,
            previous_epoch_last_checkpoint_sequence_number,
        );
        tasks.spawn(monitored_future!(builder.run()));

        let aggregator = SystemCheckpointAggregator::new(
            system_checkpoint_store.clone(),
            epoch_store.clone(),
            notify_aggregator.clone(),
            certified_system_checkpoint_output,
            previous_epoch_last_checkpoint_sequence_number,
            state.clone(),
            metrics.clone(),
        );
        tasks.spawn(monitored_future!(aggregator.run()));

        let last_signature_index = epoch_store
            .get_last_system_checkpoint_signature_index()
            .expect("should not cross end of epoch");
        let last_signature_index = Mutex::new(last_signature_index);

        let service = Arc::new(Self {
            tables: system_checkpoint_store,
            notify_builder,
            notify_aggregator,
            last_signature_index,
            metrics,
        });

        (service, tasks)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn write_and_notify_system_checkpoint_for_testing(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        system_checkpoint: PendingSystemCheckpoint,
    ) -> IkaResult {
        use crate::authority::authority_per_epoch_store::ConsensusCommitOutput;

        let mut output = ConsensusCommitOutput::new(0);
        epoch_store.write_pending_system_checkpoint(&mut output, &system_checkpoint)?;
        let mut batch = epoch_store.db_batch_for_test();
        output.write_to_batch(epoch_store, &mut batch)?;
        batch.write()?;
        self.notify_checkpoint()?;
        Ok(())
    }
}

impl SystemCheckpointServiceNotify for SystemCheckpointService {
    fn notify_checkpoint_signature(
        &self,
        epoch_store: &AuthorityPerEpochStore,
        info: &SystemCheckpointSignatureMessage,
    ) -> IkaResult {
        let sequence = info.checkpoint_message.sequence_number;
        let signer = info.checkpoint_message.auth_sig().authority.concise();

        if let Some(highest_verified_checkpoint) = self
            .tables
            .get_highest_verified_system_checkpoint()?
            .map(|x| *x.sequence_number())
        {
            if sequence <= highest_verified_checkpoint {
                debug!(
                    checkpoint_seq = sequence,
                    "Ignore system checkpoint signature from {} - already certified", signer,
                );
                self.metrics
                    .last_ignored_system_checkpoint_signature_received
                    .set(sequence as i64);
                return Ok(());
            }
        }
        debug!(
            checkpoint_seq = sequence,
            "Received system checkpoint signature, digest {} from {}",
            info.checkpoint_message.digest(),
            signer,
        );
        self.metrics
            .last_received_system_checkpoint_signatures
            .with_label_values(&[&signer.to_string()])
            .set(sequence as i64);
        // While it can be tempting to make last_signature_index into AtomicU64, this won't work
        // We need to make sure we write to `pending_signatures`
        // and trigger `notify_aggregator` without race conditions.
        let mut index = self.last_signature_index.lock();
        *index += 1;
        epoch_store.insert_system_checkpoint_signature(sequence, *index, info)?;
        self.notify_aggregator.notify_one();
        Ok(())
    }

    fn notify_checkpoint(&self) -> IkaResult {
        self.notify_builder.notify_one();
        Ok(())
    }
}
