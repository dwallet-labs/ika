// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::error::Result;
use crate::checkpoint::{CheckpointSequenceNumber, DWallet, System, VerifiedCheckpointMessage};
use crate::committee::{Committee, EpochId};
use crate::digests::{DWalletCheckpointMessageDigest, SystemCheckpointMessageDigest};
use std::sync::Arc;

pub trait ReadStore {
    //
    // Committee Getters
    //

    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>>;

    //
    // Checkpoint Getters
    //

    /// Get the latest available dwallet checkpoint. This is the latest executed dwallet checkpoint.
    ///
    /// All transactions, effects, objects and events are guaranteed to be available for the
    /// returned dwallet checkpoint.
    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>>;

    /// Get the latest available dwallet checkpoint sequence number. This is the sequence number of the latest executed dwallet checkpoint.
    fn get_latest_checkpoint_sequence_number(&self) -> Result<CheckpointSequenceNumber> {
        let latest_dwallet_checkpoint = self.get_latest_dwallet_checkpoint()?;
        Ok(*latest_dwallet_checkpoint.sequence_number())
    }

    /// Get the epoch of the latest dwallet checkpoint
    fn get_latest_epoch_id(&self) -> Result<EpochId> {
        let latest_dwallet_checkpoint = self.get_latest_dwallet_checkpoint()?;
        Ok(latest_dwallet_checkpoint.epoch())
    }

    /// Get the highest verified dwallet checkpint. This is the highest dwallet checkpoint summary that has been
    /// verified, generally by state-sync. Only the dwallet checkpoint header is guaranteed to be present in
    /// the store.
    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>>;

    /// Get the highest synced dwallet checkpint. This is the highest dwallet checkpoint that has been synced from
    /// state-synce. The dwallet checkpoint header, contents, transactions, and effects of this dwallet checkpoint
    /// are guaranteed to be present in the store
    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>>;

    /// Lowest available dwallet checkpoint for which transaction and dwallet checkpoint data can be requested.
    ///
    /// Specifically this is the lowest dwallet checkpoint for which the following data can be requested:
    ///  - dwallet checkpoints
    ///  - transactions
    ///  - effects
    ///  - events
    ///
    /// For object availability see `get_lowest_available_dwallet_checkpoint_objects`.
    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber>;

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>>;

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>>;

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>>;

    fn get_latest_system_checkpoint_sequence_number(&self) -> Result<CheckpointSequenceNumber> {
        let latest_system_checkpoint = self.get_latest_system_checkpoint()?;
        Ok(*latest_system_checkpoint.sequence_number())
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>>;

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>>;

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber>;

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>>;

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>>;
}

impl<T: ReadStore + ?Sized> ReadStore for &T {
    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>> {
        (*self).get_committee(epoch)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>> {
        (*self).get_latest_dwallet_checkpoint()
    }

    fn get_latest_checkpoint_sequence_number(&self) -> Result<CheckpointSequenceNumber> {
        (*self).get_latest_checkpoint_sequence_number()
    }

    fn get_latest_epoch_id(&self) -> Result<EpochId> {
        (*self).get_latest_epoch_id()
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (*self).get_highest_verified_dwallet_checkpoint()
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (*self).get_highest_synced_dwallet_checkpoint()
    }

    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (*self).get_lowest_available_dwallet_checkpoint()
    }

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (*self).get_dwallet_checkpoint_by_digest(digest)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (*self).get_dwallet_checkpoint_by_sequence_number(sequence_number)
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>> {
        (*self).get_latest_system_checkpoint()
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (*self).get_highest_verified_system_checkpoint()
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (*self).get_highest_synced_system_checkpoint()
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (*self).get_lowest_available_system_checkpoint()
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (*self).get_system_checkpoint_by_digest(digest)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (*self).get_system_checkpoint_by_sequence_number(sequence_number)
    }
}

impl<T: ReadStore + ?Sized> ReadStore for Box<T> {
    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>> {
        (**self).get_committee(epoch)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>> {
        (**self).get_latest_dwallet_checkpoint()
    }

    fn get_latest_checkpoint_sequence_number(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_latest_checkpoint_sequence_number()
    }

    fn get_latest_epoch_id(&self) -> Result<EpochId> {
        (**self).get_latest_epoch_id()
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_highest_verified_dwallet_checkpoint()
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_highest_synced_dwallet_checkpoint()
    }

    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_lowest_available_dwallet_checkpoint()
    }

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_dwallet_checkpoint_by_digest(digest)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_dwallet_checkpoint_by_sequence_number(sequence_number)
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>> {
        (**self).get_latest_system_checkpoint()
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_highest_verified_system_checkpoint()
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_highest_synced_system_checkpoint()
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_lowest_available_system_checkpoint()
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_system_checkpoint_by_digest(digest)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_system_checkpoint_by_sequence_number(sequence_number)
    }
}

impl<T: ReadStore + ?Sized> ReadStore for Arc<T> {
    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>> {
        (**self).get_committee(epoch)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>> {
        (**self).get_latest_dwallet_checkpoint()
    }

    fn get_latest_checkpoint_sequence_number(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_latest_checkpoint_sequence_number()
    }

    fn get_latest_epoch_id(&self) -> Result<EpochId> {
        (**self).get_latest_epoch_id()
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_highest_verified_dwallet_checkpoint()
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_highest_synced_dwallet_checkpoint()
    }

    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_lowest_available_dwallet_checkpoint()
    }

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_dwallet_checkpoint_by_digest(digest)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        (**self).get_dwallet_checkpoint_by_sequence_number(sequence_number)
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>> {
        (**self).get_latest_system_checkpoint()
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_highest_verified_system_checkpoint()
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_highest_synced_system_checkpoint()
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        (**self).get_lowest_available_system_checkpoint()
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_system_checkpoint_by_digest(digest)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        (**self).get_system_checkpoint_by_sequence_number(sequence_number)
    }
}
