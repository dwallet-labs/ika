// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_checkpoints::DWalletCheckpointStore;
use crate::epoch::committee_store::CommitteeStore;
use crate::system_checkpoints::SystemCheckpointStore;
use ika_types::committee::Committee;
use ika_types::committee::EpochId;
use ika_types::digests::SystemCheckpointMessageDigest;
use ika_types::error::IkaError;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointMessageDigest;
use ika_types::messages_dwallet_checkpoint::DWalletCheckpointSequenceNumber;
use ika_types::messages_dwallet_checkpoint::VerifiedDWalletCheckpointMessage;
use ika_types::messages_system_checkpoints::{
    SystemCheckpointSequenceNumber, VerifiedSystemCheckpointMessage,
};
use ika_types::storage::ReadStore;
use ika_types::storage::WriteStore;
use ika_types::storage::error::Error as StorageError;
use ika_types::storage::error::Result;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone)]
pub struct RocksDbStore {
    committee_store: Arc<CommitteeStore>,
    dwallet_checkpoint_store: Arc<DWalletCheckpointStore>,
    // in memory checkpoint watermark sequence numbers
    highest_verified_dwallet_checkpoint: Arc<Mutex<Option<DWalletCheckpointSequenceNumber>>>,
    highest_synced_dwallet_checkpoint: Arc<Mutex<Option<DWalletCheckpointSequenceNumber>>>,

    system_checkpoint_store: Arc<SystemCheckpointStore>,
    // in memory system_checkpoint watermark sequence numbers
    highest_verified_system_checkpoint: Arc<Mutex<Option<SystemCheckpointSequenceNumber>>>,
    highest_synced_system_checkpoint: Arc<Mutex<Option<SystemCheckpointSequenceNumber>>>,
}

impl RocksDbStore {
    pub fn new(
        committee_store: Arc<CommitteeStore>,
        checkpoint_store: Arc<DWalletCheckpointStore>,
        system_checkpoint_store: Arc<SystemCheckpointStore>,
    ) -> Self {
        Self {
            committee_store,
            dwallet_checkpoint_store: checkpoint_store,
            highest_verified_dwallet_checkpoint: Arc::new(Mutex::new(None)),
            highest_synced_dwallet_checkpoint: Arc::new(Mutex::new(None)),
            system_checkpoint_store,
            highest_verified_system_checkpoint: Arc::new(Mutex::new(None)),
            highest_synced_system_checkpoint: Arc::new(Mutex::new(None)),
        }
    }

    pub fn get_last_executed_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, IkaError> {
        Ok(self
            .dwallet_checkpoint_store
            .get_highest_executed_dwallet_checkpoint()?)
    }
}

impl ReadStore for RocksDbStore {
    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, StorageError> {
        self.dwallet_checkpoint_store
            .get_dwallet_checkpoint_by_digest(digest)
            .map_err(Into::into)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: DWalletCheckpointSequenceNumber,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, StorageError> {
        self.dwallet_checkpoint_store
            .get_dwallet_checkpoint_by_sequence_number(sequence_number)
            .map_err(Into::into)
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, StorageError> {
        self.dwallet_checkpoint_store
            .get_highest_verified_dwallet_checkpoint()
            .map_err(Into::into)
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedDWalletCheckpointMessage>, StorageError> {
        self.dwallet_checkpoint_store
            .get_highest_synced_dwallet_checkpoint()
            .map_err(Into::into)
    }

    fn get_lowest_available_dwallet_checkpoint(
        &self,
    ) -> Result<DWalletCheckpointSequenceNumber, StorageError> {
        let highest_pruned_cp = self
            .dwallet_checkpoint_store
            .get_highest_pruned_dwallet_checkpoint_seq_number()
            .map_err(Into::<StorageError>::into)?;

        if highest_pruned_cp == 0 {
            Ok(0)
        } else {
            Ok(highest_pruned_cp + 1)
        }
    }

    fn get_committee(
        &self,
        epoch: EpochId,
    ) -> Result<Option<Arc<Committee>>, ika_types::storage::error::Error> {
        // Propagate rather than unwrap: a committee_map read can fail on a
        // decode error (e.g. a record written by an older binary with a
        // different `Committee` layout), and a panic here on the read path
        // would crash-loop under panic=abort.
        self.committee_store
            .get_committee(&epoch)
            .map_err(ika_types::storage::error::Error::custom)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedDWalletCheckpointMessage> {
        self.dwallet_checkpoint_store
            .get_highest_executed_dwallet_checkpoint()
            .map_err(ika_types::storage::error::Error::custom)?
            .ok_or_else(|| {
                ika_types::storage::error::Error::missing("unable to get latest checkpoint")
            })
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedSystemCheckpointMessage> {
        self.system_checkpoint_store
            .get_highest_executed_system_checkpoint()
            .map_err(ika_types::storage::error::Error::custom)?
            .ok_or_else(|| {
                ika_types::storage::error::Error::missing("unable to get latest params message")
            })
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>> {
        self.system_checkpoint_store
            .get_highest_verified_system_checkpoint()
            .map_err(ika_types::storage::error::Error::custom)
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>> {
        self.system_checkpoint_store
            .get_highest_synced_system_checkpoint()
            .map_err(ika_types::storage::error::Error::custom)
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<SystemCheckpointSequenceNumber> {
        let highest_pruned_cp = self
            .system_checkpoint_store
            .get_highest_pruned_system_checkpoint_seq_number()
            .map_err(ika_types::storage::error::Error::custom)?;

        if highest_pruned_cp == 0 {
            Ok(0)
        } else {
            Ok(highest_pruned_cp + 1)
        }
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>> {
        self.system_checkpoint_store
            .get_system_checkpoint_by_digest(digest)
            .map_err(ika_types::storage::error::Error::custom)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: SystemCheckpointSequenceNumber,
    ) -> Result<Option<VerifiedSystemCheckpointMessage>> {
        self.system_checkpoint_store
            .get_system_checkpoint_by_sequence_number(sequence_number)
            .map_err(ika_types::storage::error::Error::custom)
    }
}

impl WriteStore for RocksDbStore {
    fn insert_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), ika_types::storage::error::Error> {
        self.dwallet_checkpoint_store
            .insert_verified_checkpoint(checkpoint)
            .map_err(Into::into)
    }

    fn update_highest_synced_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), ika_types::storage::error::Error> {
        let mut locked = self.highest_synced_dwallet_checkpoint.lock();
        if locked.is_some() && locked.unwrap() >= checkpoint.sequence_number {
            return Ok(());
        }
        self.dwallet_checkpoint_store
            .update_highest_synced_checkpoint(checkpoint)
            .map_err(ika_types::storage::error::Error::custom)?;
        *locked = Some(checkpoint.sequence_number);
        Ok(())
    }

    fn update_highest_verified_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedDWalletCheckpointMessage,
    ) -> Result<(), ika_types::storage::error::Error> {
        let mut locked = self.highest_verified_dwallet_checkpoint.lock();
        if locked.is_some() && locked.unwrap() >= checkpoint.sequence_number {
            return Ok(());
        }
        self.dwallet_checkpoint_store
            .update_highest_verified_checkpoint(checkpoint)
            .map_err(ika_types::storage::error::Error::custom)?;
        *locked = Some(checkpoint.sequence_number);
        Ok(())
    }

    fn insert_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<()> {
        self.system_checkpoint_store
            .insert_verified_system_checkpoint(system_checkpoint)
            .map_err(ika_types::storage::error::Error::custom)
    }

    fn update_highest_synced_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<()> {
        let mut locked = self.highest_synced_system_checkpoint.lock();
        if locked.is_some() && locked.unwrap() >= system_checkpoint.sequence_number {
            return Ok(());
        }
        self.system_checkpoint_store
            .update_highest_synced_system_checkpoint(system_checkpoint)
            .map_err(ika_types::storage::error::Error::custom)?;
        *locked = Some(system_checkpoint.sequence_number);
        Ok(())
    }

    fn update_highest_verified_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedSystemCheckpointMessage,
    ) -> Result<()> {
        let mut locked = self.highest_verified_system_checkpoint.lock();
        if locked.is_some() && locked.unwrap() >= system_checkpoint.sequence_number {
            return Ok(());
        }
        self.system_checkpoint_store
            .update_highest_verified_system_checkpoint(system_checkpoint)
            .map_err(ika_types::storage::error::Error::custom)?;
        *locked = Some(system_checkpoint.sequence_number);
        Ok(())
    }

    fn insert_committee(
        &self,
        new_committee: Committee,
    ) -> Result<(), ika_types::storage::error::Error> {
        self.committee_store
            .insert_new_committee(&new_committee)
            .unwrap();
        Ok(())
    }
}
