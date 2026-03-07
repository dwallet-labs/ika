// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::error::Result;
use crate::checkpoint::{CheckpointSequenceNumber, DWallet, System, VerifiedCheckpointMessage};
use crate::committee::{Committee, EpochId};
use crate::digests::{
    DWalletCheckpointContentsDigest, DWalletCheckpointMessageDigest,
    SystemCheckpointContentsDigest, SystemCheckpointMessageDigest,
};
use crate::storage::{ReadStore, WriteStore};
use std::collections::HashMap;
use std::sync::Arc;
use tap::Pipe;
use tracing::error;

#[derive(Clone, Debug, Default)]
pub struct SharedInMemoryStore(Arc<std::sync::RwLock<InMemoryStore>>);

impl SharedInMemoryStore {
    pub fn inner(&self) -> std::sync::RwLockReadGuard<'_, InMemoryStore> {
        self.0.read().unwrap()
    }

    pub fn inner_mut(&self) -> std::sync::RwLockWriteGuard<'_, InMemoryStore> {
        self.0.write().unwrap()
    }
}

impl ReadStore for SharedInMemoryStore {
    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>> {
        self.inner()
            .get_committee_by_epoch(epoch)
            .cloned()
            .map(Arc::new)
            .pipe(Ok)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>> {
        todo!()
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.inner()
            .get_highest_verified_dwallet_checkpoint()
            .cloned()
            .pipe(Ok)
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.inner()
            .get_highest_synced_dwallet_checkpoint()
            .cloned()
            .pipe(Ok)
    }

    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        Ok(self.inner().get_lowest_available_dwallet_checkpoint())
    }

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.inner()
            .get_dwallet_checkpoint_by_digest(digest)
            .cloned()
            .pipe(Ok)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.inner()
            .get_dwallet_checkpoint_by_sequence_number(sequence_number)
            .cloned()
            .pipe(Ok)
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>> {
        todo!()
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.inner()
            .get_highest_verified_system_checkpoint()
            .cloned()
            .pipe(Ok)
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.inner()
            .get_highest_synced_system_checkpoint()
            .cloned()
            .pipe(Ok)
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        Ok(self.inner().get_lowest_available_system_checkpoint())
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.inner()
            .get_system_checkpoint_by_digest(digest)
            .cloned()
            .pipe(Ok)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.inner()
            .get_system_checkpoint_by_sequence_number(sequence_number)
            .cloned()
            .pipe(Ok)
    }
}

impl WriteStore for SharedInMemoryStore {
    fn insert_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        self.inner_mut().insert_checkpoint(checkpoint);
        Ok(())
    }

    fn update_highest_synced_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        self.inner_mut()
            .update_highest_synced_checkpoint(checkpoint);
        Ok(())
    }

    fn update_highest_verified_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        self.inner_mut()
            .update_highest_verified_checkpoint(checkpoint);
        Ok(())
    }

    fn insert_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        self.inner_mut().insert_system_checkpoint(system_checkpoint);
        Ok(())
    }

    fn update_highest_synced_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        self.inner_mut()
            .update_highest_synced_system_checkpoint(system_checkpoint);
        Ok(())
    }

    fn update_highest_verified_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        self.inner_mut()
            .update_highest_verified_system_checkpoint(system_checkpoint);
        Ok(())
    }

    fn insert_committee(&self, new_committee: Committee) -> Result<()> {
        self.inner_mut().insert_committee(new_committee);
        Ok(())
    }
}

impl SharedInMemoryStore {
    pub fn insert_certified_checkpoint(&self, checkpoint: &VerifiedCheckpointMessage<DWallet>) {
        self.inner_mut().insert_certified_checkpoint(checkpoint);
    }

    pub fn insert_certified_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) {
        self.inner_mut()
            .insert_certified_system_checkpoint(system_checkpoint);
    }
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    highest_verified_dwallet_checkpoint:
        Option<(CheckpointSequenceNumber, DWalletCheckpointMessageDigest)>,
    highest_synced_dwallet_checkpoint:
        Option<(CheckpointSequenceNumber, DWalletCheckpointMessageDigest)>,
    checkpoints: HashMap<DWalletCheckpointMessageDigest, VerifiedCheckpointMessage<DWallet>>,
    contents_digest_to_sequence_number:
        HashMap<DWalletCheckpointContentsDigest, CheckpointSequenceNumber>,
    sequence_number_to_digest: HashMap<CheckpointSequenceNumber, DWalletCheckpointMessageDigest>,

    epoch_to_committee: Vec<Committee>,

    lowest_dwallet_checkpoint_number: CheckpointSequenceNumber,

    highest_verified_system_checkpoint:
        Option<(CheckpointSequenceNumber, SystemCheckpointMessageDigest)>,
    highest_synced_system_checkpoint:
        Option<(CheckpointSequenceNumber, SystemCheckpointMessageDigest)>,
    system_checkpoints: HashMap<SystemCheckpointMessageDigest, VerifiedCheckpointMessage<System>>,
    system_checkpoint_contents_digest_to_sequence_number:
        HashMap<SystemCheckpointContentsDigest, CheckpointSequenceNumber>,
    system_checkpoint_sequence_number_to_digest:
        HashMap<CheckpointSequenceNumber, SystemCheckpointMessageDigest>,
    lowest_system_checkpoint_number: CheckpointSequenceNumber,
}

impl InMemoryStore {
    pub fn insert_genesis_state(
        &mut self,
        checkpoint: VerifiedCheckpointMessage<DWallet>,
        system_checkpoint: VerifiedCheckpointMessage<System>,
        committee: Committee,
    ) {
        self.insert_committee(committee);
        self.insert_checkpoint(&checkpoint);
        self.insert_system_checkpoint(&system_checkpoint);
        self.update_highest_synced_checkpoint(&checkpoint);
        self.update_highest_verified_system_checkpoint(&system_checkpoint);
    }

    pub fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Option<&VerifiedCheckpointMessage<DWallet>> {
        self.checkpoints.get(digest)
    }

    pub fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<&VerifiedCheckpointMessage<DWallet>> {
        self.sequence_number_to_digest
            .get(&sequence_number)
            .and_then(|digest| self.get_dwallet_checkpoint_by_digest(digest))
    }

    pub fn get_sequence_number_by_contents_digest(
        &self,
        digest: &DWalletCheckpointContentsDigest,
    ) -> Option<CheckpointSequenceNumber> {
        self.contents_digest_to_sequence_number.get(digest).copied()
    }

    pub fn get_system_checkpoint_sequence_number_by_contents_digest(
        &self,
        digest: &SystemCheckpointContentsDigest,
    ) -> Option<CheckpointSequenceNumber> {
        self.system_checkpoint_contents_digest_to_sequence_number
            .get(digest)
            .copied()
    }

    pub fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Option<&VerifiedCheckpointMessage<DWallet>> {
        self.highest_verified_dwallet_checkpoint
            .as_ref()
            .and_then(|(_, digest)| self.get_dwallet_checkpoint_by_digest(digest))
    }

    pub fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Option<&VerifiedCheckpointMessage<DWallet>> {
        self.highest_synced_dwallet_checkpoint
            .as_ref()
            .and_then(|(_, digest)| self.get_dwallet_checkpoint_by_digest(digest))
    }

    pub fn get_lowest_available_dwallet_checkpoint(&self) -> CheckpointSequenceNumber {
        self.lowest_dwallet_checkpoint_number
    }

    pub fn set_lowest_available_checkpoint(
        &mut self,
        checkpoint_seq_num: CheckpointSequenceNumber,
    ) {
        self.lowest_dwallet_checkpoint_number = checkpoint_seq_num;
    }

    pub fn insert_checkpoint(&mut self, checkpoint: &VerifiedCheckpointMessage<DWallet>) {
        self.insert_certified_checkpoint(checkpoint);
        let digest = *checkpoint.digest();
        let sequence_number = *checkpoint.sequence_number();

        if Some(sequence_number) > self.highest_verified_dwallet_checkpoint.map(|x| x.0) {
            self.highest_verified_dwallet_checkpoint = Some((sequence_number, digest));
        }
    }

    // This function simulates Consensus inserts certified checkpoint into the checkpoint store
    // without bumping the highest_verified_checkpoint watermark.
    pub fn insert_certified_checkpoint(&mut self, checkpoint: &VerifiedCheckpointMessage<DWallet>) {
        let digest = *checkpoint.digest();
        let sequence_number = *checkpoint.sequence_number();

        self.checkpoints.insert(digest, checkpoint.clone());
        self.sequence_number_to_digest
            .insert(sequence_number, digest);
    }

    pub fn update_highest_synced_checkpoint(
        &mut self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) {
        if !self.checkpoints.contains_key(checkpoint.digest()) {
            panic!("store should already contain checkpoint");
        }
        if let Some(highest_synced_checkpoint) = self.highest_synced_dwallet_checkpoint
            && highest_synced_checkpoint.0 >= checkpoint.sequence_number
        {
            return;
        }
        self.highest_synced_dwallet_checkpoint =
            Some((*checkpoint.sequence_number(), *checkpoint.digest()));
    }

    pub fn update_highest_verified_checkpoint(
        &mut self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) {
        if !self.checkpoints.contains_key(checkpoint.digest()) {
            panic!("store should already contain checkpoint");
        }
        if let Some(highest_verified_checkpoint) = self.highest_verified_dwallet_checkpoint
            && highest_verified_checkpoint.0 >= checkpoint.sequence_number
        {
            return;
        }
        self.highest_verified_dwallet_checkpoint =
            Some((*checkpoint.sequence_number(), *checkpoint.digest()));
    }

    pub fn checkpoints(
        &self,
    ) -> &HashMap<DWalletCheckpointMessageDigest, VerifiedCheckpointMessage<DWallet>> {
        &self.checkpoints
    }

    pub fn checkpoint_sequence_number_to_digest(
        &self,
    ) -> &HashMap<CheckpointSequenceNumber, DWalletCheckpointMessageDigest> {
        &self.sequence_number_to_digest
    }

    pub fn get_committee_by_epoch(&self, epoch: EpochId) -> Option<&Committee> {
        self.epoch_to_committee.get(epoch as usize)
    }

    pub fn insert_committee(&mut self, committee: Committee) {
        let epoch = committee.epoch as usize;

        if self.epoch_to_committee.get(epoch).is_some() {
            return;
        }

        self.epoch_to_committee.push(committee);

        if self.epoch_to_committee.len() != epoch + 1 {
            error!("committee was inserted into EpochCommitteeMap out of order");
        }
    }

    pub fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Option<&VerifiedCheckpointMessage<System>> {
        self.system_checkpoints.get(digest)
    }

    pub fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Option<&VerifiedCheckpointMessage<System>> {
        self.system_checkpoint_sequence_number_to_digest
            .get(&sequence_number)
            .and_then(|digest| self.get_system_checkpoint_by_digest(digest))
    }

    pub fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Option<&VerifiedCheckpointMessage<System>> {
        self.highest_verified_system_checkpoint
            .as_ref()
            .and_then(|(_, digest)| self.get_system_checkpoint_by_digest(digest))
    }

    pub fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Option<&VerifiedCheckpointMessage<System>> {
        self.highest_synced_system_checkpoint
            .as_ref()
            .and_then(|(_, digest)| self.get_system_checkpoint_by_digest(digest))
    }

    pub fn get_lowest_available_system_checkpoint(&self) -> CheckpointSequenceNumber {
        self.lowest_system_checkpoint_number
    }

    pub fn set_lowest_available_system_checkpoint(
        &mut self,
        system_checkpoint_seq_num: CheckpointSequenceNumber,
    ) {
        self.lowest_system_checkpoint_number = system_checkpoint_seq_num;
    }

    pub fn insert_system_checkpoint(
        &mut self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) {
        self.insert_certified_system_checkpoint(system_checkpoint);
        let digest = *system_checkpoint.digest();
        let sequence_number = *system_checkpoint.sequence_number();

        if Some(sequence_number) > self.highest_verified_system_checkpoint.map(|x| x.0) {
            self.highest_verified_system_checkpoint = Some((sequence_number, digest));
        }
    }

    // This function simulates Consensus inserts certified system_checkpoint into the system_checkpoint store
    // without bumping the highest_verified_system_checkpoint watermark.
    pub fn insert_certified_system_checkpoint(
        &mut self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) {
        let digest = *system_checkpoint.digest();
        let sequence_number = *system_checkpoint.sequence_number();

        self.system_checkpoints
            .insert(digest, system_checkpoint.clone());
        self.system_checkpoint_sequence_number_to_digest
            .insert(sequence_number, digest);
    }

    pub fn update_highest_synced_system_checkpoint(
        &mut self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) {
        if !self
            .system_checkpoints
            .contains_key(system_checkpoint.digest())
        {
            panic!("store should already contain system_checkpoint");
        }
        if let Some(highest_synced_system_checkpoint) = self.highest_synced_system_checkpoint
            && highest_synced_system_checkpoint.0 >= system_checkpoint.sequence_number
        {
            return;
        }
        self.highest_synced_system_checkpoint = Some((
            *system_checkpoint.sequence_number(),
            *system_checkpoint.digest(),
        ));
    }

    pub fn update_highest_verified_system_checkpoint(
        &mut self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) {
        if !self
            .system_checkpoints
            .contains_key(system_checkpoint.digest())
        {
            panic!("store should already contain system_checkpoint");
        }
        if let Some(highest_verified_system_checkpoint) = self.highest_verified_system_checkpoint
            && highest_verified_system_checkpoint.0 >= system_checkpoint.sequence_number
        {
            return;
        }
        self.highest_verified_system_checkpoint = Some((
            *system_checkpoint.sequence_number(),
            *system_checkpoint.digest(),
        ));
    }

    pub fn system_checkpoints(
        &self,
    ) -> &HashMap<SystemCheckpointMessageDigest, VerifiedCheckpointMessage<System>> {
        &self.system_checkpoints
    }

    pub fn system_checkpoint_sequence_number_to_digest(
        &self,
    ) -> &HashMap<CheckpointSequenceNumber, SystemCheckpointMessageDigest> {
        &self.system_checkpoint_sequence_number_to_digest
    }
}

// This store only keeps last checkpoint in memory which is all we need
// for archive verification.
#[derive(Clone, Debug, Default)]
pub struct SingleCheckpointSharedInMemoryStore(SharedInMemoryStore);

impl SingleCheckpointSharedInMemoryStore {
    pub fn insert_genesis_state(
        &mut self,
        checkpoint: VerifiedCheckpointMessage<DWallet>,
        system_checkpoint: VerifiedCheckpointMessage<System>,
        committee: Committee,
    ) {
        let mut locked = self.0.0.write().unwrap();
        locked.insert_genesis_state(checkpoint, system_checkpoint, committee);
    }
}

impl ReadStore for SingleCheckpointSharedInMemoryStore {
    fn get_committee(&self, epoch: EpochId) -> Result<Option<Arc<Committee>>> {
        self.0.get_committee(epoch)
    }

    fn get_latest_dwallet_checkpoint(&self) -> Result<VerifiedCheckpointMessage<DWallet>> {
        todo!()
    }

    fn get_highest_verified_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.0.get_highest_verified_dwallet_checkpoint()
    }

    fn get_highest_synced_dwallet_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.0.get_highest_synced_dwallet_checkpoint()
    }

    fn get_lowest_available_dwallet_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        self.0.get_lowest_available_dwallet_checkpoint()
    }

    fn get_dwallet_checkpoint_by_digest(
        &self,
        digest: &DWalletCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.0.get_dwallet_checkpoint_by_digest(digest)
    }

    fn get_dwallet_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<DWallet>>> {
        self.0
            .get_dwallet_checkpoint_by_sequence_number(sequence_number)
    }

    fn get_latest_system_checkpoint(&self) -> Result<VerifiedCheckpointMessage<System>> {
        todo!()
    }

    fn get_highest_verified_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.0.get_highest_verified_system_checkpoint()
    }

    fn get_highest_synced_system_checkpoint(
        &self,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.0.get_highest_synced_system_checkpoint()
    }

    fn get_lowest_available_system_checkpoint(&self) -> Result<CheckpointSequenceNumber> {
        self.0.get_lowest_available_system_checkpoint()
    }

    fn get_system_checkpoint_by_digest(
        &self,
        digest: &SystemCheckpointMessageDigest,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.0.get_system_checkpoint_by_digest(digest)
    }

    fn get_system_checkpoint_by_sequence_number(
        &self,
        sequence_number: CheckpointSequenceNumber,
    ) -> Result<Option<VerifiedCheckpointMessage<System>>> {
        self.0
            .get_system_checkpoint_by_sequence_number(sequence_number)
    }
}

impl WriteStore for SingleCheckpointSharedInMemoryStore {
    fn insert_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        {
            let mut locked = self.0.0.write().unwrap();
            locked.checkpoints.clear();
            locked.sequence_number_to_digest.clear();
        }
        self.0.insert_dwallet_checkpoint(checkpoint)?;
        Ok(())
    }

    fn update_highest_synced_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        self.0
            .update_highest_synced_dwallet_checkpoint(checkpoint)?;
        Ok(())
    }

    fn update_highest_verified_dwallet_checkpoint(
        &self,
        checkpoint: &VerifiedCheckpointMessage<DWallet>,
    ) -> Result<()> {
        self.0
            .update_highest_verified_dwallet_checkpoint(checkpoint)?;
        Ok(())
    }

    fn insert_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        {
            let mut locked = self.0.0.write().unwrap();
            locked.system_checkpoints.clear();
            locked.system_checkpoint_sequence_number_to_digest.clear();
        }
        self.0.insert_system_checkpoint(system_checkpoint)?;
        Ok(())
    }

    fn update_highest_synced_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        self.0
            .update_highest_synced_system_checkpoint(system_checkpoint)?;
        Ok(())
    }

    fn update_highest_verified_system_checkpoint(
        &self,
        system_checkpoint: &VerifiedCheckpointMessage<System>,
    ) -> Result<()> {
        self.0
            .update_highest_verified_system_checkpoint(system_checkpoint)?;
        Ok(())
    }

    fn insert_committee(&self, new_committee: Committee) -> Result<()> {
        self.0.insert_committee(new_committee)
    }
}
