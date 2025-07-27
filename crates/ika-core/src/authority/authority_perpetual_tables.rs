// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::*;
use std::collections::HashMap;
use std::path::Path;
use typed_store::traits::Map;

use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use typed_store::DBMapUtils;
use typed_store::rocks::{DBBatch, DBMap, MetricConf};
use typed_store::rocksdb::Options;

/// AuthorityPerpetualTables contains data that must be preserved from one epoch to the next.
#[derive(DBMapUtils)]
pub struct AuthorityPerpetualTables {
    /// Parameters of the system fixed at the epoch start
    pub(crate) epoch_start_configuration: DBMap<(), EpochStartConfiguration>,

    /// A singleton table that stores latest pruned checkpoint. Used to keep objects pruner progress
    pub(crate) pruned_checkpoint: DBMap<(), DWalletCheckpointSequenceNumber>,

    /// Holds the completed MPC session IDs, to avoid re-using them in the case of a bug
    /// or in the unlikely case of a malicious full-node/Move contract/Sui network.
    pub(crate) dwallet_mpc_computation_completed_sessions: DBMap<SessionIdentifier, ()>,
}

impl AuthorityPerpetualTables {
    pub fn path(parent_path: &Path) -> PathBuf {
        parent_path.join("perpetual")
    }

    pub fn open(parent_path: &Path, db_options: Option<Options>) -> Self {
        Self::open_tables_read_write(
            Self::path(parent_path),
            MetricConf::new("perpetual"),
            db_options,
            None,
        )
    }

    pub fn get_recovery_epoch_at_restart(&self) -> IkaResult<EpochId> {
        Ok(self
            .epoch_start_configuration
            .get(&())?
            .expect("Must have current epoch.")
            .epoch_start_state()
            .epoch())
    }

    pub fn set_epoch_start_configuration(
        &self,
        epoch_start_configuration: &EpochStartConfiguration,
    ) -> IkaResult {
        let mut wb = self.epoch_start_configuration.batch();
        wb.insert_batch(
            &self.epoch_start_configuration,
            std::iter::once(((), epoch_start_configuration)),
        )?;
        wb.write()?;
        Ok(())
    }

    pub fn get_highest_pruned_checkpoint(&self) -> IkaResult<DWalletCheckpointSequenceNumber> {
        Ok(self.pruned_checkpoint.get(&())?.unwrap_or_default())
    }

    pub fn set_highest_pruned_checkpoint(
        &self,
        wb: &mut DBBatch,
        checkpoint_number: DWalletCheckpointSequenceNumber,
    ) -> IkaResult {
        wb.insert_batch(&self.pruned_checkpoint, [((), checkpoint_number)])?;
        Ok(())
    }

    pub fn set_highest_pruned_checkpoint_without_wb(
        &self,
        checkpoint_number: DWalletCheckpointSequenceNumber,
    ) -> IkaResult {
        let mut wb = self.pruned_checkpoint.batch();
        self.set_highest_pruned_checkpoint(&mut wb, checkpoint_number)?;
        wb.write()?;
        Ok(())
    }

    pub fn get_dwallet_mpc_sessions_completed_status(
        &self,
        session_identifiers: Vec<SessionIdentifier>,
    ) -> IkaResult<HashMap<SessionIdentifier, bool>> {
        let multi_get_result = self
            .dwallet_mpc_computation_completed_sessions
            .multi_get(&session_identifiers)?;

        let mpc_session_identifier_to_computation_completed = session_identifiers
            .into_iter()
            .zip(multi_get_result)
            .map(|(session_identifier, res)| (session_identifier, res.is_some()))
            .collect();

        Ok(mpc_session_identifier_to_computation_completed)
    }

    pub fn insert_dwallet_mpc_computation_completed_sessions(
        &self,
        newly_completed_session_ids: &[SessionIdentifier],
    ) -> IkaResult {
        let newly_completed_session_ids: Vec<_> = newly_completed_session_ids
            .iter()
            .map(|&session_identifier| (session_identifier, ()))
            .collect();

        let mut wb = self.dwallet_mpc_computation_completed_sessions.batch();
        wb.insert_batch(
            &self.dwallet_mpc_computation_completed_sessions,
            newly_completed_session_ids,
        )?;
        wb.write()?;
        Ok(())
    }
}
