// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::*;
use std::collections::HashMap;
use std::path::Path;
use typed_store::traits::Map;

use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use ika_types::handoff::CertifiedHandoffAttestation;
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

    /// Content-addressed cache of MPC output blobs (validator mpc_data,
    /// and in later steps: network DKG outputs and reconfiguration
    /// outputs). Keyed by `Blake2b256(bytes)`. Survives restart so a
    /// validator that produced a blob in the current epoch can keep
    /// serving it to peers after a crash, before the next-epoch
    /// handoff cert pins the same digest.
    pub(crate) mpc_artifact_blobs: DBMap<[u8; 32], Vec<u8>>,

    /// Once-per-epoch `CertifiedHandoffAttestation` keyed by the
    /// epoch the outgoing committee is handing off *from*. Kept
    /// forever — joiners pulling history may need to verify the
    /// chain back to whichever cert they have a trusted committee
    /// for, and skipping a single epoch can permanently break their
    /// ability to bootstrap.
    pub(crate) certified_handoff_attestations: DBMap<EpochId, CertifiedHandoffAttestation>,
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

    /// Inserts an MPC artifact blob keyed by `digest = Blake2b256(bytes)`.
    /// Idempotent — callers writing the same bytes produce the same
    /// digest. Callers MUST compute the digest from the exact bytes
    /// they pass in; the table does not re-verify.
    pub fn insert_mpc_artifact_blob(&self, digest: [u8; 32], bytes: &[u8]) -> IkaResult {
        self.mpc_artifact_blobs.insert(&digest, &bytes.to_vec())?;
        Ok(())
    }

    pub fn get_mpc_artifact_blob(&self, digest: &[u8; 32]) -> IkaResult<Option<Vec<u8>>> {
        Ok(self.mpc_artifact_blobs.get(digest)?)
    }

    /// Iterator over every persisted artifact blob. Used at node
    /// startup to hydrate the in-memory blob store so peers can serve
    /// blobs immediately after restart.
    pub fn iter_mpc_artifact_blobs(
        &self,
    ) -> impl Iterator<Item = IkaResult<([u8; 32], Vec<u8>)>> + '_ {
        self.mpc_artifact_blobs
            .safe_iter()
            .map(|res| res.map_err(IkaError::from))
    }

    /// Persists a `CertifiedHandoffAttestation` for the epoch it
    /// attests. Idempotent at the byte level — re-writing the
    /// exact same cert is a no-op. Re-writing a *different* cert
    /// for the same epoch overwrites; the caller is expected to
    /// only persist certs that came out of a quorum-aggregated
    /// `HandoffAggregator` (so divergence here would indicate a
    /// protocol violation worth investigating, not a routine
    /// occurrence).
    pub fn insert_certified_handoff_attestation(
        &self,
        epoch: EpochId,
        cert: &CertifiedHandoffAttestation,
    ) -> IkaResult {
        self.certified_handoff_attestations.insert(&epoch, cert)?;
        Ok(())
    }

    pub fn get_certified_handoff_attestation(
        &self,
        epoch: EpochId,
    ) -> IkaResult<Option<CertifiedHandoffAttestation>> {
        Ok(self.certified_handoff_attestations.get(&epoch)?)
    }

    /// Iterator over every persisted handoff cert, oldest first.
    /// Used by the Anemo handoff-cert service (next step) to
    /// answer joiner bootstrap requests.
    pub fn iter_certified_handoff_attestations(
        &self,
    ) -> impl Iterator<Item = IkaResult<(EpochId, CertifiedHandoffAttestation)>> + '_ {
        self.certified_handoff_attestations
            .safe_iter()
            .map(|res| res.map_err(IkaError::from))
    }
}

/// Adapter so the Anemo `validator_metadata` server can read certs
/// directly out of perpetual storage without taking on a dep on
/// `ika-core` types beyond `ika-types`.
impl ika_network::validator_metadata::HandoffCertStorage for AuthorityPerpetualTables {
    fn get(&self, epoch: EpochId) -> Option<CertifiedHandoffAttestation> {
        match self.get_certified_handoff_attestation(epoch) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    epoch,
                    "perpetual read of certified handoff attestation failed"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation};

    fn open_tables() -> (tempfile::TempDir, AuthorityPerpetualTables) {
        let dir = tempfile::tempdir().unwrap();
        let tables = AuthorityPerpetualTables::open(dir.path(), None);
        (dir, tables)
    }

    fn empty_cert(epoch: EpochId) -> CertifiedHandoffAttestation {
        CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch,
                next_committee_pubkey_set_hash: [0xAB; 32],
                items: vec![],
            },
            signatures: vec![],
        }
    }

    #[tokio::test]
    async fn certified_handoff_attestation_insert_get_roundtrip() {
        let (_dir, tables) = open_tables();
        let cert = empty_cert(5);
        tables
            .insert_certified_handoff_attestation(5, &cert)
            .expect("insert");
        let loaded = tables
            .get_certified_handoff_attestation(5)
            .expect("get")
            .expect("present");
        assert_eq!(loaded, cert);
        assert!(
            tables
                .get_certified_handoff_attestation(6)
                .expect("get")
                .is_none()
        );
    }

    #[tokio::test]
    async fn certified_handoff_attestation_iter_returns_all_epochs() {
        let (_dir, tables) = open_tables();
        for epoch in [3u64, 1, 2] {
            tables
                .insert_certified_handoff_attestation(epoch, &empty_cert(epoch))
                .unwrap();
        }
        let mut seen: Vec<EpochId> = tables
            .iter_certified_handoff_attestations()
            .map(|r| r.unwrap().0)
            .collect();
        seen.sort();
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn certified_handoff_attestation_insert_is_idempotent_on_identical_bytes() {
        let (_dir, tables) = open_tables();
        let cert = empty_cert(9);
        tables
            .insert_certified_handoff_attestation(9, &cert)
            .unwrap();
        tables
            .insert_certified_handoff_attestation(9, &cert)
            .unwrap();
        let count = tables.iter_certified_handoff_attestations().count();
        assert_eq!(count, 1);
    }
}
