// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use super::*;
use std::collections::HashMap;
use std::path::Path;
use typed_store::traits::Map;

use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::sui_connector::verified_state_cache::VerifiedSnapshot;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::handoff::CertifiedHandoffAttestation;
use ika_types::messages_dwallet_mpc::SessionIdentifier;
use sui_types::base_types::TransactionDigest as SuiTransactionDigest;
use sui_types::committee::Committee as SuiCommittee;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary as SuiCertifiedCheckpointSummary,
    CheckpointSequenceNumber as SuiCheckpointSequenceNumber,
};
use typed_store::DBMapUtils;
use typed_store::TypedStoreError;
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

    /// The validator's own MPC output consensus transaction per session,
    /// serialized (bcs), persisted when it is first submitted. Kept so a
    /// session whose computation completed astride an epoch boundary can be
    /// RE-SUBMITTED in the next epoch: an output sequenced in the dying
    /// epoch's consensus dies with that epoch's tally, while the validator's
    /// durable computation-completed flag suppresses recomputation on the
    /// re-pull — without resubmission the output quorum splits across the
    /// two epochs and the session never completes on-chain, pinning the
    /// epoch close forever.
    pub(crate) dwallet_mpc_own_output_transactions: DBMap<SessionIdentifier, Vec<u8>>,

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

    /// Per-key map `network_key_id -> blob digest` for the network
    /// DKG output. Stable across epochs (a key's DKG output is
    /// produced once and never replaced), so storing it perpetually
    /// lets `EpochStoreBlobSource` resolve the blob bytes for a key
    /// whose DKG completed in a prior epoch. The per-epoch
    /// `network_dkg_output_digests` table is still kept and written
    /// in the originating epoch — this is its perpetual mirror.
    pub(crate) network_dkg_output_digests_by_key: DBMap<ObjectID, [u8; 32]>,

    /// Per-key map `network_key_id -> blob digest` for the LATEST
    /// network reconfiguration output. Reconfig outputs change each
    /// epoch, but only the most recent one matters for class-groups
    /// assembly + downstream MPC, so we overwrite on each write.
    pub(crate) network_reconfiguration_output_digests_by_key: DBMap<ObjectID, [u8; 32]>,

    /// `(reconfiguration_epoch, network_key_id) -> reconfig output
    /// digest`, keyed by the reconfiguration session's *own* epoch
    /// (the on-chain request event's epoch, identical across
    /// validators) rather than the wall-clock epoch in which the
    /// output happened to be processed locally. The handoff
    /// attestation for epoch `e` reads exactly the `e` slice: this is
    /// what makes the `NetworkReconfigurationOutput` item
    /// epoch-deterministic. Without it, a reconfiguration output
    /// finalized just after a validator rolled to epoch `e+1` lands in
    /// `e+1`'s per-epoch table on that validator but `e`'s on a faster
    /// peer, so the two certify different digests for epoch `e` and
    /// cross-reject as `AttestationMismatch` — wedging EndOfPublish.
    /// One small entry per (epoch, key); never overwritten, so the
    /// historical slice stays available for late handoff retries.
    pub(crate) network_reconfiguration_output_digest_by_epoch_and_key:
        DBMap<(EpochId, ObjectID), [u8; 32]>,

    // -- OCS verifier (Sui state ingest) ----------------------------------------------------
    /// Sui committees with NO backing end-of-epoch summary: the bootstrap
    /// base committee and any unverified-fallback installs. Sparse — every
    /// other committee is derived on demand from `sui_committee_summaries`
    /// (see `CommitteeStore`). Survives Ika epoch boundaries.
    pub(crate) sui_committees: DBMap<u64, SuiCommittee>,

    /// Highest Sui epoch we hold a (derivable) committee for — the ratchet
    /// head. Advanced by `record_sui_committee_transition` (verified path) or
    /// `install_sui_committee` (no-summary path).
    pub(crate) sui_committee_head: DBMap<(), u64>,

    /// Verified end-of-epoch `CertifiedCheckpointSummary` keyed by the epoch
    /// it terminates. The summary at epoch E proves the transition to
    /// committee[E+1]. Sparse: only present for epochs whose end-of-epoch
    /// summary we've actually seen (the trusted anchor's epoch + every
    /// epoch the ratchet has walked through).
    pub(crate) sui_committee_summaries: DBMap<u64, SuiCertifiedCheckpointSummary>,

    /// Last checkpoint sequence number of each Sui epoch. Used by the ratchet
    /// to fetch the right end-of-epoch CheckpointData without re-querying the
    /// `LedgerService::GetEpoch` RPC.
    pub(crate) sui_end_of_epoch_seqs: DBMap<u64, SuiCheckpointSequenceNumber>,

    /// Retained full end-of-epoch `CheckpointData`, keyed by its sequence
    /// number. A sui-state-direct node persists each one as the pusher streams
    /// past it (`RetainedFullnodeTransport`), so it can serve a mirrored peer's
    /// committee ratchet the end-of-epoch checkpoint *after* its own Sui fullnode
    /// has pruned it. Heavier than the summary alone but sparse (one per epoch);
    /// pruned with the verified-cache retention floor.
    pub(crate) sui_end_of_epoch_checkpoints: DBMap<SuiCheckpointSequenceNumber, CheckpointData>,

    /// TX digest → checkpoint sequence index. Avoids a `get_transaction` round-trip
    /// when verifying repeat reads of objects whose `previous_transaction` we've seen before.
    pub(crate) sui_tx_to_checkpoint: DBMap<SuiTransactionDigest, SuiCheckpointSequenceNumber>,

    /// Highest Sui checkpoint sequence number the sui-state-direct pusher has considered.
    /// Persisted so that a restart resumes pushing where it left off rather than
    /// jumping to `latest` and silently leaving a gap during downtime.
    pub(crate) sui_pusher_last_seq: DBMap<(), SuiCheckpointSequenceNumber>,

    /// Durable copy of the OCS-verified state cache (`VerifiedStateCache`):
    /// `ObjectID → VerifiedSnapshot { object, proof, summary, source seq }`.
    /// Written through on every checkpoint the pusher folds, so a restart
    /// rehydrates the cache from here instead of re-fetching from the (possibly
    /// pruned) Sui fullnode. The parent→children index is rebuilt from the
    /// objects' owners on load, not persisted.
    pub(crate) verified_object_cache: DBMap<ObjectID, VerifiedSnapshot>,

    /// Highest checkpoint sequence the `verified_object_cache` reflects — the
    /// cache head, restored on load so the staleness tripwire isn't tricked
    /// into treating a freshly-rehydrated cache as stale.
    pub(crate) verified_object_cache_head: DBMap<(), SuiCheckpointSequenceNumber>,
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

    /// Persist this validator's own serialized MPC output consensus
    /// transaction for `session_identifier` (see the table doc for why).
    pub fn insert_dwallet_mpc_own_output_transaction(
        &self,
        session_identifier: SessionIdentifier,
        serialized_transaction: Vec<u8>,
    ) -> IkaResult {
        self.dwallet_mpc_own_output_transactions
            .insert(&session_identifier, &serialized_transaction)?;
        Ok(())
    }

    /// The validator's own serialized MPC output consensus transaction for
    /// `session_identifier`, if one was ever submitted.
    pub fn get_dwallet_mpc_own_output_transaction(
        &self,
        session_identifier: SessionIdentifier,
    ) -> IkaResult<Option<Vec<u8>>> {
        Ok(self
            .dwallet_mpc_own_output_transactions
            .get(&session_identifier)?)
    }

    /// Inserts an MPC artifact blob keyed by `digest = Blake2b256(bytes)`.
    /// Idempotent on equal `(digest, bytes)`.
    ///
    /// Verifies `Blake2b256(bytes) == digest` before writing. The
    /// blob table is perpetual and is served back to peers by
    /// digest, so a wrong-digest insert would silently corrupt P2P
    /// fetches across epochs — peers asking for `digest=X` would
    /// receive bytes that don't hash to `X` and either fail
    /// verification or, worse, accept an inconsistent value if
    /// they don't verify. Caller bugs are caught here at the
    /// boundary rather than detonating downstream.
    pub fn insert_mpc_artifact_blob(&self, digest: [u8; 32], bytes: &[u8]) -> IkaResult {
        let computed = mpc_data_blob_hash(bytes);
        if computed != digest {
            return Err(IkaError::SuiConnectorInternalError(format!(
                "insert_mpc_artifact_blob: digest mismatch — caller passed {} but Blake2b256(bytes) = {}",
                hex::encode(digest),
                hex::encode(computed),
            )));
        }
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

    /// Records the latest known digest of a network key's DKG output.
    /// DKG output is produced once per key and doesn't change across
    /// epochs, so callers can re-insert with the same digest safely
    /// (idempotent on equal bytes). Stored perpetually so consumers
    /// in epochs *after* the originating epoch can still resolve the
    /// blob bytes via the digest.
    pub fn insert_network_dkg_output_digest(
        &self,
        network_key_id: ObjectID,
        digest: [u8; 32],
    ) -> IkaResult {
        self.network_dkg_output_digests_by_key
            .insert(&network_key_id, &digest)?;
        Ok(())
    }

    pub fn get_network_dkg_output_digest(
        &self,
        network_key_id: &ObjectID,
    ) -> IkaResult<Option<[u8; 32]>> {
        Ok(self.network_dkg_output_digests_by_key.get(network_key_id)?)
    }

    /// Records the LATEST known digest of a network key's
    /// reconfiguration output. Reconfig outputs change every epoch,
    /// so the table stores only the most recent digest per key —
    /// downstream class-groups assembly + reconfig MPC only ever
    /// need the latest.
    pub fn insert_network_reconfiguration_output_digest(
        &self,
        network_key_id: ObjectID,
        digest: [u8; 32],
    ) -> IkaResult {
        self.network_reconfiguration_output_digests_by_key
            .insert(&network_key_id, &digest)?;
        Ok(())
    }

    /// Records a reconfiguration output digest under the
    /// reconfiguration session's own epoch (deterministic across
    /// validators), for the epoch-keyed handoff attestation lookup.
    /// Distinct from [`Self::insert_network_reconfiguration_output_digest`],
    /// which keeps only the latest per key for the off-chain overlay.
    pub fn insert_network_reconfiguration_output_digest_for_epoch(
        &self,
        reconfiguration_epoch: EpochId,
        network_key_id: ObjectID,
        digest: [u8; 32],
    ) -> IkaResult {
        self.network_reconfiguration_output_digest_by_epoch_and_key
            .insert(&(reconfiguration_epoch, network_key_id), &digest)?;
        Ok(())
    }

    /// Point lookup of the digest recorded by
    /// [`Self::insert_network_reconfiguration_output_digest_for_epoch`] —
    /// the digest of the reconfiguration output produced by
    /// `reconfiguration_epoch`'s reconfiguration session for this key
    /// (i.e. the output targeting `reconfiguration_epoch + 1`'s committee).
    pub fn get_network_reconfiguration_output_digest_for_epoch(
        &self,
        reconfiguration_epoch: EpochId,
        network_key_id: &ObjectID,
    ) -> IkaResult<Option<[u8; 32]>> {
        Ok(self
            .network_reconfiguration_output_digest_by_epoch_and_key
            .get(&(reconfiguration_epoch, *network_key_id))?)
    }

    pub fn get_network_reconfiguration_output_digest(
        &self,
        network_key_id: &ObjectID,
    ) -> IkaResult<Option<[u8; 32]>> {
        Ok(self
            .network_reconfiguration_output_digests_by_key
            .get(network_key_id)?)
    }

    /// Returns the `key_id -> digest` slice recorded for `epoch` by
    /// [`Self::insert_network_reconfiguration_output_digest_for_epoch`].
    /// Keys are be-fix-int serialized, so the `(epoch, key)` tuples sort
    /// epoch-major and the epoch slice is a bounded range scan — the
    /// table is perpetual and this is read from per-second loops.
    pub fn get_network_reconfiguration_output_digests_for_epoch(
        &self,
        epoch: EpochId,
    ) -> IkaResult<std::collections::BTreeMap<ObjectID, [u8; 32]>> {
        let upper_bound = epoch.checked_add(1).map(|next| (next, ObjectID::ZERO));
        let mut out = std::collections::BTreeMap::new();
        for entry in self
            .network_reconfiguration_output_digest_by_epoch_and_key
            .safe_iter_with_bounds(Some((epoch, ObjectID::ZERO)), upper_bound)
        {
            let ((_, key_id), digest) = entry?;
            out.insert(key_id, digest);
        }
        Ok(out)
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

    // -- Sui-side state (consumed by ika-core/sui_connector) --------------------------------

    pub fn get_sui_committee(&self, sui_epoch: u64) -> IkaResult<Option<SuiCommittee>> {
        Ok(self.sui_committees.get(&sui_epoch)?)
    }

    pub fn highest_sui_committee_epoch(&self) -> IkaResult<Option<u64>> {
        Ok(self.sui_committee_head.get(&())?)
    }

    /// The lowest-epoch retained end-of-epoch summary (the bootstrap anchor's),
    /// if any. Its checkpoint is the deepest the node can committee-verify, so a
    /// changeset backfill can fold no earlier than `seq + 1`.
    pub fn oldest_sui_committee_summary(&self) -> IkaResult<Option<SuiCertifiedCheckpointSummary>> {
        match self.sui_committee_summaries.safe_iter().next() {
            Some(res) => Ok(Some(res.map_err(IkaError::from)?.1)),
            None => Ok(None),
        }
    }

    /// Install a Sui committee directly, bumping `sui_committee_head` to
    /// `committee.epoch`. Used only for committees with no backing
    /// end-of-epoch summary — the bootstrap genesis committee and
    /// unverified-fallback installs. Verified transitions instead persist the
    /// summary via [`Self::record_sui_committee_transition`] and derive the
    /// committee from it.
    pub fn install_sui_committee(&self, committee: &SuiCommittee) -> IkaResult {
        let epoch = committee.epoch;
        let mut wb = self.sui_committees.batch();
        wb.insert_batch(&self.sui_committees, [(epoch, committee.clone())])?;
        // Non-regressing head: a staggered lower install must not clobber a
        // higher persisted head (it would survive restart and force a network
        // re-walk that can ProofChainBroken if the boundary checkpoint was
        // pruned). `CommitteeStore` serializes installs so this read-max-write
        // is atomic.
        if self
            .sui_committee_head
            .get(&())?
            .is_none_or(|cur| epoch > cur)
        {
            wb.insert_batch(&self.sui_committee_head, [((), epoch)])?;
        }
        wb.write()?;
        Ok(())
    }

    /// Record a verified end-of-epoch summary for epoch `E` and advance
    /// `sui_committee_head` to `E+1` in the same batch. Recording the
    /// transition summary *is* the head advance: `committee[E+1]` is derived
    /// from this summary's `next_epoch_committee` on demand, so there is no
    /// separate per-epoch committee write.
    pub fn record_sui_committee_transition(
        &self,
        summary: &SuiCertifiedCheckpointSummary,
    ) -> IkaResult {
        let next_epoch = summary.epoch() + 1;
        let mut wb = self.sui_committee_summaries.batch();
        wb.insert_batch(
            &self.sui_committee_summaries,
            [(summary.epoch(), summary.clone())],
        )?;
        // Non-regressing head (see `install_sui_committee`).
        if self
            .sui_committee_head
            .get(&())?
            .is_none_or(|cur| next_epoch > cur)
        {
            wb.insert_batch(&self.sui_committee_head, [((), next_epoch)])?;
        }
        wb.write()?;
        Ok(())
    }

    pub fn get_sui_committee_summary(
        &self,
        sui_epoch: u64,
    ) -> IkaResult<Option<SuiCertifiedCheckpointSummary>> {
        Ok(self.sui_committee_summaries.get(&sui_epoch)?)
    }

    pub fn get_sui_end_of_epoch_seq(
        &self,
        sui_epoch: u64,
    ) -> IkaResult<Option<SuiCheckpointSequenceNumber>> {
        Ok(self.sui_end_of_epoch_seqs.get(&sui_epoch)?)
    }

    pub fn put_sui_end_of_epoch_seq(
        &self,
        sui_epoch: u64,
        seq: SuiCheckpointSequenceNumber,
    ) -> IkaResult {
        let mut wb = self.sui_end_of_epoch_seqs.batch();
        wb.insert_batch(&self.sui_end_of_epoch_seqs, [(sui_epoch, seq)])?;
        wb.write()?;
        Ok(())
    }

    pub fn get_sui_end_of_epoch_checkpoint(
        &self,
        seq: SuiCheckpointSequenceNumber,
    ) -> IkaResult<Option<CheckpointData>> {
        Ok(self.sui_end_of_epoch_checkpoints.get(&seq)?)
    }

    pub fn put_sui_end_of_epoch_checkpoint(
        &self,
        seq: SuiCheckpointSequenceNumber,
        checkpoint: &CheckpointData,
    ) -> IkaResult {
        let mut wb = self.sui_end_of_epoch_checkpoints.batch();
        wb.insert_batch(
            &self.sui_end_of_epoch_checkpoints,
            [(seq, checkpoint.clone())],
        )?;
        wb.write()?;
        Ok(())
    }

    /// Persist an end-of-epoch checkpoint AND its epoch→seq index entry in ONE
    /// batch, so a crash can't leave the `sui_end_of_epoch_seqs` mapping without
    /// its backing `CheckpointData` in `sui_end_of_epoch_checkpoints` (or vice
    /// versa). Both serve a mirrored peer's committee ratchet; a dangling half
    /// would just force a fullnode fallback, but keeping them atomic avoids that.
    pub fn put_sui_end_of_epoch(
        &self,
        sui_epoch: u64,
        seq: SuiCheckpointSequenceNumber,
        checkpoint: &CheckpointData,
    ) -> IkaResult {
        let mut wb = self.sui_end_of_epoch_seqs.batch();
        wb.insert_batch(&self.sui_end_of_epoch_seqs, [(sui_epoch, seq)])?;
        wb.insert_batch(
            &self.sui_end_of_epoch_checkpoints,
            [(seq, checkpoint.clone())],
        )?;
        wb.write()?;
        Ok(())
    }

    /// Drop retained end-of-epoch checkpoints below `floor` (the verified-cache
    /// retention floor) — a mirrored peer cannot bootstrap below it anyway.
    pub fn retain_sui_end_of_epoch_checkpoints(
        &self,
        floor: SuiCheckpointSequenceNumber,
    ) -> IkaResult {
        let stale: Vec<SuiCheckpointSequenceNumber> = self
            .sui_end_of_epoch_checkpoints
            .safe_iter()
            .filter_map(|item| item.ok().map(|(seq, _)| seq).filter(|seq| *seq < floor))
            .collect();
        if stale.is_empty() {
            return Ok(());
        }
        let mut wb = self.sui_end_of_epoch_checkpoints.batch();
        wb.delete_batch(&self.sui_end_of_epoch_checkpoints, stale)?;
        wb.write()?;
        Ok(())
    }

    pub fn get_sui_tx_checkpoint(
        &self,
        tx: &SuiTransactionDigest,
    ) -> IkaResult<Option<SuiCheckpointSequenceNumber>> {
        Ok(self.sui_tx_to_checkpoint.get(tx)?)
    }

    pub fn put_sui_tx_checkpoint(
        &self,
        tx: SuiTransactionDigest,
        seq: SuiCheckpointSequenceNumber,
    ) -> IkaResult {
        let mut wb = self.sui_tx_to_checkpoint.batch();
        wb.insert_batch(&self.sui_tx_to_checkpoint, [(tx, seq)])?;
        wb.write()?;
        Ok(())
    }

    pub fn get_sui_pusher_last_seq(&self) -> IkaResult<Option<SuiCheckpointSequenceNumber>> {
        Ok(self.sui_pusher_last_seq.get(&())?)
    }

    pub fn put_sui_pusher_last_seq(&self, seq: SuiCheckpointSequenceNumber) -> IkaResult {
        let mut wb = self.sui_pusher_last_seq.batch();
        wb.insert_batch(&self.sui_pusher_last_seq, [((), seq)])?;
        wb.write()?;
        Ok(())
    }

    /// All persisted verified-state-cache snapshots, for rehydrating
    /// `VerifiedStateCache` on boot. Returns the raw `TypedStoreError` (rather
    /// than the stringified `IkaError`) so the caller can distinguish a
    /// `SerializationError` — a stale on-disk format after a Sui upgrade, which
    /// is recoverable by wiping and rebuilding — from a transient RocksDB IO
    /// error, which is not.
    pub fn load_verified_object_cache(
        &self,
    ) -> Result<Vec<(ObjectID, VerifiedSnapshot)>, TypedStoreError> {
        let mut out = Vec::new();
        for item in self.verified_object_cache.safe_iter() {
            out.push(item?);
        }
        Ok(out)
    }

    pub fn get_verified_object_cache_head(&self) -> IkaResult<Option<SuiCheckpointSequenceNumber>> {
        Ok(self.verified_object_cache_head.get(&())?)
    }

    /// Write a checkpoint's folded snapshots and the new cache head through in
    /// one batch.
    pub fn write_verified_object_cache(
        &self,
        snapshots: Vec<(ObjectID, VerifiedSnapshot)>,
        head: SuiCheckpointSequenceNumber,
    ) -> IkaResult {
        let mut wb = self.verified_object_cache.batch();
        wb.insert_batch(&self.verified_object_cache, snapshots)?;
        wb.insert_batch(&self.verified_object_cache_head, [((), head)])?;
        wb.write()?;
        Ok(())
    }

    /// Drop the given keys from the persisted verified-state cache (retention
    /// pruning). The head is left untouched — pruning never lowers it.
    pub fn delete_verified_object_cache_keys(&self, ids: &[ObjectID]) -> IkaResult {
        let mut wb = self.verified_object_cache.batch();
        wb.delete_batch(&self.verified_object_cache, ids.iter())?;
        wb.write()?;
        Ok(())
    }

    /// Reset the direct-node verified-cache cursors so the node boots cold after
    /// the persisted cache fails to deserialize — a Sui version upgrade changed
    /// the on-disk BCS layout of `Object` / `CertifiedCheckpointSummary`. Only the
    /// singleton cache head and pusher cursor are deleted (reliable point
    /// deletes). The `verified_object_cache` value entries themselves are left in
    /// place: they no longer decode, so they're simply not loaded (`open` returns
    /// empty) and the pusher re-folds from the node's own re-verified Sui access,
    /// overwriting live entries. A physical wipe of the arbitrary-`ObjectID`-keyed
    /// column isn't possible here — this typed_store build's range deletes are
    /// no-ops, and the keys can't be enumerated once the values stop decoding — so
    /// persistence is degraded (re-fold from the fullnode each boot) until the
    /// operator clears the OCS cache, but the node BOOTS, which is the point.
    /// Trust is unaffected: every re-folded object is re-verified.
    pub fn reset_direct_cache_for_format_recovery(&self) -> IkaResult {
        let mut batch = self.verified_object_cache_head.batch();
        batch.delete_batch(&self.verified_object_cache_head, std::iter::once(()))?;
        batch.delete_batch(&self.sui_pusher_last_seq, std::iter::once(()))?;
        batch.write()?;
        Ok(())
    }

    /// Wipe the Sui committee trust columns (committees, summaries, head) so the
    /// next bootstrap re-anchors from the operator-pinned trust anchor. Used only
    /// by the opt-in `auto_reanchor_on_format_change` recovery after a committee
    /// value fails to deserialize on boot. Sui epochs are small and sequential, so
    /// the committee columns are swept by point-deleting their known key space
    /// `0..=head` (this typed_store build's range deletes are no-ops); the
    /// singleton head is reset too. Reads only the head (a stable `u64`); never
    /// deserializes the stale committee values.
    pub fn wipe_sui_committee_state_for_format_recovery(&self) -> IkaResult {
        let head = self.sui_committee_head.get(&())?.unwrap_or(0);
        let mut batch = self.sui_committees.batch();
        batch.delete_batch(&self.sui_committees, 0..=head)?;
        batch.delete_batch(&self.sui_committee_summaries, 0..=head)?;
        batch.delete_batch(&self.sui_committee_head, std::iter::once(()))?;
        batch.write()?;
        Ok(())
    }

    /// Probe whether the persisted head Sui committee still deserializes. Returns
    /// `Ok(())` when there is no committee state, or when the head committee
    /// (stored directly, or derived from the prior epoch's end-of-epoch summary)
    /// decodes. Surfaces a `TypedStoreError::SerializationError` (distinct from a
    /// transient `RocksDBError`) when the on-disk format is stale after a Sui
    /// upgrade, so the caller can tell a format break from an IO error. Mirrors
    /// `CommitteeStore::resolve_committee`'s read path. (Release-build behavior:
    /// in debug, `DBMap::get`'s `debug_fatal!` panics first — an acceptable loud
    /// dev signal.)
    pub fn probe_head_committee_readable(&self) -> Result<(), TypedStoreError> {
        let Some(head) = self.sui_committee_head.get(&())? else {
            return Ok(());
        };
        if self.sui_committees.get(&head)?.is_some() {
            return Ok(());
        }
        if let Some(prev) = head.checked_sub(1) {
            self.sui_committee_summaries.get(&prev)?;
        }
        Ok(())
    }
}

/// Adapter so the Anemo `validator_metadata` server can read certs
/// directly out of perpetual storage without taking on a dep on
/// `ika-core` types beyond `ika-types`.
impl ika_network::mpc_artifacts::HandoffCertStorage for AuthorityPerpetualTables {
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
    async fn reconfiguration_digest_epoch_slice_returns_exactly_that_epoch() {
        let (_dir, tables) = open_tables();
        let first_key = ObjectID::from_single_byte(0x11);
        let second_key = ObjectID::from_single_byte(0x22);
        // Neighboring epochs on both sides must NOT leak into the slice —
        // this is what the range bounds (epoch-major be-fix-int key order)
        // are trusted for.
        for (epoch, key_id, digest) in [
            (4u64, first_key, [0x04; 32]),
            (5, first_key, [0x51; 32]),
            (5, second_key, [0x52; 32]),
            (6, first_key, [0x06; 32]),
        ] {
            tables
                .insert_network_reconfiguration_output_digest_for_epoch(epoch, key_id, digest)
                .unwrap();
        }
        let slice = tables
            .get_network_reconfiguration_output_digests_for_epoch(5)
            .unwrap();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice.get(&first_key), Some(&[0x51; 32]));
        assert_eq!(slice.get(&second_key), Some(&[0x52; 32]));
        assert!(
            tables
                .get_network_reconfiguration_output_digests_for_epoch(7)
                .unwrap()
                .is_empty()
        );
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

    #[tokio::test]
    async fn insert_mpc_artifact_blob_accepts_matching_digest() {
        let (_dir, tables) = open_tables();
        let bytes = b"hello world".to_vec();
        let digest = mpc_data_blob_hash(&bytes);
        tables
            .insert_mpc_artifact_blob(digest, &bytes)
            .expect("insert with correct digest must succeed");
        let loaded = tables.get_mpc_artifact_blob(&digest).unwrap().unwrap();
        assert_eq!(loaded, bytes);
    }

    #[tokio::test]
    async fn insert_mpc_artifact_blob_rejects_mismatched_digest() {
        let (_dir, tables) = open_tables();
        let bytes = b"hello world".to_vec();
        let wrong_digest = [0xFFu8; 32];
        let err = tables
            .insert_mpc_artifact_blob(wrong_digest, &bytes)
            .expect_err("wrong digest must be rejected at the boundary");
        let msg = format!("{err}");
        assert!(
            msg.contains("digest mismatch"),
            "expected digest-mismatch error, got: {msg}"
        );
        // Verify nothing was written.
        assert!(
            tables
                .get_mpc_artifact_blob(&wrong_digest)
                .unwrap()
                .is_none(),
            "rejected insert must not write the blob"
        );
    }

    // -- OCS stale-format recovery (the N1 boot-halt fix) ---------------------

    #[tokio::test]
    async fn reset_direct_cache_for_format_recovery_resets_the_cursors() {
        let (_dir, tables) = open_tables();
        tables.put_sui_pusher_last_seq(4242).unwrap();
        assert_eq!(tables.get_sui_pusher_last_seq().unwrap(), Some(4242));

        tables.reset_direct_cache_for_format_recovery().unwrap();

        assert_eq!(
            tables.get_sui_pusher_last_seq().unwrap(),
            None,
            "the pusher cursor is reset so the cold cache re-folds from the start"
        );
        assert!(
            tables.get_verified_object_cache_head().unwrap().is_none(),
            "the cache head is reset so the staleness tripwire isn't seeded stale"
        );
    }

    #[tokio::test]
    async fn wipe_sui_committee_state_empties_the_head_and_committees() {
        let (_dir, tables) = open_tables();
        let (committee, _keys) = SuiCommittee::new_simple_test_committee();
        let epoch = committee.epoch;
        tables.install_sui_committee(&committee).unwrap();
        assert_eq!(tables.highest_sui_committee_epoch().unwrap(), Some(epoch));
        assert!(tables.get_sui_committee(epoch).unwrap().is_some());

        tables
            .wipe_sui_committee_state_for_format_recovery()
            .unwrap();

        // With the committee state gone, `highest_sui_committee_epoch()` is None,
        // so the next bootstrap re-anchors from the configured trust anchor.
        assert_eq!(tables.highest_sui_committee_epoch().unwrap(), None);
        assert!(tables.get_sui_committee(epoch).unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_head_committee_readable_ok_on_empty_and_on_valid_state() {
        let (_dir, tables) = open_tables();
        // No committee state yet → nothing to read → Ok.
        tables
            .probe_head_committee_readable()
            .expect("empty committee state is readable");
        // A directly-installed committee decodes → Ok. (A SerializationError can
        // only arise from a genuinely stale on-disk format, which can't be
        // injected here without raw-byte access — that end-to-end recovery path
        // is exercised by the release-mode setup/cache recovery tests.)
        let (committee, _keys) = SuiCommittee::new_simple_test_committee();
        tables.install_sui_committee(&committee).unwrap();
        tables
            .probe_head_committee_readable()
            .expect("valid committee state is readable");
    }
}
