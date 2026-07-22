// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Sui committee ratchet.
//!
//! `OcsVerifyingClient` now carries just the ratchet (committee chain
//! advance + pruning fallback) plus references to the raw transport and
//! the [`CommitteeStore`]. End-to-end verified reads moved to
//! [`crate::sui_connector::verified_reader::OcsVerifiedReader`], which
//! is built on top of an
//! [`ika_network::proof_provider::ProofProvider`].
//!
//! Requires the upstream Sui chain to have
//! `include_checkpoint_artifacts_digest_in_summary` enabled (Sui
//! protocol v122+). Testnet and devnet have it on; mainnet is still on
//! v121 as of 2026-05.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use ika_sui_client::archive::CheckpointArchive;
use ika_sui_client::transport::{SuiTransport, TransportError};

use crate::sui_connector::committee_store::{
    CommitteeStore, CommitteeTransition, CommitteeTransitionError,
};
use crate::sui_connector::ocs_metrics::OcsMetrics;

#[derive(thiserror::Error, Debug)]
pub enum OcsError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("missing Sui committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("checkpoint {0} signature verification failed: {1}")]
    BadCheckpointSig(CheckpointSequenceNumber, String),
    #[error("checkpoint {0} is not end-of-epoch")]
    NotEndOfEpoch(CheckpointSequenceNumber),
    #[error(
        "proof chain broken at epoch {epoch}: the epoch record or its end-of-epoch checkpoint is \
         pruned upstream (and absent from any configured checkpoint archive) so the next \
         committee cannot be BLS-verified from the persisted anchor. Remediation: boot once \
         against a full-retention Sui RPC so the persisted committee anchor catches up, \
         configure a `sui_checkpoint_archive` that retains this epoch's end-of-epoch \
         checkpoint, or set allow_unverified_committee_fallback to accept degraded trust"
    )]
    ProofChainBroken { epoch: u64 },
    #[error(
        "unverified committee fallback returned a committee for epoch {returned} when epoch \
         {requested} was requested; refusing to install it"
    )]
    FallbackEpochMismatch { requested: u64, returned: u64 },
    #[error(
        "the BLS-verified end-of-epoch checkpoint committed to a committee for epoch {returned} \
         when epoch {requested} was expected; refusing to install it"
    )]
    RatchetEpochMismatch { requested: u64, returned: u64 },
    #[error("ika error: {0}")]
    Ika(String),
}

impl From<ika_types::error::IkaError> for OcsError {
    fn from(e: ika_types::error::IkaError) -> Self {
        Self::Ika(e.to_string())
    }
}

impl OcsError {
    /// Whether retrying the same operation could plausibly succeed *without
    /// operator intervention*. Only transport failures qualify: the relay or a
    /// peer may recover, or an as-yet-unindexed checkpoint may appear on a
    /// later attempt. Every other variant is a determinate condition that a
    /// retry cannot heal — a pruned/broken proof chain (`ProofChainBroken`), a
    /// checkpoint that fails BLS verification (`BadCheckpointSig`) or isn't
    /// end-of-epoch (`NotEndOfEpoch`), a committee installed at the wrong epoch
    /// (`FallbackEpochMismatch`/`RatchetEpochMismatch`), or a missing local committee
    /// (`MissingCommittee`/`Ika`) — and needs the operator to act (typically
    /// re-anchor). A caller that loops on the ratchet (the peer-only boot
    /// ratchet) MUST stop and surface a fatal error on a non-retryable result
    /// rather than spin forever against an unhealable condition.
    pub fn is_retryable(&self) -> bool {
        matches!(self, OcsError::Transport(_))
    }

    /// Bounded label for `OcsMetrics::ratchet_failures_total`.
    pub fn metric_reason(&self) -> &'static str {
        match self {
            OcsError::Transport(_) => "transport",
            OcsError::MissingCommittee(_) => "missing_committee",
            OcsError::BadCheckpointSig(..) => "bad_checkpoint_sig",
            OcsError::NotEndOfEpoch(_) => "not_end_of_epoch",
            OcsError::ProofChainBroken { .. } => "proof_chain_broken",
            OcsError::FallbackEpochMismatch { .. } | OcsError::RatchetEpochMismatch { .. } => {
                "epoch_mismatch"
            }
            OcsError::Ika(_) => "store",
        }
    }
}

/// Map one committee-transition install onto the ratchet's error surface.
/// `Installed(E)` is the only success; a checkpoint served at an epoch
/// boundary that is not the next transition means the chain the source
/// presented is inconsistent with the verified head — a determinate
/// `NotEndOfEpoch` at `seq`.
fn installed_epoch(
    result: Result<CommitteeTransition, CommitteeTransitionError>,
    seq: CheckpointSequenceNumber,
) -> Result<u64, OcsError> {
    match result {
        Ok(CommitteeTransition::Installed(epoch)) => Ok(epoch),
        Ok(CommitteeTransition::NotNextTransition) => Err(OcsError::NotEndOfEpoch(seq)),
        Err(CommitteeTransitionError::MissingCommittee(epoch)) => {
            Err(OcsError::MissingCommittee(epoch))
        }
        Err(
            CommitteeTransitionError::BadSignature { error, .. }
            | CommitteeTransitionError::Extract { error, .. },
        ) => Err(OcsError::BadCheckpointSig(seq, error)),
        Err(CommitteeTransitionError::EpochMismatch { expected, got }) => {
            Err(OcsError::RatchetEpochMismatch {
                requested: expected,
                returned: got,
            })
        }
        Err(CommitteeTransitionError::Store(e)) => Err(e.into()),
    }
}

pub struct OcsVerifyingClient {
    transport: Arc<dyn SuiTransport>,
    committees: Arc<CommitteeStore>,
    metrics: Arc<OcsMetrics>,
    /// When the end-of-epoch checkpoint is pruned upstream, fall back to an
    /// *unverified* direct committee fetch instead of erroring. Default off —
    /// the un-verified fallback re-roots the proof chain on the endpoint's
    /// word (see `OcsError::ProofChainBroken`).
    allow_unverified_committee_fallback: bool,
    /// Verified fallback source for end-of-epoch checkpoints the upstream
    /// fullnode has pruned: fetch the end-of-epoch checkpoint from a Sui
    /// checkpoint archive (or configured mirror), BLS-verify it against
    /// `committee[head]`, and install — trust unchanged. Tried *before* the
    /// degraded unverified fallback. `None` until wired (see `with_archive`).
    archive: Option<Arc<dyn CheckpointArchive>>,
    /// Whether the one-time cold-bootstrap-from-archive walk has been attempted.
    /// It runs at the start of the first ratchet, advancing the committee chain
    /// genesis -> latest purely from the archive (BLS-verifying every summary
    /// against the running committee); later ratchets skip it and rely on the
    /// transport plus the per-seq archive fallback.
    backfill_attempted: AtomicBool,
    /// Coalesces concurrent ratchet calls to one: the periodic ratchet, the
    /// boot ratchet, and the reactive (`missing_committee`) push ratchet all
    /// share this. A caller that finds a ratchet already in flight returns
    /// `Ok` and lets the in-flight one advance the head (the push handler then
    /// re-`verify()`s against the possibly-advanced store).
    ratchet_lock: Mutex<()>,
}

impl OcsVerifyingClient {
    pub fn new(
        transport: Arc<dyn SuiTransport>,
        committees: Arc<CommitteeStore>,
        metrics: Arc<OcsMetrics>,
        allow_unverified_committee_fallback: bool,
    ) -> Self {
        Self {
            transport,
            committees,
            metrics,
            allow_unverified_committee_fallback,
            archive: None,
            backfill_attempted: AtomicBool::new(false),
            ratchet_lock: Mutex::new(()),
        }
    }

    /// Attach a verified end-of-epoch checkpoint archive used as a fallback when
    /// the upstream fullnode has pruned an end-of-epoch checkpoint. Everything
    /// fetched from it is BLS-verified before install, so the archive is an
    /// untrusted availability source — never a trust source.
    pub fn with_archive(mut self, archive: Option<Arc<dyn CheckpointArchive>>) -> Self {
        self.archive = archive;
        self
    }

    pub fn transport(&self) -> &Arc<dyn SuiTransport> {
        &self.transport
    }

    pub fn committees(&self) -> &Arc<CommitteeStore> {
        &self.committees
    }

    /// Cold-bootstrap the committee chain from the checkpoint `archive`: walk
    /// `head → latest` purely from the object store. For each step it reads
    /// epoch `head`'s end-of-epoch sequence number from the (untrusted)
    /// `epochs.json` enumeration, fetches that checkpoint, and BLS-verifies its
    /// summary against `committee[head]` before installing `committee[head+1]`.
    ///
    /// Because `head` starts at 0 (the genesis committee) and advances one
    /// verified epoch at a time, **every** committee is verified from genesis
    /// forward — the archive is never trusted. A forged, gapped, or reordered
    /// `epochs.json` is caught by `install_next_from_summary`'s per-summary
    /// signature check and its `next.epoch == head + 1` contiguity assertion
    /// (worst case the walk stalls; it can never install a forged committee).
    ///
    /// Resumable: the persisted head means a re-run skips the already-installed
    /// prefix. Past the end of the enumerated (completed) epochs it returns
    /// `Ok` — the live tail is the transport ratchet's / follower's job.
    async fn backfill_committee_chain_from_archive(
        &self,
        archive: &Arc<dyn CheckpointArchive>,
    ) -> Result<(), OcsError> {
        let seqs = archive
            .enumerate_end_of_epoch_seqs()
            .await
            .map_err(|e| OcsError::Ika(format!("archive enumerate epochs.json: {e}")))?;
        loop {
            let head = self.committees.head_epoch();
            let Some(&seq) = seqs.get(head as usize) else {
                return Ok(());
            };
            let (summary, _contents) = archive
                .fetch_checkpoint(seq)
                .await
                .map_err(|e| OcsError::Ika(format!("archive fetch checkpoint {seq}: {e}")))?;
            // `epochs.json[head]` not being epoch `head`'s end-of-epoch
            // checkpoint means the enumeration is inconsistent with the
            // verified chain (gapped/reordered) — `installed_epoch` surfaces
            // that as `NotEndOfEpoch`, so we cannot verify past this point.
            let epoch = installed_epoch(self.committees.install_next_from_summary(&summary), seq)?;
            info!(epoch, seq, "cold-bootstrapped Sui committee from archive");
        }
    }

    /// Walk forward from the current `head_epoch` of [`CommitteeStore`] to the
    /// upstream's current epoch, BLS-verifying each end-of-epoch checkpoint
    /// against the previous epoch's committee and installing the next one.
    ///
    /// Pruning behaviour: if `get_full_checkpoint(last_of_E)` returns
    /// `NotFound` because the end-of-epoch checkpoint was pruned upstream, the
    /// `E → E+1` transition can't be BLS-verified. By default this is a hard
    /// `ProofChainBroken` error (the operator must re-anchor); only with
    /// `allow_unverified_committee_fallback` does it fetch `committee[E+1]`
    /// directly and install it unverified (trust degraded to the endpoint).
    ///
    /// Coalesced via `ratchet_lock`: concurrent callers return `Ok` and let
    /// the in-flight ratchet advance the head.
    pub async fn ratchet_to_current_epoch(&self) -> Result<(), OcsError> {
        let _guard = match self.ratchet_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                debug!("ratchet already in flight; coalescing");
                return Ok(());
            }
        };
        // Health signal around the actual attempt (the coalesced early return
        // above must not clear a stall another caller is observing): stalled
        // is 1 while the last completed ratchet attempt failed, 0 once one
        // succeeds. This is what makes a wedged ratchet — e.g. a boot against
        // a source that serves no historical epochs — visible to alerting
        // instead of presenting only as absent downstream series.
        let result = self.ratchet_locked().await;
        match &result {
            Ok(()) => self.metrics.ratchet_stalled.set(0),
            Err(e) => {
                self.metrics.ratchet_stalled.set(1);
                self.metrics
                    .ratchet_failures_total
                    .with_label_values(&[e.metric_reason()])
                    .inc();
            }
        }
        result
    }

    /// The walk itself; the caller holds `ratchet_lock`.
    async fn ratchet_locked(&self) -> Result<(), OcsError> {
        // Cold-bootstrap once from the archive (if configured): walk the
        // committee chain genesis -> latest purely from the object store before
        // the transport walk below, BLS-verifying every summary from genesis
        // forward. Best-effort — failures (no archive, unreachable, pruned tail)
        // log and fall through to the transport ratchet. Runs only on the first
        // ratchet; later ratchets rely on the transport + per-seq archive
        // fallback for the live tail.
        if let Some(archive) = self.archive.clone()
            && !self.backfill_attempted.swap(true, Ordering::Relaxed)
            && let Err(e) = self.backfill_committee_chain_from_archive(&archive).await
        {
            warn!(
                error = %e,
                "archive cold-bootstrap incomplete; continuing with the transport ratchet"
            );
        }
        // `get_current_epoch` is a relay-claimed, unverified passthrough, but
        // it only sets the loop's *target* — it can't forge progress. Every
        // step below BLS-verifies the end-of-epoch checkpoint against
        // committee[head], derives committee[head+1] from that verified summary,
        // and asserts `next.epoch == head + 1`. So a malicious relay claiming a
        // far-future epoch can't walk the verified head faster than one real,
        // committee-signed epoch per step: at worst its checkpoint fetches fail
        // and the ratchet stalls (or takes the unverified fallback, gated by
        // `allow_unverified_committee_fallback`) — never a forged advance.
        let target = self.transport.get_current_epoch().await?;
        self.metrics.chain_latest_epoch.set(target as i64);
        loop {
            let head = self.committees.head_epoch();
            if head >= target {
                break;
            }
            // Both boundary reads can come back `NotFound` on a source that no
            // longer serves epoch `head`: the epoch *record* itself (a pruned
            // fullnode or sui-state-direct, which serves current state only —
            // "Epoch N not found"), or the end-of-epoch *checkpoint*. Either
            // way the transition can't be verified from this source, which is
            // determinate for it — so both route to the same fallback chain
            // instead of surfacing as a retryable transport error the callers
            // would spin on forever.
            let last_seq = match self.transport.last_checkpoint_of_epoch(head).await {
                Ok(seq) => seq,
                Err(TransportError::NotFound(reason)) => {
                    self.pruned_boundary_fallback(head, target, None, &reason)
                        .await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let data = match self.transport.get_full_checkpoint(last_seq).await {
                Ok(d) => d,
                Err(TransportError::NotFound(reason)) => {
                    self.pruned_boundary_fallback(head, target, Some(last_seq), &reason)
                        .await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // The single audited verify + derive + assert + persist step,
            // shared with the pusher's eager capture
            // (`CommitteeStore::install_next_from_checkpoint`). `data` is the
            // end-of-epoch checkpoint of `head`, so this installs
            // `committee[head + 1]`.
            let epoch = installed_epoch(
                self.committees.install_next_from_checkpoint(&data),
                last_seq,
            )?;
            info!(epoch, last_seq, "ratcheted Sui committee");
        }
        Ok(())
    }

    /// Fallback chain for a pruned epoch boundary at `head` — the source
    /// returned `NotFound` for the epoch record (`last_seq` is `None`) or for
    /// its end-of-epoch checkpoint. On success `committee[head + 1]` is
    /// installed and the caller continues the walk.
    ///
    /// Verified archive first: fetch + BLS-verify against `committee[head]` +
    /// install — identical trust to the primary path. The archive is untrusted:
    /// a forged/corrupt summary fails verification (hard error, fail-closed),
    /// while a mere fetch miss falls through. When the epoch record itself was
    /// pruned, the end-of-epoch sequence is resolved from the archive's own
    /// `epochs.json` enumeration — an untrusted hint that can stall the walk
    /// but never forge an install (the per-summary verification decides).
    ///
    /// Then the degraded unverified direct fetch, only when
    /// `allow_unverified_committee_fallback` is set; otherwise the terminal,
    /// non-retryable `ProofChainBroken` whose message names the remediation.
    async fn pruned_boundary_fallback(
        &self,
        head: u64,
        target: u64,
        last_seq: Option<CheckpointSequenceNumber>,
        reason: &str,
    ) -> Result<(), OcsError> {
        if let Some(archive) = &self.archive {
            let seq = match last_seq {
                Some(seq) => Some(seq),
                None => match archive.enumerate_end_of_epoch_seqs().await {
                    Ok(seqs) => seqs.get(head as usize).copied(),
                    Err(e) => {
                        warn!(
                            head,
                            target,
                            error = %e,
                            "ratchet: archive epochs.json enumeration failed while resolving a \
                             pruned epoch record; trying next fallback"
                        );
                        None
                    }
                },
            };
            match seq {
                Some(seq) => match archive.fetch_checkpoint(seq).await {
                    Ok((summary, _contents)) => {
                        let epoch = installed_epoch(
                            self.committees.install_next_from_summary(&summary),
                            seq,
                        )?;
                        info!(
                            epoch,
                            seq, "ratcheted Sui committee (verified archive fallback)"
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(
                            head,
                            seq,
                            target,
                            error = %e,
                            "ratchet: epoch boundary pruned upstream and the verified archive \
                             fallback also failed; trying next fallback"
                        );
                    }
                },
                None => {
                    warn!(
                        head,
                        target,
                        "ratchet: epoch boundary pruned upstream and the archive does not \
                         enumerate this epoch; trying next fallback"
                    );
                }
            }
        }
        if !self.allow_unverified_committee_fallback {
            error!(
                head,
                ?last_seq,
                target,
                reason,
                "ratchet: epoch boundary pruned upstream and the unverified fallback is \
                 disabled — proof chain broken; boot once against a full-retention Sui RPC (or \
                 configure a `sui_checkpoint_archive`) so the persisted committee anchor \
                 catches up"
            );
            return Err(OcsError::ProofChainBroken { epoch: head });
        }
        error!(
            security_critical = true,
            head,
            ?last_seq,
            target,
            reason,
            "ratchet: epoch boundary pruned upstream; installing committee[E+1] via UNVERIFIED \
             direct fetch — trust degraded to the endpoint's word"
        );
        self.metrics.unverified_committee_fallback_total.inc();
        let next = self.transport.get_committee(Some(head + 1)).await?;
        // Even in unverified mode the endpoint doesn't get to pick the epoch:
        // `install_next` keys the store by the committee's own epoch field, so
        // an endpoint returning a mislabeled committee could jump the ratchet
        // head past epochs that were never installed.
        if next.epoch != head + 1 {
            return Err(OcsError::FallbackEpochMismatch {
                requested: head + 1,
                returned: next.epoch,
            });
        }
        self.committees.install_next(next, None)?;
        info!(
            epoch = head + 1,
            "ratcheted Sui committee (UNVERIFIED direct-fetch fallback)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use ika_sui_client::transport::{DynamicFieldPage, ExecutedTransaction};
    use sui_light_client::proof::committee::extract_new_committee_info;
    use sui_types::base_types::{ObjectID, SequenceNumber, TransactionDigest};
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::digests::CheckpointDigest;
    use sui_types::full_checkpoint_content::CheckpointData;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointContents, CheckpointSummary, EndOfEpochData,
    };
    use sui_types::object::Object;

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::CommitteeBootstrap;

    /// An end-of-epoch `CheckpointData` for `committee.epoch()` at `seq`,
    /// signed by `committee`/`keys` and committing to the SAME members at
    /// epoch `E+1`. Mirrors the helper in `push_worker`'s tests: the signing
    /// committee determines the epoch, so chaining one per epoch lets the
    /// ratchet walk forward verifying each transition.
    fn end_of_epoch_checkpoint(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CheckpointData {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data: Some(EndOfEpochData {
                next_epoch_committee: committee.voting_rights.clone(),
                next_epoch_protocol_version: ProtocolVersion::MIN,
                epoch_commitments: vec![],
            }),
            version_specific_data: Vec::new(),
        };
        let checkpoint_summary =
            CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee);
        CheckpointData {
            checkpoint_summary,
            checkpoint_contents: contents,
            transactions: vec![],
        }
    }

    /// Re-key the same members to `epoch` so the same keypairs sign the
    /// end-of-epoch summary of every epoch (`new_from_keypairs_for_testing`
    /// signs as `committee.epoch()`). Derived via `extract_new_committee_info`
    /// off a self-signed transition, so the voting weights stay normalized.
    fn committee_at_epoch(base: &Committee, keys: &[AuthorityKeyPair], epoch: u64) -> Committee {
        if epoch == base.epoch() {
            return base.clone();
        }
        let mut current = base.clone();
        // Walk one epoch at a time; each derived committee keeps the same
        // members, only the epoch number advances.
        for _ in base.epoch()..epoch {
            let eoe = end_of_epoch_checkpoint(&current, keys, 0);
            current = extract_new_committee_info(&eoe.checkpoint_summary).unwrap();
        }
        current
    }

    /// Outcome the ratchet's transport asks of the mock for a given
    /// `get_full_checkpoint(seq)`. `CheckpointData` is boxed so the variants
    /// stay similarly sized.
    enum FullCheckpointOutcome {
        Data(Box<CheckpointData>),
        NotFound,
        Network,
    }

    /// Configurable transport for the committee ratchet. Records every
    /// `get_committee` call so a test can assert the fallback was (not) taken.
    struct RatchetMock {
        target_epoch: u64,
        /// Epochs below this floor have no record on this source:
        /// `last_checkpoint_of_epoch` answers NotFound ("Epoch N not found")
        /// for them — the sui-state-direct / pruned-fullnode shape. `None`
        /// serves every epoch record.
        epoch_floor: Option<u64>,
        /// `last_checkpoint_of_epoch(E)` -> seq. Defaults to `E` when absent.
        full_checkpoints: HashMap<CheckpointSequenceNumber, FullCheckpointOutcome>,
        /// Committee handed back by the unverified `get_committee(Some(_))`
        /// fallback, keyed by requested epoch.
        committees: HashMap<u64, Committee>,
        get_committee_calls: StdMutex<Vec<Option<u64>>>,
    }

    impl RatchetMock {
        fn new(target_epoch: u64) -> Self {
            Self {
                target_epoch,
                epoch_floor: None,
                full_checkpoints: HashMap::new(),
                committees: HashMap::new(),
                get_committee_calls: StdMutex::new(Vec::new()),
            }
        }
        fn get_committee_call_count(&self) -> usize {
            self.get_committee_calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl SuiTransport for RatchetMock {
        async fn get_current_epoch(&self) -> Result<u64, TransportError> {
            Ok(self.target_epoch)
        }
        async fn last_checkpoint_of_epoch(
            &self,
            epoch: u64,
        ) -> Result<CheckpointSequenceNumber, TransportError> {
            if self.epoch_floor.is_some_and(|floor| epoch < floor) {
                return Err(TransportError::NotFound(format!("Epoch {epoch} not found")));
            }
            // Identity mapping epoch->seq keeps the test's checkpoint map simple.
            Ok(epoch)
        }
        async fn get_full_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<CheckpointData, TransportError> {
            match self.full_checkpoints.get(&seq) {
                Some(FullCheckpointOutcome::Data(d)) => Ok((**d).clone()),
                Some(FullCheckpointOutcome::NotFound) => {
                    Err(TransportError::NotFound(format!("checkpoint {seq} pruned")))
                }
                Some(FullCheckpointOutcome::Network) => {
                    Err(TransportError::Network(format!("relay down at {seq}")))
                }
                None => Err(TransportError::NotFound(format!("no checkpoint {seq}"))),
            }
        }
        async fn get_committee(&self, epoch: Option<u64>) -> Result<Committee, TransportError> {
            self.get_committee_calls.lock().unwrap().push(epoch);
            let requested = epoch.expect("ratchet fallback always pins an epoch");
            self.committees
                .get(&requested)
                .cloned()
                .ok_or_else(|| TransportError::NotFound(format!("no committee {requested}")))
        }

        async fn get_chain_identifier(&self) -> Result<String, TransportError> {
            unimplemented!()
        }
        async fn get_latest_checkpoint(
            &self,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_checkpoint_summary_by_digest(
            &self,
            _digest: CheckpointDigest,
        ) -> Result<CertifiedCheckpointSummary, TransportError> {
            unimplemented!()
        }
        async fn get_object(&self, _id: ObjectID) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn get_object_with_version(
            &self,
            _id: ObjectID,
            _version: SequenceNumber,
        ) -> Result<Object, TransportError> {
            unimplemented!()
        }
        async fn batch_get_objects(
            &self,
            _ids: &[ObjectID],
        ) -> Result<Vec<Object>, TransportError> {
            unimplemented!()
        }
        async fn list_dynamic_fields(
            &self,
            _parent: ObjectID,
            _page_size: Option<u32>,
            _page_token: Option<Vec<u8>>,
        ) -> Result<DynamicFieldPage, TransportError> {
            unimplemented!()
        }
        async fn get_transaction(
            &self,
            _tx: TransactionDigest,
        ) -> Result<ExecutedTransaction, TransportError> {
            unimplemented!()
        }
    }

    /// Open a committee store bootstrapped from `committee[0]` over fresh
    /// perpetual tables. The `TempDir` is returned so it outlives the store.
    fn store_with_genesis(committee: Committee) -> (tempfile::TempDir, Arc<CommitteeStore>) {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store = Arc::new(
            CommitteeStore::open(
                perpetual,
                Some(CommitteeBootstrap::UnsafeGenesis(committee)),
            )
            .unwrap(),
        );
        (dir, store)
    }

    /// A mock checkpoint archive backed by in-memory signed summaries, so the
    /// cold-bootstrap loop is tested without a real object store.
    struct MockArchive {
        seqs: Vec<CheckpointSequenceNumber>,
        checkpoints:
            HashMap<CheckpointSequenceNumber, (CertifiedCheckpointSummary, CheckpointContents)>,
        /// Fail this many `enumerate_end_of_epoch_seqs` calls before serving.
        /// Lets a test defeat the one-shot cold-bootstrap backfill (which
        /// enumerates first) so the ratchet's per-boundary archive fallback is
        /// what gets exercised.
        fail_enumerations: StdMutex<u32>,
    }

    #[async_trait]
    impl CheckpointArchive for MockArchive {
        async fn enumerate_end_of_epoch_seqs(
            &self,
        ) -> Result<Vec<CheckpointSequenceNumber>, ika_sui_client::archive::ArchiveError> {
            let mut remaining = self.fail_enumerations.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err(ika_sui_client::archive::ArchiveError::Enumerate {
                    url: "mock".into(),
                    source: anyhow::anyhow!("enumeration unavailable"),
                });
            }
            Ok(self.seqs.clone())
        }
        async fn fetch_checkpoint(
            &self,
            seq: CheckpointSequenceNumber,
        ) -> Result<
            (CertifiedCheckpointSummary, CheckpointContents),
            ika_sui_client::archive::ArchiveError,
        > {
            self.checkpoints.get(&seq).cloned().ok_or_else(|| {
                ika_sui_client::archive::ArchiveError::Fetch {
                    url: "mock".into(),
                    seq,
                    source: anyhow::anyhow!("seq {seq} not in mock archive"),
                }
            })
        }
    }

    /// Build a mock archive holding the end-of-epoch checkpoint of epochs
    /// `0..epochs`, each signed by `committee[e]` and committing to
    /// `committee[e+1]`. `seqs[e]` (the `epochs.json` index) is epoch `e`'s EOP.
    fn archive_for_chain(base: &Committee, keys: &[AuthorityKeyPair], epochs: u64) -> MockArchive {
        let mut seqs = Vec::new();
        let mut checkpoints = HashMap::new();
        for e in 0..epochs {
            let seq = 1_000 + e;
            let committee_e = committee_at_epoch(base, keys, e);
            let cp = end_of_epoch_checkpoint(&committee_e, keys, seq);
            seqs.push(seq);
            checkpoints.insert(seq, (cp.checkpoint_summary, cp.checkpoint_contents));
        }
        MockArchive {
            seqs,
            checkpoints,
            fail_enumerations: StdMutex::new(0),
        }
    }

    fn client_with_store(store: Arc<CommitteeStore>) -> OcsVerifyingClient {
        OcsVerifyingClient::new(
            Arc::new(RatchetMock::new(0)),
            store,
            OcsMetrics::new_for_testing(),
            false,
        )
    }

    /// Cold-bootstrap walks the whole chain from the archive, BLS-verifying each
    /// summary against the running committee from genesis (head 0) forward; the
    /// head advances to the last enumerated epoch.
    #[tokio::test]
    async fn archive_backfill_installs_the_full_chain() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        let archive: Arc<dyn CheckpointArchive> = Arc::new(archive_for_chain(&committee, &keys, 5));
        let client = client_with_store(store.clone());
        client
            .backfill_committee_chain_from_archive(&archive)
            .await
            .unwrap();
        // EOPs for epochs 0..5 -> committee[5] installed; past the list is Ok.
        assert_eq!(store.head_epoch(), 5);
    }

    /// An UNTRUSTED `epochs.json` that omits an epoch's end-of-epoch checkpoint
    /// is caught by the `+1` contiguity check: the walk stops with an error
    /// rather than installing a shifted/forged committee, and the head holds at
    /// the gap. (verify everything — the enumeration is only a hint.)
    #[tokio::test]
    async fn archive_backfill_rejects_a_gapped_enumeration() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        let mut mock = archive_for_chain(&committee, &keys, 5);
        // Drop epoch 2's EOP so `seqs[2]` now points at epoch 3's EOP.
        let dropped = mock.seqs.remove(2);
        mock.checkpoints.remove(&dropped);
        let archive: Arc<dyn CheckpointArchive> = Arc::new(mock);
        let client = client_with_store(store.clone());
        let err = client
            .backfill_committee_chain_from_archive(&archive)
            .await
            .unwrap_err();
        // 0,1 install; at head=2 `seqs[2]` is epoch 3's summary -> NotNextTransition.
        assert!(matches!(err, OcsError::NotEndOfEpoch(_)), "got {err:?}");
        assert_eq!(store.head_epoch(), 2, "head stops at the gap");
    }

    /// With the unverified fallback enabled, a pruned end-of-epoch checkpoint
    /// triggers a direct `get_committee` fetch -- but if the endpoint returns a
    /// committee for the wrong epoch the ratchet refuses to install it
    /// (`FallbackEpochMismatch`), the head does NOT advance, and the
    /// security-critical fallback metric was incremented BEFORE the guard fired
    /// (so operators still see the attempted degradation).
    #[tokio::test]
    async fn unverified_fallback_rejects_epoch_mismatch() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        assert_eq!(store.head_epoch(), 0);

        // head=0, target=1: the ratchet reaches for last_checkpoint_of_epoch(0)
        // (seq 0), which the endpoint reports as pruned -> unverified fallback.
        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::NotFound);
        // The endpoint returns a committee labelled epoch 2 when epoch 1 was
        // requested -- a mislabel that would jump the head past epoch 1.
        let wrong = committee_at_epoch(&committee, &_keys, 2);
        mock.committees.insert(1, wrong);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), true);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(
                err,
                OcsError::FallbackEpochMismatch {
                    requested: 1,
                    returned: 2
                }
            ),
            "expected FallbackEpochMismatch, got {err:?}"
        );
        assert_eq!(store.head_epoch(), 0, "head must not advance on mismatch");
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            1,
            "the fallback metric increments before the epoch guard fires"
        );
        assert_eq!(
            mock.get_committee_call_count(),
            1,
            "the fallback fetched the committee exactly once"
        );
    }

    /// The unverified fallback keys STRICTLY on `NotFound`. A `Network` error
    /// from `get_full_checkpoint` is retryable, so the ratchet surfaces it as
    /// `Transport(..)` WITHOUT taking the degraded direct-fetch path:
    /// `get_committee` is never called and the fallback metric stays 0.
    #[tokio::test]
    async fn ratchet_does_not_fall_back_on_network_error() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee);
        assert_eq!(store.head_epoch(), 0);

        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::Network);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), true);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::Transport(TransportError::Network(_))),
            "a transient network error must stay retryable, got {err:?}"
        );
        assert!(err.is_retryable());
        assert_eq!(store.head_epoch(), 0, "head must not advance");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "fallback must NOT be taken on a network error"
        );
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            0,
            "the fallback metric stays 0 on a network error"
        );
    }

    /// finding-17 core, trusted-only posture: with the unverified fallback
    /// DISABLED (the default), a pruned end-of-epoch checkpoint
    /// (`get_full_checkpoint` -> NotFound) makes the ratchet fail with a TERMINAL
    /// `ProofChainBroken` rather than silently fetch `committee[E+1]` from the
    /// untrusted endpoint. The head does not advance, `get_committee` is never
    /// called, and the error is non-retryable (the operator must re-anchor). This
    /// is the in-process proxy for the cluster "peer-only bootstrap aborts on a
    /// pruned end-of-epoch" scenario — the real-pruning version is not expressible
    /// in the in-process Sui test cluster.
    #[tokio::test]
    async fn ratchet_pruned_end_of_epoch_is_fatal_without_fallback() {
        let (committee, _keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee);
        assert_eq!(store.head_epoch(), 0);

        // head=0, target=1: the end-of-epoch checkpoint of epoch 0 (seq 0) is
        // pruned upstream.
        let mut mock = RatchetMock::new(1);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::NotFound);
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        // allow_unverified_committee_fallback = false (the default, trust-preserving).
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::ProofChainBroken { epoch: 0 }),
            "a pruned end-of-epoch with fallback disabled must be a terminal \
             ProofChainBroken, got {err:?}"
        );
        assert!(
            !err.is_retryable(),
            "ProofChainBroken is fatal (operator must re-anchor), not retryable"
        );
        assert_eq!(store.head_epoch(), 0, "head must not advance");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "the trusted-only path must never fetch a committee from the endpoint"
        );
        assert_eq!(
            metrics.unverified_committee_fallback_total.get(),
            0,
            "no fallback was attempted"
        );
    }

    /// Driving the ratchet from head E to target E+2 over correctly-chained,
    /// committee-signed end-of-epoch checkpoints installs exactly E+1 then E+2
    /// -- head advances by exactly one per verified step, never skipping. A
    /// summary whose derived next committee is for the wrong epoch surfaces
    /// `RatchetEpochMismatch`.
    #[tokio::test]
    async fn ratchet_advances_epoch_by_one_per_step() {
        let (committee0, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee0.clone());
        assert_eq!(store.head_epoch(), 0);

        // Chain: committee[E] signs the end-of-epoch checkpoint of epoch E,
        // committing to committee[E+1]. seq == epoch under the mock's identity
        // last_checkpoint_of_epoch mapping.
        let committee1 = committee_at_epoch(&committee0, &keys, 1);
        let eoe0 = end_of_epoch_checkpoint(&committee0, &keys, 0);
        let eoe1 = end_of_epoch_checkpoint(&committee1, &keys, 1);

        let mut mock = RatchetMock::new(2);
        mock.full_checkpoints
            .insert(0, FullCheckpointOutcome::Data(Box::new(eoe0)));
        mock.full_checkpoints
            .insert(1, FullCheckpointOutcome::Data(Box::new(eoe1)));
        let mock = Arc::new(mock);
        let metrics = OcsMetrics::new_for_testing();
        // Fallback OFF: every step must verify, no degraded path.
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(store.head_epoch(), 2, "advanced exactly E+1 then E+2");
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "verified path never touches the unverified fallback"
        );
        assert_eq!(metrics.unverified_committee_fallback_total.get(), 0);

        // Never skipping: a checkpoint served at last_checkpoint_of_epoch(head)
        // that is NOT the end-of-epoch transition of `head` is rejected, head
        // does not move. Here the relay serves the (validly committee-signed)
        // end-of-epoch checkpoint of epoch 3 when the head is 2 -- its epoch
        // doesn't match the head, so install treats it as not-the-next
        // transition and the ratchet surfaces the determinate NotEndOfEpoch.
        //
        // Note `RatchetEpochMismatch` (the EpochMismatch belt-and-suspenders in
        // the store's install step) is unreachable from the ratchet with any
        // committee-signed summary: the install head-guard fires first when
        // `summary.epoch() != head`, and when it does match, the derived next
        // epoch is always `head + 1` (Sui's `extract_new_committee_info` sets it
        // to `summary.epoch() + 1`). So the reachable "wrong epoch served at the
        // head boundary" outcome is NotEndOfEpoch, asserted here.
        let committee3 = committee_at_epoch(&committee0, &keys, 3);
        let wrong_epoch_eoe = end_of_epoch_checkpoint(&committee3, &keys, 2);
        let mut mock2 = RatchetMock::new(3);
        mock2
            .full_checkpoints
            .insert(2, FullCheckpointOutcome::Data(Box::new(wrong_epoch_eoe)));
        let mock2 = Arc::new(mock2);
        let client2 = OcsVerifyingClient::new(mock2, store.clone(), metrics, false);
        let err = client2.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::NotEndOfEpoch(2)),
            "a non-transition checkpoint at the head boundary must surface \
             NotEndOfEpoch, got {err:?}"
        );
        assert!(!err.is_retryable(), "the mismatch is a determinate failure");
        assert_eq!(store.head_epoch(), 2, "head stays at 2 on the mismatch");
    }

    // The peer-only boot ratchet loops on this classification: only transport
    // failures are retried, every determinate (proof/committee) failure must be
    // fatal so boot fails fast instead of spinning forever.
    #[test]
    fn only_transport_errors_are_retryable() {
        // Transport failures may clear on a later attempt (relay/peer recovers,
        // checkpoint gets indexed) — retryable.
        assert!(OcsError::Transport(TransportError::Network("relay down".into())).is_retryable());
        assert!(
            OcsError::Transport(TransportError::NotFound("not indexed yet".into())).is_retryable()
        );

        // Determinate conditions a retry cannot heal — must be fatal.
        assert!(!OcsError::ProofChainBroken { epoch: 7 }.is_retryable());
        assert!(
            !OcsError::FallbackEpochMismatch {
                requested: 8,
                returned: 9,
            }
            .is_retryable()
        );
        assert!(!OcsError::NotEndOfEpoch(42).is_retryable());
        assert!(!OcsError::BadCheckpointSig(42, "bad bls".into()).is_retryable());
        assert!(!OcsError::MissingCommittee(3).is_retryable());
        assert!(!OcsError::Ika("store write failed".into()).is_retryable());
    }

    /// A transport whose current epoch is `target` and which serves epoch
    /// records + end-of-epoch checkpoints only for epochs in `floor..target`:
    /// `floor = 0` is a full-retention source, `floor = target` a history-less
    /// (sui-state-direct-shaped) one that answers "Epoch N not found" for every
    /// completed epoch.
    fn mock_with_history(
        base: &Committee,
        keys: &[AuthorityKeyPair],
        target: u64,
        floor: u64,
    ) -> RatchetMock {
        let mut mock = RatchetMock::new(target);
        mock.epoch_floor = (floor > 0).then_some(floor);
        for epoch in floor..target {
            let committee_e = committee_at_epoch(base, keys, epoch);
            mock.full_checkpoints.insert(
                epoch,
                FullCheckpointOutcome::Data(Box::new(end_of_epoch_checkpoint(
                    &committee_e,
                    keys,
                    epoch,
                ))),
            );
        }
        mock
    }

    /// First boot: bootstrap from genesis and ratchet to `head` over a
    /// full-retention source, persisting the anchor into the perpetual tables
    /// at `path`. Everything is dropped before returning — the "process" exits.
    async fn anchor_db_at(
        path: &std::path::Path,
        base: &Committee,
        keys: &[AuthorityKeyPair],
        head: u64,
    ) {
        let tables = Arc::new(AuthorityPerpetualTables::open(path, None));
        let store = Arc::new(
            CommitteeStore::open(
                tables,
                Some(CommitteeBootstrap::UnsafeGenesis(base.clone())),
            )
            .unwrap(),
        );
        let mock = Arc::new(mock_with_history(base, keys, head, 0));
        let client =
            OcsVerifyingClient::new(mock, store.clone(), OcsMetrics::new_for_testing(), false);
        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(store.head_epoch(), head, "first boot must reach the anchor");
    }

    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let target = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// The regression for the state-direct boot wedge: verify → persist the
    /// anchor → restart against a source with NO history (every completed epoch
    /// answers "Epoch N not found") → verification resumes from the persisted
    /// anchor, ratchets forward using only the source's live window, and
    /// current-epoch summaries verify. No genesis re-bootstrap, no unverified
    /// fallback, no stall.
    #[tokio::test]
    async fn persisted_anchor_round_trip_resumes_on_history_less_source() {
        let (base, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        anchor_db_at(dir.path(), &base, &keys, 3).await;

        // Restart: no bootstrap material — resumption must come purely from the
        // persisted anchor in the perpetual tables.
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store =
            Arc::new(CommitteeStore::open(tables, None).expect("resume from the persisted anchor"));
        assert_eq!(
            store.head_epoch(),
            3,
            "boot resumes at the anchor, not genesis"
        );

        // History-less source at epoch 4: only epoch 3's record/checkpoint (the
        // live window) is served; epochs 0..3 are "Epoch N not found".
        let mock = Arc::new(mock_with_history(&base, &keys, 4, 3));
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);
        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(
            store.head_epoch(),
            4,
            "ratchet resumed forward from the anchor"
        );
        assert_eq!(
            mock.get_committee_call_count(),
            0,
            "no unverified fallback on the resumed path"
        );
        assert_eq!(metrics.ratchet_stalled.get(), 0);

        // The resumed chain verifies current-epoch summaries — the capability
        // every verified read (`verify_summary`) hangs off.
        let current = end_of_epoch_checkpoint(&committee_at_epoch(&base, &keys, 4), &keys, 99);
        store
            .verify_summary(current.checkpoint_summary)
            .expect("current-epoch summary verifies against the resumed committee chain");
    }

    /// The anchor is machine/identity-independent: copying the perpetual DB to
    /// fresh directories (a mirrored / snapshot-restored "different node") and
    /// booting there against the history-less source verifies exactly like the
    /// original.
    #[tokio::test]
    async fn mirrored_db_copy_boots_from_the_same_anchor() {
        let (base, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        anchor_db_at(dir.path(), &base, &keys, 3).await;

        let mirror_dir = tempfile::tempdir().unwrap();
        copy_dir_recursive(dir.path(), mirror_dir.path());

        let tables = Arc::new(AuthorityPerpetualTables::open(mirror_dir.path(), None));
        let store = Arc::new(
            CommitteeStore::open(tables, None).expect("a copied DB must be exactly as bootable"),
        );
        assert_eq!(store.head_epoch(), 3);

        let mock = Arc::new(mock_with_history(&base, &keys, 4, 3));
        let client =
            OcsVerifyingClient::new(mock, store.clone(), OcsMetrics::new_for_testing(), false);
        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(store.head_epoch(), 4);
        let current = end_of_epoch_checkpoint(&committee_at_epoch(&base, &keys, 4), &keys, 99);
        store
            .verify_summary(current.checkpoint_summary)
            .expect("the mirrored DB verifies current-epoch summaries");
    }

    /// A stale anchor (mirror promoted after the primary ran on) ratchets
    /// forward as long as the source still serves the walk's needs — the epoch
    /// record and end-of-epoch checkpoint of every epoch from the anchor to
    /// current. Here: anchor 3, current 6, source window `3..`.
    #[tokio::test]
    async fn stale_anchor_within_source_window_catches_up() {
        let (base, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        anchor_db_at(dir.path(), &base, &keys, 3).await;

        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store = Arc::new(CommitteeStore::open(tables, None).unwrap());
        let mock = Arc::new(mock_with_history(&base, &keys, 6, 3));
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);
        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(
            store.head_epoch(),
            6,
            "stale anchor bridged across the window"
        );
        assert_eq!(mock.get_committee_call_count(), 0);
        assert_eq!(metrics.ratchet_stalled.get(), 0);
    }

    /// Beyond the source's window the walk cannot be verified: the outcome is
    /// the terminal, non-retryable `ProofChainBroken` naming the remediation —
    /// never a silent retryable loop — and the stall is visible in metrics.
    /// Here: anchor 3, current 6, but the source only serves epochs `5..`.
    #[tokio::test]
    async fn stale_anchor_beyond_source_window_fails_terminally_not_silently() {
        let (base, keys) = Committee::new_simple_test_committee();
        let dir = tempfile::tempdir().unwrap();
        anchor_db_at(dir.path(), &base, &keys, 3).await;

        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store = Arc::new(CommitteeStore::open(tables, None).unwrap());
        let mock = Arc::new(mock_with_history(&base, &keys, 6, 5));
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::ProofChainBroken { epoch: 3 }),
            "expected ProofChainBroken at the anchor epoch, got {err:?}"
        );
        assert!(
            !err.is_retryable(),
            "beyond the window is determinate, not a retry loop"
        );
        assert!(
            err.to_string().contains("full-retention Sui RPC"),
            "the error must name the remediation: {err}"
        );
        assert_eq!(store.head_epoch(), 3, "head holds at the anchor");
        assert_eq!(mock.get_committee_call_count(), 0, "no unverified fallback");
        assert_eq!(metrics.ratchet_stalled.get(), 1, "the stall is visible");
        assert_eq!(
            metrics
                .ratchet_failures_total
                .with_label_values(&["proof_chain_broken"])
                .get(),
            1
        );
    }

    /// When the epoch *record* itself is pruned (`last_checkpoint_of_epoch` →
    /// NotFound), a configured checkpoint archive bridges the boundary: the
    /// end-of-epoch sequence is resolved from the archive's own enumeration and
    /// the fetched summary is BLS-verified before install — same trust as the
    /// primary path, no unverified fallback. The one-shot cold-bootstrap
    /// backfill is defeated (its enumeration fails once) so the per-boundary
    /// fallback is what bridges.
    #[tokio::test]
    async fn pruned_epoch_record_bridged_by_verified_archive_fallback() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        let mut archive = archive_for_chain(&committee, &keys, 2);
        archive.fail_enumerations = StdMutex::new(1);
        let archive: Arc<dyn CheckpointArchive> = Arc::new(archive);

        // The transport serves NO epoch records below the current epoch (2).
        let mock = Arc::new(mock_with_history(&committee, &keys, 2, 2));
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false)
            .with_archive(Some(archive));

        client.ratchet_to_current_epoch().await.unwrap();
        assert_eq!(store.head_epoch(), 2, "archive bridged the pruned records");
        assert_eq!(mock.get_committee_call_count(), 0);
        assert_eq!(metrics.unverified_committee_fallback_total.get(), 0);
        assert_eq!(metrics.ratchet_stalled.get(), 0);
    }

    /// Anchor-less cold start on a history-less source (fresh DB, genesis-only
    /// anchor, sui-state-direct-shaped source): the DEFINED behavior is an
    /// immediate terminal error naming the remediation, plus the stall metric —
    /// not the historical invisible 30s retry-forever loop. (At node boot the
    /// non-retryable classification asserted here is what fails startup loudly.)
    #[tokio::test]
    async fn anchorless_cold_start_on_history_less_source_fails_loud_with_metric() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = store_with_genesis(committee.clone());
        assert_eq!(store.head_epoch(), 0, "genesis-only anchor");

        let mock = Arc::new(mock_with_history(&committee, &keys, 100, 100));
        let metrics = OcsMetrics::new_for_testing();
        let client = OcsVerifyingClient::new(mock.clone(), store.clone(), metrics.clone(), false);

        let err = client.ratchet_to_current_epoch().await.unwrap_err();
        assert!(
            matches!(err, OcsError::ProofChainBroken { epoch: 0 }),
            "expected ProofChainBroken at genesis, got {err:?}"
        );
        assert!(
            !err.is_retryable(),
            "cold-start-on-pruned-source must be terminal"
        );
        assert!(
            err.to_string().contains("full-retention Sui RPC"),
            "the error must name the remediation: {err}"
        );
        assert_eq!(metrics.ratchet_stalled.get(), 1);
        assert_eq!(
            metrics
                .ratchet_failures_total
                .with_label_values(&["proof_chain_broken"])
                .get(),
            1
        );
        assert_eq!(store.head_epoch(), 0);
        assert_eq!(mock.get_committee_call_count(), 0);
    }
}
