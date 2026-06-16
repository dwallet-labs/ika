// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Persistent store of Sui committees for OCS verification, with a bounded
//! in-memory cache.
//!
//! Backing store is [`AuthorityPerpetualTables`]'s `sui_committee_summaries`,
//! `sui_committees`, and `sui_committee_head` columns.
//!
//! # Committees are derived from summaries, not stored per epoch
//!
//! An end-of-epoch `CertifiedCheckpointSummary` for epoch `E` carries the
//! *next* committee in `end_of_epoch_data.next_epoch_committee` — so
//! `committee[E+1] == extract_new_committee_info(summary[E])`. The store
//! therefore persists only the verified summaries and **derives** committees
//! from them on demand: keeping a separate per-epoch committee table would
//! double the storage and grow it unboundedly. `sui_committees` is kept only
//! for committees that have *no* backing summary — the bootstrap base
//! committee and any unverified-fallback installs (`install_next(.., None)`).
//!
//! Derivation is cheap (a summary read + `next_epoch_committee` decode, no
//! crypto), so the in-memory [`CommitteeStore::cache`] is a pure performance
//! optimization with a fixed cap; a miss re-derives. This bounds RAM
//! regardless of chain age — the previous design hydrated every committee of
//! every epoch into memory forever.
//!
//! # Bootstrapping
//!
//! - If the perpetual tables already have a committee head, we resume from it.
//! - Otherwise [`CommitteeBootstrap`] is installed:
//!   - [`CommitteeBootstrap::EndOfEpoch`]: a digest-verified end-of-epoch
//!     summary at epoch `E`; we persist it and head sits at `E+1`
//!     (`committee[E+1]` is derived from it).
//!   - [`CommitteeBootstrap::UnsafeGenesis`]: explicit `committee[0]`, stored
//!     directly (it has no preceding summary); localnet/test only.
//! - If neither perpetual state nor bootstrap is available, [`Self::open`]
//!   errors.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use ika_types::error::{IkaError, IkaResult};
use sui_light_client::proof::committee::extract_new_committee_info;
use sui_types::committee::Committee as SuiCommittee;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{
    CertifiedCheckpointSummary, CheckpointContents, VerifiedCheckpoint,
};
use tracing::info;

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;

/// Most committee lookups hit a recent epoch (proofs usually anchor near
/// head). Older committees are re-derived from the stored summary on a miss
/// (a DB read + `extract_new_committee_info`, no crypto), so this cache is a
/// pure optimization and bounded eviction is harmless. Capped to bound RAM.
const COMMITTEE_CACHE_CAP: usize = 256;

/// Why [`CommitteeStore::verify_summary`] rejected a summary. The two cases
/// differ in retriability: a missing committee can resolve once the ratchet
/// catches up to the summary's epoch; a bad signature never does.
#[derive(thiserror::Error, Debug)]
pub enum SummaryVerifyError {
    #[error("no Sui committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("summary BLS verify (epoch {epoch}): {error}")]
    BadSignature { epoch: u64, error: String },
}

/// Result of [`CommitteeStore::install_next_from_checkpoint`].
#[derive(Debug)]
pub enum CommitteeTransition {
    /// Installed `committee[E+1]`; the head advanced to the returned epoch.
    Installed(u64),
    /// The checkpoint is not the transition the store currently needs — it
    /// isn't end-of-epoch, or its epoch isn't the current head (already
    /// installed, or not yet reachable). A no-op; safe to ignore.
    NotNextTransition,
}

/// Why [`CommitteeStore::install_next_from_checkpoint`] could not install the
/// transition (the checkpoint *was* the next end-of-epoch boundary but failed a
/// verification step). Mirrors the determinate, non-retryable conditions the
/// ratchet surfaces.
#[derive(thiserror::Error, Debug)]
pub enum CommitteeTransitionError {
    #[error("no Sui committee for epoch {0}")]
    MissingCommittee(u64),
    #[error("checkpoint summary BLS verify (epoch {epoch}): {error}")]
    BadSignature { epoch: u64, error: String },
    #[error("committee extraction (epoch {epoch}): {error}")]
    Extract { epoch: u64, error: String },
    #[error("committee epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    #[error(transparent)]
    Store(#[from] IkaError),
}

pub enum CommitteeBootstrap {
    /// Production path: a `CertifiedCheckpointSummary` whose digest the
    /// caller has already validated against the operator-pinned anchor.
    /// Must be end-of-epoch — `committee[E+1]` is derived from
    /// `summary.end_of_epoch_data`.
    EndOfEpoch(CertifiedCheckpointSummary),
    /// Localnet/test path: explicit epoch-0 committee. Skips the
    /// digest-anchored trust gate entirely; only used when the chain
    /// hasn't reached its first end-of-epoch.
    UnsafeGenesis(SuiCommittee),
}

pub struct CommitteeStore {
    tables: Arc<AuthorityPerpetualTables>,
    /// Bounded cache of recently-resolved committees. NOT the source of
    /// truth — a miss re-derives from the persisted summary chain (or the
    /// sparse `sui_committees` table for committees with no backing summary).
    cache: RwLock<BTreeMap<u64, SuiCommittee>>,
    /// Highest Sui epoch we hold a (derivable) committee for. Tracked here so
    /// `head_epoch` doesn't depend on the bounded cache's contents.
    head: AtomicU64,
}

impl CommitteeStore {
    pub fn open(
        tables: Arc<AuthorityPerpetualTables>,
        bootstrap: Option<CommitteeBootstrap>,
    ) -> IkaResult<Self> {
        let store = Self {
            tables,
            cache: RwLock::new(BTreeMap::new()),
            head: AtomicU64::new(0),
        };
        match store.tables.highest_sui_committee_epoch()? {
            Some(head_epoch) => {
                store.head.store(head_epoch, Ordering::Relaxed);
                // Fail fast if the persisted head committee can't be resolved
                // (corrupt store / missing summary) rather than at first read.
                store.committee(head_epoch).ok_or_else(|| {
                    IkaError::SuiClientInternalError(format!(
                        "perpetual Sui committee head is {head_epoch} but its committee cannot be \
                         resolved from the stored summaries"
                    ))
                })?;
                info!(
                    head_epoch,
                    "opened Sui committee store from perpetual tables"
                );
            }
            None => {
                let bootstrap = bootstrap.ok_or_else(|| {
                    IkaError::SuiClientInternalError(
                        "OCS verifier needs bootstrap material: perpetual Sui committee state is \
                         empty and no `sui_trusted_anchor` / `sui_unsafe_genesis_committee` was \
                         provided"
                            .to_string(),
                    )
                })?;
                match bootstrap {
                    CommitteeBootstrap::EndOfEpoch(summary) => {
                        store.install_end_of_epoch(&summary)?
                    }
                    CommitteeBootstrap::UnsafeGenesis(committee) => {
                        store.install_unsafe_genesis(committee)?
                    }
                }
            }
        }
        Ok(store)
    }

    /// End-of-epoch bootstrap: the caller has digest-verified the summary,
    /// asserted `end_of_epoch_data.is_some()`, and is handing us a trusted
    /// summary at epoch `E`. We persist it; `committee[E+1]` is derived from
    /// `next_epoch_committee` and head sits at `E+1`. `committee[E]` itself
    /// isn't installed — the ratchet doesn't verify older summaries, and we
    /// trust the operator-pinned digest, not a BLS chain through `committee[E]`.
    fn install_end_of_epoch(&self, summary: &CertifiedCheckpointSummary) -> IkaResult<()> {
        let next_committee = extract_new_committee_info(summary).map_err(|e| {
            IkaError::SuiClientInternalError(format!(
                "trusted-anchor summary marked end-of-epoch but next_epoch_committee missing: {e}"
            ))
        })?;
        let summary_epoch = summary.epoch();
        let head_epoch = summary_epoch + 1;
        // Records the summary AND advances head to summary.epoch()+1.
        self.tables.record_sui_committee_transition(summary)?;
        self.head.store(head_epoch, Ordering::Relaxed);
        self.cache_committee(head_epoch, next_committee);
        info!(
            anchor_epoch = summary_epoch,
            head_epoch, "installed Sui trusted anchor (digest-verified end-of-epoch summary)"
        );
        Ok(())
    }

    /// Unsafe-genesis bootstrap: install the operator-supplied `committee[0]`
    /// directly (it has no preceding summary to derive from). The ratchet
    /// picks up `committee[1]` once the chain's first end-of-epoch summary
    /// appears upstream. Localnet/test only.
    fn install_unsafe_genesis(&self, committee: SuiCommittee) -> IkaResult<()> {
        let epoch = committee.epoch;
        self.tables.install_sui_committee(&committee)?;
        self.head.store(epoch, Ordering::Relaxed);
        self.cache_committee(epoch, committee);
        info!(
            head_epoch = epoch,
            "installed UNSAFE genesis committee (no digest anchor; localnet/test path)"
        );
        Ok(())
    }

    pub fn committee(&self, sui_epoch: u64) -> Option<SuiCommittee> {
        if let Some(c) = self.cache.read().unwrap().get(&sui_epoch) {
            return Some(c.clone());
        }
        let resolved = self.resolve_committee(sui_epoch)?;
        self.cache_committee(sui_epoch, resolved.clone());
        Some(resolved)
    }

    /// Resolve `committee[E]` from persistent state without touching the cache.
    /// A committee with no backing summary (bootstrap base / unverified
    /// fallback) is stored directly in `sui_committees`; otherwise it is
    /// derived from the end-of-epoch summary of `E-1`, which carries it.
    fn resolve_committee(&self, sui_epoch: u64) -> Option<SuiCommittee> {
        if let Ok(Some(committee)) = self.tables.get_sui_committee(sui_epoch) {
            return Some(committee);
        }
        let prev = sui_epoch.checked_sub(1)?;
        let summary = self.tables.get_sui_committee_summary(prev).ok()??;
        extract_new_committee_info(&summary).ok()
    }

    fn cache_committee(&self, epoch: u64, committee: SuiCommittee) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(epoch, committee);
        // Evict the oldest epochs over the cap. `head` is the highest epoch,
        // so the smallest key is never the head — head stays hot.
        while cache.len() > COMMITTEE_CACHE_CAP {
            let Some(&oldest) = cache.keys().next() else {
                break;
            };
            cache.remove(&oldest);
        }
    }

    /// BLS-verify `summary` against the committee for the summary's own epoch.
    /// The one place where "is this checkpoint signed by a Sui committee we
    /// trust" is decided; every consumer goes through here so the check can't
    /// drift.
    pub fn verify_summary(
        &self,
        summary: CertifiedCheckpointSummary,
    ) -> Result<VerifiedCheckpoint, SummaryVerifyError> {
        let epoch = summary.epoch();
        let committee = self
            .committee(epoch)
            .ok_or(SummaryVerifyError::MissingCommittee(epoch))?;
        summary
            .try_into_verified(&committee)
            .map_err(|e| SummaryVerifyError::BadSignature {
                epoch,
                error: e.to_string(),
            })
    }

    pub fn head_epoch(&self) -> u64 {
        self.head.load(Ordering::Relaxed)
    }

    /// Advance the head to `committee` (typically the epoch after the prior
    /// head). `source_summary`, when `Some`, is the summary signed by
    /// `committee[prior_head]` that commits to this committee: we persist only
    /// the summary and derive the committee from it. When `None` (the
    /// unverified-fallback path, which has no summary), we store the committee
    /// directly so it can still be resolved.
    pub fn install_next(
        &self,
        committee: SuiCommittee,
        source_summary: Option<&CertifiedCheckpointSummary>,
    ) -> IkaResult<()> {
        let epoch = committee.epoch;
        match source_summary {
            Some(summary) => self.tables.record_sui_committee_transition(summary)?,
            None => self.tables.install_sui_committee(&committee)?,
        }
        self.head.store(epoch, Ordering::Relaxed);
        self.cache_committee(epoch, committee);
        Ok(())
    }

    /// The single audited committee-transition step, shared by the background
    /// ratchet ([`super::ocs_verifier::OcsVerifyingClient`]) and the eager
    /// capture in the checkpoint pusher ([`super::push_worker::IkaCheckpointPusher`]).
    ///
    /// Installs `committee[E+1]` *only* when `data` is the end-of-epoch
    /// checkpoint of the current head epoch `E` (`summary.epoch() == head` and
    /// `end_of_epoch_data.is_some()`); BLS-verifies it against `committee[E]`,
    /// derives `committee[E+1]` from it, asserts the derived epoch is `E+1`, and
    /// persists the verified summary. Any other checkpoint — not end-of-epoch,
    /// or for an epoch already installed or not yet reached — is a
    /// [`CommitteeTransition::NotNextTransition`] no-op, so this is idempotent
    /// and safe to call on every streamed checkpoint.
    pub fn install_next_from_checkpoint(
        &self,
        data: &CheckpointData,
    ) -> Result<CommitteeTransition, CommitteeTransitionError> {
        self.install_next_from_verified_summary(
            &data.checkpoint_summary,
            Some(&data.checkpoint_contents),
        )
    }

    /// Summary-only sibling of [`Self::install_next_from_checkpoint`], for the
    /// live committee follower ([`super::committee_follower::CommitteeFollower`])
    /// which subscribes to the Sui checkpoint *summary* stream — no contents,
    /// no objects, so it is independent of the fullnode's object pruning.
    /// Verification is BLS-only (the contents-digest bind is skipped), which is
    /// exactly the committee-transition guarantee: `committee[E]`'s quorum signs
    /// the end-of-epoch summary that commits to `committee[E+1]`. Head-guarded
    /// and idempotent like the full variant, so the follower and the background
    /// ratchet may both call it.
    pub fn install_next_from_summary(
        &self,
        summary: &CertifiedCheckpointSummary,
    ) -> Result<CommitteeTransition, CommitteeTransitionError> {
        self.install_next_from_verified_summary(summary, None)
    }

    /// Shared core. Installs `committee[E+1]` *only* when `summary` is the
    /// end-of-epoch summary of the current head epoch `E`; BLS-verifies it
    /// against `committee[E]`, derives and asserts `committee[E+1]`, and
    /// persists the verified summary. `contents`, when `Some`, additionally
    /// binds the summary to its checkpoint-contents digest; `None` checks the
    /// quorum signature alone. Any other checkpoint is a
    /// [`CommitteeTransition::NotNextTransition`] no-op (idempotent).
    fn install_next_from_verified_summary(
        &self,
        summary: &CertifiedCheckpointSummary,
        contents: Option<&CheckpointContents>,
    ) -> Result<CommitteeTransition, CommitteeTransitionError> {
        let head = self.head_epoch();
        let epoch = summary.epoch();
        if epoch != head || summary.end_of_epoch_data.is_none() {
            return Ok(CommitteeTransition::NotNextTransition);
        }
        let committee = self
            .committee(head)
            .ok_or(CommitteeTransitionError::MissingCommittee(head))?;
        summary
            .verify_with_contents(&committee, contents)
            .map_err(|e| CommitteeTransitionError::BadSignature {
                epoch,
                error: e.to_string(),
            })?;
        let next =
            extract_new_committee_info(summary).map_err(|e| CommitteeTransitionError::Extract {
                epoch,
                error: e.to_string(),
            })?;
        // A summary verified by `committee[head]` commits to `committee[head+1]`
        // by the protocol, but assert it explicitly so a faulty extraction can't
        // jump the head past an uninstalled epoch.
        if next.epoch != head + 1 {
            return Err(CommitteeTransitionError::EpochMismatch {
                expected: head + 1,
                got: next.epoch,
            });
        }
        self.install_next(next, Some(summary))?;
        Ok(CommitteeTransition::Installed(head + 1))
    }
}
