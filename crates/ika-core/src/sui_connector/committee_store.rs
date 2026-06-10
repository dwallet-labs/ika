// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! In-memory + persistent store of Sui committees for OCS verification.
//!
//! Backing store is [`AuthorityPerpetualTables`]'s `sui_committees`,
//! `sui_committee_head`, and `sui_committee_summaries` columns. Committees
//! are append-only across Sui epoch transitions and survive Ika epoch
//! boundaries.
//!
//! # Bootstrapping
//!
//! - If the perpetual tables already have committee entries, they win
//!   (we've already verified past whatever bootstrap would otherwise apply).
//! - Otherwise [`CommitteeBootstrap`] is installed:
//!   - [`CommitteeBootstrap::EndOfEpoch`]: a verified end-of-epoch
//!     summary; we install `committee[E]` plus `committee[E+1]` extracted
//!     from `end_of_epoch_data` and head sits at E+1.
//!   - [`CommitteeBootstrap::UnsafeGenesis`]: explicit `committee[0]`,
//!     used only by localnet/test bootstrap when the chain hasn't
//!     reached its first end-of-epoch yet.
//! - If neither perpetual nor bootstrap is available, [`Self::open`] errors.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use ika_types::error::{IkaError, IkaResult};
use sui_light_client::proof::committee::extract_new_committee_info;
use sui_types::committee::Committee as SuiCommittee;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, VerifiedCheckpoint};
use tracing::info;

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;

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

pub enum CommitteeBootstrap {
    /// Production path: a `CertifiedCheckpointSummary` whose digest the
    /// caller has already validated against the operator-pinned anchor.
    /// Must be end-of-epoch — we extract `committee[E+1]` from
    /// `summary.end_of_epoch_data`.
    EndOfEpoch(CertifiedCheckpointSummary),
    /// Localnet/test path: explicit epoch-0 committee. Skips the
    /// digest-anchored trust gate entirely; only used when the chain
    /// hasn't reached its first end-of-epoch.
    UnsafeGenesis(SuiCommittee),
}

pub struct CommitteeStore {
    tables: Arc<AuthorityPerpetualTables>,
    in_memory: RwLock<BTreeMap<u64, SuiCommittee>>,
}

impl CommitteeStore {
    pub fn open(
        tables: Arc<AuthorityPerpetualTables>,
        bootstrap: Option<CommitteeBootstrap>,
    ) -> IkaResult<Self> {
        let mut map: BTreeMap<u64, SuiCommittee> = BTreeMap::new();
        let head = tables.highest_sui_committee_epoch()?;
        match head {
            Some(head_epoch) => {
                for (epoch, committee) in tables.iter_sui_committees()? {
                    map.insert(epoch, committee);
                }
                info!(
                    head_epoch,
                    entries = map.len(),
                    "hydrated Sui committee history from perpetual tables"
                );
            }
            None => {
                let bootstrap = bootstrap.ok_or_else(|| {
                    IkaError::SuiClientInternalError(
                        "OCS verifier needs bootstrap material: perpetual `sui_committees` is \
                         empty and no `sui_trusted_anchor` / `sui_unsafe_genesis_committee` was \
                         provided"
                            .to_string(),
                    )
                })?;
                match bootstrap {
                    CommitteeBootstrap::EndOfEpoch(summary) => {
                        Self::install_end_of_epoch(&tables, &summary, &mut map)?
                    }
                    CommitteeBootstrap::UnsafeGenesis(committee) => {
                        Self::install_unsafe_genesis(&tables, committee, &mut map)?
                    }
                }
            }
        }
        Ok(Self {
            tables,
            in_memory: RwLock::new(map),
        })
    }

    /// End-of-epoch bootstrap: the caller has digest-verified the
    /// summary, asserted `end_of_epoch_data.is_some()`, and is handing
    /// us a trusted summary at epoch E. We install `committee[E+1]`
    /// from `next_epoch_committee` and persist the summary as the
    /// transition record. `committee[E]` itself isn't installed —
    /// the ratchet doesn't need to verify older summaries, and we
    /// trust the operator-pinned digest, not a BLS chain through
    /// committee[E].
    fn install_end_of_epoch(
        tables: &AuthorityPerpetualTables,
        summary: &CertifiedCheckpointSummary,
        map: &mut BTreeMap<u64, SuiCommittee>,
    ) -> IkaResult<()> {
        let next_committee = extract_new_committee_info(summary).map_err(|e| {
            IkaError::SuiClientInternalError(format!(
                "trusted-anchor summary marked end-of-epoch but next_epoch_committee missing: {e}"
            ))
        })?;
        tables.record_sui_committee_summary(summary)?;
        tables.install_sui_committee(&next_committee)?;
        let summary_epoch = summary.epoch();
        map.insert(summary_epoch + 1, next_committee);
        info!(
            anchor_epoch = summary_epoch,
            head_epoch = summary_epoch + 1,
            "installed Sui trusted anchor (digest-verified end-of-epoch summary)"
        );
        Ok(())
    }

    /// Unsafe-genesis bootstrap: install the operator-supplied
    /// `committee[0]` as the head. The ratchet will pick up
    /// `committee[1]` once the chain's first end-of-epoch summary
    /// appears upstream. Localnet/test only; production must use
    /// the digest-anchored end-of-epoch path.
    fn install_unsafe_genesis(
        tables: &AuthorityPerpetualTables,
        committee: SuiCommittee,
        map: &mut BTreeMap<u64, SuiCommittee>,
    ) -> IkaResult<()> {
        let epoch = committee.epoch;
        tables.install_sui_committee(&committee)?;
        info!(
            head_epoch = epoch,
            "installed UNSAFE genesis committee (no digest anchor; localnet/test path)"
        );
        map.insert(epoch, committee);
        Ok(())
    }

    pub fn committee(&self, sui_epoch: u64) -> Option<SuiCommittee> {
        self.in_memory.read().unwrap().get(&sui_epoch).cloned()
    }

    /// BLS-verify `summary` against the stored committee for the summary's
    /// own epoch. The one place where "is this checkpoint signed by a Sui
    /// committee we trust" is decided; every consumer (reader, push handler,
    /// snapshot verifier) goes through here so the check can't drift.
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
        *self
            .in_memory
            .read()
            .unwrap()
            .keys()
            .last()
            .expect("bootstrap must seed at least one committee at open()")
    }

    /// Advance the head to `committee` (typically `committee.epoch == prior_head + 1`),
    /// and optionally persist the summary at the prior head's epoch — i.e., the
    /// summary signed by `committee[prior_head]` that committed to this new
    /// committee. `source_summary`, when `Some`, is keyed by `summary.epoch()`.
    pub fn install_next(
        &self,
        committee: SuiCommittee,
        source_summary: Option<&CertifiedCheckpointSummary>,
    ) -> IkaResult<()> {
        let epoch = committee.epoch;
        self.tables.install_sui_committee(&committee)?;
        if let Some(summary) = source_summary {
            self.tables.record_sui_committee_summary(summary)?;
        }
        self.in_memory.write().unwrap().insert(epoch, committee);
        Ok(())
    }
}
