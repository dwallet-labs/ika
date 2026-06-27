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
    /// Install `committee[0]` directly. The committee comes from a verified Sui
    /// genesis blob (the genesis-rooted production path) or, on localnet/test,
    /// from the chain's epoch-0 committee fetched over RPC. The OCS ratchet then
    /// walks the end-of-epoch checkpoint chain forward from here. (The name is
    /// retained from the pre-genesis-blob era; on a public chain the genesis
    /// blob is verified against the compiled-in chain identifier, so it is no
    /// longer unsafe.)
    UnsafeGenesis(SuiCommittee),
}

pub struct CommitteeStore {
    tables: Arc<AuthorityPerpetualTables>,
    /// Bounded cache of recently-resolved committees. NOT the source of
    /// truth — a miss re-derives from the persisted summary chain (or the
    /// sparse `sui_committees` table for committees with no backing summary).
    cache: RwLock<BTreeMap<u64, SuiCommittee>>,
    /// Highest Sui epoch we hold a (derivable) committee for. Tracked here so
    /// `head_epoch` doesn't depend on the bounded cache's contents. Advanced
    /// with `fetch_max` (never a plain store on the install paths) so a
    /// staggered lower install can never regress it.
    head: AtomicU64,
    /// Serializes the install paths (ratchet, committee follower, checkpoint
    /// pusher all install through this store) so the read-current-then-write-max
    /// of the persisted `sui_committee_head` is atomic. Without it two
    /// concurrent installs could both read the same persisted head and the
    /// lower one could win the write, regressing the persisted head across a
    /// restart.
    install_lock: std::sync::Mutex<()>,
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
            install_lock: std::sync::Mutex::new(()),
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
                         empty and no `sui_genesis` / `sui_unsafe_genesis_committee` was provided"
                            .to_string(),
                    )
                })?;
                match bootstrap {
                    CommitteeBootstrap::UnsafeGenesis(committee) => {
                        store.install_unsafe_genesis(committee)?
                    }
                }
            }
        }
        Ok(store)
    }

    /// Genesis bootstrap: install the supplied `committee[0]`
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
        // Serialize vs the other installers and keep the head monotonic: a
        // ratchet that derived this committee at an earlier head and was
        // preempted while a follower advanced past it must not regress the head
        // (in memory or persisted) — that regression survives restart and can
        // force a network re-walk that ProofChainBroken-wedges if the boundary
        // checkpoint was pruned upstream.
        let _install = self
            .install_lock
            .lock()
            .expect("committee install lock poisoned");
        match source_summary {
            Some(summary) => self.tables.record_sui_committee_transition(summary)?,
            None => self.tables.install_sui_committee(&committee)?,
        }
        self.head.fetch_max(epoch, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Barrier;

    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointContents, CheckpointSequenceNumber, CheckpointSummary, EndOfEpochData,
    };
    use typed_store::traits::Map;

    /// The same validator set, re-stamped at `epoch`. The keypairs never change
    /// across epochs (only the committee's epoch number does), so a summary
    /// signed by `committee_at(E)` carries `voting_rights` that derive into
    /// `committee_at(E + 1)` — exactly the on-chain committee-transition chain.
    fn committee_at(base: &Committee, epoch: u64) -> Committee {
        Committee::new(epoch, base.voting_rights.iter().cloned().collect())
    }

    /// An end-of-epoch summary for `committee`'s epoch, committing to the same
    /// validator set as the next epoch's committee so `install_next_*` can
    /// BLS-verify it against `committee` and derive `committee[epoch + 1]`.
    fn signed_end_of_epoch(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
    ) -> CertifiedCheckpointSummary {
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
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee)
    }

    /// A fresh store bootstrapped at `committee[0]` over its own temp perpetual
    /// tables. The returned `TempDir` guard must be held for as long as the
    /// store is used (dropping it deletes the backing RocksDB directory).
    fn open_store(committee: &Committee) -> (tempfile::TempDir, Arc<CommitteeStore>) {
        let dir = tempfile::tempdir().unwrap();
        let tables = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        let store = Arc::new(
            CommitteeStore::open(
                tables,
                Some(CommitteeBootstrap::UnsafeGenesis(committee.clone())),
            )
            .unwrap(),
        );
        (dir, store)
    }

    fn voting_rights_bytes(committee: &SuiCommittee) -> Vec<u8> {
        bcs::to_bytes(&committee.voting_rights).unwrap()
    }

    /// Driving the chain far past the 256-entry cache cap evicts the oldest
    /// committees, but `committee(1)` is still re-derived byte-identically from
    /// the epoch-0 end-of-epoch summary via the cache-miss `resolve_committee`
    /// path. The cache is a pure optimization; correctness must not depend on a
    /// committee still being resident.
    #[tokio::test(flavor = "multi_thread")]
    async fn committee_derivation_after_cache_eviction() {
        let (base, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = open_store(&base);
        assert_eq!(store.head_epoch(), 0);

        // Install committee[1..=257] from the signed end-of-epoch summary of
        // each preceding epoch. 257 boundaries past head 0 forces eviction
        // well beyond COMMITTEE_CACHE_CAP (= 256).
        for epoch in 0..=COMMITTEE_CACHE_CAP as u64 {
            let committee_e = committee_at(&base, epoch);
            let summary = signed_end_of_epoch(&committee_e, &keys, epoch);
            let installed = store.install_next_from_summary(&summary).unwrap();
            assert!(
                matches!(installed, CommitteeTransition::Installed(e) if e == epoch + 1),
                "epoch {epoch} should install committee[{}]",
                epoch + 1
            );
            assert_eq!(store.head_epoch(), epoch + 1);
        }

        // The store advanced past the cap.
        assert_eq!(store.head_epoch(), COMMITTEE_CACHE_CAP as u64 + 1);

        // committee[1] was evicted (head and the most-recent 256 epochs are
        // hot; epoch 1 is the oldest installed and long gone).
        assert!(
            store.cache.read().unwrap().get(&1).is_none(),
            "committee[1] should have been evicted past the cache cap"
        );

        // Re-deriving it from the stored epoch-0 summary (the cache-miss path)
        // yields the originally-installed committee, byte-identically. The
        // oracle is the committee carried by the persisted epoch-0 summary
        // itself (the exact value the original install used), so we never have
        // to regenerate the random validator keys.
        let derived = store.committee(1).expect("committee[1] must re-derive");
        assert_eq!(derived.epoch, 1);

        // Cross-check against the committee carried by the persisted epoch-0
        // summary directly (the same value the original install used).
        let summary_zero = store
            .tables
            .get_sui_committee_summary(0)
            .unwrap()
            .expect("epoch-0 summary must be persisted");
        let oracle = extract_new_committee_info(&summary_zero).unwrap();
        assert_eq!(
            derived, oracle,
            "re-derived committee[1] must equal the oracle"
        );
        assert_eq!(
            voting_rights_bytes(&derived),
            voting_rights_bytes(&oracle),
            "re-derived committee[1] must be byte-identical to the install-time committee"
        );

        // The miss re-derived epoch 1 without disturbing the hot head: the most
        // recent committee stays resident (the cache keeps the highest epochs;
        // epoch 1, being the oldest, is re-evicted on insert — bounded RAM holds).
        assert!(
            store
                .cache
                .read()
                .unwrap()
                .get(&(COMMITTEE_CACHE_CAP as u64 + 1))
                .is_some(),
            "the head committee must stay cached across an old-epoch miss"
        );
        assert!(
            store.cache.read().unwrap().len() <= COMMITTEE_CACHE_CAP,
            "the cache must never exceed COMMITTEE_CACHE_CAP"
        );
    }

    /// Two threads racing the *same* end-of-epoch summary of head epoch `E`
    /// converge to a single committee[E+1] and a head of exactly E+1. The
    /// head guard is a check-then-act (load `head`, then later `store` it), not
    /// a critical section, so under a genuine race both threads may pass the
    /// guard and re-install the *identical* derived committee — that is benign
    /// (same summary, same `committee[E+1]`, head still lands on E+1). The
    /// guarantee the follower and the ratchet rely on is therefore eventual-
    /// state idempotency, deterministic regardless of the interleaving: no
    /// error, no foreign epoch, head advances to exactly E+1 once and never
    /// past it, and committee[E+1] is the single deterministic value.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_install_same_boundary_is_idempotent() {
        let (base, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = open_store(&base);
        let committee_zero = committee_at(&base, 0);
        let summary = signed_end_of_epoch(&committee_zero, &keys, 0);

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let summary = summary.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.install_next_from_summary(&summary).unwrap()
                })
            })
            .collect();

        let outcomes: Vec<CommitteeTransition> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Each call is one of the only two legal outcomes — it either installs
        // *this* boundary (E+1 == 1) or no-ops; never an error, never a foreign
        // epoch. At least one must have installed it.
        assert!(
            outcomes.iter().all(|o| matches!(
                o,
                CommitteeTransition::Installed(1) | CommitteeTransition::NotNextTransition
            )),
            "every racing call must install boundary 1 or be a clean no-op: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, CommitteeTransition::Installed(1))),
            "at least one call must install the boundary"
        );

        // Head advanced to exactly E+1 (never skipped past it) and committee[1]
        // is the single deterministic value, whichever thread(s) wrote it.
        assert_eq!(store.head_epoch(), 1);
        let resolved = store.committee(1).expect("committee[1] resolves");
        assert_eq!(resolved.epoch, 1);
        let oracle = extract_new_committee_info(&summary).unwrap();
        assert_eq!(resolved, oracle);
        assert_eq!(voting_rights_bytes(&resolved), voting_rights_bytes(&oracle));
    }

    /// Reopening over perpetual tables resumes from the recorded head and
    /// resolves its committee. A head whose backing summary is absent
    /// (corrupt/truncated store) fails `open` fast, not at first read.
    #[tokio::test(flavor = "multi_thread")]
    async fn open_resumes_from_perpetual_head_or_errors_on_unresolvable_head() {
        let (base, keys) = Committee::new_simple_test_committee();

        // -- Resume path: install a couple of boundaries, drop the store, reopen.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        let tables = Arc::new(AuthorityPerpetualTables::open(&path, None));
        {
            let store = CommitteeStore::open(
                tables.clone(),
                Some(CommitteeBootstrap::UnsafeGenesis(base.clone())),
            )
            .unwrap();
            for epoch in 0..=1u64 {
                let committee_e = committee_at(&base, epoch);
                store
                    .install_next_from_summary(&signed_end_of_epoch(&committee_e, &keys, epoch))
                    .unwrap();
            }
            assert_eq!(store.head_epoch(), 2);
        }

        // Reopen over the same tables with NO bootstrap: it must resume from the
        // persisted head (2) and resolve committee[2] from the epoch-1 summary.
        let reopened = CommitteeStore::open(tables.clone(), None)
            .expect("reopen must resume from the persisted head");
        assert_eq!(reopened.head_epoch(), 2);
        let head_committee = reopened
            .committee(2)
            .expect("head committee resolves on resume");
        assert_eq!(head_committee.epoch, 2);
        drop(reopened);

        // -- Fail-fast path: point the head at an epoch with no backing summary
        // and no directly-stored committee. `open` must error, not defer to the
        // first read.
        tables.sui_committee_head.insert(&(), &99).unwrap();
        // `CommitteeStore` isn't `Debug`, so match the result directly rather
        // than `expect_err`.
        let msg = match CommitteeStore::open(tables.clone(), None) {
            Ok(_) => panic!("an unresolvable head must fail open fast"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("99") && msg.contains("cannot be"),
            "error must name the unresolvable head: {msg}"
        );
    }

    /// The follower installing ahead (boundaries E, E+1) and a ratchet driving
    /// the same boundaries concurrently must converge: head advances
    /// monotonically, each boundary installs exactly once, no skip, every call
    /// returns Ok. The head-guarded idempotent install is the join point.
    #[tokio::test(flavor = "multi_thread")]
    async fn follower_ahead_then_ratchet_catches_up_no_double_install() {
        let (base, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = open_store(&base);

        let boundary_zero = signed_end_of_epoch(&committee_at(&base, 0), &keys, 0);
        let boundary_one = signed_end_of_epoch(&committee_at(&base, 1), &keys, 1);

        // "Follower" runs ahead and installs both boundaries.
        let first = store.install_next_from_summary(&boundary_zero).unwrap();
        assert!(matches!(first, CommitteeTransition::Installed(1)));
        assert_eq!(store.head_epoch(), 1);
        let second = store.install_next_from_summary(&boundary_one).unwrap();
        assert!(matches!(second, CommitteeTransition::Installed(2)));
        assert_eq!(store.head_epoch(), 2);

        // "Ratchet" (slower path) replays the same boundaries. Both are now
        // already installed, so each is a clean NotNextTransition no-op — no
        // double install, no skip, and Ok throughout.
        let replay_zero = store.install_next_from_summary(&boundary_zero).unwrap();
        let replay_one = store.install_next_from_summary(&boundary_one).unwrap();
        assert!(matches!(
            replay_zero,
            CommitteeTransition::NotNextTransition
        ));
        assert!(matches!(replay_one, CommitteeTransition::NotNextTransition));

        // Head never regressed and never skipped past 2.
        assert_eq!(store.head_epoch(), 2);
        assert_eq!(store.committee(1).unwrap().epoch, 1);
        assert_eq!(store.committee(2).unwrap().epoch, 2);

        // The reverse interleaving (ratchet for E while the follower is still at
        // E, then the follower replays) converges to the same single install.
        let (base, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = open_store(&base);
        let boundary_zero = signed_end_of_epoch(&committee_at(&base, 0), &keys, 0);
        let ratchet = store.install_next_from_summary(&boundary_zero).unwrap();
        let follower = store.install_next_from_summary(&boundary_zero).unwrap();
        assert!(matches!(ratchet, CommitteeTransition::Installed(1)));
        assert!(matches!(follower, CommitteeTransition::NotNextTransition));
        assert_eq!(store.head_epoch(), 1);
    }

    /// A staggered LOWER install must never regress the head. The public
    /// `install_next_from_summary` guards on `epoch == head`, but that read and
    /// the `install_next` head write are not atomic: a ratchet can derive
    /// `committee[E+1]` while head is `E`, be preempted while a follower advances
    /// head to `E+2`, then perform the raw `install_next(committee[E+1], ..)`.
    /// `fetch_max` (in memory) and the non-regressing persisted-head write must
    /// keep both heads at `E+2`. Exercises the path the existing tests miss
    /// (they only replay an *already-installed* boundary, a clean no-op).
    #[tokio::test(flavor = "multi_thread")]
    async fn staggered_lower_install_does_not_regress_head() {
        let (base, keys) = Committee::new_simple_test_committee();
        let (_dir, store) = open_store(&base);

        let boundary_zero = signed_end_of_epoch(&committee_at(&base, 0), &keys, 0);
        let boundary_one = signed_end_of_epoch(&committee_at(&base, 1), &keys, 1);

        // Advance the head to 2.
        store.install_next_from_summary(&boundary_zero).unwrap();
        store.install_next_from_summary(&boundary_one).unwrap();
        assert_eq!(store.head_epoch(), 2);
        assert_eq!(store.tables.highest_sui_committee_epoch().unwrap(), Some(2));

        // The raw lower install a preempted ratchet would perform: it derived
        // committee[1] from boundary[0] back when the head was 1, and only now
        // gets to write it.
        let committee_one = extract_new_committee_info(&boundary_zero).unwrap();
        store
            .install_next(committee_one, Some(&boundary_zero))
            .unwrap();

        // Neither the in-memory nor the persisted head regressed.
        assert_eq!(
            store.head_epoch(),
            2,
            "in-memory head must not regress on a staggered lower install"
        );
        assert_eq!(
            store.tables.highest_sui_committee_epoch().unwrap(),
            Some(2),
            "persisted head must not regress on a staggered lower install"
        );
    }
}
