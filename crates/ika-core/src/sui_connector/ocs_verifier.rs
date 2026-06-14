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

use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use ika_sui_client::transport::{SuiTransport, TransportError};

use crate::sui_connector::committee_store::CommitteeStore;
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
        "proof chain broken at epoch {epoch}: the end-of-epoch checkpoint is pruned upstream so \
         the next committee cannot be BLS-verified; re-anchor closer to the current epoch (set \
         sui_trusted_anchor AND clear the node's OCS committee tables — perpetual state otherwise \
         wins over the configured anchor), or set allow_unverified_committee_fallback to accept \
         degraded trust"
    )]
    ProofChainBroken { epoch: u64 },
    #[error(
        "unverified committee fallback returned a committee for epoch {returned} when epoch \
         {requested} was requested; refusing to install it"
    )]
    FallbackEpochMismatch { requested: u64, returned: u64 },
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
    /// end-of-epoch (`NotEndOfEpoch`), an endpoint returning the wrong epoch
    /// (`FallbackEpochMismatch`), or a missing local committee
    /// (`MissingCommittee`/`Ika`) — and needs the operator to act (typically
    /// re-anchor). A caller that loops on the ratchet (the peer-only boot
    /// ratchet) MUST stop and surface a fatal error on a non-retryable result
    /// rather than spin forever against an unhealable condition.
    pub fn is_retryable(&self) -> bool {
        matches!(self, OcsError::Transport(_))
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
            ratchet_lock: Mutex::new(()),
        }
    }

    pub fn transport(&self) -> &Arc<dyn SuiTransport> {
        &self.transport
    }

    pub fn committees(&self) -> &Arc<CommitteeStore> {
        &self.committees
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
        let target = self.transport.get_current_epoch().await?;
        self.metrics.chain_latest_epoch.set(target as i64);
        loop {
            let head = self.committees.head_epoch();
            if head >= target {
                break;
            }
            let last_seq = self.transport.last_checkpoint_of_epoch(head).await?;
            let data = match self.transport.get_full_checkpoint(last_seq).await {
                Ok(d) => d,
                Err(TransportError::NotFound(reason)) => {
                    if !self.allow_unverified_committee_fallback {
                        error!(
                            head,
                            last_seq,
                            target,
                            ?reason,
                            "ratchet: end-of-epoch checkpoint pruned upstream and the unverified \
                             fallback is disabled — proof chain broken; re-anchor required"
                        );
                        return Err(OcsError::ProofChainBroken { epoch: head });
                    }
                    error!(
                        security_critical = true,
                        head,
                        last_seq,
                        target,
                        ?reason,
                        "ratchet: end-of-epoch checkpoint pruned upstream; installing committee[E+1] \
                         via UNVERIFIED direct fetch — trust degraded to the endpoint's word"
                    );
                    self.metrics.unverified_committee_fallback_total.inc();
                    let next = self.transport.get_committee(Some(head + 1)).await?;
                    // Even in unverified mode the endpoint doesn't get to pick
                    // the epoch: `install_next` keys the store by the
                    // committee's own epoch field, so an endpoint returning a
                    // mislabeled committee could jump the ratchet head past
                    // epochs that were never installed.
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
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let committee = self
                .committees
                .committee(head)
                .ok_or(OcsError::MissingCommittee(head))?;

            data.checkpoint_summary
                .verify_with_contents(&committee, Some(&data.checkpoint_contents))
                .map_err(|e| OcsError::BadCheckpointSig(last_seq, e.to_string()))?;

            if data.checkpoint_summary.end_of_epoch_data.is_none() {
                return Err(OcsError::NotEndOfEpoch(last_seq));
            }
            let next = sui_light_client::proof::committee::extract_new_committee_info(
                &data.checkpoint_summary,
            )
            .map_err(|e| OcsError::BadCheckpointSig(last_seq, e.to_string()))?;
            // Persist the verified summary at epoch `head` alongside the
            // committee for `head + 1` it commits to.
            self.committees
                .install_next(next, Some(&data.checkpoint_summary))?;
            info!(epoch = head + 1, last_seq, "ratcheted Sui committee");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
