// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Live committee follower: a decoupled, summary-only subscription to the Sui
//! checkpoint stream that keeps the OCS committee chain current.
//!
//! The background ratchet ([`super::ocs_verifier::OcsVerifyingClient`]) advances
//! the committee chain by *reaching back* for each epoch's end-of-epoch
//! checkpoint via [`SuiTransport::get_full_checkpoint`]. That fetch is gated by
//! the fullnode's object-pruning watermark, so a node that falls behind finds
//! the checkpoint pruned and the chain hard-stalls (`ProofChainBroken`).
//!
//! This follower removes that dependency for the steady state: it subscribes to
//! the fullnode's live checkpoint *summary* stream
//! ([`SuiTransport::subscribe_checkpoint_summaries`]) — served from an in-memory
//! broadcast, summary-only, independent of object pruning — and installs
//! `committee[E+1]` the moment the end-of-epoch summary of epoch `E` streams by,
//! while that data is still fresh at the tip. A continuously-running node never
//! reaches back; the ratchet stays the catch-up backstop for the cold-start /
//! restart window the live tail can't cover (it has no historical backfill).
//!
//! The follower is intentionally tiny and shares the audited transition step
//! [`CommitteeStore::install_next_from_summary`] with the ratchet, so the two
//! can run concurrently: the install is head-guarded and idempotent.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ika_sui_client::transport::{CheckpointSummaryStream, SuiTransport};
use sui_types::messages_checkpoint::CertifiedCheckpointSummary;
use tracing::{info, warn};

use crate::sui_connector::committee_store::{CommitteeStore, CommitteeTransition};

/// Delay between a stream ending/erroring and resubscribing. A dropped stream
/// (fullnode restart, transient error) is expected occasionally; the gap it
/// leaves is closed by the ratchet, so a short fixed backoff is enough.
const RESUBSCRIBE_BACKOFF: Duration = Duration::from_secs(1);

pub struct CommitteeFollower {
    transport: Arc<dyn SuiTransport>,
    committees: Arc<CommitteeStore>,
}

impl CommitteeFollower {
    pub fn new(transport: Arc<dyn SuiTransport>, committees: Arc<CommitteeStore>) -> Self {
        Self {
            transport,
            committees,
        }
    }

    /// Subscribe to the Sui checkpoint summary stream and install every
    /// end-of-epoch committee it carries, resubscribing across stream drops
    /// forever. Spawned on sui-state-direct nodes.
    pub async fn run(self) {
        loop {
            match self.transport.subscribe_checkpoint_summaries().await {
                Ok(stream) => {
                    info!("committee follower: subscribed to the Sui checkpoint summary stream");
                    Self::consume(&self.committees, stream).await;
                    warn!("committee follower: summary stream ended; resubscribing");
                }
                Err(e) => {
                    warn!(error = ?e, "committee follower: subscribe failed; retrying");
                }
            }
            tokio::time::sleep(RESUBSCRIBE_BACKOFF).await;
        }
    }

    /// Drain one subscription stream, installing each end-of-epoch committee.
    /// Returns when the stream ends or yields an error (the caller resubscribes;
    /// any boundary missed in the gap is the ratchet's to recover).
    async fn consume(committees: &CommitteeStore, mut stream: CheckpointSummaryStream) {
        while let Some(item) = stream.next().await {
            match item {
                Ok(summary) => Self::capture(committees, &summary),
                Err(e) => {
                    warn!(error = ?e, "committee follower: stream error; will resubscribe");
                    break;
                }
            }
        }
    }

    /// Install `committee[E+1]` if `summary` is the end-of-epoch summary of the
    /// current head epoch; a no-op for every other (non-boundary, already-seen,
    /// or not-yet-reachable) summary. Best-effort: a verify/install failure is
    /// logged and left to the ratchet rather than tearing down the stream.
    fn capture(committees: &CommitteeStore, summary: &CertifiedCheckpointSummary) {
        match committees.install_next_from_summary(summary) {
            Ok(CommitteeTransition::Installed(epoch)) => {
                info!(
                    epoch,
                    seq = *summary.sequence_number(),
                    "committee follower captured Sui committee from the live summary stream"
                );
            }
            Ok(CommitteeTransition::NotNextTransition) => {}
            Err(e) => {
                warn!(
                    error = ?e,
                    epoch = summary.epoch(),
                    "committee follower: committee install failed; leaving to the ratchet"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ika_sui_client::transport::TransportError;
    use sui_types::committee::{Committee, ProtocolVersion};
    use sui_types::crypto::AuthorityKeyPair;
    use sui_types::gas::GasCostSummary;
    use sui_types::messages_checkpoint::{
        CheckpointContents, CheckpointSequenceNumber, CheckpointSummary, EndOfEpochData,
    };

    use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
    use crate::sui_connector::committee_store::{CommitteeBootstrap, CommitteeStore};

    /// A committee-signed checkpoint summary for the committee's epoch at `seq`.
    /// When `end_of_epoch`, it commits to the next epoch's committee (same
    /// members, epoch E+1) so `install_next_from_summary` can verify + derive
    /// it; otherwise it's a mid-epoch summary the follower must skip.
    fn signed_summary(
        committee: &Committee,
        keys: &[AuthorityKeyPair],
        seq: CheckpointSequenceNumber,
        end_of_epoch: bool,
    ) -> CertifiedCheckpointSummary {
        let contents = CheckpointContents::new_with_digests_only_for_tests(vec![]);
        let end_of_epoch_data = end_of_epoch.then(|| EndOfEpochData {
            next_epoch_committee: committee.voting_rights.clone(),
            next_epoch_protocol_version: ProtocolVersion::MIN,
            epoch_commitments: vec![],
        });
        let summary = CheckpointSummary {
            epoch: committee.epoch(),
            sequence_number: seq,
            network_total_transactions: 0,
            content_digest: *contents.digest(),
            previous_digest: None,
            epoch_rolling_gas_cost_summary: GasCostSummary::default(),
            timestamp_ms: 0,
            checkpoint_commitments: vec![],
            end_of_epoch_data,
            version_specific_data: Vec::new(),
        };
        CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, keys, committee)
    }

    fn committee_store(committee: &Committee) -> Arc<CommitteeStore> {
        let dir = tempfile::tempdir().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        Arc::new(
            CommitteeStore::open(
                perpetual,
                Some(CommitteeBootstrap::UnsafeGenesis(committee.clone())),
            )
            .unwrap(),
        )
    }

    /// The follower installs `committee[E+1]` from the live summary stream —
    /// verifying summary-only (no contents/objects, no `get_full_checkpoint`) —
    /// and skips mid-epoch summaries. This is the steady-state keep-up that
    /// makes the committee chain independent of the fullnode's object pruning.
    #[tokio::test]
    async fn follower_installs_committee_from_summary_stream() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let committees = committee_store(&committee);
        assert_eq!(committees.head_epoch(), 0);

        // A mid-epoch summary (skipped) followed by the end-of-epoch summary of
        // epoch 0 (installs committee[1]).
        let stream: CheckpointSummaryStream = Box::pin(futures::stream::iter(vec![
            Ok(signed_summary(&committee, &keys, 10, false)),
            Ok(signed_summary(&committee, &keys, 42, true)),
        ]));

        CommitteeFollower::consume(&committees, stream).await;

        assert_eq!(
            committees.head_epoch(),
            1,
            "follower should advance the committee head to 1 from the end-of-epoch summary"
        );
    }

    /// A stream error stops the drain (the caller resubscribes) without
    /// advancing past what was already installed.
    #[tokio::test]
    async fn follower_stops_draining_on_stream_error() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let committees = committee_store(&committee);

        // The error arrives before the end-of-epoch summary → head stays at 0.
        let stream: CheckpointSummaryStream = Box::pin(futures::stream::iter(vec![
            Ok(signed_summary(&committee, &keys, 10, false)),
            Err(TransportError::Network("stream dropped".into())),
            Ok(signed_summary(&committee, &keys, 42, true)),
        ]));

        CommitteeFollower::consume(&committees, stream).await;

        assert_eq!(
            committees.head_epoch(),
            0,
            "drain should stop at the stream error, before the post-error boundary"
        );
    }

    /// A `capture` whose install fails (here: the end-of-epoch summary of the
    /// head epoch carries a quorum signature from a *different* committee, so
    /// the BLS check against `committee[head]` rejects it) is best-effort: it
    /// logs a warning and leaves the boundary to the ratchet — it must not
    /// panic, must not advance the head, and must not tear down the stream. The
    /// drain keeps going, and once the genuine, correctly-signed boundary
    /// arrives it installs `committee[E+1]` exactly once; replaying it is then a
    /// no-op (idempotent), so the ratchet and the follower can't double-install.
    #[tokio::test]
    async fn capture_failure_is_benign_and_recovers_on_replay() {
        let (committee, keys) = Committee::new_simple_test_committee();
        let committees = committee_store(&committee);
        assert_eq!(committees.head_epoch(), 0);

        // A foreign committee at the same epoch (0): its members sign a
        // well-formed end-of-epoch summary that the head committee can't verify.
        let (foreign, foreign_keys) = Committee::new_simple_test_committee();
        let bad_boundary = signed_summary(&foreign, &foreign_keys, 7, true);

        // The genuine end-of-epoch summary of epoch 0, signed by the real head
        // committee — the boundary the bad one impersonated.
        let good_boundary = signed_summary(&committee, &keys, 42, true);

        // Stream: a mid-epoch summary (skipped), the un-verifiable boundary
        // (warns, no advance), then more mid-epoch traffic, then the genuine
        // boundary. The bad capture must NOT stop the drain — the genuine
        // boundary after it still installs.
        let stream: CheckpointSummaryStream = Box::pin(futures::stream::iter(vec![
            Ok(signed_summary(&committee, &keys, 5, false)),
            Ok(bad_boundary),
            Ok(signed_summary(&committee, &keys, 9, false)),
            Ok(good_boundary.clone()),
        ]));

        CommitteeFollower::consume(&committees, stream).await;

        // The bad boundary did not advance or panic; the genuine one installed
        // committee[1] exactly once.
        assert_eq!(
            committees.head_epoch(),
            1,
            "the genuine boundary installs committee[1]; the bad one is benign"
        );

        // Replaying the genuine boundary now that the head is past epoch 0 is a
        // head-guarded no-op — no second install, head unchanged.
        CommitteeFollower::capture(&committees, &good_boundary);
        assert_eq!(
            committees.head_epoch(),
            1,
            "replaying an already-installed boundary must not advance the head again"
        );
    }
}
