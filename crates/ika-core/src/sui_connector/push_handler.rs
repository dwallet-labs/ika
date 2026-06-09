// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Receive-side handler for `SuiStateMirror::push_verified_objects`.
//!
//! Trust model: pushing peer is untrusted. We verify each
//! `(object, OCSInclusionProof)` pair against our local
//! [`CommitteeStore`] before accepting. Failed pushes are dropped and
//! logged; we don't ban the peer here — that policy lives elsewhere.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anemo::{Network, PeerId, Request};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use ika_network::sui_state_mirror::{
    GetVerifiedSnapshotRequest, GetVerifiedSnapshotResponse, PushVerifiedObjectsHandler,
    PushVerifiedObjectsRequest, SuiStateMirrorClient,
};
use sui_light_client::proof::base::{ProofContents, ProofContentsVerifier, ProofTarget};
use sui_light_client::proof::ocs::{OCSInclusionProof, OCSProof};
use tracing::{debug, info, warn};

use crate::sui_connector::committee_store::CommitteeStore;
use crate::sui_connector::ocs_metrics::OcsMetrics;
use crate::sui_connector::ocs_verifier::OcsVerifyingClient;
use crate::sui_connector::verified_state_cache::SharedVerifiedStateCache;

pub struct IkaPushHandler {
    committees: Arc<CommitteeStore>,
    /// Used to ratchet on demand if a pushed proof references an epoch
    /// our committee store hasn't reached yet (Sui epoch boundary race).
    ocs: Arc<OcsVerifyingClient>,
    metrics: Arc<OcsMetrics>,
    /// Write target for the verified state cache. Populated only after
    /// every entry's proof has been verified against the local
    /// `CommitteeStore`.
    cache: SharedVerifiedStateCache,
    /// anemo network used to pull a `GetVerifiedSnapshot` from a peer when
    /// a push gap is detected. Set after the network is bound (the handler
    /// is constructed before the p2p network exists). `None` until then —
    /// gap recovery is simply skipped while unset.
    network: ArcSwapOption<Network>,
    /// Guards against piling up concurrent recovery pulls: at most one
    /// `GetVerifiedSnapshot` recovery runs at a time.
    recovery_in_flight: Arc<AtomicBool>,
}

impl IkaPushHandler {
    pub fn new(
        committees: Arc<CommitteeStore>,
        ocs: Arc<OcsVerifyingClient>,
        metrics: Arc<OcsMetrics>,
        cache: SharedVerifiedStateCache,
    ) -> Self {
        Self {
            committees,
            ocs,
            metrics,
            cache,
            network: ArcSwapOption::empty(),
            recovery_in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Hand the handler the bound anemo network so push-gap recovery can
    /// pull a `GetVerifiedSnapshot` from the peer that revealed the gap.
    /// Called once, after `create_p2p_network`.
    pub fn set_network(&self, network: Network) {
        self.network.store(Some(Arc::new(network)));
    }

    /// On a detected push gap, pull a full verified snapshot from `from`,
    /// verify every `(object, proof)` against the local committee store,
    /// and fold it into the cache. Best-effort and non-blocking: spawned
    /// onto the runtime, deduplicated by `recovery_in_flight`, and a no-op
    /// if the network isn't set or the peer is unreachable. The local
    /// pusher would eventually refill the cache regardless; this just
    /// closes the gap promptly.
    fn spawn_gap_recovery(&self, from: PeerId) {
        let Some(network) = self.network.load_full() else {
            debug!(?from, "push-gap recovery skipped: network not yet set");
            return;
        };
        if self
            .recovery_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            debug!(?from, "push-gap recovery already in flight; skipping");
            return;
        }
        let committees = self.committees.clone();
        let cache = self.cache.clone();
        let metrics = self.metrics.clone();
        let in_flight = self.recovery_in_flight.clone();
        tokio::spawn(async move {
            recover_from_peer(&network, from, &committees, &cache, &metrics).await;
            in_flight.store(false, Ordering::Release);
        });
    }

    /// Verify every `(object, proof)` in `push` against the local
    /// committee for `push.summary.epoch()`. Borrows `push` so the
    /// caller can hand the same value to `cache.absorb_push` on
    /// success without an extra deep clone.
    fn verify(&self, push: &PushVerifiedObjectsRequest) -> Result<usize, (String, &'static str)> {
        let epoch = push.summary.epoch();
        let committee = self.committees.committee(epoch).ok_or_else(|| {
            (
                format!("no Sui committee for epoch {epoch}"),
                "missing_committee",
            )
        })?;

        // Per-summary BLS dedup: every object in a push shares `push.summary`,
        // so BLS-verify it once and reuse the `VerifiedCheckpoint` for each
        // object's (per-entry) inclusion check.
        let verified_summary = push
            .summary
            .clone()
            .try_into_verified(&committee)
            .map_err(|e| {
                (
                    format!("push summary BLS verify (epoch {epoch}): {e}"),
                    "bad_proof",
                )
            })?;

        let mut accepted = 0usize;
        for entry in &push.objects_with_proofs {
            let object_ref = entry.object.compute_object_reference();
            // `OCSInclusionProof` isn't `Clone`; round-trip through
            // bcs so the verifier can take ownership without us having
            // to consume `push`.
            let proof_clone: OCSInclusionProof = {
                let bytes = bcs::to_bytes(&entry.proof)
                    .map_err(|e| (format!("encode proof for {object_ref:?}: {e}"), "bad_proof"))?;
                bcs::from_bytes(&bytes)
                    .map_err(|e| (format!("decode proof for {object_ref:?}: {e}"), "bad_proof"))?
            };
            ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof_clone))
                .verify(
                    &ProofTarget::new_ocs_inclusion(object_ref),
                    &verified_summary,
                )
                .map_err(|e| (format!("proof for {object_ref:?}: {e:?}"), "bad_proof"))?;
            accepted += 1;
        }
        Ok(accepted)
    }
}

#[async_trait]
impl PushVerifiedObjectsHandler for IkaPushHandler {
    async fn handle_pushed_verified_objects(
        &self,
        from: PeerId,
        push: PushVerifiedObjectsRequest,
    ) -> Result<(), String> {
        self.metrics.push_received_total.inc();

        // First attempt; if missing_committee, ratchet once and retry.
        // Closes the tight Sui epoch-boundary race where the sender already
        // saw committee[E] but our local ratchet hasn't ticked yet.
        let result = match self.verify(&push) {
            Err((_, "missing_committee")) => {
                if let Err(e) = self.ocs.ratchet_to_current_epoch().await {
                    warn!(?from, error = ?e, "reactive ratchet failed");
                } else {
                    info!(
                        ?from,
                        head = self.committees.head_epoch(),
                        "ratcheted in response to missing-committee push; retrying"
                    );
                }
                self.verify(&push)
            }
            other => other,
        };

        match result {
            Ok(count) => {
                // Detect dropped pushes by comparing the sender's
                // declared previous push seq against our local cache
                // head. `prev > head` ⇒ at least one push was lost; bump
                // a metric, log, and kick off a `GetVerifiedSnapshot`
                // pull from the sender to refill the gap promptly.
                if let Some(prev) = push.prev_checkpoint_seq {
                    let head = self.cache.head_seq();
                    if prev > head && head > 0 {
                        self.metrics.push_gap_detected_total.inc();
                        warn!(
                            ?from,
                            prev_seq = prev,
                            local_head_seq = head,
                            "push gap detected — at least one prior push lost; recovering"
                        );
                        self.spawn_gap_recovery(from);
                    }
                }
                // Fold the just-verified state into the local cache.
                // Step 2: cache is shadow-populated; readers do not yet
                // hit it. Done here (post-verification) so we never
                // expose unverified state to a future consumer.
                self.cache.absorb_push(&push);
                debug!(?from, count, "accepted pushed verified objects");
                self.metrics.push_accepted_total.inc_by(count as u64);
                Ok(())
            }
            Err((msg, reason)) => {
                self.metrics
                    .push_rejected_total
                    .with_label_values(&[reason])
                    .inc();
                warn!(?from, error = %msg, "rejected pushed verified objects");
                Err(msg)
            }
        }
    }
}

/// Pull a `GetVerifiedSnapshot` from `from`, verify every entry against
/// the local committee store, and (only if *all* entries verify) fold the
/// snapshot into the cache. All-or-nothing: a single bad entry rejects the
/// whole pull rather than letting a peer poison part of the cache.
async fn recover_from_peer(
    network: &Network,
    from: PeerId,
    committees: &Arc<CommitteeStore>,
    cache: &SharedVerifiedStateCache,
    metrics: &Arc<OcsMetrics>,
) {
    let Some(peer) = network.peer(from) else {
        debug!(?from, "push-gap recovery: peer not connected");
        return;
    };
    let mut client = SuiStateMirrorClient::new(peer);
    let request = Request::new(GetVerifiedSnapshotRequest {}).with_timeout(Duration::from_secs(30));
    let snapshot = match client.get_verified_snapshot(request).await {
        Ok(resp) => resp.into_inner(),
        Err(status) => {
            warn!(
                ?from,
                ?status,
                "push-gap recovery: GetVerifiedSnapshot failed"
            );
            return;
        }
    };
    match verify_snapshot(committees, &snapshot) {
        Ok(count) => {
            // Verified above; `absorb_snapshot` trusts its input.
            cache.absorb_snapshot(&snapshot);
            metrics.push_gap_recovered_total.inc();
            info!(
                ?from,
                count,
                head_seq = snapshot.head_seq,
                "push-gap recovery: absorbed verified snapshot"
            );
        }
        Err(e) => warn!(
            ?from,
            error = %e,
            "push-gap recovery: snapshot failed verification; dropping"
        ),
    }
}

/// Verify every `(object, proof)` in a `GetVerifiedSnapshot` response
/// against the committee for the summary it anchors to. Returns the number
/// of entries verified, or the first failure.
fn verify_snapshot(
    committees: &Arc<CommitteeStore>,
    snapshot: &GetVerifiedSnapshotResponse,
) -> Result<usize, String> {
    // Per-summary BLS dedup: BLS-verify each distinct summary once (the
    // `summaries` map is 1:1 with checkpoint seq), then per entry do only the
    // Merkle/artifacts-digest inclusion check against the reused
    // `VerifiedCheckpoint`.
    let mut verified_summaries: std::collections::HashMap<
        sui_types::messages_checkpoint::CheckpointSequenceNumber,
        sui_types::messages_checkpoint::VerifiedCheckpoint,
    > = std::collections::HashMap::new();
    let mut verified = 0usize;
    for entry in &snapshot.objects_with_proofs {
        let seq = entry.checkpoint_seq;
        if !verified_summaries.contains_key(&seq) {
            let summary = snapshot.summaries.get(&seq).ok_or_else(|| {
                format!(
                    "entry {:?} references missing summary {seq}",
                    entry.object.id(),
                )
            })?;
            let epoch = summary.epoch();
            let committee = committees
                .committee(epoch)
                .ok_or_else(|| format!("no Sui committee for epoch {epoch}"))?;
            let verified_summary = summary
                .clone()
                .try_into_verified(&committee)
                .map_err(|e| format!("snapshot summary BLS verify (epoch {epoch}): {e}"))?;
            verified_summaries.insert(seq, verified_summary);
        }
        // unwrap: inserted just above for this `seq`.
        let verified_summary = verified_summaries.get(&seq).expect("summary present");

        let object_ref = entry.object.compute_object_reference();
        // `OCSInclusionProof` isn't `Clone`; round-trip through bcs so the
        // verifier can take ownership.
        let proof_clone: OCSInclusionProof = {
            let bytes = bcs::to_bytes(&entry.proof)
                .map_err(|e| format!("encode proof for {object_ref:?}: {e}"))?;
            bcs::from_bytes(&bytes).map_err(|e| format!("decode proof for {object_ref:?}: {e}"))?
        };
        ProofContents::ObjectCheckpointStateProof(OCSProof::Inclusion(proof_clone))
            .verify(
                &ProofTarget::new_ocs_inclusion(object_ref),
                verified_summary,
            )
            .map_err(|e| format!("proof for {object_ref:?}: {e:?}"))?;
        verified += 1;
    }
    Ok(verified)
}
