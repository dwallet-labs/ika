// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Joiner-side task that fans a next-epoch validator's
//! `ValidatorMpcDataAnnouncement` out to the current committee over
//! P2P, with retry.
//!
//! A validator selected into the next-epoch committee (`V_{e+1}`)
//! but not yet in the current committee can't submit to consensus
//! itself. Instead it signs its announcement with its Ed25519
//! consensus key and fans the signed envelope out to current-
//! committee peers; any one honest relayer forwards it into
//! consensus (see `announcement_relay`).
//!
//! Retry is load-bearing: a relayer may reject with
//! `UnregisteredJoiner` if its own view of `V_{e+1}` hasn't caught
//! up yet, or a peer may be transiently unreachable. The joiner
//! can't read consensus to confirm inclusion (it isn't a
//! participant), so it re-fans-out on a fixed cadence until it has
//! collected acceptances from enough distinct peers (so at least
//! one is honest) or a bounded attempt budget is exhausted.

use crate::blob_cache::BlobCache;
use crate::validator_metadata::{
    derive_mpc_data_blob, now_ms, sign_validator_mpc_data_announcement,
};
use anemo::PeerId;
use dwallet_rng::RootSeed;
use fastcrypto::ed25519::Ed25519KeyPair;
use ika_network::mpc_artifacts::{
    SubmitMpcDataAnnouncementResponse, mpc_data_blob_hash, submit_announcement_to_committee,
};
use ika_types::committee::EpochId;
use ika_types::crypto::AuthorityName;
use ika_types::validator_metadata::SignedValidatorMpcDataAnnouncement;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Per-peer outcome of one fan-out attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanoutOutcome {
    /// The relayer queued the announcement for consensus submission.
    Accepted,
    /// The relayer declined (e.g. `UnregisteredJoiner` while its
    /// view of the next committee lags) — retryable.
    Rejected(String),
    /// Transport-level failure reaching the peer — retryable.
    TransportError(String),
}

/// Fans a signed announcement out to the current committee. Injected
/// so the retry loop can be unit-tested without a live Anemo network.
#[async_trait::async_trait]
pub trait AnnouncementFanout: Send + Sync {
    async fn fan_out(
        &self,
        announcement: &SignedValidatorMpcDataAnnouncement,
    ) -> Vec<(PeerId, FanoutOutcome)>;
}

/// Production fan-out over Anemo to a fixed current-committee peer set.
pub struct P2pAnnouncementFanout {
    network: anemo::Network,
    peers: Vec<PeerId>,
}

impl P2pAnnouncementFanout {
    pub fn new(network: anemo::Network, peers: Vec<PeerId>) -> Self {
        Self { network, peers }
    }
}

#[async_trait::async_trait]
impl AnnouncementFanout for P2pAnnouncementFanout {
    async fn fan_out(
        &self,
        announcement: &SignedValidatorMpcDataAnnouncement,
    ) -> Vec<(PeerId, FanoutOutcome)> {
        submit_announcement_to_committee(&self.network, &self.peers, announcement.clone())
            .await
            .into_iter()
            .map(|(peer_id, result)| {
                let outcome = match result {
                    Ok(SubmitMpcDataAnnouncementResponse::Accepted) => FanoutOutcome::Accepted,
                    Ok(SubmitMpcDataAnnouncementResponse::Rejected { reason }) => {
                        FanoutOutcome::Rejected(reason)
                    }
                    Err(e) => FanoutOutcome::TransportError(e.to_string()),
                };
                (peer_id, outcome)
            })
            .collect()
    }
}

/// Tunables for the retry loop. `min_accepts` distinct accepting
/// peers ensures at least one honest relayer (set it to the
/// committee's validity threshold f+1). `max_attempts` bounds the
/// window so a joiner that can never be accepted (e.g. never
/// registered) doesn't loop forever.
#[derive(Debug, Clone, Copy)]
pub struct JoinerFanoutConfig {
    pub min_accepts: usize,
    pub retry_interval: Duration,
    pub max_attempts: usize,
}

pub struct JoinerAnnouncementSender {
    authority: AuthorityName,
    next_epoch: EpochId,
    root_seed: RootSeed,
    consensus_keypair: Arc<Ed25519KeyPair>,
    blob_cache: Arc<BlobCache>,
    fanout: Arc<dyn AnnouncementFanout>,
    config: JoinerFanoutConfig,
}

impl JoinerAnnouncementSender {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: AuthorityName,
        next_epoch: EpochId,
        root_seed: RootSeed,
        consensus_keypair: Arc<Ed25519KeyPair>,
        blob_cache: Arc<BlobCache>,
        fanout: Arc<dyn AnnouncementFanout>,
        config: JoinerFanoutConfig,
    ) -> Self {
        Self {
            authority,
            next_epoch,
            root_seed,
            consensus_keypair,
            blob_cache,
            fanout,
            config,
        }
    }

    /// Derive + persist our own blob, build the signed announcement,
    /// then fan it out with retry until enough distinct peers accept
    /// or the attempt budget is exhausted.
    pub async fn run(self) {
        let signed = match self.build_signed_announcement() {
            Ok(signed) => signed,
            Err(e) => {
                warn!(error = %e, "joiner announcement sender: failed to build announcement; not fanning out");
                return;
            }
        };
        self.run_fanout_loop(&signed).await;
    }

    /// The retry loop, factored out of `run` so it can be unit-tested
    /// without deriving/persisting a real blob.
    async fn run_fanout_loop(&self, signed: &SignedValidatorMpcDataAnnouncement) {
        let mut accepted_peers: HashSet<PeerId> = HashSet::new();
        for attempt in 0..self.config.max_attempts {
            let outcomes = self.fanout.fan_out(signed).await;
            for (peer_id, outcome) in outcomes {
                match outcome {
                    FanoutOutcome::Accepted => {
                        accepted_peers.insert(peer_id);
                    }
                    FanoutOutcome::Rejected(reason) => {
                        debug!(?peer_id, reason, attempt, "joiner fan-out rejected by peer");
                    }
                    FanoutOutcome::TransportError(error) => {
                        debug!(?peer_id, error, attempt, "joiner fan-out transport error");
                    }
                }
            }
            if accepted_peers.len() >= self.config.min_accepts {
                info!(
                    epoch = self.next_epoch,
                    accepts = accepted_peers.len(),
                    attempt,
                    "joiner announcement accepted by enough peers; stopping fan-out"
                );
                return;
            }
            // Don't sleep after the final attempt.
            if attempt + 1 < self.config.max_attempts {
                tokio::time::sleep(self.config.retry_interval).await;
            }
        }
        warn!(
            epoch = self.next_epoch,
            accepts = accepted_peers.len(),
            min_accepts = self.config.min_accepts,
            max_attempts = self.config.max_attempts,
            "joiner announcement fan-out exhausted its attempt budget without \
             enough acceptances; the joiner may be excluded from the next epoch's \
             working set"
        );
    }

    fn build_signed_announcement(&self) -> anyhow::Result<SignedValidatorMpcDataAnnouncement> {
        let blob = derive_mpc_data_blob(&self.root_seed)
            .map_err(|e| anyhow::anyhow!("derive mpc_data blob: {e}"))?;
        let digest = mpc_data_blob_hash(&blob);
        // Persist our own blob locally so once we relay the digest,
        // current-committee peers can fetch the bytes from us via P2P.
        if let Err(e) = self.blob_cache.insert(digest, blob) {
            warn!(error = ?e, "joiner: failed to persist own mpc_data blob; peers can't fetch it");
        }
        let timestamp_ms = now_ms().map_err(|e| anyhow::anyhow!("now_ms: {e}"))?;
        sign_validator_mpc_data_announcement(
            self.authority,
            self.next_epoch,
            timestamp_ms,
            digest,
            &self.consensus_keypair,
        )
        .map_err(|e| anyhow::anyhow!("sign announcement: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::validator_metadata::ValidatorMpcDataAnnouncement;
    use parking_lot::Mutex;

    fn peer(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    fn test_consensus_keypair() -> Ed25519KeyPair {
        // Deterministic from a fixed seed; avoids the multiple-rand-
        // version conflict that bites direct `KeyPair::generate`
        // calls from ika-core tests. The loop tests never use the
        // key, but the struct requires one.
        use fastcrypto::ed25519::Ed25519PrivateKey;
        use fastcrypto::traits::ToFromBytes;
        let sk = Ed25519PrivateKey::from_bytes(&[3u8; 32]).unwrap();
        Ed25519KeyPair::from(sk)
    }

    fn dummy_signed() -> SignedValidatorMpcDataAnnouncement {
        // The retry loop never inspects the signature; a default
        // Ed25519 signature is fine for exercising it.
        use fastcrypto::ed25519::Ed25519Signature;
        use fastcrypto::traits::ToFromBytes;
        SignedValidatorMpcDataAnnouncement {
            announcement: ValidatorMpcDataAnnouncement {
                validator: AuthorityName::new([1; 48]),
                epoch: 5,
                timestamp_ms: 42,
                blob_hash: [0x11; 32],
            },
            joiner_sig: Ed25519Signature::from_bytes(&[0u8; 64]).unwrap(),
        }
    }

    /// Scripted fan-out: returns the outcomes for attempt `i` from a
    /// pre-loaded list, recording how many times it was called.
    struct ScriptedFanout {
        script: Vec<Vec<(PeerId, FanoutOutcome)>>,
        calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl AnnouncementFanout for ScriptedFanout {
        async fn fan_out(
            &self,
            _announcement: &SignedValidatorMpcDataAnnouncement,
        ) -> Vec<(PeerId, FanoutOutcome)> {
            let mut calls = self.calls.lock();
            let idx = (*calls).min(self.script.len().saturating_sub(1));
            *calls += 1;
            self.script.get(idx).cloned().unwrap_or_default()
        }
    }

    async fn run_with_script(
        script: Vec<Vec<(PeerId, FanoutOutcome)>>,
        min_accepts: usize,
        max_attempts: usize,
    ) -> usize {
        let fanout = Arc::new(ScriptedFanout {
            script,
            calls: Mutex::new(0),
        });
        let sender = JoinerAnnouncementSender {
            authority: AuthorityName::new([1; 48]),
            next_epoch: 5,
            // run() builds the announcement, but we override by
            // calling the loop directly to avoid blob derivation;
            // instead we test the loop via a thin reimplementation.
            root_seed: RootSeed::new([0; 32]),
            consensus_keypair: Arc::new(test_consensus_keypair()),
            blob_cache: unreachable_blob_cache(),
            fanout: fanout.clone(),
            config: JoinerFanoutConfig {
                min_accepts,
                retry_interval: Duration::from_millis(1),
                max_attempts,
            },
        };
        sender.run_fanout_loop(&dummy_signed()).await;
        *fanout.calls.lock()
    }

    // A BlobCache the test never touches (run_fanout_loop doesn't
    // derive/persist). Constructing a real one needs a temp DB, so we
    // route tests through `run_fanout_loop` which skips blob work.
    fn unreachable_blob_cache() -> Arc<BlobCache> {
        use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
        use ika_network::mpc_artifacts::InMemoryBlobStore;
        let dir = tempfile::TempDir::new().unwrap();
        let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
        // Leak the TempDir so the DB path stays valid for the test's
        // lifetime; tests are short-lived processes.
        std::mem::forget(dir);
        BlobCache::new(InMemoryBlobStore::new(), perpetual)
    }

    #[tokio::test]
    async fn stops_early_once_enough_distinct_peers_accept() {
        // First attempt: peer 1 accepts, peer 2 rejects. Second:
        // peer 2 accepts. min_accepts=2 reached on attempt 2.
        let script = vec![
            vec![
                (peer(1), FanoutOutcome::Accepted),
                (
                    peer(2),
                    FanoutOutcome::Rejected("UnregisteredJoiner".into()),
                ),
            ],
            vec![(peer(2), FanoutOutcome::Accepted)],
            vec![(peer(3), FanoutOutcome::Accepted)], // should not be reached
        ];
        let calls = run_with_script(script, 2, 5).await;
        assert_eq!(calls, 2, "should stop right after the 2nd accept");
    }

    #[tokio::test]
    async fn retries_on_unregistered_then_succeeds() {
        // Relayer rejects with UnregisteredJoiner twice, then accepts.
        let script = vec![
            vec![(
                peer(1),
                FanoutOutcome::Rejected("UnregisteredJoiner".into()),
            )],
            vec![(
                peer(1),
                FanoutOutcome::Rejected("UnregisteredJoiner".into()),
            )],
            vec![(peer(1), FanoutOutcome::Accepted)],
        ];
        let calls = run_with_script(script, 1, 5).await;
        assert_eq!(calls, 3, "retries through both rejections, accepts on 3rd");
    }

    #[tokio::test]
    async fn exhausts_attempts_when_never_accepted() {
        // Every attempt is a transport error; never reaches min_accepts.
        let script = vec![vec![(
            peer(1),
            FanoutOutcome::TransportError("down".into()),
        )]];
        let calls = run_with_script(script, 1, 4).await;
        assert_eq!(
            calls, 4,
            "fans out exactly max_attempts times, then gives up"
        );
    }

    #[tokio::test]
    async fn distinct_peers_required_not_repeat_accepts() {
        // The SAME peer accepting on every attempt only counts once;
        // min_accepts=2 is never satisfied, so we exhaust attempts.
        let script = vec![vec![(peer(1), FanoutOutcome::Accepted)]];
        let calls = run_with_script(script, 2, 3).await;
        assert_eq!(
            calls, 3,
            "one repeat-accepting peer counts once; budget exhausted"
        );
    }
}
