// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Joiner-side bootstrap verification of the cross-epoch handoff cert.
//!
//! A node that becomes a validator at epoch `E` having NOT been in the
//! committee at `E-1` is a true joiner. Its off-chain trust chain into
//! epoch `E` is anchored by the `CertifiedHandoffAttestation` for epoch
//! `E-1` — the cert that the `E-1` committee produced, attesting the
//! handoff into `E` (it pins the validator-mpc_data and network-key
//! output digests `E` inherits, and binds the hash of `E`'s committee
//! pubkey set).
//!
//! This task fetches that cert from current-committee peers over P2P
//! and verifies it with [`verify_joiner_bootstrap_cert`] — epoch-bound
//! to `E-1`, signatures checked against the `E-1` committee, and the
//! pinned next-committee hash matched against `E`'s own committee. A
//! verified cert is the joiner's cryptographic confirmation that the
//! committee it's joining from genuinely certified this handoff;
//! failure surfaces a tampered/wrong bootstrap (a malicious peer
//! serving a cert for the wrong committee or a forged one).
//!
//! The fetch is injected behind [`HandoffCertSource`] so the
//! fetch/retry/verify loop is unit-testable without an Anemo network,
//! and the per-cert verification is injected as a closure so the loop
//! is exercised without standing up committees + crypto. Production
//! wires the P2P fetch and `verify_joiner_bootstrap_cert`.

use anemo::{Network, PeerId};
use ika_network::mpc_artifacts::fetch_certified_handoff_attestation;
use ika_types::committee::EpochId;
use ika_types::error::IkaResult;
use ika_types::handoff::CertifiedHandoffAttestation;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Fetches candidate `CertifiedHandoffAttestation`s for `prior_epoch`
/// from peers. Returns every cert a peer offered this round (callers
/// verify each); an empty vec means no peer had one yet.
#[async_trait::async_trait]
pub trait HandoffCertSource: Send + Sync {
    async fn fetch_candidates(&self, prior_epoch: EpochId) -> Vec<CertifiedHandoffAttestation>;
}

/// Production fetch: ask each current-committee peer over Anemo for the
/// `prior_epoch` cert, collecting whatever they return.
pub struct P2pHandoffCertSource {
    network: Network,
    peers: Vec<PeerId>,
}

impl P2pHandoffCertSource {
    pub fn new(network: Network, peers: Vec<PeerId>) -> Self {
        Self { network, peers }
    }
}

#[async_trait::async_trait]
impl HandoffCertSource for P2pHandoffCertSource {
    async fn fetch_candidates(&self, prior_epoch: EpochId) -> Vec<CertifiedHandoffAttestation> {
        let futures =
            self.peers.iter().map(|peer_id| {
                let peer_id = *peer_id;
                async move {
                    fetch_certified_handoff_attestation(&self.network, peer_id, prior_epoch).await
                }
            });
        futures::future::join_all(futures)
            .await
            .into_iter()
            .filter_map(|r| match r {
                Ok(Some(cert)) => Some(cert),
                Ok(None) => None,
                Err(e) => {
                    debug!(error = %e, "handoff cert fetch transport error");
                    None
                }
            })
            .collect()
    }
}

/// Verifies a candidate cert (epoch-bound, prior committee, pubkey-set
/// hash). Boxed so the node can capture the prior committee + provider
/// + expected next-committee, and tests can inject a stub.
pub type CertVerifier = Arc<dyn Fn(&CertifiedHandoffAttestation) -> IkaResult<()> + Send + Sync>;

#[derive(Debug, Clone, Copy)]
pub struct BootstrapRetryConfig {
    pub retry_interval: Duration,
    pub max_attempts: usize,
}

/// Result of the bootstrap verification loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// A fetched cert verified against the prior committee.
    Verified,
    /// No peer served a cert that verified within the attempt budget.
    Unverified,
}

pub struct JoinerBootstrapVerifier {
    /// The epoch whose handoff cert anchors this joiner — `E - 1`.
    prior_epoch: EpochId,
    source: Arc<dyn HandoffCertSource>,
    verify: CertVerifier,
    config: BootstrapRetryConfig,
}

impl JoinerBootstrapVerifier {
    pub fn new(
        prior_epoch: EpochId,
        source: Arc<dyn HandoffCertSource>,
        verify: CertVerifier,
        config: BootstrapRetryConfig,
    ) -> Self {
        Self {
            prior_epoch,
            source,
            verify,
            config,
        }
    }

    /// Fetch + verify with retry. Returns once a candidate verifies, or
    /// after exhausting the attempt budget. Does NOT halt the validator
    /// on failure — a missing/unverifiable cert is surfaced as an
    /// `error!` for operators rather than bricking a node whose peers
    /// may not have distributed the cert yet. (Fail-closed enforcement
    /// — refusing to participate until verified — is a deliberate
    /// follow-up; this wiring establishes the verified anchor and makes
    /// tampering observable.)
    pub async fn run(self) -> BootstrapOutcome {
        for attempt in 0..self.config.max_attempts {
            let candidates = self.source.fetch_candidates(self.prior_epoch).await;
            for cert in &candidates {
                match (self.verify)(cert) {
                    Ok(()) => {
                        info!(
                            prior_epoch = self.prior_epoch,
                            attempt,
                            "joiner bootstrap handoff cert verified against prior committee"
                        );
                        return BootstrapOutcome::Verified;
                    }
                    Err(e) => {
                        debug!(
                            prior_epoch = self.prior_epoch,
                            error = ?e,
                            "candidate handoff cert failed verification; trying next/again"
                        );
                    }
                }
            }
            if attempt + 1 < self.config.max_attempts {
                tokio::time::sleep(self.config.retry_interval).await;
            }
        }
        error!(
            prior_epoch = self.prior_epoch,
            max_attempts = self.config.max_attempts,
            "joiner could not fetch + verify a handoff cert for the prior epoch — \
             its cross-epoch off-chain trust anchor is unconfirmed (peers may not \
             have distributed the cert, or a verification mismatch occurred)"
        );
        BootstrapOutcome::Unverified
    }
}

/// Warn helper for the node wiring when the prior committee or its
/// pubkeys can't be assembled (so the verifier can't run at all).
pub fn warn_bootstrap_inputs_unavailable(prior_epoch: EpochId, reason: &str) {
    warn!(
        prior_epoch,
        reason, "skipping joiner bootstrap cert verification: inputs unavailable"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ika_types::error::IkaError;
    use ika_types::handoff::HandoffAttestation;
    use parking_lot::Mutex;

    fn dummy_cert(epoch: EpochId) -> CertifiedHandoffAttestation {
        CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch,
                next_committee_pubkey_set_hash: [0u8; 32],
                items: vec![],
            },
            signatures: vec![],
        }
    }

    struct ScriptedSource {
        rounds: Vec<Vec<CertifiedHandoffAttestation>>,
        calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl HandoffCertSource for ScriptedSource {
        async fn fetch_candidates(
            &self,
            _prior_epoch: EpochId,
        ) -> Vec<CertifiedHandoffAttestation> {
            let mut calls = self.calls.lock();
            let idx = (*calls).min(self.rounds.len().saturating_sub(1));
            *calls += 1;
            self.rounds.get(idx).cloned().unwrap_or_default()
        }
    }

    fn run_loop(
        rounds: Vec<Vec<CertifiedHandoffAttestation>>,
        verify: CertVerifier,
        max_attempts: usize,
    ) -> (BootstrapOutcome, usize) {
        let source = Arc::new(ScriptedSource {
            rounds,
            calls: Mutex::new(0),
        });
        let verifier = JoinerBootstrapVerifier::new(
            6,
            source.clone(),
            verify,
            BootstrapRetryConfig {
                retry_interval: Duration::from_millis(1),
                max_attempts,
            },
        );
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(verifier.run());
        (outcome, *source.calls.lock())
    }

    #[test]
    fn verifies_first_accepting_candidate_and_stops() {
        // Round 1: one candidate that verifies → stop immediately.
        let verify: CertVerifier = Arc::new(|_cert| Ok(()));
        let (outcome, calls) = run_loop(vec![vec![dummy_cert(6)]], verify, 5);
        assert_eq!(outcome, BootstrapOutcome::Verified);
        assert_eq!(calls, 1);
    }

    #[test]
    fn retries_until_a_peer_serves_a_verifiable_cert() {
        // Rounds 1-2: no peer has it. Round 3: a verifiable cert.
        let verify: CertVerifier = Arc::new(|_cert| Ok(()));
        let rounds = vec![vec![], vec![], vec![dummy_cert(6)]];
        let (outcome, calls) = run_loop(rounds, verify, 5);
        assert_eq!(outcome, BootstrapOutcome::Verified);
        assert_eq!(calls, 3);
    }

    #[test]
    fn rejects_bad_candidates_and_keeps_trying() {
        // Every round serves a candidate, but verification always
        // fails (e.g. wrong committee). Exhaust the budget Unverified.
        let verify: CertVerifier = Arc::new(|_cert| Err(IkaError::Unknown("nope".into())));
        let (outcome, calls) = run_loop(vec![vec![dummy_cert(6)]], verify, 4);
        assert_eq!(outcome, BootstrapOutcome::Unverified);
        assert_eq!(calls, 4);
    }

    #[test]
    fn picks_the_verifiable_cert_among_several_candidates() {
        // Two candidates in one round; only the second verifies.
        let good = dummy_cert(6);
        let good_hash = good.attestation.next_committee_pubkey_set_hash;
        let verify: CertVerifier = Arc::new(move |cert| {
            // "good" is the one whose (here trivial) hash matches; the
            // bad one we mark with a different epoch.
            if cert.attestation.epoch == 6
                && cert.attestation.next_committee_pubkey_set_hash == good_hash
            {
                Ok(())
            } else {
                Err(IkaError::Unknown("bad candidate".into()))
            }
        });
        let bad = dummy_cert(99);
        let (outcome, calls) = run_loop(vec![vec![bad, good]], verify, 3);
        assert_eq!(outcome, BootstrapOutcome::Verified);
        assert_eq!(calls, 1);
    }
}
