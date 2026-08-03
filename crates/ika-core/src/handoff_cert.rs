// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Handoff-attestation cert subsystem: building, signing, verifying,
//! and aggregating the cross-epoch `HandoffAttestation` that the
//! outgoing committee certifies and joiners verify on bootstrap.
//!
//! Extracted from `validator_metadata` so the cert machinery is
//! navigable on its own. `validator_metadata` re-exports these
//! symbols, so existing `crate::validator_metadata::*` paths keep
//! working.

use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::traits::{Signer, VerifyingKey};
use ika_types::committee::{Committee, CommitteeTrait, EpochId, StakeUnit};
use ika_types::crypto::AuthorityName;
use ika_types::error::{IkaError, IkaResult};
use ika_types::handoff::{
    CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey, HandoffSignatureMessage,
};
use ika_types::intent::{Intent, IntentMessage, IntentScope};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, warn};

/// Builds a `HandoffAttestation` from a (possibly unsorted) list of
/// items. Items are sorted strictly ascending by `HandoffItemKey`
/// before storage so the canonical encoding is identical across all
/// signers (BCS-encoded sorted Vec). Duplicate keys are rejected —
/// the handoff layer treats two entries for the same key as a
/// protocol violation, not a "latest wins".
pub fn build_handoff_attestation(
    epoch: EpochId,
    next_committee_pubkey_set_hash: [u8; 32],
    items: Vec<(HandoffItemKey, [u8; 32])>,
) -> IkaResult<HandoffAttestation> {
    let mut sorted = items;
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(IkaError::Unknown(
            "duplicate HandoffItemKey in handoff attestation items".to_string(),
        ));
    }
    Ok(HandoffAttestation {
        epoch,
        next_committee_pubkey_set_hash,
        items: sorted,
    })
}

/// The canonical next-committee pubkey set that BOTH the handoff
/// producer (`HandoffSignatureSender`) and the joiner verifier
/// (`verify_joiner_bootstrap_cert`) hash into
/// `HandoffAttestation.next_committee_pubkey_set_hash`: the full
/// committee membership (`voting_rights`).
///
/// Deriving the set through this one helper on both sides is what
/// guarantees the producer's attestation and the joiner's `expected`
/// stay reproducible from each other. The membership is
/// chain-deterministic — every signer's assembled next committee and
/// every joiner's installed committee carry the identical
/// `voting_rights` — so a signer must NOT narrow it by the frozen
/// mpc_data set: the freeze filters which members' *class-groups* are
/// assembled, not who sits on the committee. Narrowing it is exactly
/// what made honest certs unverifiable by the joiners they certify
/// whenever the freeze excluded a still-seated member.
pub fn next_committee_pubkey_set(committee: &Committee) -> Vec<AuthorityName> {
    committee
        .voting_rights
        .iter()
        .map(|(name, _)| *name)
        .collect()
}

/// Blake2b256 digest of the next committee's BLS pubkey set. Pubkeys
/// are deduplicated and sorted strictly ascending before BCS encoding,
/// so callers don't need to normalize beforehand. This is the value
/// embedded in `HandoffAttestation.next_committee_pubkey_set_hash`;
/// verifiers recompute it from the next committee they observe and
/// reject any cert whose hash doesn't match.
pub fn hash_next_committee_pubkey_set(
    pubkeys: impl IntoIterator<Item = AuthorityName>,
) -> [u8; 32] {
    let mut sorted: Vec<AuthorityName> = pubkeys.into_iter().collect();
    sorted.sort();
    sorted.dedup();
    let bytes = bcs::to_bytes(&sorted).expect("AuthorityName Vec is always BCS-encodable");
    let mut hasher = Blake2b256::default();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Signs a `HandoffAttestation` with the validator's **consensus**
/// (Ed25519) keypair — *not* the BLS authority key. Cross-validator
/// off-chain attestations like this one use the consensus key, which
/// joiners look up against the previous committee's on-chain validator
/// info as `consensus_pubkey`.
///
/// The signing domain is
/// `bcs(IntentMessage::new(Intent::ika_app(HandoffAttestation), attestation))`;
/// the attestation itself carries the epoch, so we don't bind the
/// signature to an external epoch parameter.
pub fn sign_handoff_attestation(
    attestation: HandoffAttestation,
    signer: AuthorityName,
    consensus_keypair: &Ed25519KeyPair,
) -> HandoffSignatureMessage {
    let intent_msg = IntentMessage::new(
        Intent::ika_app(IntentScope::HandoffAttestation),
        attestation.clone(),
    );
    let bytes = bcs::to_bytes(&intent_msg).expect("intent message BCS-encodable");
    let signature: Ed25519Signature = consensus_keypair.sign(&bytes);
    HandoffSignatureMessage {
        attestation,
        signer,
        signature,
    }
}

/// Provider for looking up a signer's **consensus pubkey** (Ed25519).
/// Backed off-chain by Sui RPC over the previous-epoch committee's
/// `StakingPool.validator_info.consensus_pubkey_bytes`. Returning
/// `None` means "I don't have a consensus pubkey for this signer" —
/// the caller drops the signature.
pub trait ConsensusPubkeyProvider: Send + Sync + 'static {
    fn consensus_pubkey(&self, signer: &AuthorityName) -> Option<Ed25519PublicKey>;
}

/// In-memory `ConsensusPubkeyProvider` for tests and as the empty
/// default before the syncer is up.
pub struct StaticConsensusPubkeyProvider {
    keys: BTreeMap<AuthorityName, Ed25519PublicKey>,
}

impl StaticConsensusPubkeyProvider {
    pub fn empty() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }
}

impl FromIterator<(AuthorityName, Ed25519PublicKey)> for StaticConsensusPubkeyProvider {
    fn from_iter<I: IntoIterator<Item = (AuthorityName, Ed25519PublicKey)>>(items: I) -> Self {
        Self {
            keys: items.into_iter().collect(),
        }
    }
}

impl ConsensusPubkeyProvider for StaticConsensusPubkeyProvider {
    fn consensus_pubkey(&self, signer: &AuthorityName) -> Option<Ed25519PublicKey> {
        self.keys.get(signer).cloned()
    }
}

/// A `Committee` is itself a consensus-pubkey provider: it carries each
/// member's consensus key, so handoff verification reads the keys straight
/// from the committee it verifies against — no side channel to populate.
impl ConsensusPubkeyProvider for Committee {
    fn consensus_pubkey(&self, signer: &AuthorityName) -> Option<Ed25519PublicKey> {
        self.consensus_key(signer).cloned()
    }
}

/// Outcome of verifying a single `HandoffSignatureMessage`. Anything
/// other than `Accept` is non-fatal — the caller drops the message
/// and waits for the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffSignatureVerdict {
    Accept,
    /// The provider doesn't know about `signer`'s consensus pubkey.
    UnknownSigner,
    /// `signer != msg.signer`, or signature failed to verify.
    InvalidSignature,
    /// `msg.attestation` doesn't equal the expected attestation —
    /// the signer attested to a different bundle than this validator
    /// computed. Could mean a software bug, a divergent view, or a
    /// stale signature from before a freeze decision.
    AttestationMismatch,
}

/// Verifies a single handoff signature against the expected attestation
/// and a consensus pubkey provider. The attestation parameter is what
/// THIS validator computed; `msg.attestation` must equal it.
pub fn verify_handoff_signature(
    msg: &HandoffSignatureMessage,
    expected: &HandoffAttestation,
    provider: &dyn ConsensusPubkeyProvider,
) -> HandoffSignatureVerdict {
    if &msg.attestation != expected {
        return HandoffSignatureVerdict::AttestationMismatch;
    }
    let Some(pubkey) = provider.consensus_pubkey(&msg.signer) else {
        return HandoffSignatureVerdict::UnknownSigner;
    };
    let intent_msg = IntentMessage::new(
        Intent::ika_app(IntentScope::HandoffAttestation),
        msg.attestation.clone(),
    );
    let bytes = bcs::to_bytes(&intent_msg).expect("intent message BCS-encodable");
    match pubkey.verify(&bytes, &msg.signature) {
        Ok(()) => HandoffSignatureVerdict::Accept,
        Err(_) => HandoffSignatureVerdict::InvalidSignature,
    }
}

/// Accumulates per-signer handoff signatures for a fixed attestation
/// and emits a `CertifiedHandoffAttestation` once stake reaches the
/// committee's quorum threshold. It keeps collecting past quorum (up
/// to the full committee), enriching the cert with each new signer so
/// the cert carries slack — a signer that departs before a future
/// joiner verifies the cert can then be dropped while a quorum of the
/// rest still validates the handoff.
///
/// Ed25519 doesn't aggregate, so the cert is a list of
/// `(signer, signature)` pairs rather than a single aggregate sig.
pub struct HandoffAggregator {
    committee: Arc<Committee>,
    attestation: HandoffAttestation,
    signatures: BTreeMap<AuthorityName, Ed25519Signature>,
    accumulated_stake: StakeUnit,
    certified: Option<CertifiedHandoffAttestation>,
}

impl HandoffAggregator {
    pub fn new(committee: Arc<Committee>, attestation: HandoffAttestation) -> Self {
        Self {
            committee,
            attestation,
            signatures: BTreeMap::new(),
            accumulated_stake: 0,
            certified: None,
        }
    }

    pub fn attestation(&self) -> &HandoffAttestation {
        &self.attestation
    }

    pub fn certified(&self) -> Option<&CertifiedHandoffAttestation> {
        self.certified.as_ref()
    }

    /// Number of distinct signers whose verified signature has been
    /// inserted so far. For observability (metrics) only.
    pub fn signer_count(&self) -> usize {
        self.signatures.len()
    }

    /// Stake accumulated by the inserted verified signatures so far.
    /// For observability (metrics) only — quorum is stake-weighted.
    pub fn accumulated_stake(&self) -> StakeUnit {
        self.accumulated_stake
    }

    /// Inserts a signature. Caller is responsible for having already
    /// run `verify_handoff_signature` against this validator's
    /// expected attestation — `insert_verified` trusts that.
    ///
    /// Returns `Some(cert)` whenever this insert produces *or enriches*
    /// the certified attestation: the first time the running stake
    /// crosses quorum, and on every later insert of a new signer (which
    /// appends that signature to the cert). Returns `None` when the
    /// insert doesn't advance the cert — a non-member, a
    /// replayed/replacement signature for a signer already counted, or
    /// stake still below quorum.
    ///
    /// Collecting past quorum (up to the full committee) is deliberate:
    /// the extra signatures give the cert slack, so a signer that
    /// departs before a future joiner verifies the cert can be dropped
    /// at verification while a quorum of the remaining signers still
    /// validates the handoff.
    pub fn insert_verified(
        &mut self,
        signer: AuthorityName,
        signature: Ed25519Signature,
    ) -> Option<&CertifiedHandoffAttestation> {
        let weight = self.committee.weight(&signer);
        if weight == 0 {
            // Not a member of the committee that's signing this
            // handoff; reject silently rather than mutate state.
            return None;
        }
        if self.signatures.insert(signer, signature).is_some() {
            // Replaced an existing signature for the same signer —
            // don't double-count their stake. (Replacement is
            // tolerated for resilience: a flaky signer could
            // re-submit a fresher signature.)
            return None;
        }
        self.accumulated_stake = self.accumulated_stake.saturating_add(weight);
        if self.accumulated_stake < self.committee.quorum_threshold() {
            return None;
        }
        // At or past quorum: (re)build the cert with every signature
        // collected so far, so each new signer enriches the cert (and
        // the caller re-persists the richer cert).
        let signatures = self
            .signatures
            .iter()
            .map(|(name, sig)| (*name, sig.clone()))
            .collect();
        self.certified = Some(CertifiedHandoffAttestation {
            attestation: self.attestation.clone(),
            signatures,
        });
        self.certified.as_ref()
    }
}

/// Outcome of pushing one `HandoffSignatureMessage` through the
/// per-epoch record path. `Recorded` means the signature verified
/// and was added to the aggregator but didn't advance the cert (still
/// below quorum, or a replay); the caller should persist it.
/// `Certified` is `Recorded` plus the cert produced or enriched by
/// this insert (also persist the signature *and* (re-)persist the
/// cert). Anything else is a non-fatal rejection — drop the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffSignatureRecordOutcome {
    Recorded,
    Certified(CertifiedHandoffAttestation),
    Rejected(HandoffSignatureVerdict),
}

/// Pure helper that runs a single incoming `HandoffSignatureMessage`
/// through `verify_handoff_signature` and, on `Accept`, inserts it
/// into `aggregator`. Returns `Recorded` for under-quorum inserts and
/// `Certified(cert)` once the aggregator is at quorum — both the
/// quorum-crossing insert and every later new-signer insert, which
/// enriches the cert with an extra signature for the caller to
/// re-persist. A replayed/replacement signature yields `Recorded`.
pub fn process_handoff_signature(
    msg: &HandoffSignatureMessage,
    expected: &HandoffAttestation,
    provider: &dyn ConsensusPubkeyProvider,
    aggregator: &mut HandoffAggregator,
) -> HandoffSignatureRecordOutcome {
    match verify_handoff_signature(msg, expected, provider) {
        HandoffSignatureVerdict::Accept => {}
        verdict => return HandoffSignatureRecordOutcome::Rejected(verdict),
    }
    let cert = aggregator
        .insert_verified(msg.signer, msg.signature.clone())
        .cloned();
    match cert {
        Some(cert) => HandoffSignatureRecordOutcome::Certified(cert),
        None => HandoffSignatureRecordOutcome::Recorded,
    }
}

/// If the buffered peer handoff signatures already include a single
/// attestation that a quorum (by stake) of DISTINCT committee members have
/// signed, returns it. A validator whose own snapshot isn't ready yet (its
/// local reconfiguration output still lagging) never installs an expected
/// attestation and would otherwise NEVER persist the cert — it would advance
/// the epoch and later have to re-fetch its own prior-epoch cert from peers,
/// delaying its re-entry and wedging the next reconfiguration's mpc_data
/// freeze. Adopting the quorum-agreed attestation lets it persist the cert
/// from the observed quorum instead of waiting to compute its own.
///
/// Counting is by the attestation each buffered message *claims*; the
/// signatures themselves are re-verified on replay when the attestation is
/// installed, so a byzantine member that buffers a bogus signature for the
/// quorum attestation cannot forge the cert (its row fails verification and
/// drops), and one that claims a different attestation cannot block a real
/// quorum (the honest quorum still agrees on the real one).
pub(crate) fn quorum_attestation_in_buffer(
    committee: &Committee,
    pending: &[HandoffSignatureMessage],
) -> Option<HandoffAttestation> {
    let mut signers_by_attestation: HashMap<&HandoffAttestation, Vec<AuthorityName>> =
        HashMap::new();
    for msg in pending {
        let signers = signers_by_attestation.entry(&msg.attestation).or_default();
        if !signers.contains(&msg.signer) {
            signers.push(msg.signer);
        }
    }
    signers_by_attestation
        .into_iter()
        .find(|(_, signers)| {
            let stake: StakeUnit = signers.iter().map(|signer| committee.weight(signer)).sum();
            stake >= committee.quorum_threshold()
        })
        .map(|(attestation, _)| attestation.clone())
}

/// Joiner-side single-hop bootstrap: fetch a cert for `prior_epoch`
/// from a peer, verify it against the prior committee (the committee
/// that produced it) and a consensus-pubkey provider sourced from
/// that prior committee's on-chain validator info.
///
/// The verification rule (per the handoff design memo):
/// - One hop only. Joiners verify against `prior_committee`, never
///   walking a chain of handoff certs back through E-2, E-3, … to
///   genesis. This is sound because the prior committee's trust root
///   is *Sui*, not an earlier handoff cert: `prior_committee` comes
///   from the `committee_store` (filled by the reconfiguration
///   handler) and the chain exposes the prior committee directly
///   (`validator_set.previous_committee`), with its signer consensus
///   pubkeys resolved from the members' still-on-chain StakingPools.
///   So a joiner anchors on the chain-provided recent committee —
///   already authenticated by Sui's consensus/checkpoints — rather
///   than deriving trust in it from an older cert. A multi-epoch
///   cert-chain walk would only matter if a joiner distrusted the
///   on-chain recent committee but trusted an older one, which isn't
///   a path this bootstrap takes. (The one real residual gap — a
///   prior signer whose StakingPool was fully deleted — is a
///   single-hop concern handled by the aggregator's slack + the
///   skip-on-unresolvable rule in `verify_certified_handoff_attestation`.)
/// - The cert's `attestation.next_committee_pubkey_set_hash` must
///   match what the joiner expects for the committee they're joining
///   into. This binding is what stops a malicious peer from serving
///   a real cert for the wrong committee.
/// - The cert's `attestation.epoch` must equal `expected_prior_epoch`
///   (the epoch the joiner believes it's anchoring to). The epoch is
///   signature-bound inside the attestation, so a forged epoch can't
///   pass verification — but a *real* cert for a different epoch must
///   not be accepted just because the caller happened to pass a
///   matching committee. Binding it explicitly keeps the
///   cross-epoch anchor unambiguous.
///
/// ## The next-committee hash is ADVISORY — quorum decides
///
/// A mismatch is logged, not rejected. The digest covers the whole
/// membership set and every signer signs the identical attestation, so it is
/// a single equality with no per-signer weighting: any disagreement between
/// the signing epoch's naming and the entering epoch's rejects the cert
/// outright, no matter how much valid stake signed it. Since `AuthorityName`
/// IS the consensus key, that made a routine event fatal fleet-wide: ANY
/// validator rotating its consensus key at a boundary, where the outgoing
/// epoch names it by the old key and the entering epoch by the new one.
///
/// By decision, a cert carrying a stake quorum of valid signatures from the
/// prior committee is accepted even when it commits to a different naming of
/// the next committee than we derive locally: the outgoing committee's
/// quorum view wins over our own read.
///
/// Still enforced, and now the whole of the guarantee:
/// `attestation.epoch == expected_prior_epoch`; every signature valid; every
/// signer a member of the verifying committee; summed stake >= the quorum
/// threshold.
///
/// Given up: the assurance that the cert attests to the committee we believe
/// we are entering. With the epoch binding retained, the residual exposure
/// is a cert from a forked or divergent view of the SAME epoch, signed by a
/// quorum of that epoch's committee.
pub fn verify_joiner_bootstrap_cert(
    cert: &CertifiedHandoffAttestation,
    expected_prior_epoch: EpochId,
    prior_committee: &Committee,
    prior_consensus_pubkeys: &dyn ConsensusPubkeyProvider,
    expected_next_committee_pubkeys: impl IntoIterator<Item = AuthorityName>,
) -> IkaResult<()> {
    if cert.attestation.epoch != expected_prior_epoch {
        return Err(IkaError::Unknown(format!(
            "handoff cert epoch mismatch: cert attests epoch {} but joiner expected \
             prior epoch {expected_prior_epoch}",
            cert.attestation.epoch
        )));
    }
    let expected_hash = hash_next_committee_pubkey_set(expected_next_committee_pubkeys);
    if cert.attestation.next_committee_pubkey_set_hash != expected_hash {
        // Advisory, not fatal: the quorum check below decides. The likeliest
        // cause is a member that rotated its consensus key at this boundary —
        // the committee is named BY that key, so the outgoing epoch names it
        // by the old one and this epoch by the new one, and no amount of valid
        // stake could satisfy an exact digest comparison. Loud because the
        // remaining explanation is that this node's view of the next committee
        // diverges from the signing quorum's.
        warn!(
            prior_epoch = expected_prior_epoch,
            cert_hash = ?cert.attestation.next_committee_pubkey_set_hash,
            ?expected_hash,
            "handoff cert commits to a DIFFERENT next-committee naming than this node \
             derives; proceeding on the prior committee's quorum signatures. Expected \
             when a validator rotated its consensus key at this boundary; otherwise \
             this node's view of the next committee diverges from the signing quorum's"
        );
    }
    verify_certified_handoff_attestation(cert, prior_committee, prior_consensus_pubkeys)
}

/// Independently re-verifies a `CertifiedHandoffAttestation` against
/// a committee and a consensus pubkey provider. Used by joiners
/// during bootstrap (where the relevant committee is the *previous*
/// committee, the one that produced this cert).
///
/// Returns `Ok(())` iff every listed signature verifies against the
/// claimed signer's consensus pubkey AND the summed stake reaches
/// the committee's quorum threshold. Otherwise an `IkaError`
/// describes the failure.
///
/// WARNING: this verifies *only* the signatures, committee membership,
/// and quorum — it does NOT check the attestation's `epoch` or
/// `next_committee_pubkey_set_hash`. Those bindings are what stop a
/// real cert for the wrong epoch/committee from being accepted, and
/// they live in the caller. Do not call this directly to validate a
/// fetched cert; use `verify_joiner_bootstrap_cert`, which applies
/// both bindings first. A direct caller MUST bind epoch +
/// next-committee itself before trusting the result.
pub fn verify_certified_handoff_attestation(
    cert: &CertifiedHandoffAttestation,
    committee: &Committee,
    provider: &dyn ConsensusPubkeyProvider,
) -> IkaResult<()> {
    // This cert was signed at the END of epoch N and is verified in N+1, so it
    // is the one payload that straddles the v7 `AuthorityName` width flip: the
    // signatures below are checked against bytes we RE-SERIALIZE locally, at
    // the entering epoch's width, while the signers used the outgoing epoch's.
    // Retry once at the other width before rejecting.
    //
    // This does not widen what is accepted: both widths encode the SAME
    // attestation value (a name decodes identically from either), so the retry
    // resolves an encoding ambiguity rather than admitting a second message.
    // It is scoped to this thread, so concurrent serialization is untouched.
    match verify_certified_handoff_attestation_at_current_width(cert, committee, provider) {
        Err(first @ IkaError::InvalidSignature { .. }) => {
            let other_width = !ika_types::crypto::authority_name_short_encoding();
            let retried =
                ika_types::crypto::with_authority_name_short_encoding(other_width, || {
                    verify_certified_handoff_attestation_at_current_width(cert, committee, provider)
                });
            // Counted, because this path is otherwise invisible: a successful
            // retry looks exactly like a verification that never needed one,
            // so "the boundary worked" cannot distinguish the two. Exactly one
            // `recovered` is the expected shape at an activation boundary —
            // the cert is signed at the end of epoch N under the old width and
            // verified in N+1 under the new one. Anywhere else means two
            // validators disagree about the width mid-epoch. `exhausted` is a
            // bad cert rather than an encoding problem, kept on its own label
            // so the retry is not blamed for it.
            match &retried {
                Ok(()) => {
                    ika_types::metrics::record_handoff_attestation_width_retry(
                        ika_types::metrics::WIDTH_RETRY_RECOVERED,
                    );
                    tracing::info!(
                        epoch = cert.attestation.epoch,
                        retried_at_width_bytes = if other_width { 32 } else { 48 },
                        "handoff attestation verified at the other AuthorityName width"
                    );
                }
                Err(_) => ika_types::metrics::record_handoff_attestation_width_retry(
                    ika_types::metrics::WIDTH_RETRY_EXHAUSTED,
                ),
            }
            retried.map_err(|_| {
                // Report the FIRST failure: the retry's error is always
                // "wrong width" noise when the cert is genuinely bad, and it
                // would send the reader after an encoding problem that isn't
                // there.
                first
            })
        }
        result => result,
    }
}

fn verify_certified_handoff_attestation_at_current_width(
    cert: &CertifiedHandoffAttestation,
    committee: &Committee,
    provider: &dyn ConsensusPubkeyProvider,
) -> IkaResult<()> {
    let intent_msg = IntentMessage::new(
        Intent::ika_app(IntentScope::HandoffAttestation),
        cert.attestation.clone(),
    );
    let bytes = bcs::to_bytes(&intent_msg)
        .map_err(|e| IkaError::Unknown(format!("bcs encode handoff intent message: {e}")))?;
    let mut seen = HashSet::new();
    let mut stake: StakeUnit = 0;
    for (signer, signature) in &cert.signatures {
        if !seen.insert(*signer) {
            return Err(IkaError::Unknown(format!(
                "duplicate signer {signer:?} in certified handoff attestation"
            )));
        }
        let weight = committee.weight(signer);
        if weight == 0 {
            return Err(IkaError::Unknown(format!(
                "signer {signer:?} is not a member of the verifying committee"
            )));
        }
        let Some(pubkey) = provider.consensus_pubkey(signer) else {
            // Genuine prior-committee member (weight > 0, above) whose
            // consensus pubkey is no longer resolvable: it has fully
            // departed since signing, so its registration left the
            // current active-validator set — the only pubkey source (a
            // local epoch-start config is single-valued, and continuing
            // peers have the same gap). Skip its signature instead of
            // failing the whole cert: a quorum of the still-resolvable
            // signers can still validate the handoff. Under extreme
            // churn (a quorum departs in a single epoch) the accumulated
            // stake falls short and the cert is rejected below —
            // correctly, since too few signers are verifiable to anchor
            // cross-epoch trust.
            debug!(
                ?signer,
                "prior-committee handoff signer pubkey unresolvable (departed since signing); \
                 skipping its signature"
            );
            continue;
        };
        pubkey
            .verify(&bytes, signature)
            .map_err(|e| IkaError::InvalidSignature {
                error: format!("handoff signature verify failed for {signer:?}: {e}"),
            })?;
        stake = stake.saturating_add(weight);
    }
    if stake < committee.quorum_threshold() {
        return Err(IkaError::Unknown(format!(
            "certified handoff attestation stake {stake} below quorum threshold {}",
            committee.quorum_threshold()
        )));
    }
    Ok(())
}
