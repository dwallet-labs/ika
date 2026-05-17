// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Producer-side helpers for the off-chain validator-metadata flow.
//!
//! `derive_mpc_data_blob` produces the canonical BCS bytes that a
//! validator commits to (this is what gets hashed and announced; the
//! same bytes are served over P2P). `sign_validator_mpc_data_announcement`
//! builds the `SignedValidatorMpcDataAnnouncement` ready for consensus.
//!
//! These functions are deterministic given the same seed (modulo the
//! `timestamp_ms` parameter), so producer-side and any verifier
//! re-derivation will produce byte-identical blobs.

use dwallet_classgroups_types::ClassGroupsKeyPairAndProof;
use dwallet_mpc_types::dwallet_mpc::{MPCDataV1, VersionedMPCData};
use dwallet_rng::RootSeed;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::traits::{Signer, VerifyingKey};
use ika_types::committee::{Committee, CommitteeTrait, EpochId, StakeUnit};
use ika_types::crypto::{AuthorityKeyPair, AuthorityName, AuthoritySignInfo};
use ika_types::error::{IkaError, IkaResult};
use ika_types::intent::{Intent, IntentMessage, IntentScope};
use ika_types::messages_consensus::ConsensusTransaction;
use ika_types::validator_metadata::{
    CertifiedHandoffAttestation, EpochMpcDataReadySignal, HandoffAttestation, HandoffItemKey,
    HandoffSignatureMessage, SignedValidatorMpcDataAnnouncement, ValidatorMpcDataAnnouncement,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Look up whether a given authority is registered as a next-epoch
/// joiner — i.e., its pubkey is in the `PendingActiveSet` (and the
/// staking pool's `next_epoch_protocol_pubkey`, if set, matches that
/// pubkey). Returning `true` certifies the announcement signer; the
/// caller then verifies the signature using `authority` directly as
/// the pubkey (`AuthorityName == AuthorityPublicKeyBytes`).
///
/// The Sui-backed impl reads `validator_set.pending_active_set` plus
/// each entry's `StakingPool.validator_info`'s next-epoch pubkey,
/// hosted by a `sui_syncer` task that refreshes on a cadence (and on
/// `CommitteeSelected` events). Before the syncer task is up, an
/// empty provider is installed, which drops all joiner announcements
/// — current-committee announcements still work.
pub trait JoinerPubkeyProvider: Send + Sync + 'static {
    fn is_registered_joiner(&self, authority: &AuthorityName) -> bool;
}

/// In-memory `JoinerPubkeyProvider` over a fixed `AuthorityName` set.
/// Used as the default no-op (empty set) and by tests.
pub struct StaticJoinerPubkeyProvider {
    members: HashSet<AuthorityName>,
}

impl StaticJoinerPubkeyProvider {
    pub fn empty() -> Self {
        Self {
            members: HashSet::new(),
        }
    }

    pub fn from_iter<I: IntoIterator<Item = AuthorityName>>(members: I) -> Self {
        Self {
            members: members.into_iter().collect(),
        }
    }
}

impl JoinerPubkeyProvider for StaticJoinerPubkeyProvider {
    fn is_registered_joiner(&self, authority: &AuthorityName) -> bool {
        self.members.contains(authority)
    }
}

/// Outcome of validating a next-epoch joiner announcement, before
/// inserting it into the per-epoch store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinerAnnouncementVerdict {
    /// All checks passed; caller may proceed to apply the
    /// latest-by-timestamp insert rule.
    Accept,
    /// The provider doesn't know about this authority. Drop the
    /// announcement; it's either spam or the provider is stale.
    UnregisteredJoiner,
    /// The signature didn't verify against the claimed authority
    /// for `expected_epoch`.
    InvalidSignature,
    /// `signed.announcement.epoch != signed.auth_sig.epoch` or the
    /// announcement validator != sig authority.
    InconsistentEnvelope,
}

/// Pure verification of a next-epoch joiner announcement. Intended
/// for both unit tests and for `AuthorityPerEpochStore`'s next-epoch
/// branch — the per-epoch-store method calls this and only inserts
/// on `Accept`. Returning anything other than `Accept` is non-fatal
/// (callers should `drop and log`); these are protocol-level
/// outcomes, not unexpected errors.
pub fn verify_joiner_announcement(
    signed: &SignedValidatorMpcDataAnnouncement,
    provider: &dyn JoinerPubkeyProvider,
    expected_epoch: EpochId,
) -> JoinerAnnouncementVerdict {
    use ika_types::crypto::IkaAuthoritySignature;
    use ika_types::intent::IntentMessage;
    if signed.announcement.epoch != signed.auth_sig.epoch
        || signed.announcement.validator != signed.auth_sig.authority
        || signed.announcement.epoch != expected_epoch
    {
        return JoinerAnnouncementVerdict::InconsistentEnvelope;
    }
    if !provider.is_registered_joiner(&signed.auth_sig.authority) {
        return JoinerAnnouncementVerdict::UnregisteredJoiner;
    }
    let intent_msg = IntentMessage::new(
        Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
        signed.announcement.clone(),
    );
    match ika_types::crypto::AuthoritySignature::verify_secure(
        &signed.auth_sig.signature,
        &intent_msg,
        expected_epoch,
        signed.auth_sig.authority,
    ) {
        Ok(()) => JoinerAnnouncementVerdict::Accept,
        Err(_) => JoinerAnnouncementVerdict::InvalidSignature,
    }
}

/// Derives the canonical MPC data blob (BCS-encoded
/// `VersionedMPCData::V1`) from a `RootSeed` — the same encoding the
/// CLI submits on chain via `set_next_epoch_mpc_data_bytes`. Both
/// paths hashing this output produce the same digest.
pub fn derive_mpc_data_blob(seed: &RootSeed) -> IkaResult<Vec<u8>> {
    let key_and_proof = ClassGroupsKeyPairAndProof::from_seed(seed).encryption_key_and_proof();
    let inner = bcs::to_bytes(&key_and_proof)
        .map_err(|e| IkaError::Unknown(format!("bcs encode class-groups key+proof: {e}")))?;
    let mpc_data = VersionedMPCData::V1(MPCDataV1 {
        class_groups_public_key_and_proof: inner,
    });
    bcs::to_bytes(&mpc_data)
        .map_err(|e| IkaError::Unknown(format!("bcs encode versioned mpc data: {e}")))
}

/// Returns the current wall-clock time as milliseconds since the
/// Unix epoch. Used as the `timestamp_ms` field of a new
/// announcement; the latest-by-timestamp rule means later calls
/// (e.g. after a seed rotation) win.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Signs a `ValidatorMpcDataAnnouncement` with the validator's
/// authority (BLS) keypair, producing a
/// `SignedValidatorMpcDataAnnouncement` ready to submit via consensus.
pub fn sign_validator_mpc_data_announcement(
    validator: AuthorityName,
    epoch: EpochId,
    timestamp_ms: u64,
    blob_hash: [u8; 32],
    keypair: &AuthorityKeyPair,
) -> SignedValidatorMpcDataAnnouncement {
    let announcement = ValidatorMpcDataAnnouncement {
        validator,
        epoch,
        timestamp_ms,
        blob_hash,
    };
    let auth_sig = AuthoritySignInfo::new(
        epoch,
        &announcement,
        Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
        validator,
        keypair,
    );
    SignedValidatorMpcDataAnnouncement {
        announcement,
        auth_sig,
    }
}

/// Builds the `ConsensusTransaction` that wraps an
/// `EpochMpcDataReadySignal`. The signal carries no payload signature
/// — the consensus authority binding (sender == authority) is the
/// only authentication needed, and the consensus handler enforces it
/// at message verification time.
pub fn build_epoch_mpc_data_ready_signal_transaction(
    authority: AuthorityName,
    epoch: EpochId,
) -> ConsensusTransaction {
    let signal = EpochMpcDataReadySignal { authority, epoch };
    ConsensusTransaction::new_epoch_mpc_data_ready_signal(signal)
}

/// Intersects the frozen `validator -> blob_hash` map with the union
/// of the current and next committees (V_e ∪ V_{e+1}) — the
/// "effective" set the handoff cert and reconfig MPC both consume.
///
/// Validators who announced mpc_data this epoch but withdrew before
/// `next_committee` was selected are dropped. The cert thus pins
/// only entries that have a place in either committee, and reconfig
/// MPC won't waste effort on dead announcers.
pub fn compute_effective_reconfig_input_set(
    frozen: &BTreeMap<AuthorityName, [u8; 32]>,
    current_committee: impl IntoIterator<Item = AuthorityName>,
    next_committee: impl IntoIterator<Item = AuthorityName>,
) -> BTreeMap<AuthorityName, [u8; 32]> {
    let mut allowed: HashSet<AuthorityName> = HashSet::new();
    allowed.extend(current_committee);
    allowed.extend(next_committee);
    frozen
        .iter()
        .filter(|(authority, _)| allowed.contains(*authority))
        .map(|(authority, digest)| (*authority, *digest))
        .collect()
}

/// Assembles the items list of a `HandoffAttestation` from the three
/// digest sources every validator computes locally:
/// - `validator_mpc_data` — frozen `validator -> blob_hash` snapshot
///   (effectively the intersection with V_e ∪ V_{e+1}; gating to
///   that intersection happens at install time, not here).
/// - `network_dkg_outputs` — per-network-key DKG output digests.
/// - `network_reconfiguration_outputs` — per-network-key reconfig
///   output digests produced *this* epoch.
///
/// Returns the items sorted strictly ascending by `HandoffItemKey`,
/// ready to feed straight into `build_handoff_attestation`. Empty
/// inputs are fine (yields an empty list), which is the state up
/// until steps 9–11 populate the latter two.
pub fn compute_handoff_items(
    validator_mpc_data: &BTreeMap<AuthorityName, [u8; 32]>,
    network_dkg_outputs: &BTreeMap<sui_types::base_types::ObjectID, [u8; 32]>,
    network_reconfiguration_outputs: &BTreeMap<sui_types::base_types::ObjectID, [u8; 32]>,
) -> Vec<(HandoffItemKey, [u8; 32])> {
    let mut items = Vec::with_capacity(
        validator_mpc_data.len()
            + network_dkg_outputs.len()
            + network_reconfiguration_outputs.len(),
    );
    for (key_id, digest) in network_dkg_outputs {
        items.push((
            HandoffItemKey::NetworkDkgOutput { key_id: *key_id },
            *digest,
        ));
    }
    for (key_id, digest) in network_reconfiguration_outputs {
        items.push((
            HandoffItemKey::NetworkReconfigurationOutput { key_id: *key_id },
            *digest,
        ));
    }
    for (validator, digest) in validator_mpc_data {
        items.push((
            HandoffItemKey::ValidatorMpcData {
                validator: *validator,
            },
            *digest,
        ));
    }
    items.sort_by(|left, right| left.0.cmp(&right.0));
    items
}

/// Wraps a signed `HandoffSignatureMessage` in a `ConsensusTransaction`
/// ready for submission via the consensus adapter.
pub fn build_handoff_signature_transaction(msg: HandoffSignatureMessage) -> ConsensusTransaction {
    ConsensusTransaction::new_handoff_signature(msg)
}

/// Builds the `ConsensusTransaction` that wraps a
/// `NetworkKeyDKGReadySignal`. Per-network-key counterpart to
/// `build_epoch_mpc_data_ready_signal_transaction`. Authentication
/// is the consensus authority binding (sender == authority); no
/// payload signature.
pub fn build_network_key_dkg_ready_signal_transaction(
    authority: AuthorityName,
    network_key_id: sui_types::base_types::ObjectID,
    epoch: EpochId,
) -> ConsensusTransaction {
    let signal = ika_types::validator_metadata::NetworkKeyDKGReadySignal {
        authority,
        network_key_id,
        epoch,
    };
    ConsensusTransaction::new_network_key_dkg_ready_signal(signal)
}

/// Outcome of trying to assemble the committee's class-groups
/// public-keys map from off-chain announcements + the local blob
/// store. `Complete` means every supplied authority resolved
/// successfully; `Incomplete` means *at least one* didn't and the
/// caller MUST fall back to the chain-read path — partial maps are
/// load-bearing-broken because reconfig MPC reads
/// `Committee.class_groups_public_keys_and_proofs` directly and an
/// empty/partial entry silently drops that validator's share.
#[derive(Debug)]
pub enum OffChainClassGroupsAssembly {
    Complete(
        std::collections::HashMap<
            AuthorityName,
            ika_types::committee::ClassGroupsEncryptionKeyAndProof,
        >,
    ),
    Incomplete {
        missing: Vec<AuthorityName>,
    },
}

/// Tries to assemble a committee's class-groups public-keys-and-
/// proofs map from announcements + a local blob store. The map is
/// keyed by `AuthorityName`; each entry's BCS-encoded
/// `VersionedMPCData` blob is looked up by digest in the blob
/// store, decoded, and the inner `ClassGroupsEncryptionKeyAndProof`
/// is BCS-decoded out of it.
///
/// The completion gate is strict: even one authority missing a
/// blob *or* failing decode aborts the assembly with `Incomplete`,
/// because reconfig MPC consumes
/// `Committee.class_groups_public_keys_and_proofs` directly and
/// any gap silently drops that validator's share.
///
/// `blob_lookup` returns the bytes (e.g. from perpetual
/// `mpc_artifact_blobs`) for a given digest, or `None`.
pub fn assemble_committee_class_groups_off_chain<F>(
    announcements: impl IntoIterator<Item = (AuthorityName, [u8; 32])>,
    blob_lookup: F,
) -> OffChainClassGroupsAssembly
where
    F: Fn(&[u8; 32]) -> Option<Vec<u8>>,
{
    use dwallet_mpc_types::dwallet_mpc::{MPCDataTrait, VersionedMPCData};
    use ika_types::committee::ClassGroupsEncryptionKeyAndProof;

    let mut map = std::collections::HashMap::new();
    let mut missing = Vec::new();
    for (authority, digest) in announcements {
        let Some(blob) = blob_lookup(&digest) else {
            missing.push(authority);
            continue;
        };
        let Ok(versioned) = bcs::from_bytes::<VersionedMPCData>(&blob) else {
            missing.push(authority);
            continue;
        };
        let inner_bytes = versioned.class_groups_public_key_and_proof();
        let Ok(key_and_proof) = bcs::from_bytes::<ClassGroupsEncryptionKeyAndProof>(&inner_bytes)
        else {
            missing.push(authority);
            continue;
        };
        map.insert(authority, key_and_proof);
    }
    if missing.is_empty() {
        OffChainClassGroupsAssembly::Complete(map)
    } else {
        OffChainClassGroupsAssembly::Incomplete { missing }
    }
}

/// Off-chain source of the large `DWalletNetworkEncryptionKeyData`
/// blobs (DKG output, current reconfiguration output). Implemented
/// at runtime by `AuthorityPerEpochStore`, which holds digest
/// indices into perpetual `mpc_artifact_blobs`. Returning `None`
/// means "I don't have this blob off-chain" — the caller falls
/// back to the chain read.
///
/// This is read-only on the hot path; producer caching (step 9)
/// is the write side.
pub trait NetworkKeyBlobSource: Send + Sync + 'static {
    fn network_dkg_output_blob(
        &self,
        network_key_id: &sui_types::base_types::ObjectID,
    ) -> Option<Vec<u8>>;

    fn network_reconfiguration_output_blob(
        &self,
        network_key_id: &sui_types::base_types::ObjectID,
    ) -> Option<Vec<u8>>;
}

/// In-memory `NetworkKeyBlobSource` for tests and as a typed
/// empty default. Keyed by `network_key_id`.
#[derive(Default)]
pub struct StaticNetworkKeyBlobSource {
    dkg: BTreeMap<sui_types::base_types::ObjectID, Vec<u8>>,
    reconfig: BTreeMap<sui_types::base_types::ObjectID, Vec<u8>>,
}

impl StaticNetworkKeyBlobSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_dkg(&mut self, key_id: sui_types::base_types::ObjectID, bytes: Vec<u8>) {
        self.dkg.insert(key_id, bytes);
    }

    pub fn insert_reconfig(&mut self, key_id: sui_types::base_types::ObjectID, bytes: Vec<u8>) {
        self.reconfig.insert(key_id, bytes);
    }
}

impl NetworkKeyBlobSource for StaticNetworkKeyBlobSource {
    fn network_dkg_output_blob(
        &self,
        network_key_id: &sui_types::base_types::ObjectID,
    ) -> Option<Vec<u8>> {
        self.dkg.get(network_key_id).cloned()
    }

    fn network_reconfiguration_output_blob(
        &self,
        network_key_id: &sui_types::base_types::ObjectID,
    ) -> Option<Vec<u8>> {
        self.reconfig.get(network_key_id).cloned()
    }
}

/// Loads `DWalletNetworkEncryptionKeyData` for `network_key_id` by:
/// 1. Always taking the lightweight metadata (id, epoch, state,
///    dkg_at_epoch) from `chain_data` — that's what's authoritative.
/// 2. Preferring the off-chain `source` for the two large blobs
///    (`network_dkg_public_output`,
///    `current_reconfiguration_public_output`). If `source` doesn't
///    have a blob, the corresponding field on `chain_data` is used
///    as the fallback.
///
/// The chain blob is read by the caller and stitched into
/// `chain_data` already; this function just chooses whether to
/// overlay each large blob from off-chain. Returns a fresh
/// `DWalletNetworkEncryptionKeyData` rather than mutating in place
/// so callers can pass the on-chain copy by value or by clone.
pub fn fetch_network_key_data_with_off_chain_blobs(
    chain_data: ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData,
    source: &dyn NetworkKeyBlobSource,
) -> ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData {
    let network_dkg_public_output = source
        .network_dkg_output_blob(&chain_data.id)
        .unwrap_or(chain_data.network_dkg_public_output);
    let current_reconfiguration_public_output = source
        .network_reconfiguration_output_blob(&chain_data.id)
        .unwrap_or(chain_data.current_reconfiguration_public_output);
    ika_types::messages_dwallet_mpc::DWalletNetworkEncryptionKeyData {
        id: chain_data.id,
        current_epoch: chain_data.current_epoch,
        dkg_at_epoch: chain_data.dkg_at_epoch,
        network_dkg_public_output,
        current_reconfiguration_public_output,
        state: chain_data.state,
    }
}

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

    pub fn from_iter<I: IntoIterator<Item = (AuthorityName, Ed25519PublicKey)>>(items: I) -> Self {
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
/// committee's quorum threshold. Aggregation is one-shot — once
/// certified, subsequent inserts are ignored.
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

    /// Inserts a signature. Caller is responsible for having already
    /// run `verify_handoff_signature` against this validator's
    /// expected attestation — `insert_verified` trusts that. Returns
    /// `Some(cert)` the *first* time the running stake crosses the
    /// committee's quorum threshold; subsequent calls return `None`
    /// (and don't mutate `self.certified`).
    pub fn insert_verified(
        &mut self,
        signer: AuthorityName,
        signature: Ed25519Signature,
    ) -> Option<&CertifiedHandoffAttestation> {
        if self.certified.is_some() {
            return None;
        }
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
        if self.accumulated_stake >= self.committee.quorum_threshold() {
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
        } else {
            None
        }
    }
}

/// Outcome of pushing one `HandoffSignatureMessage` through the
/// per-epoch record path. `Recorded` means the signature verified
/// and was added to the aggregator without crossing quorum; the
/// caller should persist it. `Certified` is `Recorded` plus the
/// freshly-minted cert (also persist the signature *and* the cert).
/// Anything else is a non-fatal rejection — drop the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffSignatureRecordOutcome {
    Recorded,
    Certified(CertifiedHandoffAttestation),
    Rejected(HandoffSignatureVerdict),
}

/// Pure helper that runs a single incoming `HandoffSignatureMessage`
/// through `verify_handoff_signature` and, on `Accept`, inserts it
/// into `aggregator`. Returns `Recorded` for under-quorum inserts
/// and `Certified(cert)` the first time the aggregator crosses
/// quorum. Subsequent calls after certification yield `Recorded`
/// without mutating `aggregator.certified` (the aggregator's
/// `insert_verified` enforces one-shot semantics).
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

/// Joiner-side single-hop bootstrap: fetch a cert for `prior_epoch`
/// from a peer, verify it against the prior committee (the committee
/// that produced it) and a consensus-pubkey provider sourced from
/// that prior committee's on-chain validator info.
///
/// The verification rule (per the handoff design memo):
/// - One hop only. Joiners verify against `prior_committee`, not all
///   the way back to genesis. Anchoring trust to the prior committee
///   is sufficient because that committee was reached through some
///   earlier handoff chain that this joiner either already trusts
///   (steady-state) or doesn't (initial sync — caller's job).
/// - The cert's `attestation.next_committee_pubkey_set_hash` must
///   match what the joiner expects for the committee they're joining
///   into. This binding is what stops a malicious peer from serving
///   a real cert for the wrong committee.
pub fn verify_joiner_bootstrap_cert(
    cert: &CertifiedHandoffAttestation,
    prior_committee: &Committee,
    prior_consensus_pubkeys: &dyn ConsensusPubkeyProvider,
    expected_next_committee_pubkeys: impl IntoIterator<Item = AuthorityName>,
) -> IkaResult<()> {
    let expected_hash = hash_next_committee_pubkey_set(expected_next_committee_pubkeys);
    if cert.attestation.next_committee_pubkey_set_hash != expected_hash {
        return Err(IkaError::Unknown(format!(
            "handoff cert next_committee_pubkey_set_hash mismatch: cert {:?} vs expected {:?}",
            cert.attestation.next_committee_pubkey_set_hash, expected_hash
        )));
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
pub fn verify_certified_handoff_attestation(
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
        let pubkey = provider.consensus_pubkey(signer).ok_or_else(|| {
            IkaError::Unknown(format!("no consensus pubkey for handoff signer {signer:?}"))
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::KeyPair;
    use ika_network::validator_metadata::mpc_data_blob_hash;
    use ika_types::crypto::AuthoritySignInfoTrait;
    use ika_types::crypto::random_committee_key_pairs_of_size;

    fn name_of(kp: &AuthorityKeyPair) -> AuthorityName {
        kp.public().into()
    }

    fn build_signed_for_epoch(
        kp: &AuthorityKeyPair,
        target_epoch: EpochId,
        blob_hash: [u8; 32],
    ) -> SignedValidatorMpcDataAnnouncement {
        sign_validator_mpc_data_announcement(name_of(kp), target_epoch, 42_000, blob_hash, kp)
    }

    #[test]
    fn derive_mpc_data_blob_is_deterministic() {
        // Same seed → byte-identical blob (and therefore identical
        // digest). This is what guarantees the off-chain blob bytes
        // match what the CLI would have written to chain.
        let seed_bytes = [42u8; 32];
        let seed1 = RootSeed::new(seed_bytes);
        let seed2 = RootSeed::new(seed_bytes);
        let b1 = derive_mpc_data_blob(&seed1).expect("derive");
        let b2 = derive_mpc_data_blob(&seed2).expect("derive");
        assert_eq!(b1, b2);
        assert_eq!(mpc_data_blob_hash(&b1), mpc_data_blob_hash(&b2));
    }

    #[test]
    fn sign_announcement_verifies_against_signer() {
        // Construct a committee containing our signer, then verify
        // the signed announcement against it. Catches: intent
        // scope mismatches, epoch mismatches, key-derivation bugs.
        // Use the project's seeded-deterministic test keypair
        // generator to avoid the fastcrypto `AllowedRng` version
        // skew on directly-calling `KeyPair::generate`.
        let mut keypairs = random_committee_key_pairs_of_size(1);
        let kp: AuthorityKeyPair = keypairs.remove(0);
        let name: AuthorityName = (kp.public()).into();
        let voting_rights = vec![(name, 1u64)];
        let committee = ika_types::committee::Committee::new(
            5, // epoch
            voting_rights,
            std::collections::HashMap::new(),
            1,
            1,
        );

        let signed = sign_validator_mpc_data_announcement(name, 5, 1_000, [0xAB; 32], &kp);
        signed
            .auth_sig
            .verify_secure(
                &signed.announcement,
                Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
                &committee,
            )
            .expect("sig should verify");

        // Tamper the announcement → sig should fail.
        let mut tampered = signed.clone();
        tampered.announcement.timestamp_ms = 999;
        assert!(
            tampered
                .auth_sig
                .verify_secure(
                    &tampered.announcement,
                    Intent::ika_app(IntentScope::ValidatorMpcDataAnnouncement),
                    &committee,
                )
                .is_err()
        );
    }

    #[test]
    fn verify_joiner_accepts_well_formed_registered_signer() {
        // Joiner produced a sig for next epoch; the provider lists
        // them as registered; bytes are byte-perfect — expect Accept.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let next_epoch: EpochId = 7;
        let signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::Accept
        );
    }

    #[test]
    fn verify_joiner_rejects_unregistered_signer() {
        // Provider doesn't know this joiner — drop.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let next_epoch: EpochId = 7;
        let signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::empty();
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::UnregisteredJoiner
        );
    }

    #[test]
    fn verify_joiner_rejects_tampered_blob_hash() {
        // Sig was over the original blob_hash; tamper post-sign and
        // the signature won't verify against the new bytes even
        // though the signer is registered.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let next_epoch: EpochId = 7;
        let mut signed = build_signed_for_epoch(&kp, next_epoch, [0x77; 32]);
        signed.announcement.blob_hash = [0x99; 32];
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::InvalidSignature
        );
    }

    #[test]
    fn verify_joiner_rejects_wrong_epoch() {
        // Joiner signed for epoch 8 but caller is processing epoch
        // 7. Reject before signature check — the envelope is
        // inconsistent with what we're processing.
        let mut kps = random_committee_key_pairs_of_size(1);
        let kp = kps.remove(0);
        let joiner_name = name_of(&kp);
        let signed = build_signed_for_epoch(&kp, 8, [0x77; 32]);
        let provider = StaticJoinerPubkeyProvider::from_iter([joiner_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, 7),
            JoinerAnnouncementVerdict::InconsistentEnvelope
        );
    }

    #[test]
    fn verify_joiner_rejects_envelope_authority_mismatch() {
        // The envelope claims one validator but the auth sig was
        // produced by a different keypair (post-sign mutation of
        // the announcement.validator field).
        let mut kps = random_committee_key_pairs_of_size(2);
        let kp_signer = kps.remove(0);
        let kp_other = kps.remove(0);
        let other_name = name_of(&kp_other);
        let next_epoch: EpochId = 7;
        let mut signed = build_signed_for_epoch(&kp_signer, next_epoch, [0x77; 32]);
        signed.announcement.validator = other_name;
        let provider = StaticJoinerPubkeyProvider::from_iter([other_name]);
        assert_eq!(
            verify_joiner_announcement(&signed, &provider, next_epoch),
            JoinerAnnouncementVerdict::InconsistentEnvelope
        );
    }

    #[test]
    fn static_provider_round_trip() {
        // The fixture rng is seeded-deterministic, so a separate
        // `random_committee_key_pairs_of_size(N)` call returns the
        // *same* prefix. To get a non-member, allocate 4 keys and
        // hold the last one out of the provider.
        let kps = random_committee_key_pairs_of_size(4);
        let registered_names: Vec<AuthorityName> = kps[..3].iter().map(name_of).collect();
        let unknown_name = name_of(&kps[3]);
        let provider = StaticJoinerPubkeyProvider::from_iter(registered_names.iter().copied());
        for n in &registered_names {
            assert!(provider.is_registered_joiner(n));
        }
        assert!(!provider.is_registered_joiner(&unknown_name));
    }

    // ---- Handoff attestation helpers ----

    use fastcrypto::ed25519::Ed25519PrivateKey;
    use fastcrypto::traits::ToFromBytes;
    use ika_types::committee::Committee;
    use ika_types::validator_metadata::HandoffItemKey;
    use sui_types::base_types::ObjectID;

    fn make_consensus_keys(count: usize) -> Vec<Ed25519KeyPair> {
        // Build deterministic Ed25519 keypairs from a counter seed.
        // Avoids the multiple-rand-version conflict that bites
        // direct `KeyPair::generate` calls from ika-core tests.
        (0..count)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i + 1) as u8;
                let sk = Ed25519PrivateKey::from_bytes(&seed)
                    .expect("32-byte seed produces a valid Ed25519 private key");
                Ed25519KeyPair::from(sk)
            })
            .collect()
    }

    #[test]
    fn build_handoff_attestation_sorts_items() {
        let kp = random_committee_key_pairs_of_size(1).remove(0);
        let validator = name_of(&kp);
        let key_id_a = ObjectID::random();
        let key_id_b = ObjectID::random();
        // Pass items in non-canonical order; build_handoff_attestation
        // must return them sorted so all signers' bytes match.
        let items = vec![
            (HandoffItemKey::ValidatorMpcData { validator }, [0x33; 32]),
            (
                HandoffItemKey::NetworkDkgOutput { key_id: key_id_a },
                [0x11; 32],
            ),
            (
                HandoffItemKey::NetworkReconfigurationOutput { key_id: key_id_b },
                [0x22; 32],
            ),
        ];
        let att = build_handoff_attestation(9, [0xAA; 32], items).expect("build");
        assert_eq!(att.epoch, 9);
        assert!(matches!(
            att.items[0].0,
            HandoffItemKey::NetworkDkgOutput { .. }
        ));
        assert!(matches!(
            att.items[1].0,
            HandoffItemKey::NetworkReconfigurationOutput { .. }
        ));
        assert!(matches!(
            att.items[2].0,
            HandoffItemKey::ValidatorMpcData { .. }
        ));
    }

    #[test]
    fn build_handoff_attestation_rejects_duplicate_keys() {
        let key_id = ObjectID::random();
        let items = vec![
            (HandoffItemKey::NetworkDkgOutput { key_id }, [0x11; 32]),
            (HandoffItemKey::NetworkDkgOutput { key_id }, [0x22; 32]),
        ];
        assert!(build_handoff_attestation(1, [0; 32], items).is_err());
    }

    #[test]
    fn hash_next_committee_pubkey_set_is_order_independent() {
        let kps = random_committee_key_pairs_of_size(3);
        let names: Vec<AuthorityName> = kps.iter().map(name_of).collect();
        let h1 = hash_next_committee_pubkey_set(names.iter().copied());
        let h2 = hash_next_committee_pubkey_set(names.iter().copied().rev());
        assert_eq!(h1, h2);
        // Duplicates are deduped — adding a duplicate doesn't change the hash.
        let mut with_dup = names.clone();
        with_dup.push(names[0]);
        let h3 = hash_next_committee_pubkey_set(with_dup);
        assert_eq!(h1, h3);
    }

    #[test]
    fn sign_and_verify_handoff_signature_round_trips() {
        let kps = random_committee_key_pairs_of_size(1);
        let bls = &kps[0];
        let signer = name_of(bls);
        let consensus_kps = make_consensus_keys(1);
        let consensus_kp = &consensus_kps[0];
        let consensus_pub = consensus_kp.public().clone();

        let att = build_handoff_attestation(11, [0xBB; 32], vec![]).expect("build");
        let msg = sign_handoff_attestation(att.clone(), signer, consensus_kp);
        let provider = StaticConsensusPubkeyProvider::from_iter([(signer, consensus_pub.clone())]);
        assert_eq!(
            verify_handoff_signature(&msg, &att, &provider),
            HandoffSignatureVerdict::Accept
        );

        // Different attestation → AttestationMismatch.
        let other_att = build_handoff_attestation(11, [0xCC; 32], vec![]).expect("build");
        assert_eq!(
            verify_handoff_signature(&msg, &other_att, &provider),
            HandoffSignatureVerdict::AttestationMismatch
        );

        // Missing pubkey in provider → UnknownSigner.
        let empty_provider = StaticConsensusPubkeyProvider::empty();
        assert_eq!(
            verify_handoff_signature(&msg, &att, &empty_provider),
            HandoffSignatureVerdict::UnknownSigner
        );

        // Wrong pubkey in provider → InvalidSignature.
        let other_consensus_kp = &make_consensus_keys(2)[1];
        let wrong_provider = StaticConsensusPubkeyProvider::from_iter([(
            signer,
            other_consensus_kp.public().clone(),
        )]);
        assert_eq!(
            verify_handoff_signature(&msg, &att, &wrong_provider),
            HandoffSignatureVerdict::InvalidSignature
        );
    }

    fn build_quorum_test_fixture(
        size: usize,
    ) -> (
        Arc<Committee>,
        Vec<AuthorityName>,
        Vec<Ed25519KeyPair>,
        StaticConsensusPubkeyProvider,
    ) {
        let bls_kps = random_committee_key_pairs_of_size(size);
        let names: Vec<AuthorityName> = bls_kps.iter().map(name_of).collect();
        let consensus_kps = make_consensus_keys(size);
        let consensus_pubs: Vec<Ed25519PublicKey> =
            consensus_kps.iter().map(|kp| kp.public().clone()).collect();
        let voting_rights: Vec<(AuthorityName, u64)> = names.iter().map(|n| (*n, 1u64)).collect();
        // quorum_threshold = 2f+1 over 3f+1; for size=4, f=1, q=3.
        let q = (2 * size / 3) as u64 + 1;
        let v = (size / 3) as u64 + 1;
        let committee = Arc::new(Committee::new(
            5,
            voting_rights,
            std::collections::HashMap::new(),
            q,
            v,
        ));
        let provider = StaticConsensusPubkeyProvider::from_iter(
            names.iter().copied().zip(consensus_pubs.into_iter()),
        );
        (committee, names, consensus_kps, provider)
    }

    #[test]
    fn aggregator_certifies_only_after_quorum() {
        let (committee, names, consensus_kps, _provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0xDD; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee.clone(), att.clone());
        // First two inserts: under quorum (q=3 with size=4, stake=1 each).
        for i in 0..2 {
            let msg = sign_handoff_attestation(att.clone(), names[i], &consensus_kps[i]);
            assert!(agg.insert_verified(names[i], msg.signature).is_none());
        }
        assert!(agg.certified().is_none());

        // Third insert crosses quorum → cert returned, and from then
        // on it stays the same.
        let msg = sign_handoff_attestation(att.clone(), names[2], &consensus_kps[2]);
        let cert = agg.insert_verified(names[2], msg.signature).cloned();
        let cert = cert.expect("crossed quorum");
        assert_eq!(cert.attestation, att);
        assert_eq!(cert.signatures.len(), 3);

        // Fourth insert post-cert is a no-op.
        let msg = sign_handoff_attestation(att.clone(), names[3], &consensus_kps[3]);
        assert!(agg.insert_verified(names[3], msg.signature).is_none());
        assert_eq!(agg.certified().unwrap().signatures.len(), 3);
    }

    #[test]
    fn aggregator_ignores_non_committee_signer() {
        // The committee is built from the first 4 keypairs of the
        // size-5 fixture; the 5th is our "outsider" who is not in
        // the committee.
        let mut bls_kps = random_committee_key_pairs_of_size(5);
        let outsider_kp = bls_kps.pop().unwrap();
        let outsider_name = name_of(&outsider_kp);
        let names: Vec<AuthorityName> = bls_kps.iter().map(name_of).collect();
        let voting_rights: Vec<(AuthorityName, u64)> = names.iter().map(|n| (*n, 1u64)).collect();
        let committee = Arc::new(Committee::new(
            5,
            voting_rights,
            std::collections::HashMap::new(),
            3,
            2,
        ));
        let att = build_handoff_attestation(5, [0xEE; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee, att.clone());

        let outsider_consensus = &make_consensus_keys(1)[0];
        let msg = sign_handoff_attestation(att.clone(), outsider_name, outsider_consensus);
        // weight==0 path: insert silently ignored.
        assert!(agg.insert_verified(outsider_name, msg.signature).is_none());
        assert!(agg.certified().is_none());

        // One legitimate signer alone is below quorum (q=3), so
        // aggregator still uncertified.
        let consensus_kps = make_consensus_keys(4);
        let in_committee_msg = sign_handoff_attestation(att.clone(), names[0], &consensus_kps[0]);
        assert!(
            agg.insert_verified(names[0], in_committee_msg.signature)
                .is_none()
        );
        assert!(agg.certified().is_none());
    }

    #[test]
    fn aggregator_replacement_does_not_double_count() {
        let (committee, names, consensus_kps, _provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0xFF; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee, att.clone());
        let first_msg = sign_handoff_attestation(att.clone(), names[0], &consensus_kps[0]);
        agg.insert_verified(names[0], first_msg.signature.clone());
        // Same signer submits again — accumulated_stake must not grow.
        agg.insert_verified(names[0], first_msg.signature);
        // We've only seen one signer at stake=1, q=3, so still uncertified.
        assert!(agg.certified().is_none());
    }

    #[test]
    fn process_handoff_signature_records_then_certifies_at_quorum() {
        let (committee, names, consensus_kps, provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0x21; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee, att.clone());
        // First two: Recorded, no cert.
        for i in 0..2 {
            let msg = sign_handoff_attestation(att.clone(), names[i], &consensus_kps[i]);
            let outcome = process_handoff_signature(&msg, &att, &provider, &mut agg);
            assert_eq!(outcome, HandoffSignatureRecordOutcome::Recorded);
        }
        // Third: Certified, with full cert.
        let msg = sign_handoff_attestation(att.clone(), names[2], &consensus_kps[2]);
        match process_handoff_signature(&msg, &att, &provider, &mut agg) {
            HandoffSignatureRecordOutcome::Certified(cert) => {
                assert_eq!(cert.attestation, att);
                assert_eq!(cert.signatures.len(), 3);
            }
            other => panic!("expected Certified, got {other:?}"),
        }
        // Fourth, post-cert: aggregator is one-shot, so just Recorded.
        let msg = sign_handoff_attestation(att.clone(), names[3], &consensus_kps[3]);
        assert_eq!(
            process_handoff_signature(&msg, &att, &provider, &mut agg),
            HandoffSignatureRecordOutcome::Recorded
        );
    }

    #[test]
    fn process_handoff_signature_rejects_non_matching_attestation() {
        let (committee, names, consensus_kps, provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0x21; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee, att.clone());

        // Sign over a different attestation than what the validator expects.
        let other_att = build_handoff_attestation(5, [0x42; 32], vec![]).expect("build");
        let msg = sign_handoff_attestation(other_att.clone(), names[0], &consensus_kps[0]);
        assert_eq!(
            process_handoff_signature(&msg, &att, &provider, &mut agg),
            HandoffSignatureRecordOutcome::Rejected(HandoffSignatureVerdict::AttestationMismatch)
        );
        assert!(agg.certified().is_none());
    }

    #[test]
    fn compute_handoff_items_returns_sorted_combined_list() {
        // Items are sorted strictly ascending by variant order
        // (NetworkDkgOutput, NetworkReconfigurationOutput,
        // ValidatorMpcData) then by inner key. Combine all three
        // sources and confirm the output canonicalizes.
        let kp = random_committee_key_pairs_of_size(1).remove(0);
        let validator = name_of(&kp);
        let key_id_a = ObjectID::random();
        let key_id_b = ObjectID::random();
        let (smaller, bigger) = if key_id_a < key_id_b {
            (key_id_a, key_id_b)
        } else {
            (key_id_b, key_id_a)
        };

        let mut mpc_data = BTreeMap::new();
        mpc_data.insert(validator, [0xAA; 32]);
        let mut dkg = BTreeMap::new();
        dkg.insert(bigger, [0xBB; 32]);
        dkg.insert(smaller, [0xCC; 32]);
        let mut reconfig = BTreeMap::new();
        reconfig.insert(smaller, [0xDD; 32]);

        let items = compute_handoff_items(&mpc_data, &dkg, &reconfig);
        assert_eq!(items.len(), 4);
        // DKG entries come first, ordered by inner key.
        assert_eq!(
            items[0].0,
            HandoffItemKey::NetworkDkgOutput { key_id: smaller }
        );
        assert_eq!(
            items[1].0,
            HandoffItemKey::NetworkDkgOutput { key_id: bigger }
        );
        // Then reconfig.
        assert_eq!(
            items[2].0,
            HandoffItemKey::NetworkReconfigurationOutput { key_id: smaller }
        );
        // Then validator mpc_data.
        assert_eq!(items[3].0, HandoffItemKey::ValidatorMpcData { validator });
        // Strictly ascending — no duplicate keys.
        for w in items.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
    }

    #[test]
    fn assemble_committee_class_groups_off_chain_round_trip() {
        // Two distinct seeds → two valid `VersionedMPCData::V1`
        // blobs. Stash them in an in-memory lookup keyed by their
        // hashes (matching the announcement digest contract), and
        // verify that the assembler decodes both back into the
        // committee map.
        let kps = random_committee_key_pairs_of_size(2);
        let name_a = name_of(&kps[0]);
        let name_b = name_of(&kps[1]);

        let seed_a = RootSeed::new([1u8; 32]);
        let seed_b = RootSeed::new([2u8; 32]);
        let blob_a = derive_mpc_data_blob(&seed_a).expect("derive A");
        let blob_b = derive_mpc_data_blob(&seed_b).expect("derive B");
        let digest_a = mpc_data_blob_hash(&blob_a);
        let digest_b = mpc_data_blob_hash(&blob_b);

        let mut store: std::collections::HashMap<[u8; 32], Vec<u8>> =
            std::collections::HashMap::new();
        store.insert(digest_a, blob_a);
        store.insert(digest_b, blob_b);

        let outcome = assemble_committee_class_groups_off_chain(
            [(name_a, digest_a), (name_b, digest_b)],
            |d| store.get(d).cloned(),
        );
        match outcome {
            OffChainClassGroupsAssembly::Complete(map) => {
                assert_eq!(map.len(), 2);
                assert!(map.contains_key(&name_a));
                assert!(map.contains_key(&name_b));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn assemble_committee_class_groups_off_chain_reports_missing_blob() {
        // One announcer's blob isn't in the store → Incomplete with
        // that announcer listed. The whole assembly must abort
        // (load-bearing rule: partial map is worse than no map).
        let kps = random_committee_key_pairs_of_size(2);
        let name_a = name_of(&kps[0]);
        let name_b = name_of(&kps[1]);
        let seed_a = RootSeed::new([3u8; 32]);
        let blob_a = derive_mpc_data_blob(&seed_a).expect("derive A");
        let digest_a = mpc_data_blob_hash(&blob_a);
        let digest_b = [0u8; 32]; // never inserted

        let mut store: std::collections::HashMap<[u8; 32], Vec<u8>> =
            std::collections::HashMap::new();
        store.insert(digest_a, blob_a);

        let outcome = assemble_committee_class_groups_off_chain(
            [(name_a, digest_a), (name_b, digest_b)],
            |d| store.get(d).cloned(),
        );
        match outcome {
            OffChainClassGroupsAssembly::Incomplete { missing } => {
                assert_eq!(missing, vec![name_b]);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn assemble_committee_class_groups_off_chain_reports_corrupt_blob() {
        // Digest resolves but the bytes don't decode as
        // `VersionedMPCData` → still Incomplete; that authority is
        // listed as missing.
        let kp = random_committee_key_pairs_of_size(1).remove(0);
        let name = name_of(&kp);
        let bogus_digest = [0xFF; 32];
        let bogus_bytes = vec![0xFF; 8];
        let mut store: std::collections::HashMap<[u8; 32], Vec<u8>> =
            std::collections::HashMap::new();
        store.insert(bogus_digest, bogus_bytes);

        let outcome = assemble_committee_class_groups_off_chain([(name, bogus_digest)], |d| {
            store.get(d).cloned()
        });
        match outcome {
            OffChainClassGroupsAssembly::Incomplete { missing } => {
                assert_eq!(missing, vec![name]);
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn fetch_network_key_data_overlays_off_chain_blobs_when_present() {
        use ika_types::messages_dwallet_mpc::{
            DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
        };
        let key_id = ObjectID::random();
        let chain = DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch: 5,
            dkg_at_epoch: 3,
            network_dkg_public_output: vec![0xCC; 16],
            current_reconfiguration_public_output: vec![0xDD; 16],
            state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
        };

        let mut source = StaticNetworkKeyBlobSource::new();
        source.insert_dkg(key_id, vec![0x11; 8]);
        // No reconfig blob in source → caller should keep chain's
        // reconfig bytes.

        let merged = fetch_network_key_data_with_off_chain_blobs(chain.clone(), &source);
        assert_eq!(merged.id, key_id);
        assert_eq!(merged.current_epoch, 5);
        assert_eq!(merged.dkg_at_epoch, 3);
        assert_eq!(merged.network_dkg_public_output, vec![0x11; 8]);
        assert_eq!(merged.current_reconfiguration_public_output, vec![0xDD; 16]);
        assert_eq!(merged.state, chain.state);
    }

    #[test]
    fn fetch_network_key_data_falls_back_to_chain_when_source_empty() {
        use ika_types::messages_dwallet_mpc::{
            DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
        };
        let key_id = ObjectID::random();
        let chain = DWalletNetworkEncryptionKeyData {
            id: key_id,
            current_epoch: 1,
            dkg_at_epoch: 1,
            network_dkg_public_output: vec![0xAA; 4],
            current_reconfiguration_public_output: vec![0xBB; 4],
            state: DWalletNetworkEncryptionKeyState::NetworkDKGCompleted,
        };
        let source = StaticNetworkKeyBlobSource::new();
        let merged = fetch_network_key_data_with_off_chain_blobs(chain.clone(), &source);
        // Nothing overlayed; should be byte-identical to chain.
        assert_eq!(merged, chain);
    }

    #[test]
    fn effective_reconfig_input_set_intersects_both_committees() {
        // 4 announcers in `frozen`: 2 are in V_e, 1 is only in
        // V_{e+1} (a joiner), 1 has withdrawn (in neither). The
        // joiner is kept; the withdrawn announcer is dropped.
        let kps = random_committee_key_pairs_of_size(4);
        let staying = name_of(&kps[0]);
        let leaving_into_no_one = name_of(&kps[1]); // not in V_e or V_{e+1}
        let joiner = name_of(&kps[2]);
        let leaving_to_next = name_of(&kps[3]); // in V_e and V_{e+1}

        let mut frozen = BTreeMap::new();
        frozen.insert(staying, [0xA0; 32]);
        frozen.insert(leaving_into_no_one, [0xA1; 32]);
        frozen.insert(joiner, [0xA2; 32]);
        frozen.insert(leaving_to_next, [0xA3; 32]);

        let current = vec![staying, leaving_to_next];
        let next = vec![staying, joiner, leaving_to_next];

        let effective = compute_effective_reconfig_input_set(&frozen, current, next);
        assert_eq!(effective.len(), 3);
        assert_eq!(effective.get(&staying), Some(&[0xA0; 32]));
        assert_eq!(effective.get(&joiner), Some(&[0xA2; 32]));
        assert_eq!(effective.get(&leaving_to_next), Some(&[0xA3; 32]));
        assert!(effective.get(&leaving_into_no_one).is_none());
    }

    #[test]
    fn effective_reconfig_input_set_empty_when_no_overlap() {
        let kps = random_committee_key_pairs_of_size(2);
        let alone = name_of(&kps[0]);
        let nobody_in_committees = name_of(&kps[1]);
        let mut frozen = BTreeMap::new();
        frozen.insert(nobody_in_committees, [0x11; 32]);
        // alone is the only one in V_e and V_{e+1}, but they never
        // announced (not in `frozen`).
        let effective = compute_effective_reconfig_input_set(&frozen, vec![alone], vec![alone]);
        assert!(effective.is_empty());
    }

    #[test]
    fn compute_handoff_items_empty_inputs_yield_empty_list() {
        let empty: BTreeMap<AuthorityName, [u8; 32]> = BTreeMap::new();
        let empty_obj: BTreeMap<ObjectID, [u8; 32]> = BTreeMap::new();
        let items = compute_handoff_items(&empty, &empty_obj, &empty_obj);
        assert!(items.is_empty());
    }

    #[test]
    fn process_handoff_signature_rejects_unknown_signer() {
        // Provider doesn't know the signer's consensus key.
        let (committee, names, consensus_kps, _full_provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0x21; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee, att.clone());
        let empty = StaticConsensusPubkeyProvider::empty();
        let msg = sign_handoff_attestation(att.clone(), names[0], &consensus_kps[0]);
        assert_eq!(
            process_handoff_signature(&msg, &att, &empty, &mut agg),
            HandoffSignatureRecordOutcome::Rejected(HandoffSignatureVerdict::UnknownSigner)
        );
    }

    #[test]
    fn verify_joiner_bootstrap_cert_round_trip_and_mismatch() {
        let (committee, names, consensus_kps, provider) = build_quorum_test_fixture(4);
        // Pretend names[..2] are the next committee — joiner expects
        // exactly these pubkeys in the handoff.
        let next_pubkeys: Vec<AuthorityName> = names[..2].to_vec();
        let att = build_handoff_attestation(
            7,
            hash_next_committee_pubkey_set(next_pubkeys.iter().copied()),
            vec![],
        )
        .expect("build");
        let mut agg = HandoffAggregator::new(committee.clone(), att.clone());
        for i in 0..3 {
            let msg = sign_handoff_attestation(att.clone(), names[i], &consensus_kps[i]);
            agg.insert_verified(names[i], msg.signature);
        }
        let cert = agg.certified().expect("certified").clone();

        // Joiner verifies against the prior committee (which is
        // `committee` in this fixture) and the same pubkey set the
        // cert pinned. Should pass.
        verify_joiner_bootstrap_cert(&cert, &committee, &provider, next_pubkeys.iter().copied())
            .expect("verify");

        // Joiner expects a different committee than what's pinned →
        // refuse, even though signatures are individually valid.
        let wrong_pubkeys = vec![names[2], names[3]];
        let err = verify_joiner_bootstrap_cert(&cert, &committee, &provider, wrong_pubkeys)
            .expect_err("should mismatch");
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("next_committee_pubkey_set_hash mismatch"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn verify_certified_handoff_attestation_round_trip() {
        let (committee, names, consensus_kps, provider) = build_quorum_test_fixture(4);
        let att = build_handoff_attestation(5, [0x12; 32], vec![]).expect("build");
        let mut agg = HandoffAggregator::new(committee.clone(), att.clone());
        for i in 0..3 {
            let msg = sign_handoff_attestation(att.clone(), names[i], &consensus_kps[i]);
            agg.insert_verified(names[i], msg.signature);
        }
        let cert = agg.certified().expect("certified").clone();
        verify_certified_handoff_attestation(&cert, &committee, &provider)
            .expect("verify against producing committee");

        // Tamper one of the signatures — verification must fail.
        let mut bad = cert.clone();
        let zero_sig = make_consensus_keys(1)[0].sign(b"garbage");
        bad.signatures[0].1 = zero_sig;
        assert!(verify_certified_handoff_attestation(&bad, &committee, &provider).is_err());
    }
}
