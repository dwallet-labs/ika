// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::crypto::{
    AuthorityKeyPair, AuthorityName, AuthorityPublicKey, NetworkPublicKey,
    random_committee_key_pairs_of_size,
};
use crate::error::{IkaError, IkaResult};
use class_groups::CompactIbqf;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, KnowledgeOfDiscreteLogUCProof, MAX_PRIMES,
};
use fastcrypto::traits::KeyPair;
use group::PartyID;
use group::curve25519;
pub use ika_protocol_config::ProtocolVersion;
use mpc::hybrid_public_key_encryption::{
    KnowledgeOfDecryptionKeyUCProof as VssHpkeKnowledgeOfDecryptionKeyUCProof,
    parse_and_uc_verify_encryption_keys,
};
use rand::rngs::{StdRng, ThreadRng};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use sui_types::base_types::*;
use sui_types::multiaddr::Multiaddr;

pub type EpochId = u64;

// TODO: the stake and voting power of a validator can be different so
// in some places when we are actually referring to the voting power, we
// should use a different type alias, field name, etc.
pub type StakeUnit = u64;

pub type CommitteeDigest = [u8; 32];

/// A crypto-free snapshot of a committee — membership, stake, and
/// thresholds, without the class-groups / PVSS key material a full
/// [`Committee`] carries.
///
/// Published on the chain-committee channel, which Sui fills as soon as
/// it selects the next committee (before the off-chain class-groups
/// assembly produces the full `Committee`). Its consumers — the freeze
/// emit-gate and the joiner watcher — need only membership and the
/// epoch. Keeping it a distinct type makes "read the chain committee
/// for reconfiguration crypto" — which on a full `Committee` would
/// silently see empty key maps and drop every share — a compile error
/// rather than a runtime failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeMembership {
    pub epoch: EpochId,
    pub voting_rights: Vec<(AuthorityName, StakeUnit)>,
    pub quorum_threshold: StakeUnit,
    pub validity_threshold: StakeUnit,
}

impl CommitteeMembership {
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }
}

// The voting power, quorum threshold and max voting power are defined in the `voting_power.move` module.
// We're following the very same convention in the validator binaries.

#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct Committee {
    pub epoch: EpochId,
    pub voting_rights: Vec<(AuthorityName, StakeUnit)>,
    /// Per-validator class-groups CRT-decryption-key encryption key + proof.
    /// This is the ONLY validator MPC key carried on `Committee`: it is the
    /// bare mainnet-v1.1.8 shape stored on Sui, so it is available from the
    /// chain in every epoch (including the v3→v4 transition).
    ///
    /// The off-chain-only validator MPC material — the three per-curve PVSS
    /// HPKE keys and the Fast Schnorr (VSS) HPKE key — is deliberately NOT on
    /// `Committee`. It never lived on Sui; it travels off-chain via validator
    /// announcements and is delivered to the MPC manager per-epoch (see
    /// `ValidatorMpcKeysByPartyId` and the off-chain key channels), populated
    /// only once the information is actually available rather than initialised
    /// empty here.
    pub class_groups_public_keys_and_proofs:
        HashMap<AuthorityName, ClassGroupsEncryptionKeyAndProof>,
    pub quorum_threshold: u64,
    pub validity_threshold: u64,
    /// `AuthorityName -> BLS protocol pubkey`, for BLS aggregate-certificate
    /// verification. For BLS-basis names (committees of epochs below
    /// protocol version 6) the name IS the BLS key, so this
    /// is decoded from it (a cache). For consensus-basis names the BLS key
    /// cannot be recovered from the name — such committees must be built
    /// with [`Committee::new_with_protocol_keys`], which carries the map
    /// from the on-chain read.
    // TODO(consensus-key-certs): once BLS aggregate certs are replaced by
    // consensus-key-signed certs, drop `expanded_keys` / `public_key()` and
    // the validators' BLS key entirely.
    expanded_keys: HashMap<AuthorityName, AuthorityPublicKey>,
    /// `AuthorityName -> consensus Ed25519 pubkey`, for verifying
    /// consensus-key-signed messages (handoff certs today, more certs later).
    /// Supplied at construction from chain — the BLS-derived name can't
    /// recover it. May be empty for committees that never verify such
    /// messages (e.g. legacy/test committees).
    consensus_keys: HashMap<AuthorityName, NetworkPublicKey>,
    /// AuthorityName -> to PartyID (from 0).
    index_map: HashMap<AuthorityName, usize>,
}

/// The `Committee` layout as written by mainnet-v1.1.8, i.e. before the
/// mid-struct `consensus_keys` field was added at protocol v4. `Committee`
/// derives `Serialize`/`Deserialize` with no field skips, so its bcs layout is
/// positional; a 1.1.8 record has no `consensus_keys` bytes and cannot be
/// decoded by the current `Committee`. This mirror decodes those records so a
/// v4 binary can read a `committee_map` entry its own prior (1.1.8) version
/// persisted. Fields mirror the 1.1.8 declaration order EXACTLY — do not
/// reorder. Only used by `CommitteeStore::migrate_legacy_records`, which
/// rewrites such records in the current layout at store open; remove both
/// together once no fleet upgrades directly from 1.1.8 data dirs.
///
/// `Serialize` is derived only to satisfy the `DBMap` value bound; all
/// writes go through the primary `Committee` schema.
#[derive(Serialize, Deserialize)]
pub struct LegacyCommittee {
    epoch: EpochId,
    voting_rights: Vec<(AuthorityName, StakeUnit)>,
    class_groups_public_keys_and_proofs: HashMap<AuthorityName, ClassGroupsEncryptionKeyAndProof>,
    quorum_threshold: u64,
    validity_threshold: u64,
    // Present in the 1.1.8 serialized bytes but rebuilt from voting_rights by
    // `Committee::new`, so the decoded values are discarded. Underscore-named
    // so they still deserialize positionally (bcs is positional; the names are
    // not in the wire format) without tripping the dead-code lint.
    _expanded_keys: HashMap<AuthorityName, AuthorityPublicKey>,
    _index_map: HashMap<AuthorityName, usize>,
}

impl LegacyCommittee {
    /// A `LegacyCommittee` mirroring a given `Committee`'s mainnet-v1.1.8
    /// on-wire layout (no `consensus_keys`), for migration tests.
    #[cfg(any(test, feature = "test_helpers"))]
    pub fn mirror_of(committee: &Committee) -> Self {
        let (expanded_keys, index_map) = Committee::load_inner(&committee.voting_rights);
        LegacyCommittee {
            epoch: committee.epoch,
            voting_rights: committee.voting_rights.clone(),
            class_groups_public_keys_and_proofs: committee
                .class_groups_public_keys_and_proofs
                .clone(),
            quorum_threshold: committee.quorum_threshold,
            validity_threshold: committee.validity_threshold,
            _expanded_keys: expanded_keys,
            _index_map: index_map,
        }
    }
}

impl From<LegacyCommittee> for Committee {
    fn from(legacy: LegacyCommittee) -> Self {
        // consensus_keys defaults to empty. Sound because a 1.1.8-written
        // record always DESCRIBES a ≤v3 epoch (it can be READ at any later
        // epoch), and no handoff certificate can exist for a ≤v3 epoch (cert
        // minting is v4-gated) — so these keys are never asked to verify
        // anything. The "describes ≤v3" guarantee rests on: (1) 1.1.8 pins
        // MAX_PROTOCOL_VERSION = 3; (2) 1.1.8's `reconfigure` checks the
        // protocol version BEFORE `insert_new_committee`, so it cannot
        // persist a record for a v4 epoch; (3) the state-sync
        // `insert_committee` plumbing has no live callers. If any link
        // breaks, a cert verified against this committee skips every
        // unresolvable signer and fails quorum — an honest fail-closed
        // outcome far from the cause (see cross-binary-upgrade.md).
        // `expanded_keys`/`index_map` are rebuilt from voting_rights.
        Committee::new(
            legacy.epoch,
            legacy.voting_rights,
            legacy.class_groups_public_keys_and_proofs,
            HashMap::new(),
            legacy.quorum_threshold,
            legacy.validity_threshold,
        )
    }
}

impl Committee {
    pub fn new(
        epoch: EpochId,
        voting_rights: Vec<(AuthorityName, StakeUnit)>,
        class_groups_public_keys_and_proofs: HashMap<
            AuthorityName,
            ClassGroupsEncryptionKeyAndProof,
        >,
        consensus_keys: HashMap<AuthorityName, NetworkPublicKey>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        assert!(!voting_rights.is_empty());
        assert!(voting_rights.iter().any(|(_, s)| *s != 0));

        let (expanded_keys, index_map) = Self::load_inner(&voting_rights);

        Committee {
            epoch,
            voting_rights,
            class_groups_public_keys_and_proofs,
            expanded_keys,
            consensus_keys,
            index_map,
            quorum_threshold,
            validity_threshold,
        }
    }

    /// Like [`Committee::new`], but with the `AuthorityName -> BLS protocol
    /// pubkey` map supplied by the caller (from the on-chain read) instead of
    /// decoded from the names. Required for committees whose names are
    /// consensus-basis (`consensus_key_authority_names`, on from protocol
    /// version 6): a consensus-basis name does not contain the BLS key, and
    /// BLS aggregate-certificate verification still needs it.
    pub fn new_with_protocol_keys(
        epoch: EpochId,
        voting_rights: Vec<(AuthorityName, StakeUnit)>,
        class_groups_public_keys_and_proofs: HashMap<
            AuthorityName,
            ClassGroupsEncryptionKeyAndProof,
        >,
        consensus_keys: HashMap<AuthorityName, NetworkPublicKey>,
        protocol_keys: HashMap<AuthorityName, AuthorityPublicKey>,
        quorum_threshold: u64,
        validity_threshold: u64,
    ) -> Self {
        assert!(!voting_rights.is_empty());
        assert!(voting_rights.iter().any(|(_, s)| *s != 0));

        let index_map = voting_rights
            .iter()
            .enumerate()
            .map(|(index, (addr, _))| (*addr, index))
            .collect();

        Committee {
            epoch,
            voting_rights,
            class_groups_public_keys_and_proofs,
            expanded_keys: protocol_keys,
            consensus_keys,
            index_map,
            quorum_threshold,
            validity_threshold,
        }
    }

    /// Normalize the given weights to TOTAL_VOTING_POWER and create the committee.
    /// Used for testing only: a production system is using the voting weights
    /// of the Ika System object.
    pub fn new_for_testing_with_normalized_voting_power(
        epoch: EpochId,
        mut voting_weights: Vec<(AuthorityName, StakeUnit)>,
    ) -> Self {
        let num_nodes = voting_weights.len();
        let total_votes: StakeUnit = voting_weights.iter().map(|(_, stake)| stake).sum();

        let normalization_coef = num_nodes as f64 / total_votes as f64;
        let mut total_sum = 0;
        for (idx, (_auth, weight)) in voting_weights.iter_mut().enumerate() {
            if idx < num_nodes - 1 {
                *weight = (*weight as f64 * normalization_coef).floor() as u64; // adjust the weights following the normalization coef
                total_sum += *weight;
            } else {
                // the last element is taking all the rest
                *weight = (num_nodes as u64) - total_sum;
            }
        }

        let quorum_threshold = (2 * num_nodes as u64).div_ceil(3);
        let validity_threshold = (num_nodes as u64).div_ceil(3);

        Self::new(
            epoch,
            voting_weights.into_iter().collect(),
            HashMap::new(),
            HashMap::new(),
            quorum_threshold,
            validity_threshold,
        )
    }

    // We call this if these have not yet been computed
    /// Builds the `expanded_keys` (`AuthorityName -> BLS protocol pubkey`,
    /// for aggregate-cert verification) and `index_map`
    /// (`AuthorityName -> position`) caches. A BLS-basis name IS the BLS
    /// key, so `expanded_keys` is decoded directly from `voting_rights`; a
    /// name that does not decode as a BLS key (a consensus-basis name — a
    /// zero-padded Ed25519 key is not a valid BLS12-381 point) is skipped,
    /// NOT an error: committees with consensus-basis names that verify BLS
    /// certs are built via [`Committee::new_with_protocol_keys`], and one
    /// built through this path fails closed at `public_key()` (signer not
    /// found) rather than panicking at construction.
    pub fn load_inner(
        voting_rights: &[(AuthorityName, StakeUnit)],
    ) -> (
        HashMap<AuthorityName, AuthorityPublicKey>,
        HashMap<AuthorityName, usize>,
    ) {
        let expanded_keys: HashMap<AuthorityName, AuthorityPublicKey> = voting_rights
            .iter()
            .filter_map(|(addr, _)| Some((*addr, (*addr).try_into().ok()?)))
            .collect();

        let index_map: HashMap<AuthorityName, usize> = voting_rights
            .iter()
            .enumerate()
            .map(|(index, (addr, _))| (*addr, index))
            .collect();
        (expanded_keys, index_map)
    }

    pub fn authority_index(&self, author: &AuthorityName) -> Option<u32> {
        self.index_map.get(author).map(|i| *i as u32)
    }

    pub fn authority_by_index(&self, index: u32) -> Option<&AuthorityName> {
        self.voting_rights.get(index as usize).map(|(name, _)| name)
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    pub fn public_key(&self, authority: &AuthorityName) -> IkaResult<&AuthorityPublicKey> {
        // NOTE: `expanded_keys` may legitimately be smaller than
        // `voting_rights` — consensus-basis names don't decode to BLS keys,
        // and a committee that never verifies BLS certs may carry none.
        match self.expanded_keys.get(authority) {
            Some(v) => Ok(v),
            None => Err(IkaError::InvalidCommittee(format!(
                "Authority #{} not found, committee size {}",
                authority,
                self.expanded_keys.len()
            ))),
        }
    }

    /// Maps each member's name under EITHER identity basis to the name this
    /// committee actually uses.
    ///
    /// `AuthorityName` is the BLS protocol key below protocol v6 and the
    /// consensus key from v6, so anything one epoch names and a later epoch
    /// reads back — prior-epoch handoff-cert items, carried-forward mpc_data —
    /// arrives keyed in the producing epoch's name space. Away from the
    /// activation boundary both spaces agree and every entry maps a name to
    /// itself; at the boundary this is what stops those lookups from silently
    /// missing every member. Derived from the committee's own key maps, so it
    /// needs no chain read.
    pub fn name_translation(&self) -> HashMap<AuthorityName, AuthorityName> {
        self.voting_rights
            .iter()
            .flat_map(|(name, _)| {
                let bls = self.expanded_keys.get(name).map(AuthorityName::from);
                let consensus = self
                    .consensus_keys
                    .get(name)
                    .map(AuthorityName::from_consensus_key);
                [bls, consensus]
                    .into_iter()
                    .flatten()
                    .map(move |alias| (alias, *name))
            })
            .collect()
    }

    /// The signer's consensus Ed25519 pubkey, if this committee carries it.
    /// Used to verify consensus-key-signed messages (handoff certs today).
    /// `None` means the committee wasn't built with this signer's consensus
    /// key, so the caller treats the signature as unverifiable and drops it.
    pub fn consensus_key(&self, authority: &AuthorityName) -> Option<&NetworkPublicKey> {
        self.consensus_keys.get(authority)
    }

    /// Return a `HashMap` from **1-based** `PartyID` to `AuthorityName`.
    pub fn party_to_authority_map(&self) -> HashMap<PartyID, AuthorityName> {
        self.index_map
            .iter()
            .map(|(auth, &idx)| {
                // idx is 0-based in index_map, so we add 1 to match the crypto lib.
                ((idx + 1) as PartyID, *auth)
            })
            .collect()
    }

    pub fn class_groups_public_key_and_proof(
        &self,
        authority: &AuthorityName,
    ) -> IkaResult<ClassGroupsEncryptionKeyAndProof> {
        match self.class_groups_public_keys_and_proofs.get(authority) {
            Some(v) => Ok(v.clone()),
            None => Err(IkaError::InvalidCommittee(format!(
                "Authority #{} not found, committee size {}",
                authority,
                self.expanded_keys.len()
            ))),
        }
    }

    /// Samples authorities by weight
    pub fn sample(&self) -> &AuthorityName {
        // unwrap safe unless committee is empty
        Self::choose_multiple_weighted(&self.voting_rights[..], 1, &mut ThreadRng::default())
            .next()
            .unwrap()
    }

    fn choose_multiple_weighted<'a, T: Rng>(
        slice: &'a [(AuthorityName, StakeUnit)],
        count: usize,
        rng: &mut T,
    ) -> impl Iterator<Item = &'a AuthorityName> + use<'a, T> {
        // unwrap is safe because we validate the committee composition in `new` above.
        // See https://docs.rs/rand/latest/rand/distributions/weighted/enum.WeightedError.html
        // for possible errors.
        slice
            .choose_multiple_weighted(rng, count, |(_, weight)| *weight as f64)
            .unwrap()
            .map(|(a, _)| a)
    }

    pub fn choose_multiple_weighted_iter(
        &self,
        count: usize,
    ) -> impl Iterator<Item = &AuthorityName> {
        self.voting_rights
            .choose_multiple_weighted(&mut ThreadRng::default(), count, |(_, weight)| {
                *weight as f64
            })
            .unwrap()
            .map(|(a, _)| a)
    }

    pub fn total_votes(&self) -> StakeUnit {
        self.voting_rights.len() as u64
    }

    pub fn quorum_threshold(&self) -> StakeUnit {
        self.quorum_threshold
    }

    pub fn validity_threshold(&self) -> StakeUnit {
        self.validity_threshold
    }

    pub fn threshold<const STRENGTH: bool>(&self) -> StakeUnit {
        if STRENGTH {
            self.quorum_threshold
        } else {
            self.validity_threshold
        }
    }

    pub fn num_members(&self) -> usize {
        self.voting_rights.len()
    }

    pub fn members(&self) -> impl Iterator<Item = &(AuthorityName, StakeUnit)> {
        self.voting_rights.iter()
    }

    pub fn names(&self) -> impl Iterator<Item = &AuthorityName> {
        self.voting_rights.iter().map(|(name, _)| name)
    }

    pub fn stakes(&self) -> impl Iterator<Item = StakeUnit> + '_ {
        self.voting_rights.iter().map(|(_, stake)| *stake)
    }

    pub fn authority_exists(&self, name: &AuthorityName) -> bool {
        self.index_map.contains_key(name)
    }

    /// Derive a seed deterministically from the transaction digest and shuffle the validators.
    pub fn shuffle_by_stake_from_tx_digest(
        &self,
        tx_digest: &TransactionDigest,
    ) -> Vec<AuthorityName> {
        // the 32 is as requirement of the default StdRng::from_seed choice
        let digest_bytes = tx_digest.into_inner();

        // permute the validators deterministically, based on the digest
        let mut rng = StdRng::from_seed(digest_bytes);
        self.shuffle_by_stake_with_rng(None, None, &mut rng)
    }

    // ===== Testing-only methods =====
    //
    pub fn new_simple_test_committee_of_size(size: usize) -> (Self, Vec<AuthorityKeyPair>) {
        let key_pairs: Vec<_> = random_committee_key_pairs_of_size(size)
            .into_iter()
            .collect();
        let committee = Self::new_for_testing_with_normalized_voting_power(
            0,
            key_pairs
                .iter()
                .map(|key| {
                    (AuthorityName::from(key.public()), /* voting right */ 1)
                })
                .collect(),
        );
        (committee, key_pairs)
    }

    /// Generate a simple committee with 4 validators each with equal voting stake of 1.
    pub fn new_simple_test_committee() -> (Self, Vec<AuthorityKeyPair>) {
        Self::new_simple_test_committee_of_size(4)
    }

    /// Verify the per-validator Fast Schnorr (VSS) HPKE UC proofs against this
    /// committee's membership and return only the verified public key values,
    /// keyed by [`PartyID`] (1-based index into `voting_rights`).
    ///
    /// The off-chain validator MPC keys no longer live on `Committee`; they are
    /// delivered to the MPC manager per-epoch. This method is how that delivery
    /// is converted into the cheap, already-verified form consumed by VSS
    /// presign/sign — the UC proof is checked once here, not per session. Any
    /// party whose key failed to parse or whose proof didn't verify is simply
    /// absent (upstream's per-party filter excludes only that party); a systemic
    /// failure yields an empty map.
    pub fn verified_vss_hpke_party_encryption_key_values(
        &self,
        raw: &HashMap<AuthorityName, VssHpkeEncryptionKeyAndProof>,
    ) -> HashMap<PartyID, curve25519::Value> {
        verify_vss_hpke_keys_by_party_id(raw, &self.index_map)
    }
}

/// Verify per-validator VSS HPKE UC proofs and return only the verified public
/// key values, keyed by [`PartyID`] (1-based index into voting_rights). Run once
/// per epoch when the off-chain validator MPC keys are ingested (no longer at
/// committee construction).
fn verify_vss_hpke_keys_by_party_id(
    raw: &HashMap<AuthorityName, VssHpkeEncryptionKeyAndProof>,
    index_map: &HashMap<AuthorityName, usize>,
) -> HashMap<PartyID, curve25519::Value> {
    let by_party_id: HashMap<PartyID, VssHpkeEncryptionKeyAndProof> = raw
        .iter()
        .filter_map(|(name, kp)| {
            let index = index_map.get(name)?;
            let party_id = u16::try_from(index.checked_add(1)?).ok()?;
            Some((party_id, kp.clone()))
        })
        .collect();
    match parse_and_uc_verify_encryption_keys(&by_party_id) {
        Ok(verified) => {
            if verified.len() < by_party_id.len() {
                tracing::warn!(
                    raw = raw.len(),
                    mapped = by_party_id.len(),
                    verified = verified.len(),
                    "some validators' VSS HPKE keys failed UC verification and were dropped \
                     from the epoch's verified set"
                );
            }
            verified
                .into_iter()
                .map(|(pid, ek)| {
                    use group::GroupElement as _;
                    (pid, ek.value())
                })
                .collect()
        }
        Err(e) => {
            // An empty verified set means EVERY VSS (Fast Schnorr) session
            // this epoch is rejected as not-ready — an epoch-long VSS
            // outage. This error was previously swallowed silently, leaving
            // the outage with no attributable cause in the logs.
            tracing::error!(
                error = ?e,
                raw = raw.len(),
                mapped = by_party_id.len(),
                "VSS HPKE UC verification failed for the whole bundle — the epoch's verified \
                 VSS key set is EMPTY and every VSS session this epoch will be rejected as \
                 not-ready"
            );
            HashMap::new()
        }
    }
}

impl CommitteeTrait<AuthorityName> for Committee {
    fn shuffle_by_stake_with_rng(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        rng: &mut impl Rng,
    ) -> Vec<AuthorityName> {
        let restricted = self
            .voting_rights
            .iter()
            .filter(|(name, _)| {
                if let Some(restrict_to) = restrict_to {
                    restrict_to.contains(name)
                } else {
                    true
                }
            })
            .cloned();

        let (preferred, rest): (Vec<_>, Vec<_>) = if let Some(preferences) = preferences {
            restricted.partition(|(name, _)| preferences.contains(name))
        } else {
            (Vec::new(), restricted.collect())
        };

        Self::choose_multiple_weighted(&preferred, preferred.len(), rng)
            .chain(Self::choose_multiple_weighted(&rest, rest.len(), rng))
            .cloned()
            .collect()
    }

    fn weight(&self, author: &AuthorityName) -> StakeUnit {
        let Some(index) = self.index_map.get(author) else {
            return 0;
        };

        match self.voting_rights.get(*index) {
            None => 0,
            Some((_, s)) => *s,
        }
    }
}

impl PartialEq for Committee {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.voting_rights == other.voting_rights
    }
}

impl Hash for Committee {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.epoch.hash(state);
        self.voting_rights.hash(state);
    }
}

impl Display for Committee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut voting_rights = String::new();
        for (name, vote) in &self.voting_rights {
            write!(voting_rights, "{}: {}, ", name.concise(), vote)?;
        }
        write!(
            f,
            "Committee (epoch={:?}, voting_rights=[{}])",
            self.epoch, voting_rights
        )
    }
}

pub trait CommitteeTrait<K: Ord> {
    fn shuffle_by_stake_with_rng(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<K>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<K>>,
        rng: &mut impl Rng,
    ) -> Vec<K>;

    fn shuffle_by_stake(
        &self,
        // try these authorities first
        preferences: Option<&BTreeSet<K>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<K>>,
    ) -> Vec<K> {
        self.shuffle_by_stake_with_rng(preferences, restrict_to, &mut ThreadRng::default())
    }

    fn weight(&self, author: &K) -> StakeUnit;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMetadata {
    pub name: String,
    pub network_address: Multiaddr,
    pub consensus_address: Multiaddr,
    pub network_public_key: Option<NetworkPublicKey>,
    /// Bare mainnet-v1.1.8 class-groups key — the only validator MPC key on the
    /// chain-derived metadata. The off-chain-only PVSS / VSS HPKE keys are not
    /// carried here; they reach the MPC manager via the off-chain key channels.
    pub class_groups_public_key_and_proof: Option<ClassGroupsEncryptionKeyAndProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeWithNetworkMetadata {
    epoch_id: EpochId,
    validators: BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)>,
}

impl CommitteeWithNetworkMetadata {
    pub fn new(
        epoch_id: EpochId,
        validators: BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)>,
    ) -> Self {
        Self {
            epoch_id,
            validators,
        }
    }
    pub fn epoch(&self) -> EpochId {
        self.epoch_id
    }

    pub fn validators(&self) -> &BTreeMap<AuthorityName, (StakeUnit, NetworkMetadata)> {
        &self.validators
    }
}

impl Display for CommitteeWithNetworkMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CommitteeWithNetworkMetadata (epoch={}, validators={:?})",
            self.epoch_id, self.validators
        )
    }
}

pub type ClassGroupsProof = KnowledgeOfDiscreteLogUCProof;
pub type ClassGroupsEncryptionKeyAndProof = [(
    CompactIbqf<{ CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    ClassGroupsProof,
); MAX_PRIMES];

// ─────────────────────────────────────────────────────────────────────────────
// PVSS HPKE encryption keys and proofs
// ─────────────────────────────────────────────────────────────────────────────
//
// Per-curve publicly-verifiable-secret-sharing (PVSS) HPKE encryption keys plus
// UC-secure proofs of knowledge of the corresponding decryption key. Required by
// `cryptography-private @ 9d35fa76`'s decentralized DKG / reconfiguration
// `PublicInput::new` to wire the threshold_encryption_to_sharing sub-protocol;
// generated per validator at startup from the validator's `RootSeed` (mirrors
// the `class_groups_decryption_key` pattern, distinct domain-separation labels
// per curve so the 3 per-curve keys never collide with each other or with the
// existing class-groups CRT decryption key).
//
// All three curves currently use the SAME const-generic limbs
// (`SECP256K1/SECP256R1/RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS == U2048::LIMBS`,
// `*_FUNDAMENTAL_DISCRIMINANT_LIMBS == U1536::LIMBS`); the per-curve type
// aliases nonetheless stay distinct so a future divergence in upstream's curve
// parameter selection doesn't silently cross wires.

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the secp256k1 plaintext space.
pub type Secp256k1PvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the secp256r1 plaintext space.
pub type Secp256r1PvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// PVSS encryption key + UC-secure proof of knowledge of the corresponding
/// decryption key, parameterised for the ristretto plaintext space.
pub type RistrettoPvssEncryptionKeyAndProof = (
    CompactIbqf<{ class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
        { class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
);

/// Fast Schnorr (VSS) HPKE encryption public key (curve25519, serializable
/// `Value` form) plus the UC-secure proof of knowledge of the corresponding
/// decryption key. The proof is verified — and the holder kept only if it passes
/// — via `mpc::hybrid_public_key_encryption::
/// verify_uc_proofs_of_knowledge_of_encryption_secret_keys` when building the VSS
/// presign input; the verified set becomes the presign's
/// `parties_with_uc_verified_public_keys`.
///
/// A single curve25519 key per validator serves all VSS signing curves (the HPKE
/// transport layer is curve-independent), unlike the three class-groups `*_pvss`
/// keys which are per plaintext space.
pub type VssHpkeEncryptionKeyAndProof = (curve25519::Value, VssHpkeKnowledgeOfDecryptionKeyUCProof);

/// Full per-validator MPC public-key payload propagated via the off-chain
/// validator-metadata pipeline (see PR #1721): the class-groups CRT key, the
/// three per-curve PVSS HPKE keys, and the Fast Schnorr (VSS) curve25519 HPKE
/// key — all with their respective UC-secure proofs.
///
/// **NOT** what Move stores. The Move field `MPCDataV1::mpc_data_bytes`
/// always carries the bare `ClassGroupsEncryptionKeyAndProof`
/// (mainnet-v1.1.8 shape). The bundle here
/// is broadcast off-chain (consensus-signed announcement + P2P blob fetch),
/// reaches consensus via `EpochMpcDataReadySignal`, and is then deserialized
/// directly with `bcs::from_bytes::<ValidatorEncryptionKeysAndProofs>(_)` at
/// the off-chain-overlay sites. No shape-tolerant fallback: chain reads use
/// `ClassGroupsEncryptionKeyAndProof` directly, off-chain reads use this
/// struct directly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorEncryptionKeysAndProofs {
    /// Existing class-groups CRT-decryption-key encryption key + proof of
    /// knowledge of discrete log (per CRT prime). Same shape as the field
    /// historically held standalone; preserved here to keep callers that only
    /// need this piece working.
    pub class_groups: ClassGroupsEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the secp256k1 plaintext space. New at this
    /// bump; required by `decentralized_party::dkg::PublicInput::new` and the
    /// reconfiguration-party constructors for the threshold-encryption-to-
    /// sharing sub-protocol.
    pub secp256k1_pvss: Secp256k1PvssEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the secp256r1 plaintext space.
    pub secp256r1_pvss: Secp256r1PvssEncryptionKeyAndProof,
    /// PVSS HPKE key + proof for the ristretto plaintext space.
    pub ristretto_pvss: RistrettoPvssEncryptionKeyAndProof,
    /// Fast Schnorr (VSS) HPKE encryption public key (curve25519) + UC proof of
    /// knowledge of the decryption key. This is the curve25519 HPKE key the VSS
    /// presign's `party_encryption_keys` requires (distinct from the three
    /// class-groups `*_pvss` keys above, which share the class-groups decryption
    /// key over the integers); one key serves all VSS signing curves.
    ///
    /// The proof is verified once at [`Committee`] construction by
    /// `mpc::hybrid_public_key_encryption::parse_and_uc_verify_encryption_keys`;
    /// only validators whose proof verifies are admitted to subsequent VSS
    /// presign / sign sessions.
    pub vss_hpke_public_key_and_proof: VssHpkeEncryptionKeyAndProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_committee_record_decodes_via_fallback() {
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let legacy_bytes = bcs::to_bytes(&LegacyCommittee::mirror_of(&committee)).unwrap();

        // A 1.1.8-layout record does NOT decode as the current `Committee`
        // (the mid-struct `consensus_keys` field shifts every following byte),
        // which is exactly why the store migrates such records at open.
        assert!(
            bcs::from_bytes::<Committee>(&legacy_bytes).is_err(),
            "legacy record must not silently decode as the current Committee"
        );

        // The fallback decodes it and fills empty consensus_keys, preserving
        // membership / voting power / thresholds.
        let decoded: LegacyCommittee = bcs::from_bytes(&legacy_bytes).unwrap();
        let recovered = Committee::from(decoded);
        assert_eq!(recovered.epoch, committee.epoch);
        assert_eq!(recovered.voting_rights, committee.voting_rights);
        assert_eq!(recovered.quorum_threshold, committee.quorum_threshold);
        assert!(recovered.consensus_keys.is_empty());
    }

    #[test]
    fn current_committee_record_is_not_misread_as_legacy() {
        // The safety property behind the migration's "rewrite only records
        // that fail the current decode": a current-layout record must not
        // decode cleanly under the legacy schema (bcs trailing-byte
        // strictness catches the shift).
        let (committee, _keys) = Committee::new_simple_test_committee_of_size(4);
        let current_bytes = bcs::to_bytes(&committee).unwrap();
        assert!(
            bcs::from_bytes::<LegacyCommittee>(&current_bytes).is_err(),
            "current record must not decode under the legacy schema"
        );
    }
}
