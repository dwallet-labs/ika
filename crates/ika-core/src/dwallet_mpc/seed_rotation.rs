// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Per-epoch root-seed resolution (issue #2119).
//!
//! Every MPC key a validator holds is derived from its root seed. The network
//! learns which key set to deal a validator's shares to from the off-chain
//! `mpc_data` announcement/freeze pipeline, and the record that settles it for
//! epoch `E` is the `E-1 -> E` handoff certificate: its `ValidatorMpcData`
//! item for this authority is the digest of the bundle `E-1`'s reconfiguration
//! encrypted epoch `E`'s shares to.
//!
//! So "which seed do I run epoch `E` with?" has an answer that is *certified*,
//! not configured, and it is asked once per epoch — the MPC service is rebuilt
//! at every boundary, so resolution happens at every construction.
//!
//! ## Rotation
//!
//! An operator rotates by writing a new `root-seed.key` and restarting. The
//! epoch they restart into was already dealt its shares under the OLD bundle,
//! so the freshly derived digest cannot match the certificate. Pointing
//! `previous-root-seed-key-pair` at the old seed resolves that epoch to the
//! PREVIOUS seed: the node decrypts `E`'s shares with the seed those shares
//! were actually encrypted to, while the announcement sender keeps announcing
//! the CURRENT seed's bundle — which is what makes `E -> E+1` deal the next
//! epoch's shares to the new key. One epoch later the certificate names the
//! new digest, resolution picks `Current`, and the field can be removed.
//!
//! ## No abort path
//!
//! When neither seed matches, the node does NOT refuse to start. It joins the
//! epoch as a full consensus member that takes no part in MPC: it decrypts
//! nothing and emits no MPC message, which is exactly how an unresponsive
//! member looks to the protocol — as opposed to a node that tries with the
//! wrong key material and gets itself convicted as malicious (issue #1978).
//! It still announces the current seed's bundle, so the certificate catches up
//! at the next boundary and it resumes normally in `E+1`. An operator who
//! notices sooner repairs it inside `E`: point the previous-seed field at the
//! certified seed and restart, and resolution re-runs immediately.
//!
//! The state is loud — `ika_dwallet_mpc_seed_identity_state` plus a once-per-
//! epoch `error!` — because it is a real loss of MPC stake for the epoch.

use std::collections::BTreeSet;

use dwallet_classgroups_types::{ValidatorKeyDerivation, ValidatorMPCSecrets};
use dwallet_mpc_types::dwallet_mpc::{MPCDataTrait, VersionedMPCData};
use dwallet_rng::RootSeed;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::ValidatorEncryptionKeysAndProofs;
use ika_types::crypto::AuthorityName;
use ika_types::error::{IkaError, IkaResult};
use sui_types::base_types::EpochId;
use tracing::{error, info, warn};

use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::validator_metadata::derive_mpc_data_blob;

/// The `mpc_data` bundle digests this binary emits from one seed.
///
/// Announcements and operator diagnostics use these digests. The certified
/// digest covers the entire encoded bundle, including proofs, so a derivation
/// change can produce a different digest even when the encryption keys match.
/// [`EpochSeedResolution`] therefore compares the encryption keys in the
/// authenticated certified bundle with the supported local derivations.
///
/// The set has exactly one member today (`derive_mpc_data_blob` emits
/// `VersionedMPCData::V1` and nothing else), pinned by
/// `derivable_digest_set_has_exactly_the_encodings_this_binary_emits`. Before
/// emitting a new bundle encoding, readers must already support decoding and
/// verifying it, while retaining support for every encoding a live handoff
/// can still reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivableDigests {
    digests: BTreeSet<[u8; 32]>,
}

impl DerivableDigests {
    /// Derives the emitted bundle digests for `seed`.
    pub fn derive(seed: &RootSeed) -> IkaResult<Self> {
        let mut digests = BTreeSet::new();
        // V1 is the only encoding this binary emits.
        digests.insert(ika_network::mpc_artifacts::mpc_data_blob_hash(
            &derive_mpc_data_blob(seed)?,
        ));
        Ok(Self { digests })
    }

    #[cfg(test)]
    pub(crate) fn from_digests(digests: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            digests: digests.into_iter().collect(),
        }
    }

    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.digests.contains(digest)
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// The digest this binary emits in its announcement and operator messages.
    pub fn emitted(&self) -> Option<[u8; 32]> {
        self.digests.iter().next().copied()
    }

    fn describe(&self) -> String {
        self.digests
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The `validator -> mpc_data digest` map a handoff certificate carries.
///
/// One extraction, shared by the epoch store's carry-forward reader and by the
/// seed resolution, so the digest this validator resolves against is provably
/// the same one the freeze carries forward for it. Both the certificate and
/// the epoch name validators by their CONSENSUS key, so the keys carry over
/// as-is (the BLS protocol key is a different name space).
pub fn certified_mpc_data_digests(
    cert: &ika_types::handoff::CertifiedHandoffAttestation,
) -> std::collections::HashMap<AuthorityName, [u8; 32]> {
    cert.attestation
        .items
        .iter()
        .filter_map(|(key, digest)| match key {
            ika_types::handoff::HandoffItemKey::ValidatorMpcData { validator } => {
                Some((*validator, *digest))
            }
            _ => None,
        })
        .collect()
}

/// Which seed epoch `E` runs on, and whether MPC runs at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSeedDecision {
    /// No certified digest names this authority: genesis or a true joiner's
    /// first epoch. Run the current seed and leave identity reporting to the
    /// announcement sender's per-tick check. Startup must authenticate and
    /// hydrate any required handoff certificate before reaching this rule.
    NoCertifiedDigest { previous_configured: bool },
    /// The CURRENT seed derives the certified encryption keys. Normal.
    /// `previous_configured` separates the steady state from "the rotation
    /// completed, the operator can drop the field".
    RunOnCurrent { previous_configured: bool },
    /// Only the PREVIOUS seed derives the certified encryption keys: a rotation is in
    /// flight. Epoch `E`'s MPC runs on the previous seed; the sender keeps
    /// announcing the current one.
    RunOnPrevious,
    /// Neither seed derives the certified encryption keys. The node joins the epoch as
    /// a consensus member that takes no part in MPC. Never an abort.
    NoParticipation { previous_configured: bool },
}

/// State-label values of `ika_dwallet_mpc_seed_identity_state`.
///
/// Closed set, pinned by `state_labels_are_a_closed_pinned_set`. The two
/// non-participating values share no prefix by accident — an alert must name
/// both, and the test below is what stops a seventh state from being added
/// without the alert being revisited.
pub const SEED_IDENTITY_STATES: &[&str] = &[
    // Current seed is certified, no previous seed configured. Steady state.
    "matches",
    // Current seed is certified AND a previous seed is still configured:
    // the rotation is complete and the field should be removed.
    "rotation_complete",
    // Genesis / first-epoch joiner.
    "no_certified_digest",
    // Rotation in flight: this epoch's MPC runs on the previous seed.
    "rotating_on_previous_seed",
    // NOT PARTICIPATING: the current seed is not certified and no previous
    // seed was configured. The usual cause is a rotation done without setting
    // the previous-seed field.
    "awaiting_certification",
    // NOT PARTICIPATING: a previous seed IS configured and neither it nor the
    // current seed is certified — two rotations before the first was
    // certified, or a wrong seed restored from a backup.
    "previous_seed_mismatch",
];

/// The subset of [`SEED_IDENTITY_STATES`] in which this validator contributes
/// nothing to MPC for the epoch. One alert expression covers both:
///
/// ```text
/// ika_dwallet_mpc_seed_identity_state{state=~"awaiting_certification|previous_seed_mismatch"} == 1
/// ```
pub const SEED_IDENTITY_NON_PARTICIPATING_STATES: &[&str] =
    &["awaiting_certification", "previous_seed_mismatch"];

impl EpochSeedDecision {
    /// Whether this epoch's MPC runs at all.
    pub fn mpc_active(self) -> bool {
        match self {
            Self::NoCertifiedDigest { .. } | Self::RunOnCurrent { .. } | Self::RunOnPrevious => {
                true
            }
            Self::NoParticipation { .. } => false,
        }
    }

    /// Whether the epoch's MPC runs on the PREVIOUS seed.
    pub fn uses_previous_seed(self) -> bool {
        matches!(self, Self::RunOnPrevious)
    }

    pub fn state_label(self) -> &'static str {
        match self {
            Self::RunOnCurrent {
                previous_configured: false,
            } => "matches",
            Self::RunOnCurrent {
                previous_configured: true,
            } => "rotation_complete",
            Self::NoCertifiedDigest { .. } => "no_certified_digest",
            Self::RunOnPrevious => "rotating_on_previous_seed",
            Self::NoParticipation {
                previous_configured: false,
            } => "awaiting_certification",
            Self::NoParticipation {
                previous_configured: true,
            } => "previous_seed_mismatch",
        }
    }
}

/// The whole decision, as a pure function of whether each configured seed
/// derives the certified encryption keys and whether a certified digest exists
/// for this authority. No node, no store, no clock.
///
/// Order matters in exactly one place: CURRENT is tested first, so an operator
/// who points both fields at the same seed gets `RunOnCurrent` (no rotation)
/// rather than a spurious "rotating" state.
pub fn resolve_epoch_seed(
    current_matches: bool,
    previous_matches: Option<bool>,
    has_certified_digest: bool,
) -> EpochSeedDecision {
    let previous_configured = previous_matches.is_some();
    if !has_certified_digest {
        return EpochSeedDecision::NoCertifiedDigest {
            previous_configured,
        };
    }
    if current_matches {
        return EpochSeedDecision::RunOnCurrent {
            previous_configured,
        };
    }
    if previous_matches == Some(true) {
        return EpochSeedDecision::RunOnPrevious;
    }
    EpochSeedDecision::NoParticipation {
        previous_configured,
    }
}

/// Decode only the blob named by the authenticated handoff or frozen input set.
/// Proofs remain part of that digest and are verified by the normal MPC input
/// validation; they are not the identity of the local decryption keys.
pub(crate) fn decode_certified_mpc_keys(
    digest: &[u8; 32],
    blob: &[u8],
) -> IkaResult<ValidatorEncryptionKeysAndProofs> {
    if mpc_data_blob_hash(blob) != *digest {
        return Err(IkaError::Generic {
            error: "certified validator MPC data hash mismatch".into(),
        });
    }
    let versioned: VersionedMPCData = bcs::from_bytes(blob).map_err(|error| IkaError::Generic {
        error: format!("invalid certified validator MPC data: {error}"),
    })?;
    let VersionedMPCData::V1(data) = versioned;
    bcs::from_bytes(&data.mpc_data_bytes()).map_err(|error| IkaError::Generic {
        error: format!("invalid certified validator encryption keys: {error}"),
    })
}

fn same_encryption_keys(
    left: &ValidatorEncryptionKeysAndProofs,
    right: &ValidatorEncryptionKeysAndProofs,
) -> bool {
    left.class_groups
        .iter()
        .zip(&right.class_groups)
        .all(|(left, right)| left.0 == right.0)
        && left.secp256k1_pvss.0 == right.secp256k1_pvss.0
        && left.secp256r1_pvss.0 == right.secp256r1_pvss.0
        && left.ristretto_pvss.0 == right.ristretto_pvss.0
        && left.vss_hpke_public_key_and_proof.0 == right.vss_hpke_public_key_and_proof.0
}

fn derive_seed_identity(
    seed: &RootSeed,
    certified_digest: Option<[u8; 32]>,
    certified_keys: Option<&ValidatorEncryptionKeysAndProofs>,
) -> IkaResult<(DerivableDigests, Option<ValidatorKeyDerivation>)> {
    let blob = derive_mpc_data_blob(seed)?;
    let digest = mpc_data_blob_hash(&blob);
    let digests = DerivableDigests {
        digests: BTreeSet::from([digest]),
    };
    let Some(certified_keys) = certified_keys else {
        return Ok((digests, None));
    };
    let current_keys = decode_certified_mpc_keys(&digest, &blob)?;
    if certified_digest == Some(digest) || same_encryption_keys(&current_keys, certified_keys) {
        return Ok((digests, Some(ValidatorKeyDerivation::Current)));
    }

    // TODO: Remove this temporary legacy validator-key fallback in a later
    // binary after every validator's certified keys are verified against the
    // deployed native derivation. Current and legacy now agree on native.
    // Keep historical browser user-key recovery available.
    let (_, legacy_keys) =
        ValidatorMPCSecrets::from_seed_with_derivation(seed, ValidatorKeyDerivation::Legacy);
    let derivation = same_encryption_keys(&legacy_keys, certified_keys)
        .then_some(ValidatorKeyDerivation::Legacy);
    Ok((digests, derivation))
}

pub(crate) fn matching_key_derivation(
    seed: &RootSeed,
    digest: &[u8; 32],
    blob: &[u8],
) -> IkaResult<Option<ValidatorKeyDerivation>> {
    let keys = decode_certified_mpc_keys(digest, blob)?;
    derive_seed_identity(seed, Some(*digest), Some(&keys)).map(|(_, derivation)| derivation)
}

/// A resolved epoch: the decision plus the seed the MPC manager must run with
/// and the digests the operator-facing reporting names.
#[derive(Clone, Debug)]
pub struct EpochSeedResolution {
    decision: EpochSeedDecision,
    mpc_seed: RootSeed,
    key_derivation: ValidatorKeyDerivation,
    current_digests: DerivableDigests,
    previous_digests: Option<DerivableDigests>,
    certified: Option<[u8; 32]>,
}

impl EpochSeedResolution {
    /// Resolves the seed and sampler from the authenticated certified keys.
    /// Key derivation is expensive, so the previous seed is only derived when
    /// it is configured — i.e. never outside a rotation.
    pub fn resolve(
        current_seed: RootSeed,
        previous_seed: Option<RootSeed>,
        certified_digest_for_self: Option<[u8; 32]>,
        certified_blob: Option<&[u8]>,
    ) -> IkaResult<Self> {
        let certified_keys = certified_digest_for_self
            .map(|digest| {
                let blob = certified_blob.ok_or_else(|| IkaError::Generic {
                    error: "certified validator MPC data is missing at epoch startup".into(),
                })?;
                decode_certified_mpc_keys(&digest, blob)
            })
            .transpose()?;
        let (current_digests, current_derivation) = derive_seed_identity(
            &current_seed,
            certified_digest_for_self,
            certified_keys.as_ref(),
        )?;
        let previous_identity = previous_seed
            .as_ref()
            .map(|seed| {
                derive_seed_identity(seed, certified_digest_for_self, certified_keys.as_ref())
            })
            .transpose()?;
        let previous_digests = previous_identity
            .as_ref()
            .map(|(digests, _)| digests.clone());
        let decision = resolve_epoch_seed(
            current_derivation.is_some(),
            previous_identity
                .as_ref()
                .map(|(_, derivation)| derivation.is_some()),
            certified_digest_for_self.is_some(),
        );
        // `RunOnPrevious` is the only case that hands the manager anything but
        // the current seed, and it is only reachable when `previous_seed` is
        // `Some` (it is the arm that matched the previous seed's keys).
        let mpc_seed = if decision.uses_previous_seed() {
            previous_seed.expect("RunOnPrevious is only produced from a configured previous seed")
        } else {
            current_seed
        };
        let key_derivation = if decision.uses_previous_seed() {
            previous_identity.and_then(|(_, derivation)| derivation)
        } else {
            current_derivation
        }
        .unwrap_or(ValidatorKeyDerivation::Current);
        Ok(Self {
            decision,
            mpc_seed,
            key_derivation,
            current_digests,
            previous_digests,
            certified: certified_digest_for_self,
        })
    }

    pub fn decision(&self) -> EpochSeedDecision {
        self.decision
    }

    /// The seed epoch `E`'s MPC manager must derive its key material from.
    /// Meaningless (and unused) when [`Self::mpc_active`] is false.
    pub fn mpc_seed(&self) -> &RootSeed {
        &self.mpc_seed
    }

    pub fn key_derivation(&self) -> ValidatorKeyDerivation {
        self.key_derivation
    }

    /// Whether the MPC service should run this epoch's protocol at all.
    pub fn mpc_active(&self) -> bool {
        self.decision.mpc_active()
    }

    pub fn state_label(&self) -> &'static str {
        self.decision.state_label()
    }

    /// Publishes the state gauge and logs the epoch's one operator-facing
    /// line. Called once per epoch, from the per-epoch component start — the
    /// gauge reports a configuration/identity fact, not liveness, so it is
    /// deliberately set from OUTSIDE the MPC service (a subsystem cannot
    /// report its own stall, `dev-docs/conventions/metrics.md`).
    pub fn report(&self, metrics: &DWalletMPCMetrics, authority: &AuthorityName, epoch: EpochId) {
        metrics.set_seed_identity_state(self.state_label());
        if self.mpc_active() {
            info!(?authority, epoch, derivation = ?self.key_derivation,
                "selected validator key derivation from the certified handoff");
        }

        let certified = self
            .certified
            .map(hex::encode)
            .unwrap_or_else(|| "none".to_string());
        let current = self.current_digests.describe();
        let previous = self
            .previous_digests
            .as_ref()
            .map(DerivableDigests::describe)
            .unwrap_or_else(|| "not configured".to_string());

        match self.decision {
            EpochSeedDecision::RunOnCurrent {
                previous_configured: false,
            } => {
                info!(
                    ?authority,
                    epoch, "root seed derives the encryption keys certified for this epoch"
                );
            }
            EpochSeedDecision::RunOnCurrent {
                previous_configured: true,
            } => {
                // The rotation-complete signal. WARN because leaving the field
                // in place is not harmless: the next rotation would then have
                // TWO stale candidates and no way to say which is current.
                warn!(
                    ?authority,
                    epoch,
                    %certified,
                    %current,
                    %previous,
                    "seed rotation COMPLETE — the certificate now names the current \
                     root seed's mpc_data bundle. Remove `previous-root-seed-key-pair` \
                     from the node config at the next convenient restart, and delete \
                     the old seed file. Nothing breaks if it stays, but every epoch \
                     re-derives that seed's bundle on the boot path for a comparison \
                     that can no longer match, and a later rotation that swaps only \
                     the current seed would leave this field pointing two seeds back."
                );
            }
            EpochSeedDecision::NoCertifiedDigest { .. } => {
                info!(
                    ?authority,
                    epoch,
                    %current,
                    "no certified mpc_data digest for this validator in the prior epoch's \
                     handoff certificate (genesis or a first-epoch joiner) — running \
                     MPC on the current root seed and leaving \
                     seed identity to the per-tick off-chain check"
                );
            }
            EpochSeedDecision::RunOnPrevious => {
                warn!(
                    ?authority,
                    epoch,
                    %certified,
                    %current,
                    %previous,
                    "seed rotation IN PROGRESS — this epoch's shares were dealt to the \
                     PREVIOUS root seed's mpc_data bundle, so this epoch's MPC runs on \
                     the previous seed. The current seed's bundle is being announced now \
                     and will be certified at the next epoch boundary; keep \
                     `previous-root-seed-key-pair` in place until then."
                );
            }
            EpochSeedDecision::NoParticipation { .. } => {
                error!(
                    ?authority,
                    epoch,
                    %certified,
                    %current,
                    %previous,
                    state = self.state_label(),
                    "NOT PARTICIPATING IN MPC THIS EPOCH: the prior epoch's handoff \
                     certificate deals this validator's shares to mpc_data bundle \
                     {certified}, whose encryption keys neither the configured root seed ({current}) nor \
                     the configured previous root seed ({previous}) derives. This node \
                     cannot decrypt this epoch's shares, so it will run consensus and \
                     every other duty but send no MPC messages at all — deliberately, \
                     rather than computing with key material the network did not deal \
                     to it. It announces the current seed's bundle, so it rejoins MPC \
                     at the next epoch boundary on its own. TO REJOIN THIS EPOCH \
                     IMMEDIATELY: set `previous-root-seed-key-pair` to the seed whose \
                     bundle digest is {certified} (or restore that seed as \
                     `root-seed-key-pair`) and restart — no epoch boundary is needed."
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "dwallet-mpc-unsafe-mock"))]
    #[test]
    fn certified_key_identity_checks_every_encryption_key() {
        let blob = include_bytes!("integration_tests/fixtures/legacy-validator-mpc-data.bcs");
        let digest = mpc_data_blob_hash(blob);
        let certified = decode_certified_mpc_keys(&digest, blob).unwrap();
        let other = ValidatorMPCSecrets::from_seed(&RootSeed::new([32; 32])).1;
        assert!(same_encryption_keys(&certified, &certified));
        for index in 0..certified.class_groups.len() {
            let mut changed = certified.clone();
            changed.class_groups[index].0 = other.class_groups[index].0;
            assert!(
                !same_encryption_keys(&certified, &changed),
                "every CRT key must match"
            );
        }
        let mut changed = certified.clone();
        changed.secp256k1_pvss.0 = other.secp256k1_pvss.0;
        assert!(
            !same_encryption_keys(&certified, &changed),
            "secp256k1 PVSS key must match"
        );
        let mut changed = certified.clone();
        changed.secp256r1_pvss.0 = other.secp256r1_pvss.0;
        assert!(
            !same_encryption_keys(&certified, &changed),
            "secp256r1 PVSS key must match"
        );
        let mut changed = certified.clone();
        changed.ristretto_pvss.0 = other.ristretto_pvss.0;
        assert!(
            !same_encryption_keys(&certified, &changed),
            "ristretto PVSS key must match"
        );
        let mut changed = certified.clone();
        changed.vss_hpke_public_key_and_proof.0 = other.vss_hpke_public_key_and_proof.0;
        assert!(
            !same_encryption_keys(&certified, &changed),
            "VSS HPKE key must match"
        );
    }

    #[test]
    fn certified_key_blob_requires_matching_hash_and_valid_encoding() {
        let invalid = [255];
        let error = decode_certified_mpc_keys(&[0; 32], &invalid).unwrap_err();
        assert!(error.to_string().contains("hash mismatch"));
        let error = decode_certified_mpc_keys(&mpc_data_blob_hash(&invalid), &invalid).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid certified validator MPC data")
        );
    }

    /// All four outcomes of the pure resolution rule.
    #[test]
    fn resolution_covers_current_previous_neither_and_both() {
        // No certified digest for this authority — genesis / first-epoch joiner.
        assert_eq!(
            resolve_epoch_seed(false, None, false),
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: false
            }
        );
        assert_eq!(
            resolve_epoch_seed(false, Some(false), false),
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: true
            }
        );

        // Current matches: normal, with and without a previous seed.
        assert_eq!(
            resolve_epoch_seed(true, None, true),
            EpochSeedDecision::RunOnCurrent {
                previous_configured: false
            }
        );
        assert_eq!(
            resolve_epoch_seed(true, Some(false), true),
            EpochSeedDecision::RunOnCurrent {
                previous_configured: true
            }
        );

        // Only the previous matches: rotation in flight.
        assert_eq!(
            resolve_epoch_seed(false, Some(true), true),
            EpochSeedDecision::RunOnPrevious
        );

        // Neither matches. NEVER an abort — both shapes are a decision to sit
        // the epoch out, and both must be `mpc_active() == false`.
        let no_previous = resolve_epoch_seed(false, None, true);
        assert_eq!(
            no_previous,
            EpochSeedDecision::NoParticipation {
                previous_configured: false
            }
        );
        let with_previous = resolve_epoch_seed(false, Some(false), true);
        assert_eq!(
            with_previous,
            EpochSeedDecision::NoParticipation {
                previous_configured: true
            }
        );
        assert!(!no_previous.mpc_active());
        assert!(!with_previous.mpc_active());

        // Both point at the same seed: NOT a rotation.
        assert_eq!(
            resolve_epoch_seed(true, Some(true), true),
            EpochSeedDecision::RunOnCurrent {
                previous_configured: true
            }
        );
    }

    /// Everything that participates in MPC does so on exactly one seed, and
    /// the previous seed is chosen only in the rotation case.
    #[test]
    fn only_the_rotation_case_runs_on_the_previous_seed() {
        for (decision, active, previous) in [
            (
                EpochSeedDecision::RunOnCurrent {
                    previous_configured: false,
                },
                true,
                false,
            ),
            (
                EpochSeedDecision::RunOnCurrent {
                    previous_configured: true,
                },
                true,
                false,
            ),
            (
                EpochSeedDecision::NoCertifiedDigest {
                    previous_configured: false,
                },
                true,
                false,
            ),
            (EpochSeedDecision::RunOnPrevious, true, true),
            (
                EpochSeedDecision::NoParticipation {
                    previous_configured: false,
                },
                false,
                false,
            ),
            (
                EpochSeedDecision::NoParticipation {
                    previous_configured: true,
                },
                false,
                false,
            ),
        ] {
            assert_eq!(decision.mpc_active(), active, "{decision:?}");
            assert_eq!(decision.uses_previous_seed(), previous, "{decision:?}");
        }
    }

    /// The label set is closed and every decision maps into it. If a seventh
    /// state is ever added, this fails and forces a look at the alert
    /// expression built on `SEED_IDENTITY_NON_PARTICIPATING_STATES`.
    #[test]
    fn state_labels_are_a_closed_pinned_set() {
        assert_eq!(
            SEED_IDENTITY_STATES,
            &[
                "matches",
                "rotation_complete",
                "no_certified_digest",
                "rotating_on_previous_seed",
                "awaiting_certification",
                "previous_seed_mismatch",
            ]
        );
        let produced: BTreeSet<&str> = [
            EpochSeedDecision::RunOnCurrent {
                previous_configured: false,
            },
            EpochSeedDecision::RunOnCurrent {
                previous_configured: true,
            },
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: false,
            },
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: true,
            },
            EpochSeedDecision::RunOnPrevious,
            EpochSeedDecision::NoParticipation {
                previous_configured: false,
            },
            EpochSeedDecision::NoParticipation {
                previous_configured: true,
            },
        ]
        .into_iter()
        .map(EpochSeedDecision::state_label)
        .collect();
        let declared: BTreeSet<&str> = SEED_IDENTITY_STATES.iter().copied().collect();
        assert_eq!(
            produced, declared,
            "every state must be declared, and vice versa"
        );

        // The alert's label set is exactly the non-participating decisions.
        let non_participating: BTreeSet<&str> = [
            EpochSeedDecision::NoParticipation {
                previous_configured: false,
            },
            EpochSeedDecision::NoParticipation {
                previous_configured: true,
            },
        ]
        .into_iter()
        .map(EpochSeedDecision::state_label)
        .collect();
        assert_eq!(
            non_participating,
            SEED_IDENTITY_NON_PARTICIPATING_STATES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
    }

    /// This binary emits exactly one bundle encoding. Its digest set records
    /// that emitted bundle for announcement diagnostics.
    ///
    /// Also the end-to-end check over the REAL derivation that the pure rule
    /// above cannot make: that two different seeds are actually
    /// distinguishable, and that a rotation hands the manager the seed the
    /// certificate names rather than the configured one. Class-groups
    /// derivation takes seconds even in release, so the remaining decision
    /// cases reuse these digests without deriving again.
    #[test]
    fn derivable_digest_set_has_exactly_the_encodings_this_binary_emits() {
        let old = RootSeed::new([21u8; 32]);
        let new = RootSeed::new([22u8; 32]);
        let old_digests = DerivableDigests::derive(&old).expect("derive old");
        let new_digests = DerivableDigests::derive(&new).expect("derive new");

        assert_eq!(
            new_digests.len(),
            1,
            "this binary emits one mpc_data encoding; update this pin when that changes"
        );
        // The member is precisely what the announcement carries.
        let emitted = ika_network::mpc_artifacts::mpc_data_blob_hash(
            &derive_mpc_data_blob(&new).expect("derive blob"),
        );
        assert!(new_digests.contains(&emitted));
        assert_eq!(new_digests.emitted(), Some(emitted));
        // Different seeds must be distinguishable, or the whole comparison is
        // vacuous and every mismatch would read as a match.
        assert_ne!(old_digests, new_digests);

        let old_digest = old_digests.emitted().expect("one digest");

        // A rotation resolves onto the PREVIOUS seed and hands the manager
        // that seed — not the configured (current) one. This is the only
        // assertion that needs the real seeds rather than digests.
        let rotating = EpochSeedResolution::resolve(
            new.clone(),
            Some(old.clone()),
            Some(old_digest),
            Some(&derive_mpc_data_blob(&old).expect("old blob")),
        )
        .expect("resolve");
        assert_eq!(rotating.decision(), EpochSeedDecision::RunOnPrevious);
        assert!(rotating.mpc_active());
        assert_eq!(rotating.mpc_seed(), &old);

        // The rest of the cases over the same real digests, through the pure
        // rule (no further derivation).
        assert_eq!(
            resolve_epoch_seed(
                new_digests.contains(&emitted),
                Some(old_digests.contains(&emitted)),
                true
            )
            .state_label(),
            "rotation_complete"
        );
        assert_eq!(
            resolve_epoch_seed(new_digests.contains(&old_digest), None, true).state_label(),
            "awaiting_certification"
        );
        assert!(!resolve_epoch_seed(new_digests.contains(&old_digest), None, true).mpc_active());
    }
}
