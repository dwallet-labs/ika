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

use dwallet_rng::RootSeed;
use ika_types::crypto::AuthorityName;
use ika_types::error::IkaResult;
use sui_types::base_types::EpochId;
use tracing::{error, info, warn};

use crate::dwallet_mpc::dwallet_mpc_metrics::DWalletMPCMetrics;
use crate::validator_metadata::derive_mpc_data_blob;

/// Every `mpc_data` bundle digest this binary can derive from ONE seed.
///
/// The certified digest covers the whole encoded bundle, so it is a function
/// of the seed AND of the bundle's encoding. Comparing against a single
/// derived digest therefore makes a future encoding change fleet-fatal: every
/// validator would derive a new digest while the certificates still carry the
/// old one, and every validator would resolve to "neither seed matches" on the
/// same upgrade.
///
/// The comparison is a set membership test instead — "is the certified digest
/// one this binary can produce from this seed?" — so a binary that can derive
/// two encodings accepts a certificate written by either.
///
/// **Today the set has exactly one member** (`derive_mpc_data_blob` emits
/// `VersionedMPCData::V1` and nothing else), pinned by
/// `derivable_digest_set_has_exactly_the_encodings_this_binary_emits`. That is
/// an honest no-op: the tolerance is structural, not yet load-bearing.
///
/// **A future encoding bump (`VersionedMPCData::V2`) must** insert BOTH the V1
/// and the V2 digest here, and must do so a release BEFORE
/// `derive_mpc_data_blob` starts *emitting* V2: a certificate is written by
/// the previous epoch's committee running the previous binary, so accepting
/// has to be deployed ahead of emitting or the fleet resolves to
/// "neither seed matches" on the upgrade — the exact failure this set exists
/// to prevent. Drop V1 only once no certificate a live network can still
/// present carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivableDigests {
    digests: BTreeSet<[u8; 32]>,
}

impl DerivableDigests {
    /// Derives the full accepted-digest set for `seed`.
    pub fn derive(seed: &RootSeed) -> IkaResult<Self> {
        let mut digests = BTreeSet::new();
        // v1: the only encoding this binary emits. See the type's docs for
        // what a version bump must add here.
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

    /// The digest this binary *emits* — the one the announcement carries. Used
    /// only for operator-facing messages; the comparison always uses the set.
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
    /// No certified digest names this authority: genesis, a true joiner's
    /// first epoch, or the `E-1` cert not yet installed at boot. Nothing to
    /// resolve against — run the current seed and leave the epoch to the
    /// announcement sender's per-tick check. Cert ABSENCE is never evidence
    /// of a wrong seed.
    NoCertifiedDigest { previous_configured: bool },
    /// The certified digest is one the CURRENT seed derives. Normal.
    /// `previous_configured` separates the steady state from "the rotation
    /// completed, the operator can drop the field".
    RunOnCurrent { previous_configured: bool },
    /// Only the PREVIOUS seed derives the certified digest: a rotation is in
    /// flight. Epoch `E`'s MPC runs on the previous seed; the sender keeps
    /// announcing the current one.
    RunOnPrevious,
    /// Neither seed derives the certified digest. The node joins the epoch as
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
    // Genesis / first-epoch joiner / cert not installed.
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

/// The whole decision, as a pure function of the two derivable-digest sets and
/// the certified digest. No node, no store, no clock.
///
/// Order matters in exactly one place: CURRENT is tested first, so an operator
/// who points both fields at the same seed gets `RunOnCurrent` (no rotation)
/// rather than a spurious "rotating" state.
pub fn resolve_epoch_seed(
    current: &DerivableDigests,
    previous: Option<&DerivableDigests>,
    certified_digest_for_self: Option<[u8; 32]>,
) -> EpochSeedDecision {
    let previous_configured = previous.is_some();
    let Some(certified) = certified_digest_for_self else {
        return EpochSeedDecision::NoCertifiedDigest {
            previous_configured,
        };
    };
    if current.contains(&certified) {
        return EpochSeedDecision::RunOnCurrent {
            previous_configured,
        };
    }
    if previous.is_some_and(|previous| previous.contains(&certified)) {
        return EpochSeedDecision::RunOnPrevious;
    }
    EpochSeedDecision::NoParticipation {
        previous_configured,
    }
}

/// A resolved epoch: the decision plus the seed the MPC manager must run with
/// and the digests the operator-facing reporting names.
#[derive(Clone, Debug)]
pub struct EpochSeedResolution {
    decision: EpochSeedDecision,
    mpc_seed: RootSeed,
    current_digests: DerivableDigests,
    previous_digests: Option<DerivableDigests>,
    certified: Option<[u8; 32]>,
}

impl EpochSeedResolution {
    /// Derives both digest sets and resolves. The derivation is the epoch's
    /// single most expensive computation, so the previous seed's set is only
    /// derived when a previous seed is actually configured — i.e. never
    /// outside a rotation.
    pub fn resolve(
        current_seed: RootSeed,
        previous_seed: Option<RootSeed>,
        certified_digest_for_self: Option<[u8; 32]>,
    ) -> IkaResult<Self> {
        let current_digests = DerivableDigests::derive(&current_seed)?;
        let previous_digests = previous_seed
            .as_ref()
            .map(DerivableDigests::derive)
            .transpose()?;
        let decision = resolve_epoch_seed(
            &current_digests,
            previous_digests.as_ref(),
            certified_digest_for_self,
        );
        // `RunOnPrevious` is the only case that hands the manager anything but
        // the current seed, and it is only reachable when `previous_seed` is
        // `Some` (it is the arm that matched the previous digest set).
        let mpc_seed = if decision.uses_previous_seed() {
            previous_seed.expect("RunOnPrevious is only produced from a configured previous seed")
        } else {
            current_seed
        };
        Ok(Self {
            decision,
            mpc_seed,
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
                    epoch, "root seed derives the mpc_data bundle certified for this epoch"
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
                     handoff certificate (genesis, a first-epoch joiner, or the cert not \
                     yet installed) — running MPC on the current root seed and leaving \
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
                     {certified}, which neither the configured root seed ({current}) nor \
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

    fn digest(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn set(n: u8) -> DerivableDigests {
        DerivableDigests::from_digests([digest(n)])
    }

    /// All four outcomes of the pure resolution rule.
    #[test]
    fn resolution_covers_current_previous_neither_and_both() {
        let current = set(1);
        let previous = set(2);

        // No certified digest — genesis / joiner / cert absent.
        assert_eq!(
            resolve_epoch_seed(&current, None, None),
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: false
            }
        );
        assert_eq!(
            resolve_epoch_seed(&current, Some(&previous), None),
            EpochSeedDecision::NoCertifiedDigest {
                previous_configured: true
            }
        );

        // Current matches: normal, with and without a previous seed.
        assert_eq!(
            resolve_epoch_seed(&current, None, Some(digest(1))),
            EpochSeedDecision::RunOnCurrent {
                previous_configured: false
            }
        );
        assert_eq!(
            resolve_epoch_seed(&current, Some(&previous), Some(digest(1))),
            EpochSeedDecision::RunOnCurrent {
                previous_configured: true
            }
        );

        // Only the previous matches: rotation in flight.
        assert_eq!(
            resolve_epoch_seed(&current, Some(&previous), Some(digest(2))),
            EpochSeedDecision::RunOnPrevious
        );

        // Neither matches. NEVER an abort — both shapes are a decision to sit
        // the epoch out, and both must be `mpc_active() == false`.
        let no_previous = resolve_epoch_seed(&current, None, Some(digest(9)));
        assert_eq!(
            no_previous,
            EpochSeedDecision::NoParticipation {
                previous_configured: false
            }
        );
        let with_previous = resolve_epoch_seed(&current, Some(&previous), Some(digest(9)));
        assert_eq!(
            with_previous,
            EpochSeedDecision::NoParticipation {
                previous_configured: true
            }
        );
        assert!(!no_previous.mpc_active());
        assert!(!with_previous.mpc_active());

        // Both point at the same seed: NOT a rotation.
        let same = DerivableDigests::from_digests([digest(1)]);
        assert_eq!(
            resolve_epoch_seed(&current, Some(&same), Some(digest(1))),
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

    /// Encoding-version tolerance, pinned honestly: this binary emits exactly
    /// ONE bundle encoding, so the accepted set has exactly one member and the
    /// tolerance is structural rather than load-bearing today. A version bump
    /// that adds `VersionedMPCData::V2` must make this 2 (accept both) a
    /// release BEFORE it starts emitting V2 — see `DerivableDigests`.
    ///
    /// Also the end-to-end check over the REAL derivation that the pure rule
    /// above cannot make: that two different seeds are actually
    /// distinguishable, and that a rotation hands the manager the seed the
    /// certificate names rather than the configured one. Each
    /// `DerivableDigests::derive` runs the full class-groups derivation
    /// (seconds, even in release), so this does the minimum number of them —
    /// two — and drives every remaining case through the pure rule.
    #[test]
    fn derivable_digest_set_has_exactly_the_encodings_this_binary_emits() {
        let old = RootSeed::new([21u8; 32]);
        let new = RootSeed::new([22u8; 32]);
        let old_digests = DerivableDigests::derive(&old).expect("derive old");
        let new_digests = DerivableDigests::derive(&new).expect("derive new");

        assert_eq!(
            new_digests.len(),
            1,
            "this binary emits one mpc_data encoding; update this pin AND the \
             accept-before-emit rule in `DerivableDigests` when that changes"
        );
        // The accepted member is precisely what the announcement carries.
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
        let rotating =
            EpochSeedResolution::resolve(new.clone(), Some(old.clone()), Some(old_digest))
                .expect("resolve");
        assert_eq!(rotating.decision(), EpochSeedDecision::RunOnPrevious);
        assert!(rotating.mpc_active());
        assert_eq!(rotating.mpc_seed(), &old);

        // The rest of the cases over the same real digests, through the pure
        // rule (no further derivation).
        assert_eq!(
            resolve_epoch_seed(&new_digests, Some(&old_digests), new_digests.emitted())
                .state_label(),
            "rotation_complete"
        );
        assert_eq!(
            resolve_epoch_seed(&new_digests, None, Some(old_digest)).state_label(),
            "awaiting_certification"
        );
        assert!(!resolve_epoch_seed(&new_digests, None, Some(old_digest)).mpc_active());
    }
}
