// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Store-backed liveness test for the per-epoch root-seed resolution (#2119).
//!
//! The unit tests in `dwallet_mpc::seed_rotation` drive the decision from a
//! digest handed to them, which proves the RULE and nothing about the wiring.
//! This one goes through the real chain the validator goes through at every
//! epoch start:
//!
//!   real `AuthorityPerpetualTables` (rocksdb, tempdir)
//!     -> `insert_certified_handoff_attestation`
//!     -> `get_certified_handoff_attestation`
//!     -> `certified_mpc_data_digests` (the SAME extraction the epoch store's
//!        `prior_epoch_mpc_data_digests` uses — it calls this function)
//!     -> `EpochSeedResolution::resolve` (what `verify_validator_keys` calls,
//!        with real seeds and the real class-groups derivation)
//!
//! so a broken cert round-trip, a wrong `HandoffItemKey` variant, or a digest
//! that disagrees with `derive_mpc_data_blob` fails here rather than on a
//! production validator at an epoch boundary.
//!
//! The three cases are the ones the boot check owes: correct seed starts;
//! wrong seed with no previous seed reaches the NON-PARTICIPATING decision
//! (post-amendment — it is emphatically NOT a startup error, since aborting
//! made the documented rotation flow a crashloop); wrong current seed with the
//! correct previous seed starts on the previous seed.

use std::sync::Arc;

use dwallet_rng::RootSeed;
use ika_types::crypto::AuthorityName;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffAttestation, HandoffItemKey};

use crate::authority::authority_perpetual_tables::AuthorityPerpetualTables;
use crate::dwallet_mpc::seed_rotation::{
    DerivableDigests, EpochSeedDecision, EpochSeedResolution, certified_mpc_data_digests,
};

fn cert_naming(
    prior_epoch: u64,
    entries: &[(AuthorityName, [u8; 32])],
) -> CertifiedHandoffAttestation {
    CertifiedHandoffAttestation {
        attestation: HandoffAttestation {
            epoch: prior_epoch,
            next_committee_pubkey_set_hash: [0u8; 32],
            items: entries
                .iter()
                .map(|(validator, digest)| {
                    (
                        HandoffItemKey::ValidatorMpcData {
                            validator: *validator,
                        },
                        *digest,
                    )
                })
                .collect(),
        },
        signatures: vec![],
    }
}

/// Drives all three boot outcomes through a real handoff-cert store.
///
/// One test rather than three so the (expensive, real) class-groups
/// derivations are shared: `DerivableDigests::derive` runs the full
/// derivation, and the assertions below need each seed's digest once.
#[tokio::test]
async fn boot_seed_resolution_through_a_real_handoff_cert_store() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let self_name = AuthorityName([3; 32]);
    let other_name = AuthorityName([4; 32]);
    let certified_seed = RootSeed::new([31u8; 32]);
    let rotated_seed = RootSeed::new([32u8; 32]);

    let certified_digest = DerivableDigests::derive(&certified_seed)
        .expect("derive the certified seed's bundle")
        .emitted()
        .expect("one encoding");
    let rotated_digest = DerivableDigests::derive(&rotated_seed)
        .expect("derive the rotated seed's bundle")
        .emitted()
        .expect("one encoding");
    assert_ne!(
        certified_digest, rotated_digest,
        "two different seeds must derive two different bundles, or every \
         assertion below is vacuous"
    );

    // A real store, a real write, a real read.
    let dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
    let prior_epoch = 7u64;
    perpetual
        .insert_certified_handoff_attestation(
            prior_epoch,
            // A second validator's item is present so the self-lookup is a
            // real lookup and not "the only entry there is".
            &cert_naming(
                prior_epoch,
                &[(self_name, certified_digest), (other_name, rotated_digest)],
            ),
        )
        .expect("insert the handoff cert");

    let cert = perpetual
        .get_certified_handoff_attestation(prior_epoch)
        .expect("read the handoff cert")
        .expect("the cert must round-trip through the store");
    let digests = certified_mpc_data_digests(&cert);
    let certified_for_self = digests.get(&self_name).copied();
    assert_eq!(
        certified_for_self,
        Some(certified_digest),
        "the store round-trip must preserve THIS authority's ValidatorMpcData item"
    );

    // (a) The certified seed: starts, on the current seed.
    let healthy = EpochSeedResolution::resolve(certified_seed.clone(), None, certified_for_self)
        .expect("resolve");
    assert_eq!(
        healthy.decision(),
        EpochSeedDecision::RunOnCurrent {
            previous_configured: false
        }
    );
    assert!(healthy.mpc_active());
    assert_eq!(healthy.mpc_seed(), &certified_seed);
    assert_eq!(healthy.state_label(), "matches");

    // (b) The rotated seed with NO previous seed configured: the node still
    // starts — there is no error path left — and resolves to the
    // non-participating state. Alertable, self-healing at the next boundary.
    let stranded = EpochSeedResolution::resolve(rotated_seed.clone(), None, certified_for_self)
        .expect("a seed the cert does not name must NOT be a startup error");
    assert_eq!(
        stranded.decision(),
        EpochSeedDecision::NoParticipation {
            previous_configured: false
        }
    );
    assert!(
        !stranded.mpc_active(),
        "it must sit the epoch out rather than compute with key material the \
         network never dealt to it (#1978)"
    );
    assert_eq!(stranded.state_label(), "awaiting_certification");

    // (c) The rotated seed WITH the certified one as previous: starts, and
    // runs the epoch on the previous seed — the shares it is about to be
    // handed were encrypted to exactly that bundle.
    let rotating = EpochSeedResolution::resolve(
        rotated_seed.clone(),
        Some(certified_seed.clone()),
        certified_for_self,
    )
    .expect("resolve");
    assert_eq!(rotating.decision(), EpochSeedDecision::RunOnPrevious);
    assert!(rotating.mpc_active());
    assert_eq!(
        rotating.mpc_seed(),
        &certified_seed,
        "the MPC manager must be built from the CERTIFIED seed, not the \
         configured current one"
    );
    assert_eq!(rotating.state_label(), "rotating_on_previous_seed");

    // And the epoch after the boundary, once the cert names the new bundle:
    // back on the current seed, with the rotation-complete signal.
    let complete = EpochSeedResolution::resolve(
        rotated_seed.clone(),
        Some(certified_seed),
        Some(rotated_digest),
    )
    .expect("resolve");
    assert_eq!(complete.state_label(), "rotation_complete");
    assert_eq!(complete.mpc_seed(), &rotated_seed);
    assert!(complete.mpc_active());
}

/// An authority the certificate does not name at all — a genuine first-epoch
/// joiner — resolves to `NoCertifiedDigest` and runs normally. Cert ABSENCE is
/// never evidence of a wrong seed, and this is the case a fail-closed check
/// would have wedged.
#[tokio::test]
async fn an_authority_absent_from_the_cert_starts_normally() {
    let joiner = AuthorityName([9; 32]);
    let incumbent = AuthorityName([8; 32]);
    let seed = RootSeed::new([33u8; 32]);

    let dir = tempfile::tempdir().expect("tempdir");
    let perpetual = Arc::new(AuthorityPerpetualTables::open(dir.path(), None));
    perpetual
        .insert_certified_handoff_attestation(4, &cert_naming(4, &[(incumbent, [1u8; 32])]))
        .expect("insert");
    let cert = perpetual
        .get_certified_handoff_attestation(4)
        .expect("read")
        .expect("present");
    let certified_for_self = certified_mpc_data_digests(&cert).get(&joiner).copied();
    assert_eq!(certified_for_self, None);

    let resolution =
        EpochSeedResolution::resolve(seed.clone(), None, certified_for_self).expect("resolve");
    assert_eq!(
        resolution.decision(),
        EpochSeedDecision::NoCertifiedDigest {
            previous_configured: false
        }
    );
    assert!(resolution.mpc_active());
    assert_eq!(resolution.mpc_seed(), &seed);
}
