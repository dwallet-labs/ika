// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! The epoch's network-owned-address (NOA) signing key: the network
//! encryption key every NOA sign demand's presign is drawn under and every
//! NOA sign session runs on.
//!
//! It is a pure function of the prior epoch's handoff certificate, fixed for
//! the epoch, and every validator derives it on its own — nothing announces a
//! choice. The prepare-then-start barrier evaluates [`select`] once the
//! certificate is local, before the epoch's components exist, and hands the
//! answer to the MPC manager as a constructor input. Choosing over the
//! locally adopted key set instead let honest validators name different keys
//! while their adoption lagged at different rates.

use crate::dwallet_mpc::network_dkg::spawn_network_key_id_registration;
use crate::network_key_id_mapping::network_key_id_for;
use arc_swap::ArcSwap;
use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sui_types::base_types::ObjectID;

/// The outcome of [`select`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkOwnedAddressSigningKeySelection {
    /// The key: among the certified keys, the largest `dkg_at_epoch`, ties
    /// broken by the smaller `NetworkKeyId`.
    Selected {
        object_id: ObjectID,
        network_key_id: NetworkKeyId,
        dkg_at_epoch: u64,
    },
    /// The certificate names no network key: none existed at the end of the
    /// prior epoch, and one created this epoch is not eligible.
    NoCertifiedKey,
    /// These certified keys have no `NetworkKeyId -> ObjectID` translation
    /// on this process, so no key can be chosen: a choice among the
    /// translatable rest would be a per-validator answer. The barrier
    /// prepares the missing mappings before starting any epoch components.
    Untranslatable(Vec<NetworkKeyId>),
    /// Every certified key translates, but the chain metadata of these keys
    /// is not local yet. Retry: the network-key syncer publishes it.
    AwaitingMetadata(Vec<ObjectID>),
}

impl NetworkOwnedAddressSigningKeySelection {
    /// The constructor input, or `None` while startup must wait. A resolved
    /// `Some(None)` means the certificate names no key, uniformly across the
    /// committee. With NOA enabled, missing local mappings must never produce
    /// that answer: skipping NOA demand assignment would leave the shared
    /// presign pool out of step with keyed peers, including after a restart.
    /// The flag-off exception preserves the live protocol's startup behavior.
    pub fn epoch_start_key(&self, noa_checkpoints: bool) -> Option<Option<ObjectID>> {
        match self {
            Self::Selected { object_id, .. } => Some(Some(*object_id)),
            Self::NoCertifiedKey => Some(None),
            Self::Untranslatable(_) if !noa_checkpoints => Some(None),
            Self::Untranslatable(_) | Self::AwaitingMetadata(_) => None,
        }
    }
}

/// Breaks the mapping/adoption cycle before the MPC manager exists. The
/// syncer is already running at the barrier: flag blob-empty prior-epoch
/// keys for its existing chain recovery, then derive their identities on
/// rayon from the published blobs. Identical inputs spawn only once;
/// changed inputs retry a failed derivation. Only keys old enough to occur
/// in the certificate are candidates; a fresh DKG must not trigger recovery.
pub fn prepare_missing_key_mappings(
    anchor_epoch: u64,
    overlay: &HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
    derivation_inputs: &mut HashMap<ObjectID, [u8; 32]>,
    stranded_network_keys: &ArcSwap<HashSet<ObjectID>>,
) {
    for (object_id, data) in overlay {
        if data.dkg_at_epoch > anchor_epoch || network_key_id_for(object_id).is_some() {
            continue;
        }
        if data.network_dkg_public_output.is_empty()
            || (matches!(
                data.state,
                DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
            ) && data.current_reconfiguration_public_output.is_empty())
        {
            stranded_network_keys.rcu(|keys| {
                let mut keys = (**keys).clone();
                keys.insert(*object_id);
                Arc::new(keys)
            });
            continue;
        }
        let input_digest = mpc_data_blob_hash(
            &bcs::to_bytes(&(
                &data.network_dkg_public_output,
                &data.current_reconfiguration_public_output,
            ))
            .expect("network-key derivation inputs serialize"),
        );
        if derivation_inputs.get(object_id) != Some(&input_digest) {
            derivation_inputs.insert(*object_id, input_digest);
            spawn_network_key_id_registration(
                *object_id,
                data.network_dkg_public_output.clone(),
                data.current_reconfiguration_public_output.clone(),
            );
        }
    }
}

/// Derives the NOA signing key for the epoch the certificate hands into.
///
/// THE RULE. Among the keys the certificate names — its `NetworkDkgOutput`
/// items, one per network encryption key that existed at the end of the
/// prior epoch — the key with the largest `dkg_at_epoch` (the most recently
/// created key), ties broken by the smaller `NetworkKeyId` bytes. A key
/// created by DKG after the certificate is not in it and waits one epoch.
///
/// ALL OR NOTHING. The certificate names keys by their content-derived
/// `NetworkKeyId`; `object_id_of` supplies this process's translation into
/// the Sui `ObjectID` used by the pool and manager, and
/// `dkg_at_epoch` is chain metadata keyed by `ObjectID`, read through
/// `dkg_at_epoch_of`. If any certified key cannot be translated the answer is
/// [`Untranslatable`](NetworkOwnedAddressSigningKeySelection::Untranslatable);
/// if any translated key has no metadata yet it is
/// [`AwaitingMetadata`](NetworkOwnedAddressSigningKeySelection::AwaitingMetadata).
/// Neither chooses among the keys that are known: that choice is exactly the
/// per-validator divergence this derivation exists to remove.
pub fn select(
    certificate: &CertifiedHandoffAttestation,
    object_id_of: impl Fn(&NetworkKeyId) -> Option<ObjectID>,
    dkg_at_epoch_of: impl Fn(&ObjectID) -> Option<u64>,
) -> NetworkOwnedAddressSigningKeySelection {
    let certified_keys = certificate
        .attestation
        .items
        .iter()
        .filter_map(|(item, _digest)| match item {
            HandoffItemKey::NetworkDkgOutput { key_id } => Some(*key_id),
            HandoffItemKey::NetworkReconfigurationOutput { .. }
            | HandoffItemKey::ValidatorMpcData { .. } => None,
        });
    let mut untranslatable = Vec::new();
    let mut awaiting_metadata = Vec::new();
    let mut candidates = Vec::new();
    for network_key_id in certified_keys {
        let Some(object_id) = object_id_of(&network_key_id) else {
            untranslatable.push(network_key_id);
            continue;
        };
        match dkg_at_epoch_of(&object_id) {
            Some(dkg_at_epoch) => candidates.push((network_key_id, object_id, dkg_at_epoch)),
            None => awaiting_metadata.push(object_id),
        }
    }
    if !untranslatable.is_empty() {
        return NetworkOwnedAddressSigningKeySelection::Untranslatable(untranslatable);
    }
    if !awaiting_metadata.is_empty() {
        return NetworkOwnedAddressSigningKeySelection::AwaitingMetadata(awaiting_metadata);
    }
    // `max_by_key` keeps the last of several equal maxima, but the key embeds
    // the unique `NetworkKeyId`, so no two candidates compare equal.
    // `Reverse` makes the SMALLER id win a `dkg_at_epoch` tie.
    candidates
        .into_iter()
        .max_by_key(|(network_key_id, _, dkg_at_epoch)| (*dkg_at_epoch, Reverse(*network_key_id)))
        .map_or(
            NetworkOwnedAddressSigningKeySelection::NoCertifiedKey,
            |(network_key_id, object_id, dkg_at_epoch)| {
                NetworkOwnedAddressSigningKeySelection::Selected {
                    object_id,
                    network_key_id,
                    dkg_at_epoch,
                }
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_key_id_mapping;
    use crate::network_key_id_mapping::object_id_for;
    use dwallet_mpc_types::dwallet_mpc::{
        VersionedDecryptionKeyReconfigurationOutput, VersionedNetworkDkgOutput,
    };
    use ika_types::handoff::HandoffAttestation;
    use std::time::Duration;

    /// A key whose `NetworkKeyId` is its `ObjectID`'s bytes — so ordering the
    /// object ids orders the network key ids identically — registered in the
    /// process-global mapping.
    fn registered_key() -> (ObjectID, NetworkKeyId) {
        let object_id = ObjectID::random();
        let network_key_id = NetworkKeyId(object_id.into_bytes());
        network_key_id_mapping::register(object_id, network_key_id);
        (object_id, network_key_id)
    }

    fn ordered_registered_keys<const N: usize>() -> [(ObjectID, NetworkKeyId); N] {
        let mut keys: Vec<_> = (0..N).map(|_| registered_key()).collect();
        keys.sort();
        keys.try_into().expect("N keys")
    }

    fn certificate_naming(network_key_ids: &[NetworkKeyId]) -> CertifiedHandoffAttestation {
        let mut items: Vec<_> = network_key_ids
            .iter()
            .map(|key_id| {
                (
                    HandoffItemKey::NetworkDkgOutput { key_id: *key_id },
                    [0u8; 32],
                )
            })
            .collect();
        items.sort_by(|(a, _), (b, _)| a.cmp(b));
        CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch: 0,
                next_committee_pubkey_set_hash: [0u8; 32],
                items,
            },
            signatures: vec![],
        }
    }

    fn metadata(entries: &[(ObjectID, u64)]) -> impl Fn(&ObjectID) -> Option<u64> + use<> {
        let map: HashMap<ObjectID, u64> = entries.iter().copied().collect();
        move |object_id| map.get(object_id).copied()
    }

    #[test]
    fn the_newest_certified_key_wins_and_ties_break_to_the_smaller_id() {
        let [oldest_smallest_id, newer_smaller_id, newer_larger_id] =
            ordered_registered_keys::<3>();
        // The smallest id is the OLDEST key, so it must lose to both newer
        // keys despite winning every tie-break; the two newer keys tie on
        // epoch.
        let certificate =
            certificate_naming(&[oldest_smallest_id.1, newer_smaller_id.1, newer_larger_id.1]);
        let dkg_at_epoch = metadata(&[
            (oldest_smallest_id.0, 0),
            (newer_smaller_id.0, 1),
            (newer_larger_id.0, 1),
        ]);
        assert_eq!(
            select(&certificate, object_id_for, dkg_at_epoch),
            NetworkOwnedAddressSigningKeySelection::Selected {
                object_id: newer_smaller_id.0,
                network_key_id: newer_smaller_id.1,
                dkg_at_epoch: 1,
            }
        );
    }

    #[test]
    fn a_key_the_certificate_does_not_name_is_not_eligible() {
        let [certified, fresh] = ordered_registered_keys::<2>();
        // The fresh key is newer and its metadata is known; only the
        // certificate decides eligibility.
        let certificate = certificate_naming(&[certified.1]);
        let dkg_at_epoch = metadata(&[(certified.0, 0), (fresh.0, 1)]);
        assert_eq!(
            select(&certificate, object_id_for, dkg_at_epoch),
            NetworkOwnedAddressSigningKeySelection::Selected {
                object_id: certified.0,
                network_key_id: certified.1,
                dkg_at_epoch: 0,
            }
        );
    }

    #[test]
    fn an_untranslatable_certified_key_blocks_any_choice() {
        let (translated_object_id, translated) = registered_key();
        // Never registered: the certificate names it, nothing translates it.
        let untranslatable = NetworkKeyId(rand::random());
        let certificate = certificate_naming(&[translated, untranslatable]);
        // Even with the translatable key's metadata known and the other
        // key OLDER by every tie-break, no partial choice is made.
        let dkg_at_epoch = metadata(&[(translated_object_id, 5)]);
        assert_eq!(
            select(&certificate, object_id_for, dkg_at_epoch),
            NetworkOwnedAddressSigningKeySelection::Untranslatable(vec![untranslatable])
        );
    }

    #[test]
    fn missing_metadata_for_a_certified_key_waits_rather_than_choosing() {
        let [low, high] = ordered_registered_keys::<2>();
        let certificate = certificate_naming(&[low.1, high.1]);
        assert_eq!(
            select(&certificate, object_id_for, metadata(&[(high.0, 0)])),
            NetworkOwnedAddressSigningKeySelection::AwaitingMetadata(vec![low.0])
        );
        // The same inputs plus the missing metadata resolve.
        assert_eq!(
            select(
                &certificate,
                object_id_for,
                metadata(&[(low.0, 0), (high.0, 0)])
            ),
            NetworkOwnedAddressSigningKeySelection::Selected {
                object_id: low.0,
                network_key_id: low.1,
                dkg_at_epoch: 0,
            }
        );
    }

    #[test]
    fn untranslatable_takes_precedence_over_awaiting_metadata() {
        let (_, translated) = registered_key();
        let untranslatable = NetworkKeyId(rand::random());
        let certificate = certificate_naming(&[translated, untranslatable]);
        // The translatable key ALSO lacks metadata; waiting cannot fix the
        // other one, so the answer is the one waiting cannot change.
        assert_eq!(
            select(&certificate, object_id_for, |_| None),
            NetworkOwnedAddressSigningKeySelection::Untranslatable(vec![untranslatable])
        );
    }

    #[test]
    fn a_certificate_naming_no_key_selects_none() {
        let certificate = certificate_naming(&[]);
        assert_eq!(
            select(&certificate, object_id_for, |_| Some(0)),
            NetworkOwnedAddressSigningKeySelection::NoCertifiedKey
        );
    }

    #[test]
    fn epoch_start_waits_for_mapping_and_metadata_with_noa_enabled() {
        let object_id = ObjectID::random();
        let network_key_id = NetworkKeyId(rand::random());
        let certificate = certificate_naming(&[network_key_id]);
        let missing_mapping = select(&certificate, |_| None, |_| Some(0));
        assert_eq!(
            missing_mapping.epoch_start_key(true),
            None,
            "an unresolved certified key must block epoch startup"
        );
        assert_eq!(missing_mapping.epoch_start_key(false), Some(None));

        let missing_metadata = select(&certificate, |_| Some(object_id), |_| None);
        assert_eq!(missing_metadata.epoch_start_key(true), None);
        assert_eq!(missing_metadata.epoch_start_key(false), None);

        let resolved = select(&certificate, |_| Some(object_id), |_| Some(0));
        assert_eq!(resolved.epoch_start_key(true), Some(Some(object_id)));
        assert_eq!(resolved.epoch_start_key(false), Some(Some(object_id)));
        assert_eq!(
            select(&certificate_naming(&[]), |_| None, |_| None).epoch_start_key(true),
            Some(None),
            "a certificate with no key is uniformly keyless"
        );
    }

    #[test]
    fn preparation_requests_missing_blobs_without_waiting_for_mpc_startup() {
        let missing_dkg = ObjectID::random();
        let missing_reconfiguration = ObjectID::random();
        let fresh = ObjectID::random();
        let (already_mapped, _) = registered_key();
        let overlay = HashMap::from([
            (missing_dkg, (0, Vec::new())),
            (missing_reconfiguration, (0, vec![1])),
            (fresh, (1, Vec::new())),
            (already_mapped, (0, Vec::new())),
        ])
        .into_iter()
        .map(|(id, (dkg_at_epoch, network_dkg_public_output))| {
            (
                id,
                DWalletNetworkEncryptionKeyData {
                    id,
                    current_epoch: 1,
                    dkg_at_epoch,
                    network_dkg_public_output,
                    current_reconfiguration_public_output: Vec::new(),
                    state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
                },
            )
        })
        .collect();
        let stranded = ArcSwap::from_pointee(HashSet::new());
        let mut derivation_inputs = HashMap::new();
        prepare_missing_key_mappings(0, &overlay, &mut derivation_inputs, &stranded);
        assert_eq!(
            **stranded.load(),
            HashSet::from([missing_dkg, missing_reconfiguration]),
            "preparation must request recovery for incomplete prior-epoch keys only"
        );
        assert!(
            derivation_inputs.is_empty(),
            "incomplete blobs cannot derive a key"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preparation_derives_a_mapping_before_mpc_components_exist() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let object_id = ObjectID::random();
        let network_dkg_public_output = bcs::to_bytes(&VersionedNetworkDkgOutput::V4(
            include_bytes!("integration_tests/fixtures/dkg_anchor_aggregated.bcs").to_vec(),
        ))
        .unwrap();
        let current_reconfiguration_public_output =
            bcs::to_bytes(&VersionedDecryptionKeyReconfigurationOutput::V4(
                include_bytes!("integration_tests/fixtures/reconfiguration_output_aggregated.bcs")
                    .to_vec(),
            ))
            .unwrap();
        let overlay = HashMap::from([(
            object_id,
            DWalletNetworkEncryptionKeyData {
                id: object_id,
                current_epoch: 1,
                dkg_at_epoch: 0,
                network_dkg_public_output,
                current_reconfiguration_public_output,
                state: DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted,
            },
        )]);
        let mut derivation_inputs = HashMap::new();
        let stranded = ArcSwap::from_pointee(HashSet::new());
        assert_eq!(network_key_id_for(&object_id), None);
        prepare_missing_key_mappings(0, &overlay, &mut derivation_inputs, &stranded);
        assert_eq!(
            derivation_inputs.len(),
            1,
            "preparation must schedule derivation"
        );

        // No MPC manager or adoption pass exists in this test. The barrier's
        // own preparation must make progress using real serialized key data.
        let network_key_id = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if let Some(network_key_id) = network_key_id_for(&object_id) {
                    break network_key_id;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("preparation must resolve the mapping without starting MPC");
        assert_eq!(object_id_for(&network_key_id), Some(object_id));
        let certificate = certificate_naming(&[network_key_id]);
        assert_eq!(
            select(&certificate, object_id_for, |_| Some(0)).epoch_start_key(true),
            Some(Some(object_id))
        );
    }
}
