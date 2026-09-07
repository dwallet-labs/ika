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

use crate::network_key_id_mapping::object_id_for;
use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use std::cmp::Reverse;
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
    /// translatable rest would be a per-validator answer. Waiting does not
    /// help — the translation registers only when the key is instantiated
    /// or derived, after the epoch's components start.
    Untranslatable(Vec<NetworkKeyId>),
    /// Every certified key translates, but the chain metadata of these keys
    /// is not local yet. Retry: the network-key syncer publishes it.
    AwaitingMetadata(Vec<ObjectID>),
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
/// `NetworkKeyId`; the pool and the manager key by Sui `ObjectID`, and
/// `dkg_at_epoch` is chain metadata keyed by `ObjectID`, read through
/// `dkg_at_epoch_of`. If any certified key cannot be translated the answer is
/// [`Untranslatable`](NetworkOwnedAddressSigningKeySelection::Untranslatable);
/// if any translated key has no metadata yet it is
/// [`AwaitingMetadata`](NetworkOwnedAddressSigningKeySelection::AwaitingMetadata).
/// Neither chooses among the keys that are known: that choice is exactly the
/// per-validator divergence this derivation exists to remove.
pub fn select(
    certificate: &CertifiedHandoffAttestation,
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
        let Some(object_id) = object_id_for(&network_key_id) else {
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
    use ika_types::handoff::HandoffAttestation;
    use std::collections::HashMap;

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
            select(&certificate, dkg_at_epoch),
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
            select(&certificate, dkg_at_epoch),
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
            select(&certificate, dkg_at_epoch),
            NetworkOwnedAddressSigningKeySelection::Untranslatable(vec![untranslatable])
        );
    }

    #[test]
    fn missing_metadata_for_a_certified_key_waits_rather_than_choosing() {
        let [low, high] = ordered_registered_keys::<2>();
        let certificate = certificate_naming(&[low.1, high.1]);
        assert_eq!(
            select(&certificate, metadata(&[(high.0, 0)])),
            NetworkOwnedAddressSigningKeySelection::AwaitingMetadata(vec![low.0])
        );
        // The same inputs plus the missing metadata resolve.
        assert_eq!(
            select(&certificate, metadata(&[(low.0, 0), (high.0, 0)])),
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
            select(&certificate, |_| None),
            NetworkOwnedAddressSigningKeySelection::Untranslatable(vec![untranslatable])
        );
    }

    #[test]
    fn a_certificate_naming_no_key_selects_none() {
        let certificate = certificate_naming(&[]);
        assert_eq!(
            select(&certificate, |_| Some(0)),
            NetworkOwnedAddressSigningKeySelection::NoCertifiedKey
        );
    }
}
