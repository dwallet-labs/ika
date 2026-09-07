// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Immutable MPC inputs inherited from the preceding epoch. Preparation reads
//! blobs by the verified certificate's digest, never through the live overlay:
//! on a restart that overlay may already contain the next committee's shares.

use crate::network_key_id_mapping::object_id_for;
use crate::validator_metadata::{PeerBlobVerdict, verify_peer_blob_for_relay};
use ika_network::mpc_artifacts::mpc_data_blob_hash;
use ika_types::committee::{Committee, EpochId};
use ika_types::crypto::AuthorityName;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::handoff::{CertifiedHandoffAttestation, HandoffItemKey};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use std::collections::HashMap;
use sui_types::base_types::ObjectID;

pub fn missing_validator_mpc_data(
    cert: &CertifiedHandoffAttestation,
    committee: &Committee,
    get_blob: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Vec<AuthorityName> {
    cert.attestation
        .items
        .iter()
        .filter_map(|(item, digest)| match item {
            HandoffItemKey::ValidatorMpcData { validator }
                if committee.authority_index(validator).is_some()
                    && !get_blob(digest).is_some_and(|bytes| {
                        matches!(
                            verify_peer_blob_for_relay(&bytes, digest),
                            PeerBlobVerdict::Accept
                        )
                    }) =>
            {
                Some(*validator)
            }
            _ => None,
        })
        .collect()
}

/// Assemble the entering epoch's network-key inputs. Chain metadata supplies
/// only the immutable creation epoch; the certificate fixes the output bytes,
/// their state, and the epoch whose access structure must decrypt them.
pub fn certified_network_key_data(
    cert: &CertifiedHandoffAttestation,
    epoch: EpochId,
    metadata: &HashMap<ObjectID, DWalletNetworkEncryptionKeyData>,
    get_blob: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> DwalletMPCResult<HashMap<ObjectID, DWalletNetworkEncryptionKeyData>> {
    if cert.attestation.epoch.checked_add(1) != Some(epoch) {
        return Err(DwalletMPCError::InternalError(
            "epoch preparation certificate does not name the preceding epoch".to_owned(),
        ));
    }
    let mut keys = HashMap::new();
    for (item, digest) in &cert.attestation.items {
        let (network_key_id, reconfiguration) = match item {
            HandoffItemKey::NetworkDkgOutput { key_id } => (key_id, false),
            HandoffItemKey::NetworkReconfigurationOutput { key_id } => (key_id, true),
            HandoffItemKey::ValidatorMpcData { .. } => continue,
        };
        let id = object_id_for(network_key_id).ok_or_else(|| {
            DwalletMPCError::InternalError(format!(
                "epoch preparation has no ObjectID mapping for {network_key_id:?}"
            ))
        })?;
        let metadata = metadata
            .get(&id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(id))?;
        let bytes = get_blob(digest)
            .filter(|bytes| mpc_data_blob_hash(bytes) == *digest)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(id))?;
        let data = keys
            .entry(id)
            .or_insert_with(|| DWalletNetworkEncryptionKeyData {
                id,
                current_epoch: epoch,
                dkg_at_epoch: metadata.dkg_at_epoch,
                network_dkg_public_output: Vec::new(),
                current_reconfiguration_public_output: Vec::new(),
                state: DWalletNetworkEncryptionKeyState::NetworkDKGCompleted,
            });
        if reconfiguration {
            data.current_reconfiguration_public_output = bytes;
            data.state = DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted;
        } else {
            data.network_dkg_public_output = bytes;
        }
    }
    if let Some(id) = keys
        .iter()
        .find_map(|(id, data)| data.network_dkg_public_output.is_empty().then_some(*id))
    {
        return Err(DwalletMPCError::WaitingForNetworkKey(id));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_key_id_mapping;
    use crate::validator_metadata::derive_mpc_data_blob;
    use dwallet_mpc_types::dwallet_mpc::NetworkKeyId;
    use dwallet_rng::RootSeed;
    use ika_types::handoff::HandoffAttestation;

    fn certificate(items: Vec<(HandoffItemKey, [u8; 32])>) -> CertifiedHandoffAttestation {
        CertifiedHandoffAttestation {
            attestation: HandoffAttestation {
                epoch: 4,
                next_committee_pubkey_set_hash: [0; 32],
                items,
            },
            signatures: Vec::new(),
        }
    }

    #[test]
    fn certified_bytes_override_a_future_epoch_overlay() {
        let id = ObjectID::random();
        let key_id = NetworkKeyId(id.into_bytes());
        network_key_id_mapping::register(id, key_id);
        let dkg = b"certified DKG".to_vec();
        let reconfiguration = b"shares for the entering committee".to_vec();
        let dkg_digest = mpc_data_blob_hash(&dkg);
        let reconfiguration_digest = mpc_data_blob_hash(&reconfiguration);
        let cert = certificate(vec![
            (HandoffItemKey::NetworkDkgOutput { key_id }, dkg_digest),
            (
                HandoffItemKey::NetworkReconfigurationOutput { key_id },
                reconfiguration_digest,
            ),
        ]);
        let metadata = HashMap::from([(
            id,
            DWalletNetworkEncryptionKeyData {
                id,
                current_epoch: 6,
                dkg_at_epoch: 2,
                network_dkg_public_output: b"untrusted overlay anchor".to_vec(),
                current_reconfiguration_public_output: b"shares for the NEXT committee".to_vec(),
                state: DWalletNetworkEncryptionKeyState::AwaitingNetworkReconfiguration,
            },
        )]);
        let blobs = HashMap::from([
            (dkg_digest, dkg.clone()),
            (reconfiguration_digest, reconfiguration.clone()),
        ]);
        let prepared =
            certified_network_key_data(&cert, 5, &metadata, |digest| blobs.get(digest).cloned())
                .unwrap();
        assert_eq!(prepared[&id].network_dkg_public_output, dkg);
        assert_eq!(
            prepared[&id].current_reconfiguration_public_output, reconfiguration,
            "startup must use the certified shares, not the live overlay"
        );
        assert_eq!(prepared[&id].current_epoch, 5);
        assert_eq!(prepared[&id].dkg_at_epoch, 2);
        assert_eq!(
            prepared[&id].state,
            DWalletNetworkEncryptionKeyState::NetworkReconfigurationCompleted
        );

        assert!(
            certified_network_key_data(&cert, 5, &metadata, |_| None).is_err(),
            "digest rows alone are not ready"
        );
        assert!(
            certified_network_key_data(&cert, 5, &metadata, |_| Some(b"corrupt".to_vec())).is_err()
        );
        assert!(
            certified_network_key_data(&cert, 5, &HashMap::new(), |digest| blobs
                .get(digest)
                .cloned())
            .is_err()
        );
        assert!(
            certified_network_key_data(&cert, 6, &metadata, |digest| blobs.get(digest).cloned())
                .is_err()
        );
    }

    #[test]
    fn absent_mapping_never_produces_an_empty_prepared_key_set() {
        let key_id = NetworkKeyId(ObjectID::random().into_bytes());
        let bytes = b"certified DKG".to_vec();
        let cert = certificate(vec![(
            HandoffItemKey::NetworkDkgOutput { key_id },
            mpc_data_blob_hash(&bytes),
        )]);
        assert!(
            certified_network_key_data(&cert, 5, &HashMap::new(), |_| Some(bytes.clone())).is_err()
        );
        assert!(
            certified_network_key_data(&certificate(Vec::new()), 5, &HashMap::new(), |_| None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn validator_bundles_must_be_present_hash_matching_and_decodable() {
        let (committee, _) = Committee::new_simple_test_committee();
        let validator = *committee.names().next().unwrap();
        let blob = derive_mpc_data_blob(&RootSeed::new([71; 32])).unwrap();
        let digest = mpc_data_blob_hash(&blob);
        let cert = certificate(vec![(
            HandoffItemKey::ValidatorMpcData { validator },
            digest,
        )]);
        assert_eq!(
            missing_validator_mpc_data(&cert, &committee, |_| None),
            vec![validator]
        );
        assert_eq!(
            missing_validator_mpc_data(&cert, &committee, |_| Some(b"wrong hash".to_vec())),
            vec![validator]
        );
        assert!(missing_validator_mpc_data(&cert, &committee, |_| Some(blob.clone())).is_empty());
        let garbage = b"hash-matching but undecodable".to_vec();
        let cert = certificate(vec![(
            HandoffItemKey::ValidatorMpcData { validator },
            mpc_data_blob_hash(&garbage),
        )]);
        assert_eq!(
            missing_validator_mpc_data(&cert, &committee, |_| Some(garbage.clone())),
            vec![validator]
        );

        let other_committee = Committee::new_for_testing_with_normalized_voting_power(
            committee.epoch,
            committee
                .names()
                .filter(|name| **name != validator)
                .map(|name| (*name, 1))
                .collect(),
        );
        assert!(
            missing_validator_mpc_data(&cert, &other_committee, |_| None).is_empty(),
            "departed validators do not feed the entering committee's MPC inputs"
        );
    }
}
