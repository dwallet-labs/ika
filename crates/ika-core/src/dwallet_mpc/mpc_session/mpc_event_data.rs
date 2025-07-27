// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::dwallet_mpc::mpc_session::input::PublicInput;
use crate::dwallet_mpc::mpc_session::session_input_from_event;
use crate::dwallet_mpc::network_dkg::DwalletMPCNetworkKeys;
use dwallet_mpc_types::dwallet_mpc::MPCPrivateInput;
use group::PartyID;
use ika_types::committee::{ClassGroupsEncryptionKeyAndProof, Committee};
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::messages_dwallet_mpc::{
    AsyncProtocol, DWalletMPCEvent, MPCRequestInput, SessionType,
};
use mpc::WeightedThresholdAccessStructure;
use std::cmp::Ordering;
use std::collections::HashMap;
use tracing::error;
use twopc_mpc::sign::Protocol;

/// The DWallet MPC session data that is based on the event that initiated the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MPCEventData {
    pub private_input: MPCPrivateInput,
    pub request_input: MPCRequestInput,
    pub(crate) decryption_key_shares:
        Option<HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>>,
    pub(crate) session_type: SessionType,
    pub(crate) session_sequence_number: u64,
    pub(crate) public_input: PublicInput,
    pub(crate) requires_network_key_data: bool,
    pub(crate) requires_next_active_committee: bool,
}

impl MPCEventData {
    pub(crate) fn try_new(
        event: DWalletMPCEvent,
        access_structure: &WeightedThresholdAccessStructure,
        committee: &Committee,
        network_keys: &DwalletMPCNetworkKeys,
        next_active_committee: Option<Committee>,
        validators_class_groups_public_keys_and_proofs: HashMap<
            PartyID,
            ClassGroupsEncryptionKeyAndProof,
        >,
    ) -> Result<Self, DwalletMPCError> {
        let (public_input, private_input) = session_input_from_event(
            event.clone(),
            access_structure,
            committee,
            network_keys,
            next_active_committee,
            validators_class_groups_public_keys_and_proofs,
        )?;

        let needs_decryption_key_shares = matches!(
            event.session_request.request_input.clone(),
            MPCRequestInput::Sign(_) | MPCRequestInput::NetworkEncryptionKeyReconfiguration(_)
        );

        let decryption_key_shares = if needs_decryption_key_shares {
            if let Some(network_encryption_key_id) = event
                .session_request
                .request_input
                .get_network_encryption_key_id()
            {
                Some(network_keys.get_decryption_key_shares(&network_encryption_key_id)?)
            } else {
                error!(
                    should_never_happen =? true,
                    session_identifier=?event.session_request.session_identifier,
                    "failed to get network encryption key ID for a session that requires decryption key shares",
                );

                None
            }
        } else {
            None
        };

        let mpc_event_data = Self {
            session_type: event.session_request.session_type,
            session_sequence_number: event.session_request.session_sequence_number,
            request_input: event.session_request.request_input,
            private_input,
            decryption_key_shares,
            public_input,
            requires_network_key_data: event.session_request.requires_network_key_data,
            requires_next_active_committee: event.session_request.requires_next_active_committee,
        };

        Ok(mpc_event_data)
    }
}

impl PartialOrd<Self> for MPCEventData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MPCEventData {
    fn cmp(&self, other: &Self) -> Ordering {
        // System sessions have a higher priority than user session and therefore come first (are smaller).
        // Both system and user sessions are sorted by their sequence number between themselves.
        match (self.session_type, other.session_type) {
            (SessionType::User, SessionType::User) => self
                .session_sequence_number
                .cmp(&other.session_sequence_number),
            (SessionType::System, SessionType::User) => Ordering::Less,
            (SessionType::System, SessionType::System) => self
                .session_sequence_number
                .cmp(&other.session_sequence_number),
            (SessionType::User, SessionType::System) => Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use class_groups::DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER;
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::construct_setup_parameters_per_crt_prime;
    use class_groups::test_helpers::setup_dkg_secp256k1;
    use dwallet_mpc_types::dwallet_mpc::DWalletMPCNetworkKeyScheme;
    use group::OsCsRng;
    use ika_types::messages_dwallet_mpc::DWalletNetworkDKGEncryptionKeyRequestEvent;
    use ika_types::messages_dwallet_mpc::test_helpers::mock_dwallet_session_event;
    use sui_types::base_types::ObjectID;

    fn mock_mpc_event_data(is_system: bool, session_sequence_number: u64) -> MPCEventData {
        let event_data = DWalletNetworkDKGEncryptionKeyRequestEvent {
            dwallet_network_encryption_key_id: ObjectID::random(),
            params_for_network: vec![],
        };

        let event = mock_dwallet_session_event(is_system, session_sequence_number, event_data);

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let access_structure =
            WeightedThresholdAccessStructure::uniform(2, 2, 2, &mut OsCsRng).unwrap();

        let (_, _, public_inputs) = setup_dkg_secp256k1(
            &access_structure,
            setup_parameters_per_crt_prime.clone(),
            true,
        );

        let public_input =
            PublicInput::NetworkEncryptionKeyDkg(public_inputs.into_values().next().unwrap());

        MPCEventData {
            private_input: None,
            request_input: MPCRequestInput::NetworkEncryptionKeyDkg(
                DWalletMPCNetworkKeyScheme::Secp256k1,
                event.clone(),
            ),
            decryption_key_shares: None,
            session_type: event.session_type,
            session_sequence_number: event.session_sequence_number,
            public_input,
            requires_network_key_data: false,
            requires_next_active_committee: false,
        }
    }

    #[test]
    fn orders() {
        let first = mock_mpc_event_data(true, 3);
        let second = mock_mpc_event_data(false, 1);
        let third = mock_mpc_event_data(false, 3);
        let fourth = mock_mpc_event_data(true, 2);
        let fifth = mock_mpc_event_data(true, 5);
        let sixth = mock_mpc_event_data(false, 2);

        let mut ordered = vec![
            (2, first),
            (4, second),
            (6, third),
            (1, fourth),
            (3, fifth),
            (5, sixth),
        ];
        ordered.sort_by(|(_, first_event_data), (_, second_event_data)| {
            first_event_data.cmp(second_event_data)
        });

        let ordered_keys: Vec<_> = ordered.into_iter().map(|(key, _)| key).collect();

        assert_eq!(ordered_keys, vec![1, 2, 3, 4, 5, 6]);
    }
}
