// Copyright (c) dWallet Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the network DKG protocol for the dWallet MPC sessions.
//! The network DKG protocol handles generating the network Decryption-Key shares.
//! The module provides the management of the network Decryption-Key shares and
//! the network DKG protocol.

use crate::dwallet_mpc::crytographic_computation::advance;
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::reconfiguration::{
    ReconfigurationSecp256k1Party,
    instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output,
};
use class_groups::dkg::{Secp256k1Party, Secp256k1PublicInput};
use class_groups::{
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, Secp256k1DecryptionKeySharePublicParameters,
    SecretKeyShareSizedInteger,
};
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletMPCNetworkKeyScheme, NetworkDecryptionKeyPublicOutputType,
    NetworkEncryptionKeyPublicData, SerializedWrappedMPCPublicOutput, VersionedNetworkDkgOutput,
};
use group::{OsCsRng, PartyID, secp256k1};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::AsyncProtocol;
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkDKGEncryptionKeyRequestEvent, DWalletNetworkEncryptionKeyData,
    DWalletNetworkEncryptionKeyState, DWalletSessionEvent, MPCRequestInput, MPCSessionRequest,
};
use mpc::{GuaranteedOutputDeliveryRoundResult, WeightedThresholdAccessStructure};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use sui_types::base_types::ObjectID;
use tokio::sync::oneshot;
use tracing::error;
use twopc_mpc::ProtocolPublicParameters;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use twopc_mpc::sign::Protocol;

/// Holds the network (decryption) keys of the network MPC protocols.
pub struct DwalletMPCNetworkKeys {
    /// Holds all network (decryption) keys for the current network in encrypted form.
    /// This data is identical for all the Validator nodes.
    pub(crate) network_encryption_keys: HashMap<ObjectID, NetworkEncryptionKeyPublicData>,
    pub(crate) validator_private_dec_key_data: ValidatorPrivateDecryptionKeyData,
}

/// Holds the private decryption key data for a validator node.
pub struct ValidatorPrivateDecryptionKeyData {
    /// The unique party ID of the validator, representing its index within the committee.
    pub party_id: PartyID,

    /// The validator's class groups decryption key.
    pub class_groups_decryption_key: ClassGroupsDecryptionKey,

    /// A map of the validator's decryption key shares.
    ///
    /// This structure maps each key ID (`ObjectID`) to a sub-map of `PartyID`
    /// to the corresponding decryption key share.
    /// These shares are used in multi-party cryptographic protocols.
    /// NOTE: EACH PARTY IN HERE IS A **VIRTUAL PARTY**.
    /// NOTE 2: `ObjectID` is the ID of the network decryption key, not the party.
    pub validator_decryption_key_shares:
        HashMap<ObjectID, HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>>,
}

async fn get_decryption_key_shares_from_public_output(
    shares: NetworkEncryptionKeyPublicData,
    party_id: PartyID,
    personal_decryption_key: ClassGroupsDecryptionKey,
    access_structure: WeightedThresholdAccessStructure,
) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
    let (key_shares_sender, key_shares_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = match shares.state {
            NetworkDecryptionKeyPublicOutputType::NetworkDkg => {
                match &shares.latest_public_output {
                    VersionedNetworkDkgOutput::V1(public_output) => {
                        match bcs::from_bytes::<<Secp256k1Party as mpc::Party>::PublicOutput>(
                            public_output,
                        ) {
                            Ok(dkg_public_output) => dkg_public_output
                                .default_decryption_key_shares::<secp256k1::GroupElement>(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                }
            }
            NetworkDecryptionKeyPublicOutputType::Reconfiguration => {
                match &shares.latest_public_output {
                    VersionedNetworkDkgOutput::V1(public_output) => {
                        match bcs::from_bytes::<
                            <ReconfigurationSecp256k1Party as mpc::Party>::PublicOutput,
                        >(public_output)
                        {
                            Ok(public_output) => public_output
                                .decrypt_decryption_key_shares::<secp256k1::GroupElement>(
                                    party_id,
                                    &access_structure,
                                    personal_decryption_key,
                                )
                                .map_err(DwalletMPCError::from),
                            Err(e) => Err(e.into()),
                        }
                    }
                }
            }
        };

        if let Err(err) = key_shares_sender.send(res) {
            error!(error=?err, "failed to send key shares");
        }
    });

    key_shares_receiver
        .await
        .map_err(|_| DwalletMPCError::TokioRecv)?
}

impl ValidatorPrivateDecryptionKeyData {
    /// Stores the new decryption key shares of the validator.
    /// Decrypts the decryption key shares (for all the virtual parties)
    /// from the public output of the network DKG protocol.
    pub async fn decrypt_and_store_secret_key_shares(
        &mut self,
        key_id: ObjectID,
        key: NetworkEncryptionKeyPublicData,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> DwalletMPCResult<()> {
        let secret_key_shares = get_decryption_key_shares_from_public_output(
            key.clone(),
            self.party_id,
            self.class_groups_decryption_key,
            access_structure.clone(),
        )
        .await?;

        let self_decryption_key_shares = Self::convert_secret_key_shares_type_to_decryption_shares(
            secret_key_shares,
            &key.decryption_key_share_public_parameters,
        )?;

        self.validator_decryption_key_shares
            .insert(key_id, self_decryption_key_shares);
        Ok(())
    }

    /// Only for type convertion.
    fn convert_secret_key_shares_type_to_decryption_shares(
        secret_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        public_parameters: &Secp256k1DecryptionKeySharePublicParameters,
    ) -> DwalletMPCResult<HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>> {
        secret_shares
            .into_iter()
            .map(|(virtual_party_id, secret_key_share)| {
                let decryption_key_share = <AsyncProtocol as Protocol>::DecryptionKeyShare::new(
                    virtual_party_id,
                    secret_key_share,
                    public_parameters,
                    &mut OsCsRng,
                )
                .map_err(DwalletMPCError::from)?;

                Ok((virtual_party_id, decryption_key_share))
            })
            .collect::<DwalletMPCResult<HashMap<_, _>>>()
    }
}

impl DwalletMPCNetworkKeys {
    pub fn new(node_context: ValidatorPrivateDecryptionKeyData) -> Self {
        Self {
            network_encryption_keys: Default::default(),
            validator_private_dec_key_data: node_context,
        }
    }

    pub async fn update_network_key(
        &mut self,
        key_id: ObjectID,
        key: &NetworkEncryptionKeyPublicData,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> DwalletMPCResult<()> {
        self.network_encryption_keys.insert(key_id, key.clone());
        self.validator_private_dec_key_data
            .decrypt_and_store_secret_key_shares(key_id, key.clone(), access_structure)
            .await
    }

    pub fn get_decryption_key_share_public_parameters(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<Secp256k1DecryptionKeySharePublicParameters> {
        Ok(self
            .network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))?
            .decryption_key_share_public_parameters
            .clone())
    }

    /// Retrieves the decryption key shares for the current authority.
    pub(crate) fn get_decryption_key_shares(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>> {
        self.validator_private_dec_key_data
            .validator_decryption_key_shares
            .get(key_id)
            .cloned()
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))
    }

    pub fn key_public_data_exists(&self, key_id: &ObjectID) -> bool {
        self.network_encryption_keys.contains_key(key_id)
    }

    /// Retrieves the protocol public parameters for the specified key ID.
    pub fn get_protocol_public_parameters(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters> {
        let Some(result) = self.network_encryption_keys.get(key_id) else {
            error!(
                ?key_id,
                "failed to fetch the network decryption key shares for key ID"
            );
            return Err(DwalletMPCError::WaitingForNetworkKey(*key_id));
        };
        Ok(result.protocol_public_parameters.clone())
    }

    pub fn get_network_dkg_public_output(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<VersionedNetworkDkgOutput> {
        Ok(self
            .network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))?
            .network_dkg_output
            .clone())
    }
}

/// Advances the network DKG protocol for the supported key types.
pub(crate) fn advance_network_dkg(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: &PublicInput,
    party_id: PartyID,
    key_scheme: &DWalletMPCNetworkKeyScheme,
    messages: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    class_groups_decryption_key: ClassGroupsDecryptionKey,
    rng: ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let res = match key_scheme {
        DWalletMPCNetworkKeyScheme::Secp256k1 => {
            let PublicInput::NetworkEncryptionKeyDkg(public_input) = public_input else {
                unreachable!();
            };
            let result = advance::<Secp256k1Party>(
                session_id,
                party_id,
                access_structure,
                messages,
                public_input,
                class_groups_decryption_key,
                rng,
            );
            match result.clone() {
                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                    public_output_value,
                    malicious_parties,
                    private_output,
                }) => {
                    let public_output_value =
                        bcs::to_bytes(&VersionedNetworkDkgOutput::V1(public_output_value))?;

                    Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                        public_output_value,
                        malicious_parties,
                        private_output,
                    })
                }
                _ => result,
            }
        }
        DWalletMPCNetworkKeyScheme::Ristretto => todo!(),
    }?;
    Ok(res)
}

pub(crate) fn network_dkg_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
    key_scheme: DWalletMPCNetworkKeyScheme,
) -> DwalletMPCResult<<Secp256k1Party as mpc::Party>::PublicInput> {
    match key_scheme {
        DWalletMPCNetworkKeyScheme::Secp256k1 => {
            generate_secp256k1_dkg_party_public_input(access_structure, encryption_keys_and_proofs)
        }
        DWalletMPCNetworkKeyScheme::Ristretto => todo!(),
    }
}

pub(crate) fn network_dkg_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
    key_scheme: DWalletMPCNetworkKeyScheme,
) -> DwalletMPCResult<MPCSessionRequest> {
    match key_scheme {
        DWalletMPCNetworkKeyScheme::Secp256k1 => {
            Ok(network_dkg_secp256k1_session_request(deserialized_event))
        }
        DWalletMPCNetworkKeyScheme::Ristretto => {
            Ok(network_dkg_ristretto_session_request(deserialized_event))
        }
    }
}

fn network_dkg_secp256k1_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
) -> MPCSessionRequest {
    MPCSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        epoch: deserialized_event.epoch,
        request_input: MPCRequestInput::NetworkEncryptionKeyDkg(
            DWalletMPCNetworkKeyScheme::Secp256k1,
            deserialized_event,
        ),
        requires_network_key_data: false,
        requires_next_active_committee: false,
    }
}

fn network_dkg_ristretto_session_request(
    deserialized_event: DWalletSessionEvent<DWalletNetworkDKGEncryptionKeyRequestEvent>,
) -> MPCSessionRequest {
    MPCSessionRequest {
        session_type: deserialized_event.session_type,
        session_identifier: deserialized_event.session_identifier_digest(),
        session_sequence_number: deserialized_event.session_sequence_number,
        epoch: deserialized_event.epoch,
        request_input: MPCRequestInput::NetworkEncryptionKeyDkg(
            DWalletMPCNetworkKeyScheme::Ristretto,
            deserialized_event,
        ),
        requires_network_key_data: false,
        requires_next_active_committee: false,
    }
}

pub(crate) fn generate_secp256k1_dkg_party_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
) -> DwalletMPCResult<<Secp256k1Party as mpc::Party>::PublicInput> {
    let public_input = Secp256k1PublicInput::new::<secp256k1::GroupElement>(
        access_structure,
        secp256k1::scalar::PublicParameters::default(),
        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        encryption_keys_and_proofs,
    )
    .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))?;

    Ok(public_input)
}

pub(crate) async fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
    epoch: u64,
    key_scheme: DWalletMPCNetworkKeyScheme,
    access_structure: WeightedThresholdAccessStructure,
    key_data: DWalletNetworkEncryptionKeyData,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let (key_public_data_sender, key_public_data_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = if key_data.current_reconfiguration_public_output.is_empty() {
            if key_data.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG {
                Err(DwalletMPCError::WaitingForNetworkKey(key_data.id))
            } else {
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
                    epoch,
                    key_scheme,
                    &access_structure,
                    &key_data.network_dkg_public_output,
                )
            }
        } else {
            instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output(
                epoch,
                &access_structure,
                &key_data.current_reconfiguration_public_output,
                &key_data.network_dkg_public_output,
            )
        };

        if let Err(err) = key_public_data_sender.send(res) {
            error!(error=?err, "failed to send a network encryption key ");
        }
    });

    key_public_data_receiver
        .await
        .map_err(|_| DwalletMPCError::TokioRecv)?
}

fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
    epoch: u64,
    key_scheme: DWalletMPCNetworkKeyScheme,
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<NetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    match key_scheme {
        DWalletMPCNetworkKeyScheme::Secp256k1 => match &mpc_public_output {
            VersionedNetworkDkgOutput::V1(public_output_bytes) => {
                let public_output: <Secp256k1Party as mpc::Party>::PublicOutput =
                    bcs::from_bytes(public_output_bytes)?;

                let decryption_key_share_public_parameters = public_output
                    .default_decryption_key_share_public_parameters::<secp256k1::GroupElement>(
                        access_structure,
                    )
                    .map_err(DwalletMPCError::from)?;

                let protocol_public_parameters = ProtocolPublicParameters::new::<
                    { secp256k1::SCALAR_LIMBS },
                    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >(
                    decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .clone(),
                );

                Ok(NetworkEncryptionKeyPublicData {
                    epoch,
                    state: NetworkDecryptionKeyPublicOutputType::NetworkDkg,
                    latest_public_output: mpc_public_output.clone(),
                    decryption_key_share_public_parameters,
                    network_dkg_output: mpc_public_output,
                    protocol_public_parameters,
                })
            }
        },
        DWalletMPCNetworkKeyScheme::Ristretto => todo!("Ristretto key scheme"),
    }
}
