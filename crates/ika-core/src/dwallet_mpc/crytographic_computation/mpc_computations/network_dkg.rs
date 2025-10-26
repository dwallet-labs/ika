// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! This module contains the network DKG protocol for the dWallet MPC sessions.
//! The network DKG protocol handles generating the network Decryption-Key shares.
//! The module provides the management of the network Decryption-Key shares and
//! the network DKG protocol.

use crate::dwallet_mpc::crytographic_computation::protocol_public_parameters::ProtocolPublicParametersByCurve;
use crate::dwallet_mpc::reconfiguration::instantiate_dwallet_mpc_network_encryption_key_public_data_from_reconfiguration_public_output;
use class_groups::dkg::{Secp256k1Party, Secp256k1PublicInput};
use class_groups::{
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, Secp256k1DecryptionKeySharePublicParameters,
    SecretKeyShareSizedInteger,
};
use commitment::CommitmentSizedNumber;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{
    DWalletCurve, NetworkDecryptionKeyPublicOutputType, NetworkEncryptionKeyPublicDataTrait,
    NetworkEncryptionKeyPublicDataV1, NetworkEncryptionKeyPublicDataV2, ReconfigurationParty,
    SerializedWrappedMPCPublicOutput, VersionedDecryptionKeyReconfigurationOutput,
    VersionedNetworkDkgOutput, VersionedNetworkEncryptionKeyPublicData,
};
use group::{GroupElement, PartyID, secp256k1};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use ika_types::committee::ClassGroupsEncryptionKeyAndProof;
use ika_types::dwallet_mpc_error::{DwalletMPCError, DwalletMPCResult};
use ika_types::messages_dwallet_mpc::{
    DWalletNetworkEncryptionKeyData, DWalletNetworkEncryptionKeyState,
};
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party};
use mpc::{
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, WeightedThresholdAccessStructure,
};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use sui_types::base_types::ObjectID;
use tokio::sync::oneshot;
use tracing::error;
use twopc_mpc::ProtocolPublicParameters;
use twopc_mpc::decentralized_party::dkg;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};

/// Holds the network (decryption) keys of the network MPC protocols.
pub struct DwalletMPCNetworkKeys {
    /// Holds all network (decryption) keys for the current network in encrypted form.
    /// This data is identical for all the Validator nodes.
    pub(crate) network_encryption_keys: HashMap<ObjectID, VersionedNetworkEncryptionKeyPublicData>,
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
        HashMap<ObjectID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
}

async fn get_decryption_key_shares_from_public_output(
    shares: VersionedNetworkEncryptionKeyPublicData,
    party_id: PartyID,
    personal_decryption_key: ClassGroupsDecryptionKey,
    access_structure: WeightedThresholdAccessStructure,
) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
    let (key_shares_sender, key_shares_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = match shares.state() {
            NetworkDecryptionKeyPublicOutputType::NetworkDkg => {
                match &shares.network_dkg_output() {
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
                    VersionedNetworkDkgOutput::V2(public_output) => {
                        match bcs::from_bytes::<<dkg::Party as mpc::Party>::PublicOutput>(
                            public_output,
                        ) {
                            Ok(dkg_public_output) => dkg_public_output
                                .decrypt_decryption_key_shares(
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
                match &shares
                    .latest_network_reconfiguration_public_output()
                    .unwrap()
                {
                    VersionedDecryptionKeyReconfigurationOutput::V1(public_output) => {
                        match bcs::from_bytes::<
                            <ReconfigurationParty as mpc::Party>::PublicOutput,
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
                    VersionedDecryptionKeyReconfigurationOutput::V2(public_output) => {
                        match bcs::from_bytes::<
                            <twopc_mpc::decentralized_party::reconfiguration::Party as mpc::Party>::PublicOutput,
                        >(public_output)
                        {
                            Ok(public_output) => public_output
                                .decrypt_decryption_key_shares(
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
        key: VersionedNetworkEncryptionKeyPublicData,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> DwalletMPCResult<()> {
        let decryption_key_shares = get_decryption_key_shares_from_public_output(
            key.clone(),
            self.party_id,
            self.class_groups_decryption_key,
            access_structure.clone(),
        )
        .await?;

        self.validator_decryption_key_shares
            .insert(key_id, decryption_key_shares);
        Ok(())
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
        key: &VersionedNetworkEncryptionKeyPublicData,
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
            .secp256k1_decryption_key_share_public_parameters()
            .clone())
    }

    pub fn get_network_key_version(&self, key_id: &ObjectID) -> DwalletMPCResult<usize> {
        let latest_reconfig_data = self
            .network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::InternalError(format!(
                "cannot find network encryption key for key ID {key_id}"
            )))?
            .latest_network_reconfiguration_public_output()
            .clone();
        if latest_reconfig_data.is_none() {
            let network_dkg_output = self
                .network_encryption_keys
                .get(key_id)
                .ok_or(DwalletMPCError::InternalError(format!(
                    "cannot find network encryption key for key ID {key_id}"
                )))?
                .network_dkg_output()
                .clone();
            return Ok(match network_dkg_output {
                VersionedNetworkDkgOutput::V1(_) => 1,
                VersionedNetworkDkgOutput::V2(_) => 2,
            });
        }
        Ok(match latest_reconfig_data.unwrap() {
            VersionedDecryptionKeyReconfigurationOutput::V1(_) => 1,
            VersionedDecryptionKeyReconfigurationOutput::V2(_) => 2,
        })
    }

    /// Retrieves the decryption key shares for the current authority.
    pub(crate) fn decryption_key_shares(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<HashMap<PartyID, SecretKeyShareSizedInteger>> {
        self.validator_private_dec_key_data
            .validator_decryption_key_shares
            .get(key_id)
            .cloned()
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))
    }

    pub fn key_public_data_exists(&self, key_id: &ObjectID) -> bool {
        self.network_encryption_keys.contains_key(key_id)
    }

    pub fn get_network_encryption_key_public_data(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<&VersionedNetworkEncryptionKeyPublicData> {
        self.network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))
    }

    /// Retrieves the protocol public parameters for the specified key ID.
    pub fn get_protocol_public_parameters(
        &self,
        curve: &DWalletCurve,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<ProtocolPublicParametersByCurve> {
        let Some(result) = self.network_encryption_keys.get(key_id) else {
            error!(
                ?key_id,
                "failed to fetch the network decryption key shares for key ID"
            );
            return Err(DwalletMPCError::WaitingForNetworkKey(*key_id));
        };

        let protocol_public_parameters = match curve {
            DWalletCurve::Secp256k1 => ProtocolPublicParametersByCurve::Secp256k1(
                result.secp256k1_protocol_public_parameters().clone(),
            ),
            DWalletCurve::Secp256r1 => ProtocolPublicParametersByCurve::Secp256r1(
                result.secp256r1_protocol_public_parameters()?.clone(),
            ),
            DWalletCurve::Ristretto => ProtocolPublicParametersByCurve::Ristretto(
                result.ristretto_protocol_public_parameters()?.clone(),
            ),
            DWalletCurve::Curve25519 => ProtocolPublicParametersByCurve::Curve25519(
                result.curve25519_protocol_public_parameters()?.clone(),
            ),
        };

        Ok(protocol_public_parameters)
    }

    pub fn get_network_dkg_public_output(
        &self,
        key_id: &ObjectID,
    ) -> DwalletMPCResult<VersionedNetworkDkgOutput> {
        Ok(self
            .network_encryption_keys
            .get(key_id)
            .ok_or(DwalletMPCError::WaitingForNetworkKey(*key_id))?
            .network_dkg_output()
            .clone())
    }

    pub fn get_last_reconfiguration_output(
        &self,
        key_id: &ObjectID,
    ) -> Option<VersionedDecryptionKeyReconfigurationOutput> {
        let key = self.network_encryption_keys.get(key_id)?;
        key.latest_network_reconfiguration_public_output()
    }
}

/// Advances the network DKG protocol for the supported key types.
pub(crate) fn advance_network_dkg_v1(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <Secp256k1Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<Secp256k1Party as mpc::Party>::Message>,
    class_groups_decryption_key: ClassGroupsDecryptionKey,
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = Party::<Secp256k1Party>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        Some(class_groups_decryption_key),
        &public_input,
        rng,
    );

    let res = match result.clone() {
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
    }?;

    Ok(res)
}

/// Advances the network DKG protocol for the supported key types.
pub(crate) fn advance_network_dkg_v2(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: <dkg::Party as mpc::Party>::PublicInput,
    party_id: PartyID,
    advance_request: AdvanceRequest<<dkg::Party as mpc::Party>::Message>,
    class_groups_decryption_key: ClassGroupsDecryptionKey,
    rng: &mut ChaCha20Rng,
) -> DwalletMPCResult<GuaranteedOutputDeliveryRoundResult> {
    let result = Party::<dkg::Party>::advance_with_guaranteed_output(
        session_id,
        party_id,
        access_structure,
        advance_request,
        Some(class_groups_decryption_key),
        &public_input,
        rng,
    );

    let res = match result.clone() {
        Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
            public_output_value,
            malicious_parties,
            private_output,
        }) => {
            let public_output_value =
                bcs::to_bytes(&VersionedNetworkDkgOutput::V2(public_output_value))?;

            Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output,
            })
        }
        _ => result,
    }?;

    Ok(res)
}

pub(crate) fn network_dkg_v1_public_input(
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

pub(crate) fn network_dkg_v2_public_input(
    access_structure: &WeightedThresholdAccessStructure,
    encryption_keys_and_proofs: HashMap<PartyID, ClassGroupsEncryptionKeyAndProof>,
) -> DwalletMPCResult<<dkg::Party as mpc::Party>::PublicInput> {
    let public_input =
        <dkg::Party as mpc::Party>::PublicInput::new(access_structure, encryption_keys_and_proofs)
            .map_err(|e| DwalletMPCError::InvalidMPCPartyType(e.to_string()))?;

    Ok(public_input)
}

pub(crate) async fn instantiate_dwallet_mpc_network_encryption_key_public_data_from_public_output(
    epoch: u64,
    access_structure: WeightedThresholdAccessStructure,
    key_data: DWalletNetworkEncryptionKeyData,
) -> DwalletMPCResult<VersionedNetworkEncryptionKeyPublicData> {
    let (key_public_data_sender, key_public_data_receiver) = oneshot::channel();

    rayon::spawn_fifo(move || {
        let res = if key_data.current_reconfiguration_public_output.is_empty() {
            if key_data.state == DWalletNetworkEncryptionKeyState::AwaitingNetworkDKG {
                Err(DwalletMPCError::WaitingForNetworkKey(key_data.id))
            } else {
                instantiate_dwallet_mpc_network_encryption_key_public_data_from_dkg_public_output(
                    epoch,
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
    access_structure: &WeightedThresholdAccessStructure,
    public_output_bytes: &SerializedWrappedMPCPublicOutput,
) -> DwalletMPCResult<VersionedNetworkEncryptionKeyPublicData> {
    let mpc_public_output: VersionedNetworkDkgOutput =
        bcs::from_bytes(public_output_bytes).map_err(DwalletMPCError::BcsError)?;

    match &mpc_public_output {
        VersionedNetworkDkgOutput::V1(public_output_bytes) => {
            let public_output: <Secp256k1Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;

            let decryption_key_share_public_parameters = public_output
                .default_decryption_key_share_public_parameters::<secp256k1::GroupElement>(
                    access_structure,
                )
                .map_err(DwalletMPCError::from)?;

            let neutral_group_value =
                group::secp256k1::GroupElement::neutral_from_public_parameters(
                    &group::secp256k1::group_element::PublicParameters::default(),
                )
                .map_err(twopc_mpc::Error::from)?
                .value();
            let neutral_ciphertext_value =
                ::class_groups::CiphertextSpaceGroupElement::neutral_from_public_parameters(
                    decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
                .map_err(twopc_mpc::Error::from)?
                .value();

            let protocol_public_parameters = ProtocolPublicParameters::new::<
                { secp256k1::SCALAR_LIMBS },
                { FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >(
                neutral_group_value,
                neutral_group_value,
                neutral_ciphertext_value,
                neutral_ciphertext_value,
                decryption_key_share_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
            );

            Ok(VersionedNetworkEncryptionKeyPublicData::V1(
                NetworkEncryptionKeyPublicDataV1 {
                    epoch,
                    state: NetworkDecryptionKeyPublicOutputType::NetworkDkg,
                    latest_network_reconfiguration_public_output: None,
                    secp256k1_decryption_key_share_public_parameters:
                        decryption_key_share_public_parameters,
                    network_dkg_output: mpc_public_output,
                    secp256k1_protocol_public_parameters: protocol_public_parameters,
                },
            ))
        }
        VersionedNetworkDkgOutput::V2(public_output_bytes) => {
            let public_output: <dkg::Party as mpc::Party>::PublicOutput =
                bcs::from_bytes(public_output_bytes)?;

            let decryption_key_share_public_parameters = public_output
                .secp256k1_decryption_key_share_public_parameters(access_structure)
                .map_err(DwalletMPCError::from)?;

            Ok(VersionedNetworkEncryptionKeyPublicData::V2(
                NetworkEncryptionKeyPublicDataV2 {
                    epoch,
                    state: NetworkDecryptionKeyPublicOutputType::NetworkDkg,
                    latest_network_reconfiguration_public_output: None,
                    secp256k1_decryption_key_share_public_parameters:
                        decryption_key_share_public_parameters,
                    secp256r1_protocol_public_parameters: public_output
                        .secp256r1_protocol_public_parameters()?,
                    secp256r1_decryption_key_share_public_parameters: public_output
                        .secp256r1_decryption_key_share_public_parameters(access_structure)?,
                    ristretto_protocol_public_parameters: public_output
                        .ristretto_protocol_public_parameters()?,
                    ristretto_decryption_key_share_public_parameters: public_output
                        .ristretto_decryption_key_share_public_parameters(access_structure)?,
                    curve25519_protocol_public_parameters: public_output
                        .curve25519_protocol_public_parameters()?,
                    network_dkg_output: mpc_public_output,
                    secp256k1_protocol_public_parameters: public_output
                        .secp256k1_protocol_public_parameters()?,
                    curve25519_decryption_key_share_public_parameters: public_output
                        .curve25519_decryption_key_share_public_parameters(access_structure)?,
                },
            ))
        }
    }
}
