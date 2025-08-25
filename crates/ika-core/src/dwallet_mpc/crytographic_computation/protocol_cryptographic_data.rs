use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::mpc_session::PublicInput;
use crate::dwallet_mpc::network_dkg::DwalletMPCNetworkKeys;
use crate::dwallet_mpc::presign::PresignParty;
use crate::dwallet_mpc::reconfiguration::ReconfigurationSecp256k1Party;
use crate::dwallet_mpc::sign::SignParty;
use crate::request_protocol_data::{
    DKGFirstData, DKGSecondData, EncryptedShareVerificationData, ImportedKeyVerificationData,
    MakeDWalletUserSecretKeySharesPublicData, NetworkEncryptionKeyDkgData,
    NetworkEncryptionKeyReconfigurationData, PartialSignatureVerificationData, PresignData,
    ProtocolData, SignData,
};
use class_groups::dkg::Secp256k1Party;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use group::PartyID;
use ika_types::dwallet_mpc_error::DwalletMPCError;
use ika_types::messages_dwallet_mpc::AsyncProtocol;
use mpc::guaranteed_output_delivery::{AdvanceRequest, Party, ReadyToAdvanceResult};
use mpc::{GuaranteesOutputDelivery, WeightedThresholdAccessStructure};
use std::collections::HashMap;
use twopc_mpc::sign::Protocol;
use ika_protocol_config::ProtocolConfig;

pub enum ProtocolCryptographicData {
    ImportedKeyVerification {
        data: ImportedKeyVerificationData,
        public_input: <DWalletImportedKeyVerificationParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<()>,
    },

    MakeDWalletUserSecretKeySharesPublic {
        data: MakeDWalletUserSecretKeySharesPublicData,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },

    DKGFirst {
        data: DKGFirstData,
        public_input: <DWalletDKGFirstParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<DWalletDKGFirstParty as mpc::Party>::Message>,
    },

    DKGSecond {
        data: DKGSecondData,
        public_input: <DWalletDKGSecondParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<DWalletDKGSecondParty as mpc::Party>::Message>,
    },

    Presign {
        data: PresignData,
        public_input: <PresignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<PresignParty as mpc::Party>::Message>,
    },

    Sign {
        data: SignData,
        public_input: <SignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<SignParty as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
    },

    NetworkEncryptionKeyDkg {
        data: NetworkEncryptionKeyDkgData,
        public_input: <Secp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<Secp256k1Party as mpc::Party>::Message>,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    },

    NetworkEncryptionKeyReconfiguration {
        data: NetworkEncryptionKeyReconfigurationData,
        public_input: <ReconfigurationSecp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationSecp256k1Party as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, <AsyncProtocol as Protocol>::DecryptionKeyShare>,
        key_version: usize
    },

    EncryptedShareVerification {
        data: EncryptedShareVerificationData,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },

    PartialSignatureVerification {
        data: PartialSignatureVerificationData,
        protocol_public_parameters: twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters,
    },
}

impl ProtocolCryptographicData {
    pub fn try_new(
        protocol_specific_data: &ProtocolData,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        consensus_round: u64,
        serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
        public_input: PublicInput,
        network_dkg_third_round_delay: u64,
        decryption_key_reconfiguration_third_round_delay: u64,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
        decryption_key_shares: &Box<DwalletMPCNetworkKeys>,
        protocol_config: &ProtocolConfig,
    ) -> Result<Option<Self>, DwalletMPCError> {
        let res = match protocol_specific_data {
            ProtocolData::MakeDWalletUserSecretKeySharesPublic {
                data:
                    MakeDWalletUserSecretKeySharesPublicData {
                        curve,
                        public_user_secret_key_shares,
                        dwallet_decentralized_output,
                    },
                ..
            } => {
                let PublicInput::MakeDWalletUserSecretKeySharesPublic(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };
                ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic {
                    data: MakeDWalletUserSecretKeySharesPublicData {
                        curve: *curve,
                        public_user_secret_key_shares: public_user_secret_key_shares.clone(),
                        dwallet_decentralized_output: dwallet_decentralized_output.clone(),
                    },
                    protocol_public_parameters: public_input.clone(),
                }
            }
            ProtocolData::ImportedKeyVerification {
                data:
                    ImportedKeyVerificationData {
                        curve,
                        encrypted_centralized_secret_share_and_proof,
                        encryption_key,
                    },
                ..
            } => {
                let PublicInput::DWalletImportedKeyVerificationRequest(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result =
                    Party::<DWalletImportedKeyVerificationParty>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::new(),
                        &serialized_messages_by_consensus_round,
                    )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::ImportedKeyVerification {
                    data: ImportedKeyVerificationData {
                        curve: *curve,
                        encrypted_centralized_secret_share_and_proof:
                            encrypted_centralized_secret_share_and_proof.clone(),
                        encryption_key: encryption_key.clone(),
                    },
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::DKGFirst {
                data: DKGFirstData { curve },
                ..
            } => {
                let PublicInput::DKGFirst(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<DWalletDKGFirstParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::DKGFirst {
                    data: DKGFirstData { curve: *curve },
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::DKGSecond {
                data:
                    DKGSecondData {
                        curve,
                        encrypted_centralized_secret_share_and_proof,
                        encryption_key,
                    },
                ..
            } => {
                let PublicInput::DKGSecond(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<DWalletDKGSecondParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::DKGSecond {
                    data: DKGSecondData {
                        curve: *curve,
                        encrypted_centralized_secret_share_and_proof:
                            encrypted_centralized_secret_share_and_proof.clone(),
                        encryption_key: encryption_key.clone(),
                    },
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::Presign {
                data:
                    PresignData {
                        curve,
                        signature_algorithm,
                    },
                ..
            } => {
                let PublicInput::Presign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<PresignParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::Presign {
                    data: PresignData {
                        curve: *curve,
                        signature_algorithm: *signature_algorithm,
                    },
                    public_input: public_input.clone(),
                    advance_request,
                }
            }
            ProtocolData::Sign {
                data:
                    SignData {
                        curve,
                        hash_scheme,
                        signature_algorithm,
                    },
                dwallet_network_encryption_key_id,
                ..
            } => {
                let PublicInput::Sign(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<SignParty>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                let decryption_key_shares = decryption_key_shares
                    .get_decryption_key_shares(dwallet_network_encryption_key_id)?;

                ProtocolCryptographicData::Sign {
                    data: SignData {
                        curve: *curve,
                        hash_scheme: hash_scheme.clone(),
                        signature_algorithm: *signature_algorithm,
                    },
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                }
            }
            ProtocolData::NetworkEncryptionKeyDkg {
                data: NetworkEncryptionKeyDkgData { key_scheme },
                ..
            } => {
                let PublicInput::NetworkEncryptionKeyDkg(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result = Party::<Secp256k1Party>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round,
                    HashMap::from([(3, network_dkg_third_round_delay)]),
                    &serialized_messages_by_consensus_round,
                )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                    data: NetworkEncryptionKeyDkgData {
                        key_scheme: key_scheme.clone(),
                    },
                    public_input: public_input.clone(),
                    advance_request,
                    class_groups_decryption_key,
                }
            }
            ProtocolData::NetworkEncryptionKeyReconfigurationV1 {
                data: NetworkEncryptionKeyReconfigurationData {},
                dwallet_network_encryption_key_id,
            } => {
                let key_version = decryption_key_shares
                    .get_network_key_version(dwallet_network_encryption_key_id)?;
                
                let PublicInput::NetworkEncryptionKeyReconfiguration(public_input) = public_input
                else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                let advance_request_result =
                    Party::<ReconfigurationSecp256k1Party>::ready_to_advance(
                        party_id,
                        access_structure,
                        consensus_round,
                        HashMap::from([(3, decryption_key_reconfiguration_third_round_delay)]),
                        &serialized_messages_by_consensus_round,
                    )?;

                let ReadyToAdvanceResult::ReadyToAdvance(advance_request) = advance_request_result
                else {
                    return Ok(None);
                };

                let decryption_key_shares = decryption_key_shares
                    .get_decryption_key_shares(dwallet_network_encryption_key_id)?;

                ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                    data: NetworkEncryptionKeyReconfigurationData {},
                    public_input: public_input.clone(),
                    advance_request,
                    decryption_key_shares: decryption_key_shares.clone(),
                    key_version
                }
            }
            ProtocolData::EncryptedShareVerification {
                data:
                    EncryptedShareVerificationData {
                        curve,
                        encrypted_centralized_secret_share_and_proof,
                        decentralized_public_output,
                        encryption_key,
                    },
                ..
            } => {
                let PublicInput::EncryptedShareVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                ProtocolCryptographicData::EncryptedShareVerification {
                    data: EncryptedShareVerificationData {
                        curve: *curve,
                        encrypted_centralized_secret_share_and_proof:
                            encrypted_centralized_secret_share_and_proof.clone(),
                        decentralized_public_output: decentralized_public_output.clone(),
                        encryption_key: encryption_key.clone(),
                    },
                    protocol_public_parameters: public_input.clone(),
                }
            }
            ProtocolData::PartialSignatureVerification {
                data:
                    PartialSignatureVerificationData {
                        curve,
                        message,
                        hash_type,
                        signature_algorithm,
                        dwallet_decentralized_output,
                        presign,
                        partially_signed_message,
                    },
                ..
            } => {
                let PublicInput::PartialSignatureVerification(public_input) = public_input else {
                    return Err(DwalletMPCError::InvalidSessionPublicInput);
                };

                ProtocolCryptographicData::PartialSignatureVerification {
                    data: PartialSignatureVerificationData {
                        curve: *curve,
                        message: message.clone(),
                        hash_type: hash_type.clone(),
                        signature_algorithm: *signature_algorithm,
                        dwallet_decentralized_output: dwallet_decentralized_output.clone(),
                        presign: presign.clone(),
                        partially_signed_message: partially_signed_message.clone(),
                    },
                    protocol_public_parameters: public_input.clone(),
                }
            }
        };
        Ok(Some(res))
    }

    pub fn get_attempt_number(&self) -> u64 {
        match self {
            ProtocolCryptographicData::DKGFirst {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::DKGSecond {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Sign {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                advance_request,
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::EncryptedShareVerification { .. } => 1,
            ProtocolCryptographicData::PartialSignatureVerification { .. } => 1,
            ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic { .. } => 1,
            ProtocolCryptographicData::ImportedKeyVerification {
                advance_request, ..
            } => advance_request.attempt_number,
        }
    }
}
