use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGAdvanceRequestByCurve, DWalletDKGFirstParty, DWalletDKGPublicInputByCurve,
    DWalletImportedKeyVerificationParty, Secp256K1DWalletDKGParty,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::{PublicInput, SessionComputationType};
use crate::dwallet_mpc::presign::{PresignAdvanceRequestByProtocol, PresignPublicInputByProtocol};
use crate::dwallet_mpc::reconfiguration::ReconfigurationV1toV2Party;
use crate::dwallet_mpc::sign::SignParty;
use crate::request_protocol_data::{
    DKGFirstData, DKGSecondData, DWalletDKGData, EncryptedShareVerificationData,
    ImportedKeyVerificationData, MakeDWalletUserSecretKeySharesPublicData,
    NetworkEncryptionKeyDkgData, NetworkEncryptionKeyReconfigurationData,
    NetworkEncryptionKeyV1ToV2ReconfigurationData, NetworkEncryptionKeyV2ReconfigurationData,
    PartialSignatureVerificationData, PresignData, ProtocolData, SignData,
};
use class_groups::SecretKeyShareSizedInteger;
use class_groups::dkg::Secp256k1Party;
use dwallet_classgroups_types::ClassGroupsDecryptionKey;
use dwallet_mpc_types::dwallet_mpc::{ReconfigurationParty, ReconfigurationV2Party};
use group::PartyID;
use ika_protocol_config::ProtocolVersion;
use ika_types::dwallet_mpc_error::DwalletMPCError;
use mpc::guaranteed_output_delivery::AdvanceRequest;
use std::collections::HashMap;

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
        public_input: <Secp256K1DWalletDKGParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<Secp256K1DWalletDKGParty as mpc::Party>::Message>,
        first_round_output: Vec<u8>,
    },

    DWalletDKG {
        data: DWalletDKGData,
        public_input: DWalletDKGPublicInputByCurve,
        advance_request: DWalletDKGAdvanceRequestByCurve,
    },

    Presign {
        data: PresignData,
        public_input: PresignPublicInputByProtocol,
        advance_request: PresignAdvanceRequestByProtocol,
        protocol_version: ProtocolVersion,
    },

    Sign {
        data: SignData,
        public_input: <SignParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<SignParty as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
    },
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyDkgV1 {
        data: NetworkEncryptionKeyDkgData,
        public_input: <Secp256k1Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<Secp256k1Party as mpc::Party>::Message>,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    },
    NetworkEncryptionKeyDkgV2 {
        data: NetworkEncryptionKeyDkgData,
        public_input: <twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::PublicInput,
        advance_request:
            AdvanceRequest<<twopc_mpc::decentralized_party::dkg::Party as mpc::Party>::Message>,
        class_groups_decryption_key: ClassGroupsDecryptionKey,
    },
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyV1Reconfiguration {
        data: NetworkEncryptionKeyReconfigurationData,
        public_input: <ReconfigurationParty as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationParty as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
    },
    // TODO (#1487): Remove temporary v1 to v2 & v1 reconfiguration code
    NetworkEncryptionKeyV1ToV2Reconfiguration {
        data: NetworkEncryptionKeyV1ToV2ReconfigurationData,
        public_input: <ReconfigurationV1toV2Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationV1toV2Party as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
    },
    NetworkEncryptionKeyV2Reconfiguration {
        data: NetworkEncryptionKeyV2ReconfigurationData,
        public_input: <ReconfigurationV2Party as mpc::Party>::PublicInput,
        advance_request: AdvanceRequest<<ReconfigurationV2Party as mpc::Party>::Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
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
    pub fn get_attempt_number(&self) -> u64 {
        match self {
            ProtocolCryptographicData::DKGFirst {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::DKGSecond {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Taproot(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Secp256r1ECDSA(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::EdDSA(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Presign {
                advance_request:
                    PresignAdvanceRequestByProtocol::SchnorrkelSubstrate(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::Sign {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV1 {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyV1Reconfiguration {
                advance_request,
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::EncryptedShareVerification { .. } => 1,
            ProtocolCryptographicData::PartialSignatureVerification { .. } => 1,
            ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic { .. } => 1,
            ProtocolCryptographicData::ImportedKeyVerification {
                advance_request, ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                advance_request,
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyV2Reconfiguration {
                advance_request,
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256K1DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256R1DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG(advance_request),
                ..
            } => advance_request.attempt_number,
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV2 {
                advance_request, ..
            } => advance_request.attempt_number,
        }
    }

    pub fn get_mpc_round(&self) -> Option<u64> {
        match self {
            ProtocolCryptographicData::DKGFirst {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256K1DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Secp256R1DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::Curve25519DWalletDKG(advance_request),
                ..
            }
            | ProtocolCryptographicData::DWalletDKG {
                advance_request:
                    DWalletDKGAdvanceRequestByCurve::RistrettoDWalletDKG(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::DKGSecond {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Secp256k1ECDSA(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Taproot(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::Secp256r1ECDSA(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request: PresignAdvanceRequestByProtocol::EdDSA(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request:
                    PresignAdvanceRequestByProtocol::SchnorrkelSubstrate(advance_request),
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Sign {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV1 {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyV1Reconfiguration {
                advance_request,
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::ImportedKeyVerification {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::EncryptedShareVerification { .. }
            | ProtocolCryptographicData::PartialSignatureVerification { .. }
            | ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
            ProtocolCryptographicData::NetworkEncryptionKeyV1ToV2Reconfiguration {
                advance_request,
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyV2Reconfiguration {
                advance_request,
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyDkgV2 {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
        }
    }
}

impl DWalletMPCManager {
    pub fn generate_protocol_cryptographic_data(
        &self,
        session_type: &SessionComputationType,
        protocol_data: &ProtocolData,
        consensus_round: u64,
        public_input: PublicInput,
        protocol_version: &ProtocolVersion,
    ) -> Result<Option<ProtocolCryptographicData>, DwalletMPCError> {
        match session_type {
            SessionComputationType::Native => {
                ProtocolCryptographicData::try_new_native(protocol_data, public_input)
            }
            SessionComputationType::MPC {
                messages_by_consensus_round,
                ..
            } => ProtocolCryptographicData::try_new_mpc(
                protocol_data,
                self.party_id,
                &self.access_structure,
                consensus_round,
                messages_by_consensus_round.clone(),
                public_input.clone(),
                self.network_dkg_third_round_delay,
                self.decryption_key_reconfiguration_third_round_delay,
                self.network_keys
                    .validator_private_dec_key_data
                    .class_groups_decryption_key
                    .clone(),
                &self.network_keys,
                protocol_version,
            ),
        }
    }
}
