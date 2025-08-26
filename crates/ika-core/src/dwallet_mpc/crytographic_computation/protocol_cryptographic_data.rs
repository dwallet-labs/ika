use crate::dwallet_mpc::dwallet_dkg::{
    DWalletDKGFirstParty, DWalletDKGSecondParty, DWalletImportedKeyVerificationParty,
};
use crate::dwallet_mpc::mpc_manager::DWalletMPCManager;
use crate::dwallet_mpc::mpc_session::{PublicInput, SessionComputationType};
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
use mpc::guaranteed_output_delivery::AdvanceRequest;
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

    pub fn get_mpc_round(&self) -> Option<u64> {
        match self {
            ProtocolCryptographicData::DKGFirst {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::DKGSecond {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Presign {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::Sign {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyDkg {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::NetworkEncryptionKeyReconfiguration {
                advance_request,
                ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::ImportedKeyVerification {
                advance_request, ..
            } => Some(advance_request.mpc_round_number),
            ProtocolCryptographicData::EncryptedShareVerification { .. }
            | ProtocolCryptographicData::PartialSignatureVerification { .. }
            | ProtocolCryptographicData::MakeDWalletUserSecretKeySharesPublic { .. } => None,
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
            ),
        }
    }
}
