// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::crypto::default_hash;
use crate::digests::MessageDigest;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DKGFirstRoundOutput {
    pub dwallet_id: Vec<u8>,
    pub output: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DKGSecondRoundOutput {
    pub dwallet_id: Vec<u8>,
    pub encrypted_secret_share_id: Vec<u8>,
    pub output: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct PresignOutput {
    pub dwallet_id: Option<Vec<u8>>,
    pub presign_id: Vec<u8>,
    pub presign: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct SignOutput {
    pub dwallet_id: Vec<u8>,
    pub sign_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub is_future_sign: bool,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct EncryptedUserShareOutput {
    pub dwallet_id: Vec<u8>,
    pub encrypted_user_secret_key_share_id: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct PartialSignatureVerificationOutput {
    pub dwallet_id: Vec<u8>,
    pub partial_centralized_signed_message_id: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct MPCNetworkDKGOutput {
    pub dwallet_network_encryption_key_id: Vec<u8>,
    pub public_output: Vec<u8>,
    pub supported_curves: Vec<u32>,
    pub is_last: bool,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct MPCNetworkReconfigurationOutput {
    pub dwallet_network_encryption_key_id: Vec<u8>,
    pub public_output: Vec<u8>,
    pub supported_curves: Vec<u32>,
    pub is_last: bool,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct MakeDWalletUserSecretKeySharesPublicOutput {
    pub dwallet_id: Vec<u8>,
    pub public_user_secret_key_shares: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DWalletImportedKeyVerificationOutput {
    pub dwallet_id: Vec<u8>,
    pub public_output: Vec<u8>,
    pub encrypted_user_secret_key_share_id: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

// Note: the order of these fields, and the number must correspond to the Move code in
// `dwallet_2pc_mpc_coordinator_inner.move`.
#[derive(PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub enum DWalletCheckpointMessageKind {
    RespondDWalletDKGFirstRoundOutput(DKGFirstRoundOutput),
    RespondDWalletDKGSecondRoundOutput(DKGSecondRoundOutput),
    RespondDWalletEncryptedUserShare(EncryptedUserShareOutput),
    RespondMakeDWalletUserSecretKeySharesPublic(MakeDWalletUserSecretKeySharesPublicOutput),
    RespondDWalletImportedKeyVerificationOutput(DWalletImportedKeyVerificationOutput),
    RespondDWalletPresign(PresignOutput),
    RespondDWalletSign(SignOutput),
    RespondDWalletPartialSignatureVerificationOutput(PartialSignatureVerificationOutput),
    RespondDWalletMPCNetworkDKGOutput(MPCNetworkDKGOutput),
    RespondDWalletMPCNetworkReconfigurationOutput(MPCNetworkReconfigurationOutput),
    SetMaxActiveSessionsBuffer(u64),
    SetGasFeeReimbursementSuiSystemCallValue(u64),
    EndOfPublish,
}

impl DWalletCheckpointMessageKind {
    pub fn name(&self) -> &'static str {
        match self {
            DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(_) => {
                "RespondDWalletDKGFirstRoundOutput"
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(_) => {
                "RespondDWalletDKGSecondRoundOutput"
            }
            DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(_) => {
                "RespondDWalletEncryptedUserShare"
            }
            DWalletCheckpointMessageKind::RespondDWalletPresign(_) => "RespondDWalletPresign",
            DWalletCheckpointMessageKind::RespondDWalletSign(_) => "RespondDWalletSign",
            DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(_) => {
                "RespondDWalletPartialSignatureVerificationOutput"
            }
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(_) => {
                "RespondDWalletMPCNetworkDKGOutput"
            }
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(_) => {
                "RespondDWalletMPCNetworkReconfigurationOutput"
            }
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(_) => {
                "RespondMakeDWalletUserSecretKeySharesPublic"
            }
            DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(_) => {
                "RespondDWalletImportedKeyVerificationOutput"
            }
            DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(_) => {
                "SetMaxActiveSessionsBuffer"
            }
            DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(_) => {
                "SetGasFeeReimbursementSuiSystemCallValue"
            }
            DWalletCheckpointMessageKind::EndOfPublish => "EndOfPublish",
        }
    }

    pub fn digest(&self) -> MessageDigest {
        MessageDigest::new(default_hash(self))
    }
}

impl Display for DWalletCheckpointMessageKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match &self {
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(_) => {
                writeln!(writer, "MessageKind : RespondDwalletMPCNetworkDKGOutput")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(_) => {
                writeln!(writer, "MessageKind : RespondDwalletDKGFirstRoundOutput")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(_) => {
                writeln!(writer, "MessageKind : RespondDwalletDKGSecondRoundOutput")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletPresign(_) => {
                writeln!(writer, "MessageKind : RespondDwalletPresign")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletSign(_) => {
                writeln!(writer, "MessageKind : RespondDwalletSign")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(_) => {
                writeln!(writer, "MessageKind : RespondDwalletEncryptedUserShare")?;
            }
            DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletPartialSignatureVerificationOutput"
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDWalletMPCNetworkReconfigurationOutput"
                )?;
            }
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondMakeDWalletUserSecretKeySharesPublic"
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDWalletImportedKeyVerificationOutput"
                )?;
            }
            DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(buffer_size) => {
                writeln!(
                    writer,
                    "MessageKind : SetMaxActiveSessionsBuffer({buffer_size})"
                )?;
            }
            DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(value) => {
                writeln!(
                    writer,
                    "MessageKind : SetGasFeeReimbursementSuiSystemCallValue({value})"
                )?;
            }
            DWalletCheckpointMessageKind::EndOfPublish => {
                writeln!(writer, "MessageKind : EndOfPublish")?;
            }
        }
        write!(f, "{writer}")
    }
}

impl Debug for DWalletCheckpointMessageKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match &self {
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletMPCNetworkDKGOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletDKGFirstRoundOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletDKGSecondRoundOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletPresign(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletPresign {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletSign(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletSign {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletEncryptedUserShare {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletPartialSignatureVerificationOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDWalletMPCNetworkReconfigurationOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondMakeDWalletUserSecretKeySharesPublic {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDWalletImportedKeyVerificationOutput {:?}",
                    self.digest()
                )?;
            }
            DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(buffer_size) => {
                writeln!(
                    writer,
                    "MessageKind : SetMaxActiveSessionsBuffer({buffer_size})"
                )?;
            }
            DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(value) => {
                writeln!(
                    writer,
                    "MessageKind : SetGasFeeReimbursementSuiSystemCallValue({value})"
                )?;
            }
            DWalletCheckpointMessageKind::EndOfPublish => {
                writeln!(writer, "MessageKind : EndOfPublish")?;
            }
        }
        write!(f, "{writer}")
    }
}

// #[enum_dispatch(MessageDataAPI)]
// #[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
// pub enum MessageKind {
//     V1(MessageDataV1),
//     // When new variants are introduced, it is important that we check version support
//     // in the validity_check function based on the protocol config.
// }
//
// #[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
// pub struct MessageDataV1 {
//     pub kind: MessageKind,
//     // pub sender: IkaAddress,
//     // pub gas_data: GasData,
//     // pub expiration: TransactionExpiration,
// }
//
// impl MessageKind {
//     pub fn new(
//         kind: MessageKind
//     ) -> Self {
//         MessageKind::V1(MessageDataV1 {
//             kind,
//         })
//     }
//
//     pub fn new_initiate_process_mid_epoch_message() -> Self {
//         Self::new(MessageKind::InitiateProcessMidEpoch)
//     }
//
//     pub fn new_end_of_epoch_message(messages: Vec<EndOfEpochMessageKind>) -> Self {
//         Self::new(MessageKind::EndOfEpoch(messages))
//     }
//
//     pub fn kind(&self) -> &MessageKind {
//         match self {
//             MessageKind::V1(MessageDataV1 { kind }) => kind,
//         }
//     }
//
//     pub fn message_version(&self) -> u64 {
//         match self {
//             MessageKind::V1(_) => 1,
//         }
//     }
//
//     pub fn digest(&self) -> MessageDigest {
//         MessageDigest::new(default_hash(self))
//     }
// }
//
// #[enum_dispatch]
// pub trait MessageDataAPI {
//     // Note: this implies that SingleMessageKind itself must be versioned, so that it can be
//     // shared across versions. This will be easy to do since it is already an enum.
//     fn kind(&self) -> &MessageKind;
//
//     // Used by programmable_transaction_builder
//     fn kind_mut(&mut self) -> &mut MessageKind;
//
//     // kind is moved out of often enough that this is worth it to special case.
//     fn into_kind(self) -> MessageKind;
//
//     /// returns true if the transaction is one that is specially sequenced to run at the very end
//     /// of the epoch
//     fn is_end_of_epoch_tx(&self) -> bool;
// }
//
// impl MessageDataAPI for MessageDataV1 {
//     fn kind(&self) -> &MessageKind {
//         &self.kind
//     }
//
//     fn kind_mut(&mut self) -> &mut MessageKind {
//         &mut self.kind
//     }
//
//     fn into_kind(self) -> MessageKind {
//         self.kind
//     }
//
//     fn is_end_of_epoch_tx(&self) -> bool {
//         matches!(
//             self.kind,
//             MessageKind::EndOfEpoch(_)
//         )
//     }
// }
//
// impl MessageDataV1 {}
