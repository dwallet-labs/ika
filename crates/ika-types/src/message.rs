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
pub struct DWalletDKGSecondRoundOutput {
    pub dwallet_id: Vec<u8>,
    pub encrypted_secret_share_id: Vec<u8>,
    pub output: Vec<u8>,
    pub rejected: bool,
    pub session_sequence_number: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DWalletDKGOutput {
    pub dwallet_id: Vec<u8>,
    pub output: Vec<u8>,
    pub encrypted_secret_share_id: Option<Vec<u8>>,
    pub sign_id: Option<Vec<u8>>,
    pub signature: Vec<u8>,
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
    RespondDWalletDKGSecondRoundOutput(DWalletDKGSecondRoundOutput),
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
    RespondDWalletDKGOutput(DWalletDKGOutput),
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
            DWalletCheckpointMessageKind::RespondDWalletDKGOutput(_) => "RespondDWalletDKGOutput",
        }
    }

    pub fn digest(&self) -> MessageDigest {
        MessageDigest::new(default_hash(self))
    }
    pub fn rejected(&self) -> Option<bool> {
        match self {
            DWalletCheckpointMessageKind::RespondDWalletDKGFirstRoundOutput(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondDWalletDKGSecondRoundOutput(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondDWalletEncryptedUserShare(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondDWalletPresign(output) => Some(output.rejected),
            DWalletCheckpointMessageKind::RespondDWalletSign(output) => Some(output.rejected),

            DWalletCheckpointMessageKind::RespondDWalletPartialSignatureVerificationOutput(
                output,
            ) => Some(output.rejected),
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkDKGOutput(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondDWalletMPCNetworkReconfigurationOutput(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondMakeDWalletUserSecretKeySharesPublic(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::RespondDWalletImportedKeyVerificationOutput(output) => {
                Some(output.rejected)
            }
            DWalletCheckpointMessageKind::SetMaxActiveSessionsBuffer(_) => None,
            DWalletCheckpointMessageKind::SetGasFeeReimbursementSuiSystemCallValue(_) => None,
            DWalletCheckpointMessageKind::EndOfPublish => None,
            DWalletCheckpointMessageKind::RespondDWalletDKGOutput(output) => Some(output.rejected),
        }
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
            DWalletCheckpointMessageKind::RespondDWalletDKGOutput(_) => {
                writeln!(writer, "MessageKind : RespondDwalletDKGOutput")?;
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
            DWalletCheckpointMessageKind::RespondDWalletDKGOutput(_) => {
                writeln!(
                    writer,
                    "MessageKind : RespondDwalletDKGOutput {:?}",
                    self.digest()
                )?;
            }
        }
        write!(f, "{writer}")
    }
}
