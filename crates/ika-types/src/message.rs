// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::committee::{EpochId, ProtocolVersion};
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

// Note: the order of these fields, and the number must correspond to the Move code in
// `system_inner.move`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SystemCheckpointMessageKind {
    /// Set the next protocol version for the next epoch.
    SetNextConfigVersion(ProtocolVersion),
    /// Set a new epoch duration in milliseconds.
    SetEpochDurationMs(u64),
    /// Set a new stake subsidy start epoch.
    SetStakeSubsidyStartEpoch(EpochId),
    /// Set a new stake subsidy rate in basis points (1/100th of a percent).
    /// The distribution per period will be recalculated.
    SetStakeSubsidyRate(u16),
    /// Set a new length of the stake subsidy period.
    /// The distribution per period will be recalculated.
    SetStakeSubsidyPeriodLength(u64),
    /// Set a new minimum number of validators required to be active in the system.
    SetMinValidatorCount(u64),
    /// Set a new maximum number of validators allowed in the system.
    SetMaxValidatorCount(u64),
    /// Set a new minimum stake required for a validator to join the system.
    SetMinValidatorJoiningStake(u64),
    /// Set a new maximum number of validators that can change in a single epoch.
    SetMaxValidatorChangeCount(u64),
    /// Set a new rate at which rewards are slashed in basis points (1/100th of a percent).
    SetRewardSlashingRate(u64),
    /// Marks the final checkpoint message for an epoch.
    /// Once the Sui smart contract processes this message, it recognizes that no further
    /// system checkpoints will be created in the current epoch, enabling external calls
    /// to proceed with advancing the epoch.
    EndOfPublish,
    /// Set an approved upgrade for a package.
    SetApprovedUpgrade {
        /// The ID of the package that is approved for upgrade.
        package_id: Vec<u8>,
        /// The version of the package that is approved for upgrade.
        /// if None, the upgrade approval will be deleted.
        digest: Option<Vec<u8>>,
    },
    /// Set or remove a witness approving advance epoch.
    SetOrRemoveWitnessApprovingAdvanceEpochMessageType {
        /// The type of the witness that is being set or removed.
        witness_type: String,
        /// If false, the witness is being set, if true, the witness is being removed.
        remove: bool,
    },
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
