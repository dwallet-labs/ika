// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_system::dwallet_checkpoint;

use std::bcs;

const CHECKPOINT_MESSAGE_INTENT: vector<u8> = vector[1, 0, 0];

public struct DKGFirstRoundOutput has drop, copy {
    dwallet_id: vector<u8>,
    output: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public struct DKGSecondRoundOutput has drop, copy {
    dwallet_id: vector<u8>,
    session_id: vector<u8>,
    encrypted_secret_share_id: vector<u8>,
    output: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public struct PresignOutput has drop, copy {
    dwallet_id: Option<vector<u8>>,
    presign_id: vector<u8>,
    session_id: vector<u8>,
    presign: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public struct SignOutput has drop, copy {
    dwallet_id: vector<u8>,
    sign_id: vector<u8>,
    session_id: vector<u8>,
    signature: vector<u8>,
    is_future_sign: bool,
    rejected: bool,
    session_sequence_number: u64,
}

public struct EncryptedUserShareOutput has drop, copy {
    dwallet_id: vector<u8>,
    encrypted_user_secret_key_share_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public struct PartialSignatureVerificationOutput has drop, copy {
    session_id: vector<u8>,
    dwallet_id: vector<u8>,
    partial_centralized_signed_message_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public struct NetworkKeyPublicOutputSlice has drop, copy {
    dwallet_network_decryption_key_id: vector<u8>,
    public_output: vector<u8>,
    supported_curves: vector<u32>,
    is_last: bool,
    rejected: bool,
}

public struct MakeDWalletUserSecretKeySharesPublicOutput has drop, copy {
    dwallet_id: vector<u8>,
    public_user_secret_key_shares: vector<u8>,
    rejected: bool,
    session_sequence_number: u64
}

public struct DWalletImportedKeyVerificationOutput has drop, copy {
    dwallet_id: vector<u8>,
    public_output: vector<u8>,
    encrypted_user_secret_key_share_id: vector<u8>,
    session_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
}

public enum MessageKind has drop, copy {
    RespondDWalletDKGFirstRoundOutput(DKGFirstRoundOutput),
    RespondDWalletDKGSecondRoundOutput(DKGSecondRoundOutput),
    RespondDWalletEncryptedUserShare(EncryptedUserShareOutput),
    RespondMakeDWalletUserSecretKeySharesPublic(MakeDWalletUserSecretKeySharesPublicOutput),
    RespondDWalletImportedKeyVerificationOutput(DWalletImportedKeyVerificationOutput),
    RespondDWalletPresign(PresignOutput),
    RespondDWalletSign(SignOutput),
    RespondDWalletPartialSignatureVerificationOutput(PartialSignatureVerificationOutput),
    RespondDWalletMPCNetworkDKGOutput(NetworkKeyPublicOutputSlice),
    RespondDWalletMPCNetworkReconfigurationOutput(NetworkKeyPublicOutputSlice),
    SetMaxActiveSessionsBuffer(u64),
    SetGasFeeReimbursementSuiSystemCallValue(u64),
}

public struct DWalletCheckpointMessage has drop, copy {
    epoch: u64,
    sequence_number: u64,
    timestamp_ms: u64,
    messages: vector<MessageKind>,
}

public fun dkg_first_round_output(
    dwallet_id: vector<u8>,
    output: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletDKGFirstRoundOutput(DKGFirstRoundOutput {
        dwallet_id,
        output,
        rejected,
        session_sequence_number,
    })
}

public fun dkg_second_round_output(
    dwallet_id: vector<u8>,
    session_id: vector<u8>,
    encrypted_secret_share_id: vector<u8>,
    output: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletDKGSecondRoundOutput(DKGSecondRoundOutput {
        dwallet_id,
        session_id,
        encrypted_secret_share_id,
        output,
        rejected,
        session_sequence_number,
    })
}

public fun encrypted_user_share(
    dwallet_id: vector<u8>,
    encrypted_user_secret_key_share_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletEncryptedUserShare(EncryptedUserShareOutput {
        dwallet_id,
        encrypted_user_secret_key_share_id,
        rejected,
        session_sequence_number,
    })
}

public fun make_dwallet_user_secret_key_shares_public(
    dwallet_id: vector<u8>,
    public_user_secret_key_shares: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondMakeDWalletUserSecretKeySharesPublic(MakeDWalletUserSecretKeySharesPublicOutput {
        dwallet_id,
        public_user_secret_key_shares,
        rejected,
        session_sequence_number,
    })
}

public fun dwallet_imported_key_verification_output(
    dwallet_id: vector<u8>,
    public_output: vector<u8>,
    encrypted_user_secret_key_share_id: vector<u8>,
    session_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletImportedKeyVerificationOutput(DWalletImportedKeyVerificationOutput {
        dwallet_id,
        public_output,
        encrypted_user_secret_key_share_id,
        session_id,
        rejected,
        session_sequence_number,
    })
}

public fun dwallet_presign(
    dwallet_id: Option<vector<u8>>,
    presign_id: vector<u8>,
    session_id: vector<u8>,
    presign: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletPresign(PresignOutput {
        dwallet_id,
        presign_id,
        session_id,
        presign,
        rejected,
        session_sequence_number,
    })
}

public fun dwallet_sign(
    dwallet_id: vector<u8>,
    sign_id: vector<u8>,
    session_id: vector<u8>,
    signature: vector<u8>,
    is_future_sign: bool,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletSign(SignOutput {
        dwallet_id,
        sign_id,
        session_id,
        signature,
        is_future_sign,
        rejected,
        session_sequence_number,
    })
}

public fun dwallet_partial_signature_verification_output(
    session_id: vector<u8>,
    dwallet_id: vector<u8>,
    partial_centralized_signed_message_id: vector<u8>,
    rejected: bool,
    session_sequence_number: u64,
): MessageKind {
    MessageKind::RespondDWalletPartialSignatureVerificationOutput(PartialSignatureVerificationOutput {
        session_id,
        dwallet_id,
        partial_centralized_signed_message_id,
        rejected,
        session_sequence_number,
    })
}

public fun dwallet_mpc_network_dkg_output(
    dwallet_network_decryption_key_id: vector<u8>,
    public_output: vector<u8>,
    is_last: bool,
    supported_curves: vector<u32>,
    rejected: bool,
): MessageKind {
    MessageKind::RespondDWalletMPCNetworkDKGOutput(NetworkKeyPublicOutputSlice {
        dwallet_network_decryption_key_id,
        public_output,
        supported_curves,
        is_last,
        rejected,
    })
}

public fun dwallet_mpc_network_reconfiguration_output(
    dwallet_network_decryption_key_id: vector<u8>,
    public_output: vector<u8>,
    is_last: bool,
    supported_curves: vector<u32>,
    rejected: bool,
): MessageKind {
    MessageKind::RespondDWalletMPCNetworkReconfigurationOutput(NetworkKeyPublicOutputSlice {
        dwallet_network_decryption_key_id,
        public_output,
        supported_curves,
        is_last,
        rejected,
    })
}

public fun set_max_active_sessions_buffer(
    max_active_sessions_buffer: u64,
): MessageKind {
    MessageKind::SetMaxActiveSessionsBuffer(max_active_sessions_buffer)
}

public fun set_gas_fee_reimbursement_sui_system_call_value(
    gas_fee_reimbursement_sui_system_call_value: u64,
): MessageKind {
    MessageKind::SetGasFeeReimbursementSuiSystemCallValue(gas_fee_reimbursement_sui_system_call_value)
}

public fun dwallet_checkpoint_message(
    epoch: u64,
    sequence_number: u64,
    timestamp_ms: u64,
    messages: vector<MessageKind>,
): DWalletCheckpointMessage {
    DWalletCheckpointMessage {
        epoch,
        sequence_number,
        timestamp_ms,
        messages,
    }
}

public fun dwallet_checkpoint_message_bytes(
    message: DWalletCheckpointMessage,
): vector<u8> {
    bcs::to_bytes(&message)
}

public fun dwallet_checkpoint_message_intent(
    message: vector<u8>,
    epoch: u64,
): vector<u8> {
    let mut intent_bytes = CHECKPOINT_MESSAGE_INTENT;
    intent_bytes.append(message);
    intent_bytes.append(bcs::to_bytes(&epoch));
    intent_bytes
}