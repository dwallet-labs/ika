#![cfg_attr(not(test), no_std)]

pub mod auth;
pub mod error;
pub mod state;
pub mod sweep;

pub mod instructions;

// Backwards-compat re-exports — keeps `ikavery::challenges::…`,
// `ikavery::members::…`, etc. working for the integration tests and any
// external SDK consumers while internal code uses the cleaner `auth::*`
// and `sweep::*` paths.
pub use auth::challenges;
pub use auth::members;
pub use auth::precompile;
pub use auth::secp256k1;
pub use auth::webauthn;
pub use sweep::intent as sweep_intent;
pub use sweep::solana_msg;

use crate::instructions::create_recovery::CREATE_MEMBERS_BYTES;
use crate::instructions::*;
use crate::state::{
    AUTH_PUBKEY_BYTES, AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, MAX_MESSAGE_BYTES,
    PROPOSE_DIGESTS_BYTES,
};
use quasar_lang::prelude::*;

declare_id!("4ZrXgy2Grv9RH3gWF7mksQvRqSUgc4atQyhcss569fw7");

#[program]
mod ikavery {
    use super::*;

    #[instruction(discriminator = 0)]
    pub fn create_recovery(
        ctx: Ctx<CreateRecovery>,
        dwallet: [u8; 32],
        dwallet_curve: u16,
        threshold: u16,
        member_count: u8,
        approver_only_bitmap: u16,
        members_packed: [u8; CREATE_MEMBERS_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.create(
            dwallet,
            dwallet_curve,
            threshold,
            member_count,
            approver_only_bitmap,
            members_packed,
        )
    }

    #[instruction(discriminator = 1)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        ctx: Ctx<Propose>,
        proposal_index: u32,
        digests_packed: [u8; PROPOSE_DIGESTS_BYTES],
        digest_count: u8,
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.propose(
            proposal_index,
            digests_packed,
            digest_count,
            user_pubkey,
            signature_scheme,
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 2)]
    #[allow(clippy::too_many_arguments)]
    pub fn approve(
        ctx: Ctx<Approve>,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.approve(
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 3)]
    pub fn execute(
        ctx: Ctx<Execute>,
        tx_index: u8,
        message_bytes: [u8; MAX_MESSAGE_BYTES],
        message_len: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.execute(
            tx_index,
            message_bytes,
            message_len,
            message_approval_bump,
            cpi_authority_bump,
        )
    }

    #[instruction(discriminator = 4)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_roster_change(
        ctx: Ctx<ProposeRosterChange>,
        roster_change_index: u32,
        payload_hash: [u8; 32],
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.propose_roster_change(
            roster_change_index,
            payload_hash,
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 5)]
    #[allow(clippy::too_many_arguments)]
    pub fn approve_roster_change(
        ctx: Ctx<ApproveRosterChange>,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.approve_roster_change(
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 6)]
    pub fn execute_roster_change(ctx: Ctx<ExecuteRosterChange>) -> Result<(), ProgramError> {
        ctx.accounts.execute_roster_change()
    }

    #[instruction(discriminator = 7)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_enrollment(
        ctx: Ctx<ProposeEnrollment>,
        enrollment_index: u32,
        new_member_packed: [u8; crate::state::MEMBER_SLOT_LEN],
        new_encryption_key_address: [u8; 32],
        addition_approver_only: u8,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.propose_enrollment(
            enrollment_index,
            new_member_packed,
            new_encryption_key_address,
            addition_approver_only,
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 8)]
    #[allow(clippy::too_many_arguments)]
    pub fn approve_enrollment(
        ctx: Ctx<ApproveEnrollment>,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        ctx.accounts.approve_enrollment(
            auth_scheme,
            auth_pubkey,
            client_data_json,
            client_data_json_len,
            auth_signature,
        )
    }

    #[instruction(discriminator = 9)]
    pub fn execute_enrollment(ctx: Ctx<ExecuteEnrollment>) -> Result<(), ProgramError> {
        ctx.accounts.execute_enrollment()
    }

    #[instruction(discriminator = 10)]
    #[allow(clippy::too_many_arguments)]
    pub fn stage_roster_change_payload(
        ctx: Ctx<StageRosterChangePayload>,
        roster_change_index: u32,
        additions_packed: [u8; CREATE_MEMBERS_BYTES],
        addition_count: u8,
        addition_approver_only_bitmap: u16,
        removals_packed: [u8; CREATE_MEMBERS_BYTES],
        removal_count: u8,
        new_threshold: u16,
        has_new_threshold: u8,
    ) -> Result<(), ProgramError> {
        ctx.accounts.stage(
            roster_change_index,
            additions_packed,
            addition_count,
            addition_approver_only_bitmap,
            removals_packed,
            removal_count,
            new_threshold,
            has_new_threshold,
        )
    }
}
