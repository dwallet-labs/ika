use crate::auth::challenges;
use crate::auth::members;
use crate::auth::precompile;
use crate::auth::{auth_error_to_program_error, verify_credential};
use crate::error::IkaveryError;
use crate::state::{
    EnrollmentProposal, EnrollmentProposalInner, MemberSlot, Recovery, AUTH_PUBKEY_BYTES,
    AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, MAX_MEMBERS, STATUS_ACTIVE,
};
use quasar_lang::prelude::*;
use solana_address::Address;

#[derive(Accounts)]
#[instruction(enrollment_index: u32)]
pub struct ProposeEnrollment {
    #[account(mut, address = Recovery::seeds(recovery_id.address()))]
    pub recovery: Account<Recovery>,
    pub recovery_id: UncheckedAccount,
    #[account(
        init,
        payer = payer,
        address = EnrollmentProposal::seeds(recovery.address(), enrollment_index),
    )]
    pub enrollment: Account<EnrollmentProposal>,
    #[account(mut)]
    pub payer: Signer,
    pub instructions_sysvar: UncheckedAccount,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl ProposeEnrollment {
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn propose_enrollment(
        &mut self,
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
        let expected_index: u32 = self.recovery.enrollment_count.into();
        require!(enrollment_index == expected_index, IkaveryError::WrongIndex);

        // Existing-member auth: the proposer must already be in the roster.
        let cred_pubkey = members::pubkey_slice(auth_scheme, &auth_pubkey)?;
        let proposer_slot: MemberSlot = members::credential_slot(auth_scheme, cred_pubkey)?;
        let proposer_id = members::slot_id(&proposer_slot)?;
        let _ = members::find_index(self.recovery.members(), proposer_id)
            .ok_or(IkaveryError::NotAMember)?;

        // The new member must not already be in the roster, and the roster
        // must have headroom.
        let new_member: MemberSlot = new_member_packed;
        members::validate_slot(&new_member)?;
        let new_id = members::slot_id(&new_member)?;
        if members::find_index(self.recovery.members(), new_id).is_some() {
            return Err(IkaveryError::DuplicateMember.into());
        }
        if self.recovery.members().len() >= MAX_MEMBERS {
            return Err(IkaveryError::RosterFull.into());
        }

        // Per-op challenge — `challenges::enroll_propose` matches Sui's
        // `recovery::enroll_propose` byte-for-byte.
        let challenge = challenges::enroll_propose(
            self.recovery.recovery_id.as_array().as_slice(),
            new_id,
            enrollment_index as u64,
        );
        let cdj_len = client_data_json_len as usize;
        if cdj_len > MAX_CLIENT_DATA_JSON_BYTES {
            return Err(IkaveryError::BadMessageLength.into());
        }
        let cdj = &client_data_json[..cdj_len];
        let sysvar_view = self.instructions_sysvar.to_account_view();
        precompile::check_sysvar_address(sysvar_view.address())
            .map_err(|_| IkaveryError::BadInstructionsSysvar)?;
        let sysvar_data = sysvar_view
            .try_borrow()
            .map_err(|_| IkaveryError::BadInstructionsSysvar)?;
        verify_credential(
            auth_scheme,
            cred_pubkey,
            &challenge,
            self.payer.address(),
            &sysvar_data,
            cdj,
            &auth_signature,
        )
        .map_err(auth_error_to_program_error)?;

        self.enrollment.set_inner(EnrollmentProposalInner {
            recovery: *self.recovery.address(),
            enrollment_index,
            proposer_id: proposer_slot,
            new_member,
            new_encryption_key_address: Address::new_from_array(new_encryption_key_address),
            addition_approver_only,
            approval_count: 0,
            status: STATUS_ACTIVE,
        });

        self.recovery.enrollment_count = enrollment_index
            .checked_add(1)
            .ok_or(IkaveryError::ArithmeticOverflow)?
            .into();
        Ok(())
    }
}
