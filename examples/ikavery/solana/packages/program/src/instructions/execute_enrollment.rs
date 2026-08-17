use crate::auth::members;
use crate::error::IkaveryError;
use crate::state::{
    EnrollmentProposal, MemberSlot, Recovery, RecoveryInner, MAX_MEMBERS, MEMBER_SLOT_LEN,
    STATUS_APPROVED, STATUS_EXECUTED,
};
use quasar_lang::prelude::*;
use solana_address::Address;

#[derive(Accounts)]
pub struct ExecuteEnrollment {
    #[account(mut)]
    pub recovery: Account<Recovery>,
    #[account(mut, has_one(recovery))]
    pub enrollment: Account<EnrollmentProposal>,
    /// Anyone can fire `execute_enrollment` once threshold is met. Same
    /// rationale as `execute` / `execute_roster_change` — the Signer
    /// is just a sponsor that pays for any account-data resize when the
    /// roster grows.
    #[account(mut)]
    pub payer: Signer,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl ExecuteEnrollment {
    #[inline(always)]
    pub fn execute_enrollment(&mut self) -> Result<(), ProgramError> {
        // Snapshot fixed-state fields before mutating.
        let recovery_id: Address = self.recovery.recovery_id;
        let creator: Address = self.recovery.creator;
        let dwallet: Address = self.recovery.dwallet;
        let dwallet_curve: u16 = self.recovery.dwallet_curve.into();
        let threshold: u16 = self.recovery.threshold.into();
        let proposal_count: u32 = self.recovery.proposal_count.into();
        let roster_change_count: u32 = self.recovery.roster_change_count.into();
        let enrollment_count: u32 = self.recovery.enrollment_count.into();
        let mut approver_only_bitmap: u16 = self.recovery.approver_only_bitmap.into();

        // Snapshot member list into a stack buffer.
        let mut roster: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut roster_len = 0usize;
        for slot in self.recovery.members().iter() {
            roster[roster_len] = *slot;
            roster_len += 1;
        }

        require!(
            self.enrollment.status == STATUS_APPROVED,
            IkaveryError::NotApproved
        );
        let approval_count: u16 = self.enrollment.approval_count.into();
        require!(approval_count >= threshold, IkaveryError::NotApproved);

        // Re-validate the new member at execute time so a stale roster
        // can't slip a duplicate through. The propose-time check used the
        // pre-execute roster; same property is required here.
        let new_member: MemberSlot = self.enrollment.new_member;
        members::validate_slot(&new_member)?;
        let new_id = members::slot_id(&new_member)?;
        if members::find_index(&roster[..roster_len], new_id).is_some() {
            return Err(IkaveryError::DuplicateMember.into());
        }
        if roster_len >= MAX_MEMBERS {
            return Err(IkaveryError::RosterFull.into());
        }

        // Add to roster + update bitmap. (No re-encrypt CPI: Solana ika
        // pre-alpha has only mock user shares. When mainnet exposes
        // real share encryption the CPI plugs in here, gated on
        // `addition_approver_only == 0`.)
        let new_slot_idx = roster_len;
        roster[new_slot_idx] = new_member;
        if self.enrollment.addition_approver_only == 1 {
            approver_only_bitmap |= 1u16 << (new_slot_idx as u16);
        } else {
            approver_only_bitmap &= !(1u16 << (new_slot_idx as u16));
        }
        roster_len += 1;

        self.recovery.set_inner(
            RecoveryInner {
                recovery_id,
                creator,
                dwallet,
                dwallet_curve,
                threshold,
                approver_only_bitmap,
                proposal_count,
                roster_change_count,
                enrollment_count,
                members: &roster[..roster_len],
            },
            self.payer.to_account_view(),
            self.rent.lamports_per_byte(),
            self.rent.exemption_threshold_raw(),
        )?;
        self.enrollment.status = STATUS_EXECUTED;
        Ok(())
    }
}
