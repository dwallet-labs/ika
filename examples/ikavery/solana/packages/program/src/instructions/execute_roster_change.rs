use crate::auth::members;
use crate::error::IkaveryError;
use crate::state::{
    MemberSlot, Recovery, RecoveryInner, RosterChangeProposal, MAX_MEMBERS, MEMBER_SLOT_LEN,
    STATUS_APPROVED, STATUS_EXECUTED,
};
use quasar_lang::prelude::*;
use solana_address::Address;

#[derive(Accounts)]
pub struct ExecuteRosterChange {
    #[account(mut)]
    pub recovery: Account<Recovery>,
    #[account(mut, has_one(recovery))]
    pub roster_change: Account<RosterChangeProposal>,
    /// Anyone can fire `execute_roster_change` once threshold is met — same
    /// reasoning as `execute`. The Signer is just a sponsor that pays for any
    /// account-data resize when the roster grows.
    #[account(mut)]
    pub payer: Signer,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl ExecuteRosterChange {
    #[inline(always)]
    pub fn execute_roster_change(&mut self) -> Result<(), ProgramError> {
        // Snapshot fixed-state fields before mutating.
        let recovery_id: Address = self.recovery.recovery_id;
        let creator: Address = self.recovery.creator;
        let dwallet: Address = self.recovery.dwallet;
        let dwallet_curve: u16 = self.recovery.dwallet_curve.into();
        let mut threshold: u16 = self.recovery.threshold.into();
        let proposal_count: u32 = self.recovery.proposal_count.into();
        let roster_change_count: u32 = self.recovery.roster_change_count.into();
        let enrollment_count: u32 = self.recovery.enrollment_count.into();

        // Snapshot member list into a stack buffer.
        let mut roster: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut roster_len = 0usize;
        for slot in self.recovery.members().iter() {
            roster[roster_len] = *slot;
            roster_len += 1;
        }

        // Snapshot the roster-change proposal's payload.
        let mut additions: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut addition_len = 0usize;
        for slot in self.roster_change.additions().iter() {
            additions[addition_len] = *slot;
            addition_len += 1;
        }
        let mut removals: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut removal_len = 0usize;
        for slot in self.roster_change.removals().iter() {
            removals[removal_len] = *slot;
            removal_len += 1;
        }
        let addition_approver_only_bitmap: u16 =
            self.roster_change.addition_approver_only_bitmap.into();
        let new_threshold: u16 = self.roster_change.new_threshold.into();
        let has_new_threshold: u8 = self.roster_change.has_new_threshold;

        require!(
            self.roster_change.status == STATUS_APPROVED,
            IkaveryError::NotApproved
        );
        let approval_count: u16 = self.roster_change.approval_count.into();
        require!(approval_count >= threshold, IkaveryError::NotApproved);

        roster_len = apply_removals(&mut roster, roster_len, &removals[..removal_len])?;

        // Removals can shift slots — rebuild the bitmap from scheme tags.
        let mut approver_only_bitmap = members::bitmap_from_members(&roster[..roster_len]);

        if addition_len > 0 {
            roster_len = apply_additions(
                &mut roster,
                &mut approver_only_bitmap,
                roster_len,
                &additions[..addition_len],
                addition_approver_only_bitmap,
            )?;
        }

        if roster_len == 0 {
            return Err(IkaveryError::NoMembers.into());
        }

        if has_new_threshold == 1 {
            threshold = new_threshold;
        }
        if threshold == 0 {
            return Err(IkaveryError::InvalidThreshold.into());
        }
        if threshold as usize > roster_len {
            return Err(IkaveryError::ThresholdAboveRoster.into());
        }

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
        self.roster_change.status = STATUS_EXECUTED;
        Ok(())
    }
}

fn apply_removals(
    roster: &mut [MemberSlot; MAX_MEMBERS],
    mut len: usize,
    removals: &[MemberSlot],
) -> Result<usize, ProgramError> {
    for slot in removals {
        let id = members::slot_id(slot)?;
        let idx = members::find_index(&roster[..len], id).ok_or(IkaveryError::NotAMember)?;
        // Shift down to keep order stable; the bitmap is recomputed afterwards.
        for j in idx..len - 1 {
            roster[j] = roster[j + 1];
        }
        roster[len - 1] = [0u8; MEMBER_SLOT_LEN];
        len -= 1;
    }
    Ok(len)
}

fn apply_additions(
    roster: &mut [MemberSlot; MAX_MEMBERS],
    bitmap: &mut u16,
    mut len: usize,
    additions: &[MemberSlot],
    addition_approver_only_bitmap: u16,
) -> Result<usize, ProgramError> {
    for (i, slot) in additions.iter().enumerate() {
        if len >= MAX_MEMBERS {
            return Err(IkaveryError::RosterFull.into());
        }
        members::validate_slot(slot)?;
        let id = members::slot_id(slot)?;
        if members::find_index(&roster[..len], id).is_some() {
            return Err(IkaveryError::DuplicateMember.into());
        }
        roster[len] = *slot;
        if (addition_approver_only_bitmap >> (i as u16)) & 1 == 1 {
            *bitmap |= 1u16 << (len as u16);
        } else {
            *bitmap &= !(1u16 << (len as u16));
        }
        len += 1;
    }
    Ok(len)
}
