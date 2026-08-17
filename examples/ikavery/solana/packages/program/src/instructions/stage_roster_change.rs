use crate::auth::challenges;
use crate::auth::members;
use crate::error::IkaveryError;
use crate::instructions::create_recovery::CREATE_MEMBERS_BYTES;
use crate::state::{
    MemberSlot, Recovery, RosterChangeStaging, RosterChangeStagingInner, MAX_MEMBERS,
};
use quasar_lang::prelude::*;

#[derive(Accounts)]
#[instruction(roster_change_index: u32)]
pub struct StageRosterChangePayload {
    #[account(address = Recovery::seeds(recovery_id.address()))]
    pub recovery: Account<Recovery>,
    pub recovery_id: UncheckedAccount,
    #[account(
        init(idempotent),
        payer = payer,
        address = RosterChangeStaging::seeds(recovery.address(), roster_change_index),
    )]
    pub staging: Account<RosterChangeStaging>,
    #[account(mut)]
    pub payer: Signer,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl StageRosterChangePayload {
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn stage(
        &mut self,
        roster_change_index: u32,
        additions_packed: [u8; CREATE_MEMBERS_BYTES],
        addition_count: u8,
        addition_approver_only_bitmap: u16,
        removals_packed: [u8; CREATE_MEMBERS_BYTES],
        removal_count: u8,
        new_threshold: u16,
        has_new_threshold: u8,
    ) -> Result<(), ProgramError> {
        // Match the staging PDA to the next pending roster change so we don't
        // buffer payloads against stale indexes. Same monotonic check the
        // propose ix runs.
        let expected_index: u32 = self.recovery.roster_change_count.into();
        require!(
            roster_change_index == expected_index,
            IkaveryError::WrongIndex
        );

        let n_add = addition_count as usize;
        let n_rem = removal_count as usize;
        if n_add > MAX_MEMBERS || n_rem > MAX_MEMBERS {
            return Err(IkaveryError::TooManyMembers.into());
        }

        // SAFETY: see create_recovery; flat byte buffer aliases array-of-slots
        // with identical size and alignment (1).
        let additions: &[MemberSlot; MAX_MEMBERS] = unsafe {
            &*(&additions_packed as *const [u8; CREATE_MEMBERS_BYTES]
                as *const [MemberSlot; MAX_MEMBERS])
        };
        let removals: &[MemberSlot; MAX_MEMBERS] = unsafe {
            &*(&removals_packed as *const [u8; CREATE_MEMBERS_BYTES]
                as *const [MemberSlot; MAX_MEMBERS])
        };
        let active_additions = &additions[..n_add];
        let active_removals = &removals[..n_rem];

        if n_add > 0 {
            members::validate_members(active_additions)?;
        }
        for slot in active_removals {
            members::validate_slot(slot)?;
        }

        // Recompute the canonical payload hash and stash it. The propose ix
        // will hand the credential's signed payload_hash and we'll compare —
        // there's no trust in `self.payer` to have computed it correctly.
        let mut id_slices: [&[u8]; MAX_MEMBERS] = [&[]; MAX_MEMBERS];
        for (i, slot) in active_removals.iter().enumerate() {
            id_slices[i] = members::slot_id(slot)?;
        }
        let payload_hash = challenges::roster_change_payload(
            &id_slices[..n_rem],
            new_threshold as u64,
            has_new_threshold == 1,
        )
        .ok_or(IkaveryError::TooManyMembers)?;

        self.staging.set_inner(
            RosterChangeStagingInner {
                recovery: *self.recovery.address(),
                roster_change_index,
                payload_hash,
                addition_approver_only_bitmap,
                new_threshold,
                has_new_threshold,
                additions: active_additions,
                removals: active_removals,
            },
            self.payer.to_account_view(),
            self.rent.lamports_per_byte(),
            self.rent.exemption_threshold_raw(),
        )
    }
}
