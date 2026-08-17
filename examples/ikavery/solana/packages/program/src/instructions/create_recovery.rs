use crate::auth::members;
use crate::error::IkaveryError;
use crate::state::{MemberSlot, Recovery, RecoveryInner, MAX_MEMBERS, MEMBER_SLOT_LEN};
use quasar_lang::prelude::*;
use solana_address::Address;

pub const CREATE_MEMBERS_BYTES: usize = MAX_MEMBERS * MEMBER_SLOT_LEN;

#[derive(Accounts)]
pub struct CreateRecovery {
    #[account(mut)]
    pub creator: Signer,
    /// Fresh keypair owned by the caller. Used as the PDA seed nonce so a
    /// creator can host multiple recoveries; signs once at creation, never
    /// referenced again.
    pub recovery_id: Signer,
    #[account(
        init,
        payer = creator,
        address = Recovery::seeds(recovery_id.address()),
    )]
    pub recovery: Account<Recovery>,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl CreateRecovery {
    #[inline(always)]
    pub fn create(
        &mut self,
        dwallet: [u8; 32],
        dwallet_curve: u16,
        threshold: u16,
        member_count: u8,
        approver_only_bitmap: u16,
        members_packed: [u8; CREATE_MEMBERS_BYTES],
    ) -> Result<(), ProgramError> {
        let count = member_count as usize;
        if count == 0 || count > MAX_MEMBERS {
            return Err(IkaveryError::TooManyMembers.into());
        }
        require!(threshold > 0, IkaveryError::InvalidThreshold);
        require!(threshold as usize <= count, IkaveryError::InvalidThreshold);

        // Reinterpret the flat byte buffer as a fixed-size array of slots.
        // SAFETY: `[u8; MEMBER_SLOT_LEN * MAX_MEMBERS]` and `[MemberSlot; MAX_MEMBERS]`
        // have identical size and alignment (1).
        let slots: &[MemberSlot; MAX_MEMBERS] = unsafe {
            &*(&members_packed as *const [u8; CREATE_MEMBERS_BYTES]
                as *const [MemberSlot; MAX_MEMBERS])
        };
        let active = &slots[..count];
        members::validate_members(active)?;

        self.recovery.set_inner(
            RecoveryInner {
                recovery_id: *self.recovery_id.address(),
                creator: *self.creator.address(),
                dwallet: Address::new_from_array(dwallet),
                dwallet_curve,
                threshold,
                approver_only_bitmap,
                proposal_count: 0,
                roster_change_count: 0,
                enrollment_count: 0,
                members: active,
            },
            self.creator.to_account_view(),
            self.rent.lamports_per_byte(),
            self.rent.exemption_threshold_raw(),
        )
    }
}
