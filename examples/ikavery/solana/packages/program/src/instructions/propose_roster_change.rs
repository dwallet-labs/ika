use crate::auth::challenges;
use crate::auth::members;
use crate::auth::precompile;
use crate::auth::{auth_error_to_program_error, verify_credential};
use crate::error::IkaveryError;
use crate::state::{
    MemberSlot, Recovery, RosterChangeProposal, RosterChangeProposalInner, RosterChangeStaging,
    AUTH_PUBKEY_BYTES, AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, MAX_MEMBERS,
    MEMBER_SLOT_LEN, STATUS_ACTIVE,
};
use quasar_lang::prelude::*;

#[derive(Accounts)]
#[instruction(roster_change_index: u32)]
pub struct ProposeRosterChange {
    #[account(mut, address = Recovery::seeds(recovery_id.address()))]
    pub recovery: Account<Recovery>,
    pub recovery_id: UncheckedAccount,
    #[account(
        init,
        payer = payer,
        address = RosterChangeProposal::seeds(recovery.address(), roster_change_index),
    )]
    pub roster_change: Account<RosterChangeProposal>,
    /// Pre-staged payload (additions/removals/threshold). Closed on success
    /// with rent refunded to `payer`. The 1-tx flow uses the same wallet
    /// for stage + propose, so this folds the refund into the propose
    /// payer (avoids the dup-mut-borrow error from declaring the refund
    /// target as a second writable slot pointing at the same address).
    #[account(
        mut,
        has_one(recovery),
        close(dest = payer),
        address = RosterChangeStaging::seeds(recovery.address(), roster_change_index),
    )]
    pub staging: Account<RosterChangeStaging>,
    #[account(mut)]
    pub payer: Signer,
    pub instructions_sysvar: UncheckedAccount,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl ProposeRosterChange {
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn propose_roster_change(
        &mut self,
        roster_change_index: u32,
        payload_hash: [u8; 32],
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        let expected_index: u32 = self.recovery.roster_change_count.into();
        require!(
            roster_change_index == expected_index,
            IkaveryError::WrongIndex
        );

        // The credential signed `payload_hash`; the staging account holds the
        // canonical recompute. If they disagree the credential isn't
        // authorising whatever the staging payer wrote — reject.
        if self.staging.payload_hash != payload_hash {
            return Err(IkaveryError::IntentDigestMismatch.into());
        }

        // Resolve the credential's canonical id and confirm membership.
        let cred_pubkey = members::pubkey_slice(auth_scheme, &auth_pubkey)?;
        let proposer_slot: MemberSlot = members::credential_slot(auth_scheme, cred_pubkey)?;
        let proposer_id = members::slot_id(&proposer_slot)?;
        let _ = members::find_index(self.recovery.members(), proposer_id)
            .ok_or(IkaveryError::NotAMember)?;

        // Snapshot the staging payload onto the stack before mutating the
        // proposal. After this point the staging account gets closed via the
        // accounts macro epilogue.
        let mut additions: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut addition_len = 0usize;
        for slot in self.staging.additions().iter() {
            additions[addition_len] = *slot;
            addition_len += 1;
        }
        let mut removals: [MemberSlot; MAX_MEMBERS] = [[0u8; MEMBER_SLOT_LEN]; MAX_MEMBERS];
        let mut removal_len = 0usize;
        for slot in self.staging.removals().iter() {
            removals[removal_len] = *slot;
            removal_len += 1;
        }
        let active_additions = &additions[..addition_len];
        let active_removals = &removals[..removal_len];
        let addition_approver_only_bitmap: u16 = self.staging.addition_approver_only_bitmap.into();
        let new_threshold: u16 = self.staging.new_threshold.into();
        let has_new_threshold: u8 = self.staging.has_new_threshold;

        // Re-run the structural checks even though stage already did. The
        // staging account is keyed by recovery + index so it can only be
        // written with the correct recovery / index, but a second pass here
        // is cheap insurance.
        if addition_len > 0 {
            members::validate_members(active_additions)?;
        }
        for slot in active_removals {
            members::validate_slot(slot)?;
            let id = members::slot_id(slot)?;
            let _ =
                members::find_index(self.recovery.members(), id).ok_or(IkaveryError::NotAMember)?;
        }

        let challenge = challenges::roster_change_propose(
            self.recovery.recovery_id.as_array().as_slice(),
            &payload_hash,
            roster_change_index as u64,
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

        self.roster_change.set_inner(
            RosterChangeProposalInner {
                recovery: *self.recovery.address(),
                roster_change_index,
                proposer_id: proposer_slot,
                payload_hash,
                addition_approver_only_bitmap,
                new_threshold,
                has_new_threshold,
                approval_count: 0,
                status: STATUS_ACTIVE,
                additions: active_additions,
                removals: active_removals,
            },
            self.payer.to_account_view(),
            self.rent.lamports_per_byte(),
            self.rent.exemption_threshold_raw(),
        )?;

        self.recovery.roster_change_count = roster_change_index
            .checked_add(1)
            .ok_or(IkaveryError::ArithmeticOverflow)?
            .into();
        Ok(())
    }
}
