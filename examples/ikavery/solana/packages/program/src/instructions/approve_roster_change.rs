use crate::auth::challenges;
use crate::auth::members;
use crate::auth::precompile;
use crate::auth::{auth_error_to_program_error, verify_credential};
use crate::error::IkaveryError;
use crate::state::{
    MemberSlot, Recovery, RosterChangeApproval, RosterChangeApprovalInner, RosterChangeProposal,
    AUTH_PUBKEY_BYTES, AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, STATUS_ACTIVE,
    STATUS_APPROVED,
};
use quasar_lang::prelude::*;
use solana_address::Address;
use solana_sha256_hasher::hashv;

#[derive(Accounts)]
pub struct ApproveRosterChange {
    pub recovery: Account<Recovery>,
    #[account(mut, has_one(recovery))]
    pub roster_change: Account<RosterChangeProposal>,
    /// Carries the credential's `member_id_hash` via its address. Same
    /// rationale as in `Approve` — Quasar's `address = …` can't reach
    /// instruction args, so the seed value rides in on an account address.
    pub member_id: UncheckedAccount,
    #[account(
        init,
        payer = payer,
        address = RosterChangeApproval::seeds(roster_change.address(), member_id.address()),
    )]
    pub approval: Account<RosterChangeApproval>,
    #[account(mut)]
    pub payer: Signer,
    pub instructions_sysvar: UncheckedAccount,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl ApproveRosterChange {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn approve_roster_change(
        &mut self,
        auth_scheme: u8,
        auth_pubkey: [u8; AUTH_PUBKEY_BYTES],
        client_data_json: [u8; MAX_CLIENT_DATA_JSON_BYTES],
        client_data_json_len: u16,
        auth_signature: [u8; AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ProgramError> {
        let cred_pubkey = members::pubkey_slice(auth_scheme, &auth_pubkey)?;
        let member_slot: MemberSlot = members::credential_slot(auth_scheme, cred_pubkey)?;
        let member_id = members::slot_id(&member_slot)?;
        let _ = members::find_index(self.recovery.members(), member_id)
            .ok_or(IkaveryError::NotAMember)?;

        let expected_hash = Address::new_from_array(hashv(&[member_id]).to_bytes());
        if &expected_hash != self.member_id.address() {
            return Err(IkaveryError::WrongSigner.into());
        }

        require!(
            self.roster_change.status == STATUS_ACTIVE,
            IkaveryError::ProposalNotActive
        );

        let roster_change_index: u32 = self.roster_change.roster_change_index.into();
        let challenge = challenges::roster_change_approve(
            self.recovery.recovery_id.as_array().as_slice(),
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

        let approval_count: u16 = self.roster_change.approval_count.into();
        let new_approvals = approval_count
            .checked_add(1)
            .ok_or(IkaveryError::ArithmeticOverflow)?;

        self.approval.set_inner(RosterChangeApprovalInner {
            roster_change: *self.roster_change.address(),
            member_id_hash: expected_hash,
            approved_at_count: new_approvals,
        });

        self.roster_change.approval_count = new_approvals.into();

        let threshold: u16 = self.recovery.threshold.into();
        if new_approvals >= threshold {
            self.roster_change.status = STATUS_APPROVED;
        }
        Ok(())
    }
}
