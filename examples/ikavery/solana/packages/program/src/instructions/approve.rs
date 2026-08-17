use crate::auth::challenges;
use crate::auth::members;
use crate::auth::precompile;
use crate::auth::{auth_error_to_program_error, verify_credential};
use crate::error::IkaveryError;
use crate::state::{
    Approval, ApprovalInner, MemberSlot, Proposal, Recovery, AUTH_PUBKEY_BYTES,
    AUTH_SIGNATURE_BYTES, MAX_CLIENT_DATA_JSON_BYTES, STATUS_ACTIVE, STATUS_APPROVED,
};
use quasar_lang::prelude::*;
use solana_address::Address;
use solana_sha256_hasher::hashv;

#[derive(Accounts)]
pub struct Approve {
    pub recovery: Account<Recovery>,
    #[account(mut, has_one(recovery))]
    pub proposal: Account<Proposal>,
    /// Carries the credential's `member_id_hash` via its own account
    /// address. Not loaded; the handler verifies the supplied hash actually
    /// derives from the credential before any state mutates. This is the
    /// only way to feed a per-credential value into the `Approval` PDA's
    /// seed expression — Quasar's `address = …` is evaluated in the
    /// accounts-struct scope and can't reach instruction arguments.
    pub member_id: UncheckedAccount,
    #[account(
        init,
        payer = payer,
        address = Approval::seeds(proposal.address(), member_id.address()),
    )]
    pub approval: Account<Approval>,
    /// Whoever pays for the Approval PDA's rent. Decoupled from the auth
    /// identity: a sponsor wallet can pay while a passkey-derived
    /// credential authorises the vote.
    #[account(mut)]
    pub payer: Signer,
    pub instructions_sysvar: UncheckedAccount,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl Approve {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn approve(
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

        // The hash carried by `member_id` must match what we'd compute from
        // the credential — otherwise a caller could pin their vote to a
        // different member's slot and dodge double-vote checks.
        let expected_hash = Address::new_from_array(hashv(&[member_id]).to_bytes());
        if &expected_hash != self.member_id.address() {
            return Err(IkaveryError::WrongSigner.into());
        }
        let member_id_hash = expected_hash;

        require!(
            self.proposal.status == STATUS_ACTIVE,
            IkaveryError::ProposalNotActive
        );

        let proposal_index: u32 = self.proposal.proposal_index.into();
        let challenge = challenges::approve(
            self.recovery.recovery_id.as_array().as_slice(),
            proposal_index as u64,
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

        let approval_count: u16 = self.proposal.approval_count.into();
        let new_approvals = approval_count
            .checked_add(1)
            .ok_or(IkaveryError::ArithmeticOverflow)?;

        self.approval.set_inner(ApprovalInner {
            proposal: *self.proposal.address(),
            member_id_hash,
            approved_at_count: new_approvals,
        });

        self.proposal.approval_count = new_approvals.into();

        let threshold: u16 = self.recovery.threshold.into();
        if new_approvals >= threshold {
            self.proposal.status = STATUS_APPROVED;
        }
        Ok(())
    }
}
