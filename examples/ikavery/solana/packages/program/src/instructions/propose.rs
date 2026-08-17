use crate::auth::challenges;
use crate::auth::members;
use crate::auth::precompile;
use crate::auth::{auth_error_to_program_error, verify_credential};
use crate::error::IkaveryError;
use crate::state::{
    MemberSlot, Proposal, ProposalInner, Recovery, AUTH_PUBKEY_BYTES, AUTH_SIGNATURE_BYTES,
    MAX_BUNDLE_PER_PROPOSAL, MAX_CLIENT_DATA_JSON_BYTES, PROPOSE_DIGESTS_BYTES, STATUS_ACTIVE,
};
use quasar_lang::prelude::*;

#[derive(Accounts)]
#[instruction(proposal_index: u32)]
pub struct Propose {
    #[account(mut, address = Recovery::seeds(recovery_id.address()))]
    pub recovery: Account<Recovery>,
    pub recovery_id: UncheckedAccount,
    #[account(
        init,
        payer = proposer,
        address = Proposal::seeds(recovery.address(), proposal_index),
    )]
    pub proposal: Account<Proposal>,
    #[account(mut)]
    pub proposer: Signer,
    /// Solana's `Sysvar1nstructions…`. Read directly (not via `Sysvar<…>`)
    /// because `solana-instructions-sysvar` works on `AccountInfo`, not the
    /// Quasar `AccountView` we have here. We re-decode the binary layout
    /// in [`crate::precompile`].
    pub instructions_sysvar: UncheckedAccount,
    pub rent: Sysvar<Rent>,
    pub system_program: Program<SystemProgram>,
}

impl Propose {
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        &mut self,
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
        // The ix-arg index must match the on-account counter so PDAs stay
        // monotonic; mismatched callers can't squat on stale slots.
        let expected_index: u32 = self.recovery.proposal_count.into();
        require!(proposal_index == expected_index, IkaveryError::WrongIndex);

        // Bundle size validation. `digest_count == 0` would let a proposer
        // collect approvals on a no-op; the cap matches the on-account Vec
        // capacity and Sui's `MAX_BUNDLE_SIZE`.
        let n = digest_count as usize;
        require!(n > 0, IkaveryError::BundleEmpty);
        require!(n <= MAX_BUNDLE_PER_PROPOSAL, IkaveryError::BundleTooLarge);

        // Unpack the contiguous 32*N byte buffer into discrete digests for
        // the bundle-hash helper. The trailing slots in `digests_packed`
        // past `n*32` are ignored (proposer can leave them zero).
        let mut digests: [[u8; 32]; MAX_BUNDLE_PER_PROPOSAL] = [[0u8; 32]; MAX_BUNDLE_PER_PROPOSAL];
        for (i, dst) in digests.iter_mut().enumerate().take(n) {
            let off = i * 32;
            dst.copy_from_slice(&digests_packed[off..off + 32]);
        }

        // Resolve the credential into its on-chain id and confirm it's a
        // current member.
        let cred_pubkey = members::pubkey_slice(auth_scheme, &auth_pubkey)?;
        let proposer_slot: MemberSlot = members::credential_slot(auth_scheme, cred_pubkey)?;
        let proposer_id = members::slot_id(&proposer_slot)?;
        let _ = members::find_index(self.recovery.members(), proposer_id)
            .ok_or(IkaveryError::NotAMember)?;

        // Per-op challenge digest the credential must have signed. The
        // bundle hash commits to all N intent digests in order, so the
        // credential's signature gates the entire sweep bundle.
        let bundle = challenges::bundle_hash_from_digests(&digests[..n])
            .ok_or(IkaveryError::IntentExtractionFailed)?;
        let challenge = challenges::propose(
            self.recovery.recovery_id.as_array().as_slice(),
            &bundle,
            proposal_index as u64,
        );

        // Verify the precompile (or the on-tx Signer for SolanaAddress)
        // proves the credential authorised this exact challenge.
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
            self.proposer.address(),
            &sysvar_data,
            cdj,
            &auth_signature,
        )
        .map_err(auth_error_to_program_error)?;

        self.proposal.set_inner(
            ProposalInner {
                recovery: *self.recovery.address(),
                proposal_index,
                proposer_id: proposer_slot,
                user_pubkey,
                signature_scheme,
                approval_count: 0,
                status: STATUS_ACTIVE,
                executed_bitmap: 0,
                intent_digests: &digests[..n],
            },
            self.proposer.to_account_view(),
            self.rent.lamports_per_byte(),
            self.rent.exemption_threshold_raw(),
        )?;

        self.recovery.proposal_count = proposal_index
            .checked_add(1)
            .ok_or(IkaveryError::ArithmeticOverflow)?
            .into();
        Ok(())
    }
}
