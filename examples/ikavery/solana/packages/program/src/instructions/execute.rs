use crate::error::IkaveryError;
use crate::state::{Proposal, Recovery, MAX_MESSAGE_BYTES, STATUS_APPROVED, STATUS_EXECUTED};
use crate::sweep::intent as sweep_intent;
use ika_dwallet_quasar::DWalletContext;
use quasar_lang::prelude::*;
use solana_keccak_hasher::hashv;

#[derive(Accounts)]
pub struct Execute {
    pub recovery: Account<Recovery>,
    #[account(mut, has_one(recovery))]
    pub proposal: Account<Proposal>,
    /// Anyone can fire `execute` once `STATUS_APPROVED` and the rebuilt
    /// intent digest match — the security gate is the threshold of
    /// credential-authorised approvals already on the proposal, not who
    /// signs the on-chain tx. This matches Sui's design and lets passkey-only
    /// rosters use a sponsor wallet to actually broadcast the tx.
    #[account(mut)]
    pub payer: Signer,
    pub coordinator: UncheckedAccount,
    #[account(mut)]
    pub message_approval: UncheckedAccount,
    pub dwallet: UncheckedAccount,
    pub caller_program: UncheckedAccount,
    pub cpi_authority: UncheckedAccount,
    pub dwallet_program: UncheckedAccount,
    pub system_program: Program<SystemProgram>,
}

impl Execute {
    #[inline(always)]
    pub fn execute(
        &mut self,
        tx_index: u8,
        message_bytes: [u8; MAX_MESSAGE_BYTES],
        message_len: u16,
        message_approval_bump: u8,
        cpi_authority_bump: u8,
    ) -> Result<(), ProgramError> {
        require!(
            self.proposal.status == STATUS_APPROVED || self.proposal.status == STATUS_EXECUTED,
            IkaveryError::NotApproved
        );

        let bundle_len = self.proposal.intent_digests().len();
        let idx = tx_index as usize;
        require!(idx < bundle_len, IkaveryError::TxIndexOutOfBounds);

        // Per-tx idempotency. The CPI to dWallet's `approve_message` writes
        // a MessageApproval PDA keyed by the per-tx digest; firing twice for
        // the same index would either re-init the same PDA (collision) or
        // worse, sign-and-broadcast the same tx twice. The bitmap rejects
        // re-runs cleanly.
        let bit = 1u8 << tx_index;
        require!(
            self.proposal.executed_bitmap & bit == 0,
            IkaveryError::TxAlreadyExecuted
        );

        if message_len as usize > MAX_MESSAGE_BYTES {
            return Err(IkaveryError::BadMessageLength.into());
        }
        let msg_slice = &message_bytes[..message_len as usize];

        // Re-derive the structural intent digest from the freshly-built
        // message bytes and assert it matches the proposal's stored
        // digest at the requested index. This is the property that lets
        // the executor refresh the recent blockhash without redirecting
        // funds.
        let rebuilt_digest = sweep_intent::hash_message_bytes(msg_slice)
            .map_err(|_| IkaveryError::IntentExtractionFailed)?;
        let stored_digest = *self
            .proposal
            .intent_digests()
            .get(idx)
            .ok_or(IkaveryError::TxIndexOutOfBounds)?;
        require!(
            rebuilt_digest == stored_digest,
            IkaveryError::IntentDigestMismatch
        );

        let message_digest = hashv(&[msg_slice]).to_bytes();

        let dwallet_ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            cpi_authority_bump,
        };
        dwallet_ctx.approve_message(
            self.coordinator.to_account_view(),
            self.message_approval.to_account_view(),
            self.dwallet.to_account_view(),
            self.payer.to_account_view(),
            self.system_program.to_account_view(),
            message_digest,
            [0u8; 32],
            self.proposal.user_pubkey,
            self.proposal.signature_scheme.into(),
            message_approval_bump,
        )?;

        // Mark this index executed; once every bit in 0..bundle_len is set,
        // the proposal moves to STATUS_EXECUTED. Bundles smaller than 8
        // leave high bits zero, so we mask down to `bundle_len` bits.
        self.proposal.executed_bitmap |= bit;
        let full_mask: u8 = if bundle_len >= 8 {
            0xFFu8
        } else {
            (1u8 << bundle_len) - 1
        };
        if self.proposal.executed_bitmap == full_mask {
            self.proposal.status = STATUS_EXECUTED;
        }
        Ok(())
    }
}
