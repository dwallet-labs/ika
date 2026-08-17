//! On-chain account state.
//!
//! Account discriminator allocation (must stay stable):
//!   1 = Recovery
//!   2 = Proposal               (sweep proposal)
//!   3 = RosterChangeProposal
//!   4 = Approval               (per-member approval of a Proposal)
//!   5 = RosterChangeApproval   (per-member approval of a RosterChangeProposal)
//!   6 = EnrollmentProposal     (single-member-add with encryption-key binding)
//!   7 = EnrollmentApproval     (per-member approval of an EnrollmentProposal)
//!   8 = RosterChangeStaging    (additions/removals/threshold buffered for the
//!                               2-tx propose_roster_change flow; closed on
//!                               propose success or via explicit cleanup ix)
//!
//! Member-id slots: each slot is `[u8; MEMBER_SLOT_LEN]` where `slot[0]` is the
//! scheme tag and `slot[1..id_len_for_scheme(slot[0])]` is the pubkey/address.
//! Padding bytes past the active id are zero. Active member tables are stored
//! as `Vec<MemberSlot, MAX_MEMBERS>`; the Vec's length is the live member count.

use quasar_lang::prelude::*;
use solana_address::Address;

// Solana tx packets are capped at 1232 bytes. With MAX_MEMBERS=16 the
// `propose_roster_change` ix data alone is 1489 bytes (two 544-byte
// members buffers) — fundamentally unsendable. 8 keeps the max ix data
// at 945 bytes, which fits when sysvars + recovery + recoveryId are in
// an Address Lookup Table. Sui-side ikavery still uses 16; the cap is
// chain-specific and documented in QUASAR_FEEDBACK.md.
pub const MAX_MEMBERS: usize = 8;
// Quasar's Vec<T, N> macro takes a literal — keep it locked to MAX_MEMBERS.
const _: () = assert!(MAX_MEMBERS == 8);
pub const MEMBER_SLOT_LEN: usize = 34;

pub type MemberSlot = [u8; MEMBER_SLOT_LEN];

/// Maximum on-chain message-bytes per Solana tx that this program can
/// re-parse at execute time. Sweep transactions are small (≤300B
/// typical) — the headroom over that gives room for compute-budget
/// prefixes and SPL `TransferChecked` + `CloseAccount` combos.
pub const MAX_MESSAGE_BYTES: usize = 512;

/// Maximum number of transactions a single Proposal can carry in its sweep
/// bundle. Mirrors Sui's `MAX_BUNDLE_SIZE = 8`. The propose ix carries one
/// 32-byte intent digest per tx, capped to keep the ix data within Solana's
/// tx-packet budget alongside the WebAuthn auth args.
pub const MAX_BUNDLE_PER_PROPOSAL: usize = 8;
const _: () = assert!(MAX_BUNDLE_PER_PROPOSAL == 8);

/// Packed digest buffer length on the propose ix wire (`MAX_BUNDLE_PER_PROPOSAL * 32`).
pub const PROPOSE_DIGESTS_BYTES: usize = MAX_BUNDLE_PER_PROPOSAL * 32;

/// Fixed-size buffer for a credential's pubkey on the wire. The longest
/// scheme stores 33 bytes (compressed secp256k1/r1/webauthn); shorter
/// schemes pad with trailing zeroes and use the per-scheme length tag.
pub const AUTH_PUBKEY_BYTES: usize = 33;

/// Fixed-size buffer for a WebAuthn `client_data_json` blob. Browser-emitted
/// canonical form is typically ~120-200 bytes; 256 leaves headroom for long
/// origins and the optional `crossOrigin` / `topOrigin` fields. Unused for
/// every scheme other than `SCHEME_WEBAUTHN`.
pub const MAX_CLIENT_DATA_JSON_BYTES: usize = 256;

/// Fixed-size buffer for an inline ECDSA signature: 64-byte (r||s) plus a
/// 1-byte recovery_id. Currently only used by `SCHEME_SECP256K1`; other
/// schemes pad with zeroes. Exists as a separate ix arg so the SDK doesn't
/// have to overload `client_data_json` for non-WebAuthn use.
pub const AUTH_SIGNATURE_BYTES: usize = 65;

pub const STATUS_ACTIVE: u8 = 0;
pub const STATUS_APPROVED: u8 = 1;
pub const STATUS_EXECUTED: u8 = 2;

#[account(discriminator = 1, set_inner)]
#[seeds(b"recovery", recovery_id: Address)]
pub struct Recovery {
    pub recovery_id: Address,
    pub creator: Address,
    pub dwallet: Address,
    pub dwallet_curve: u16,
    pub threshold: u16,
    pub approver_only_bitmap: u16,
    pub proposal_count: u32,
    pub roster_change_count: u32,
    pub enrollment_count: u32,
    pub members: Vec<MemberSlot, 8>,
}

#[account(discriminator = 2, set_inner)]
#[seeds(b"proposal", recovery: Address, proposal_index: u32)]
pub struct Proposal {
    pub recovery: Address,
    pub proposal_index: u32,
    pub proposer_id: MemberSlot,
    /// dWallet user pubkey for the `approve_message` CPI.
    pub user_pubkey: [u8; 32],
    pub signature_scheme: u16,
    pub approval_count: u16,
    /// `STATUS_ACTIVE` → `STATUS_APPROVED` (threshold met) → `STATUS_EXECUTED`
    /// (every tx in the bundle has fired its `approve_message` CPI).
    pub status: u8,
    /// Bit `i` set iff `intent_digests[i]`'s `approve_message` CPI has
    /// fired. Per-tx execution is one-shot per proposal; the executor
    /// walks indexes 0..N-1 and broadcasts each tx after its bit flips.
    pub executed_bitmap: u8,
    /// One BCS-keccak intent digest per tx in the proposal's sweep bundle.
    /// Stored at propose time; at execute time the freshly-built message
    /// bytes for the requested `tx_index` are re-parsed, re-hashed, and
    /// compared against `intent_digests[tx_index]`. The blockhash is
    /// excluded from the digest, so the executor can refresh it without
    /// redirecting funds. Sui-parity with `RecoveryProposal.sweep_intents`.
    pub intent_digests: Vec<[u8; 32], 8>,
}

#[account(discriminator = 3, set_inner)]
#[seeds(b"roster", recovery: Address, roster_change_index: u32)]
pub struct RosterChangeProposal {
    pub recovery: Address,
    pub roster_change_index: u32,
    pub proposer_id: MemberSlot,
    pub payload_hash: [u8; 32],
    pub addition_approver_only_bitmap: u16,
    pub new_threshold: u16,
    pub has_new_threshold: u8,
    pub approval_count: u16,
    pub status: u8,
    pub additions: Vec<MemberSlot, 8>,
    pub removals: Vec<MemberSlot, 8>,
}

#[account(discriminator = 4, set_inner)]
#[seeds(b"approval", proposal: Address, member_id_hash: Address)]
pub struct Approval {
    pub proposal: Address,
    /// `sha256([scheme_byte, ...pubkey_or_address_bytes])` — the hash of
    /// the canonical member-id, packed into the 32-byte `Address` slot
    /// (Quasar's seed macro only accepts `Address`/`uN`). Using the hash
    /// lets the same PDA-keyed slot work across credential schemes where
    /// the credential isn't a Solana wallet at all (passkey, ed25519,
    /// secp256r1).
    pub member_id_hash: Address,
    pub approved_at_count: u16,
}

#[account(discriminator = 5, set_inner)]
#[seeds(b"roster_approval", roster_change: Address, member_id_hash: Address)]
pub struct RosterChangeApproval {
    pub roster_change: Address,
    pub member_id_hash: Address,
    pub approved_at_count: u16,
}

#[account(discriminator = 6, set_inner)]
#[seeds(b"enrollment", recovery: Address, enrollment_index: u32)]
pub struct EnrollmentProposal {
    pub recovery: Address,
    pub enrollment_index: u32,
    pub proposer_id: MemberSlot,
    pub new_member: MemberSlot,
    /// 32-byte encryption-key address — stored opaquely. The re-encrypt
    /// CPI fires once Solana ika exposes user-share encryption; pre-alpha
    /// has only mock shares, so `execute_enrollment` skips it today.
    pub new_encryption_key_address: Address,
    /// 1 if the new member is approver-only (votes but doesn't hold a
    /// share); 0 if key-holding. Mirrors the per-addition bit in
    /// `RosterChangeProposal`'s `addition_approver_only_bitmap`.
    pub addition_approver_only: u8,
    pub approval_count: u16,
    pub status: u8,
}

#[account(discriminator = 7, set_inner)]
#[seeds(b"enrollment_approval", enrollment: Address, member_id_hash: Address)]
pub struct EnrollmentApproval {
    pub enrollment: Address,
    pub member_id_hash: Address,
    pub approved_at_count: u16,
}

/// Pre-staged payload for `propose_roster_change`. Solana's 1232-byte tx
/// packet can't hold the propose ix's 945 bytes of args alongside a
/// secp256r1 precompile and the lookup-table footprint, so the bulky
/// additions/removals + threshold change are buffered into this PDA via
/// `stage_roster_change_payload` first; the propose tx then carries only
/// `payload_hash` + auth args and reads everything else from the staging
/// PDA. Closed (rent-refunded to `payer`) when propose succeeds.
#[account(discriminator = 8, set_inner)]
#[seeds(b"roster_staging_v2", recovery: Address, roster_change_index: u32)]
pub struct RosterChangeStaging {
    pub recovery: Address,
    pub roster_change_index: u32,
    pub payload_hash: [u8; 32],
    pub addition_approver_only_bitmap: u16,
    pub new_threshold: u16,
    pub has_new_threshold: u8,
    pub additions: Vec<MemberSlot, 8>,
    pub removals: Vec<MemberSlot, 8>,
}
