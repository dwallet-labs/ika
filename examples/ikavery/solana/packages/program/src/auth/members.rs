//! Helpers for the on-chain member-id slot layout.
//!
//! A slot is `[u8; MEMBER_SLOT_LEN]` (= 34) where `slot[0]` is the scheme tag
//! and `slot[1..id_len_for_scheme(slot[0])]` is the pubkey or address. Bytes
//! past the active id length are zero-padded. Active membership lives in a
//! `Vec<MemberSlot, MAX_MEMBERS>` whose length is the live member count.

use super::{id_len_for_scheme, MAX_MEMBER_ID_LEN, SCHEME_SOLANA_ADDRESS, SOLANA_ADDRESS_LEN};
use crate::auth;
use crate::error::IkaveryError;
use crate::state::{MemberSlot, MAX_MEMBERS, MEMBER_SLOT_LEN};
use quasar_lang::prelude::ProgramError;
use solana_address::Address;

const _: () = assert!(MEMBER_SLOT_LEN == MAX_MEMBER_ID_LEN);

/// Slice the active id out of a slot.
#[inline]
pub fn slot_id(slot: &MemberSlot) -> Result<&[u8], ProgramError> {
    let len = id_len_for_scheme(slot[0]).ok_or(IkaveryError::UnknownScheme)?;
    Ok(&slot[..len])
}

/// Find a member's index by canonical id. Returns `None` if absent.
pub fn find_index(members: &[MemberSlot], needle: &[u8]) -> Option<usize> {
    for (i, slot) in members.iter().enumerate() {
        if let Ok(id) = slot_id(slot) {
            if id == needle {
                return Some(i);
            }
        }
    }
    None
}

/// Build the canonical Solana-address member-id slot for `addr`.
pub fn solana_member_slot(addr: &Address) -> MemberSlot {
    let mut slot = [0u8; MEMBER_SLOT_LEN];
    slot[0] = SCHEME_SOLANA_ADDRESS;
    slot[1..1 + SOLANA_ADDRESS_LEN].copy_from_slice(addr.as_array().as_slice());
    slot
}

/// Build a canonical member-id slot from a `(scheme, pubkey)` pair as it
/// appears on the wire. `pubkey` is the contiguous 33-byte buffer the
/// instruction received; only the active prefix (length determined by
/// `scheme`) is copied into the slot, the rest stays zero-padded.
pub fn credential_slot(scheme: u8, pubkey: &[u8]) -> Result<MemberSlot, ProgramError> {
    let id_len = id_len_for_scheme(scheme).ok_or(IkaveryError::UnknownScheme)?;
    let key_len = id_len - 1;
    if pubkey.len() < key_len {
        return Err(IkaveryError::BadMemberLength.into());
    }
    let mut slot = [0u8; MEMBER_SLOT_LEN];
    slot[0] = scheme;
    slot[1..1 + key_len].copy_from_slice(&pubkey[..key_len]);
    Ok(slot)
}

/// Active pubkey slice inside a fixed-size 33-byte ix buffer for `scheme`.
pub fn pubkey_slice(scheme: u8, pubkey: &[u8]) -> Result<&[u8], ProgramError> {
    let id_len = id_len_for_scheme(scheme).ok_or(IkaveryError::UnknownScheme)?;
    let key_len = id_len - 1;
    if pubkey.len() < key_len {
        return Err(IkaveryError::BadMemberLength.into());
    }
    Ok(&pubkey[..key_len])
}

/// Validate that a slot's scheme tag is known and any bytes past the active
/// id are zeroed.
pub fn validate_slot(slot: &MemberSlot) -> Result<(), ProgramError> {
    let len = id_len_for_scheme(slot[0]).ok_or(IkaveryError::UnknownScheme)?;
    if len > MEMBER_SLOT_LEN {
        return Err(IkaveryError::BadMemberLength.into());
    }
    for &b in &slot[len..] {
        if b != 0 {
            return Err(IkaveryError::BadMemberLength.into());
        }
    }
    Ok(())
}

/// Validate every slot in a member list, reject duplicates, and ensure the
/// list is non-empty and within capacity.
pub fn validate_members(members: &[MemberSlot]) -> Result<(), ProgramError> {
    if members.is_empty() {
        return Err(IkaveryError::NoMembers.into());
    }
    if members.len() > MAX_MEMBERS {
        return Err(IkaveryError::TooManyMembers.into());
    }
    for slot in members {
        validate_slot(slot)?;
    }
    for (i, m_i) in members.iter().enumerate() {
        let id_i = slot_id(m_i)?;
        for m_j in members.iter().skip(i + 1) {
            let id_j = slot_id(m_j)?;
            if id_i == id_j {
                return Err(IkaveryError::DuplicateMember.into());
            }
        }
    }
    Ok(())
}

/// Compute the approver-only bitmap for a member list. Bit `i` is set when
/// the member at index `i` uses the Solana-address scheme.
pub fn bitmap_from_members(members: &[MemberSlot]) -> u16 {
    let mut bm = 0u16;
    for (i, slot) in members.iter().enumerate() {
        if slot[0] == auth::SCHEME_SOLANA_ADDRESS {
            bm |= 1u16 << (i as u16);
        }
    }
    bm
}
