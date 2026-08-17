//! Inspect Solana's signature-verification precompile invocations.
//!
//! Solana ships three "precompile" programs that verify signatures the
//! runtime invokes for free as part of the transaction:
//!   * `Ed25519SigVerify…`  — Ed25519 (32-byte pubkey, 64-byte signature)
//!   * `Secp256r1SigVerify…` — Secp256r1 / NIST P-256 (33-byte compressed
//!     pubkey, 64-byte raw r||s signature) — the same curve passkeys use
//!   * `KeccakSecp256k1…`   — Secp256k1 with ETH-style 20-byte address
//!     recovery (not used here; see [`crate::auth`] for why)
//!
//! Each precompile takes a header that points at byte ranges inside its
//! own instruction data (or any other instruction in the same tx). The
//! runtime executes the precompile before the program runs; if the
//! precompile fails the whole tx aborts. So by the time we read the
//! Instructions sysvar inside a recovery instruction, every precompile
//! invocation we see *has already passed verification*. All we need to
//! do is locate the matching precompile invocation, prove it covered the
//! pubkey + message we expect, and trust the runtime did the rest.
//!
//! We require precompile invocations to be self-contained (signature,
//! pubkey, and message all live inside the precompile's own data) — a
//! sentinel `instruction_index = 0xFFFF` in the offsets struct means
//! "use my own data", which is what Solana's own `new_ed25519_instruction`
//! / `new_secp256r1_instruction` builders emit. Cross-instruction layouts
//! exist for power users but pull in surface area we don't need.

use solana_address::Address;

/// Sysvar account that exposes the current transaction's serialised
/// instruction list to programs that need to introspect it.
pub const INSTRUCTIONS_SYSVAR_ID: Address =
    Address::from_str_const("Sysvar1nstructions1111111111111111111111111");

/// Native Ed25519 signature precompile.
pub const ED25519_PRECOMPILE_ID: Address =
    Address::from_str_const("Ed25519SigVerify111111111111111111111111111");

/// Native Secp256r1 signature precompile (passkeys / WebAuthn).
pub const SECP256R1_PRECOMPILE_ID: Address =
    Address::from_str_const("Secp256r1SigVerify1111111111111111111111111");

/// Sentinel that the offsets-table entry refers to data inside the
/// precompile's own instruction.
const SAME_INSTRUCTION: u16 = 0xFFFF;

/// Per-signature offset record emitted by the Ed25519 / Secp256r1
/// precompile builders. Layout matches Solana's `Ed25519SignatureOffsets`
/// and `Secp256r1SignatureOffsets` byte-for-byte.
const OFFSETS_LEN: usize = 14;

/// Errors that can fire while walking the instructions sysvar looking
/// for a matching precompile invocation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrecompileError {
    /// Sysvar account address didn't match `Sysvar1nstructions…`.
    NotInstructionsSysvar,
    /// Bytes were truncated mid-record while parsing the sysvar.
    Malformed,
    /// An offsets entry referenced data in a different instruction; we
    /// require self-contained precompile data for now.
    CrossInstructionUnsupported,
    /// No precompile invocation in the tx matched the requested
    /// (scheme, pubkey, message) triple.
    NoMatchingInvocation,
}

/// Read a little-endian `u16` at `off` and bump `*off` by 2. `None` if
/// the read would run past the buffer.
#[inline]
fn read_u16_le(data: &[u8], off: &mut usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    if end > data.len() {
        return None;
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off = end;
    Some(v)
}

/// Pull a fixed-length slice and bump `*off`. `None` on overrun.
#[inline]
fn read_slice<'a>(data: &'a [u8], off: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = off.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let s = &data[*off..end];
    *off = end;
    Some(s)
}

/// Decoded reference to one signature record inside a precompile's
/// data buffer. Lifetimes tie back to the sysvar borrow.
#[derive(Debug, Copy, Clone)]
pub struct PrecompileRecord<'a> {
    pub signature: &'a [u8],
    pub public_key: &'a [u8],
    pub message: &'a [u8],
}

/// Pull the i-th signature record out of an Ed25519/Secp256r1 precompile
/// invocation's data buffer. `pubkey_len` differs by curve (32 for
/// Ed25519, 33 for Secp256r1).
fn parse_record<'a>(
    precompile_data: &'a [u8],
    record_index: usize,
    pubkey_len: usize,
    signature_len: usize,
) -> Result<PrecompileRecord<'a>, PrecompileError> {
    if precompile_data.len() < 2 {
        return Err(PrecompileError::Malformed);
    }
    let num_records = precompile_data[0] as usize;
    if record_index >= num_records {
        return Err(PrecompileError::Malformed);
    }
    // Header: 1-byte count, 1-byte padding, then 14 bytes per record.
    let offsets_start = 2usize
        .checked_add(
            record_index
                .checked_mul(OFFSETS_LEN)
                .ok_or(PrecompileError::Malformed)?,
        )
        .ok_or(PrecompileError::Malformed)?;
    if offsets_start + OFFSETS_LEN > precompile_data.len() {
        return Err(PrecompileError::Malformed);
    }
    let mut p = offsets_start;
    let signature_offset =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let signature_instruction_index =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let public_key_offset =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let public_key_instruction_index =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let message_data_offset =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let message_data_size =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;
    let message_instruction_index =
        read_u16_le(precompile_data, &mut p).ok_or(PrecompileError::Malformed)?;

    if signature_instruction_index != SAME_INSTRUCTION
        || public_key_instruction_index != SAME_INSTRUCTION
        || message_instruction_index != SAME_INSTRUCTION
    {
        return Err(PrecompileError::CrossInstructionUnsupported);
    }

    let sig_end = (signature_offset as usize)
        .checked_add(signature_len)
        .ok_or(PrecompileError::Malformed)?;
    let pk_end = (public_key_offset as usize)
        .checked_add(pubkey_len)
        .ok_or(PrecompileError::Malformed)?;
    let msg_end = (message_data_offset as usize)
        .checked_add(message_data_size as usize)
        .ok_or(PrecompileError::Malformed)?;
    if sig_end > precompile_data.len()
        || pk_end > precompile_data.len()
        || msg_end > precompile_data.len()
    {
        return Err(PrecompileError::Malformed);
    }

    Ok(PrecompileRecord {
        signature: &precompile_data[signature_offset as usize..sig_end],
        public_key: &precompile_data[public_key_offset as usize..pk_end],
        message: &precompile_data[message_data_offset as usize..msg_end],
    })
}

/// Walk every precompile invocation in the tx (matching `expected_program`)
/// and hand each signature record to `predicate`. Returns the first record
/// for which `predicate` returns `true`.
///
/// The sysvar layout is documented in Solana's `solana-instructions-sysvar`
/// crate; we re-implement the parse here to stay zero-alloc / `no_std`
/// and to read directly out of the Quasar `AccountView` borrow.
pub fn find_verified<'a>(
    sysvar_data: &'a [u8],
    expected_program: &Address,
    pubkey_len: usize,
    signature_len: usize,
    mut predicate: impl FnMut(&PrecompileRecord<'a>) -> bool,
) -> Result<PrecompileRecord<'a>, PrecompileError> {
    let mut cur = 0usize;
    let n = read_u16_le(sysvar_data, &mut cur).ok_or(PrecompileError::Malformed)? as usize;

    for i in 0..n {
        let mut idx_cur = 2usize
            .checked_add(i.checked_mul(2).ok_or(PrecompileError::Malformed)?)
            .ok_or(PrecompileError::Malformed)?;
        let inst_off =
            read_u16_le(sysvar_data, &mut idx_cur).ok_or(PrecompileError::Malformed)? as usize;

        let mut p = inst_off;
        let num_accounts =
            read_u16_le(sysvar_data, &mut p).ok_or(PrecompileError::Malformed)? as usize;
        let metas_len = num_accounts
            .checked_mul(33)
            .ok_or(PrecompileError::Malformed)?;
        p = p.checked_add(metas_len).ok_or(PrecompileError::Malformed)?;

        let program_id_bytes =
            read_slice(sysvar_data, &mut p, 32).ok_or(PrecompileError::Malformed)?;
        let mut prog_arr = [0u8; 32];
        prog_arr.copy_from_slice(program_id_bytes);
        let program_id = Address::new_from_array(prog_arr);

        let data_len = read_u16_le(sysvar_data, &mut p).ok_or(PrecompileError::Malformed)? as usize;
        let data = read_slice(sysvar_data, &mut p, data_len).ok_or(PrecompileError::Malformed)?;

        if &program_id != expected_program || data.is_empty() {
            continue;
        }
        let num_records = data[0] as usize;
        for r in 0..num_records {
            if let Ok(rec) = parse_record(data, r, pubkey_len, signature_len) {
                if predicate(&rec) {
                    return Ok(rec);
                }
            }
        }
    }
    Err(PrecompileError::NoMatchingInvocation)
}

/// Confirm the Instructions-sysvar account address is canonical. Mirrors
/// the check `solana-instructions-sysvar::load_*_checked` does in stock
/// Solana programs.
#[inline]
pub fn check_sysvar_address(addr: &Address) -> Result<(), PrecompileError> {
    if addr == &INSTRUCTIONS_SYSVAR_ID {
        Ok(())
    } else {
        Err(PrecompileError::NotInstructionsSysvar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    /// Hand-roll a tx-instructions sysvar buffer from a single precompile
    /// invocation. Mirrors what the Solana runtime would emit before the
    /// program's instruction runs.
    fn build_sysvar_with_precompile(program_id: &Address, precompile_data: &[u8]) -> Vec<u8> {
        // Header: num_instructions (1) + 1 offset entry (u16 LE).
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&1u16.to_le_bytes());
        // We'll backfill the offset after we know it.
        let offset_pos = out.len();
        out.extend_from_slice(&0u16.to_le_bytes());
        // Optional: slot for the current-instruction-index trailer
        // is at the very end; runtime writes it in. Leave a placeholder.
        let inst_start = out.len();
        out[offset_pos..offset_pos + 2].copy_from_slice(&(inst_start as u16).to_le_bytes());

        // Instruction body: num_accounts(0) || program_id(32) || data_len(u16) || data.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(program_id.as_array());
        out.extend_from_slice(&(precompile_data.len() as u16).to_le_bytes());
        out.extend_from_slice(precompile_data);

        // Two trailing bytes for current_instruction_index (zero is fine).
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    /// Build a single-record Ed25519/Secp256r1 precompile data buffer.
    /// `signature_len` is 64 for both; `pubkey_len` is 32 (Ed25519) or
    /// 33 (Secp256r1).
    fn build_precompile_data(signature: &[u8], public_key: &[u8], message: &[u8]) -> Vec<u8> {
        // Header (count, padding) + 1 offsets record + raw bytes.
        let mut out: Vec<u8> = vec![1u8, 0u8];
        out.extend_from_slice(&[0u8; OFFSETS_LEN]); // placeholder, fill below

        let signature_offset = out.len() as u16;
        out.extend_from_slice(signature);
        let public_key_offset = out.len() as u16;
        out.extend_from_slice(public_key);
        let message_data_offset = out.len() as u16;
        out.extend_from_slice(message);

        // Backfill the offsets record.
        let mut p = 2usize;
        out[p..p + 2].copy_from_slice(&signature_offset.to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION.to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&public_key_offset.to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION.to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&message_data_offset.to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&(message.len() as u16).to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&SAME_INSTRUCTION.to_le_bytes());

        out
    }

    #[test]
    fn finds_ed25519_record_in_synthetic_sysvar() {
        let sig = [0xaau8; 64];
        let pk = [0xbbu8; 32];
        let msg = [0xccu8; 32];
        let pdata = build_precompile_data(&sig, &pk, &msg);
        let sysvar = build_sysvar_with_precompile(&ED25519_PRECOMPILE_ID, &pdata);

        let rec = find_verified(&sysvar, &ED25519_PRECOMPILE_ID, 32, 64, |r| {
            r.public_key == pk.as_slice() && r.message == msg.as_slice()
        })
        .unwrap();
        assert_eq!(rec.signature, sig.as_slice());
    }

    #[test]
    fn finds_secp256r1_record_with_33_byte_pubkey() {
        let sig = [0x11u8; 64];
        let pk = [0x22u8; 33];
        let msg = [0x33u8; 16];
        let pdata = build_precompile_data(&sig, &pk, &msg);
        let sysvar = build_sysvar_with_precompile(&SECP256R1_PRECOMPILE_ID, &pdata);

        let rec = find_verified(&sysvar, &SECP256R1_PRECOMPILE_ID, 33, 64, |r| {
            r.public_key == pk.as_slice()
        })
        .unwrap();
        assert_eq!(rec.message, msg.as_slice());
    }

    #[test]
    fn rejects_unmatched_predicate() {
        let sig = [0x11u8; 64];
        let pk = [0x22u8; 33];
        let msg = [0x33u8; 16];
        let pdata = build_precompile_data(&sig, &pk, &msg);
        let sysvar = build_sysvar_with_precompile(&SECP256R1_PRECOMPILE_ID, &pdata);
        let other_pk = [0x44u8; 33];

        let err = find_verified(&sysvar, &SECP256R1_PRECOMPILE_ID, 33, 64, |r| {
            r.public_key == other_pk.as_slice()
        })
        .unwrap_err();
        assert_eq!(err, PrecompileError::NoMatchingInvocation);
    }

    #[test]
    fn rejects_wrong_program_id() {
        let pdata = build_precompile_data(&[0u8; 64], &[0u8; 32], &[0u8; 16]);
        let sysvar = build_sysvar_with_precompile(&ED25519_PRECOMPILE_ID, &pdata);

        let err = find_verified(&sysvar, &SECP256R1_PRECOMPILE_ID, 33, 64, |_| true).unwrap_err();
        assert_eq!(err, PrecompileError::NoMatchingInvocation);
    }

    #[test]
    fn rejects_cross_instruction_sentinel() {
        // Build a precompile data buffer that points its message at
        // instruction-index 0 instead of 0xFFFF — we intentionally
        // don't support that path.
        let mut pdata: Vec<u8> = vec![1u8, 0u8];
        pdata.extend_from_slice(&[0u8; OFFSETS_LEN]);
        let sig_off = pdata.len() as u16;
        pdata.extend_from_slice(&[0u8; 64]);
        let pk_off = pdata.len() as u16;
        pdata.extend_from_slice(&[0u8; 32]);
        let msg_off = pdata.len() as u16;
        pdata.extend_from_slice(&[0u8; 16]);

        let mut p = 2usize;
        pdata[p..p + 2].copy_from_slice(&sig_off.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&SAME_INSTRUCTION.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&pk_off.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&SAME_INSTRUCTION.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&msg_off.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&16u16.to_le_bytes());
        p += 2;
        pdata[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // cross-ix index 0

        let sysvar = build_sysvar_with_precompile(&ED25519_PRECOMPILE_ID, &pdata);
        let err = find_verified(&sysvar, &ED25519_PRECOMPILE_ID, 32, 64, |_| true).unwrap_err();
        // The error surfaces as NoMatchingInvocation because parse_record
        // failed and we kept walking; that's OK — caller treats either
        // as "not present".
        assert_eq!(err, PrecompileError::NoMatchingInvocation);
    }

    #[test]
    fn check_sysvar_address_accepts_canonical_id() {
        assert!(check_sysvar_address(&INSTRUCTIONS_SYSVAR_ID).is_ok());
        let bogus = Address::new_from_array([1u8; 32]);
        assert_eq!(
            check_sysvar_address(&bogus),
            Err(PrecompileError::NotInstructionsSysvar)
        );
    }
}
