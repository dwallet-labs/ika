//! Parser for Solana versioned `MessageV0` wire format.
//!
//! Wire format (per `solana-program/src/message/versions/v0/mod.rs`):
//! ```text
//!   1B   version-prefix (must be 0x80 for v0)
//!   1B   numRequiredSignatures
//!   1B   numReadonlySignedAccounts
//!   1B   numReadonlyUnsignedAccounts
//!   sv   staticAccountKeys.len, then N*32B
//!   32B  recentBlockhash
//!   sv   instructions.len, then per-instruction
//!   sv   addressTableLookups.len (must be 0; ALT is rejected)
//! ```
//!
//! ALT is rejected so every account referenced by an instruction
//! resolves through `account_keys` and the intent check sees the real
//! pubkeys.

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParseError {
    ShortvecOverflow,
    UnexpectedEof,
    InvalidVersion,
    AddressTableLookupsNotSupported,
    TrailingBytes,
    TooManyAccountKeys,
    TooManyInstructions,
}

pub const PUBKEY_LEN: usize = 32;
pub const BLOCKHASH_LEN: usize = 32;
pub const VERSION_V0_PREFIX: u8 = 0x80;

/// Per-instruction view borrowing into the original message bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ParsedInstruction<'a> {
    pub program_id_index: u8,
    pub account_indices: &'a [u8],
    pub data: &'a [u8],
}

/// View over a parsed Solana `MessageV0`. Borrows from the input bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ParsedMessage<'a> {
    raw: &'a [u8],
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    account_keys_off: usize,
    account_keys_count: u8,
    instructions_off: usize,
    instructions_count: u8,
}

impl<'a> ParsedMessage<'a> {
    pub fn account_keys_count(&self) -> u8 {
        self.account_keys_count
    }

    pub fn instructions_count(&self) -> u8 {
        self.instructions_count
    }

    /// MessageV0 always places the fee payer first in the static account keys.
    pub fn fee_payer(&self) -> &'a [u8; PUBKEY_LEN] {
        // Validated by `parse`: at least one account key is always present.
        self.account_at_index(0).expect("fee_payer always present")
    }

    pub fn account_at_index(&self, idx: u8) -> Option<&'a [u8; PUBKEY_LEN]> {
        if idx >= self.account_keys_count {
            return None;
        }
        let start = self.account_keys_off + (idx as usize) * PUBKEY_LEN;
        let end = start + PUBKEY_LEN;
        let slice = self.raw.get(start..end)?;
        let array: &'a [u8; PUBKEY_LEN] = <&[u8; PUBKEY_LEN]>::try_from(slice).ok()?;
        Some(array)
    }

    /// Resolves the program id (32-byte pubkey) for an instruction.
    pub fn program_id(&self, ix: &ParsedInstruction<'a>) -> Option<&'a [u8; PUBKEY_LEN]> {
        self.account_at_index(ix.program_id_index)
    }

    /// Resolves `account_indices[idx]` to its 32-byte pubkey.
    pub fn account_at(
        &self,
        ix: &ParsedInstruction<'a>,
        idx: usize,
    ) -> Option<&'a [u8; PUBKEY_LEN]> {
        let key_idx = *ix.account_indices.get(idx)?;
        self.account_at_index(key_idx)
    }

    pub fn instructions(&self) -> InstructionIter<'a> {
        InstructionIter {
            raw: self.raw,
            cursor: self.instructions_off,
            remaining: self.instructions_count,
        }
    }
}

/// Streaming iterator over instructions in the wire buffer. Re-decodes each
/// `ParsedInstruction` on demand by walking from the saved offset.
#[derive(Debug, Clone)]
pub struct InstructionIter<'a> {
    raw: &'a [u8],
    cursor: usize,
    remaining: u8,
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = Result<ParsedInstruction<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(read_instruction(self.raw, &mut self.cursor))
    }
}

fn read_instruction<'a>(
    raw: &'a [u8],
    off: &mut usize,
) -> Result<ParsedInstruction<'a>, ParseError> {
    let program_id_index = read_u8(raw, off)?;

    let acc_count = read_compact_u16(raw, off)? as usize;
    let acc_start = *off;
    let acc_end = acc_start
        .checked_add(acc_count)
        .ok_or(ParseError::UnexpectedEof)?;
    if acc_end > raw.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let account_indices = &raw[acc_start..acc_end];
    *off = acc_end;

    let data_len = read_compact_u16(raw, off)? as usize;
    let data_start = *off;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(ParseError::UnexpectedEof)?;
    if data_end > raw.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let data = &raw[data_start..data_end];
    *off = data_end;

    Ok(ParsedInstruction {
        program_id_index,
        account_indices,
        data,
    })
}

pub fn parse(bytes: &[u8]) -> Result<ParsedMessage<'_>, ParseError> {
    let mut off: usize = 0;

    let version = read_u8(bytes, &mut off)?;
    if version != VERSION_V0_PREFIX {
        return Err(ParseError::InvalidVersion);
    }
    let num_required_signatures = read_u8(bytes, &mut off)?;
    let num_readonly_signed = read_u8(bytes, &mut off)?;
    let num_readonly_unsigned = read_u8(bytes, &mut off)?;

    let key_count = read_compact_u16(bytes, &mut off)?;
    if key_count > u8::MAX as u16 {
        return Err(ParseError::TooManyAccountKeys);
    }
    if key_count == 0 {
        return Err(ParseError::UnexpectedEof);
    }
    let account_keys_off = off;
    let account_keys_bytes = (key_count as usize)
        .checked_mul(PUBKEY_LEN)
        .ok_or(ParseError::UnexpectedEof)?;
    off = off
        .checked_add(account_keys_bytes)
        .ok_or(ParseError::UnexpectedEof)?;
    if off > bytes.len() {
        return Err(ParseError::UnexpectedEof);
    }

    // Recent blockhash — read and discarded; intent must be blockhash-independent.
    off = off
        .checked_add(BLOCKHASH_LEN)
        .ok_or(ParseError::UnexpectedEof)?;
    if off > bytes.len() {
        return Err(ParseError::UnexpectedEof);
    }

    let ix_count = read_compact_u16(bytes, &mut off)?;
    if ix_count > u8::MAX as u16 {
        return Err(ParseError::TooManyInstructions);
    }
    let instructions_off = off;

    // Walk the instruction list once to validate framing and find the
    // trailing lookup-count byte. We don't keep the iterator's state.
    {
        let mut tmp = off;
        for _ in 0..ix_count {
            let _ix = read_instruction(bytes, &mut tmp)?;
        }
        off = tmp;
    }

    let lookup_count = read_compact_u16(bytes, &mut off)?;
    if lookup_count != 0 {
        return Err(ParseError::AddressTableLookupsNotSupported);
    }

    if off != bytes.len() {
        return Err(ParseError::TrailingBytes);
    }

    Ok(ParsedMessage {
        raw: bytes,
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        account_keys_off,
        account_keys_count: key_count as u8,
        instructions_off,
        instructions_count: ix_count as u8,
    })
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, ParseError> {
    let i = *off;
    if i >= bytes.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let v = bytes[i];
    *off = i + 1;
    Ok(v)
}

/// Solana shortvec / compact-u16: up to 3 bytes, 7 data bits each, MSB
/// is continuation. Bounded at `0xffff`; rejects a 4th continuation byte.
fn read_compact_u16(bytes: &[u8], off: &mut usize) -> Result<u16, ParseError> {
    let mut value: u32 = 0;
    let mut shift: u8 = 0;
    let mut count: u8 = 0;
    loop {
        if count >= 3 {
            return Err(ParseError::ShortvecOverflow);
        }
        let byte = read_u8(bytes, off)?;
        let low = (byte & 0x7f) as u32;
        value |= low << shift;
        count += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if value > 0xffff {
        return Err(ParseError::ShortvecOverflow);
    }
    Ok(value as u16)
}

pub fn read_u32_le(data: &[u8], off: usize) -> Result<u32, ParseError> {
    let end = off.checked_add(4).ok_or(ParseError::UnexpectedEof)?;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

pub fn read_u64_le(data: &[u8], off: usize) -> Result<u64, ParseError> {
    let end = off.checked_add(8).ok_or(ParseError::UnexpectedEof)?;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[off..end]);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Real `MessageV0` produced by `@solana/web3.js`'s `TransactionMessage`
    /// with a single `SystemProgram::Transfer(100 lamports)` from a synthetic
    /// `from` account to `to`. Identical to the Sui test fixture.
    const TRANSFER_FIXTURE: &[u8] = &[
        // version v0
        0x80, // header
        0x01, 0x00, 0x01, // 3 account keys (shortvec count = 3)
        0x03, // account[0] = from
        0x58, 0xb2, 0xb4, 0x06, 0xdb, 0xfb, 0x8a, 0x70, 0xba, 0xf0, 0xb1, 0x85, 0x30, 0x3e, 0xfb,
        0xf4, 0x1c, 0xab, 0xb7, 0x0a, 0x83, 0x9f, 0x1e, 0xff, 0xee, 0x31, 0x33, 0x3c, 0x6f, 0xb0,
        0xd9, 0x90, // account[1] = to
        0xb6, 0x55, 0xba, 0x30, 0x4a, 0xc0, 0xa4, 0x54, 0x46, 0xdb, 0xf9, 0x60, 0x97, 0xc6, 0x94,
        0xc6, 0x59, 0x1e, 0xd0, 0xd4, 0x84, 0x95, 0xfd, 0x18, 0x49, 0x69, 0x28, 0xd8, 0x97, 0x75,
        0x29, 0x9c, // account[2] = SystemProgram (zero pubkey)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // recent blockhash (placeholder 0x33...)
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, // 1 instruction
        0x01, // program_id_index = 2 (SystemProgram)
        0x02, // ix accounts shortvec count = 2, then [0, 1]
        0x02, 0x00, 0x01,
        // data length = 12, then Transfer(100 lamports): u32 LE 2 | u64 LE 100
        0x0c, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0 lookups
        0x00,
    ];

    const FROM_PUBKEY: [u8; 32] = [
        0x58, 0xb2, 0xb4, 0x06, 0xdb, 0xfb, 0x8a, 0x70, 0xba, 0xf0, 0xb1, 0x85, 0x30, 0x3e, 0xfb,
        0xf4, 0x1c, 0xab, 0xb7, 0x0a, 0x83, 0x9f, 0x1e, 0xff, 0xee, 0x31, 0x33, 0x3c, 0x6f, 0xb0,
        0xd9, 0x90,
    ];
    const TO_PUBKEY: [u8; 32] = [
        0xb6, 0x55, 0xba, 0x30, 0x4a, 0xc0, 0xa4, 0x54, 0x46, 0xdb, 0xf9, 0x60, 0x97, 0xc6, 0x94,
        0xc6, 0x59, 0x1e, 0xd0, 0xd4, 0x84, 0x95, 0xfd, 0x18, 0x49, 0x69, 0x28, 0xd8, 0x97, 0x75,
        0x29, 0x9c,
    ];
    const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];

    fn collect_instructions<'a>(parsed: &ParsedMessage<'a>) -> Vec<ParsedInstruction<'a>> {
        parsed
            .instructions()
            .map(|r| r.expect("valid ix"))
            .collect()
    }

    #[test]
    fn parse_real_transfer_fixture() {
        let parsed = parse(TRANSFER_FIXTURE).unwrap();
        assert_eq!(parsed.num_required_signatures, 1);

        assert_eq!(parsed.account_keys_count(), 3);
        assert_eq!(parsed.account_at_index(0).unwrap(), &FROM_PUBKEY);
        assert_eq!(parsed.account_at_index(1).unwrap(), &TO_PUBKEY);
        assert_eq!(parsed.account_at_index(2).unwrap(), &SYSTEM_PROGRAM);

        let ixs = collect_instructions(&parsed);
        assert_eq!(ixs.len(), 1);
        let ix = &ixs[0];
        assert_eq!(ix.program_id_index, 2);
        assert_eq!(ix.account_indices, &[0u8, 1u8]);
        assert_eq!(ix.data.len(), 12);
        assert_eq!(read_u32_le(ix.data, 0).unwrap(), 2);
        assert_eq!(read_u64_le(ix.data, 4).unwrap(), 100);

        assert_eq!(parsed.fee_payer(), &FROM_PUBKEY);
        assert_eq!(parsed.program_id(ix).unwrap(), &SYSTEM_PROGRAM);
        assert_eq!(parsed.account_at(ix, 0).unwrap(), &FROM_PUBKEY);
        assert_eq!(parsed.account_at(ix, 1).unwrap(), &TO_PUBKEY);
    }

    #[test]
    fn read_u64_le_zero() {
        let data = [0u8; 8];
        assert_eq!(read_u64_le(&data, 0).unwrap(), 0);
    }

    #[test]
    fn read_u64_le_max() {
        let data = [0xffu8; 8];
        assert_eq!(read_u64_le(&data, 0).unwrap(), 0xffffffffffffffff);
    }

    #[test]
    fn read_u32_le_arbitrary() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 0x04030201);
    }

    #[test]
    fn reject_legacy_version() {
        let bytes = [0x01u8];
        assert_eq!(parse(&bytes), Err(ParseError::InvalidVersion));
    }

    #[test]
    fn reject_address_table_lookups() {
        let mut bytes = TRANSFER_FIXTURE.to_vec();
        bytes.pop();
        bytes.extend_from_slice(&[
            0x01, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            0xee, 0xee, 0xee, 0xee, 0xee, 0x00, 0x00,
        ]);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::AddressTableLookupsNotSupported)
        );
    }

    #[test]
    fn reject_truncated_message() {
        let bytes = [0x80u8];
        assert_eq!(parse(&bytes), Err(ParseError::UnexpectedEof));
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut bytes = TRANSFER_FIXTURE.to_vec();
        bytes.push(0xff);
        assert_eq!(parse(&bytes), Err(ParseError::TrailingBytes));
    }

    #[test]
    fn reject_shortvec_overflow() {
        let bytes = [0x80, 0x01, 0x00, 0x01, 0x80, 0x80, 0x80, 0x80];
        assert_eq!(parse(&bytes), Err(ParseError::ShortvecOverflow));
    }
}
