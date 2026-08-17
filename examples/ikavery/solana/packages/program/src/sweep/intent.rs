//! Structural intent of a Solana sweep transaction.
//!
//! On-chain: [`hash_message_bytes`] parses the message and emits the BCS
//! encoding of `vec![SweepIntent { fee_payer, ixs }]` into a fixed-size
//! buffer, then Keccak-256s it. Compute-budget instructions are excluded
//! from the intent so the executor can refresh them.
//!
//! Host (gated `cfg(not(target_os = "solana"))`): [`SweepIntent`] /
//! [`SweepIxIntent`] reference shapes used by the SDK. The
//! `host_bcs_matches_handrolled_bcs` and `on_chain_digest_matches_host`
//! tests pin both encoders against `bcs::to_bytes` and against each
//! other so they cannot diverge.

use solana_keccak_hasher::hashv;

use super::solana_msg::{self, ParseError, ParsedInstruction, ParsedMessage, PUBKEY_LEN};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IntentError {
    Parse(ParseError),
    UnknownProgram,
    UnknownInstruction,
    NotEnoughAccounts,
    BadInstructionData,
    BcsSerialize,
    IntentBufferOverflow,
}

impl From<ParseError> for IntentError {
    fn from(e: ParseError) -> Self {
        IntentError::Parse(e)
    }
}

// Program ids (32-byte pubkeys).
/// `11111111111111111111111111111111`
pub const SYSTEM_PROGRAM_ID: [u8; PUBKEY_LEN] = [0u8; PUBKEY_LEN];
/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
pub const TOKEN_PROGRAM_ID: [u8; PUBKEY_LEN] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];
/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022_PROGRAM_ID: [u8; PUBKEY_LEN] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];
/// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
pub const ATA_PROGRAM_ID: [u8; PUBKEY_LEN] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];
/// `ComputeBudget111111111111111111111111111111`
pub const COMPUTE_BUDGET_PROGRAM_ID: [u8; PUBKEY_LEN] = [
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
];

/// SystemProgram instruction tag (u32 LE) — `Transfer` = 2.
pub const SYSTEM_IX_TRANSFER: u32 = 2;
/// SPL Token / Token-2022 instruction discriminators (u8).
pub const SPL_IX_TRANSFER_CHECKED: u8 = 12;
pub const SPL_IX_CLOSE_ACCOUNT: u8 = 9;
/// Associated Token Account program — `CreateIdempotent` = 1.
pub const ATA_IX_CREATE_IDEMPOTENT: u8 = 1;

/// Upper bound on BCS-encoded intent bytes for a single `SweepIntent`.
pub const MAX_INTENT_BCS_BYTES: usize = 2048;

/// Equivalent to `hash_intents(&[from_message_bytes(message_bytes)?])`.
pub fn hash_message_bytes(message_bytes: &[u8]) -> Result<[u8; 32], IntentError> {
    let parsed = solana_msg::parse(message_bytes)?;

    let mut buf = [0u8; MAX_INTENT_BCS_BYTES];
    let mut cur = Cursor::new(&mut buf);

    // Outer Vec<SweepIntent> length = 1.
    write_uleb128(&mut cur, 1)?;

    // SweepIntent.fee_payer (Vec<u8> in BCS = uleb128 length + bytes).
    write_bcs_bytes(&mut cur, parsed.fee_payer())?;

    // SweepIntent.ixs (Vec<SweepIxIntent>) — emit count, then each variant.
    let mut whitelisted_count = 0u32;
    for ix in parsed.instructions() {
        let ix = ix?;
        let pid = parsed
            .program_id(&ix)
            .ok_or(IntentError::Parse(ParseError::UnexpectedEof))?;
        if pid != &COMPUTE_BUDGET_PROGRAM_ID {
            whitelisted_count += 1;
        }
    }
    write_uleb128(&mut cur, whitelisted_count as usize)?;

    for ix in parsed.instructions() {
        let ix = ix?;
        let pid = parsed
            .program_id(&ix)
            .ok_or(IntentError::Parse(ParseError::UnexpectedEof))?;
        if pid == &COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        } else if pid == &SYSTEM_PROGRAM_ID {
            encode_system_transfer(&parsed, &ix, &mut cur)?;
        } else if pid == &TOKEN_PROGRAM_ID || pid == &TOKEN_2022_PROGRAM_ID {
            encode_token_ix(&parsed, &ix, pid, &mut cur)?;
        } else if pid == &ATA_PROGRAM_ID {
            encode_ata_create_idempotent(&parsed, &ix, &mut cur)?;
        } else {
            return Err(IntentError::UnknownProgram);
        }
    }

    let len = cur.pos();
    Ok(hashv(&[&buf[..len]]).to_bytes())
}

fn encode_system_transfer(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
    cur: &mut Cursor,
) -> Result<(), IntentError> {
    if ix.data.len() < 12 {
        return Err(IntentError::BadInstructionData);
    }
    let tag = solana_msg::read_u32_le(ix.data, 0)?;
    if tag != SYSTEM_IX_TRANSFER {
        return Err(IntentError::UnknownInstruction);
    }
    let lamports = solana_msg::read_u64_le(ix.data, 4)?;
    let from = msg
        .account_at(ix, 0)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let to = msg
        .account_at(ix, 1)
        .ok_or(IntentError::NotEnoughAccounts)?;

    write_uleb128(cur, 0)?; // SystemTransfer variant
    write_bcs_bytes(cur, from)?;
    write_bcs_bytes(cur, to)?;
    write_u64_le(cur, lamports)
}

fn encode_token_ix(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
    program_id: &[u8; PUBKEY_LEN],
    cur: &mut Cursor,
) -> Result<(), IntentError> {
    if ix.data.is_empty() {
        return Err(IntentError::BadInstructionData);
    }
    let disc = ix.data[0];
    if disc == SPL_IX_TRANSFER_CHECKED {
        if ix.data.len() < 10 {
            return Err(IntentError::BadInstructionData);
        }
        let amount = solana_msg::read_u64_le(ix.data, 1)?;
        let decimals = ix.data[9];
        let source = msg
            .account_at(ix, 0)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let mint = msg
            .account_at(ix, 1)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let destination = msg
            .account_at(ix, 2)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let authority = msg
            .account_at(ix, 3)
            .ok_or(IntentError::NotEnoughAccounts)?;

        write_uleb128(cur, 1)?; // SplTransferChecked variant
        write_bcs_bytes(cur, program_id)?;
        write_bcs_bytes(cur, source)?;
        write_bcs_bytes(cur, mint)?;
        write_bcs_bytes(cur, destination)?;
        write_bcs_bytes(cur, authority)?;
        write_u64_le(cur, amount)?;
        write_u8(cur, decimals)
    } else if disc == SPL_IX_CLOSE_ACCOUNT {
        let account = msg
            .account_at(ix, 0)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let destination = msg
            .account_at(ix, 1)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let authority = msg
            .account_at(ix, 2)
            .ok_or(IntentError::NotEnoughAccounts)?;

        write_uleb128(cur, 3)?; // SplCloseAccount variant
        write_bcs_bytes(cur, program_id)?;
        write_bcs_bytes(cur, account)?;
        write_bcs_bytes(cur, destination)?;
        write_bcs_bytes(cur, authority)
    } else {
        Err(IntentError::UnknownInstruction)
    }
}

fn encode_ata_create_idempotent(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
    cur: &mut Cursor,
) -> Result<(), IntentError> {
    if ix.data.len() != 1 {
        return Err(IntentError::BadInstructionData);
    }
    if ix.data[0] != ATA_IX_CREATE_IDEMPOTENT {
        return Err(IntentError::UnknownInstruction);
    }
    let payer = msg
        .account_at(ix, 0)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let ata = msg
        .account_at(ix, 1)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let owner = msg
        .account_at(ix, 2)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let mint = msg
        .account_at(ix, 3)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let token_program = msg
        .account_at(ix, 5)
        .ok_or(IntentError::NotEnoughAccounts)?;

    write_uleb128(cur, 2)?; // AtaCreateIdempotent variant
    write_bcs_bytes(cur, token_program)?;
    write_bcs_bytes(cur, payer)?;
    write_bcs_bytes(cur, ata)?;
    write_bcs_bytes(cur, owner)?;
    write_bcs_bytes(cur, mint)
}

struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), IntentError> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(IntentError::IntentBufferOverflow)?;
        if end > self.buf.len() {
            return Err(IntentError::IntentBufferOverflow);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
}

fn write_uleb128(cur: &mut Cursor, value: usize) -> Result<(), IntentError> {
    let mut x = value as u64;
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while x >= 0x80 {
        tmp[len] = ((x & 0x7f) | 0x80) as u8;
        len += 1;
        x >>= 7;
    }
    tmp[len] = x as u8;
    len += 1;
    cur.write(&tmp[..len])
}

fn write_bcs_bytes(cur: &mut Cursor, bytes: &[u8]) -> Result<(), IntentError> {
    write_uleb128(cur, bytes.len())?;
    cur.write(bytes)
}

fn write_u64_le(cur: &mut Cursor, value: u64) -> Result<(), IntentError> {
    cur.write(&value.to_le_bytes())
}

fn write_u8(cur: &mut Cursor, value: u8) -> Result<(), IntentError> {
    cur.write(&[value])
}

#[cfg(not(target_os = "solana"))]
extern crate alloc;
#[cfg(not(target_os = "solana"))]
use alloc::vec::Vec;

#[cfg(not(target_os = "solana"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepIxIntent {
    SystemTransfer {
        from: Vec<u8>,
        to: Vec<u8>,
        lamports: u64,
    },
    SplTransferChecked {
        program_id: Vec<u8>,
        source: Vec<u8>,
        mint: Vec<u8>,
        destination: Vec<u8>,
        authority: Vec<u8>,
        amount: u64,
        decimals: u8,
    },
    AtaCreateIdempotent {
        token_program: Vec<u8>,
        payer: Vec<u8>,
        ata: Vec<u8>,
        owner: Vec<u8>,
        mint: Vec<u8>,
    },
    SplCloseAccount {
        program_id: Vec<u8>,
        account: Vec<u8>,
        destination: Vec<u8>,
        authority: Vec<u8>,
    },
}

#[cfg(all(test, not(target_os = "solana")))]
mod host_bcs {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SweepIxIntentSerde {
        SystemTransfer {
            from: Vec<u8>,
            to: Vec<u8>,
            lamports: u64,
        },
        SplTransferChecked {
            program_id: Vec<u8>,
            source: Vec<u8>,
            mint: Vec<u8>,
            destination: Vec<u8>,
            authority: Vec<u8>,
            amount: u64,
            decimals: u8,
        },
        AtaCreateIdempotent {
            token_program: Vec<u8>,
            payer: Vec<u8>,
            ata: Vec<u8>,
            owner: Vec<u8>,
            mint: Vec<u8>,
        },
        SplCloseAccount {
            program_id: Vec<u8>,
            account: Vec<u8>,
            destination: Vec<u8>,
            authority: Vec<u8>,
        },
    }

    impl From<&SweepIxIntent> for SweepIxIntentSerde {
        fn from(v: &SweepIxIntent) -> Self {
            match v {
                SweepIxIntent::SystemTransfer { from, to, lamports } => {
                    SweepIxIntentSerde::SystemTransfer {
                        from: from.clone(),
                        to: to.clone(),
                        lamports: *lamports,
                    }
                }
                SweepIxIntent::SplTransferChecked {
                    program_id,
                    source,
                    mint,
                    destination,
                    authority,
                    amount,
                    decimals,
                } => SweepIxIntentSerde::SplTransferChecked {
                    program_id: program_id.clone(),
                    source: source.clone(),
                    mint: mint.clone(),
                    destination: destination.clone(),
                    authority: authority.clone(),
                    amount: *amount,
                    decimals: *decimals,
                },
                SweepIxIntent::AtaCreateIdempotent {
                    token_program,
                    payer,
                    ata,
                    owner,
                    mint,
                } => SweepIxIntentSerde::AtaCreateIdempotent {
                    token_program: token_program.clone(),
                    payer: payer.clone(),
                    ata: ata.clone(),
                    owner: owner.clone(),
                    mint: mint.clone(),
                },
                SweepIxIntent::SplCloseAccount {
                    program_id,
                    account,
                    destination,
                    authority,
                } => SweepIxIntentSerde::SplCloseAccount {
                    program_id: program_id.clone(),
                    account: account.clone(),
                    destination: destination.clone(),
                    authority: authority.clone(),
                },
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SweepIntentSerde {
        pub fee_payer: Vec<u8>,
        pub ixs: Vec<SweepIxIntentSerde>,
    }

    impl From<&SweepIntent> for SweepIntentSerde {
        fn from(v: &SweepIntent) -> Self {
            SweepIntentSerde {
                fee_payer: v.fee_payer.clone(),
                ixs: v.ixs.iter().map(SweepIxIntentSerde::from).collect(),
            }
        }
    }
}

#[cfg(not(target_os = "solana"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepIntent {
    pub fee_payer: Vec<u8>,
    pub ixs: Vec<SweepIxIntent>,
}

#[cfg(not(target_os = "solana"))]
impl SweepIntent {
    pub fn fee_payer(&self) -> &[u8] {
        &self.fee_payer
    }
    pub fn ixs(&self) -> &[SweepIxIntent] {
        &self.ixs
    }
}

#[cfg(not(target_os = "solana"))]
fn host_bcs_uleb128(v: usize, out: &mut Vec<u8>) {
    let mut x = v as u64;
    while x >= 0x80 {
        out.push(((x & 0x7f) | 0x80) as u8);
        x >>= 7;
    }
    out.push(x as u8);
}

#[cfg(not(target_os = "solana"))]
fn host_bcs_bytes(b: &[u8], out: &mut Vec<u8>) {
    host_bcs_uleb128(b.len(), out);
    out.extend_from_slice(b);
}

#[cfg(not(target_os = "solana"))]
fn host_bcs_intent(ix: &SweepIxIntent, out: &mut Vec<u8>) {
    match ix {
        SweepIxIntent::SystemTransfer { from, to, lamports } => {
            host_bcs_uleb128(0, out);
            host_bcs_bytes(from, out);
            host_bcs_bytes(to, out);
            out.extend_from_slice(&lamports.to_le_bytes());
        }
        SweepIxIntent::SplTransferChecked {
            program_id,
            source,
            mint,
            destination,
            authority,
            amount,
            decimals,
        } => {
            host_bcs_uleb128(1, out);
            host_bcs_bytes(program_id, out);
            host_bcs_bytes(source, out);
            host_bcs_bytes(mint, out);
            host_bcs_bytes(destination, out);
            host_bcs_bytes(authority, out);
            out.extend_from_slice(&amount.to_le_bytes());
            out.push(*decimals);
        }
        SweepIxIntent::AtaCreateIdempotent {
            token_program,
            payer,
            ata,
            owner,
            mint,
        } => {
            host_bcs_uleb128(2, out);
            host_bcs_bytes(token_program, out);
            host_bcs_bytes(payer, out);
            host_bcs_bytes(ata, out);
            host_bcs_bytes(owner, out);
            host_bcs_bytes(mint, out);
        }
        SweepIxIntent::SplCloseAccount {
            program_id,
            account,
            destination,
            authority,
        } => {
            host_bcs_uleb128(3, out);
            host_bcs_bytes(program_id, out);
            host_bcs_bytes(account, out);
            host_bcs_bytes(destination, out);
            host_bcs_bytes(authority, out);
        }
    }
}

#[cfg(not(target_os = "solana"))]
fn host_bcs_one_intent(s: &SweepIntent, out: &mut Vec<u8>) {
    host_bcs_bytes(&s.fee_payer, out);
    host_bcs_uleb128(s.ixs.len(), out);
    for ix in &s.ixs {
        host_bcs_intent(ix, out);
    }
}

#[cfg(not(target_os = "solana"))]
pub fn bcs_encode_intents(intents: &[SweepIntent]) -> Vec<u8> {
    let mut out = Vec::new();
    host_bcs_uleb128(intents.len(), &mut out);
    for s in intents {
        host_bcs_one_intent(s, &mut out);
    }
    out
}

#[cfg(not(target_os = "solana"))]
pub fn hash_intents(intents: &[SweepIntent]) -> [u8; 32] {
    let bytes = bcs_encode_intents(intents);
    hashv(&[&bytes]).to_bytes()
}

#[cfg(not(target_os = "solana"))]
pub fn from_message_bytes(message_bytes: &[u8]) -> Result<SweepIntent, IntentError> {
    let parsed = solana_msg::parse(message_bytes)?;
    from_parsed(&parsed)
}

#[cfg(not(target_os = "solana"))]
pub fn from_parsed(msg: &ParsedMessage) -> Result<SweepIntent, IntentError> {
    let fee_payer = msg.fee_payer().to_vec();
    let mut ixs: Vec<SweepIxIntent> = Vec::new();

    for ix in msg.instructions() {
        let ix = ix?;
        let pid = msg
            .program_id(&ix)
            .ok_or(IntentError::Parse(ParseError::UnexpectedEof))?;
        if pid == &COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        } else if pid == &SYSTEM_PROGRAM_ID {
            ixs.push(extract_system_transfer(msg, &ix)?);
        } else if pid == &TOKEN_PROGRAM_ID || pid == &TOKEN_2022_PROGRAM_ID {
            ixs.push(extract_token_ix(msg, &ix, *pid)?);
        } else if pid == &ATA_PROGRAM_ID {
            ixs.push(extract_ata_create_idempotent(msg, &ix)?);
        } else {
            return Err(IntentError::UnknownProgram);
        }
    }

    Ok(SweepIntent { fee_payer, ixs })
}

#[cfg(not(target_os = "solana"))]
fn extract_system_transfer(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
) -> Result<SweepIxIntent, IntentError> {
    if ix.data.len() < 12 {
        return Err(IntentError::BadInstructionData);
    }
    let tag = solana_msg::read_u32_le(ix.data, 0)?;
    if tag != SYSTEM_IX_TRANSFER {
        return Err(IntentError::UnknownInstruction);
    }
    let lamports = solana_msg::read_u64_le(ix.data, 4)?;
    let from = msg
        .account_at(ix, 0)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let to = msg
        .account_at(ix, 1)
        .ok_or(IntentError::NotEnoughAccounts)?;
    Ok(SweepIxIntent::SystemTransfer {
        from: from.to_vec(),
        to: to.to_vec(),
        lamports,
    })
}

#[cfg(not(target_os = "solana"))]
fn extract_token_ix(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
    program_id: [u8; PUBKEY_LEN],
) -> Result<SweepIxIntent, IntentError> {
    if ix.data.is_empty() {
        return Err(IntentError::BadInstructionData);
    }
    let disc = ix.data[0];
    if disc == SPL_IX_TRANSFER_CHECKED {
        if ix.data.len() < 10 {
            return Err(IntentError::BadInstructionData);
        }
        let amount = solana_msg::read_u64_le(ix.data, 1)?;
        let decimals = ix.data[9];
        let source = msg
            .account_at(ix, 0)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let mint = msg
            .account_at(ix, 1)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let destination = msg
            .account_at(ix, 2)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let authority = msg
            .account_at(ix, 3)
            .ok_or(IntentError::NotEnoughAccounts)?;
        Ok(SweepIxIntent::SplTransferChecked {
            program_id: program_id.to_vec(),
            source: source.to_vec(),
            mint: mint.to_vec(),
            destination: destination.to_vec(),
            authority: authority.to_vec(),
            amount,
            decimals,
        })
    } else if disc == SPL_IX_CLOSE_ACCOUNT {
        let account = msg
            .account_at(ix, 0)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let destination = msg
            .account_at(ix, 1)
            .ok_or(IntentError::NotEnoughAccounts)?;
        let authority = msg
            .account_at(ix, 2)
            .ok_or(IntentError::NotEnoughAccounts)?;
        Ok(SweepIxIntent::SplCloseAccount {
            program_id: program_id.to_vec(),
            account: account.to_vec(),
            destination: destination.to_vec(),
            authority: authority.to_vec(),
        })
    } else {
        Err(IntentError::UnknownInstruction)
    }
}

#[cfg(not(target_os = "solana"))]
fn extract_ata_create_idempotent(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
) -> Result<SweepIxIntent, IntentError> {
    if ix.data.len() != 1 {
        return Err(IntentError::BadInstructionData);
    }
    if ix.data[0] != ATA_IX_CREATE_IDEMPOTENT {
        return Err(IntentError::UnknownInstruction);
    }
    let payer = msg
        .account_at(ix, 0)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let ata = msg
        .account_at(ix, 1)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let owner = msg
        .account_at(ix, 2)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let mint = msg
        .account_at(ix, 3)
        .ok_or(IntentError::NotEnoughAccounts)?;
    let token_program = msg
        .account_at(ix, 5)
        .ok_or(IntentError::NotEnoughAccounts)?;
    Ok(SweepIxIntent::AtaCreateIdempotent {
        token_program: token_program.to_vec(),
        payer: payer.to_vec(),
        ata: ata.to_vec(),
        owner: owner.to_vec(),
        mint: mint.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    /// Reuses the wire fixture from `solana_msg::tests`.
    const TRANSFER_FIXTURE: &[u8] = &[
        0x80, 0x01, 0x00, 0x01, 0x03, 0x58, 0xb2, 0xb4, 0x06, 0xdb, 0xfb, 0x8a, 0x70, 0xba, 0xf0,
        0xb1, 0x85, 0x30, 0x3e, 0xfb, 0xf4, 0x1c, 0xab, 0xb7, 0x0a, 0x83, 0x9f, 0x1e, 0xff, 0xee,
        0x31, 0x33, 0x3c, 0x6f, 0xb0, 0xd9, 0x90, 0xb6, 0x55, 0xba, 0x30, 0x4a, 0xc0, 0xa4, 0x54,
        0x46, 0xdb, 0xf9, 0x60, 0x97, 0xc6, 0x94, 0xc6, 0x59, 0x1e, 0xd0, 0xd4, 0x84, 0x95, 0xfd,
        0x18, 0x49, 0x69, 0x28, 0xd8, 0x97, 0x75, 0x29, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x01, 0x02,
        0x02, 0x00, 0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
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

    #[test]
    fn extract_intent_from_transfer_fixture() {
        let intent = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        assert_eq!(intent.fee_payer(), FROM_PUBKEY.as_slice());
        assert_eq!(intent.ixs().len(), 1);
        match &intent.ixs[0] {
            SweepIxIntent::SystemTransfer { from, to, lamports } => {
                assert_eq!(from.as_slice(), FROM_PUBKEY.as_slice());
                assert_eq!(to.as_slice(), TO_PUBKEY.as_slice());
                assert_eq!(*lamports, 100);
            }
            _ => panic!("unexpected variant"),
        }
        let again = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        assert_eq!(intent, again);
    }

    #[test]
    fn intent_hash_is_stable_across_calls() {
        let a = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        let b = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        assert_eq!(hash_intents(&[a]), hash_intents(&[b]));
    }

    #[test]
    fn intent_hash_is_32_bytes() {
        let intent = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        assert_eq!(hash_intents(&[intent]).len(), 32);
    }

    #[test]
    fn intent_hash_changes_with_lamports() {
        let intent = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        let h_orig = hash_intents(core::slice::from_ref(&intent));
        let mut mutated = intent;
        if let SweepIxIntent::SystemTransfer { lamports, .. } = &mut mutated.ixs[0] {
            *lamports = 999;
        }
        assert_ne!(h_orig, hash_intents(&[mutated]));
    }

    #[test]
    fn intent_hash_changes_with_destination() {
        let intent = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        let h_orig = hash_intents(core::slice::from_ref(&intent));
        let mut mutated = intent;
        if let SweepIxIntent::SystemTransfer { to, .. } = &mut mutated.ixs[0] {
            to[0] ^= 0xff;
        }
        assert_ne!(h_orig, hash_intents(&[mutated]));
    }

    #[test]
    fn unknown_program_id_rejected() {
        let mut bytes = TRANSFER_FIXTURE.to_vec();
        bytes[69 + 31] = 0x01;
        assert_eq!(from_message_bytes(&bytes), Err(IntentError::UnknownProgram));
    }

    #[test]
    fn rejects_system_non_transfer_tag() {
        let tag_off = 139;
        assert_eq!(
            solana_msg::read_u32_le(TRANSFER_FIXTURE, tag_off).unwrap(),
            SYSTEM_IX_TRANSFER
        );
        let mut bytes = TRANSFER_FIXTURE.to_vec();
        bytes[tag_off] = 0x05;
        assert_eq!(
            from_message_bytes(&bytes),
            Err(IntentError::UnknownInstruction)
        );
    }

    #[test]
    fn empty_intents_hash_well_defined() {
        let h_a = hash_intents(&[]);
        let h_b = hash_intents(&[]);
        assert_eq!(h_a, h_b);
        assert_eq!(h_a.len(), 32);
    }

    #[test]
    fn host_bcs_matches_handrolled_bcs() {
        let intents = vec![
            SweepIntent {
                fee_payer: vec![1u8; 32],
                ixs: vec![
                    SweepIxIntent::SystemTransfer {
                        from: vec![1u8; 32],
                        to: vec![2u8; 32],
                        lamports: 7,
                    },
                    SweepIxIntent::SplTransferChecked {
                        program_id: TOKEN_PROGRAM_ID.to_vec(),
                        source: vec![3u8; 32],
                        mint: vec![4u8; 32],
                        destination: vec![5u8; 32],
                        authority: vec![1u8; 32],
                        amount: 1_000_000,
                        decimals: 6,
                    },
                    SweepIxIntent::AtaCreateIdempotent {
                        token_program: TOKEN_PROGRAM_ID.to_vec(),
                        payer: vec![1u8; 32],
                        ata: vec![6u8; 32],
                        owner: vec![1u8; 32],
                        mint: vec![4u8; 32],
                    },
                    SweepIxIntent::SplCloseAccount {
                        program_id: TOKEN_PROGRAM_ID.to_vec(),
                        account: vec![6u8; 32],
                        destination: vec![1u8; 32],
                        authority: vec![1u8; 32],
                    },
                ],
            },
            SweepIntent {
                fee_payer: vec![9u8; 32],
                ixs: vec![],
            },
        ];

        let serde_form: Vec<host_bcs::SweepIntentSerde> = intents
            .iter()
            .map(host_bcs::SweepIntentSerde::from)
            .collect();
        let reference = bcs::to_bytes(&serde_form).unwrap();
        let handrolled = bcs_encode_intents(&intents);
        assert_eq!(handrolled, reference);
    }

    #[test]
    fn on_chain_digest_matches_host() {
        let intent = from_message_bytes(TRANSFER_FIXTURE).unwrap();
        let host_digest = hash_intents(&[intent]);
        let oc_digest = hash_message_bytes(TRANSFER_FIXTURE).unwrap();
        assert_eq!(host_digest, oc_digest);
    }
}
