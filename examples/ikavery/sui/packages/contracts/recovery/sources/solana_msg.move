/// Parser for Solana versioned `MessageV0` wire format. Used by `recovery` to
/// derive a structural `SweepIntent` from sweep transactions at proposal time
/// and re-derive it from freshly-built messages at execute time. Verifying
/// intent in Move (rather than trusting the executor's assertion) is what
/// makes the sign-at-execute model safe: the executor can replace the recent
/// blockhash and tx ordering, but cannot redirect funds.
///
/// Wire format (per `solana-program/src/message/versions/v0/mod.rs`):
///   1B  version-prefix (must be 0x80 for v0)
///   1B  numRequiredSignatures
///   1B  numReadonlySignedAccounts
///   1B  numReadonlyUnsignedAccounts
///   shortvec  staticAccountKeys.len, then N*32B
///   32B recentBlockhash
///   shortvec  instructions.len, then per-instruction
///   shortvec  addressTableLookups.len (must be 0; ALT is rejected)
module recovery::solana_msg;

// ===== Errors =====
const EShortvecOverflow: u64 = 1;
const EUnexpectedEof: u64 = 2;
const EInvalidVersion: u64 = 3;
const EAddressTableLookupsNotSupported: u64 = 4;
const ETrailingBytes: u64 = 5;

// ===== Constants =====
const PUBKEY_LEN: u64 = 32;
const BLOCKHASH_LEN: u64 = 32;
const VERSION_V0_PREFIX: u8 = 0x80;

// ===== Output types =====
public struct ParsedInstruction has copy, drop {
    program_id_index: u8,
    account_indices: vector<u8>,
    data: vector<u8>,
}

public struct ParsedMessage has copy, drop {
    num_required_signatures: u8,
    num_readonly_signed: u8,
    num_readonly_unsigned: u8,
    /// 32-byte pubkeys, ordering preserved from wire.
    account_keys: vector<vector<u8>>,
    instructions: vector<ParsedInstruction>,
}

// ===== Accessors =====
public fun num_required_signatures(self: &ParsedMessage): u8 { self.num_required_signatures }
public fun account_keys(self: &ParsedMessage): &vector<vector<u8>> { &self.account_keys }
public fun instructions(self: &ParsedMessage): &vector<ParsedInstruction> { &self.instructions }

public fun program_id_index(ix: &ParsedInstruction): u8 { ix.program_id_index }
public fun account_indices(ix: &ParsedInstruction): &vector<u8> { &ix.account_indices }
public fun data(ix: &ParsedInstruction): &vector<u8> { &ix.data }

// ===== Public helpers used by callers when checking intent =====
/// Resolves the program id (32-byte pubkey) for an instruction.
public fun program_id(self: &ParsedMessage, ix: &ParsedInstruction): vector<u8> {
    *self.account_keys.borrow(ix.program_id_index as u64)
}

/// Resolves the account at `account_indices[idx]` to its 32-byte pubkey.
public fun account_at(
    self: &ParsedMessage,
    ix: &ParsedInstruction,
    idx: u64,
): vector<u8> {
    let key_idx = *ix.account_indices.borrow(idx) as u64;
    *self.account_keys.borrow(key_idx)
}

/// Returns the fee payer (account at index 0). MessageV0 always places the
/// fee payer first in the static account keys.
public fun fee_payer(self: &ParsedMessage): vector<u8> {
    *self.account_keys.borrow(0)
}

// ===== Parser =====
public fun parse(bytes: vector<u8>): ParsedMessage {
    let mut off: u64 = 0;
    let n = bytes.length();

    // Header
    let version = read_u8(&bytes, &mut off, n);
    assert!(version == VERSION_V0_PREFIX, EInvalidVersion);
    let num_req = read_u8(&bytes, &mut off, n);
    let num_ro_signed = read_u8(&bytes, &mut off, n);
    let num_ro_unsigned = read_u8(&bytes, &mut off, n);

    // Static account keys
    let key_count = read_compact_u16(&bytes, &mut off, n);
    let mut account_keys = vector::empty<vector<u8>>();
    let mut i: u64 = 0;
    while (i < (key_count as u64)) {
        account_keys.push_back(read_bytes(&bytes, &mut off, n, PUBKEY_LEN));
        i = i + 1;
    };

    // Recent blockhash — intentionally read and discarded; intent must be
    // blockhash-independent.
    let _blockhash = read_bytes(&bytes, &mut off, n, BLOCKHASH_LEN);

    // Instructions
    let ix_count = read_compact_u16(&bytes, &mut off, n);
    let mut instructions = vector::empty<ParsedInstruction>();
    i = 0;
    while (i < (ix_count as u64)) {
        let program_id_index = read_u8(&bytes, &mut off, n);
        let acc_count = read_compact_u16(&bytes, &mut off, n);
        let account_indices = read_bytes(&bytes, &mut off, n, acc_count as u64);
        let data_len = read_compact_u16(&bytes, &mut off, n);
        let data = read_bytes(&bytes, &mut off, n, data_len as u64);
        instructions.push_back(ParsedInstruction {
            program_id_index,
            account_indices,
            data,
        });
        i = i + 1;
    };

    // Address-table lookups: hard-rejected. ALT entries can introduce account
    // keys that aren't in `account_keys`, defeating intent checks that compare
    // resolved pubkeys.
    let lookup_count = read_compact_u16(&bytes, &mut off, n);
    assert!((lookup_count as u64) == 0, EAddressTableLookupsNotSupported);

    assert!(off == n, ETrailingBytes);

    ParsedMessage {
        num_required_signatures: num_req,
        num_readonly_signed: num_ro_signed,
        num_readonly_unsigned: num_ro_unsigned,
        account_keys,
        instructions,
    }
}

// ===== Internal byte readers =====
fun read_u8(bytes: &vector<u8>, off: &mut u64, n: u64): u8 {
    assert!(*off < n, EUnexpectedEof);
    let v = *bytes.borrow(*off);
    *off = *off + 1;
    v
}

fun read_bytes(bytes: &vector<u8>, off: &mut u64, n: u64, len: u64): vector<u8> {
    assert!(*off + len <= n, EUnexpectedEof);
    let mut out = vector::empty<u8>();
    let mut i: u64 = 0;
    while (i < len) {
        out.push_back(*bytes.borrow(*off + i));
        i = i + 1;
    };
    *off = *off + len;
    out
}

/// Solana shortvec / compact-u16: up to 3 bytes, 7 data bits each, MSB is
/// continuation. We bound the result at 0xffff and reject anything that
/// would set a 4th continuation byte.
fun read_compact_u16(bytes: &vector<u8>, off: &mut u64, n: u64): u16 {
    let mut value: u32 = 0;
    let mut shift: u8 = 0;
    let mut count: u8 = 0;
    let mut keep_going = true;
    while (keep_going) {
        assert!(count < 3, EShortvecOverflow);
        let byte = read_u8(bytes, off, n);
        let low = (byte & 0x7f) as u32;
        value = value | (low << shift);
        count = count + 1;
        if (byte & 0x80 == 0) {
            keep_going = false;
        } else {
            shift = shift + 7;
        };
    };
    assert!(value <= 0xffff, EShortvecOverflow);
    value as u16
}

// ===== Read u32 / u64 little-endian from instruction data =====
public fun read_u32_le(data: &vector<u8>, off: u64): u32 {
    assert!(off + 4 <= data.length(), EUnexpectedEof);
    let b0 = *data.borrow(off) as u32;
    let b1 = *data.borrow(off + 1) as u32;
    let b2 = *data.borrow(off + 2) as u32;
    let b3 = *data.borrow(off + 3) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

public fun read_u64_le(data: &vector<u8>, off: u64): u64 {
    assert!(off + 8 <= data.length(), EUnexpectedEof);
    let mut value: u64 = 0;
    let mut i: u64 = 0;
    while (i < 8) {
        value = value | ((*data.borrow(off + i) as u64) << ((i * 8) as u8));
        i = i + 1;
    };
    value
}
