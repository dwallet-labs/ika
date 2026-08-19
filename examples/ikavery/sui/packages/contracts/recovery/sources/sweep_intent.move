/// Structural intent of a Solana sweep transaction. Built from a parsed
/// `MessageV0` at proposal time and re-built from a fresh message at execute
/// time; the dWallet only signs if the freshly-built intent equals the stored
/// one. This is what makes blockhash-refresh-at-execute safe — the executor
/// can change the recent blockhash and re-pack instructions but cannot change
/// destinations, mints, amounts, or program ids.
///
/// Compute-budget instructions are explicitly *unconstrained*: they can be
/// added/removed/reordered between propose and execute. Compute fees are
/// paid by the source, are bounded by the runtime, and don't redirect funds.
///
/// Any unknown program or instruction discriminator causes `from_message` to
/// abort, so `propose()` will reject malformed bundles, and `execute()` will
/// reject any executor-injected instructions outside the whitelist.
module recovery::sweep_intent;

use recovery::solana_msg::{Self, ParsedMessage, ParsedInstruction};
use std::hash;
use sui::bcs;

// ===== Errors =====
const EUnknownProgram: u64 = 1;
const EUnknownInstruction: u64 = 2;
const ENotEnoughAccounts: u64 = 3;
const EBadInstructionData: u64 = 4;

// ===== Program IDs (32-byte pubkeys) =====
// `11111111111111111111111111111111`
const SYSTEM_PROGRAM_ID: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
const TOKEN_PROGRAM_ID: vector<u8> = x"06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9";
// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
const TOKEN_2022_PROGRAM_ID: vector<u8> = x"06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc";
// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
const ATA_PROGRAM_ID: vector<u8> = x"8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859";
// `ComputeBudget111111111111111111111111111111`
const COMPUTE_BUDGET_PROGRAM_ID: vector<u8> = x"0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000";

// SystemProgram instruction tag (u32 LE) — `Transfer` = 2.
const SYSTEM_IX_TRANSFER: u32 = 2;
// SPL Token / Token-2022 instruction discriminators (u8).
const SPL_IX_TRANSFER_CHECKED: u8 = 12;
const SPL_IX_CLOSE_ACCOUNT: u8 = 9;
// Associated Token Account program — `CreateIdempotent` = 1.
const ATA_IX_CREATE_IDEMPOTENT: u8 = 1;

// ===== Intent =====

/// One whitelisted instruction's structural fingerprint. Compute-budget
/// instructions are not represented here — they are dropped during intent
/// extraction.
public enum SweepIxIntent has store, copy, drop {
    SystemTransfer { from: vector<u8>, to: vector<u8>, lamports: u64 },
    SplTransferChecked {
        program_id: vector<u8>,
        source: vector<u8>,
        mint: vector<u8>,
        destination: vector<u8>,
        authority: vector<u8>,
        amount: u64,
        decimals: u8,
    },
    AtaCreateIdempotent {
        /// SPL Token program (Token-v1 or Token-2022) used as the ATA's
        /// token_program seed. Read from account index 5 of the instruction —
        /// NOT the instruction's program_id (which is always ATA_PROGRAM_ID).
        /// Required at execute-rebuild time so the ATA address derives back
        /// to the same canonical pubkey.
        token_program: vector<u8>,
        payer: vector<u8>,
        ata: vector<u8>,
        owner: vector<u8>,
        mint: vector<u8>,
    },
    SplCloseAccount {
        program_id: vector<u8>,
        account: vector<u8>,
        destination: vector<u8>,
        authority: vector<u8>,
    },
}

/// Per-tx intent: fee payer plus the ordered, whitelist-only instruction
/// fingerprint list. `from_message` produces this; `==` compares it.
public struct SweepIntent has store, copy, drop {
    fee_payer: vector<u8>,
    ixs: vector<SweepIxIntent>,
}

public fun fee_payer(self: &SweepIntent): &vector<u8> { &self.fee_payer }
public fun ixs(self: &SweepIntent): &vector<SweepIxIntent> { &self.ixs }

/// `sha256(bcs(intents))`. BCS gives a deterministic, structural-only encoding
/// (enum-tagged); two intent vectors hash equal iff every fingerprint matches
/// in order. Used both as a stable proposal identifier and as the propose-
/// challenge payload (so the WebAuthn assertion commits to the structural
/// intent, not to blockhash-bearing message bytes).
public(package) fun hash_intents(intents: &vector<SweepIntent>): vector<u8> {
    hash::sha2_256(bcs::to_bytes(intents))
}

// ===== Extraction =====

/// Parse `message_bytes` and project it down to a `SweepIntent`. Aborts on
/// any unknown program / unknown instruction / malformed instruction data /
/// address-table-lookup usage.
public fun from_message_bytes(message_bytes: vector<u8>): SweepIntent {
    from_parsed(&solana_msg::parse(message_bytes))
}

public fun from_parsed(msg: &ParsedMessage): SweepIntent {
    let fee_payer = solana_msg::fee_payer(msg);
    let mut ixs = vector::empty<SweepIxIntent>();

    let parsed_ixs = solana_msg::instructions(msg);
    let n = parsed_ixs.length();
    let mut i: u64 = 0;
    while (i < n) {
        let ix = parsed_ixs.borrow(i);
        let pid = solana_msg::program_id(msg, ix);

        if (pid == COMPUTE_BUDGET_PROGRAM_ID) {
            // Compute-budget is allowed but doesn't enter the intent.
        } else if (pid == SYSTEM_PROGRAM_ID) {
            ixs.push_back(extract_system_transfer(msg, ix));
        } else if (pid == TOKEN_PROGRAM_ID || pid == TOKEN_2022_PROGRAM_ID) {
            ixs.push_back(extract_token_ix(msg, ix, pid));
        } else if (pid == ATA_PROGRAM_ID) {
            ixs.push_back(extract_ata_create_idempotent(msg, ix));
        } else {
            abort EUnknownProgram
        };

        i = i + 1;
    };

    SweepIntent { fee_payer, ixs }
}

// ===== Per-program extractors =====

fun extract_system_transfer(msg: &ParsedMessage, ix: &ParsedInstruction): SweepIxIntent {
    let data = solana_msg::data(ix);
    assert!(data.length() >= 12, EBadInstructionData);
    let tag = solana_msg::read_u32_le(data, 0);
    assert!(tag == SYSTEM_IX_TRANSFER, EUnknownInstruction);
    let lamports = solana_msg::read_u64_le(data, 4);

    let accs = solana_msg::account_indices(ix);
    assert!(accs.length() >= 2, ENotEnoughAccounts);
    let from = solana_msg::account_at(msg, ix, 0);
    let to = solana_msg::account_at(msg, ix, 1);
    SweepIxIntent::SystemTransfer { from, to, lamports }
}

fun extract_token_ix(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
    program_id: vector<u8>,
): SweepIxIntent {
    let data = solana_msg::data(ix);
    assert!(!data.is_empty(), EBadInstructionData);
    let disc = *data.borrow(0);

    if (disc == SPL_IX_TRANSFER_CHECKED) {
        // data: [disc(1), amount(8), decimals(1)]
        assert!(data.length() >= 10, EBadInstructionData);
        let amount = solana_msg::read_u64_le(data, 1);
        let decimals = *data.borrow(9);

        let accs = solana_msg::account_indices(ix);
        assert!(accs.length() >= 4, ENotEnoughAccounts);
        // SPL TransferChecked layout: [source, mint, destination, authority, ...]
        let source = solana_msg::account_at(msg, ix, 0);
        let mint = solana_msg::account_at(msg, ix, 1);
        let destination = solana_msg::account_at(msg, ix, 2);
        let authority = solana_msg::account_at(msg, ix, 3);
        SweepIxIntent::SplTransferChecked {
            program_id,
            source,
            mint,
            destination,
            authority,
            amount,
            decimals,
        }
    } else if (disc == SPL_IX_CLOSE_ACCOUNT) {
        let accs = solana_msg::account_indices(ix);
        assert!(accs.length() >= 3, ENotEnoughAccounts);
        // SPL CloseAccount layout: [account, destination, authority, ...]
        let account = solana_msg::account_at(msg, ix, 0);
        let destination = solana_msg::account_at(msg, ix, 1);
        let authority = solana_msg::account_at(msg, ix, 2);
        SweepIxIntent::SplCloseAccount {
            program_id,
            account,
            destination,
            authority,
        }
    } else {
        abort EUnknownInstruction
    }
}

fun extract_ata_create_idempotent(
    msg: &ParsedMessage,
    ix: &ParsedInstruction,
): SweepIxIntent {
    let data = solana_msg::data(ix);
    // CreateIdempotent: data is `[1]`. Some serializers omit the byte — only
    // accept the explicit form; any other encoding indicates a different
    // ATA-program instruction we're not whitelisting.
    assert!(data.length() == 1, EBadInstructionData);
    assert!(*data.borrow(0) == ATA_IX_CREATE_IDEMPOTENT, EUnknownInstruction);

    let accs = solana_msg::account_indices(ix);
    // ATA CreateIdempotent layout: [payer, ata, owner, mint, system_program, token_program]
    assert!(accs.length() >= 6, ENotEnoughAccounts);
    let payer = solana_msg::account_at(msg, ix, 0);
    let ata = solana_msg::account_at(msg, ix, 1);
    let owner = solana_msg::account_at(msg, ix, 2);
    let mint = solana_msg::account_at(msg, ix, 3);
    let token_program = solana_msg::account_at(msg, ix, 5);
    SweepIxIntent::AtaCreateIdempotent {
        token_program,
        payer,
        ata,
        owner,
        mint,
    }
}
