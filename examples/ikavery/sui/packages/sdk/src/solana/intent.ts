import { bcs } from '@mysten/sui/bcs';
import { sha256 } from '@noble/hashes/sha2.js';
import {
	createAssociatedTokenAccountIdempotentInstruction,
	createCloseAccountInstruction,
	createTransferCheckedInstruction,
	TOKEN_2022_PROGRAM_ID,
	TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import {
	MessageV0,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	type TransactionInstruction,
} from '@solana/web3.js';

import { SweepIntent as SweepIntentBcs } from '../generated/recovery/sweep_intent';

/**
 * Solana sweep intent extraction (TypeScript mirror of `recovery::sweep_intent`).
 *
 * Walks each instruction in a `MessageV0`, projects it down to the same
 * structural fingerprint that the Move parser produces, and BCS-encodes
 * `vector<SweepIntent>` so the intent hash can be computed off-chain. This is
 * needed at proposal time: the WebAuthn assertion's challenge commits to the
 * intent hash, and the chain-side `propose()` will re-derive the same hash
 * and reject any mismatch.
 *
 * Throws on any unknown program / unknown instruction / malformed data — the
 * Move parser would abort on the same conditions, so failing fast in TS gives
 * a better error.
 */

const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const COMPUTE_BUDGET_PROGRAM_ID = new PublicKey('ComputeBudget111111111111111111111111111111');

const SYSTEM_IX_TRANSFER = 2;
const SPL_IX_TRANSFER_CHECKED = 12;
const SPL_IX_CLOSE_ACCOUNT = 9;
const ATA_IX_CREATE_IDEMPOTENT = 1;

// ===== JS shape mirrors Move BCS enum/struct schemas in generated/sweep_intent =====

/** Pubkey as 32 raw bytes. Matches Move's `vector<u8>`. */
type Pubkey = Uint8Array;

export type SweepIxIntent =
	| { SystemTransfer: { from: Pubkey; to: Pubkey; lamports: bigint } }
	| {
			SplTransferChecked: {
				program_id: Pubkey;
				source: Pubkey;
				mint: Pubkey;
				destination: Pubkey;
				authority: Pubkey;
				amount: bigint;
				decimals: number;
			};
	  }
	| {
			AtaCreateIdempotent: {
				token_program: Pubkey;
				payer: Pubkey;
				ata: Pubkey;
				owner: Pubkey;
				mint: Pubkey;
			};
	  }
	| {
			SplCloseAccount: {
				program_id: Pubkey;
				account: Pubkey;
				destination: Pubkey;
				authority: Pubkey;
			};
	  };

export interface SweepIntent {
	fee_payer: Pubkey;
	ixs: SweepIxIntent[];
}

// ===== Extraction =====

export function extractIntent(msg: MessageV0): SweepIntent {
	const keys = msg.staticAccountKeys;
	const fee_payer = keys[0]!.toBytes();

	const ixs: SweepIxIntent[] = [];
	for (const ci of msg.compiledInstructions) {
		const programIdKey = keys[ci.programIdIndex]!;
		const programId = programIdKey.toBytes();

		if (programIdKey.equals(COMPUTE_BUDGET_PROGRAM_ID)) {
			// dropped from intent
			continue;
		}
		if (programIdKey.equals(SystemProgram.programId)) {
			ixs.push(extractSystemTransfer(keys, ci));
			continue;
		}
		if (programIdKey.equals(TOKEN_PROGRAM_ID) || programIdKey.equals(TOKEN_2022_PROGRAM_ID)) {
			ixs.push(extractTokenIx(programId, keys, ci));
			continue;
		}
		if (programIdKey.equals(ASSOCIATED_TOKEN_PROGRAM_ID)) {
			ixs.push(extractAtaCreateIdempotent(keys, ci));
			continue;
		}
		throw new Error(`extractIntent: unknown program ${programIdKey.toBase58()}`);
	}

	return { fee_payer, ixs };
}

export function extractIntents(messageBytes: Uint8Array[]): SweepIntent[] {
	return messageBytes.map((b) => extractIntent(MessageV0.deserialize(b)));
}

/** `sha256(BCS(vector<SweepIntent>))` — identical to `sweep_intent::hash_intents`. */
export function intentHash(intents: SweepIntent[]): Uint8Array {
	const bytes = bcs
		.vector(SweepIntentBcs)
		.serialize(intents as Parameters<(typeof SweepIntentBcs)['serialize']>[0][])
		.toBytes();
	return sha256(bytes);
}

/** Convenience: extract + hash in one call. */
export function intentHashFromMessages(messageBytes: Uint8Array[]): {
	intents: SweepIntent[];
	hash: Uint8Array;
} {
	const intents = extractIntents(messageBytes);
	return { intents, hash: intentHash(intents) };
}

/**
 * Rebuild fresh sweep messages from stored intents using a current blockhash.
 * Used at execute time: the chain re-derives intent from these messages and
 * aborts unless they match the stored intents byte-for-byte (after BCS).
 *
 * Each tx is rebuilt independently; instruction order, account ordering, and
 * data layout are preserved by emitting the canonical wire form for each
 * `SweepIxIntent` variant.
 */
export function rebuildSweepFromIntents(
	intents: SweepIntent[],
	recentBlockhash: string,
): Uint8Array[] {
	return intents.map((intent) => buildSingleTx(intent, recentBlockhash));
}

function buildSingleTx(intent: SweepIntent, recentBlockhash: string): Uint8Array {
	const payerKey = new PublicKey(intent.fee_payer);
	const instructions = intent.ixs.map(ixToInstruction);
	const msg = new TransactionMessage({
		payerKey,
		recentBlockhash,
		instructions,
	}).compileToV0Message();
	return msg.serialize();
}

function ixToInstruction(ix: SweepIxIntent): TransactionInstruction {
	if ('SystemTransfer' in ix) {
		const { from, to, lamports } = ix.SystemTransfer;
		return SystemProgram.transfer({
			fromPubkey: new PublicKey(from),
			toPubkey: new PublicKey(to),
			lamports,
		});
	}
	if ('SplTransferChecked' in ix) {
		const { program_id, source, mint, destination, authority, amount, decimals } =
			ix.SplTransferChecked;
		return createTransferCheckedInstruction(
			new PublicKey(source),
			new PublicKey(mint),
			new PublicKey(destination),
			new PublicKey(authority),
			amount,
			decimals,
			[],
			new PublicKey(program_id),
		);
	}
	if ('AtaCreateIdempotent' in ix) {
		const { token_program, payer, ata, owner, mint } = ix.AtaCreateIdempotent;
		return createAssociatedTokenAccountIdempotentInstruction(
			new PublicKey(payer),
			new PublicKey(ata),
			new PublicKey(owner),
			new PublicKey(mint),
			new PublicKey(token_program),
		);
	}
	if ('SplCloseAccount' in ix) {
		const { program_id, account, destination, authority } = ix.SplCloseAccount;
		return createCloseAccountInstruction(
			new PublicKey(account),
			new PublicKey(destination),
			new PublicKey(authority),
			[],
			new PublicKey(program_id),
		);
	}
	throw new Error('rebuildSweepFromIntents: unknown ix variant');
}

// ===== Per-program extractors =====

function extractSystemTransfer(
	keys: PublicKey[],
	ci: MessageV0['compiledInstructions'][number],
): SweepIxIntent {
	const data = ci.data;
	if (data.length < 12) {
		throw new Error('extractIntent: SystemTransfer data too short');
	}
	const tag = readU32LE(data, 0);
	if (tag !== SYSTEM_IX_TRANSFER) {
		throw new Error(`extractIntent: unsupported System instruction tag ${tag}`);
	}
	const lamports = readU64LE(data, 4);
	const idxs = ci.accountKeyIndexes;
	if (idxs.length < 2) {
		throw new Error('extractIntent: SystemTransfer needs ≥2 accounts');
	}
	return {
		SystemTransfer: {
			from: keys[idxs[0]!]!.toBytes(),
			to: keys[idxs[1]!]!.toBytes(),
			lamports,
		},
	};
}

function extractTokenIx(
	programId: Pubkey,
	keys: PublicKey[],
	ci: MessageV0['compiledInstructions'][number],
): SweepIxIntent {
	const data = ci.data;
	if (data.length === 0) {
		throw new Error('extractIntent: empty Token instruction data');
	}
	const disc = data[0]!;
	const idxs = ci.accountKeyIndexes;

	if (disc === SPL_IX_TRANSFER_CHECKED) {
		if (data.length < 10) {
			throw new Error('extractIntent: TransferChecked data too short');
		}
		if (idxs.length < 4) {
			throw new Error('extractIntent: TransferChecked needs ≥4 accounts');
		}
		const amount = readU64LE(data, 1);
		const decimals = data[9]!;
		return {
			SplTransferChecked: {
				program_id: programId,
				source: keys[idxs[0]!]!.toBytes(),
				mint: keys[idxs[1]!]!.toBytes(),
				destination: keys[idxs[2]!]!.toBytes(),
				authority: keys[idxs[3]!]!.toBytes(),
				amount,
				decimals,
			},
		};
	}
	if (disc === SPL_IX_CLOSE_ACCOUNT) {
		if (idxs.length < 3) {
			throw new Error('extractIntent: CloseAccount needs ≥3 accounts');
		}
		return {
			SplCloseAccount: {
				program_id: programId,
				account: keys[idxs[0]!]!.toBytes(),
				destination: keys[idxs[1]!]!.toBytes(),
				authority: keys[idxs[2]!]!.toBytes(),
			},
		};
	}
	throw new Error(`extractIntent: unsupported Token instruction disc ${disc}`);
}

function extractAtaCreateIdempotent(
	keys: PublicKey[],
	ci: MessageV0['compiledInstructions'][number],
): SweepIxIntent {
	const data = ci.data;
	// Move requires explicit `[1]`; mirror that to fail-fast.
	if (data.length !== 1 || data[0] !== ATA_IX_CREATE_IDEMPOTENT) {
		throw new Error(`extractIntent: ATA program: only CreateIdempotent (data=[1]) supported`);
	}
	const idxs = ci.accountKeyIndexes;
	// Layout: [payer, ata, owner, mint, system_program, token_program]
	if (idxs.length < 6) {
		throw new Error('extractIntent: ATA CreateIdempotent needs ≥6 accounts');
	}
	return {
		AtaCreateIdempotent: {
			token_program: keys[idxs[5]!]!.toBytes(),
			payer: keys[idxs[0]!]!.toBytes(),
			ata: keys[idxs[1]!]!.toBytes(),
			owner: keys[idxs[2]!]!.toBytes(),
			mint: keys[idxs[3]!]!.toBytes(),
		},
	};
}

// ===== LE readers =====

function readU32LE(arr: Uint8Array, off: number): number {
	return (arr[off]! | (arr[off + 1]! << 8) | (arr[off + 2]! << 16) | (arr[off + 3]! << 24)) >>> 0;
}

function readU64LE(arr: Uint8Array, off: number): bigint {
	let result = 0n;
	for (let i = 0; i < 8; i++) {
		result |= BigInt(arr[off + i]!) << BigInt(8 * i);
	}
	return result;
}
