import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { MessageV0, PublicKey, SystemProgram } from '@solana/web3.js';

/**
 * Decoded summary for a single instruction. We try hard to recognize the
 * common sweep operations (SystemProgram::Transfer, SPL TransferChecked,
 * AssociatedToken::CreateIdempotent, Token::CloseAccount) and fall back to
 * `unknown` for anything else.
 */
export type InstructionPreview =
	| {
			kind: 'system-transfer';
			from: string;
			to: string;
			lamports: bigint;
	  }
	| {
			kind: 'spl-transfer-checked';
			programId: string;
			source: string;
			mint: string;
			destination: string;
			authority: string;
			amount: bigint;
			decimals: number;
	  }
	| {
			kind: 'spl-create-ata-idempotent';
			programId: string;
			payer: string;
			ata: string;
			owner: string;
			mint: string;
	  }
	| {
			kind: 'spl-close-account';
			programId: string;
			account: string;
			destination: string;
			authority: string;
	  }
	| {
			kind: 'compute-budget';
			raw: number[];
	  }
	| {
			kind: 'unknown';
			programId: string;
			data: number[];
			accounts: string[];
	  };

export interface TxPreview {
	/** Per-instruction breakdown in execution order. */
	instructions: InstructionPreview[];
	/** Compiled byte length of the serialized message (no signatures). */
	messageByteLength: number;
	/** Static account keys, in order, for `accounts` lookups. */
	staticAccountKeys: string[];
}

export interface BundlePreview {
	txCount: number;
	txs: TxPreview[];
	/** Aggregated SOL transferred via SystemProgram::Transfer (lamports). */
	totalLamportsTransferred: bigint;
	/** Sum of token amounts per (mint, programId), keyed as `programId|mint`. */
	totalSplTransferred: Array<{
		mint: string;
		programId: string;
		amount: bigint;
		decimals: number;
	}>;
}

const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111';

const SPL_TRANSFER_CHECKED_DISCRIMINATOR = 12;
const SPL_CLOSE_ACCOUNT_DISCRIMINATOR = 9;
const ATA_CREATE_IDEMPOTENT_DISCRIMINATOR = 1;

export function previewMessages(messages: MessageV0[]): BundlePreview {
	const txs = messages.map(previewSingleMessage);
	let totalLamports = 0n;
	const splTotals = new Map<
		string,
		{ mint: string; programId: string; amount: bigint; decimals: number }
	>();
	for (const t of txs) {
		for (const ix of t.instructions) {
			if (ix.kind === 'system-transfer') {
				totalLamports += ix.lamports;
			} else if (ix.kind === 'spl-transfer-checked') {
				const key = `${ix.programId}|${ix.mint}`;
				const cur = splTotals.get(key);
				if (cur) {
					cur.amount += ix.amount;
				} else {
					splTotals.set(key, {
						mint: ix.mint,
						programId: ix.programId,
						amount: ix.amount,
						decimals: ix.decimals,
					});
				}
			}
		}
	}
	return {
		txCount: txs.length,
		txs,
		totalLamportsTransferred: totalLamports,
		totalSplTransferred: Array.from(splTotals.values()),
	};
}

export function previewMessageBytes(messageBytes: Uint8Array[]): BundlePreview {
	return previewMessages(messageBytes.map((b) => MessageV0.deserialize(b)));
}

function previewSingleMessage(msg: MessageV0): TxPreview {
	const keys = msg.staticAccountKeys.map((k) => k.toBase58());
	const ixs: InstructionPreview[] = msg.compiledInstructions.map((ci) => {
		const programId = keys[ci.programIdIndex]!;
		const accounts = Array.from(ci.accountKeyIndexes).map((i) => keys[i]!);
		const data = Array.from(ci.data);

		if (programId === SystemProgram.programId.toBase58()) {
			const decoded = tryDecodeSystem(msg, ci);
			if (decoded) return decoded;
		}
		if (
			programId === TOKEN_PROGRAM_ID.toBase58() ||
			programId === TOKEN_2022_PROGRAM_ID.toBase58()
		) {
			const decoded = tryDecodeTokenIx(programId, accounts, data);
			if (decoded) return decoded;
		}
		if (programId === ASSOCIATED_TOKEN_PROGRAM_ID) {
			const decoded = tryDecodeAtaIx(programId, accounts, data);
			if (decoded) return decoded;
		}
		if (programId === COMPUTE_BUDGET_PROGRAM_ID) {
			return { kind: 'compute-budget', raw: data };
		}
		return { kind: 'unknown', programId, data, accounts };
	});

	return {
		instructions: ixs,
		messageByteLength: msg.serialize().length,
		staticAccountKeys: keys,
	};
}

function tryDecodeSystem(
	msg: MessageV0,
	ci: MessageV0['compiledInstructions'][number],
): InstructionPreview | null {
	// SystemInstruction.decodeTransfer expects a `TransactionInstruction`, so
	// we hand-decode the TRANSFER variant from raw bytes (instruction 2).
	const data = ci.data;
	if (data.length < 4) return null;
	const ixType = readU32LE(data, 0);
	if (ixType !== 2) return null;
	if (data.length < 4 + 8) return null;
	const lamports = readU64LE(data, 4);
	const keys = msg.staticAccountKeys.map((k) => k.toBase58());
	const idxs = Array.from(ci.accountKeyIndexes);
	if (idxs.length < 2) return null;
	return {
		kind: 'system-transfer',
		from: keys[idxs[0]!]!,
		to: keys[idxs[1]!]!,
		lamports,
	};
}

function tryDecodeTokenIx(
	programId: string,
	accounts: string[],
	data: number[],
): InstructionPreview | null {
	if (data.length === 0) return null;
	const disc = data[0]!;
	if (disc === SPL_TRANSFER_CHECKED_DISCRIMINATOR) {
		if (data.length < 1 + 8 + 1) return null;
		if (accounts.length < 4) return null;
		const amount = readU64LE(new Uint8Array(data), 1);
		const decimals = data[9]!;
		return {
			kind: 'spl-transfer-checked',
			programId,
			source: accounts[0]!,
			mint: accounts[1]!,
			destination: accounts[2]!,
			authority: accounts[3]!,
			amount,
			decimals,
		};
	}
	if (disc === SPL_CLOSE_ACCOUNT_DISCRIMINATOR) {
		if (accounts.length < 3) return null;
		return {
			kind: 'spl-close-account',
			programId,
			account: accounts[0]!,
			destination: accounts[1]!,
			authority: accounts[2]!,
		};
	}
	return null;
}

function tryDecodeAtaIx(
	programId: string,
	accounts: string[],
	data: number[],
): InstructionPreview | null {
	if (data.length === 0) return null;
	// Idempotent variant (1) — the only one we emit. Length-0 data is the
	// legacy `Create` (variant 0); we don't emit that, but treat it the same.
	if (data[0] === ATA_CREATE_IDEMPOTENT_DISCRIMINATOR || data.length === 0) {
		if (accounts.length < 4) return null;
		return {
			kind: 'spl-create-ata-idempotent',
			programId,
			payer: accounts[0]!,
			ata: accounts[1]!,
			owner: accounts[2]!,
			mint: accounts[3]!,
		};
	}
	return null;
}

function readU32LE(arr: Uint8Array | number[], off: number): number {
	return (arr[off]! | (arr[off + 1]! << 8) | (arr[off + 2]! << 16) | (arr[off + 3]! << 24)) >>> 0;
}

function readU64LE(arr: Uint8Array | number[], off: number): bigint {
	let result = 0n;
	for (let i = 0; i < 8; i++) {
		result |= BigInt(arr[off + i]!) << BigInt(8 * i);
	}
	return result;
}

// `PublicKey` import is required by `MessageV0.staticAccountKeys` typing.
void PublicKey;
