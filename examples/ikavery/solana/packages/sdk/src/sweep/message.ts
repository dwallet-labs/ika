import {
	MessageV0,
	PublicKey,
	SystemProgram,
	TransactionInstruction,
	TransactionMessage,
} from '@solana/web3.js';

const ZERO_BLOCKHASH = '11111111111111111111111111111111';

/** Token-kegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA — original SPL Token program. */
export const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
/** TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb — Token-2022 program. */
export const TOKEN_2022_PROGRAM_ID = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
/** ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL — ATA program. */
export const ATA_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
/** SPL Token instruction discriminators consumed by the on-chain sweep parser. */
export const SPL_IX_TRANSFER_CHECKED = 12;
export const SPL_IX_CLOSE_ACCOUNT = 9;
export const ATA_IX_CREATE_IDEMPOTENT = 1;

/**
 * Build a serialized MessageV0 carrying the sweep instructions. The on-chain
 * program re-parses these bytes to compute the structural intent digest;
 * compute-budget ixs are excluded from the intent so the executor can
 * refresh them without redirecting funds.
 *
 * The blockhash is just a parser placeholder at propose time — by execute
 * time the broadcaster pulls a fresh one and rebuilds the message bytes.
 */
export interface BuildSweepMessageParams {
	/**
	 * Fee payer of the sweep tx (NOT the proposer of the on-chain proposal —
	 * the program never reads the fee payer at propose time, only the
	 * structural intent). Typically the dWallet account itself, since that's
	 * what holds the funds being swept.
	 */
	feePayer: PublicKey;
	/**
	 * Per-instruction sweep operations. Currently only system-transfer is
	 * exposed via {@link transferSol}; the parser supports SPL transfers /
	 * close-account / ATA-create-idempotent too.
	 */
	instructions: import('@solana/web3.js').TransactionInstruction[];
	/**
	 * Recent blockhash. Optional — defaults to the all-1s placeholder, which
	 * is sufficient for propose-time intent extraction.
	 */
	recentBlockhash?: string;
}

export function buildSweepMessage(params: BuildSweepMessageParams): {
	messageBytes: Uint8Array;
	messageLen: number;
} {
	if (params.instructions.length === 0) {
		throw new Error('buildSweepMessage: at least one instruction required');
	}

	const message = new TransactionMessage({
		payerKey: params.feePayer,
		recentBlockhash: params.recentBlockhash ?? ZERO_BLOCKHASH,
		instructions: params.instructions,
	}).compileToV0Message();

	const messageBytes = message.serialize();
	return { messageBytes, messageLen: messageBytes.length };
}

/**
 * Convenience: a single SOL transfer from `from` to `to`. The dWallet
 * account is normally both the fee payer and the source of funds, so
 * the typical caller passes `from === feePayer`.
 */
export function transferSol(from: PublicKey, to: PublicKey, lamports: number | bigint) {
	return SystemProgram.transfer({
		fromPubkey: from,
		toPubkey: to,
		lamports: typeof lamports === 'bigint' ? Number(lamports) : lamports,
	});
}

export interface TransferSplCheckedParams {
	/** dWallet's ATA — source of the tokens. */
	source: PublicKey;
	/** Token mint. Echoed in the on-chain intent for replay protection. */
	mint: PublicKey;
	/** Destination ATA. */
	destination: PublicKey;
	/** Owner of the source ATA — typically the dWallet account. */
	authority: PublicKey;
	/** Amount in mint base units. */
	amount: number | bigint;
	/** Mint decimals — must match `mint`'s on-chain `decimals` field. */
	decimals: number;
	/** Token program. Defaults to the original SPL Token program. */
	programId?: PublicKey;
}

/**
 * SPL `TransferChecked` (instruction discriminator 12). The on-chain sweep
 * parser whitelists this variant for both Token and Token-2022 programs;
 * use the legacy non-checked transfer at your peril (the program rejects it).
 */
export function transferSplTokenChecked(params: TransferSplCheckedParams): TransactionInstruction {
	const programId = params.programId ?? TOKEN_PROGRAM_ID;
	const amount = typeof params.amount === 'bigint' ? params.amount : BigInt(params.amount);
	const data = new Uint8Array(10);
	data[0] = SPL_IX_TRANSFER_CHECKED;
	const view = new DataView(data.buffer);
	view.setBigUint64(1, amount, true);
	data[9] = params.decimals & 0xff;
	return new TransactionInstruction({
		programId,
		keys: [
			{ pubkey: params.source, isSigner: false, isWritable: true },
			{ pubkey: params.mint, isSigner: false, isWritable: false },
			{ pubkey: params.destination, isSigner: false, isWritable: true },
			{ pubkey: params.authority, isSigner: true, isWritable: false },
		],
		data: Buffer.from(data),
	});
}

export interface CreateIdempotentAtaParams {
	/** Pays for the new ATA's rent (typically the dWallet itself). */
	payer: PublicKey;
	/** ATA address — derive externally with `getAssociatedTokenAddressSync`. */
	ata: PublicKey;
	/** Wallet that will own the ATA. */
	owner: PublicKey;
	/** Mint the ATA holds. */
	mint: PublicKey;
	/** Token program backing the mint. Defaults to original SPL Token. */
	tokenProgramId?: PublicKey;
}

/**
 * Associated Token Account program — `CreateIdempotent` (disc 1). Creates the
 * destination ATA on-the-fly as part of the sweep when the recipient hasn't
 * touched the mint before; idempotent so re-broadcasting is safe.
 */
export function createIdempotentAta(params: CreateIdempotentAtaParams): TransactionInstruction {
	const tokenProgramId = params.tokenProgramId ?? TOKEN_PROGRAM_ID;
	return new TransactionInstruction({
		programId: ATA_PROGRAM_ID,
		keys: [
			{ pubkey: params.payer, isSigner: true, isWritable: true },
			{ pubkey: params.ata, isSigner: false, isWritable: true },
			{ pubkey: params.owner, isSigner: false, isWritable: false },
			{ pubkey: params.mint, isSigner: false, isWritable: false },
			{
				pubkey: SystemProgram.programId,
				isSigner: false,
				isWritable: false,
			},
			{ pubkey: tokenProgramId, isSigner: false, isWritable: false },
		],
		data: Buffer.from([ATA_IX_CREATE_IDEMPOTENT]),
	});
}

export interface CloseSplAccountParams {
	/** ATA being closed. */
	account: PublicKey;
	/** Recipient of the reclaimed rent lamports. */
	destination: PublicKey;
	/** Owner of the ATA. */
	authority: PublicKey;
	/** Token program backing the ATA. Defaults to original SPL Token. */
	programId?: PublicKey;
}

/**
 * SPL Token `CloseAccount` (disc 9). Reclaims the ATA's rent into
 * `destination`. Account must be empty — the caller's responsibility.
 */
export function closeSplAccount(params: CloseSplAccountParams): TransactionInstruction {
	const programId = params.programId ?? TOKEN_PROGRAM_ID;
	return new TransactionInstruction({
		programId,
		keys: [
			{ pubkey: params.account, isSigner: false, isWritable: true },
			{ pubkey: params.destination, isSigner: false, isWritable: true },
			{ pubkey: params.authority, isSigner: true, isWritable: false },
		],
		data: Buffer.from([SPL_IX_CLOSE_ACCOUNT]),
	});
}

/** Re-export the v0 type for callers building messages by hand. */
export type SweepMessageV0 = MessageV0;
