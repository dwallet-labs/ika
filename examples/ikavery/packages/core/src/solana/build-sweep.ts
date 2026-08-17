import {
	createAssociatedTokenAccountIdempotentInstruction,
	createCloseAccountInstruction,
	createTransferCheckedInstruction,
	getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import {
	ComputeBudgetProgram,
	MessageV0,
	SystemProgram,
	TransactionMessage,
	type PublicKey,
	type TransactionInstruction,
} from '@solana/web3.js';

/** Wire-format size limit for a Solana transaction (post-base58). */
export const SOLANA_TX_SIZE_LIMIT = 1232;

/**
 * Rent-exempt minimum (lamports) for a 0-byte system account. Solana rejects
 * txs that leave any writable account with a non-zero balance below this
 * threshold — so the SOL sweep must end the source either at exactly 0 or at
 * ≥ this minimum. `buildSweepBundle` enforces the latter via `feeReserveLamports`.
 */
export const SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT = 890_880n;

/**
 * Per-signature lamport cost charged by the runtime for every tx the source
 * (dWallet) signs. Used inside `buildSweepBundle` to bump the SOL reserve so
 * the final transfer doesn't leave the dWallet below rent-exempt after the
 * bundle's accumulated fees. 5000 is the network constant; we round up
 * slightly so a priority-fee bump doesn't blow past the reserve.
 */
export const SOLANA_SIGNATURE_FEE_LAMPORTS = 5_500n;

/** A token account on the source side, ready to be swept. */
export interface SourceTokenAccount {
	mint: PublicKey;
	/** The source's ATA (or any token account) holding `amount` of `mint`. */
	tokenAccount: PublicKey;
	amount: bigint;
	decimals: number;
	/** SPL token program id; defaults to the original Token program. */
	programId: PublicKey;
}

export interface BuildSweepBundleParams {
	source: PublicKey;
	destination: PublicKey;
	/** Native SOL balance on `source` in lamports. */
	solBalance: bigint;
	/** Per-tx reserve to keep in `source` for paying the bundle's signatures. */
	feeReserveLamports: bigint;
	/** Token accounts to sweep. */
	tokenAccounts: SourceTokenAccount[];
	/** Recent blockhash to bake into each `MessageV0`. */
	recentBlockhash: string;
	/** Optional compute-unit limit per tx; default omits ComputeBudget. */
	computeUnitLimit?: number;
	/** Optional priority fee in micro-lamports/CU. */
	priorityFeeMicroLamportsPerCu?: bigint;
	/**
	 * Cap on each `MessageV0.serialize()` length. Defaults to
	 * `SOLANA_TX_SIZE_LIMIT - 65` (1167) so a fully-signed tx fits the 1232-byte
	 * packet. Solana ikavery executes via a CPI carrier ix that pins the message
	 * into a fixed `[u8; 512]` arg, so callers should pass `512` to keep each
	 * bundle tx under the on-chain `MAX_MESSAGE_BYTES` cap.
	 */
	maxSerializedMessageBytes?: number;
}

/**
 * Build a multi-tx sweep targeting `destination`. Per token account we emit:
 * - `createAssociatedTokenAccountIdempotent` on the destination side (paid by source).
 * - `transferChecked(amount, decimals)` from source ATA to destination ATA.
 * - `closeAccount` on the source ATA to recover rent SOL.
 *
 * Once all SPL transfers are emitted, the FINAL tx (which may also carry SPL
 * instructions if there's room) ends with a `SystemProgram.transfer` of the
 * residual SOL — `solBalance + sum(closed-rent) - feeReserve`.
 *
 * Greedy-packs into ≤ 1232-byte `MessageV0`s; spills into a new tx whenever
 * adding the next instruction would overflow. The serialized message bytes
 * are what the dWallet signs.
 */
export function buildSweepBundle(params: BuildSweepBundleParams): Uint8Array[] {
	const {
		source,
		destination,
		solBalance,
		feeReserveLamports,
		tokenAccounts,
		recentBlockhash,
		computeUnitLimit,
		priorityFeeMicroLamportsPerCu,
		maxSerializedMessageBytes = SOLANA_TX_SIZE_LIMIT - 65,
	} = params;

	const computeIxs: TransactionInstruction[] = [];
	if (computeUnitLimit !== undefined) {
		computeIxs.push(ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnitLimit }));
	}
	if (priorityFeeMicroLamportsPerCu !== undefined) {
		computeIxs.push(
			ComputeBudgetProgram.setComputeUnitPrice({
				microLamports: priorityFeeMicroLamportsPerCu,
			}),
		);
	}

	// Per-token-account ix triplets.
	const tokenIxBatches: TransactionInstruction[][] = tokenAccounts.map((t) => {
		const destAta = getAssociatedTokenAddressSync(t.mint, destination, true, t.programId);
		return [
			createAssociatedTokenAccountIdempotentInstruction(
				source,
				destAta,
				destination,
				t.mint,
				t.programId,
			),
			createTransferCheckedInstruction(
				t.tokenAccount,
				t.mint,
				destAta,
				source,
				t.amount,
				t.decimals,
				[],
				t.programId,
			),
			createCloseAccountInstruction(t.tokenAccount, source, source, [], t.programId),
		];
	});

	// The final SOL transfer is appended to whatever tx is the last in the bundle.
	// Per-batch SOL flow on the source: it pays rent for each freshly-created
	// destination ATA (~2_039_280 lamports) and recovers rent from each closed
	// source ATA — they cancel out — so net SOL change pre-final-transfer is
	// just `-tx_fee`. The reserve must keep the source ≥ Solana's system-account
	// rent-exempt minimum: leaving it with 0 < balance < rent-exempt makes the
	// tx fail with "insufficient funds for rent" at broadcast time. Caller-side
	// drain-to-zero would require exact fee modeling so we don't expose that.
	if (feeReserveLamports < SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT) {
		throw new Error(
			`buildSweepBundle: feeReserveLamports (${feeReserveLamports}) below rent-exempt minimum (${SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT}); leaving the source between 0 and rent-exempt would make the tx fail at broadcast`,
		);
	}

	// Two-pass: pack with a placeholder SOL transfer (lamports field is fixed
	// u64 wire-size, so packing decisions don't depend on the actual value),
	// count N, then rebuild with sweepAmount adjusted down by N × per-tx fee.
	// The dWallet signs every sweep tx, so it pays N signature fees from the
	// same balance the SOL transfer drains — without this correction the
	// final transfer leaves the dWallet just below rent-exempt and the
	// runtime atomically reverts the entire last tx.
	const packAttempt = packBundle(
		source,
		recentBlockhash,
		computeIxs,
		tokenIxBatches,
		SystemProgram.transfer({
			fromPubkey: source,
			toPubkey: destination,
			lamports: 1n,
		}),
		maxSerializedMessageBytes,
	);
	const txCount = BigInt(packAttempt.length);
	const totalBundleFees = txCount * SOLANA_SIGNATURE_FEE_LAMPORTS;
	const sweepSolAmount = solBalance - feeReserveLamports - totalBundleFees;
	if (sweepSolAmount <= 0n) {
		throw new Error(
			`buildSweepBundle: sweep amount non-positive after subtracting ${txCount} bundle fees (${totalBundleFees}); raise solBalance or lower feeReserve`,
		);
	}
	const finalSolIx = SystemProgram.transfer({
		fromPubkey: source,
		toPubkey: destination,
		lamports: sweepSolAmount,
	});
	return packBundle(
		source,
		recentBlockhash,
		computeIxs,
		tokenIxBatches,
		finalSolIx,
		maxSerializedMessageBytes,
	);
}

function packBundle(
	source: PublicKey,
	recentBlockhash: string,
	computeIxs: TransactionInstruction[],
	tokenIxBatches: TransactionInstruction[][],
	finalSolIx: TransactionInstruction,
	maxSerializedMessageBytes: number,
): Uint8Array[] {
	const messages: Uint8Array[] = [];
	let current: TransactionInstruction[] = [...computeIxs];

	const pushCurrent = () => {
		if (current.length === 0) return;
		const msg = new TransactionMessage({
			payerKey: source,
			recentBlockhash,
			instructions: current,
		}).compileToV0Message();
		messages.push(msg.serialize());
		current = [...computeIxs];
	};

	const trySerialize = (ixs: TransactionInstruction[]): Uint8Array | null => {
		try {
			const msg = new TransactionMessage({
				payerKey: source,
				recentBlockhash,
				instructions: ixs,
			}).compileToV0Message();
			const bytes = msg.serialize();
			return bytes.length <= maxSerializedMessageBytes ? bytes : null;
		} catch {
			return null;
		}
	};

	for (const batch of tokenIxBatches) {
		const candidate = [...current, ...batch];
		if (trySerialize(candidate) !== null) {
			current = candidate;
		} else {
			pushCurrent();
			const fresh = [...current, ...batch];
			if (trySerialize(fresh) === null) {
				throw new Error(
					'buildSweepBundle: a single token transfer batch exceeds the tx size limit',
				);
			}
			current = fresh;
		}
	}

	const withSol = [...current, finalSolIx];
	if (trySerialize(withSol) !== null) {
		current = withSol;
	} else {
		pushCurrent();
		current = [...current, finalSolIx];
		if (trySerialize(current) === null) {
			throw new Error('buildSweepBundle: final SOL transfer alone exceeds tx size limit');
		}
	}
	pushCurrent();

	if (messages.length === 0) {
		throw new Error('buildSweepBundle: produced empty bundle');
	}
	return messages;
}

/** Helpers for the broadcast side: deserialize a message back into MessageV0. */
export function deserializeSweepMessage(bytes: Uint8Array): MessageV0 {
	return MessageV0.deserialize(bytes);
}
