import { MessageV0, VersionedTransaction, type Connection } from '@solana/web3.js';

/**
 * Pair a serialized message with its 64-byte ed25519 signature into a
 * fully-signed `VersionedTransaction` and return the wire bytes.
 *
 * The dWallet signs the message bytes verbatim — we just glue the resulting
 * signature onto the front of the transaction envelope.
 */
export function assembleSignedTransaction(
	messageBytes: Uint8Array,
	signature: Uint8Array,
): Uint8Array {
	if (signature.length !== 64) {
		throw new Error(
			`assembleSignedTransaction: expected 64-byte signature, got ${signature.length}`,
		);
	}
	const msg = MessageV0.deserialize(messageBytes);
	const tx = new VersionedTransaction(msg);
	tx.signatures = [signature];
	return tx.serialize();
}

export interface BroadcastResult {
	txIndex: number;
	/** Solana transaction signature on success, or null on failure. */
	signature: string | null;
	error?: unknown;
}

/**
 * Send each signed transaction and collect per-tx outcome. Failures don't
 * abort the rest — the caller decides what to do (retry, alert, partial-success).
 */
export async function broadcastSignedTransactions(
	connection: Connection,
	signedTxs: Uint8Array[],
	opts: { skipPreflight?: boolean; maxRetries?: number } = {},
): Promise<BroadcastResult[]> {
	const out: BroadcastResult[] = [];
	for (let i = 0; i < signedTxs.length; i++) {
		try {
			const sig = await connection.sendRawTransaction(signedTxs[i]!, {
				skipPreflight: opts.skipPreflight ?? false,
				maxRetries: opts.maxRetries,
			});
			out.push({ txIndex: i, signature: sig });
		} catch (e) {
			out.push({ txIndex: i, signature: null, error: e });
		}
	}
	return out;
}
