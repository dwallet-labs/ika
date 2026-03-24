// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Serial transaction executor for the OWS provider.
 *
 * Wraps Sui's `SerialTransactionExecutor` to prevent gas coin collisions
 * when multiple transactions are submitted concurrently. All transactions
 * are queued and executed sequentially with proper coin management.
 *
 * Returns a normalized result shape used throughout the OWS provider.
 */

import type { Keypair } from '@mysten/sui/cryptography';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { SerialTransactionExecutor, Transaction } from '@mysten/sui/transactions';

/** Normalized event from a transaction result. */
export interface TxEvent {
	type: string;
	parsedJson: unknown;
}

/** Normalized transaction execution result. */
export interface TxResult {
	events: TxEvent[];
	digest: string;
}

/**
 * OWS transaction executor — wraps `SerialTransactionExecutor`.
 *
 * Used by `IkaOWSProvider` and `PresignPool` for all on-chain operations.
 * Guarantees serial execution so gas coins and object inputs never collide.
 */
export class OWSExecutor {
	readonly #executor: SerialTransactionExecutor;

	constructor(client: SuiJsonRpcClient, signer: Keypair) {
		this.#executor = new SerialTransactionExecutor({
			client,
			signer,
			defaultGasBudget: 50_000_000n,
		});
	}

	/**
	 * Execute a transaction and return a normalized result with events.
	 */
	async execute(tx: Transaction): Promise<TxResult> {
		const result = await this.#executor.executeTransaction(tx, { events: true });

		// Result is a discriminated union: { $kind: 'Transaction' | 'FailedTransaction' }
		const txData = result.$kind === 'Transaction' ? result.Transaction : result.FailedTransaction;

		if (result.$kind === 'FailedTransaction') {
			const failed = result.FailedTransaction;
			const err = failed?.status?.error;
			const msg = err
				? (typeof err === 'string' ? err : (err as any).message ?? 'Transaction failed')
				: 'Transaction failed';
			throw new Error(msg);
		}

		if (!txData) {
			throw new Error('Transaction result missing');
		}

		// Map events to the normalized shape.
		// The new SDK uses { type, parsedJson } same as JSON-RPC but nested under Transaction.
		const events: TxEvent[] = (txData.events ?? []).map((e: any) => ({
			type: e.type ?? '',
			parsedJson: e.parsedJson ?? e.parsedJSON ?? e,
		}));

		return {
			events,
			digest: txData.digest,
		};
	}

	/**
	 * Wait for all queued transactions to complete.
	 */
	async flush(): Promise<void> {
		await this.#executor.waitForLastTransaction();
	}

	/**
	 * Reset the internal object cache. Call after epoch changes or
	 * if cached state becomes stale.
	 */
	async resetCache(): Promise<void> {
		await this.#executor.resetCache();
	}
}
