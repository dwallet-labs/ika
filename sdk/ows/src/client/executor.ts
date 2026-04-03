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
	readonly #client: SuiJsonRpcClient;

	constructor(client: SuiJsonRpcClient, signer: Keypair) {
		this.#client = client;
		this.#executor = new SerialTransactionExecutor({
			client,
			signer,
			defaultGasBudget: 500_000_000n,
		});
	}

	/** Max retries for transient network errors. */
	static readonly #MAX_RETRIES = 3;

	/**
	 * Execute a transaction and return a normalized result with events.
	 * Retries on transient network errors with exponential backoff.
	 */
	async execute(tx: Transaction): Promise<TxResult> {
		return this.#withRetry(() => this.#executeOnce(tx));
	}

	async #executeOnce(tx: Transaction): Promise<TxResult> {
		const result = await this.#executor.executeTransaction(tx, { events: true });

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

		// Map events from the executor's format.
		// The new Sui SDK returns { eventType, bcs, packageId, module, sender }.
		const rawEvents: any[] = txData.events ?? [];

		let events: TxEvent[];

		// Check if we got parsedJson (legacy/JSON-RPC) or BCS (new SDK).
		if (rawEvents.length > 0 && rawEvents[0].parsedJson) {
			// Already parsed — use directly.
			events = rawEvents.map((e: any) => ({
				type: e.type ?? e.eventType ?? '',
				parsedJson: e.parsedJson,
			}));
		} else if (rawEvents.length > 0) {
			// New SDK format — events have BCS, not parsedJson.
			// Fetch parsed events via JSON-RPC with retries for indexer lag.
			events = await this.#fetchParsedEvents(txData.digest, rawEvents);
		} else {
			events = [];
		}

		return {
			events,
			digest: txData.digest,
		};
	}

	/** Fetch parsed events from JSON-RPC, retrying for indexer lag. */
	async #fetchParsedEvents(digest: string, fallbackEvents: any[]): Promise<TxEvent[]> {
		for (let attempt = 0; attempt < 5; attempt++) {
			try {
				const txResponse = await this.#client.getTransactionBlock({
					digest,
					options: { showEvents: true },
				});
				return (txResponse.events ?? []).map((e: any) => ({
					type: e.type ?? '',
					parsedJson: e.parsedJson ?? {},
				}));
			} catch {
				// Indexer not ready — wait and retry.
				if (attempt < 4) {
					await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
				}
			}
		}
		// Fallback: return raw events with eventType field.
		return fallbackEvents.map((e: any) => ({
			type: e.eventType ?? e.type ?? '',
			parsedJson: e,
		}));
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

	/** Retry a function on transient network errors with exponential backoff. */
	async #withRetry<T>(fn: () => Promise<T>): Promise<T> {
		let lastError: unknown;
		for (let attempt = 0; attempt <= OWSExecutor.#MAX_RETRIES; attempt++) {
			try {
				return await fn();
			} catch (err: unknown) {
				lastError = err;
				const msg = err instanceof Error ? err.message : String(err);
				const isTransient =
					msg.includes('ECONNRESET') ||
					msg.includes('fetch failed') ||
					msg.includes('Network error') ||
					msg.includes('Too Many Requests') ||
					msg.includes('429') ||
					msg.includes('503') ||
					msg.includes('ETIMEDOUT');

				if (!isTransient || attempt === OWSExecutor.#MAX_RETRIES) throw err;

				const delay = 1000 * 2 ** attempt; // 1s, 2s, 4s
				await new Promise((r) => setTimeout(r, delay));
			}
		}
		throw lastError;
	}
}
