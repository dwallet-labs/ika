// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { PublisherPlugin } from '@ika.xyz/sdk/plugin';
import { Connection } from '@solana/web3.js';
import type { Commitment, SendOptions } from '@solana/web3.js';

import type { SolanaPublishablePayload } from '../destination/types.js';

export interface SolanaPublisherOptions {
	/** RPC endpoint, e.g. 'https://api.mainnet-beta.solana.com'. Ignored if `connection` is provided. */
	readonly url?: string;
	/** Pre-built connection. Overrides `url`. */
	readonly connection?: Connection;
	/** Commitment used when building the default connection. */
	readonly commitment?: Commitment;
	/** Forwarded to `Connection.sendRawTransaction` (skipPreflight, maxRetries, etc.). */
	readonly sendOptions?: SendOptions;
	/** Await on-chain confirmation before resolving. */
	readonly confirm?: boolean;
	/**
	 * Hard ceiling on confirmation polling, in milliseconds. Defaults to 180_000
	 * (3 minutes). Bounds the loop in case an RPC reports `isBlockhashValid` as
	 * true past the real validity window. On timeout, `broadcast()` throws with
	 * the signature in the message so the caller can verify on chain manually.
	 */
	readonly confirmTimeoutMs?: number;
}

const DEFAULT_CONFIRM_TIMEOUT_MS = 180_000;

/**
 * Broadcasts a Solana transaction. Returns the base58 signature. When `confirm`
 * is set, awaits the configured commitment before resolving.
 *
 * The payload is constrained to the `transaction` variant; broadcasting a
 * message-mode payload is a compile-time error.
 *
 * Requires at least one of `url` or `connection`; passing neither throws so the
 * publisher cannot silently point at the wrong cluster.
 */
export function solanaPublisher(
	opts: SolanaPublisherOptions,
): PublisherPlugin<'solana', SolanaPublishablePayload, string> {
	if (!opts.connection && !opts.url) {
		throw new Error(
			'solanaPublisher: pass at least one of `url` or `connection`. ' +
				'Use `solanaMainnet()` / `solanaDevnet()` / `solanaTestnet()` for the official endpoints.',
		);
	}
	const conn = opts.connection ?? new Connection(opts.url as string, opts.commitment);
	const confirmTimeoutMs = opts.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
	return {
		kind: 'publisher',
		chain: 'solana',
		async broadcast(signed, broadcastOpts) {
			if (broadcastOpts?.signal?.aborted) {
				throw new DOMException('publish aborted', 'AbortError');
			}
			const tx = signed.payload.transaction;
			// Confirmation must be tied to the blockhash the tx was actually
			// signed with, not a freshly-fetched one. Otherwise the loop waits
			// past the real validity window or expires prematurely.
			const txBlockhash = tx.message.recentBlockhash;
			const wire = tx.serialize();
			const sig = await conn.sendRawTransaction(wire, opts.sendOptions);
			// Some RPCs return "" on a 200; reject explicitly to avoid hanging in confirmation.
			if (!sig || typeof sig !== 'string') {
				throw new Error(
					`solana publisher: sendRawTransaction returned an empty/invalid signature ` +
						`(got ${JSON.stringify(sig)}). RPC may be misbehaving.`,
				);
			}
			if (opts.confirm) {
				await confirmWithBlockhashExpiry(
					conn,
					sig,
					txBlockhash,
					opts.commitment,
					confirmTimeoutMs,
					broadcastOpts?.signal,
				);
			}
			return sig;
		},
	};
}

/**
 * Polls `getSignatureStatuses` and uses `isBlockhashValid` on the transaction's
 * own blockhash as the expiry signal. Resolves on the first matching commitment
 * status. Rejects on chain error, on blockhash expiry, on hard timeout, or on
 * signal abort.
 *
 * Why custom: the `confirmTransaction(sig, commitment)` overload in @solana/web3.js
 * polls without an upper bound, and the `{blockhash, lastValidBlockHeight}`
 * strategy requires `lastValidBlockHeight`, which the publisher does not have
 * (the tx was signed upstream and only the blockhash is on the wire).
 */
async function confirmWithBlockhashExpiry(
	conn: Connection,
	signature: string,
	blockhash: string,
	commitment: Commitment | undefined,
	timeoutMs: number,
	signal: AbortSignal | undefined,
): Promise<void> {
	const POLL_INTERVAL_MS = 500;
	const wantedStatuses: ReadonlyArray<string> =
		commitment === 'finalized' ? ['finalized'] : ['confirmed', 'finalized'];
	const deadline = Date.now() + timeoutMs;
	while (true) {
		if (signal?.aborted) {
			throw new DOMException('publish aborted', 'AbortError');
		}
		if (Date.now() >= deadline) {
			throw new Error(
				`solana publisher: confirmation timeout (${timeoutMs}ms) for transaction ${signature}. ` +
					`The blockhash may still be valid; check the chain manually via the signature.`,
			);
		}
		const status = await conn.getSignatureStatuses([signature]);
		const s = status.value[0];
		if (s?.err) {
			throw new Error(
				`solana publisher: transaction ${signature} failed on chain: ${JSON.stringify(s.err)}`,
			);
		}
		if (s?.confirmationStatus && wantedStatuses.includes(s.confirmationStatus)) {
			return;
		}
		const valid = await conn.isBlockhashValid(blockhash, commitment ? { commitment } : undefined);
		if (!valid.value) {
			throw new Error(
				`solana publisher: transaction ${signature} did not reach '${commitment ?? 'confirmed'}' ` +
					`before its blockhash ${blockhash} expired. The tx may have been dropped.`,
			);
		}
		await abortableSleep(POLL_INTERVAL_MS, signal);
	}
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		if (signal?.aborted) {
			reject(new DOMException('publish aborted', 'AbortError'));
			return;
		}
		const t = setTimeout(() => {
			signal?.removeEventListener('abort', onAbort);
			resolve();
		}, ms);
		const onAbort = () => {
			clearTimeout(t);
			reject(new DOMException('publish aborted', 'AbortError'));
		};
		signal?.addEventListener('abort', onAbort, { once: true });
	});
}

// Cluster shortcuts.

export const SOLANA_MAINNET_URL = 'https://api.mainnet-beta.solana.com';
export const SOLANA_DEVNET_URL = 'https://api.devnet.solana.com';
export const SOLANA_TESTNET_URL = 'https://api.testnet.solana.com';

export const solanaMainnet = (
	opts?: Omit<SolanaPublisherOptions, 'url'>,
): PublisherPlugin<'solana', SolanaPublishablePayload, string> =>
	solanaPublisher({ url: SOLANA_MAINNET_URL, ...opts });

export const solanaDevnet = (
	opts?: Omit<SolanaPublisherOptions, 'url'>,
): PublisherPlugin<'solana', SolanaPublishablePayload, string> =>
	solanaPublisher({ url: SOLANA_DEVNET_URL, ...opts });

export const solanaTestnet = (
	opts?: Omit<SolanaPublisherOptions, 'url'>,
): PublisherPlugin<'solana', SolanaPublishablePayload, string> =>
	solanaPublisher({ url: SOLANA_TESTNET_URL, ...opts });
