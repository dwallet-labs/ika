// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import {
	createPublicClient,
	http,
	type Chain,
	type Hex,
	type PublicClient,
	type Transport,
} from 'viem';
import type { PublisherPlugin } from '@ika.xyz/sdk/plugin';

import type { EthereumPublishablePayload } from '../destination/types.js';

export interface EthereumPublisherOptions {
	/** Pre-built viem PublicClient. Takes precedence over `url`. */
	readonly client?: PublicClient;
	/** RPC URL. Required if `client` is not supplied. */
	readonly url?: string;
	/** Optional chain config (for typed clients). Passed to `createPublicClient`. */
	readonly chain?: Chain;
	/** Optional transport. Overrides `url`-based http transport. */
	readonly transport?: Transport;
	/** Await on-chain confirmation before resolving. */
	readonly confirm?: boolean;
	/** Number of confirmations to wait for (only when `confirm: true`). */
	readonly confirmations?: number;
	/**
	 * Hard ceiling on confirmation polling, in milliseconds. Defaults to
	 * 120_000 (2 minutes). Bounds the loop so a stalled tx does not hang
	 * `broadcast()` indefinitely. On timeout, throws with the tx hash in the
	 * message so the caller can verify on chain manually.
	 */
	readonly confirmTimeoutMs?: number;
}

const DEFAULT_CONFIRM_TIMEOUT_MS = 120_000;

/**
 * Broadcasts a signed Ethereum transaction via viem's `eth_sendRawTransaction`
 * and returns the tx hash. When `confirm` is set, waits for the configured
 * confirmation depth (default 1) before resolving.
 *
 * Payload is constrained to the `transaction` variant; message / typedData
 * payloads are rejected at the type level (they are not broadcastable).
 *
 * Requires at least one of `url`, `transport`, or `client`. Passing none
 * throws so the publisher cannot silently point at a default endpoint.
 */
export function ethPublisher(
	opts: EthereumPublisherOptions,
): PublisherPlugin<'ethereum', EthereumPublishablePayload, Hex> {
	if (!opts.client && !opts.url && !opts.transport) {
		throw new Error(
			'ethPublisher: pass at least one of `client`, `url`, or `transport`. ' +
				'Silent default endpoints can produce mainnet/testnet mismatches.',
		);
	}
	const client: PublicClient =
		opts.client ??
		createPublicClient({
			...(opts.chain ? { chain: opts.chain } : {}),
			transport: opts.transport ?? http(opts.url),
		});
	const confirmTimeoutMs = opts.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
	const confirmations = opts.confirmations ?? 1;

	return {
		kind: 'publisher',
		chain: 'ethereum',
		async broadcast(signed, broadcastOpts) {
			if (broadcastOpts?.signal?.aborted) {
				throw new DOMException('publish aborted', 'AbortError');
			}
			const txHash = await client.sendRawTransaction({
				serializedTransaction: signed.payload.serialized,
			});
			if (opts.confirm) {
				await waitForReceipt(
					client,
					txHash,
					confirmations,
					confirmTimeoutMs,
					broadcastOpts?.signal,
				);
			}
			return txHash;
		},
	};
}

/**
 * Wraps viem's `waitForTransactionReceipt` with a hard timeout and an
 * `AbortSignal`. viem's own `timeout` option is per-poll; without a deadline
 * a network that keeps producing blocks but never includes the tx will spin
 * forever. Rejection on timeout includes the tx hash so callers can verify
 * on chain manually.
 */
async function waitForReceipt(
	client: PublicClient,
	hash: Hex,
	confirmations: number,
	timeoutMs: number,
	signal: AbortSignal | undefined,
): Promise<void> {
	const deadline = new Promise<never>((_, reject) => {
		const t = setTimeout(() => {
			reject(
				new Error(
					`ethPublisher: confirmation timeout (${timeoutMs}ms) for transaction ${hash}. ` +
						`The tx may still be valid; check the chain manually via the hash.`,
				),
			);
		}, timeoutMs);
		signal?.addEventListener(
			'abort',
			() => {
				clearTimeout(t);
				reject(new DOMException('publish aborted', 'AbortError'));
			},
			{ once: true },
		);
	});
	const receipt = client.waitForTransactionReceipt({ hash, confirmations });
	await Promise.race([receipt, deadline]);
}
