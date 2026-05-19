// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Network } from '@ika.xyz/sdk';
import type { PublisherPlugin } from '@ika.xyz/sdk/plugin';

import type { SuiSignedPayload } from '../destination/types.js';

export interface SuiPublisherOptions {
	readonly suiClient?: SuiJsonRpcClient;
	readonly network?: Network;
	readonly url?: string;
}

/** Broadcasts a SignedTx<'sui', SuiSignedPayload> via the Sui RPC; returns the digest. */
export function suiPublisher(
	opts: SuiPublisherOptions = {},
): PublisherPlugin<'sui', SuiSignedPayload, string> {
	if (opts.network === undefined && opts.suiClient === undefined && opts.url === undefined) {
		throw new Error(
			'suiPublisher: pass at least one of `network`, `suiClient`, or `url`. ' +
				'Silent testnet defaults can produce mainnet/testnet mismatches.',
		);
	}
	const network: Network = opts.network ?? 'testnet';
	const client =
		opts.suiClient ??
		new SuiJsonRpcClient({
			url: opts.url ?? getJsonRpcFullnodeUrl(network),
			network,
		});

	return {
		kind: 'publisher',
		chain: 'sui',
		async broadcast(signed, opts) {
			if (opts?.signal?.aborted) {
				throw new DOMException('publish aborted', 'AbortError');
			}
			const { bytes, signature } = signed.payload;
			// `executeTransaction` does not accept an AbortSignal, so the awaiter
			// is raced against the signal. The underlying request continues in
			// the background; true cancellation requires upstream support.
			const exec = client.core.executeTransaction({
				transaction: bytes,
				signatures: [signature],
			});
			const result = await raceWithSignal(exec, opts?.signal);
			if (!result.Transaction) {
				throw new Error('sui publisher: executeTransaction returned no Transaction payload');
			}
			return result.Transaction.digest;
		},
	};
}

function raceWithSignal<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
	if (!signal) return p;
	if (signal.aborted) {
		return Promise.reject(new DOMException('publish aborted', 'AbortError'));
	}
	return new Promise<T>((resolve, reject) => {
		const onAbort = () => {
			reject(new DOMException('publish aborted', 'AbortError'));
		};
		signal.addEventListener('abort', onAbort, { once: true });
		p.then(
			(v) => {
				signal.removeEventListener('abort', onAbort);
				resolve(v);
			},
			(err) => {
				signal.removeEventListener('abort', onAbort);
				reject(err);
			},
		);
	});
}
