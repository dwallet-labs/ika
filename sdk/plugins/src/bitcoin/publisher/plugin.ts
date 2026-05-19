// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import type { PublisherPlugin } from '@ika.xyz/sdk/plugin';

import type {
	BitcoinNetwork,
	BitcoinPublishablePayload,
} from '../destination/types.js';

export interface BitcoinPublisherOptions {
	/**
	 * Esplora-compatible API base URL (mempool.space and blockstream.info
	 * both expose this). Required unless `broadcast` is supplied.
	 */
	readonly apiBaseUrl?: string;
	/**
	 * Override the broadcast function entirely. Use this to plug in a
	 * non-Esplora RPC (e.g. Bitcoin Core's `sendrawtransaction`).
	 */
	readonly broadcast?: (signedTxHex: string, signal?: AbortSignal) => Promise<string>;
	/** Optional override for `fetch` (testing / custom transports). */
	readonly fetch?: typeof fetch;
}

const ESPLORA_DEFAULTS: Record<BitcoinNetwork, string> = {
	mainnet: 'https://blockstream.info/api',
	testnet: 'https://blockstream.info/testnet/api',
	signet: 'https://blockstream.info/signet/api',
	regtest: '', // no public default; caller must supply
};

/** Pick a default Esplora endpoint for `network`. Throws for `regtest`. */
export function defaultEsploraUrl(network: BitcoinNetwork): string {
	const url = ESPLORA_DEFAULTS[network];
	if (!url) {
		throw new Error(
			`bitcoinPublisher: no default Esplora endpoint for '${network}'. Pass \`apiBaseUrl\` explicitly.`,
		);
	}
	return url;
}

/**
 * Broadcasts a signed Bitcoin transaction via an Esplora-compatible
 * `POST /tx` endpoint and returns the txid.
 *
 * The publisher does NOT poll for confirmation — Bitcoin's mempool semantics
 * make "confirmed" a moving target and confirmation depth is application
 * specific. Callers who need depth-aware confirmation should query the
 * Esplora `/tx/:txid/status` endpoint themselves.
 *
 * Payload is constrained to the `psbt` variant; `preimage` payloads are
 * rejected at the type level (no assembled tx to broadcast).
 */
export function bitcoinPublisher(
	opts: BitcoinPublisherOptions,
): PublisherPlugin<'bitcoin', BitcoinPublishablePayload, string> {
	if (!opts.broadcast && !opts.apiBaseUrl) {
		throw new Error(
			'bitcoinPublisher: pass `apiBaseUrl` or `broadcast`. Silent defaults would risk pointing at the wrong network.',
		);
	}
	const fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);

	const defaultBroadcast = async (hex: string, signal?: AbortSignal): Promise<string> => {
		const res = await fetchImpl(`${opts.apiBaseUrl}/tx`, {
			method: 'POST',
			body: hex,
			...(signal ? { signal } : {}),
		});
		if (!res.ok) {
			const body = await res.text().catch(() => '<no body>');
			throw new Error(
				`bitcoinPublisher: POST /tx returned ${res.status} ${res.statusText}: ${body}`,
			);
		}
		const txid = (await res.text()).trim();
		if (!/^[0-9a-f]{64}$/i.test(txid)) {
			throw new Error(`bitcoinPublisher: POST /tx returned non-txid response: ${txid}`);
		}
		return txid;
	};
	const broadcast = opts.broadcast ?? defaultBroadcast;

	return {
		kind: 'publisher',
		chain: 'bitcoin',
		async broadcast(signed, broadcastOpts) {
			if (broadcastOpts?.signal?.aborted) {
				throw new DOMException('publish aborted', 'AbortError');
			}
			const txid = await broadcast(signed.payload.signedTxHex, broadcastOpts?.signal);
			if (txid && signed.payload.txid && txid.toLowerCase() !== signed.payload.txid.toLowerCase()) {
				// Esplora echoes the txid; if it disagrees with the locally-computed
				// one, something corrupted the wire format. Surface the mismatch
				// instead of returning a misleading id.
				throw new Error(
					`bitcoinPublisher: broadcast txid '${txid}' does not match locally-computed '${signed.payload.txid}'`,
				);
			}
			return txid || signed.payload.txid;
		},
	};
}
