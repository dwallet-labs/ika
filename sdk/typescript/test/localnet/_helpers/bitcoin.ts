// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Thin JSON-RPC client + helpers for a bitcoind regtest container. Keeps
 * the test files focused on the plugin flow; the chain-management noise
 * lives here.
 */

const DEFAULT_RPC_URL = 'http://test:test@127.0.0.1:18443/';

export interface UnspentEntry {
	readonly txid: string;
	readonly vout: number;
	readonly amount: number; // BTC
	readonly height?: number;
	readonly scriptPubKey: string;
}

export interface BitcoinRegtest {
	readonly rpcUrl: string;
	rpc(method: string, params?: unknown[]): Promise<unknown>;
	/** Wallet-scoped JSON-RPC (POSTs to `/wallet/<name>`). */
	walletRpc(wallet: string, method: string, params?: unknown[]): Promise<unknown>;
	/** Make sure a wallet named `name` exists and is loaded. Idempotent. */
	ensureWallet(name: string): Promise<void>;
	/** Generate `n` blocks to a wallet-owned address; useful for confirming + maturing coinbase. */
	mine(blocks: number, walletName?: string): Promise<string[]>;
	/** Top up the wallet's spendable balance by mining 101 blocks to it. */
	primeWallet(walletName: string): Promise<void>;
	/** Send `amountBtc` from `walletName` to `address`; returns the txid. */
	send(walletName: string, address: string, amountBtc: number): Promise<string>;
	/** Scan the UTXO set for entries that match the descriptor of `address`. */
	scanUtxos(address: string): Promise<UnspentEntry[]>;
	/** Raw tx hex for a given txid. */
	getRawTx(txid: string): Promise<string>;
	/** Broadcast a serialized signed tx and return its txid. */
	sendRawTransaction(hex: string): Promise<string>;
}

export function bitcoinRegtest(rpcUrl: string = DEFAULT_RPC_URL): BitcoinRegtest {
	// Node 20+ rejects `fetch(url)` when `url` embeds credentials. Strip
	// userinfo and put it in an `Authorization: Basic ...` header instead.
	const parsed = new URL(rpcUrl);
	const auth =
		parsed.username || parsed.password
			? `Basic ${Buffer.from(
					`${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`,
				).toString('base64')}`
			: undefined;
	parsed.username = '';
	parsed.password = '';
	const cleanUrl = parsed.toString();

	const baseHeaders: Record<string, string> = { 'content-type': 'application/json' };
	if (auth) baseHeaders.authorization = auth;

	const rpc = async (method: string, params: unknown[] = []): Promise<unknown> => {
		const res = await fetch(cleanUrl, {
			method: 'POST',
			headers: baseHeaders,
			body: JSON.stringify({ jsonrpc: '1.0', id: 'test', method, params }),
		});
		const body = (await res.json()) as { result?: unknown; error?: { message: string } };
		if (body.error) throw new Error(`bitcoind ${method}: ${body.error.message}`);
		return body.result;
	};
	const walletRpc = async (
		wallet: string,
		method: string,
		params: unknown[] = [],
	): Promise<unknown> => {
		const url = cleanUrl.replace(/\/?$/, `/wallet/${encodeURIComponent(wallet)}`);
		const res = await fetch(url, {
			method: 'POST',
			headers: baseHeaders,
			body: JSON.stringify({ jsonrpc: '1.0', id: 'test', method, params }),
		});
		const body = (await res.json()) as { result?: unknown; error?: { message: string } };
		if (body.error) throw new Error(`bitcoind (wallet ${wallet}) ${method}: ${body.error.message}`);
		return body.result;
	};

	return {
		rpcUrl,
		rpc,
		walletRpc,
		async ensureWallet(name) {
			try {
				await rpc('createwallet', [name]);
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				if (/already exists/i.test(msg)) {
					try {
						await rpc('loadwallet', [name]);
					} catch (loadErr) {
						const loadMsg = loadErr instanceof Error ? loadErr.message : String(loadErr);
						if (!/already loaded/i.test(loadMsg)) throw loadErr;
					}
				} else if (/already loaded/i.test(msg)) {
					// already loaded — fine
				} else {
					throw err;
				}
			}
		},
		async mine(blocks, walletName = 'localnet') {
			const addr = (await walletRpc(walletName, 'getnewaddress', [])) as string;
			return (await rpc('generatetoaddress', [blocks, addr])) as string[];
		},
		async primeWallet(walletName) {
			// 101 blocks for coinbase maturity.
			const addr = (await walletRpc(walletName, 'getnewaddress', [])) as string;
			await rpc('generatetoaddress', [101, addr]);
		},
		async send(walletName, address, amountBtc) {
			return (await walletRpc(walletName, 'sendtoaddress', [address, amountBtc])) as string;
		},
		async scanUtxos(address) {
			const desc = `addr(${address})`;
			const res = (await rpc('scantxoutset', ['start', [desc]])) as {
				unspents: Array<{
					txid: string;
					vout: number;
					amount: number;
					height: number;
					scriptPubKey: string;
				}>;
			};
			return res.unspents;
		},
		async getRawTx(txid) {
			return (await rpc('getrawtransaction', [txid, false])) as string;
		},
		async sendRawTransaction(hex) {
			return (await rpc('sendrawtransaction', [hex])) as string;
		},
	};
}
