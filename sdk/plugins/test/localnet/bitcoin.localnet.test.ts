// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// End-to-end localnet test: Bitcoin destination + publisher against
// bitcoind in regtest. Funds a P2WPKH and a P2TR script-path UTXO, builds
// each spend through the plugin, broadcasts via bitcoind RPC, and mines a
// block to confirm.

import * as ecc from '@bitcoinerlab/secp256k1';
import { btc } from '@ika.xyz/plugins/bitcoin/destination';
import { bitcoinPublisher } from '@ika.xyz/plugins/bitcoin/publisher';
import { Curve } from '@ika.xyz/sdk';
import * as bitcoin from 'bitcoinjs-lib';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import { bitcoinRegtest } from './_helpers/bitcoin.js';
import { fakeDWallet, makeFixture, mockSourceContext } from './_helpers/source.js';

const fixtures = new Map<string, Uint8Array>();
vi.mock('@ika.xyz/sdk', async () => {
	const actual = await vi.importActual<typeof import('@ika.xyz/sdk')>('@ika.xyz/sdk');
	return {
		...actual,
		publicKeyFromDWalletOutput: vi.fn(async (_curve: unknown, bytes: Uint8Array) => {
			const hit = fixtures.get(Array.from(bytes).join(','));
			if (!hit) throw new Error('no registered pubkey');
			return hit;
		}),
	};
});

bitcoin.initEccLib(ecc as Parameters<typeof bitcoin.initEccLib>[0]);

const RPC_URL = process.env.BITCOIN_RPC_URL ?? 'http://test:test@127.0.0.1:18443/';
const WALLET = 'localnet';

let ready = false;
let chain: ReturnType<typeof bitcoinRegtest>;
beforeAll(async () => {
	chain = bitcoinRegtest(RPC_URL);
	try {
		// Short connect-probe before any setup work.
		await Promise.race([
			chain.rpc('getblockchaininfo'),
			new Promise((_, reject) => setTimeout(() => reject(new Error('connect timeout')), 3_000)),
		]);
		await chain.ensureWallet(WALLET);
		await chain.primeWallet(WALLET);
		ready = true;
	} catch (err) {
		console.warn(`bitcoind at ${RPC_URL} not reachable: ${(err as Error).message}`);
	}
}, 60_000);

describe('bitcoin localnet — destination + publisher', () => {
	it('spends a P2WPKH UTXO via the plugin (sign + broadcast + confirm)', async (test) => {
		if (!ready) return test.skip();
		const fixture = makeFixture();
		const publicOutput = fixture.secp256k1.publicKey;
		fixtures.set(Array.from(publicOutput).join(','), publicOutput);

		const plugin = btc();
		await plugin.install?.(mockSourceContext(fixture));
		const dWallet = fakeDWallet(Curve.SECP256K1, publicOutput);

		const dWalletAddress = await plugin.extend.bitcoin.getAddress(dWallet, {
			mode: 'p2wpkh',
			network: 'regtest',
		});

		// Fund the dWallet address with 1 BTC and confirm.
		const fundingTxid = await chain.send(WALLET, dWalletAddress, 1);
		await chain.mine(1);
		const utxos = await chain.scanUtxos(dWalletAddress);
		expect(utxos.length).toBeGreaterThan(0);
		const utxo = utxos[0];

		// Build a PSBT spending the UTXO back to a wallet-owned address.
		const sinkAddress = (await (chain as unknown as { rpc: typeof chain.rpc }).rpc(
			'getnewaddress',
			[],
		)) as string; // not actually used — wallet rpcs need /wallet path
		void sinkAddress;
		const walletAddress = (await fetch(RPC_URL.replace(/\/?$/, `/wallet/${WALLET}`), {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				jsonrpc: '1.0',
				id: 'x',
				method: 'getnewaddress',
				params: [],
			}),
		}).then(async (r) => ((await r.json()) as { result: string }).result)) as string;

		const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
		const valueSats = BigInt(Math.round(utxo.amount * 1e8));
		psbt.addInput({
			hash: Buffer.from(utxo.txid, 'hex').reverse(),
			index: utxo.vout,
			witnessUtxo: {
				script: Buffer.from(utxo.scriptPubKey, 'hex'),
				value: valueSats,
			},
		});
		// Send all but a 200 sat fee.
		psbt.addOutput({
			address: walletAddress,
			value: valueSats - 200n,
		});

		const signed = await plugin.extend.bitcoin.sign({
			dWallet,
			kind: 'psbt',
			psbt,
			inputIndex: 0,
			mode: 'p2wpkh',
			network: 'regtest',
		});
		if (signed.payload.kind !== 'psbt') throw new Error('unreachable');

		// Custom broadcast override: skip Esplora (not running) and use
		// bitcoind's `sendrawtransaction` directly.
		const publisher = bitcoinPublisher({
			apiBaseUrl: 'http://unused',
			broadcast: async (hex) => chain.sendRawTransaction(hex),
		});
		const txid = await publisher.broadcast({
			chain: 'bitcoin',
			payload: signed.payload,
		});
		expect(txid).toMatch(/^[0-9a-f]{64}$/);
		expect(txid).toBe(signed.payload.txid);

		// Mine 1 block to confirm and verify the chain sees the tx.
		await chain.mine(1);
		const rawConfirmed = (await chain.rpc('getrawtransaction', [txid, true])) as {
			confirmations: number;
		};
		expect(rawConfirmed.confirmations).toBeGreaterThan(0);
		void fundingTxid;
	}, 60_000);

	it('spends a P2TR script-path UTXO via the plugin', async (test) => {
		if (!ready) return test.skip();
		const fixture = makeFixture();
		const publicOutput = fixture.secp256k1.publicKey;
		fixtures.set(Array.from(publicOutput).join(','), publicOutput);

		const plugin = btc();
		await plugin.install?.(mockSourceContext(fixture));
		const dWallet = fakeDWallet(Curve.SECP256K1, publicOutput);

		const dWalletAddress = await plugin.extend.bitcoin.getAddress(dWallet, {
			mode: 'p2tr-script',
			network: 'regtest',
		});

		await chain.send(WALLET, dWalletAddress, 0.5);
		await chain.mine(1);
		const utxos = await chain.scanUtxos(dWalletAddress);
		expect(utxos.length).toBeGreaterThan(0);
		const utxo = utxos[0];

		// Build script-path PSBT. The plugin reads `tapLeafScript` from
		// the PSBT to know which leaf is being revealed, so we have to
		// pre-populate the leaf script + control block + internal key.
		const { buildP2trScriptPath } = await import('@ika.xyz/plugins/bitcoin/destination');
		const xOnly = publicOutput.subarray(1);
		const bundle = buildP2trScriptPath(xOnly, 'regtest');

		const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });
		const valueSats = BigInt(Math.round(utxo.amount * 1e8));
		psbt.addInput({
			hash: Buffer.from(utxo.txid, 'hex').reverse(),
			index: utxo.vout,
			witnessUtxo: {
				script: Buffer.from(utxo.scriptPubKey, 'hex'),
				value: valueSats,
			},
			tapInternalKey: bundle.internalPubkey,
			tapLeafScript: [
				{
					leafVersion: bundle.redeem.redeemVersion,
					script: bundle.redeem.output,
					controlBlock: bundle.payment.witness![bundle.payment.witness!.length - 1],
				},
			],
		});
		const walletAddress = (await fetch(RPC_URL.replace(/\/?$/, `/wallet/${WALLET}`), {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				jsonrpc: '1.0',
				id: 'x',
				method: 'getnewaddress',
				params: [],
			}),
		}).then(async (r) => ((await r.json()) as { result: string }).result)) as string;
		psbt.addOutput({ address: walletAddress, value: valueSats - 300n });

		const signed = await plugin.extend.bitcoin.sign({
			dWallet,
			kind: 'psbt',
			psbt,
			inputIndex: 0,
			mode: 'p2tr-script',
			network: 'regtest',
		});
		if (signed.payload.kind !== 'psbt') throw new Error('unreachable');

		const publisher = bitcoinPublisher({
			apiBaseUrl: 'http://unused',
			broadcast: async (hex) => chain.sendRawTransaction(hex),
		});
		const txid = await publisher.broadcast({ chain: 'bitcoin', payload: signed.payload });

		await chain.mine(1);
		const rawConfirmed = (await chain.rpc('getrawtransaction', [txid, true])) as {
			confirmations: number;
		};
		expect(rawConfirmed.confirmations).toBeGreaterThan(0);
	}, 60_000);
});
