// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// End-to-end localnet test: Sui destination + publisher against `sui start`
// (local single-validator + faucet). Funds the dWallet's derived Sui address
// via the faucet, builds a SUI self-transfer, signs through the destination,
// and broadcasts via the publisher.

import { beforeAll, describe, expect, it, vi } from 'vitest';

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

import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Transaction } from '@mysten/sui/transactions';

import { Curve } from '@ika.xyz/sdk';
import { sui as suiDestination } from '@ika.xyz/plugins/sui/destination';
import { suiPublisher } from '@ika.xyz/plugins/sui/publisher';

import { waitForJsonRpc } from './_helpers/chain-ready.js';
import { fakeDWallet, makeFixture, mockSourceContext } from './_helpers/source.js';

const SUI_RPC = process.env.SUI_LOCALNET_URL ?? 'http://127.0.0.1:9000';
const FAUCET_URL = process.env.SUI_FAUCET_URL ?? 'http://127.0.0.1:9123/v2/gas';

let ready = false;
beforeAll(async () => {
	ready = await waitForJsonRpc(SUI_RPC, 'sui_getChainIdentifier', 3_000);
	if (!ready) {
		console.warn(`sui localnet at ${SUI_RPC} not reachable. Run \`pnpm localnet:up\``);
	}
}, 5_000);

describe('sui localnet — destination + publisher', () => {
	it(
		'faucets to the dWallet, signs a Sui tx, broadcasts via the publisher',
		async (test) => {
			if (!ready) return test.skip();
			const fixture = makeFixture();
			const publicOutput = fixture.ed25519.publicKey;
			fixtures.set(Array.from(publicOutput).join(','), publicOutput);

			const plugin = suiDestination();
			const ctx = mockSourceContext(fixture);
			await plugin.install?.(ctx);
			const dWallet = fakeDWallet(Curve.ED25519, publicOutput);

			const suiClient = new SuiJsonRpcClient({ url: SUI_RPC, network: 'localnet' });
			const dWalletAddress = await plugin.extend.sui.getAddress(dWallet);

			// Faucet 100 SUI to the dWallet address. Sui's faucet HTTP API is
			// `POST /v2/gas` with `{FixedAmountRequest: {recipient}}`.
			const faucetRes = await fetch(FAUCET_URL, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					FixedAmountRequest: { recipient: dWalletAddress },
				}),
			});
			if (!faucetRes.ok) {
				throw new Error(`faucet returned ${faucetRes.status}: ${await faucetRes.text()}`);
			}

			// Wait for the gas coin to be indexed.
			let gasCoin: { coinObjectId: string; balance: string } | undefined;
			for (let i = 0; i < 30; i++) {
				const coins = await suiClient.core.getCoins({ owner: dWalletAddress });
				if (coins.data.length > 0) {
					gasCoin = coins.data[0];
					break;
				}
				await new Promise((r) => setTimeout(r, 500));
			}
			expect(gasCoin).toBeDefined();

			// Build a self-transfer of 1 MIST.
			const tx = new Transaction();
			tx.setSender(dWalletAddress);
			const [coin] = tx.splitCoins(tx.gas, [1]);
			tx.transferObjects([coin], dWalletAddress);

			const signed = await plugin.extend.sui.sign({
				dWallet,
				kind: 'transaction',
				tx,
				suiClient,
			});
			expect(signed.chain).toBe('sui');
			expect(signed.payload.sender).toBe(dWalletAddress);

			const publisher = suiPublisher({ suiClient });
			const digest = await publisher.broadcast({
				chain: 'sui',
				payload: signed.payload,
			});
			expect(digest).toMatch(/^[A-Za-z0-9]+$/);
		},
		90_000,
	);
});
