// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// End-to-end localnet test: Ethereum destination + publisher against Anvil.
// The "source" is mocked with a real secp256k1 keypair so the signatures
// the destination assembles are byte-for-byte valid against Anvil's
// state-transition rules.

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// Mock SDK's `publicKeyFromDWalletOutput` to return the fixture's pubkey
// directly. The destination's address derivation goes through this; in
// production it's a WASM call against the dWallet's public output.
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

import { createPublicClient, http, parseEther, type Hex } from 'viem';
import { foundry } from 'viem/chains';

import { Curve } from '@ika.xyz/sdk';
import { eth } from '@ika.xyz/plugins/ethereum/destination';
import { ethPublisher } from '@ika.xyz/plugins/ethereum/publisher';

import { waitForJsonRpc } from './_helpers/chain-ready.js';
import { fakeDWallet, makeFixture, mockSourceContext } from './_helpers/source.js';

const RPC_URL = process.env.ANVIL_URL ?? 'http://127.0.0.1:8545';
const ANVIL_FUNDING_KEY =
	// Anvil's default account 0 — deterministic across runs.
	'0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

let ready = false;

beforeAll(async () => {
	ready = await waitForJsonRpc(RPC_URL, 'eth_chainId', 3_000);
	if (!ready) {
		console.warn(`anvil at ${RPC_URL} not reachable — skipping. Run \`pnpm localnet:up\``);
	}
}, 5_000);

const cleanup: Array<() => void> = [];
afterAll(() => {
	for (const c of cleanup) c();
});

describe('ethereum localnet — destination + publisher', () => {
	it(
		'signs and broadcasts an EIP-1559 self-transfer to anvil',
		async (test) => {
			if (!ready) return test.skip();
			const fixture = makeFixture();
			const publicOutput = fixture.secp256k1.publicKey;
			fixtures.set(Array.from(publicOutput).join(','), publicOutput);

			const plugin = eth();
			const ctx = mockSourceContext(fixture);
			await plugin.install?.(ctx);
			const dWallet = fakeDWallet(Curve.SECP256K1, publicOutput);

			// Anvil exposes a normal RPC; the plugin uses its own viem client.
			const publisher = ethPublisher({
				url: RPC_URL,
				chain: foundry,
				confirm: true,
				confirmations: 1,
				confirmTimeoutMs: 20_000,
			});
			await publisher.install?.(ctx);

			// Derive the dWallet's address, fund it from anvil account 0.
			const dWalletAddress = await plugin.extend.ethereum.getAddress(dWallet);
			const funder = createPublicClient({ chain: foundry, transport: http(RPC_URL) });
			await rpc(RPC_URL, 'anvil_setBalance', [dWalletAddress, '0x56bc75e2d63100000']); // 100 ETH

			const balance = await funder.getBalance({ address: dWalletAddress });
			expect(balance).toBeGreaterThan(parseEther('99'));

			// Build + sign + broadcast a 1-wei self-transfer.
			const nonce = await funder.getTransactionCount({ address: dWalletAddress });
			const signed = await plugin.extend.ethereum.sign({
				dWallet,
				kind: 'transaction',
				tx: {
					type: 'eip1559',
					chainId: foundry.id,
					nonce,
					to: dWalletAddress,
					value: 1n,
					maxFeePerGas: 2_000_000_000n,
					maxPriorityFeePerGas: 1_000_000_000n,
					gas: 21_000n,
				},
			});
			expect(signed.payload.kind).toBe('transaction');
			if (signed.payload.kind !== 'transaction') throw new Error('unreachable');

			const txHash = await publisher.broadcast(
				{ chain: 'ethereum', payload: signed.payload },
				undefined,
			);
			expect(txHash).toMatch(/^0x[0-9a-f]{64}$/);

			const receipt = await funder.getTransactionReceipt({ hash: txHash as Hex });
			expect(receipt.status).toBe('success');
			expect(receipt.from.toLowerCase()).toBe(dWalletAddress.toLowerCase());
		},
		30_000,
	);

	it(
		'EIP-191 personal_sign recovers to the dWallet address',
		async (test) => {
			if (!ready) return test.skip();
			const fixture = makeFixture();
			const publicOutput = fixture.secp256k1.publicKey;
			fixtures.set(Array.from(publicOutput).join(','), publicOutput);

			const plugin = eth();
			const ctx = mockSourceContext(fixture);
			await plugin.install?.(ctx);
			const dWallet = fakeDWallet(Curve.SECP256K1, publicOutput);
			const dWalletAddress = await plugin.extend.ethereum.getAddress(dWallet);

			const { recoverMessageAddress } = await import('viem');
			const signed = await plugin.extend.ethereum.sign({
				dWallet,
				kind: 'message',
				message: new TextEncoder().encode('localnet eth check'),
			});
			if (signed.payload.kind !== 'message') throw new Error('unreachable');

			const recovered = await recoverMessageAddress({
				message: { raw: ('0x' + bytesHex(new TextEncoder().encode('localnet eth check'))) as Hex },
				signature: signed.payload.signature,
			});
			expect(recovered.toLowerCase()).toBe(dWalletAddress.toLowerCase());
		},
		15_000,
	);
});

async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
	});
	const body = (await res.json()) as { result?: unknown; error?: { message: string } };
	if (body.error) throw new Error(`${method} → ${body.error.message}`);
	return body.result;
}

function bytesHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

void ANVIL_FUNDING_KEY;
