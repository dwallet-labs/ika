// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// End-to-end localnet test: Solana destination + publisher against
// solana-test-validator. Airdrops to the dWallet's derived address, builds
// a self-transfer VersionedTransaction, signs with the destination, and
// broadcasts via the publisher with confirmation polling.

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

import {
	Connection,
	LAMPORTS_PER_SOL,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
} from '@solana/web3.js';

import { Curve } from '@ika.xyz/sdk';
import { solana } from '@ika.xyz/plugins/solana/destination';
import { solanaPublisher } from '@ika.xyz/plugins/solana/publisher';

import { waitForJsonRpc } from './_helpers/chain-ready.js';
import { fakeDWallet, makeFixture, mockSourceContext } from './_helpers/source.js';

const RPC_URL = process.env.SOLANA_RPC_URL ?? 'http://127.0.0.1:8899';

let ready = false;
beforeAll(async () => {
	ready = await waitForJsonRpc(RPC_URL, 'getHealth', 3_000);
	if (!ready) {
		console.warn(
			`solana-test-validator at ${RPC_URL} not reachable. Run \`pnpm localnet:up\``,
		);
	}
}, 5_000);

describe('solana localnet — destination + publisher', () => {
	it(
		'airdrops to the dWallet, signs a self-transfer, broadcasts + confirms',
		async (test) => {
			if (!ready) return test.skip();
			const fixture = makeFixture();
			const publicOutput = fixture.ed25519.publicKey;
			fixtures.set(Array.from(publicOutput).join(','), publicOutput);

			const plugin = solana();
			const ctx = mockSourceContext(fixture);
			await plugin.install?.(ctx);
			const dWallet = fakeDWallet(Curve.ED25519, publicOutput);

			const conn = new Connection(RPC_URL, 'confirmed');
			const payer = new PublicKey(publicOutput);

			// Airdrop 2 SOL to the dWallet's derived address.
			const airdropSig = await conn.requestAirdrop(payer, 2 * LAMPORTS_PER_SOL);
			const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
			await conn.confirmTransaction(
				{ signature: airdropSig, blockhash, lastValidBlockHeight },
				'confirmed',
			);
			const balance = await conn.getBalance(payer, 'confirmed');
			expect(balance).toBeGreaterThanOrEqual(LAMPORTS_PER_SOL);

			// Build a self-transfer.
			const tx = new VersionedTransaction(
				new TransactionMessage({
					payerKey: payer,
					recentBlockhash: blockhash,
					instructions: [
						SystemProgram.transfer({
							fromPubkey: payer,
							toPubkey: payer,
							lamports: 1,
						}),
					],
				}).compileToV0Message(),
			);

			const signed = await plugin.extend.solana.sign({
				dWallet,
				kind: 'transaction',
				tx,
			});
			expect(signed.chain).toBe('solana');
			if (signed.payload.kind !== 'transaction') throw new Error('unreachable');

			const publisher = solanaPublisher({
				connection: conn,
				confirm: true,
				confirmTimeoutMs: 30_000,
				commitment: 'confirmed',
			});
			const sig = await publisher.broadcast({
				chain: 'solana',
				payload: signed.payload,
			});
			expect(typeof sig).toBe('string');
			expect(sig.length).toBeGreaterThan(0);

			const status = await conn.getSignatureStatuses([sig], { searchTransactionHistory: false });
			expect(status.value[0]?.err).toBeNull();
		},
		60_000,
	);
});
