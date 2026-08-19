import {
	buildSweepBundle,
	previewMessageBytes,
	SOLANA_SIGNATURE_FEE_LAMPORTS,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
	SOLANA_TX_SIZE_LIMIT,
} from '@fesal-packages/ikavery-core';
import { getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { Keypair, PublicKey, SystemProgram } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

const SOURCE = Keypair.generate().publicKey;
const DESTINATION = Keypair.generate().publicKey;
const FAKE_BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

function fakeTokenAccount(seed: number) {
	const mint = new PublicKey(Buffer.alloc(32, seed));
	const tokenAccount = getAssociatedTokenAddressSync(mint, SOURCE, true, TOKEN_PROGRAM_ID);
	return {
		mint,
		tokenAccount,
		amount: BigInt(1_000 * (seed + 1)),
		decimals: 6,
		programId: TOKEN_PROGRAM_ID,
	};
}

describe('buildSweepBundle', () => {
	test('SOL-only sweep produces a single tx with one SystemProgram.transfer', () => {
		const reserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT;
		const messages = buildSweepBundle({
			source: SOURCE,
			destination: DESTINATION,
			solBalance: 5_000_000n,
			feeReserveLamports: reserve,
			tokenAccounts: [],
			recentBlockhash: FAKE_BLOCKHASH,
		});
		expect(messages.length).toBe(1);
		const preview = previewMessageBytes(messages);
		expect(preview.txCount).toBe(1);
		expect(preview.totalLamportsTransferred).toBe(
			5_000_000n - reserve - SOLANA_SIGNATURE_FEE_LAMPORTS * BigInt(messages.length),
		);

		const sysIxs = preview.txs[0]!.instructions.filter((i) => i.kind === 'system-transfer');
		expect(sysIxs.length).toBe(1);
		expect((sysIxs[0]! as { kind: 'system-transfer'; from: string }).from).toBe(SOURCE.toBase58());
	});

	test('packs multiple SPL transfers across txs and aggregates per-mint totals', () => {
		const reserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT;
		const tokenAccounts = Array.from({ length: 12 }, (_, i) => fakeTokenAccount(i));
		const messages = buildSweepBundle({
			source: SOURCE,
			destination: DESTINATION,
			solBalance: 10_000_000n,
			feeReserveLamports: reserve,
			tokenAccounts,
			recentBlockhash: FAKE_BLOCKHASH,
		});
		expect(messages.length).toBeGreaterThan(1);
		for (const m of messages) {
			// +65 for one signature; same constraint as the builder enforces.
			expect(m.length + 65).toBeLessThanOrEqual(SOLANA_TX_SIZE_LIMIT);
		}
		const preview = previewMessageBytes(messages);

		const splTransfers = preview.txs
			.flatMap((t) => t.instructions)
			.filter((i) => i.kind === 'spl-transfer-checked');
		expect(splTransfers.length).toBe(tokenAccounts.length);

		const expectedTotal = tokenAccounts.reduce((s, t) => s + t.amount, 0n);
		const splTotal = preview.totalSplTransferred.reduce((s, e) => s + e.amount, 0n);
		expect(splTotal).toBe(expectedTotal);

		expect(preview.totalLamportsTransferred).toBe(
			10_000_000n - reserve - SOLANA_SIGNATURE_FEE_LAMPORTS * BigInt(messages.length),
		);
	});

	test('rejects non-positive sweep amount', () => {
		expect(() =>
			buildSweepBundle({
				source: SOURCE,
				destination: DESTINATION,
				solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT - 1n,
				feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
				tokenAccounts: [],
				recentBlockhash: FAKE_BLOCKHASH,
			}),
		).toThrow(/sweep amount non-positive/);
	});

	test('rejects feeReserveLamports below rent-exempt minimum', () => {
		expect(() =>
			buildSweepBundle({
				source: SOURCE,
				destination: DESTINATION,
				solBalance: 5_000_000n,
				feeReserveLamports: 5_000n,
				tokenAccounts: [],
				recentBlockhash: FAKE_BLOCKHASH,
			}),
		).toThrow(/below rent-exempt minimum/);
	});

	test('preview decodes destination matches Solana transfer ix', () => {
		const messages = buildSweepBundle({
			source: SOURCE,
			destination: DESTINATION,
			solBalance: 5_000_000n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: FAKE_BLOCKHASH,
		});
		const preview = previewMessageBytes(messages);
		const transfer = preview.txs[0]!.instructions.find((i) => i.kind === 'system-transfer') as {
			kind: 'system-transfer';
			from: string;
			to: string;
		};
		expect(transfer.from).toBe(SOURCE.toBase58());
		expect(transfer.to).toBe(DESTINATION.toBase58());
	});

	test('preview tags SystemProgram correctly', () => {
		// sanity check that we recognize the runtime program id
		expect(SystemProgram.programId.toBase58()).toBe('11111111111111111111111111111111');
	});
});
