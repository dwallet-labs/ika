import { buildSweepBundle, SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT } from '@fesal-packages/ikavery-core';
import {
	Keypair,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	type TransactionInstruction,
} from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	extractIntent,
	extractIntents,
	intentHash,
	rebuildSweepFromIntents,
} from '../src/solana/intent';

const fakeBlockhash = (b: number): string => new PublicKey(new Uint8Array(32).fill(b)).toBase58();

describe('extractIntent', () => {
	test('decodes a SystemProgram::Transfer', () => {
		const from = Keypair.generate().publicKey;
		const to = Keypair.generate().publicKey;
		const ix = SystemProgram.transfer({
			fromPubkey: from,
			toPubkey: to,
			lamports: 12345n,
		});
		const msg = new TransactionMessage({
			payerKey: from,
			recentBlockhash: fakeBlockhash(0xab),
			instructions: [ix],
		}).compileToV0Message();
		const intent = extractIntent(msg);
		expect(Array.from(intent.fee_payer)).toEqual(Array.from(from.toBytes()));
		expect(intent.ixs).toHaveLength(1);
		const first = intent.ixs[0]!;
		if (!('SystemTransfer' in first)) throw new Error('expected SystemTransfer');
		expect(Array.from(first.SystemTransfer.from)).toEqual(Array.from(from.toBytes()));
		expect(Array.from(first.SystemTransfer.to)).toEqual(Array.from(to.toBytes()));
		expect(first.SystemTransfer.lamports).toBe(12345n);
	});

	test('rejects unknown program', () => {
		const from = Keypair.generate().publicKey;
		const unknownProgram = Keypair.generate().publicKey;
		const ix: TransactionInstruction = {
			programId: unknownProgram,
			keys: [{ pubkey: from, isSigner: true, isWritable: true }],
			data: Buffer.from([1, 2, 3]),
		};
		const msg = new TransactionMessage({
			payerKey: from,
			recentBlockhash: fakeBlockhash(0xcd),
			instructions: [ix],
		}).compileToV0Message();
		expect(() => extractIntent(msg)).toThrow(/unknown program/);
	});
});

describe('intent hash stability across blockhash refresh', () => {
	test('hash is identical when only blockhash differs', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const sweepA = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x11),
		});
		const sweepB = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x22),
		});
		expect(Array.from(sweepA[0]!)).not.toEqual(Array.from(sweepB[0]!)); // bytes differ

		const hashA = intentHash(extractIntents(sweepA));
		const hashB = intentHash(extractIntents(sweepB));
		expect(Array.from(hashA)).toEqual(Array.from(hashB)); // intent identical
		expect(hashA.length).toBe(32);
	});

	test('hash changes when destination changes', () => {
		const source = Keypair.generate().publicKey;
		const dest1 = Keypair.generate().publicKey;
		const dest2 = Keypair.generate().publicKey;
		const opts = (destination: PublicKey) => ({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x11),
		});
		const a = intentHash(extractIntents(buildSweepBundle(opts(dest1))));
		const b = intentHash(extractIntents(buildSweepBundle(opts(dest2))));
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('hash changes when amount changes', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const opts = (sol: bigint) => ({
			source,
			destination,
			solBalance: sol,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x11),
		});
		const a = intentHash(
			extractIntents(buildSweepBundle(opts(SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n))),
		);
		const b = intentHash(
			extractIntents(buildSweepBundle(opts(SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 3n))),
		);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});
});

describe('rebuildSweepFromIntents', () => {
	test('rebuild then re-extract yields the same intent', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const original = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x11),
		});
		const intents = extractIntents(original);
		const rebuilt = rebuildSweepFromIntents(intents, fakeBlockhash(0xef));
		const reExtracted = extractIntents(rebuilt);

		expect(Array.from(intentHash(intents))).toEqual(Array.from(intentHash(reExtracted)));
	});

	// Regression: previously the AtaCreateIdempotent intent stored the ATA
	// program id (always the same constant) and rebuild passed that as the 5th
	// arg of `createAssociatedTokenAccountIdempotentInstruction` — which expects
	// the *token* program. The result was an instruction with the wrong
	// token_program in its accounts list, causing the runtime to derive a
	// different ATA than the one passed and abort with "Provided seeds do not
	// result in a valid address". This test rebuilds an SPL bundle and asserts
	// the rebuilt CreateIdempotent instruction's token_program account matches
	// the original's, so the runtime ATA derivation will succeed.
	test('SPL bundle round-trip preserves token_program in CreateIdempotent', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const mint = Keypair.generate().publicKey;
		const tokenAccount = Keypair.generate().publicKey;
		const tokenProgram = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
		const original = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT + 5_000n,
			tokenAccounts: [
				{
					mint,
					tokenAccount,
					amount: 1_000n,
					decimals: 6,
					programId: tokenProgram,
				},
			],
			recentBlockhash: fakeBlockhash(0x11),
		});
		const intents = extractIntents(original);
		const ata = intents[0]!.ixs.find((ix) => 'AtaCreateIdempotent' in ix);
		if (!ata || !('AtaCreateIdempotent' in ata)) throw new Error('no ATA ix');
		expect(Array.from(ata.AtaCreateIdempotent.token_program)).toEqual(
			Array.from(tokenProgram.toBytes()),
		);

		// Rebuild and assert intent hash unchanged + the rebuilt MessageV0's ATA
		// CreateIdempotent has token_program at account index 5.
		const rebuilt = rebuildSweepFromIntents(intents, fakeBlockhash(0xef));
		expect(Array.from(intentHash(intents))).toEqual(
			Array.from(intentHash(extractIntents(rebuilt))),
		);
	});
});
