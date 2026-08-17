/**
 * Tests for `previewMessages` / `previewMessageBytes` — best-effort human-
 * readable decoder for sweep messages. The decoder recognizes 4 sweep ix
 * shapes (system-transfer, spl-transfer-checked, ata-create-idempotent,
 * spl-close-account), the compute-budget program, and falls back to
 * `unknown`. Coverage targets each branch.
 */

import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import {
	ComputeBudgetProgram,
	Keypair,
	PublicKey as PublicKeyClass,
	SystemProgram,
	TransactionMessage,
	type PublicKey,
	type TransactionInstruction,
} from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import { previewMessageBytes, previewMessages } from '../src/solana/preview';

const ATA_PROGRAM_ID = new PublicKeyClass('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

function build(payer: PublicKey, instructions: TransactionInstruction[]) {
	const blockhash = new PublicKeyClass(new Uint8Array(32).fill(7)).toBase58();
	return new TransactionMessage({
		payerKey: payer,
		recentBlockhash: blockhash,
		instructions,
	}).compileToV0Message();
}

describe('previewMessages', () => {
	test('decodes a single SystemProgram.transfer', () => {
		const from = Keypair.generate().publicKey;
		const to = Keypair.generate().publicKey;
		const msg = build(from, [
			SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 123n }),
		]);
		const preview = previewMessages([msg]);

		expect(preview.txCount).toBe(1);
		expect(preview.totalLamportsTransferred).toBe(123n);
		expect(preview.txs[0]!.instructions.length).toBe(1);
		const ix = preview.txs[0]!.instructions[0]!;
		expect(ix.kind).toBe('system-transfer');
		if (ix.kind !== 'system-transfer') throw new Error();
		expect(ix.from).toBe(from.toBase58());
		expect(ix.to).toBe(to.toBase58());
		expect(ix.lamports).toBe(123n);
		expect(preview.txs[0]!.messageByteLength).toBeGreaterThan(0);
	});

	test('decodes an SPL TransferChecked', () => {
		const payer = Keypair.generate().publicKey;
		const source = Keypair.generate().publicKey;
		const mint = Keypair.generate().publicKey;
		const dest = Keypair.generate().publicKey;
		const authority = Keypair.generate().publicKey;
		// Hand-build to avoid pulling in the heavy SPL ix builder
		const data = new Uint8Array(10);
		data[0] = 12;
		new DataView(data.buffer).setBigUint64(1, 5_000n, true);
		data[9] = 6;
		const ix: TransactionInstruction = {
			programId: TOKEN_PROGRAM_ID,
			keys: [
				{ pubkey: source, isSigner: false, isWritable: true },
				{ pubkey: mint, isSigner: false, isWritable: false },
				{ pubkey: dest, isSigner: false, isWritable: true },
				{ pubkey: authority, isSigner: true, isWritable: false },
			],
			data: Buffer.from(data),
		};
		const msg = build(payer, [ix]);
		const preview = previewMessages([msg]);
		const out = preview.txs[0]!.instructions[0]!;
		expect(out.kind).toBe('spl-transfer-checked');
		if (out.kind !== 'spl-transfer-checked') throw new Error();
		expect(out.amount).toBe(5_000n);
		expect(out.decimals).toBe(6);
		expect(out.programId).toBe(TOKEN_PROGRAM_ID.toBase58());
		expect(preview.totalSplTransferred.length).toBe(1);
		expect(preview.totalSplTransferred[0]!.amount).toBe(5_000n);
	});

	test('aggregates SPL totals across multiple txs (same mint+program)', () => {
		const payer = Keypair.generate().publicKey;
		const mint = Keypair.generate().publicKey;
		function mkSplIx(amount: bigint, decimals: number): TransactionInstruction {
			const data = new Uint8Array(10);
			data[0] = 12;
			new DataView(data.buffer).setBigUint64(1, amount, true);
			data[9] = decimals;
			return {
				programId: TOKEN_PROGRAM_ID,
				keys: [
					{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true },
					{ pubkey: mint, isSigner: false, isWritable: false },
					{ pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true },
					{ pubkey: payer, isSigner: true, isWritable: false },
				],
				data: Buffer.from(data),
			};
		}
		const m1 = build(payer, [mkSplIx(1_000n, 6)]);
		const m2 = build(payer, [mkSplIx(2_500n, 6)]);
		const preview = previewMessages([m1, m2]);
		expect(preview.txCount).toBe(2);
		expect(preview.totalSplTransferred.length).toBe(1);
		expect(preview.totalSplTransferred[0]!.amount).toBe(3_500n);
	});

	test('decodes ATA CreateIdempotent', () => {
		const payer = Keypair.generate().publicKey;
		const ata = Keypair.generate().publicKey;
		const owner = Keypair.generate().publicKey;
		const mint = Keypair.generate().publicKey;
		const ix: TransactionInstruction = {
			programId: ATA_PROGRAM_ID,
			keys: [
				{ pubkey: payer, isSigner: true, isWritable: true },
				{ pubkey: ata, isSigner: false, isWritable: true },
				{ pubkey: owner, isSigner: false, isWritable: false },
				{ pubkey: mint, isSigner: false, isWritable: false },
				{ pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
				{ pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
			],
			data: Buffer.from([1]),
		};
		const out = previewMessages([build(payer, [ix])]).txs[0]!.instructions[0]!;
		expect(out.kind).toBe('spl-create-ata-idempotent');
		if (out.kind !== 'spl-create-ata-idempotent') throw new Error();
		expect(out.payer).toBe(payer.toBase58());
		expect(out.mint).toBe(mint.toBase58());
	});

	test('decodes Token CloseAccount', () => {
		const payer = Keypair.generate().publicKey;
		const account = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const authority = Keypair.generate().publicKey;
		const ix: TransactionInstruction = {
			programId: TOKEN_2022_PROGRAM_ID,
			keys: [
				{ pubkey: account, isSigner: false, isWritable: true },
				{ pubkey: destination, isSigner: false, isWritable: true },
				{ pubkey: authority, isSigner: true, isWritable: false },
			],
			data: Buffer.from([9]),
		};
		const out = previewMessages([build(payer, [ix])]).txs[0]!.instructions[0]!;
		expect(out.kind).toBe('spl-close-account');
		if (out.kind !== 'spl-close-account') throw new Error();
		expect(out.programId).toBe(TOKEN_2022_PROGRAM_ID.toBase58());
	});

	test('compute-budget ix renders as kind=compute-budget', () => {
		const payer = Keypair.generate().publicKey;
		const msg = build(payer, [
			ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
			SystemProgram.transfer({
				fromPubkey: payer,
				toPubkey: Keypair.generate().publicKey,
				lamports: 1n,
			}),
		]);
		const preview = previewMessages([msg]);
		expect(preview.txs[0]!.instructions[0]!.kind).toBe('compute-budget');
		expect(preview.txs[0]!.instructions[1]!.kind).toBe('system-transfer');
	});

	test('unknown program falls back to kind=unknown', () => {
		const payer = Keypair.generate().publicKey;
		const unknown = Keypair.generate().publicKey;
		const ix: TransactionInstruction = {
			programId: unknown,
			keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
			data: Buffer.from([7, 7, 7]),
		};
		const preview = previewMessages([build(payer, [ix])]);
		const out = preview.txs[0]!.instructions[0]!;
		expect(out.kind).toBe('unknown');
		if (out.kind !== 'unknown') throw new Error();
		expect(out.programId).toBe(unknown.toBase58());
		expect(out.data).toEqual([7, 7, 7]);
	});

	test('previewMessageBytes deserializes then previews', () => {
		const payer = Keypair.generate().publicKey;
		const to = Keypair.generate().publicKey;
		const msg = build(payer, [
			SystemProgram.transfer({ fromPubkey: payer, toPubkey: to, lamports: 9n }),
		]);
		const bytes = msg.serialize();
		const preview = previewMessageBytes([bytes]);
		expect(preview.txCount).toBe(1);
		expect(preview.totalLamportsTransferred).toBe(9n);
	});
});
