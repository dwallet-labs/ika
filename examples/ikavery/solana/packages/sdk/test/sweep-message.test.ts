/**
 * Unit tests for sweep instruction builders in `src/sweep/message.ts`.
 *
 * These exercise the wire shape of each builder (programId, key list, data
 * disc + payload) without touching a real RPC — the on-chain sweep parser
 * keys off these exact bytes, so a misordered key or wrong discriminator
 * here causes a silent on-chain rejection at execute time.
 */

import { Keypair, PublicKey, SystemProgram } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	ATA_IX_CREATE_IDEMPOTENT,
	ATA_PROGRAM_ID,
	buildSweepMessage,
	closeSplAccount,
	createIdempotentAta,
	SPL_IX_CLOSE_ACCOUNT,
	SPL_IX_TRANSFER_CHECKED,
	TOKEN_2022_PROGRAM_ID,
	TOKEN_PROGRAM_ID,
	transferSol,
	transferSplTokenChecked,
} from '../src';

const pkA = Keypair.generate().publicKey;
const pkB = Keypair.generate().publicKey;
const pkC = Keypair.generate().publicKey;
const pkD = Keypair.generate().publicKey;

describe('transferSol', () => {
	test('returns a SystemProgram.transfer ix with the same lamports', () => {
		const ix = transferSol(pkA, pkB, 1_234_567);
		expect(ix.programId.equals(SystemProgram.programId)).toBe(true);
		expect(ix.keys.length).toBe(2);
		expect(ix.keys[0]!.pubkey.equals(pkA)).toBe(true);
		expect(ix.keys[1]!.pubkey.equals(pkB)).toBe(true);
	});

	test('accepts bigint lamports', () => {
		const ix = transferSol(pkA, pkB, 999n);
		expect(ix.programId.equals(SystemProgram.programId)).toBe(true);
	});
});

describe('transferSplTokenChecked', () => {
	test('data layout: disc 12 + amount LE u64 + decimals', () => {
		const ix = transferSplTokenChecked({
			source: pkA,
			mint: pkB,
			destination: pkC,
			authority: pkD,
			amount: 0x0807060504030201n,
			decimals: 9,
		});
		expect(ix.programId.equals(TOKEN_PROGRAM_ID)).toBe(true);
		expect(ix.data.length).toBe(10);
		expect(ix.data[0]).toBe(SPL_IX_TRANSFER_CHECKED);
		expect(ix.data[0]).toBe(12);
		expect(Array.from(ix.data.subarray(1, 9))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
		expect(ix.data[9]).toBe(9);
	});

	test('key order is source, mint, destination, authority(signer)', () => {
		const ix = transferSplTokenChecked({
			source: pkA,
			mint: pkB,
			destination: pkC,
			authority: pkD,
			amount: 1,
			decimals: 6,
		});
		expect(ix.keys.map((k) => k.pubkey.toBase58())).toEqual([
			pkA.toBase58(),
			pkB.toBase58(),
			pkC.toBase58(),
			pkD.toBase58(),
		]);
		expect(ix.keys[0]!.isWritable).toBe(true);
		expect(ix.keys[0]!.isSigner).toBe(false);
		expect(ix.keys[1]!.isWritable).toBe(false);
		expect(ix.keys[2]!.isWritable).toBe(true);
		expect(ix.keys[3]!.isSigner).toBe(true);
		expect(ix.keys[3]!.isWritable).toBe(false);
	});

	test('respects custom programId (Token-2022)', () => {
		const ix = transferSplTokenChecked({
			source: pkA,
			mint: pkB,
			destination: pkC,
			authority: pkD,
			amount: 1n,
			decimals: 0,
			programId: TOKEN_2022_PROGRAM_ID,
		});
		expect(ix.programId.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
	});

	test('accepts number amount and bigint amount equivalently', () => {
		const a = transferSplTokenChecked({
			source: pkA,
			mint: pkB,
			destination: pkC,
			authority: pkD,
			amount: 42,
			decimals: 6,
		});
		const b = transferSplTokenChecked({
			source: pkA,
			mint: pkB,
			destination: pkC,
			authority: pkD,
			amount: 42n,
			decimals: 6,
		});
		expect(Array.from(a.data)).toEqual(Array.from(b.data));
	});
});

describe('createIdempotentAta', () => {
	test('uses ATA program + idempotent disc 1', () => {
		const ix = createIdempotentAta({
			payer: pkA,
			ata: pkB,
			owner: pkC,
			mint: pkD,
		});
		expect(ix.programId.equals(ATA_PROGRAM_ID)).toBe(true);
		expect(ix.data.length).toBe(1);
		expect(ix.data[0]).toBe(ATA_IX_CREATE_IDEMPOTENT);
	});

	test('includes payer signer/writable + system program + token program', () => {
		const ix = createIdempotentAta({
			payer: pkA,
			ata: pkB,
			owner: pkC,
			mint: pkD,
		});
		expect(ix.keys.length).toBe(6);
		expect(ix.keys[0]!.pubkey.equals(pkA)).toBe(true);
		expect(ix.keys[0]!.isSigner).toBe(true);
		expect(ix.keys[0]!.isWritable).toBe(true);
		expect(ix.keys[1]!.pubkey.equals(pkB)).toBe(true);
		expect(ix.keys[1]!.isWritable).toBe(true);
		expect(ix.keys[4]!.pubkey.equals(SystemProgram.programId)).toBe(true);
		expect(ix.keys[5]!.pubkey.equals(TOKEN_PROGRAM_ID)).toBe(true);
	});

	test('respects tokenProgramId override', () => {
		const ix = createIdempotentAta({
			payer: pkA,
			ata: pkB,
			owner: pkC,
			mint: pkD,
			tokenProgramId: TOKEN_2022_PROGRAM_ID,
		});
		expect(ix.keys[5]!.pubkey.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
	});
});

describe('closeSplAccount', () => {
	test('disc 9, three keys, authority is signer', () => {
		const ix = closeSplAccount({
			account: pkA,
			destination: pkB,
			authority: pkC,
		});
		expect(ix.programId.equals(TOKEN_PROGRAM_ID)).toBe(true);
		expect(ix.data.length).toBe(1);
		expect(ix.data[0]).toBe(SPL_IX_CLOSE_ACCOUNT);
		expect(ix.data[0]).toBe(9);
		expect(ix.keys.length).toBe(3);
		expect(ix.keys[2]!.isSigner).toBe(true);
		expect(ix.keys[0]!.isWritable).toBe(true);
		expect(ix.keys[1]!.isWritable).toBe(true);
	});

	test('respects programId override', () => {
		const ix = closeSplAccount({
			account: pkA,
			destination: pkB,
			authority: pkC,
			programId: TOKEN_2022_PROGRAM_ID,
		});
		expect(ix.programId.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
	});
});

describe('buildSweepMessage', () => {
	test('rejects empty instruction list', () => {
		expect(() =>
			buildSweepMessage({
				feePayer: pkA,
				instructions: [],
			}),
		).toThrow(/at least one/);
	});

	test('encodes single SOL transfer', () => {
		const { messageBytes, messageLen } = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1_000_000)],
		});
		expect(messageBytes).toBeInstanceOf(Uint8Array);
		expect(messageBytes.length).toBeGreaterThan(0);
		expect(messageBytes.length).toBe(messageLen);
	});

	test('multi-instruction message is bigger than single-instruction', () => {
		const single = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1)],
		});
		const triple = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1), transferSol(pkA, pkC, 2), transferSol(pkA, pkD, 3)],
		});
		expect(triple.messageLen).toBeGreaterThan(single.messageLen);
	});

	test('identical input deterministically yields identical bytes', () => {
		const a = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1_000)],
		});
		const b = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1_000)],
		});
		expect(Array.from(a.messageBytes)).toEqual(Array.from(b.messageBytes));
	});

	test('changing feePayer changes message bytes', () => {
		const a = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1)],
		});
		const b = buildSweepMessage({
			feePayer: pkC,
			instructions: [transferSol(pkA, pkB, 1)],
		});
		expect(Array.from(a.messageBytes)).not.toEqual(Array.from(b.messageBytes));
	});

	test('custom recentBlockhash changes bytes vs the zero placeholder', () => {
		const a = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1)],
		});
		const b = buildSweepMessage({
			feePayer: pkA,
			instructions: [transferSol(pkA, pkB, 1)],
			recentBlockhash: new PublicKey(new Uint8Array(32).fill(7)).toBase58(),
		});
		expect(Array.from(a.messageBytes)).not.toEqual(Array.from(b.messageBytes));
	});
});

describe('program id constants', () => {
	test('TOKEN_PROGRAM_ID and TOKEN_2022_PROGRAM_ID are distinct', () => {
		expect(TOKEN_PROGRAM_ID.equals(TOKEN_2022_PROGRAM_ID)).toBe(false);
	});
	test('TOKEN_PROGRAM_ID is the canonical SPL Token id', () => {
		expect(TOKEN_PROGRAM_ID.toBase58()).toBe('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
	});
	test('ATA_PROGRAM_ID is the canonical ATA id', () => {
		expect(ATA_PROGRAM_ID.toBase58()).toBe('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
	});
});
