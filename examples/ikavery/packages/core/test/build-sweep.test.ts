/**
 * Tests for `buildSweepBundle`. The bundle has tight invariants — every
 * tx must serialize under the size cap, the final SOL transfer's lamports
 * field is fee-adjusted in a two-pass pack, the source must end ≥ rent
 * exempt, and the resulting messages must round-trip through `MessageV0`.
 */

import { getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { Keypair, MessageV0, PublicKey, SystemProgram } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	buildSweepBundle,
	deserializeSweepMessage,
	SOLANA_SIGNATURE_FEE_LAMPORTS,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
	SOLANA_TX_SIZE_LIMIT,
} from '../src/solana/build-sweep';

const fakeBlockhash = (b: number): string => new PublicKey(new Uint8Array(32).fill(b)).toBase58();

describe('buildSweepBundle', () => {
	test('emits a single tx for a SOL-only sweep + ends with the residual transfer', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const solBalance = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 5n;
		const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT;

		const bundle = buildSweepBundle({
			source,
			destination,
			solBalance,
			feeReserveLamports: feeReserve,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x11),
		});
		expect(bundle.length).toBe(1);

		const msg = MessageV0.deserialize(bundle[0]!);
		// First static account key is the fee payer (source).
		expect(msg.staticAccountKeys[0]!.equals(source)).toBe(true);
		// The SOL transfer lamports should be `solBalance - feeReserve - 1×SIG_FEE`.
		const expectedLamports = solBalance - feeReserve - 1n * SOLANA_SIGNATURE_FEE_LAMPORTS;
		const ci = msg.compiledInstructions[0]!;
		// SystemProgram::Transfer data: u32 tag (=2) + u64 lamports
		expect(ci.data.length).toBe(12);
		let value = 0n;
		for (let i = 0; i < 8; i++) {
			value |= BigInt(ci.data[4 + i]!) << BigInt(8 * i);
		}
		expect(value).toBe(expectedLamports);
	});

	test('rejects feeReserve < rent-exempt minimum', () => {
		expect(() =>
			buildSweepBundle({
				source: Keypair.generate().publicKey,
				destination: Keypair.generate().publicKey,
				solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
				feeReserveLamports: 100n,
				tokenAccounts: [],
				recentBlockhash: fakeBlockhash(0x11),
			}),
		).toThrow(/rent-exempt/);
	});

	test('rejects when sweep amount goes non-positive after fees', () => {
		expect(() =>
			buildSweepBundle({
				source: Keypair.generate().publicKey,
				destination: Keypair.generate().publicKey,
				solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
				feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
				tokenAccounts: [],
				recentBlockhash: fakeBlockhash(0x11),
			}),
		).toThrow(/non-positive/);
	});

	test('each emitted tx fits the configured maxSerializedMessageBytes', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const tokenAccounts = Array.from({ length: 3 }, () => {
			const mint = Keypair.generate().publicKey;
			const sourceAta = getAssociatedTokenAddressSync(mint, source, true, TOKEN_PROGRAM_ID);
			return {
				mint,
				tokenAccount: sourceAta,
				amount: 100n,
				decimals: 6,
				programId: TOKEN_PROGRAM_ID,
			};
		});
		const bundle = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 10n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts,
			recentBlockhash: fakeBlockhash(0x11),
			maxSerializedMessageBytes: 512,
		});
		for (const bytes of bundle) {
			expect(bytes.length).toBeLessThanOrEqual(512);
		}
		// Should produce at least one tx; with 3 SPL accounts at 512 byte cap,
		// typically splits into ≥2 txs.
		expect(bundle.length).toBeGreaterThan(0);
	});

	test('SOL transfer lamports adjust to bundle txCount × signature fee', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const tokenAccounts = Array.from({ length: 6 }, () => {
			const mint = Keypair.generate().publicKey;
			const sourceAta = getAssociatedTokenAddressSync(mint, source, true, TOKEN_PROGRAM_ID);
			return {
				mint,
				tokenAccount: sourceAta,
				amount: 100n,
				decimals: 6,
				programId: TOKEN_PROGRAM_ID,
			};
		});
		const solBalance = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 20n;
		const feeReserve = SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT;
		const bundle = buildSweepBundle({
			source,
			destination,
			solBalance,
			feeReserveLamports: feeReserve,
			tokenAccounts,
			recentBlockhash: fakeBlockhash(0x33),
			maxSerializedMessageBytes: 512,
		});
		const txCount = BigInt(bundle.length);

		// Find the SystemProgram.transfer in the final tx and pull lamports.
		const lastMsg = MessageV0.deserialize(bundle[bundle.length - 1]!);
		const sysProgIdx = lastMsg.staticAccountKeys.findIndex((k) =>
			k.equals(SystemProgram.programId),
		);
		const xfer = lastMsg.compiledInstructions.find(
			(ci) => ci.programIdIndex === sysProgIdx && ci.data.length === 12,
		);
		if (!xfer) throw new Error('missing system transfer in last tx');
		let lamports = 0n;
		for (let i = 0; i < 8; i++) {
			lamports |= BigInt(xfer.data[4 + i]!) << BigInt(8 * i);
		}
		const expected = solBalance - feeReserve - txCount * SOLANA_SIGNATURE_FEE_LAMPORTS;
		expect(lamports).toBe(expected);
	});

	test('deserializeSweepMessage round-trips a bundle byte', () => {
		const source = Keypair.generate().publicKey;
		const destination = Keypair.generate().publicKey;
		const bundle = buildSweepBundle({
			source,
			destination,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x77),
		});
		const msg = deserializeSweepMessage(bundle[0]!);
		expect(msg.staticAccountKeys[0]!.equals(source)).toBe(true);
	});

	test('default maxSerializedMessageBytes leaves room for a 64-byte signature', () => {
		// The default cap is `SOLANA_TX_SIZE_LIMIT - 65 = 1167`; assert no
		// emitted message exceeds the wire cap minus signature overhead.
		const source = Keypair.generate().publicKey;
		const bundle = buildSweepBundle({
			source,
			destination: Keypair.generate().publicKey,
			solBalance: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT * 2n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: fakeBlockhash(0x88),
		});
		for (const bytes of bundle) {
			expect(bytes.length).toBeLessThanOrEqual(SOLANA_TX_SIZE_LIMIT - 65);
		}
	});
});
