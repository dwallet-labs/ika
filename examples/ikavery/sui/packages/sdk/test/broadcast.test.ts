import {
	assembleSignedTransaction,
	buildSweepBundle,
	SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
} from '@fesal-packages/ikavery-core';
import { Keypair, VersionedTransaction } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

const SOURCE_KEYPAIR = Keypair.generate();
const SOURCE = SOURCE_KEYPAIR.publicKey;
const DESTINATION = Keypair.generate().publicKey;
const FAKE_BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi';

describe('assembleSignedTransaction', () => {
	test('attaches signature so the resulting VersionedTransaction round-trips', () => {
		const [messageBytes] = buildSweepBundle({
			source: SOURCE,
			destination: DESTINATION,
			solBalance: 5_000_000n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: FAKE_BLOCKHASH,
		});
		// Borrow Solana's own signing for a valid 64-byte signature; the SDK is
		// signature-agnostic, so we just need *something* well-formed.
		const tx = VersionedTransaction.deserialize(
			assembleSignedTransaction(messageBytes!, new Uint8Array(64).fill(0xab)),
		);
		expect(tx.signatures.length).toBe(1);
		expect(tx.signatures[0]!.length).toBe(64);
		expect(tx.signatures[0]![0]).toBe(0xab);
	});

	test('rejects non-64-byte signature', () => {
		const [messageBytes] = buildSweepBundle({
			source: SOURCE,
			destination: DESTINATION,
			solBalance: 5_000_000n,
			feeReserveLamports: SOLANA_SYSTEM_ACCOUNT_RENT_EXEMPT,
			tokenAccounts: [],
			recentBlockhash: FAKE_BLOCKHASH,
		});
		expect(() => assembleSignedTransaction(messageBytes!, new Uint8Array(63))).toThrow(
			/64-byte signature/,
		);
	});
});
