/**
 * Tests for `assembleSignedTransaction` and `broadcastSignedTransactions`.
 *
 * `assembleSignedTransaction` is pure: it glues a single 64-byte signature
 * onto a serialized `MessageV0` and re-emits the wire bytes. We verify the
 * resulting bytes deserialize back into a `VersionedTransaction` with one
 * signature matching what we passed in.
 *
 * `broadcastSignedTransactions` is exercised against a hand-rolled mock
 * `Connection` (only `sendRawTransaction` is called) so we can confirm
 * the per-tx error isolation contract.
 */

import {
	Keypair,
	PublicKey,
	SystemProgram,
	TransactionMessage,
	VersionedTransaction,
	type Connection,
} from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import { assembleSignedTransaction, broadcastSignedTransactions } from '../src/solana/broadcast';

function makeMessageBytes(): Uint8Array {
	const from = Keypair.generate().publicKey;
	const to = Keypair.generate().publicKey;
	const message = new TransactionMessage({
		payerKey: from,
		recentBlockhash: new PublicKey(new Uint8Array(32).fill(0xab)).toBase58(),
		instructions: [SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 1n })],
	}).compileToV0Message();
	return message.serialize();
}

describe('assembleSignedTransaction', () => {
	test('attaches signature and serializes to a wire-format VersionedTransaction', () => {
		const messageBytes = makeMessageBytes();
		const signature = new Uint8Array(64).fill(0xa1);
		const wire = assembleSignedTransaction(messageBytes, signature);

		const tx = VersionedTransaction.deserialize(wire);
		expect(tx.signatures.length).toBe(1);
		expect(Array.from(tx.signatures[0]!)).toEqual(Array.from(signature));
		// Round-trip the message bytes too.
		expect(Array.from(tx.message.serialize())).toEqual(Array.from(messageBytes));
	});

	test('rejects wrong-length signature', () => {
		const messageBytes = makeMessageBytes();
		expect(() => assembleSignedTransaction(messageBytes, new Uint8Array(63))).toThrow(/64-byte/);
	});
});

describe('broadcastSignedTransactions', () => {
	test("returns per-tx outcomes in order; failures don't abort the batch", async () => {
		let calls = 0;
		const fakeConn = {
			sendRawTransaction: async () => {
				calls++;
				if (calls === 2) throw new Error('rpc rejected');
				return `sig-${calls}`;
			},
		} as unknown as Connection;

		const messageBytes = makeMessageBytes();
		const signed = [
			assembleSignedTransaction(messageBytes, new Uint8Array(64).fill(0x01)),
			assembleSignedTransaction(messageBytes, new Uint8Array(64).fill(0x02)),
			assembleSignedTransaction(messageBytes, new Uint8Array(64).fill(0x03)),
		];

		const out = await broadcastSignedTransactions(fakeConn, signed);
		expect(out.length).toBe(3);
		expect(out[0]).toEqual({ txIndex: 0, signature: 'sig-1' });
		expect(out[1]!.txIndex).toBe(1);
		expect(out[1]!.signature).toBeNull();
		expect(out[1]!.error).toBeInstanceOf(Error);
		expect(out[2]).toEqual({ txIndex: 2, signature: 'sig-3' });
	});

	test('forwards skipPreflight + maxRetries options', async () => {
		let captured: { skipPreflight?: boolean; maxRetries?: number } | undefined;
		const fakeConn = {
			sendRawTransaction: async (
				_bytes: Uint8Array,
				opts: { skipPreflight?: boolean; maxRetries?: number },
			) => {
				captured = opts;
				return 'sig-x';
			},
		} as unknown as Connection;

		const signed = [assembleSignedTransaction(makeMessageBytes(), new Uint8Array(64).fill(0x05))];
		await broadcastSignedTransactions(fakeConn, signed, {
			skipPreflight: true,
			maxRetries: 4,
		});
		expect(captured?.skipPreflight).toBe(true);
		expect(captured?.maxRetries).toBe(4);
	});
});
