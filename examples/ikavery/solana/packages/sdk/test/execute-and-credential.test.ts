/**
 * Tests for `buildExecuteIx` and the remaining `credential.ts` helpers
 * (`idLenForScheme`, `padAuthPubkey`, padding edge cases for `packMembers`).
 */

import { Keypair, PublicKey } from '@solana/web3.js';
import { describe, expect, test } from 'bun:test';

import {
	AUTH_PUBKEY_BYTES,
	buildExecuteIx,
	idLenForScheme,
	IKAVERY_PROGRAM_ID,
	IX_EXECUTE,
	MAX_MESSAGE_BYTES,
	MEMBER_SLOT_LEN,
	memberIdBytes,
	packMemberSlot,
	padAuthPubkey,
	SCHEME_ED25519,
	SCHEME_SECP256K1,
	SCHEME_SECP256R1,
	SCHEME_SOLANA_ADDRESS,
	SCHEME_WEBAUTHN,
} from '../src';

function pk(byte: number): PublicKey {
	return new PublicKey(new Uint8Array(32).fill(byte));
}

describe('buildExecuteIx', () => {
	const defaults = {
		recovery: pk(0x01),
		proposal: pk(0x02),
		payer: Keypair.generate().publicKey,
		txIndex: 0,
		messageBytes: new Uint8Array([1, 2, 3, 4]),
		coordinator: pk(0x03),
		messageApproval: pk(0x04),
		dwallet: pk(0x05),
		callerProgram: IKAVERY_PROGRAM_ID,
		cpiAuthority: pk(0x06),
		dwalletProgram: pk(0x07),
		messageApprovalBump: 252,
		cpiAuthorityBump: 253,
	};

	test('data layout: disc + tx_index + msg(512) + len + 2 bumps', () => {
		const ix = buildExecuteIx(defaults);
		expect(ix.programId.equals(IKAVERY_PROGRAM_ID)).toBe(true);
		const expectedLen = 1 + 1 + MAX_MESSAGE_BYTES + 2 + 1 + 1;
		expect(ix.data.length).toBe(expectedLen);
		expect(ix.data[0]).toBe(IX_EXECUTE);
		expect(ix.data[1]).toBe(0); // txIndex
		expect(Array.from(ix.data.subarray(2, 2 + defaults.messageBytes.length))).toEqual(
			Array.from(defaults.messageBytes),
		);
		// message_len at offset 2 + 512 = 514
		expect(ix.data[2 + MAX_MESSAGE_BYTES]).toBe(defaults.messageBytes.length);
		expect(ix.data[2 + MAX_MESSAGE_BYTES + 1]).toBe(0);
		// bumps at the tail
		expect(ix.data[ix.data.length - 2]).toBe(252);
		expect(ix.data[ix.data.length - 1]).toBe(253);
	});

	test('account list keeps the canonical order', () => {
		const ix = buildExecuteIx(defaults);
		expect(ix.keys.length).toBe(10);
		expect(ix.keys[0]!.isWritable).toBe(false); // recovery
		expect(ix.keys[1]!.isWritable).toBe(true); // proposal
		expect(ix.keys[2]!.isSigner).toBe(true); // payer
		expect(ix.keys[4]!.isWritable).toBe(true); // messageApproval
	});

	test('rejects message over the on-chain cap', () => {
		expect(() =>
			buildExecuteIx({
				...defaults,
				messageBytes: new Uint8Array(MAX_MESSAGE_BYTES + 1),
			}),
		).toThrow(/exceeds/);
	});

	test('rejects negative or > u8 txIndex', () => {
		expect(() => buildExecuteIx({ ...defaults, txIndex: -1 })).toThrow(/u8/);
		expect(() => buildExecuteIx({ ...defaults, txIndex: 256 })).toThrow(/u8/);
	});

	test('txIndex=255 (max u8) is accepted', () => {
		const ix = buildExecuteIx({ ...defaults, txIndex: 255 });
		expect(ix.data[1]).toBe(255);
	});
});

describe('idLenForScheme', () => {
	test('returns scheme-tag + pubkey-length for each scheme', () => {
		expect(idLenForScheme(SCHEME_ED25519)).toBe(33); // 1 + 32
		expect(idLenForScheme(SCHEME_SECP256K1)).toBe(34); // 1 + 33
		expect(idLenForScheme(SCHEME_SECP256R1)).toBe(34); // 1 + 33
		expect(idLenForScheme(SCHEME_WEBAUTHN)).toBe(34); // 1 + 33
		expect(idLenForScheme(SCHEME_SOLANA_ADDRESS)).toBe(33); // 1 + 32
	});

	test('throws for unknown scheme tag', () => {
		expect(() => idLenForScheme(99)).toThrow(/unknown scheme/);
	});
});

describe('padAuthPubkey', () => {
	test('pads a shorter pubkey with trailing zeros', () => {
		const padded = padAuthPubkey(new Uint8Array(32).fill(0xab), AUTH_PUBKEY_BYTES);
		expect(padded.length).toBe(AUTH_PUBKEY_BYTES);
		expect(padded[31]).toBe(0xab);
		expect(padded[32]).toBe(0); // trailing pad
	});

	test('rejects pubkey longer than the buffer', () => {
		expect(() => padAuthPubkey(new Uint8Array(AUTH_PUBKEY_BYTES + 1), AUTH_PUBKEY_BYTES)).toThrow(
			/exceeds/,
		);
	});
});

describe('memberIdBytes', () => {
	test('returns canonical id (scheme + pubkey, no padding)', () => {
		const slot = packMemberSlot(SCHEME_ED25519, new Uint8Array(32).fill(0x42));
		const id = memberIdBytes(slot);
		expect(id.length).toBe(idLenForScheme(SCHEME_ED25519));
		expect(id[0]).toBe(SCHEME_ED25519);
		expect(Array.from(id.subarray(1))).toEqual(Array.from(new Uint8Array(32).fill(0x42)));
	});

	test('rejects non-MEMBER_SLOT_LEN slot', () => {
		expect(() => memberIdBytes(new Uint8Array(MEMBER_SLOT_LEN - 1))).toThrow(
			new RegExp(`${MEMBER_SLOT_LEN}`),
		);
	});

	test('rejects slot with unknown scheme tag', () => {
		const slot = new Uint8Array(MEMBER_SLOT_LEN);
		slot[0] = 99;
		expect(() => memberIdBytes(slot)).toThrow(/unknown scheme/);
	});
});
