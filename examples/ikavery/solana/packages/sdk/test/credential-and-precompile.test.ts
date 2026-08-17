/**
 * Unit tests for credential padding (`ix/types.credentialArgs`) and the
 * secp256r1 WebAuthn precompile builder (`passkey/precompile`).
 *
 * Both produce fixed-size byte buffers that the on-chain program reads via
 * `repr(C)` pointer-casts — anything off by a byte in the wire format here
 * silently bricks WebAuthn auth in production.
 */

import { describe, expect, test } from 'bun:test';

import {
	AUTH_PUBKEY_BYTES,
	AUTH_SIGNATURE_BYTES,
	credentialArgs,
	MAX_CLIENT_DATA_JSON_BYTES,
	passkey,
	SCHEME_ED25519,
	SCHEME_SECP256K1,
	SCHEME_SECP256R1,
	SCHEME_SOLANA_ADDRESS,
	SCHEME_WEBAUTHN,
	SECP256R1_PRECOMPILE_ID,
} from '../src';

const { buildSecp256r1VerifyIx, SECP256R1_PRECOMPILE_PROGRAM } = passkey;

describe('credentialArgs padding + edge cases', () => {
	test('solana_address: zero-fills client_data_json + signature', () => {
		const pk = new Uint8Array(32).fill(0x42);
		const args = credentialArgs({ scheme: SCHEME_SOLANA_ADDRESS, pubkey: pk });
		expect(args.authScheme).toBe(SCHEME_SOLANA_ADDRESS);
		expect(args.authPubkey.length).toBe(AUTH_PUBKEY_BYTES);
		expect(Array.from(args.authPubkey.slice(0, 32))).toEqual(Array.from(pk));
		expect(args.authPubkey[32]).toBe(0); // pad byte
		expect(args.clientDataJson.length).toBe(MAX_CLIENT_DATA_JSON_BYTES);
		expect(args.clientDataJsonLen).toBe(0);
		expect(args.authSignature.length).toBe(AUTH_SIGNATURE_BYTES);
		expect(args.authSignature.every((b) => b === 0)).toBe(true);
	});

	test('ed25519: 32-byte pubkey padded to 33, no signature required', () => {
		const pk = new Uint8Array(32).fill(0x11);
		const args = credentialArgs({ scheme: SCHEME_ED25519, pubkey: pk });
		expect(args.authPubkey.length).toBe(AUTH_PUBKEY_BYTES);
		expect(args.authPubkey[32]).toBe(0); // trailing pad
	});

	test('secp256k1: requires a 65-byte signature', () => {
		expect(() =>
			credentialArgs({
				scheme: SCHEME_SECP256K1,
				pubkey: new Uint8Array(33).fill(0xaa),
				// no signature
			}),
		).toThrow(/65-byte/);
	});

	test('secp256k1 happy path', () => {
		const args = credentialArgs({
			scheme: SCHEME_SECP256K1,
			pubkey: new Uint8Array(33).fill(0xab),
			signature: new Uint8Array(65).fill(0x99),
		});
		expect(args.authSignature.length).toBe(AUTH_SIGNATURE_BYTES);
		expect(args.authSignature.every((b) => b === 0x99)).toBe(true);
	});

	test('webauthn: requires non-empty client_data_json', () => {
		expect(() =>
			credentialArgs({
				scheme: SCHEME_WEBAUTHN,
				pubkey: new Uint8Array(33),
			}),
		).toThrow(/client_data_json/);
	});

	test('webauthn happy path', () => {
		const cdj = new TextEncoder().encode('{"type":"webauthn.get"}');
		const args = credentialArgs({
			scheme: SCHEME_WEBAUTHN,
			pubkey: new Uint8Array(33).fill(0x02),
			clientDataJson: cdj,
		});
		expect(args.clientDataJsonLen).toBe(cdj.length);
		expect(Array.from(args.clientDataJson.slice(0, cdj.length))).toEqual(Array.from(cdj));
		expect(args.clientDataJson.length).toBe(MAX_CLIENT_DATA_JSON_BYTES);
	});

	test('rejects client_data_json over cap', () => {
		expect(() =>
			credentialArgs({
				scheme: SCHEME_WEBAUTHN,
				pubkey: new Uint8Array(33),
				clientDataJson: new Uint8Array(MAX_CLIENT_DATA_JSON_BYTES + 1),
			}),
		).toThrow(/exceeds/);
	});

	test('rejects wrong-length signature', () => {
		expect(() =>
			credentialArgs({
				scheme: SCHEME_SECP256R1,
				pubkey: new Uint8Array(33),
				signature: new Uint8Array(33),
			}),
		).toThrow(/auth_signature must be/);
	});

	test('rejects pubkey larger than AUTH_PUBKEY_BYTES', () => {
		expect(() =>
			credentialArgs({
				scheme: SCHEME_ED25519,
				pubkey: new Uint8Array(AUTH_PUBKEY_BYTES + 1),
			}),
		).toThrow(/exceeds/);
	});
});

describe('secp256r1 WebAuthn precompile builder', () => {
	const sig = new Uint8Array(64).fill(0xaa);
	const pk = new Uint8Array(33).fill(0xbb);
	const msg = new Uint8Array([1, 2, 3, 4, 5]);

	test('targets the secp256r1 SigVerify precompile id', () => {
		const ix = buildSecp256r1VerifyIx({ signature: sig, publicKey: pk, message: msg });
		expect(ix.programId.equals(SECP256R1_PRECOMPILE_ID)).toBe(true);
		expect(ix.programId.equals(SECP256R1_PRECOMPILE_PROGRAM)).toBe(true);
		expect(ix.keys.length).toBe(0);
	});

	test('encodes num_signatures=1, offsets table, then payload', () => {
		const ix = buildSecp256r1VerifyIx({ signature: sig, publicKey: pk, message: msg });
		const data = ix.data;
		expect(data[0]).toBe(1);
		expect(data[1]).toBe(0);
		const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
		// signature_offset = 16 (header 2 + offsets 14)
		expect(dv.getUint16(2, true)).toBe(16);
		// signature_instruction_index = 0xFFFF
		expect(dv.getUint16(4, true)).toBe(0xffff);
		// public_key_offset = 16 + 64
		expect(dv.getUint16(6, true)).toBe(80);
		expect(dv.getUint16(8, true)).toBe(0xffff);
		// message_offset = 80 + 33
		expect(dv.getUint16(10, true)).toBe(113);
		// message_size
		expect(dv.getUint16(12, true)).toBe(msg.length);
		expect(dv.getUint16(14, true)).toBe(0xffff);
	});

	test('payload bytes appear at the declared offsets', () => {
		const ix = buildSecp256r1VerifyIx({ signature: sig, publicKey: pk, message: msg });
		const data = ix.data;
		expect(Array.from(data.subarray(16, 16 + 64))).toEqual(Array.from(sig));
		expect(Array.from(data.subarray(80, 80 + 33))).toEqual(Array.from(pk));
		expect(Array.from(data.subarray(113, 113 + msg.length))).toEqual(Array.from(msg));
		expect(data.length).toBe(113 + msg.length);
	});

	test('rejects wrong-length signature', () => {
		expect(() =>
			buildSecp256r1VerifyIx({
				signature: new Uint8Array(63),
				publicKey: pk,
				message: msg,
			}),
		).toThrow(/64 bytes/);
	});

	test('rejects wrong-length public key', () => {
		expect(() =>
			buildSecp256r1VerifyIx({
				signature: sig,
				publicKey: new Uint8Array(32),
				message: msg,
			}),
		).toThrow(/33 bytes/);
	});
});
