/**
 * Tests for the COSE_Key fallback path used when WebAuthn's
 * `response.publicKey` (SPKI) is unavailable. Synthesizes a real ES256
 * key, hand-builds a minimal `attestationObject` + `COSE_Key` per RFC 8152,
 * and asserts the extractor pulls out the same compressed P-256 point as
 * `@noble/curves/p256`.
 */

import { p256 } from '@noble/curves/nist.js';
import { describe, expect, test } from 'bun:test';

import {
	cosePubkeyToCompressedP256,
	extractEs256PubkeyFromAttestationObject,
} from '../src/passkey/cose';

// === Minimal CBOR encoders for the subset we need ===

function cborUint(v: number): Uint8Array {
	if (v < 24) return Uint8Array.of(v);
	if (v < 0x100) return Uint8Array.of(0x18, v);
	if (v < 0x10000) return Uint8Array.of(0x19, v >> 8, v & 0xff);
	return Uint8Array.of(0x1a, (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
}

function cborNegInt(v: number): Uint8Array {
	// CBOR negative int: major 1, value = -1 - n  → ai encodes n
	const n = -1 - v;
	if (n < 24) return Uint8Array.of(0x20 | n);
	return Uint8Array.of(0x38, n);
}

function cborByteString(bytes: Uint8Array): Uint8Array {
	const head = withMajor(2, bytes.length);
	return concat(head, bytes);
}

function cborTextString(s: string): Uint8Array {
	const bytes = new TextEncoder().encode(s);
	const head = withMajor(3, bytes.length);
	return concat(head, bytes);
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
	const head = withMajor(5, entries.length);
	return concat(head, ...entries.flatMap(([k, v]) => [k, v]));
}

function withMajor(major: number, n: number): Uint8Array {
	if (n < 24) return Uint8Array.of((major << 5) | n);
	if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
	if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
	return Uint8Array.of(
		(major << 5) | 26,
		(n >> 24) & 0xff,
		(n >> 16) & 0xff,
		(n >> 8) & 0xff,
		n & 0xff,
	);
}

function concat(...chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.length;
	}
	return out;
}

function makeCoseKey(x: Uint8Array, y: Uint8Array): Uint8Array {
	// CBOR map { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
	return cborMap([
		[cborUint(1), cborUint(2)], // kty = EC2
		[cborUint(3), cborNegInt(-7)], // alg = ES256
		[cborNegInt(-1), cborUint(1)], // crv = P-256
		[cborNegInt(-2), cborByteString(x)],
		[cborNegInt(-3), cborByteString(y)],
	]);
}

function makeAttestationObject(coseKey: Uint8Array, credId: Uint8Array): Uint8Array {
	// authData = rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2 BE) | credId | coseKey
	const rpIdHash = new Uint8Array(32).fill(0xaa);
	const flags = Uint8Array.of(0x40 | 0x01); // AT + UP
	const signCount = Uint8Array.of(0, 0, 0, 0);
	const aaguid = new Uint8Array(16);
	const credIdLen = Uint8Array.of((credId.length >> 8) & 0xff, credId.length & 0xff);
	const authData = concat(rpIdHash, flags, signCount, aaguid, credIdLen, credId, coseKey);

	// Top-level CBOR map: { fmt: "none", attStmt: {}, authData: <bytes> }
	return cborMap([
		[cborTextString('fmt'), cborTextString('none')],
		[cborTextString('attStmt'), cborMap([])],
		[cborTextString('authData'), cborByteString(authData)],
	]);
}

function pickXY(): { x: Uint8Array; y: Uint8Array; compressed: Uint8Array } {
	const sk = p256.utils.randomSecretKey();
	const uncompressed = p256.getPublicKey(sk, false);
	const x = uncompressed.subarray(1, 33);
	const y = uncompressed.subarray(33, 65);
	return { x, y, compressed: p256.getPublicKey(sk, true) };
}

describe('cosePubkeyToCompressedP256', () => {
	test('round-trips a real ES256 key', () => {
		const { x, y, compressed } = pickXY();
		const cose = makeCoseKey(x, y);
		expect(Array.from(cosePubkeyToCompressedP256(cose))).toEqual(Array.from(compressed));
	});

	test('rejects wrong kty', () => {
		const { x, y } = pickXY();
		const bad = cborMap([
			[cborUint(1), cborUint(3)], // kty=3 (OKP), not EC2
			[cborUint(3), cborNegInt(-7)],
			[cborNegInt(-1), cborUint(1)],
			[cborNegInt(-2), cborByteString(x)],
			[cborNegInt(-3), cborByteString(y)],
		]);
		expect(() => cosePubkeyToCompressedP256(bad)).toThrow(/kty/);
	});

	test('rejects wrong alg', () => {
		const { x, y } = pickXY();
		const bad = cborMap([
			[cborUint(1), cborUint(2)],
			[cborUint(3), cborNegInt(-8)], // RS256
			[cborNegInt(-1), cborUint(1)],
			[cborNegInt(-2), cborByteString(x)],
			[cborNegInt(-3), cborByteString(y)],
		]);
		expect(() => cosePubkeyToCompressedP256(bad)).toThrow(/alg/);
	});

	test('rejects wrong crv', () => {
		const { x, y } = pickXY();
		const bad = cborMap([
			[cborUint(1), cborUint(2)],
			[cborUint(3), cborNegInt(-7)],
			[cborNegInt(-1), cborUint(2)], // P-384, not P-256
			[cborNegInt(-2), cborByteString(x)],
			[cborNegInt(-3), cborByteString(y)],
		]);
		expect(() => cosePubkeyToCompressedP256(bad)).toThrow(/crv/);
	});

	test('rejects truncated X coordinate', () => {
		const { y } = pickXY();
		const bad = cborMap([
			[cborUint(1), cborUint(2)],
			[cborUint(3), cborNegInt(-7)],
			[cborNegInt(-1), cborUint(1)],
			[cborNegInt(-2), cborByteString(new Uint8Array(31))],
			[cborNegInt(-3), cborByteString(y)],
		]);
		expect(() => cosePubkeyToCompressedP256(bad)).toThrow(/X/);
	});

	test('rejects truncated Y coordinate', () => {
		const { x } = pickXY();
		const bad = cborMap([
			[cborUint(1), cborUint(2)],
			[cborUint(3), cborNegInt(-7)],
			[cborNegInt(-1), cborUint(1)],
			[cborNegInt(-2), cborByteString(x)],
			[cborNegInt(-3), cborByteString(new Uint8Array(31))],
		]);
		expect(() => cosePubkeyToCompressedP256(bad)).toThrow(/Y/);
	});

	test('rejects non-map top-level', () => {
		expect(() => cosePubkeyToCompressedP256(cborByteString(new Uint8Array(0)))).toThrow(/CBOR map/);
	});
});

describe('extractEs256PubkeyFromAttestationObject', () => {
	test('extracts the same compressed point as cosePubkeyToCompressedP256', () => {
		const { x, y, compressed } = pickXY();
		const cose = makeCoseKey(x, y);
		const credId = new Uint8Array(16).fill(0x77);
		const attObj = makeAttestationObject(cose, credId);
		expect(Array.from(extractEs256PubkeyFromAttestationObject(attObj))).toEqual(
			Array.from(compressed),
		);
	});

	test('rejects attestation without authData field', () => {
		const noAuthData = cborMap([
			[cborTextString('fmt'), cborTextString('none')],
			[cborTextString('attStmt'), cborMap([])],
		]);
		expect(() => extractEs256PubkeyFromAttestationObject(noAuthData)).toThrow(/authData/);
	});

	test('rejects authData when AT flag is clear', () => {
		const { x, y } = pickXY();
		const cose = makeCoseKey(x, y);
		// Build authData with AT bit OFF (only UP).
		const rpIdHash = new Uint8Array(32);
		const flags = Uint8Array.of(0x01);
		const signCount = Uint8Array.of(0, 0, 0, 0);
		const aaguid = new Uint8Array(16);
		const credId = new Uint8Array(8);
		const credIdLen = Uint8Array.of(0, credId.length);
		const authData = concat(rpIdHash, flags, signCount, aaguid, credIdLen, credId, cose);
		const attObj = cborMap([
			[cborTextString('fmt'), cborTextString('none')],
			[cborTextString('attStmt'), cborMap([])],
			[cborTextString('authData'), cborByteString(authData)],
		]);
		expect(() => extractEs256PubkeyFromAttestationObject(attObj)).toThrow(/AT flag/);
	});

	test('rejects truncated authData (too short for header)', () => {
		const shortAuthData = new Uint8Array(20);
		const attObj = cborMap([
			[cborTextString('fmt'), cborTextString('none')],
			[cborTextString('attStmt'), cborMap([])],
			[cborTextString('authData'), cborByteString(shortAuthData)],
		]);
		expect(() => extractEs256PubkeyFromAttestationObject(attObj)).toThrow(/too short/);
	});
});
