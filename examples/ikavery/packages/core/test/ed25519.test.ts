/**
 * `solanaSeedToCanonicalScalar` converts a Solana 32-byte ed25519 seed into
 * the canonical < L scalar Ika's imported-key DKG expects. Tests pin the
 * RFC 8032 derivation: SHA-512 over the seed, take the first 32 bytes,
 * clamp the top + bottom bits, reduce mod L. Then verify that `scalar*G`
 * matches the Solana pubkey produced by `@noble/curves/ed25519` from the
 * same seed.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { describe, expect, test } from 'bun:test';

import { solanaSeedToCanonicalScalar } from '../src/solana/ed25519';

const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function leBytesToBigInt(bytes: Uint8Array): bigint {
	let v = 0n;
	for (let i = bytes.length - 1; i >= 0; i--) {
		v = (v << 8n) | BigInt(bytes[i]!);
	}
	return v;
}

describe('solanaSeedToCanonicalScalar', () => {
	test('rejects wrong-length seeds', () => {
		expect(() => solanaSeedToCanonicalScalar(new Uint8Array(31))).toThrow(/32-byte/);
		expect(() => solanaSeedToCanonicalScalar(new Uint8Array(33))).toThrow(/32-byte/);
	});

	test('output is exactly 32 bytes', () => {
		const seed = new Uint8Array(32);
		expect(solanaSeedToCanonicalScalar(seed).length).toBe(32);
	});

	test('scalar is strictly less than the ed25519 order L', () => {
		for (let i = 0; i < 3; i++) {
			const seed = crypto.getRandomValues(new Uint8Array(32));
			const scalar = leBytesToBigInt(solanaSeedToCanonicalScalar(seed));
			expect(scalar).toBeGreaterThanOrEqual(0n);
			expect(scalar < L).toBe(true);
		}
	});

	test('scalar agrees with manual RFC 8032 derivation', () => {
		const seed = new Uint8Array(32).fill(0xab);
		const h = sha512(seed).slice(0, 32);
		h[0] = h[0]! & 248;
		h[31] = (h[31]! & 127) | 64;
		const expected = leBytesToBigInt(h) % L;

		const got = leBytesToBigInt(solanaSeedToCanonicalScalar(seed));
		expect(got).toBe(expected);
	});

	test('scalar*G recovers the Solana ed25519 public key', () => {
		const seed = new Uint8Array(32).fill(0x42);
		const solanaPubkey = ed25519.getPublicKey(seed);
		const scalar = solanaSeedToCanonicalScalar(seed);

		// Multiply scalar (LE) * basepoint and compare compressed point bytes.
		const point = ed25519.ExtendedPoint.BASE.multiply(leBytesToBigInt(scalar));
		expect(Array.from(point.toRawBytes())).toEqual(Array.from(solanaPubkey));
	});

	test('two different seeds yield different scalars', () => {
		const s1 = solanaSeedToCanonicalScalar(new Uint8Array(32).fill(0x01));
		const s2 = solanaSeedToCanonicalScalar(new Uint8Array(32).fill(0x02));
		expect(Array.from(s1)).not.toEqual(Array.from(s2));
	});

	test('deterministic across calls', () => {
		const seed = new Uint8Array(32).fill(0x99);
		expect(Array.from(solanaSeedToCanonicalScalar(seed))).toEqual(
			Array.from(solanaSeedToCanonicalScalar(seed)),
		);
	});
});
