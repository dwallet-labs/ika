/**
 * Mirror tests for `u64ToLeBytes` — the byte-for-byte stand-in for Move
 * `challenges::u64_to_le_bytes`. Any drift here silently breaks challenge
 * derivation across Sui + Solana.
 */
import { describe, expect, test } from 'bun:test';

import { u64ToLeBytes } from '../src/crypto/le-bytes';

describe('u64ToLeBytes', () => {
	test('encodes 0 as 8 zero bytes', () => {
		expect(Array.from(u64ToLeBytes(0n))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
	});

	test('encodes 1 little-endian', () => {
		expect(Array.from(u64ToLeBytes(1n))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
	});

	test('encodes 0x0807060504030201n little-endian', () => {
		expect(Array.from(u64ToLeBytes(0x0807060504030201n))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
	});

	test('encodes max u64', () => {
		expect(Array.from(u64ToLeBytes(0xffffffffffffffffn))).toEqual([
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		]);
	});

	test('accepts number argument', () => {
		expect(Array.from(u64ToLeBytes(42))).toEqual([42, 0, 0, 0, 0, 0, 0, 0]);
	});

	test('number and bigint inputs agree on the same value', () => {
		expect(Array.from(u64ToLeBytes(2 ** 30))).toEqual(Array.from(u64ToLeBytes(BigInt(2 ** 30))));
	});
});
