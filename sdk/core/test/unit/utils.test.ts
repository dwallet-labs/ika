// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	bytesToHex,
	encodeToASCII,
	hexToBytes,
	stringToUint8Array,
	u64ToBytesBigEndian,
} from '../../src';

describe('hexToBytes', () => {
	it('should convert valid hex to bytes', () => {
		expect(hexToBytes('deadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
	});

	it('should handle 0x prefix', () => {
		expect(hexToBytes('0xdeadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
	});

	it('should handle empty string', () => {
		expect(hexToBytes('')).toEqual(new Uint8Array([]));
	});

	it('should handle uppercase hex', () => {
		expect(hexToBytes('DEADBEEF')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
	});

	it('should reject odd-length hex', () => {
		expect(() => hexToBytes('abc')).toThrow('odd length');
	});

	it('should reject non-hex characters', () => {
		expect(() => hexToBytes('ghij')).toThrow('non-hex characters');
	});

	it('should reject mixed valid and invalid characters', () => {
		expect(() => hexToBytes('deadZZef')).toThrow('non-hex characters');
	});
});

describe('bytesToHex', () => {
	it('should convert bytes to hex', () => {
		expect(bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
	});

	it('should pad single-digit bytes', () => {
		expect(bytesToHex(new Uint8Array([0x0a, 0x00, 0x01]))).toBe('0a0001');
	});

	it('should handle empty array', () => {
		expect(bytesToHex(new Uint8Array([]))).toBe('');
	});
});

describe('hexToBytes <-> bytesToHex round-trip', () => {
	it('should round-trip arbitrary bytes', () => {
		const original = new Uint8Array([0, 1, 127, 128, 255, 42]);
		expect(hexToBytes(bytesToHex(original))).toEqual(original);
	});

	it('should round-trip 32-byte key', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		expect(hexToBytes(bytesToHex(key))).toEqual(key);
	});
});

describe('encodeToASCII', () => {
	it('should encode ASCII string', () => {
		expect(encodeToASCII('ABC')).toEqual(new Uint8Array([65, 66, 67]));
	});

	it('should handle empty string', () => {
		expect(encodeToASCII('')).toEqual(new Uint8Array([]));
	});
});

describe('stringToUint8Array', () => {
	it('should match encodeToASCII for ASCII strings', () => {
		const input = 'hello world';
		expect(stringToUint8Array(input)).toEqual(encodeToASCII(input));
	});
});

describe('u64ToBytesBigEndian', () => {
	it('should encode zero', () => {
		expect(u64ToBytesBigEndian(0)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]));
	});

	it('should encode 1', () => {
		expect(u64ToBytesBigEndian(1)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]));
	});

	it('should encode 256 in big-endian', () => {
		expect(u64ToBytesBigEndian(256)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 1, 0]));
	});

	it('should handle bigint input', () => {
		expect(u64ToBytesBigEndian(BigInt(1))).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]));
	});
});
