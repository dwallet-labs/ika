// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { InvalidObjectError } from '../../src/client/errors';
import {
	encodeToASCII,
	objResToBcs,
	stringToUint8Array,
	u64ToBytesBigEndian,
} from '../../src/client/utils';

describe('Utils', () => {
	describe('objResToBcs', () => {
		it('should extract BCS bytes from a direct Object response', () => {
			const bytes = new Uint8Array([1, 2, 3, 4]);
			const mockResponse = { content: bytes, type: 'SomeType' } as any;

			const result = objResToBcs(mockResponse);
			expect(result).toBeInstanceOf(Uint8Array);
			expect(Array.from(result)).toEqual([1, 2, 3, 4]);
		});

		it('should unwrap and extract BCS bytes from a GetObjectResponse', () => {
			const bytes = new Uint8Array([9, 8, 7]);
			const mockResponse = {
				object: { content: bytes, type: 'SomeType' },
			} as any;

			const result = objResToBcs(mockResponse);
			expect(Array.from(result)).toEqual([9, 8, 7]);
		});

		it('should throw InvalidObjectError when content is missing', () => {
			const mockResponse = { type: 'SomeType' } as any;

			expect(() => objResToBcs(mockResponse)).toThrow(InvalidObjectError);
			expect(() => objResToBcs(mockResponse)).toThrow('Response bcs missing');
		});

		it('should throw InvalidObjectError when content is missing after unwrap', () => {
			const mockResponse = { object: { type: 'SomeType' } } as any;

			expect(() => objResToBcs(mockResponse)).toThrow(InvalidObjectError);
		});

		it('should rethrow when given an Error', () => {
			const err = new Error('rpc boom');

			expect(() => objResToBcs(err)).toThrow(err);
		});
	});

	describe('encodeToASCII', () => {
		it('should convert string to ASCII byte array', () => {
			const input = 'Hello';
			const result = encodeToASCII(input);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]); // ASCII values for "Hello"
		});

		it('should handle empty string', () => {
			const result = encodeToASCII('');

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(0);
		});

		it('should handle special characters', () => {
			const input = 'A@1';
			const result = encodeToASCII(input);

			expect(Array.from(result)).toEqual([65, 64, 49]); // ASCII values for "A@1"
		});

		it('should handle spaces and punctuation', () => {
			const input = 'Hi!';
			const result = encodeToASCII(input);

			expect(Array.from(result)).toEqual([72, 105, 33]); // ASCII values for "Hi!"
		});
	});

	describe('stringToUint8Array', () => {
		it('should convert string to Uint8Array', () => {
			const input = 'Test';
			const result = stringToUint8Array(input);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(Array.from(result)).toEqual([84, 101, 115, 116]); // ASCII values for "Test"
		});

		it('should handle empty string', () => {
			const result = stringToUint8Array('');

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(0);
		});

		it('should handle special characters and numbers', () => {
			const input = 'ABC123!@#';
			const result = stringToUint8Array(input);

			expect(Array.from(result)).toEqual([65, 66, 67, 49, 50, 51, 33, 64, 35]);
		});

		it('should handle unicode characters (converts to char codes)', () => {
			const input = 'é'; // Unicode character
			const result = stringToUint8Array(input);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(1);
			expect(result[0]).toBe(233); // Unicode code point for 'é'
		});

		it('should be equivalent to encodeToASCII for ASCII strings', () => {
			const input = 'Hello World';
			const result1 = stringToUint8Array(input);
			const result2 = encodeToASCII(input);

			expect(result1).toEqual(result2);
		});
	});

	describe('u64ToBytesBigEndian', () => {
		it('should convert number to 8-byte big-endian array', () => {
			const result = u64ToBytesBigEndian(256);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(8);
			expect(Array.from(result)).toEqual([0, 0, 0, 0, 0, 0, 1, 0]); // 256 in big-endian
		});

		it('should handle zero', () => {
			const result = u64ToBytesBigEndian(0);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(8);
			expect(Array.from(result)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
		});

		it('should handle large numbers', () => {
			const result = u64ToBytesBigEndian(65535); // 0xFFFF

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(8);
			expect(Array.from(result)).toEqual([0, 0, 0, 0, 0, 0, 255, 255]);
		});

		it('should handle BigInt values', () => {
			const result = u64ToBytesBigEndian(BigInt(1000));

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(8);
			expect(Array.from(result)).toEqual([0, 0, 0, 0, 0, 0, 3, 232]); // 1000 in big-endian
		});

		it('should handle maximum safe integer', () => {
			const result = u64ToBytesBigEndian(Number.MAX_SAFE_INTEGER);

			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(8);
			// Should not throw and should produce valid bytes
			expect(result.every((byte) => byte >= 0 && byte <= 255)).toBe(true);
		});
	});
});
