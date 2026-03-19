// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { InvalidObjectError, objResToBcs } from '../../src';

describe('objResToBcs', () => {
	it('should extract BCS bytes from valid Sui object response', () => {
		const contentBytes = new Uint8Array([1, 2, 3, 4, 5]);
		const mockResponse = { content: contentBytes } as any;

		const result = objResToBcs(mockResponse);
		expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
	});

	it('should throw InvalidObjectError when content is missing', () => {
		const mockResponse = { type: 'SomeType' } as any;

		expect(() => objResToBcs(mockResponse)).toThrow(InvalidObjectError);
		expect(() => objResToBcs(mockResponse)).toThrow('Response bcs missing');
	});

	it('should throw when response is an Error', () => {
		const mockResponse = new Error('test error');

		expect(() => objResToBcs(mockResponse as any)).toThrow('test error');
	});

	it('should handle object-wrapped response', () => {
		const contentBytes = new Uint8Array([10, 20, 30]);
		const mockResponse = { object: { content: contentBytes } } as any;

		const result = objResToBcs(mockResponse);
		expect(result).toEqual(new Uint8Array([10, 20, 30]));
	});
});
