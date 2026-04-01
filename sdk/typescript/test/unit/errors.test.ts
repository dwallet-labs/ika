// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	CacheError,
	IkaClientError,
	InvalidObjectError,
	NetworkError,
	ObjectNotFoundError,
} from '../../src/client/errors';

describe('Error Classes', () => {
	describe('IkaClientError', () => {
		it('should create error with message only', () => {
			const error = new IkaClientError('Test error');

			expect(error.message).toBe('Test error');
			expect(error.name).toBe('IkaClientError');
			expect(error.cause).toBeUndefined();
			expect(error).toBeInstanceOf(Error);
			expect(error).toBeInstanceOf(IkaClientError);
		});

		it('should create error with message and cause', () => {
			const cause = new Error('Original error');
			const error = new IkaClientError('Test error', cause);

			expect(error.message).toBe('Test error');
			expect(error.name).toBe('IkaClientError');
			expect(error.cause).toBe(cause);
		});
	});

	describe('ObjectNotFoundError', () => {
		it('should create error with object type only', () => {
			const error = new ObjectNotFoundError('DWallet');

			expect(error.message).toBe('DWallet object not found');
			expect(error.name).toBe('ObjectNotFoundError');
			expect(error.cause).toBeUndefined();
			expect(error).toBeInstanceOf(IkaClientError);
		});

		it('should create error with object type and ID', () => {
			const error = new ObjectNotFoundError('DWallet', '0x123');

			expect(error.message).toBe('DWallet object with ID 0x123 not found');
			expect(error.name).toBe('ObjectNotFoundError');
		});

		it('should create error with object type, ID, and cause', () => {
			const cause = new Error('Network timeout');
			const error = new ObjectNotFoundError('Presign', '0x456', cause);

			expect(error.message).toBe('Presign object with ID 0x456 not found');
			expect(error.name).toBe('ObjectNotFoundError');
			expect(error.cause).toBe(cause);
		});

		it('should handle missing object ID gracefully', () => {
			const error = new ObjectNotFoundError('EncryptionKey', undefined);

			expect(error.message).toBe('EncryptionKey object not found');
		});
	});

	describe('InvalidObjectError', () => {
		it('should create error with object type only', () => {
			const error = new InvalidObjectError('DWallet');

			expect(error.message).toBe('Invalid DWallet object: Expected structure not found');
			expect(error.name).toBe('InvalidObjectError');
			expect(error.cause).toBeUndefined();
			expect(error).toBeInstanceOf(IkaClientError);
		});

		it('should create error with object type and ID', () => {
			const error = new InvalidObjectError('Presign', '0x789');

			expect(error.message).toBe(
				'Invalid Presign object (ID: 0x789): Expected structure not found',
			);
			expect(error.name).toBe('InvalidObjectError');
		});

		it('should create error with object type, ID, and cause', () => {
			const cause = new Error('Parsing failed');
			const error = new InvalidObjectError('EncryptionKey', '0xabc', cause);

			expect(error.message).toBe(
				'Invalid EncryptionKey object (ID: 0xabc): Expected structure not found',
			);
			expect(error.name).toBe('InvalidObjectError');
			expect(error.cause).toBe(cause);
		});

		it('should handle missing object ID gracefully', () => {
			const error = new InvalidObjectError('SystemObject', undefined);

			expect(error.message).toBe('Invalid SystemObject object: Expected structure not found');
		});
	});

	describe('CacheError', () => {
		it('should create error with message only', () => {
			const error = new CacheError('Cache expired');

			expect(error.message).toBe('Cache error: Cache expired');
			expect(error.name).toBe('CacheError');
			expect(error.cause).toBeUndefined();
			expect(error).toBeInstanceOf(IkaClientError);
		});

		it('should create error with message and cause', () => {
			const cause = new Error('Memory overflow');
			const error = new CacheError('Failed to store cache', cause);

			expect(error.message).toBe('Cache error: Failed to store cache');
			expect(error.name).toBe('CacheError');
			expect(error.cause).toBe(cause);
		});
	});

	describe('NetworkError', () => {
		it('should create error with message only', () => {
			const error = new NetworkError('Connection timeout');

			expect(error.message).toBe('Network error: Connection timeout');
			expect(error.name).toBe('NetworkError');
			expect(error.cause).toBeUndefined();
			expect(error).toBeInstanceOf(IkaClientError);
		});

		it('should create error with message and cause', () => {
			const cause = new Error('Socket closed');
			const error = new NetworkError('Request failed', cause);

			expect(error.message).toBe('Network error: Request failed');
			expect(error.name).toBe('NetworkError');
			expect(error.cause).toBe(cause);
		});
	});
});
