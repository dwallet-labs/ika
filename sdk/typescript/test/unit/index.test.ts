// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	createClassGroupsKeypair,
	encodeToASCII,
	getNetworkConfig,
	IkaClient,
	IkaClientError,
	IkaTransaction,
	UserShareEncryptionKeys,
} from '../../src/client/index';

describe('Index Exports', () => {
	it('should export IkaClient', () => {
		expect(IkaClient).toBeDefined();
		expect(typeof IkaClient).toBe('function');
	});

	it('should export IkaTransaction', () => {
		expect(IkaTransaction).toBeDefined();
		expect(typeof IkaTransaction).toBe('function');
	});

	it('should export error classes', () => {
		expect(IkaClientError).toBeDefined();
		expect(typeof IkaClientError).toBe('function');
	});

	it('should export UserShareEncryptionKeys', () => {
		expect(UserShareEncryptionKeys).toBeDefined();
		expect(typeof UserShareEncryptionKeys).toBe('function');
	});

	it('should export cryptography functions', () => {
		expect(createClassGroupsKeypair).toBeDefined();
		expect(typeof createClassGroupsKeypair).toBe('function');
	});

	it('should export utility functions', () => {
		expect(encodeToASCII).toBeDefined();
		expect(typeof encodeToASCII).toBe('function');
	});

	it('should export network config functions', () => {
		expect(getNetworkConfig).toBeDefined();
		expect(typeof getNetworkConfig).toBe('function');
	});
});
