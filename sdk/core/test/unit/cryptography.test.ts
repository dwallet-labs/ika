// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	createClassGroupsKeypair,
	createRandomSessionIdentifier,
	Curve,
	sessionIdentifierDigest,
} from '../../src';

describe('createRandomSessionIdentifier', () => {
	it('should return 32 random bytes', () => {
		const id = createRandomSessionIdentifier();
		expect(id).toHaveLength(32);
		expect(id).toBeInstanceOf(Uint8Array);
	});

	it('should produce different values each call', () => {
		const first = createRandomSessionIdentifier();
		const second = createRandomSessionIdentifier();
		expect(first).not.toEqual(second);
	});
});

describe('sessionIdentifierDigest', () => {
	it('should produce 32-byte digest', () => {
		const bytes = new Uint8Array([1, 2, 3]);
		const address = new Uint8Array(32);
		const digest = sessionIdentifierDigest(bytes, address);
		expect(digest).toHaveLength(32);
	});

	it('should be deterministic', () => {
		const bytes = new Uint8Array([1, 2, 3]);
		const address = new Uint8Array(32);
		expect(sessionIdentifierDigest(bytes, address)).toEqual(sessionIdentifierDigest(bytes, address));
	});

	it('should differ for different inputs', () => {
		const address = new Uint8Array(32);
		const digestA = sessionIdentifierDigest(new Uint8Array([1]), address);
		const digestB = sessionIdentifierDigest(new Uint8Array([2]), address);
		expect(digestA).not.toEqual(digestB);
	});

	it('should differ for different addresses', () => {
		const bytes = new Uint8Array([1, 2, 3]);
		const addrA = new Uint8Array(32).fill(0);
		const addrB = new Uint8Array(32).fill(1);
		expect(sessionIdentifierDigest(bytes, addrA)).not.toEqual(sessionIdentifierDigest(bytes, addrB));
	});
});

describe('createClassGroupsKeypair', () => {
	it('should reject non-32-byte seeds', async () => {
		await expect(createClassGroupsKeypair(new Uint8Array(16), Curve.SECP256K1)).rejects.toThrow('32 bytes');
	});

	it('should produce encryption and decryption keys', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);
		const { encryptionKey, decryptionKey } = await createClassGroupsKeypair(seed, Curve.SECP256K1);

		expect(encryptionKey).toBeInstanceOf(Uint8Array);
		expect(encryptionKey.length).toBeGreaterThan(0);
		expect(decryptionKey).toBeInstanceOf(Uint8Array);
		expect(decryptionKey.length).toBeGreaterThan(0);
	});

	it('should be deterministic', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);
		const first = await createClassGroupsKeypair(seed, Curve.SECP256K1);
		const second = await createClassGroupsKeypair(seed, Curve.SECP256K1);

		expect(first.encryptionKey).toEqual(second.encryptionKey);
		expect(first.decryptionKey).toEqual(second.decryptionKey);
	});

	it('should produce different keys for different curves', async () => {
		const seed = new Uint8Array(32);
		crypto.getRandomValues(seed);
		const secp = await createClassGroupsKeypair(seed, Curve.SECP256K1);
		const ed = await createClassGroupsKeypair(seed, Curve.ED25519);

		expect(secp.encryptionKey).not.toEqual(ed.encryptionKey);
	});
});

describe('errors module', () => {
	it('should export all error classes', async () => {
		const { IkaClientError, ObjectNotFoundError, InvalidObjectError, CacheError, NetworkError } =
			await import('../../src');

		expect(new IkaClientError('test')).toBeInstanceOf(Error);
		expect(new ObjectNotFoundError('test')).toBeInstanceOf(IkaClientError);
		expect(new InvalidObjectError('test')).toBeInstanceOf(IkaClientError);
		expect(new CacheError('test')).toBeInstanceOf(IkaClientError);
		expect(new NetworkError('test')).toBeInstanceOf(IkaClientError);
	});
});
