// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createIndividualTestSetup, getSharedTestSetup } from '../helpers/shared-test-setup';
import { generateTestKeypair } from '../helpers/test-utils';

// Shared test data to reduce redundant network calls
let sharedTestCache = {
	networkKeys: null as any,
	latestKey: null as any,
	configuredKey: null as any,
};

// Setup shared resources before all tests
beforeAll(async () => {
	await getSharedTestSetup();
}, 60000);

// Cleanup after all tests
afterAll(async () => {
	// Clear cache to help with garbage collection
	sharedTestCache = {
		networkKeys: null,
		latestKey: null,
		configuredKey: null,
	};
});

// Helper functions to reduce code duplication
function validateNetworkKey(key: any, keyName: string = 'key') {
	expect(key, `${keyName} should be defined`).toBeDefined();
	expect(key.id, `${keyName}.id should be defined`).toBeDefined();
	expect(typeof key.id, `${keyName}.id should be string`).toBe('string');
	expect(key.id, `${keyName}.id should match hex pattern`).toMatch(/^0x[a-f0-9]+$/);
	expect(key.epoch, `${keyName}.epoch should be defined`).toBeDefined();
	expect(typeof key.epoch, `${keyName}.epoch should be number`).toBe('number');
	expect(key.epoch, `${keyName}.epoch should be non-negative`).toBeGreaterThanOrEqual(0);
}

function validateNetworkKeyArray(keys: any[], arrayName: string = 'keys') {
	expect(keys, `${arrayName} should be array`).toBeInstanceOf(Array);
	expect(keys.length, `${arrayName} should not be empty`).toBeGreaterThan(0);
	
	keys.forEach((key, index) => {
		validateNetworkKey(key, `${arrayName}[${index}]`);
	});
}

function validateDWalletCapsResult(capsResult: any, testName: string = 'caps') {
	expect(capsResult, `${testName} result should be defined`).toBeDefined();
	expect(typeof capsResult, `${testName} result should be object`).toBe('object');
	expect(capsResult.dWalletCaps, `${testName}.dWalletCaps should be array`).toBeInstanceOf(Array);
	expect(typeof capsResult.hasNextPage, `${testName}.hasNextPage should be boolean`).toBe('boolean');
	
	// cursor should be null or string
	const isValidCursor = capsResult.cursor === null || typeof capsResult.cursor === 'string';
	expect(isValidCursor, `${testName}.cursor should be null or string`).toBe(true);
	
	// If there are no dWallet caps (new address), hasNextPage should be false
	if (capsResult.dWalletCaps.length === 0) {
		expect(capsResult.hasNextPage, `${testName}.hasNextPage should be false when no caps`).toBe(false);
		expect(capsResult.cursor, `${testName}.cursor should be null when no caps`).toBeNull();
	}
	
	// Validate each dWallet cap structure if any exist
	capsResult.dWalletCaps.forEach((cap: any, index: number) => {
		expect(cap, `${testName}.dWalletCaps[${index}] should be defined`).toBeDefined();
		expect(typeof cap, `${testName}.dWalletCaps[${index}] should be object`).toBe('object');
		expect(cap, `${testName}.dWalletCaps[${index}] should have id property`).toHaveProperty('id');
	});
	
	// Test pagination structure integrity
	expect(capsResult, `${testName} should have dWalletCaps property`).toHaveProperty('dWalletCaps');
	expect(capsResult, `${testName} should have hasNextPage property`).toHaveProperty('hasNextPage');
	expect(capsResult, `${testName} should have cursor property`).toHaveProperty('cursor');
}

describe('IkaClient Basic Features', () => {
	it('should handle initialization and caching', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('initialization-test');

		// Test initialization
		await ikaClient.initialize();

		// Test that cache is working by calling initialize again
		const start = Date.now();
		await ikaClient.initialize();
		const cachedTime = Date.now() - start;

		// Should be fast since it uses cache
		expect(cachedTime).toBeLessThan(500);

		// Test cache invalidation methods exist and work
		ikaClient.invalidateCache();
		ikaClient.invalidateObjectCache();
		ikaClient.invalidateEncryptionKeyCache();

		// Should still work after invalidation and be slower (not cached)
		const startAfterInvalidation = Date.now();
		await ikaClient.initialize();
		const reinitTime = Date.now() - startAfterInvalidation;

		// After cache invalidation, initialization should be slower than cached version
		expect(reinitTime).toBeGreaterThan(cachedTime);

		// Verify client is still functional after invalidation
		expect(ikaClient.ikaConfig).toBeDefined();
		expect(ikaClient.ikaConfig.packages).toBeDefined();
		expect(ikaClient.ikaConfig.objects).toBeDefined();
	});

	it('should handle network encryption key operations', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('network-encryption-test');

		// Get all network encryption keys and validate structure
		const allKeys = await ikaClient.getAllNetworkEncryptionKeys();
		validateNetworkKeyArray(allKeys, 'allKeys');
		
		// Cache for later tests to avoid redundant network calls
		sharedTestCache.networkKeys = allKeys;

		// Get latest network encryption key and validate it's in the list
		const latestKey = await ikaClient.getLatestNetworkEncryptionKey();
		validateNetworkKey(latestKey, 'latestKey');
		
		// Cache for later tests
		sharedTestCache.latestKey = latestKey;

		// Latest key should be one of the keys in allKeys
		const latestKeyExists = allKeys.some((key) => key.id === latestKey.id);
		expect(latestKeyExists, 'Latest key should exist in allKeys').toBe(true);

		// Latest key should have the highest epoch among all keys
		const maxEpoch = Math.max(...allKeys.map((key) => key.epoch));
		expect(latestKey.epoch, 'Latest key should have highest epoch').toBe(maxEpoch);

		// Get specific network encryption key by ID
		const specificKey = await ikaClient.getNetworkEncryptionKey(latestKey.id);
		expect(specificKey, 'Specific key should equal latest key').toEqual(latestKey);
		expect(specificKey.id, 'Specific key ID should match').toBe(latestKey.id);
		expect(specificKey.epoch, 'Specific key epoch should match').toBe(latestKey.epoch);

		// Get configured network encryption key
		const configuredKey = await ikaClient.getConfiguredNetworkEncryptionKey();
		validateNetworkKey(configuredKey, 'configuredKey');
		
		// Cache for later tests
		sharedTestCache.configuredKey = configuredKey;
	});

	it('should handle encryption key options configuration', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('encryption-options-test');

		// Test getting initial options and validate structure
		const initialOptions = ikaClient.getEncryptionKeyOptions();
		expect(initialOptions).toBeDefined();
		expect(typeof initialOptions).toBe('object');
		expect(typeof initialOptions.autoDetect).toBe('boolean');
		expect(initialOptions.autoDetect).toBe(true); // Default should be true

		// encryptionKeyID should be undefined initially
		expect(initialOptions.encryptionKeyID).toBeUndefined();

		// Test setting encryption key options with validation
		const testKeyId = 'test-key-id-12345';
		const newOptions = { autoDetect: false, encryptionKeyID: testKeyId };
		ikaClient.setEncryptionKeyOptions(newOptions);

		const updatedOptions = ikaClient.getEncryptionKeyOptions();
		expect(updatedOptions).toBeDefined();
		expect(updatedOptions.autoDetect).toBe(false);
		expect(updatedOptions.encryptionKeyID).toBe(testKeyId);
		expect(typeof updatedOptions.encryptionKeyID).toBe('string');

		// Test setting specific encryption key ID directly
		const anotherKeyId = 'another-test-key-id-67890';
		ikaClient.setEncryptionKeyID(anotherKeyId);

		const finalOptions = ikaClient.getEncryptionKeyOptions();
		expect(finalOptions.encryptionKeyID).toBe(anotherKeyId);
		expect(finalOptions.autoDetect).toBe(false); // Should remain false

		// Test resetting to auto-detect mode
		ikaClient.setEncryptionKeyOptions({ autoDetect: true });
		const resetOptions = ikaClient.getEncryptionKeyOptions();
		expect(resetOptions.autoDetect).toBe(true);
		// encryptionKeyID should be cleared when autoDetect is true
		expect(resetOptions.encryptionKeyID).toBeUndefined();
	});

	it('should handle dWallet capabilities retrieval', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('dwallet-caps-test');

		// Generate a test address using shared setup to reduce memory usage
		const { signerAddress } = generateTestKeypair('dwallet-caps-test');

		// Test getting owned dWallet caps and validate result structure
		const capsResult = await ikaClient.getOwnedDWalletCaps(signerAddress);
		validateDWalletCapsResult(capsResult, 'dWallet capabilities');
	});

	it('should get current epoch information', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('epoch-test');

		// Get current epoch and validate properties
		const epoch = await ikaClient.getEpoch();

		expect(typeof epoch).toBe('number');
		expect(epoch).toBeGreaterThanOrEqual(0);
		expect(Number.isInteger(epoch)).toBe(true); // Epochs should be integers
		expect(epoch).toBeLessThan(Number.MAX_SAFE_INTEGER); // Reasonable upper bound

		// Test epoch consistency - calling again should return same or higher epoch
		const epoch2 = await ikaClient.getEpoch();
		expect(epoch2).toBeGreaterThanOrEqual(epoch);

		// Epoch should not increase dramatically in a short time
		expect(epoch2 - epoch).toBeLessThanOrEqual(1);
	});

	it('should handle protocol public parameters without dWallet', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('protocol-params-test');

		// Get protocol public parameters without specifying a dWallet
		const params = await ikaClient.getProtocolPublicParameters();
		expect(params).toBeInstanceOf(Uint8Array);
		expect(params.length).toBeGreaterThan(0);

		// Validate that parameters contain meaningful data (not all zeros)
		const hasNonZeroBytes = Array.from(params).some((byte) => byte !== 0);
		expect(hasNonZeroBytes).toBe(true);

		// Test cache methods with latest encryption key
		const latestKey = await ikaClient.getLatestNetworkEncryptionKey();
		const isCached = ikaClient.isProtocolPublicParametersCached(latestKey.id);
		expect(typeof isCached).toBe('boolean');

		// After getting parameters, they should be cached
		expect(isCached).toBe(true);

		// Test cache invalidation and verify it affects caching status
		ikaClient.invalidateProtocolPublicParametersCache();
		const isCachedAfterInvalidation = ikaClient.isProtocolPublicParametersCached(latestKey.id);
		expect(isCachedAfterInvalidation).toBe(false);

		// Getting parameters again should re-populate cache
		const params2 = await ikaClient.getProtocolPublicParameters();
		expect(params2).toEqual(params); // Should be same parameters
		const isCachedAgain = ikaClient.isProtocolPublicParametersCached(latestKey.id);
		expect(isCachedAgain).toBe(true);
	});

	it('should handle batch dWallet retrieval with mock IDs', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('batch-dwallet-test');

		// Test batch retrieval with non-existent IDs and validate error handling
		const mockIds = [
			'0x1234567890abcdef12345678', // Non-existent but valid format
			'0xfedcba0987654321fedcba09', // Non-existent but valid format
		];

		// This should throw an error for non-existent IDs
		await expect(ikaClient.getMultipleDWallets(mockIds)).rejects.toThrow();

		// Test with empty array - should return empty results
		const emptyResult = await ikaClient.getMultipleDWallets([]);
		expect(emptyResult).toBeInstanceOf(Array);
		expect(emptyResult.length).toBe(0);

		// Test with invalid ID format - should throw appropriate error
		const invalidIds = ['invalid-id', 'not-a-hex-string'];
		await expect(ikaClient.getMultipleDWallets(invalidIds)).rejects.toThrow();

		// Test with mix of valid format but non-existent IDs
		const validFormatIds = [
			'0xa1b2c3d4e5f6789012345678901234567890abcd', // 40 chars after 0x
			'0xfedcba0987654321fedcba0987654321fedcba09', // 40 chars after 0x
		];

		try {
			const result = await ikaClient.getMultipleDWallets(validFormatIds);
			// If it succeeds, result should be an array
			expect(result).toBeInstanceOf(Array);
			result.forEach((dWallet) => {
				expect(dWallet).toBeDefined();
				expect(typeof dWallet).toBe('object');
			});
		} catch (error) {
			// If it throws, error should be defined and meaningful
			expect(error).toBeDefined();
			expect(error instanceof Error).toBe(true);
			expect((error as Error).message).toBeDefined();
			expect((error as Error).message.length).toBeGreaterThan(0);
		}
	});

	it('should handle error scenarios gracefully', async () => {
		const { suiClient, ikaClient } = await createIndividualTestSetup('error-scenarios-test');

		// Test with invalid encryption key ID
		await expect(ikaClient.getNetworkEncryptionKey('invalid-key-id')).rejects.toThrow();

		// Test with null/undefined parameters
		await expect(ikaClient.getNetworkEncryptionKey(null as any)).rejects.toThrow();

		// Test getting dWallet caps with invalid address format
		await expect(ikaClient.getOwnedDWalletCaps('invalid-address')).rejects.toThrow();

		// Test protocol parameters caching with invalid key ID
		const isCachedInvalid = ikaClient.isProtocolPublicParametersCached('invalid-key');
		expect(isCachedInvalid).toBe(false); // Should handle gracefully
	});
});
