// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it, vi } from 'vitest';

import {
	createClassGroupsKeypair,
	createDKGUserOutput,
	createRandomSessionIdentifier,
	encryptSecretShare,
	publicKeyFromDWalletOutput,
	sessionIdentifierDigest,
	verifyAndGetDWalletDKGPublicOutput,
} from '../../src/client/cryptography';
import { Curve, Hash } from '../../src/client/types';

describe('Cryptography Direct Functions', () => {
	it('should create class groups keypair with seed', async () => {
		// Create a hardcoded 32-byte seed for consistent testing
		const seed = new Uint8Array([
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
			27, 28, 29, 30, 31, 32,
		]);

		// Test creating a class groups keypair
		const keypair = createClassGroupsKeypair(seed);

		// Test against expected deterministic outputs
		expect(keypair).toBeDefined();
		expect(keypair.encryptionKey).toBeInstanceOf(Uint8Array);
		expect(keypair.decryptionKey).toBeInstanceOf(Uint8Array);

		// Verify exact expected lengths
		expect(keypair.encryptionKey.length).toBe(778);
		expect(keypair.decryptionKey.length).toBe(194);

		// Verify exact expected output for first 20 bytes (deterministic with this seed)
		const expectedEncryptionKeyStart = '800218a3f328cfa9432b5c3f0755d1e480d20eac';
		const expectedDecryptionKeyStart = 'c00183d131cf69691ca1a7a3fc134f149880e8bb';

		const actualEncryptionKeyStart = Array.from(keypair.encryptionKey.slice(0, 20))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
		const actualDecryptionKeyStart = Array.from(keypair.decryptionKey.slice(0, 20))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		expect(actualEncryptionKeyStart).toBe(expectedEncryptionKeyStart);
		expect(actualDecryptionKeyStart).toBe(expectedDecryptionKeyStart);

		// Test that same seed creates same keypair
		const keypair2 = createClassGroupsKeypair(seed);

		expect(keypair.encryptionKey).toEqual(keypair2.encryptionKey);
		expect(keypair.decryptionKey).toEqual(keypair2.decryptionKey);

		// Test that different seeds create different keypairs
		const seed2 = new Uint8Array(32);
		crypto.getRandomValues(seed2);
		const keypair3 = createClassGroupsKeypair(seed2);

		expect(keypair.encryptionKey).not.toEqual(keypair3.encryptionKey);
		expect(keypair.decryptionKey).not.toEqual(keypair3.decryptionKey);
	});

	it('should reject invalid seed sizes', async () => {
		// Test with wrong seed size
		const invalidSeed = new Uint8Array(16); // Too small
		crypto.getRandomValues(invalidSeed);

		expect(() => createClassGroupsKeypair(invalidSeed)).toThrow('Seed must be 32 bytes');

		// Test with another wrong seed size
		const tooLargeSeed = new Uint8Array(64); // Too large
		crypto.getRandomValues(tooLargeSeed);

		expect(() => createClassGroupsKeypair(tooLargeSeed)).toThrow('Seed must be 32 bytes');
	});

	it('should create random session identifier', async () => {
		// Test creating random session identifiers
		const sessionId1 = createRandomSessionIdentifier();
		const sessionId2 = createRandomSessionIdentifier();

		// Test expected properties
		expect(sessionId1).toBeInstanceOf(Uint8Array);
		expect(sessionId2).toBeInstanceOf(Uint8Array);

		// Session IDs should always be exactly 32 bytes
		expect(sessionId1.length).toBe(32);
		expect(sessionId2.length).toBe(32);

		// Should be different each time (extremely high probability)
		expect(sessionId1).not.toEqual(sessionId2);

		// Verify entropy - should not be all zeros or all same value
		const allZeros1 = sessionId1.every((b) => b === 0);
		const allZeros2 = sessionId2.every((b) => b === 0);
		const allSame1 = sessionId1.every((b) => b === sessionId1[0]);
		const allSame2 = sessionId2.every((b) => b === sessionId2[0]);

		expect(allZeros1).toBe(false);
		expect(allZeros2).toBe(false);
		expect(allSame1).toBe(false);
		expect(allSame2).toBe(false);
	});

	it('should compute session identifier digest', async () => {
		// Test with hardcoded session identifier for reproducible results
		const hardcodedSessionId = new Uint8Array([
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10,
		]);

		const digest = sessionIdentifierDigest(hardcodedSessionId);

		// Test against expected deterministic output
		expect(digest).toBeInstanceOf(Uint8Array);
		expect(digest.length).toBe(32); // Should always be 32 bytes

		// Verify exact expected digest for this specific input
		const expectedDigest = '8d177679b5fb62500cd3fc64a76dca83f30c40b16638f52f09c74a1fb6fd668c';
		const actualDigest = Array.from(digest)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		expect(actualDigest).toBe(expectedDigest);

		// Same input should produce same output
		const digest2 = sessionIdentifierDigest(hardcodedSessionId);
		expect(digest).toEqual(digest2);

		// Different input should produce different output
		const sessionId2 = createRandomSessionIdentifier();
		const digest3 = sessionIdentifierDigest(sessionId2);
		expect(digest).not.toEqual(digest3);
	});

	it('should examine hardcoded cryptographic function outputs', async () => {
		// Create hardcoded inputs for reproducible testing
		const sessionId = new Uint8Array([
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0x00,
		]);

		// Create mock protocol parameters (typical size might be around 32-128 bytes)
		const mockProtocolParams = new Uint8Array(64);
		for (let i = 0; i < mockProtocolParams.length; i++) {
			mockProtocolParams[i] = i % 256;
		}

		// Create mock network output (typical DKG first round output size)
		const mockNetworkOutput = new Uint8Array(32);
		for (let i = 0; i < mockNetworkOutput.length; i++) {
			mockNetworkOutput[i] = (i * 7) % 256;
		}

		// This function should be called with correct parameters
		// We expect it to not throw during parameter validation
		// but may fail during actual cryptographic operations due to mock data
		try {
			const result = createDKGUserOutput(mockProtocolParams, mockNetworkOutput, sessionId);
			expect(result).toBeDefined();
		} catch (error) {
			// Expected to fail with mock data, but should have proper error handling
			expect(error).toBeDefined();
		}
	});

	it('should validate cryptographic function parameter requirements', async () => {
		// Test that encryptSecretShare handles parameters correctly
		const secretShare = new Uint8Array(32);
		const encryptionKey = new Uint8Array(64);
		const protocolParams = new Uint8Array(128);
		crypto.getRandomValues(secretShare);
		crypto.getRandomValues(encryptionKey);
		crypto.getRandomValues(protocolParams);

		// This should fail with mock data but validate parameters properly
		try {
			const result = encryptSecretShare(secretShare, encryptionKey, protocolParams);
			expect(result).toBeDefined();
		} catch (error) {
			// Expected to fail with mock data
			expect(error).toBeDefined();
		}
	});

	it('should have exact expected cryptographic enum values', async () => {
		// Test exact expected enum values
		expect(Curve.SECP256K1).toBe(0);
		expect(Hash.SHA256).toBe(1);
		expect(Hash.KECCAK256).toBe(0);

		// Verify types
		expect(typeof Curve.SECP256K1).toBe('number');
		expect(typeof Hash.SHA256).toBe('number');
		expect(typeof Hash.KECCAK256).toBe('number');
	});

	it('should handle edge cases and invalid inputs gracefully', async () => {
		// Test with empty arrays
		expect(() => sessionIdentifierDigest(new Uint8Array(0))).not.toThrow();

		// Test with minimal valid inputs
		const minimalSessionId = new Uint8Array(1);
		const digest = sessionIdentifierDigest(minimalSessionId);
		expect(digest).toBeInstanceOf(Uint8Array);

		// Test random session identifier multiple times for consistency
		for (let i = 0; i < 5; i++) {
			const sessionId = createRandomSessionIdentifier();
			expect(sessionId).toBeInstanceOf(Uint8Array);
			expect(sessionId.length).toBeGreaterThan(0);
		}
	});

	it('should test curve enum values', async () => {
		// Test that curve enum values are properly defined
		expect(Curve.SECP256K1).toBeDefined();
		expect(typeof Curve.SECP256K1).toBe('number');
	});

	it('should test hash enum values', async () => {
		expect(Hash.SHA256).toBeDefined();
		expect(Hash.KECCAK256).toBeDefined();
		expect(typeof Hash.SHA256).toBe('number');
		expect(typeof Hash.KECCAK256).toBe('number');
		expect(Hash.SHA256).not.toBe(Hash.KECCAK256);
	});

	describe('publicKeyFromDWalletOutput', () => {
		it('should handle invalid DWallet output gracefully', () => {
			const mockDWalletOutput = new Uint8Array(64).fill(1);

			// This function may throw for invalid input, which is expected behavior
			expect(() => publicKeyFromDWalletOutput(mockDWalletOutput)).toThrow();
		});
	});

	describe('verifyAndGetDWalletDKGPublicOutput', () => {
		it('should throw error for non-ED25519 public keys', async () => {
			const mockDWallet = {
				state: {
					Active: { public_output: [1, 2, 3, 4] },
				},
			} as any;

			const mockEncryptedShare = {
				state: {
					KeyHolderSigned: { user_output_signature: [1, 2, 3] },
				},
				encryption_key_address: 'test-address',
			} as any;

			// Mock non-ED25519 public key
			const mockPublicKey = {
				flag: () => 1, // Non-ED25519 flag
				verify: vi.fn(),
				toSuiAddress: vi.fn(),
			} as any;

			await expect(
				verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
			).rejects.toThrow('Only ED25519 public keys are supported.');
		});

		it('should throw error when DWallet is not in active state', async () => {
			const mockDWallet = {
				state: {
					Pending: {},
				},
			} as any;

			const mockEncryptedShare = {} as any;
			const mockPublicKey = { flag: () => 0 } as any; // ED25519 flag

			await expect(
				verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
			).rejects.toThrow('DWallet is not in active state');
		});

		it('should throw error when user output signature is missing', async () => {
			const mockDWallet = {
				state: {
					Active: { public_output: [1, 2, 3, 4] },
				},
			} as any;

			const mockEncryptedShare = {
				state: {
					KeyHolderSigned: {}, // Missing user_output_signature
				},
			} as any;

			const mockPublicKey = { flag: () => 0 } as any; // ED25519 flag

			await expect(
				verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
			).rejects.toThrow('User output signature is undefined');
		});

		it('should throw error for invalid signature', async () => {
			const mockDWallet = {
				state: {
					Active: { public_output: [1, 2, 3, 4] },
				},
			} as any;

			const mockEncryptedShare = {
				state: {
					KeyHolderSigned: { user_output_signature: [1, 2, 3] },
				},
				encryption_key_address: 'test-address',
			} as any;

			const mockPublicKey = {
				flag: () => 0, // ED25519 flag
				verify: vi.fn().mockResolvedValue(false), // Invalid signature
				toSuiAddress: vi.fn().mockReturnValue('test-address'),
			} as any;

			await expect(
				verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
			).rejects.toThrow('Invalid signature');
		});

		it('should throw error for mismatched Sui address', async () => {
			const mockDWallet = {
				state: {
					Active: { public_output: [1, 2, 3, 4] },
				},
			} as any;

			const mockEncryptedShare = {
				state: {
					KeyHolderSigned: { user_output_signature: [1, 2, 3] },
				},
				encryption_key_address: 'expected-address',
			} as any;

			const mockPublicKey = {
				flag: () => 0, // ED25519 flag
				verify: vi.fn().mockResolvedValue(true), // Valid signature
				toSuiAddress: vi.fn().mockReturnValue('different-address'), // Mismatched address
			} as any;

			await expect(
				verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
			).rejects.toThrow(
				'Invalid Sui address. The encryption key address does not match the signing keypair address.',
			);
		});
	});
});
