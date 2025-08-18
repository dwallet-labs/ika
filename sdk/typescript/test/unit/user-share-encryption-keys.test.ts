// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { beforeAll, describe, expect, it } from 'vitest';

import type { DWallet, EncryptedUserSecretKeyShare } from '../../src/client/types.js';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys.js';

describe('UserShareEncryptionKeys', () => {
	// Pre-create two distinct keys to reuse across tests for better performance
	let testKeys1: UserShareEncryptionKeys;
	let testKeys2: UserShareEncryptionKeys;
	let testSignature1: Uint8Array;
	let testSignature2: Uint8Array;

	const testSeed1 = new Uint8Array(32).fill(42);
	const testSeed2 = new Uint8Array(32).fill(7);

	beforeAll(async () => {
		// Generate keys once and reuse across tests
		testKeys1 = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);
		testKeys2 = UserShareEncryptionKeys.fromRootSeedKey(testSeed2);

		// Pre-generate signatures for performance
		testSignature1 = await testKeys1.getEncryptionKeySignature();
		testSignature2 = await testKeys2.getEncryptionKeySignature();
	});

	// Helper function to validate key properties
	function validateKeyProperties(keys: UserShareEncryptionKeys, keyName: string) {
		expect(keys.encryptionKey, `${keyName}.encryptionKey should be Uint8Array`).toBeInstanceOf(
			Uint8Array,
		);
		expect(keys.decryptionKey, `${keyName}.decryptionKey should be Uint8Array`).toBeInstanceOf(
			Uint8Array,
		);
		expect(
			keys.encryptionKey.length,
			`${keyName}.encryptionKey should have proper length`,
		).toBeGreaterThan(0);
		expect(
			keys.decryptionKey.length,
			`${keyName}.decryptionKey should have proper length`,
		).toBeGreaterThan(0);
	}

	// Helper function to validate public key properties
	function validatePublicKeyProperties(keys: UserShareEncryptionKeys, keyName: string) {
		const publicKey = keys.getPublicKey();
		const publicKeyBytes = keys.getSigningPublicKeyBytes();
		const address = keys.getSuiAddress();

		expect(publicKey, `${keyName} public key should be defined`).toBeDefined();
		expect(
			publicKey.toRawBytes(),
			`${keyName} public key bytes should be Uint8Array`,
		).toBeInstanceOf(Uint8Array);
		expect(
			publicKeyBytes,
			`${keyName} signing public key bytes should be Uint8Array`,
		).toBeInstanceOf(Uint8Array);
		expect(
			publicKeyBytes.length,
			`${keyName} public key bytes should not be empty`,
		).toBeGreaterThan(0);
		expect(typeof address, `${keyName} address should be string`).toBe('string');
		expect(address.length, `${keyName} address should not be empty`).toBeGreaterThan(0);
	}

	describe('constructor', () => {
		it('should create instance with valid seed', () => {
			validateKeyProperties(testKeys1, 'testKeys1');
			validateKeyProperties(testKeys2, 'testKeys2');
		});

		it('should generate different keys for different seeds', () => {
			// Use pre-created keys instead of generating new ones
			expect(
				testKeys1.encryptionKey,
				'Different seeds should produce different encryption keys',
			).not.toEqual(testKeys2.encryptionKey);
			expect(
				testKeys1.decryptionKey,
				'Different seeds should produce different decryption keys',
			).not.toEqual(testKeys2.decryptionKey);
			expect(
				testKeys1.getSigningPublicKeyBytes(),
				'Different seeds should produce different signing keys',
			).not.toEqual(testKeys2.getSigningPublicKeyBytes());
		});

		it('should generate consistent keys for same seed', () => {
			// Test that same seed generates same keys (using testSeed1)
			const keys1 = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);
			const keys2 = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);

			expect(keys1.encryptionKey, 'Same seed should produce same encryption key').toEqual(
				keys2.encryptionKey,
			);
			expect(keys1.decryptionKey, 'Same seed should produce same decryption key').toEqual(
				keys2.decryptionKey,
			);
			expect(keys1.getSigningPublicKeyBytes(), 'Same seed should produce same signing key').toEqual(
				keys2.getSigningPublicKeyBytes(),
			);

			// Should also match our pre-created key
			expect(keys1.encryptionKey, 'Generated key should match pre-created key').toEqual(
				testKeys1.encryptionKey,
			);
		});
	});

	describe('fromRootSeedKey', () => {
		it('should create instance from root seed key', () => {
			expect(testKeys1, 'testKeys1 should be UserShareEncryptionKeys instance').toBeInstanceOf(
				UserShareEncryptionKeys,
			);
			expect(testKeys2, 'testKeys2 should be UserShareEncryptionKeys instance').toBeInstanceOf(
				UserShareEncryptionKeys,
			);
			validateKeyProperties(testKeys1, 'testKeys1');
			validateKeyProperties(testKeys2, 'testKeys2');
		});

		it('should generate same keys as constructor', () => {
			// Test with our pre-created seed1
			const newKeys = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);

			expect(newKeys.encryptionKey, 'New keys should match pre-created encryption key').toEqual(
				testKeys1.encryptionKey,
			);
			expect(newKeys.decryptionKey, 'New keys should match pre-created decryption key').toEqual(
				testKeys1.decryptionKey,
			);
			expect(
				newKeys.getSigningPublicKeyBytes(),
				'New keys should match pre-created signing key',
			).toEqual(testKeys1.getSigningPublicKeyBytes());
		});
	});

	describe('getPublicKey', () => {
		it('should return Ed25519 public key', () => {
			validatePublicKeyProperties(testKeys1, 'testKeys1');
			validatePublicKeyProperties(testKeys2, 'testKeys2');
		});

		it('should return consistent public key for same seed', () => {
			const newKeys = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);

			expect(
				testKeys1.getPublicKey().toRawBytes(),
				'Same seed should produce same public key bytes',
			).toEqual(newKeys.getPublicKey().toRawBytes());
		});
	});

	describe('getSuiAddress', () => {
		it('should return valid Sui address', () => {
			// Test both pre-created keys
			const address1 = testKeys1.getSuiAddress();
			const address2 = testKeys2.getSuiAddress();

			expect(typeof address1, 'testKeys1 address should be string').toBe('string');
			expect(address1.length, 'testKeys1 address should not be empty').toBeGreaterThan(0);
			expect(typeof address2, 'testKeys2 address should be string').toBe('string');
			expect(address2.length, 'testKeys2 address should not be empty').toBeGreaterThan(0);

			// Different keys should produce different addresses
			expect(address1, 'Different keys should produce different addresses').not.toBe(address2);
		});

		it('should return consistent address for same seed', () => {
			const newKeys = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);

			expect(testKeys1.getSuiAddress(), 'Same seed should produce same address').toBe(
				newKeys.getSuiAddress(),
			);
		});
	});

	describe('getSigningPublicKeyBytes', () => {
		it('should return raw bytes of public key', () => {
			const publicKeyBytes1 = testKeys1.getSigningPublicKeyBytes();
			const publicKeyBytes2 = testKeys2.getSigningPublicKeyBytes();

			expect(publicKeyBytes1, 'testKeys1 public key bytes should be Uint8Array').toBeInstanceOf(
				Uint8Array,
			);
			expect(
				publicKeyBytes1.length,
				'testKeys1 public key bytes should not be empty',
			).toBeGreaterThan(0);
			expect(publicKeyBytes2, 'testKeys2 public key bytes should be Uint8Array').toBeInstanceOf(
				Uint8Array,
			);
			expect(
				publicKeyBytes2.length,
				'testKeys2 public key bytes should not be empty',
			).toBeGreaterThan(0);

			// Different keys should produce different bytes
			expect(
				publicKeyBytes1,
				'Different keys should produce different public key bytes',
			).not.toEqual(publicKeyBytes2);
		});

		it('should return consistent bytes for same seed', () => {
			const newKeys = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);

			expect(
				testKeys1.getSigningPublicKeyBytes(),
				'Same seed should produce same public key bytes',
			).toEqual(newKeys.getSigningPublicKeyBytes());
		});
	});

	describe('getEncryptionKeySignature', () => {
		it('should create signature over encryption key', async () => {
			// Use pre-generated signatures for performance
			expect(testSignature1, 'testSignature1 should be Uint8Array').toBeInstanceOf(Uint8Array);
			expect(testSignature1.length, 'testSignature1 should not be empty').toBeGreaterThan(0);
			expect(testSignature2, 'testSignature2 should be Uint8Array').toBeInstanceOf(Uint8Array);
			expect(testSignature2.length, 'testSignature2 should not be empty').toBeGreaterThan(0);

			// Different keys should produce different signatures
			expect(testSignature1, 'Different keys should produce different signatures').not.toEqual(
				testSignature2,
			);
		});

		it('should create consistent signature for same seed', async () => {
			const newKeys = UserShareEncryptionKeys.fromRootSeedKey(testSeed1);
			const newSignature = await newKeys.getEncryptionKeySignature();

			expect(testSignature1, 'Same seed should produce same signature').toEqual(newSignature);
		});
	});

	describe('decryptUserShare', () => {
		it('should throw error when DWallet is not in active state', async () => {
			const mockDWallet: DWallet = {
				id: { id: 'test-id' },
				state: {
					AwaitingKeyHolderSignature: {
						public_output: new Uint8Array([1, 2, 3, 4, 5]),
					},
				},
			} as unknown as DWallet;

			const mockEncryptedShare: EncryptedUserSecretKeyShare = {
				id: { id: 'share-id' },
				created_at_epoch: 1,
				dwallet_id: { id: 'dwallet-id' },
				encrypted_centralized_secret_share_and_proof: new Uint8Array([1, 2, 3]),
				encryption_key_id: { id: 'key-id' },
				encryption_key_address: '0x123',
				source_encrypted_user_secret_key_share_id: null,
				state: { AwaitingNetworkVerification: {} },
			} as unknown as EncryptedUserSecretKeyShare;

			const protocolParams = new Uint8Array([1, 2, 3]);

			await expect(
				testKeys1.decryptUserShare(mockDWallet, mockEncryptedShare, protocolParams),
			).rejects.toThrow('DWallet is not in active state');
		});

		it('should throw error when DWallet public output is missing', async () => {
			const mockDWallet: DWallet = {
				id: { id: 'test-id' },
				state: {
					Active: {},
				},
			} as unknown as DWallet;

			const mockEncryptedShare: EncryptedUserSecretKeyShare = {
				id: { id: 'share-id' },
				created_at_epoch: 1,
				dwallet_id: { id: 'dwallet-id' },
				encrypted_centralized_secret_share_and_proof: new Uint8Array([1, 2, 3]),
				encryption_key_id: { id: 'key-id' },
				encryption_key_address: '0x123',
				source_encrypted_user_secret_key_share_id: null,
				state: { AwaitingNetworkVerification: {} },
			} as unknown as EncryptedUserSecretKeyShare;

			const protocolParams = new Uint8Array([1, 2, 3]);

			await expect(
				testKeys1.decryptUserShare(mockDWallet, mockEncryptedShare, protocolParams),
			).rejects.toThrow('DWallet is not in active state');
		});
	});

	describe('deterministic key generation', () => {
		it('should generate different keys for different seeds', () => {
			// Use pre-created keys that were generated from different seeds
			expect(
				testKeys1.encryptionKey,
				'Different seeds should produce different encryption keys',
			).not.toEqual(testKeys2.encryptionKey);
			expect(
				testKeys1.decryptionKey,
				'Different seeds should produce different decryption keys',
			).not.toEqual(testKeys2.decryptionKey);
			expect(
				testKeys1.getSigningPublicKeyBytes(),
				'Different seeds should produce different signing keys',
			).not.toEqual(testKeys2.getSigningPublicKeyBytes());
		});
	});

	describe('verifySignature', () => {
		it('should verify signatures correctly', async () => {
			// Use pre-created keys and signatures for performance
			const isValid1 = await testKeys1.verifySignature(testKeys1.encryptionKey, testSignature1);
			const isValid2 = await testKeys2.verifySignature(testKeys2.encryptionKey, testSignature2);

			expect(isValid1, 'testKeys1 signature should be valid').toBe(true);
			expect(isValid2, 'testKeys2 signature should be valid').toBe(true);
		});

		it('should reject invalid signatures', async () => {
			const wrongMessage = new Uint8Array([1, 2, 3, 4, 6]);

			// Test with both pre-created keys
			const isValid1 = await testKeys1.verifySignature(wrongMessage, testSignature1);
			const isValid2 = await testKeys2.verifySignature(wrongMessage, testSignature2);

			expect(isValid1, 'testKeys1 wrong message should be invalid').toBe(false);
			expect(isValid2, 'testKeys2 wrong message should be invalid').toBe(false);

			// Test cross-key verification (should also be invalid)
			const crossValid1 = await testKeys1.verifySignature(testKeys2.encryptionKey, testSignature1);
			const crossValid2 = await testKeys2.verifySignature(testKeys1.encryptionKey, testSignature2);

			expect(crossValid1, 'Cross-key verification should be invalid').toBe(false);
			expect(crossValid2, 'Cross-key verification should be invalid').toBe(false);
		});
	});

	describe('serialization', () => {
		it('should create serialized bytes', () => {
			// Test serialization with both pre-created keys
			const serialized1 = testKeys1.toShareEncryptionKeysBytes();
			const serialized2 = testKeys2.toShareEncryptionKeysBytes();

			expect(serialized1, 'testKeys1 serialized should be Uint8Array').toBeInstanceOf(Uint8Array);
			expect(serialized1.length, 'testKeys1 serialized should not be empty').toBeGreaterThan(0);
			expect(serialized2, 'testKeys2 serialized should be Uint8Array').toBeInstanceOf(Uint8Array);
			expect(serialized2.length, 'testKeys2 serialized should not be empty').toBeGreaterThan(0);

			// Different keys should produce different serialized data
			expect(serialized1, 'Different keys should produce different serialized data').not.toEqual(
				serialized2,
			);
		});
	});

	describe('error handling for signatures', () => {
		it('should throw error when DWallet is not in awaiting key holder signature state', async () => {
			// Create mock DWallet without AwaitingKeyHolderSignature state
			const mockDWallet = {
				state: {
					Active: { public_output: [1, 2, 3] },
				},
			} as any;

			const userPublicOutput = new Uint8Array([1, 2, 3]);

			// Test with pre-created keys
			await expect(
				testKeys1.getUserOutputSignature(mockDWallet, userPublicOutput),
				'testKeys1 should throw for wrong state',
			).rejects.toThrow('DWallet is not in awaiting key holder signature state');

			await expect(
				testKeys2.getUserOutputSignature(mockDWallet, userPublicOutput),
				'testKeys2 should throw for wrong state',
			).rejects.toThrow('DWallet is not in awaiting key holder signature state');
		});
	});

	describe('serialization deserialization', () => {
		it('should cover fromShareEncryptionKeysBytes method', () => {
			// Test that the static method exists and can be called
			expect(UserShareEncryptionKeys.fromShareEncryptionKeysBytes).toBeDefined();
			expect(typeof UserShareEncryptionKeys.fromShareEncryptionKeysBytes).toBe('function');
		});
	});
});
