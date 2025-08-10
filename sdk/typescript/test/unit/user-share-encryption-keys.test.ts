// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';

import type { DWallet, EncryptedUserSecretKeyShare } from '../../src/client/types.js';
import { UserShareEncrytionKeys } from '../../src/client/user-share-encryption-keys.js';

describe('UserShareEncrytionKeys', () => {
	const testSeed = new Uint8Array(32);
	testSeed.fill(42);
	const keys = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

	describe('constructor', () => {
		it('should create instance with valid seed', () => {
			expect(keys.encryptionKey).toBeInstanceOf(Uint8Array);
			expect(keys.decryptionKey).toBeInstanceOf(Uint8Array);
		});

		it('should generate different keys for different seeds', () => {
			const seed1 = new Uint8Array(32);
			seed1.fill(1);
			const seed2 = new Uint8Array(32);
			seed2.fill(2);

			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(seed1);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(seed2);

			expect(keys1.encryptionKey).not.toEqual(keys2.encryptionKey);
			expect(keys1.decryptionKey).not.toEqual(keys2.decryptionKey);
			expect(keys1.getSigningPublicKeyBytes()).not.toEqual(keys2.getSigningPublicKeyBytes());
		});

		it('should generate consistent keys for same seed', () => {
			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			expect(keys1.encryptionKey).toEqual(keys2.encryptionKey);
			expect(keys1.decryptionKey).toEqual(keys2.decryptionKey);
			expect(keys1.getSigningPublicKeyBytes()).toEqual(keys2.getSigningPublicKeyBytes());
		});
	});

	describe('fromRootSeedKey', () => {
		it('should create instance from root seed key', () => {
			expect(keys).toBeInstanceOf(UserShareEncrytionKeys);
			expect(keys.encryptionKey).toBeInstanceOf(Uint8Array);
			expect(keys.decryptionKey).toBeInstanceOf(Uint8Array);
		});

		it('should generate same keys as constructor', () => {
			const constructorKeys = UserShareEncrytionKeys.fromRootSeedKey(testSeed);
			const staticKeys = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			expect(constructorKeys.encryptionKey).toEqual(staticKeys.encryptionKey);
			expect(constructorKeys.decryptionKey).toEqual(staticKeys.decryptionKey);
			expect(constructorKeys.getSigningPublicKeyBytes()).toEqual(
				staticKeys.getSigningPublicKeyBytes(),
			);
		});
	});

	describe('getPublicKey', () => {
		it('should return Ed25519 public key', () => {
			const publicKey = keys.getPublicKey();

			expect(publicKey).toBeDefined();
			expect(publicKey.toRawBytes()).toBeInstanceOf(Uint8Array);
		});

		it('should return consistent public key for same seed', () => {
			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			expect(keys1.getPublicKey().toRawBytes()).toEqual(keys2.getPublicKey().toRawBytes());
		});
	});

	describe('getSuiAddress', () => {
		it('should return valid Sui address', () => {
			const address = keys.getSuiAddress();

			expect(typeof address).toBe('string');
			expect(address.length).toBeGreaterThan(0);
		});

		it('should return consistent address for same seed', () => {
			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			expect(keys1.getSuiAddress()).toBe(keys2.getSuiAddress());
		});
	});

	describe('getSigningPublicKeyBytes', () => {
		it('should return raw bytes of public key', () => {
			const publicKeyBytes = keys.getSigningPublicKeyBytes();

			expect(publicKeyBytes).toBeInstanceOf(Uint8Array);
			expect(publicKeyBytes.length).toBeGreaterThan(0);
		});

		it('should return consistent bytes for same seed', () => {
			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			expect(keys1.getSigningPublicKeyBytes()).toEqual(keys2.getSigningPublicKeyBytes());
		});
	});

	describe('getEncryptionKeySignature', () => {
		it('should create signature over encryption key', async () => {
			const signature = await keys.getEncryptionKeySignature();

			expect(signature).toBeInstanceOf(Uint8Array);
			expect(signature.length).toBeGreaterThan(0);
		});

		it('should create consistent signature for same seed', async () => {
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(testSeed);

			const signature1 = await keys.getEncryptionKeySignature();
			const signature2 = await keys2.getEncryptionKeySignature();

			expect(signature1).toEqual(signature2);
		});
	});

	describe('decryptUserShare', () => {
		it('should throw error when DWallet is not active', async () => {
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
				keys.decryptUserShare(mockDWallet, mockEncryptedShare, protocolParams),
			).rejects.toThrow('DWallet is not active');
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
				keys.decryptUserShare(mockDWallet, mockEncryptedShare, protocolParams),
			).rejects.toThrow('DWallet is not active');
		});
	});

	describe('deterministic key generation', () => {
		it('should generate different keys for different seeds', () => {
			const seed1 = new Uint8Array(32);
			seed1.fill(1);
			const seed2 = new Uint8Array(32);
			seed2.fill(2);

			const keys1 = UserShareEncrytionKeys.fromRootSeedKey(seed1);
			const keys2 = UserShareEncrytionKeys.fromRootSeedKey(seed2);

			expect(keys1.encryptionKey).not.toEqual(keys2.encryptionKey);
			expect(keys1.decryptionKey).not.toEqual(keys2.decryptionKey);
			expect(keys1.getSigningPublicKeyBytes()).not.toEqual(keys2.getSigningPublicKeyBytes());
		});
	});
});
