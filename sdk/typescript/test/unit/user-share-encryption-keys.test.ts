// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';

import type { DWallet, EncryptedUserSecretKeyShare } from '../../src/client/types.js';
import { UserShareEncrytionKeys } from '../../src/client/user-share-encryption-keys.js';

describe('UserShareEncrytionKeys', () => {
	const testSeed = new Uint8Array(32);
	testSeed.fill(42);
	const keys = new UserShareEncrytionKeys(testSeed);

	describe('constructor', () => {
		it('should create instance with valid seed', () => {
			expect(keys.encryptionKey).toBeInstanceOf(Uint8Array);
			expect(keys.decryptionKey).toBeInstanceOf(Uint8Array);
			expect(keys.encryptedSecretShareSigningKeypair).toBeDefined();
		});

		it('should generate different keys for different seeds', () => {
			const seed1 = new Uint8Array(32);
			seed1.fill(1);
			const seed2 = new Uint8Array(32);
			seed2.fill(2);

			const keys1 = new UserShareEncrytionKeys(seed1);
			const keys2 = new UserShareEncrytionKeys(seed2);

			expect(keys1.encryptionKey).not.toEqual(keys2.encryptionKey);
			expect(keys1.decryptionKey).not.toEqual(keys2.decryptionKey);
			expect(keys1.getSigningPublicKeyBytes()).not.toEqual(keys2.getSigningPublicKeyBytes());
		});

		it('should generate consistent keys for same seed', () => {
			const keys1 = new UserShareEncrytionKeys(testSeed);
			const keys2 = new UserShareEncrytionKeys(testSeed);

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
			const constructorKeys = new UserShareEncrytionKeys(testSeed);
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
			const keys1 = new UserShareEncrytionKeys(testSeed);
			const keys2 = new UserShareEncrytionKeys(testSeed);

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
			const keys1 = new UserShareEncrytionKeys(testSeed);
			const keys2 = new UserShareEncrytionKeys(testSeed);

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
			const keys1 = new UserShareEncrytionKeys(testSeed);
			const keys2 = new UserShareEncrytionKeys(testSeed);

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
			const keys2 = new UserShareEncrytionKeys(testSeed);

			const signature1 = await keys.getEncryptionKeySignature();
			const signature2 = await keys2.getEncryptionKeySignature();

			expect(signature1).toEqual(signature2);
		});
	});

	describe('getUserOutputSignature', () => {
		it('should create signature over DWallet public output', async () => {
			const mockDWallet: DWallet = {
				id: { id: 'test-id' },
				state: {
					AwaitingKeyHolderSignature: {
						public_output: new Uint8Array([1, 2, 3, 4, 5]),
					},
				},
			} as unknown as DWallet;

			const signature = await keys.getUserOutputSignature(mockDWallet);

			expect(signature).toBeInstanceOf(Uint8Array);
			expect(signature.length).toBeGreaterThan(0);
		});

		it('should throw error when DWallet is not in awaiting key holder signature state', async () => {
			const mockDWallet: DWallet = {
				id: { id: 'test-id' },
				state: {
					Active: {
						public_output: new Uint8Array([1, 2, 3, 4, 5]),
					},
				},
			} as unknown as DWallet;

			await expect(keys.getUserOutputSignature(mockDWallet)).rejects.toThrow(
				'DWallet is not in awaiting key holder signature state',
			);
		});

		it('should throw error when public output is missing', async () => {
			const mockDWallet: DWallet = {
				id: { id: 'test-id' },
				state: {
					AwaitingKeyHolderSignature: {},
				},
			} as DWallet;

			await expect(keys.getUserOutputSignature(mockDWallet)).rejects.toThrow(
				'DWallet is not in awaiting key holder signature state',
			);
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

			const keys1 = new UserShareEncrytionKeys(seed1);
			const keys2 = new UserShareEncrytionKeys(seed2);

			expect(keys1.encryptionKey).not.toEqual(keys2.encryptionKey);
			expect(keys1.decryptionKey).not.toEqual(keys2.decryptionKey);
			expect(keys1.getSigningPublicKeyBytes()).not.toEqual(keys2.getSigningPublicKeyBytes());
		});
	});

	describe('constructor with explicit keys', () => {
		it('should create instance with 32-byte encryption/decryption keys', () => {
			const enc = new Uint8Array(32);
			enc.fill(7);
			const dec = new Uint8Array(32);
			dec.fill(9);

			const byKeys = new UserShareEncrytionKeys(enc, dec);

			expect(byKeys.encryptionKey).toEqual(enc);
			expect(byKeys.decryptionKey).toEqual(dec);
			expect(byKeys.getSigningPublicKeyBytes()).toBeInstanceOf(Uint8Array);
			expect(byKeys.getSigningPublicKeyBytes().length).toBeGreaterThan(0);
		});

		it('should be deterministic for same key inputs', async () => {
			const enc = new Uint8Array(32);
			enc.fill(3);
			const dec = new Uint8Array(32);
			dec.fill(5);

			const a = new UserShareEncrytionKeys(enc, dec);
			const b = new UserShareEncrytionKeys(enc, dec);

			expect(a.encryptionKey).toEqual(b.encryptionKey);
			expect(a.decryptionKey).toEqual(b.decryptionKey);
			expect(a.getSigningPublicKeyBytes()).toEqual(b.getSigningPublicKeyBytes());
			expect(a.getSuiAddress()).toBe(b.getSuiAddress());
			expect(await a.getEncryptionKeySignature()).toEqual(await b.getEncryptionKeySignature());
		});

		it('should throw when keys are not 32 bytes', () => {
			const enc31 = new Uint8Array(31);
			const dec32 = new Uint8Array(32);
			dec32.fill(1);
			expect(() => new UserShareEncrytionKeys(enc31, dec32)).toThrow(
				'encryptionKey and decryptionKey must be 32 bytes',
			);

			const enc32 = new Uint8Array(32);
			enc32.fill(2);
			const dec33 = new Uint8Array(33);
			expect(() => new UserShareEncrytionKeys(enc32, dec33 as unknown as Uint8Array)).toThrow(
				'encryptionKey and decryptionKey must be 32 bytes',
			);
		});
	});

	describe('fromClassGroupKeysBytes / toClassGroupKeysBytes', () => {
		it('should construct from 64-byte buffer (32 enc + 32 dec)', () => {
			const enc = new Uint8Array(32);
			enc.fill(11);
			const dec = new Uint8Array(32);
			dec.fill(13);
			const bytes = new Uint8Array([...enc, ...dec]);

			const keys = UserShareEncrytionKeys.fromClassGroupKeysBytes(bytes);
			expect(keys.encryptionKey).toEqual(enc);
			expect(keys.decryptionKey).toEqual(dec);
		});

		it('should throw when buffer length is not 64 bytes', () => {
			const bad = new Uint8Array(63);
			expect(() => UserShareEncrytionKeys.fromClassGroupKeysBytes(bad)).toThrow(
				'classGroupKeysBytes must be 64 bytes (32 enc + 32 dec)',
			);
		});

		it('should round-trip via toClassGroupKeysBytes()', () => {
			const enc = new Uint8Array(32);
			enc.fill(21);
			const dec = new Uint8Array(32);
			dec.fill(22);

			const original = new UserShareEncrytionKeys(enc, dec);
			const bytes = original.toClassGroupKeysBytes();
			expect(bytes).toBeInstanceOf(Uint8Array);
			expect(bytes.length).toBe(64);
			expect(Array.from(bytes.slice(0, 32))).toEqual(Array.from(enc));
			expect(Array.from(bytes.slice(32))).toEqual(Array.from(dec));

			const reconstructed = UserShareEncrytionKeys.fromClassGroupKeysBytes(bytes);
			expect(reconstructed.encryptionKey).toEqual(original.encryptionKey);
			expect(reconstructed.decryptionKey).toEqual(original.decryptionKey);
			expect(reconstructed.getSigningPublicKeyBytes()).toEqual(original.getSigningPublicKeyBytes());
		});
	});
});
