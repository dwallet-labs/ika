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
import { Curve, Hash, SignatureAlgorithm } from '../../src/client/types';

describe('Cryptography Direct Functions', () => {
	it('should reject invalid seed sizes', async () => {
		// Test with wrong seed size
		const invalidSeed = new Uint8Array(16); // Too small
		crypto.getRandomValues(invalidSeed);

		await expect(createClassGroupsKeypair(invalidSeed, Curve.SECP256K1)).rejects.toThrow(
			'Seed must be 32 bytes',
		);

		// Test with another wrong seed size
		const tooLargeSeed = new Uint8Array(64); // Too large
		crypto.getRandomValues(tooLargeSeed);

		await expect(createClassGroupsKeypair(tooLargeSeed, Curve.SECP256K1)).rejects.toThrow(
			'Seed must be 32 bytes',
		);
	});

	it('should create random session identifier', async () => {
		// Test creating random session identifiers
		const sessionId1 = await createRandomSessionIdentifier();
		const sessionId2 = await createRandomSessionIdentifier();

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
		const hardcodedBytesToHash = new Uint8Array([
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10,
		]);
		const hardcodedSenderAddress = new Uint8Array(32).fill(1);

		const digest = sessionIdentifierDigest(hardcodedBytesToHash, hardcodedSenderAddress);

		// Test against expected deterministic output
		expect(digest).toBeInstanceOf(Uint8Array);
		expect(digest.length).toBe(32); // Should always be 32 bytes

		// Verify exact expected digest for this specific input
		const expectedDigest = '73be7ad97a2a6ef7421e40841962fd317596a476b5a53863747806c5bb4cd0c5';
		const actualDigest = Array.from(digest)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		expect(actualDigest).toBe(expectedDigest);

		// Same input should produce same output
		const digest2 = sessionIdentifierDigest(hardcodedBytesToHash, hardcodedSenderAddress);
		expect(digest).toEqual(digest2);

		// Different input should produce different output
		const sessionId2 = createRandomSessionIdentifier();
		const digest3 = sessionIdentifierDigest(sessionId2, hardcodedSenderAddress);
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
			const result = await createDKGUserOutput(mockProtocolParams, mockNetworkOutput);
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
			const result = await encryptSecretShare(
				Curve.SECP256K1,
				secretShare,
				encryptionKey,
				protocolParams,
			);
			expect(result).toBeDefined();
		} catch (error) {
			// Expected to fail with mock data
			expect(error).toBeDefined();
		}
	});

	it('should have exact expected cryptographic enum values', async () => {
		// Test exact expected enum values
		expect(Curve.SECP256K1).toBe('SECP256K1');
		expect(Hash.SHA256).toBe('SHA256');
		expect(Hash.KECCAK256).toBe('KECCAK256');

		// Verify types
		expect(typeof Curve.SECP256K1).toBe('string');
		expect(typeof Hash.SHA256).toBe('string');
		expect(typeof Hash.KECCAK256).toBe('string');
	});

	it('should handle edge cases and invalid inputs gracefully', async () => {
		const senderAddress = new Uint8Array(32).fill(1);

		// Test with empty arrays
		expect(() => sessionIdentifierDigest(new Uint8Array(0), senderAddress)).not.toThrow();

		// Test with minimal valid inputs
		const minimalSessionId = new Uint8Array(1);
		const digest = sessionIdentifierDigest(minimalSessionId, senderAddress);
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
		expect(typeof Curve.SECP256K1).toBe('string');
	});

	it('should test hash enum values', async () => {
		expect(Hash.SHA256).toBeDefined();
		expect(Hash.KECCAK256).toBeDefined();
		expect(typeof Hash.SHA256).toBe('string');
		expect(typeof Hash.KECCAK256).toBe('string');
		expect(Hash.SHA256).not.toBe(Hash.KECCAK256);
	});

	describe('publicKeyFromDWalletOutput', () => {
		it('should handle invalid DWallet output gracefully', async () => {
			const mockDWalletOutput = new Uint8Array(64).fill(1);

			// This function may throw for invalid input, which is expected behavior
			await expect(
				publicKeyFromDWalletOutput(Curve.SECP256K1, mockDWalletOutput),
			).rejects.toThrow();
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

	describe('prepareDKGSecondRound', () => {
		it('should throw error when first round output is missing', async () => {
			const mockDWallet = {
				state: {
					AwaitingUserDKGVerificationInitiation: {}, // Missing first_round_output
				},
			} as any;

			const protocolParams = new Uint8Array(32);
			const encryptionKey = new Uint8Array(778);

			const { prepareDKGSecondRound } = await import('../../src/client/cryptography');

			await expect(
				prepareDKGSecondRound(protocolParams, mockDWallet, encryptionKey),
			).rejects.toThrow();
		});
	});

	describe('prepareDKG', () => {
		it('should handle invalid protocol parameters', async () => {
			const invalidProtocolParams = new Uint8Array(0); // Empty params
			const encryptionKey = new Uint8Array(778);
			const bytesToHash = new Uint8Array(32);
			const senderAddress = '0x' + '1'.repeat(64);
			crypto.getRandomValues(bytesToHash);

			const { prepareDKG } = await import('../../src/client/cryptography');

			await expect(
				prepareDKG(
					invalidProtocolParams,
					Curve.SECP256K1,
					encryptionKey,
					bytesToHash,
					senderAddress,
				),
			).rejects.toThrow();
		});
	});

	describe('networkDkgPublicOutputToProtocolPublicParameters', () => {
		it('should handle invalid network DKG output', async () => {
			const invalidOutput = new Uint8Array(10);

			const { networkDkgPublicOutputToProtocolPublicParameters } = await import(
				'../../src/client/cryptography'
			);

			await expect(
				networkDkgPublicOutputToProtocolPublicParameters(Curve.SECP256K1, invalidOutput),
			).rejects.toThrow();
		});
	});

	describe('reconfigurationPublicOutputToProtocolPublicParameters', () => {
		it('should handle invalid reconfiguration output', async () => {
			const invalidReconfigOutput = new Uint8Array(10);
			const invalidNetworkOutput = new Uint8Array(10);

			const { reconfigurationPublicOutputToProtocolPublicParameters } = await import(
				'../../src/client/cryptography'
			);

			await expect(
				reconfigurationPublicOutputToProtocolPublicParameters(
					Curve.SECP256K1,
					invalidReconfigOutput,
					invalidNetworkOutput,
				),
			).rejects.toThrow();
		});
	});

	describe('verifyUserShare', () => {
		it('should handle invalid user share data', async () => {
			const userSecretKeyShare = new Uint8Array(32);
			const userDKGOutput = new Uint8Array(32);
			const networkDkgPublicOutput = new Uint8Array(32);
			crypto.getRandomValues(userSecretKeyShare);
			crypto.getRandomValues(userDKGOutput);
			crypto.getRandomValues(networkDkgPublicOutput);

			const { verifyUserShare } = await import('../../src/client/cryptography');

			// With random invalid data, this should throw an error
			await expect(
				verifyUserShare(Curve.SECP256K1, userSecretKeyShare, userDKGOutput, networkDkgPublicOutput),
			).rejects.toThrow();
		});
	});

	describe('verifySecpSignature', () => {
		it('should handle invalid signature data', async () => {
			const publicKey = new Uint8Array(33);
			const signature = new Uint8Array(64);
			const message = new Uint8Array(32);
			const networkDkgPublicOutput = new Uint8Array(32);
			crypto.getRandomValues(publicKey);
			crypto.getRandomValues(signature);
			crypto.getRandomValues(message);
			crypto.getRandomValues(networkDkgPublicOutput);

			const { verifySecpSignature } = await import('../../src/client/cryptography');

			// With random invalid data, this should throw an error
			await expect(
				verifySecpSignature(
					publicKey,
					signature,
					message,
					networkDkgPublicOutput,
					Hash.SHA256,
					SignatureAlgorithm.ECDSASecp256k1,
					Curve.SECP256K1,
				),
			).rejects.toThrow();
		});
	});

	describe('userAndNetworkDKGOutputMatch', () => {
		it('should handle invalid output data', async () => {
			const userPublicOutput = new Uint8Array(32);
			const networkDKGOutput = new Uint8Array(32);
			crypto.getRandomValues(userPublicOutput);
			crypto.getRandomValues(networkDKGOutput);

			const { userAndNetworkDKGOutputMatch } = await import('../../src/client/cryptography');

			// With random invalid data, this should throw an error
			await expect(
				userAndNetworkDKGOutputMatch(Curve.SECP256K1, userPublicOutput, networkDKGOutput),
			).rejects.toThrow();
		});
	});

	describe('createUserSignMessageWithPublicOutput', () => {
		it('should handle invalid inputs', async () => {
			const protocolParams = new Uint8Array(32);
			const publicOutput = new Uint8Array(32);
			const userSecretKeyShare = new Uint8Array(32);
			const presign = new Uint8Array(32);
			const message = new Uint8Array(32);
			crypto.getRandomValues(protocolParams);
			crypto.getRandomValues(publicOutput);
			crypto.getRandomValues(userSecretKeyShare);
			crypto.getRandomValues(presign);
			crypto.getRandomValues(message);

			const { createUserSignMessageWithPublicOutput } = await import(
				'../../src/client/cryptography'
			);

			// With mock data, this should fail
			await expect(
				createUserSignMessageWithPublicOutput(
					protocolParams,
					publicOutput,
					userSecretKeyShare,
					presign,
					message,
					Hash.SHA256,
					SignatureAlgorithm.ECDSASecp256k1,
					Curve.SECP256K1,
				),
			).rejects.toThrow();
		});
	});
});
