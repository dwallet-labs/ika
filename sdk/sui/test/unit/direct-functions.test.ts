// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it, vi } from 'vitest';

import { verifyAndGetDWalletDKGPublicOutput } from '../../src';

describe('verifyAndGetDWalletDKGPublicOutput', () => {
	it('should throw error for non-ED25519 public keys', async () => {
		const mockDWallet = {
			state: { Active: { public_output: [1, 2, 3, 4] } },
		} as any;

		const mockEncryptedShare = {
			state: { KeyHolderSigned: { user_output_signature: [1, 2, 3] } },
			encryption_key_address: 'test-address',
		} as any;

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
		const mockDWallet = { state: { Pending: {} } } as any;
		const mockEncryptedShare = {} as any;
		const mockPublicKey = { flag: () => 0 } as any;

		await expect(
			verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
		).rejects.toThrow('DWallet is not in active state');
	});

	it('should throw error when user output signature is missing', async () => {
		const mockDWallet = {
			state: { Active: { public_output: [1, 2, 3, 4] } },
		} as any;

		const mockEncryptedShare = {
			state: { KeyHolderSigned: {} },
		} as any;

		const mockPublicKey = { flag: () => 0 } as any;

		await expect(
			verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
		).rejects.toThrow('User output signature is undefined');
	});

	it('should throw error for invalid signature', async () => {
		const mockDWallet = {
			state: { Active: { public_output: [1, 2, 3, 4] } },
		} as any;

		const mockEncryptedShare = {
			state: { KeyHolderSigned: { user_output_signature: [1, 2, 3] } },
			encryption_key_address: 'test-address',
		} as any;

		const mockPublicKey = {
			flag: () => 0,
			verify: vi.fn().mockResolvedValue(false),
			toSuiAddress: vi.fn().mockReturnValue('test-address'),
		} as any;

		await expect(
			verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
		).rejects.toThrow('Invalid signature');
	});

	it('should throw error for mismatched Sui address', async () => {
		const mockDWallet = {
			state: { Active: { public_output: [1, 2, 3, 4] } },
		} as any;

		const mockEncryptedShare = {
			state: { KeyHolderSigned: { user_output_signature: [1, 2, 3] } },
			encryption_key_address: 'expected-address',
		} as any;

		const mockPublicKey = {
			flag: () => 0,
			verify: vi.fn().mockResolvedValue(true),
			toSuiAddress: vi.fn().mockReturnValue('different-address'),
		} as any;

		await expect(
			verifyAndGetDWalletDKGPublicOutput(mockDWallet, mockEncryptedShare, mockPublicKey),
		).rejects.toThrow('The encryption key address does not match');
	});

	it('should return public output on successful verification', async () => {
		const publicOutput = [10, 20, 30, 40];
		const mockDWallet = {
			state: { Active: { public_output: publicOutput } },
		} as any;

		const mockEncryptedShare = {
			state: { KeyHolderSigned: { user_output_signature: [1, 2, 3] } },
			encryption_key_address: 'matching-address',
		} as any;

		const mockPublicKey = {
			flag: () => 0,
			verify: vi.fn().mockResolvedValue(true),
			toSuiAddress: vi.fn().mockReturnValue('matching-address'),
		} as any;

		const result = await verifyAndGetDWalletDKGPublicOutput(
			mockDWallet,
			mockEncryptedShare,
			mockPublicKey,
		);
		expect(result).toEqual(new Uint8Array(publicOutput));
	});
});
