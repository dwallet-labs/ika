// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bytesToHex } from '@ika.xyz/core';
import { beforeAll, describe, expect, it } from 'vitest';

import {
	Curve,
	decryptUserShare,
	type DWallet,
	type EncryptedUserSecretKeyShare,
	getSuiAddress,
	getUserOutputSignature,
	UserShareEncryptionKeys,
} from '../../src';

describe('Sui-specific UserShareEncryptionKeys functions', () => {
	const testSeed1 = new Uint8Array(32);
	crypto.getRandomValues(testSeed1);

	let testKeys1: UserShareEncryptionKeys;

	beforeAll(async () => {
		testKeys1 = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(testSeed1, Curve.SECP256K1);
	});

	describe('getSuiAddress', () => {
		it('should return valid Sui address', () => {
			const address = getSuiAddress(testKeys1);

			expect(typeof address).toBe('string');
			expect(address.length).toBeGreaterThan(0);
			expect(address.startsWith('0x')).toBe(true);
		});

		it('should return consistent address for same keys', async () => {
			const newKeys = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(
				testSeed1,
				Curve.SECP256K1,
			);

			expect(getSuiAddress(testKeys1)).toEqual(getSuiAddress(newKeys));
		});

		it('should return different address for different keys', async () => {
			const otherSeed = new Uint8Array(32);
			crypto.getRandomValues(otherSeed);
			const otherKeys = await UserShareEncryptionKeys.fromRootSeedKey(otherSeed, Curve.SECP256K1);

			expect(getSuiAddress(testKeys1)).not.toEqual(getSuiAddress(otherKeys));
		});
	});

	describe('getUserOutputSignature', () => {
		it('should throw when DWallet is not in awaiting key holder signature state', async () => {
			const mockDWallet = {
				state: { Active: { public_output: [1, 2, 3] } },
				curve: 0,
			} as unknown as DWallet;

			const userPublicOutput = new Uint8Array([1, 2, 3]);

			await expect(
				getUserOutputSignature(testKeys1, mockDWallet, userPublicOutput),
			).rejects.toThrow('DWallet is not in awaiting key holder signature state');
		});
	});

	describe('decryptUserShare', () => {
		it('should throw when DWallet is not in active state', async () => {
			const mockDWallet = {
				state: { Pending: {} },
			} as unknown as DWallet;

			const mockEncryptedShare = {
				state: { KeyHolderSigned: { user_output_signature: [1, 2, 3] } },
				encryption_key_address: getSuiAddress(testKeys1),
				encrypted_centralized_secret_share_and_proof: [1, 2, 3],
			} as unknown as EncryptedUserSecretKeyShare;

			const protocolPublicParameters = new Uint8Array(64);

			await expect(
				decryptUserShare(testKeys1, mockDWallet, mockEncryptedShare, protocolPublicParameters),
			).rejects.toThrow('DWallet is not in active state');
		});
	});
});
