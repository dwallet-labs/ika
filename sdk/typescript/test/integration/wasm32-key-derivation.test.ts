// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { createClassGroupsKeypair, Curve, UserShareEncryptionKeys } from '../../src/index.js';

const rootSeed = new Uint8Array(32).fill(42);

// Captured from cryptography-private 0d5046df and crypto-bigint 8aabcee5 running on WASM32.
describe('historical WASM sampling', () => {
	const curves = [Curve.SECP256K1, Curve.SECP256R1, Curve.ED25519, Curve.RISTRETTO];

	it.each(curves)('preserves native 64-bit derivation by default for %s', async (curve) => {
		const { decryptionKey } = await createClassGroupsKeypair(rootSeed, curve);
		expect(toHex(sha256(decryptionKey))).toBe(
			'a60572fa54a24f66fec043e5f4c47d652163dbfd1568671062288c5ad6ebaacc',
		);
	});
	const fixedHashFingerprints = [
		[
			'c63ec02323ced4583261f1ed59c40b97fc16ea8d7aa7756ffb5d0a959590db59',
			'2c42f55121ca54e3586304c8f770a62d351d0c76ad9d81fe5fa8dbe1fdd5ff39',
		],
		[
			'afa9090f1cffe1fb194cd7b1a55ec9f4666b13723b2323c227ea5937867a3d32',
			'aa1ccce1e795d72379fa9831a5f37cd122b8b58611d761d3c076f115a7a51bf2',
		],
		[
			'43a70e84720299d7caeb9377a27504ccfb77deea52d4e561e41b7baa3de4746b',
			'ab71819c85917bef63cd15d473a2553af222732ce067ea2788a891011f7a6eae',
		],
		[
			'e313303ac9f3c3b71e199f924965234280446989d4dd941ef4fca26056b4b9a2',
			'528d2a8fcb2c3b30176f4c731913a5ebf5dab92d469f1fa7582d7fbd26ad1b27',
		],
	];
	const legacyHashPublicFingerprints = [
		'c63ec02323ced4583261f1ed59c40b97fc16ea8d7aa7756ffb5d0a959590db59',
		'2754b8d86e299d81115e9e54d3cae828d09a5145ffc8ff52d9b00040b25ccc82',
		'16792bc6cf9e8c9921c8433e562a99d7ca1ea38684d1d9bc7a550b1b047abb5b',
		'16792bc6cf9e8c9921c8433e562a99d7ca1ea38684d1d9bc7a550b1b047abb5b',
	];

	it.each(curves)('recovers historical WASM keys for %s with both hash versions', async (curve) => {
		const index = curves.indexOf(curve);
		for (const legacyHash of [false, true]) {
			const keys = await UserShareEncryptionKeys.fromRootSeedKeyWasm32(rootSeed, curve, {
				legacyHash,
			});
			const [publicFingerprint, privateFingerprint] = legacyHash
				? [legacyHashPublicFingerprints[index], fixedHashFingerprints[0][1]]
				: fixedHashFingerprints[index];
			expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
			expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
			expect(keys.legacyHash).toBe(legacyHash);
			const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
				keys.toShareEncryptionKeysBytes(),
			);
			expect(restored.encryptionKey).toEqual(keys.encryptionKey);
			expect(restored.decryptionKey).toEqual(keys.decryptionKey);
			expect(restored.legacyHash).toBe(legacyHash);
		}
	});
});
