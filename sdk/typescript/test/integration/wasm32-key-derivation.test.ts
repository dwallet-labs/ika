// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { createClassGroupsKeypair, Curve, UserShareEncryptionKeys } from '../../src/index.js';

const rootSeed = new Uint8Array(32).fill(42);

// Legacy fixtures: cryptography-private 0d5046df / crypto-bigint 8aabcee5 on WASM32.
// New fixtures: native Rust calling Protocol directly at cryptography-private c07d93b6,
// with raw seeds or keccak256(ASCII("CLASS_GROUPS_DECRYPTION_KEY_V1") || curve || rootSeed).
// The SDK uses real WASM, so the new fixtures also require native/WASM agreement.
describe('new and historical key sampling', () => {
	const curves = [Curve.SECP256K1, Curve.SECP256R1, Curve.ED25519, Curve.RISTRETTO];
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
	// Computed independently from the original SDK's signing-seed formula and
	// Ed25519Keypair.deriveKeypairFromSeed; both samplers must keep these identities.
	const signingPublicFingerprints = [
		'e3d8d641a37b0c696dd22748ca648490d0cc63ebf27d4f57831c3f9320371f23',
		'579593c40cc52aaea5cacec7696650db5a8b2bca59fabd5d79b79e00dd12c7cf',
		'61774a8f676390d39356693f6ffc814aec02e56d32d389c45a8c173b92795fe1',
		'9c6c840f430e7f1b62389698898fcaf01c78e45ec2f082c2e667b744b24535f0',
	];
	const rawNewFingerprints = [
		[
			'9049878c07ceb26854668ddccaa6c8d59b7419dd8dedf4d9f9943273838ace08',
			'4c550920ddecf4052f50b89a5a97d85df32577bfe74bb8ab41543395ffa981fe',
		],
		[
			'65ba7314f65f9506919532c6e14af8963b9f4789bf7f20f2fe6c4aa319fdc6bb',
			'4c550920ddecf4052f50b89a5a97d85df32577bfe74bb8ab41543395ffa981fe',
		],
		[
			'd0572580aa52fee182072244eb009df28c607c17e202f4b198ff40b84167bd3f',
			'4c550920ddecf4052f50b89a5a97d85df32577bfe74bb8ab41543395ffa981fe',
		],
		[
			'd0572580aa52fee182072244eb009df28c607c17e202f4b198ff40b84167bd3f',
			'4c550920ddecf4052f50b89a5a97d85df32577bfe74bb8ab41543395ffa981fe',
		],
	];
	const currentHashNewFingerprints = [
		[
			'36870e856378c4aaf9f746563eed43fb442e4394fce99fdd387d97e1e640ec35',
			'e1e025c13c4f8be3709511cf896768087ae5521cfe3eabba867c5997e46cd461',
		],
		[
			'400ae8d6f321fe1cc274efce43fe0ff71cc5a6dce540ef1a55e6cd7c88ce2c7f',
			'520ae9323430ee458cc5a58fc9fb8fc2c7279a611d56837fa12938a87170d62c',
		],
		[
			'f196cf45499af9c355e2ad7737df42c08cf1e680e6663448e87854891b404358',
			'dddf946584c9b4b3cfe8f7a29baee551818fd7a99e884cc18c999235cfaf66b6',
		],
		[
			'e040522e488781ca4dc62cee32d16384c402cd9f051c8296756b614d36110a32',
			'8d884c3e80f4287822a2464f1e38d4315fba71819c54912f8c2b03db7cbbd9a3',
		],
	];

	it.each(curves)('matches native new-sampler key bytes for %s', async (curve) => {
		const keys = await createClassGroupsKeypair(rootSeed, curve);
		const [publicFingerprint, privateFingerprint] = rawNewFingerprints[curves.indexOf(curve)];
		expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
		expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
	});

	it.each(curves)('creates portable new keys with the V2 constructor for %s', async (curve) => {
		const keys = await UserShareEncryptionKeys.fromRootSeedKeyV2(rootSeed, curve);
		const index = curves.indexOf(curve);
		const [publicFingerprint, privateFingerprint] = currentHashNewFingerprints[index];
		expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
		expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
		expect(toHex(sha256(keys.getSigningPublicKeyBytes()))).toBe(signingPublicFingerprints[index]);
		expect(keys.legacyHash).toBe(false);
		expect(toHex(sha256(keys.decryptionKey))).not.toBe(fixedHashFingerprints[index][1]);
		const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
			keys.toShareEncryptionKeysBytes(),
		);
		expect(restored.toShareEncryptionKeysBytes()).toEqual(keys.toShareEncryptionKeysBytes());
	});

	it.each(curves.flatMap((curve) => [false, true].map((legacyHash) => ({ curve, legacyHash }))))(
		'recovers historical WASM keys for $curve with legacyHash=$legacyHash',
		async ({ curve, legacyHash }) => {
			const index = curves.indexOf(curve);
			const keys = legacyHash
				? await UserShareEncryptionKeys.fromRootSeedKey(rootSeed, curve, { legacyHash: true })
				: await UserShareEncryptionKeys.fromRootSeedKey(rootSeed, curve);
			const [publicFingerprint, privateFingerprint] = legacyHash
				? [legacyHashPublicFingerprints[index], fixedHashFingerprints[0][1]]
				: fixedHashFingerprints[index];
			expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
			expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
			expect(toHex(sha256(keys.getSigningPublicKeyBytes()))).toBe(
				signingPublicFingerprints[legacyHash ? 0 : index],
			);
			expect(keys.legacyHash).toBe(legacyHash);
			const restored = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
				keys.toShareEncryptionKeysBytes(),
			);
			expect(restored.toShareEncryptionKeysBytes()).toEqual(keys.toShareEncryptionKeysBytes());
			if (legacyHash) {
				const recovered = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(rootSeed, curve);
				expect(recovered.toShareEncryptionKeysBytes()).toEqual(keys.toShareEncryptionKeysBytes());
			}
		},
	);
});
