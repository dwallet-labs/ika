// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { toHex } from '@mysten/bcs';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import {
	createClassGroupsKeypair,
	createClassGroupsKeypairV2,
	Curve,
	UserShareEncryptionKeys,
} from '../../src/index.js';

const rootSeed = new Uint8Array(32).fill(42);

// Legacy fixtures: cryptography-private 0d5046df / crypto-bigint 8aabcee5 on WASM32.
// New fixtures: native Rust using the pinned deployed sampler, checked byte-for-byte
// against production derivation at cryptography-private e5e161c2,
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
			'7415d98b6969534c7100d9db1030c804089295974d705f44abbd8d4b0e3d2cf8',
			'a60572fa54a24f66fec043e5f4c47d652163dbfd1568671062288c5ad6ebaacc',
		],
		[
			'7cb749c22b960baf812086ea162cfa9d22f1f99a05e7c288e83958e5b7b578f1',
			'a60572fa54a24f66fec043e5f4c47d652163dbfd1568671062288c5ad6ebaacc',
		],
		[
			'ddf91a1b79eba0fa9a335627b5fca83baafeaaaad8f41e3f521ecd5fe1bf3eeb',
			'a60572fa54a24f66fec043e5f4c47d652163dbfd1568671062288c5ad6ebaacc',
		],
		[
			'ddf91a1b79eba0fa9a335627b5fca83baafeaaaad8f41e3f521ecd5fe1bf3eeb',
			'a60572fa54a24f66fec043e5f4c47d652163dbfd1568671062288c5ad6ebaacc',
		],
	];
	const currentHashNewFingerprints = [
		[
			'31954113b6dcf62d8267c441f4f5e8167a9fcc51b32663730ee644884594554e',
			'5081aeac56553c1f96fe3946572a885f519c040fd955e4a325f5b5a71d513825',
		],
		[
			'09a1625220c0efd485261b00d66a5562641516dd3eb7a0e560670487d2cc3763',
			'b2146bc80a068668340118d9e27ed6ca578aba522f95f3fa423da3ea39130628',
		],
		[
			'ac1dfa23ae6ee46748b118d7dd3d4d7087c3a7f205eac241b9a8945db94d2ab1',
			'ab02e2f0d50de0d5240611da0f2de3a47c917996e826f12805dee604bb975e3b',
		],
		[
			'f24f180de661bf694cb3ef83bd4b77010b982208e1297d8a8bc1141e678f929f',
			'33cf9d62e857e4ea39930057484be7ca66c27745b6340f2833e605cc04dcc3f7',
		],
	];
	it.each(curves)(
		'preserves historical keys through the original direct API for %s',
		async (curve) => {
			const seed = UserShareEncryptionKeys.hash(
				UserShareEncryptionKeys.domainSeparators.classGroups,
				rootSeed,
				curve,
			);
			const keys = await createClassGroupsKeypair(seed, curve);
			const [publicFingerprint, privateFingerprint] = fixedHashFingerprints[curves.indexOf(curve)];
			expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
			expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
		},
	);

	it.each(curves)(
		'matches native new-sampler key bytes through the direct V2 API for %s',
		async (curve) => {
			const keys = await createClassGroupsKeypairV2(rootSeed, curve);
			const [publicFingerprint, privateFingerprint] = rawNewFingerprints[curves.indexOf(curve)];
			expect(toHex(sha256(keys.encryptionKey))).toBe(publicFingerprint);
			expect(toHex(sha256(keys.decryptionKey))).toBe(privateFingerprint);
		},
	);

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
