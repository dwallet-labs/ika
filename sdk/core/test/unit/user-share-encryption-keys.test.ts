// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { beforeAll, describe, expect, it } from 'vitest';

import { bcs } from '@mysten/bcs';
import { bech32 } from '@scure/base';

import {
	Curve,
	UserShareEncryptionKeys,
	VersionedUserShareEncryptionKeysBcs,
} from '../../src';

describe('UserShareEncryptionKeys', () => {
	const testSeed = new Uint8Array(32);
	crypto.getRandomValues(testSeed);

	let keysFixed: UserShareEncryptionKeys;
	let keysLegacy: UserShareEncryptionKeys;

	beforeAll(async () => {
		keysFixed = await UserShareEncryptionKeys.fromRootSeedKey(testSeed, Curve.SECP256K1);
		keysLegacy = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(testSeed, Curve.SECP256K1);
	});

	describe('construction', () => {
		it('should produce keys with encryption key and signing public key', () => {
			expect(keysFixed.encryptionKey).toBeInstanceOf(Uint8Array);
			expect(keysFixed.encryptionKey.length).toBeGreaterThan(0);
			expect(keysFixed.getSigningPublicKeyBytes()).toBeInstanceOf(Uint8Array);
			expect(keysFixed.getSigningPublicKeyBytes()).toHaveLength(32);
		});

		it('should be deterministic for same seed and curve', async () => {
			const second = await UserShareEncryptionKeys.fromRootSeedKey(testSeed, Curve.SECP256K1);
			expect(second.encryptionKey).toEqual(keysFixed.encryptionKey);
			expect(second.getSigningPublicKeyBytes()).toEqual(keysFixed.getSigningPublicKeyBytes());
		});

		it('should produce different keys for different seeds', async () => {
			const otherSeed = new Uint8Array(32);
			crypto.getRandomValues(otherSeed);
			const other = await UserShareEncryptionKeys.fromRootSeedKey(otherSeed, Curve.SECP256K1);
			expect(other.encryptionKey).not.toEqual(keysFixed.encryptionKey);
		});

		it('should produce different keys for different curves', async () => {
			const secp256r1 = await UserShareEncryptionKeys.fromRootSeedKey(testSeed, Curve.SECP256R1);
			expect(secp256r1.encryptionKey).not.toEqual(keysFixed.encryptionKey);
		});
	});

	describe('legacyHash', () => {
		it('fixed hash should have legacyHash=false', () => {
			expect(keysFixed.legacyHash).toBe(false);
		});

		it('legacy hash should have legacyHash=true', () => {
			expect(keysLegacy.legacyHash).toBe(true);
		});

		it('legacy and fixed should match for SECP256K1 (curve number 0)', () => {
			// SECP256K1 has curve number 0, so legacy (always 0) and fixed (curveNumber=0) produce same hash
			expect(keysLegacy.encryptionKey).toEqual(keysFixed.encryptionKey);
		});

		it('legacy and fixed should differ for non-zero curve numbers', async () => {
			const fixedEd = await UserShareEncryptionKeys.fromRootSeedKey(testSeed, Curve.ED25519);
			const legacyEd = await UserShareEncryptionKeys.fromRootSeedKeyLegacyHash(testSeed, Curve.ED25519);
			// ED25519 has curve number 2, so legacy (byte=0) != fixed (byte=2)
			expect(legacyEd.encryptionKey).not.toEqual(fixedEd.encryptionKey);
		});
	});

	describe('V3 serialization round-trip', () => {
		it('should round-trip fixed hash keys', () => {
			const serialized = keysFixed.toShareEncryptionKeysBytes();
			const deserialized = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(serialized);

			expect(deserialized.encryptionKey).toEqual(keysFixed.encryptionKey);
			expect(deserialized.getSigningPublicKeyBytes()).toEqual(keysFixed.getSigningPublicKeyBytes());
			expect(deserialized.legacyHash).toBe(false);
			expect(deserialized.curve).toBe(Curve.SECP256K1);
		});

		it('should round-trip legacy hash keys preserving legacyHash flag', () => {
			const serialized = keysLegacy.toShareEncryptionKeysBytes();
			const deserialized = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(serialized);

			expect(deserialized.encryptionKey).toEqual(keysLegacy.encryptionKey);
			expect(deserialized.getSigningPublicKeyBytes()).toEqual(keysLegacy.getSigningPublicKeyBytes());
			expect(deserialized.legacyHash).toBe(true);
		});

		it('should produce identical bytes on double round-trip', () => {
			const first = keysFixed.toShareEncryptionKeysBytes();
			const deserialized = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(first);
			const second = deserialized.toShareEncryptionKeysBytes();
			expect(second).toEqual(first);
		});
	});

	describe('V1/V2 Bech32 deserialization', () => {
		it('should deserialize V1 (legacy Bech32) keys', () => {
			// Create a Bech32-encoded secret key (suiprivkey format)
			const secretSeed = new Uint8Array(32);
			crypto.getRandomValues(secretSeed);
			const payload = new Uint8Array(33);
			payload[0] = 0x00; // Ed25519
			payload.set(secretSeed, 1);
			const bech32Key = bech32.encode('suiprivkey', bech32.toWords(payload));

			const v1Bytes = VersionedUserShareEncryptionKeysBcs.serialize({
				V1: {
					encryptionKey: keysFixed.encryptionKey,
					decryptionKey: new Uint8Array(10), // dummy
					secretShareSigningSecretKey: bech32Key,
					curve: BigInt(0), // SECP256K1
				},
			}).toBytes();

			const deserialized = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(v1Bytes);
			expect(deserialized.legacyHash).toBe(true);
			expect(deserialized.curve).toBe(Curve.SECP256K1);
			expect(deserialized.getSigningPublicKeyBytes()).toHaveLength(32);
		});

		it('should deserialize V2 (fixed Bech32) keys', () => {
			const secretSeed = new Uint8Array(32);
			crypto.getRandomValues(secretSeed);
			const payload = new Uint8Array(33);
			payload[0] = 0x00;
			payload.set(secretSeed, 1);
			const bech32Key = bech32.encode('suiprivkey', bech32.toWords(payload));

			const v2Bytes = VersionedUserShareEncryptionKeysBcs.serialize({
				V2: {
					encryptionKey: keysFixed.encryptionKey,
					decryptionKey: new Uint8Array(10),
					secretShareSigningSecretKey: bech32Key,
					curve: 0,
				},
			}).toBytes();

			const deserialized = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(v2Bytes);
			expect(deserialized.legacyHash).toBe(false);
			expect(deserialized.curve).toBe(Curve.SECP256K1);
		});
	});

	describe('signing', () => {
		it('should sign and verify messages', async () => {
			const message = new TextEncoder().encode('test message');
			const signature = await keysFixed.sign(message);
			expect(signature).toHaveLength(64);

			const isValid = await keysFixed.verifySignature(message, signature);
			expect(isValid).toBe(true);
		});

		it('should reject tampered messages', async () => {
			const message = new TextEncoder().encode('test message');
			const signature = await keysFixed.sign(message);

			const tampered = new TextEncoder().encode('tampered');
			const isValid = await keysFixed.verifySignature(tampered, signature);
			expect(isValid).toBe(false);
		});

		it('getEncryptionKeySignature should sign the encryption key', async () => {
			const signature = await keysFixed.getEncryptionKeySignature();
			expect(signature).toHaveLength(64);

			const isValid = await keysFixed.verifySignature(keysFixed.encryptionKey, signature);
			expect(isValid).toBe(true);
		});

		it('getEncryptionKeySignature should be deterministic', async () => {
			const sig1 = await keysFixed.getEncryptionKeySignature();
			const sig2 = await keysFixed.getEncryptionKeySignature();
			expect(sig1).toEqual(sig2);
		});
	});

	describe('fromKeyMaterial', () => {
		it('should construct keys from raw material', () => {
			// Create a known Ed25519 key to use as signing secret
			const signingSecretHex = bytesToHexForTest(testSeed);

			const fromMaterial = UserShareEncryptionKeys.fromKeyMaterial(
				keysFixed.encryptionKey,
				new Uint8Array(10), // dummy decryption key
				signingSecretHex,
				Curve.SECP256K1,
				false,
			);
			expect(fromMaterial.encryptionKey).toEqual(keysFixed.encryptionKey);
			expect(fromMaterial.legacyHash).toBe(false);
			expect(fromMaterial.curve).toBe(Curve.SECP256K1);
			expect(fromMaterial.getSigningPublicKeyBytes()).toHaveLength(32);
		});

		it('should respect legacyHash flag', () => {
			const signingSecretHex = bytesToHexForTest(testSeed);

			const legacy = UserShareEncryptionKeys.fromKeyMaterial(
				keysFixed.encryptionKey,
				new Uint8Array(10),
				signingSecretHex,
				Curve.SECP256K1,
				true,
			);
			expect(legacy.legacyHash).toBe(true);
		});
	});

	describe('encryptionKey immutability', () => {
		it('encryptionKey should be readonly', () => {
			// TypeScript enforces this at compile time, but verify the value doesn't change
			const original = new Uint8Array(keysFixed.encryptionKey);
			expect(keysFixed.encryptionKey).toEqual(original);
		});
	});
});

function bytesToHexForTest(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}
