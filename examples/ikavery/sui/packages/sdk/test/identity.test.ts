import { deriveDeviceIdentity } from '@fesal-packages/ikavery-core';
import { describe, expect, test } from 'bun:test';

const SEED_A = new Uint8Array(32).fill(0x11);
const SEED_B = new Uint8Array(32).fill(0x22);

// WASM-backed UserShareEncryptionKeys.fromRootSeedKey can take several seconds
// on first call.
const TIMEOUT = 30_000;

describe('deriveDeviceIdentity', () => {
	test(
		'same seed produces same Sui address + same serializable bytes',
		async () => {
			const a = await deriveDeviceIdentity(SEED_A);
			const b = await deriveDeviceIdentity(SEED_A);
			expect(a.encryptionKeySuiAddress).toBe(b.encryptionKeySuiAddress);
			expect(Array.from(a.userShareEncryptionKeys.toShareEncryptionKeysBytes())).toEqual(
				Array.from(b.userShareEncryptionKeys.toShareEncryptionKeysBytes()),
			);
		},
		TIMEOUT,
	);

	test(
		'different seeds produce different Sui addresses',
		async () => {
			const a = await deriveDeviceIdentity(SEED_A);
			const b = await deriveDeviceIdentity(SEED_B);
			expect(a.encryptionKeySuiAddress).not.toBe(b.encryptionKeySuiAddress);
		},
		TIMEOUT,
	);

	test(
		'encryptionKeySuiAddress matches userShareEncryptionKeys.getSuiAddress()',
		async () => {
			const id = await deriveDeviceIdentity(SEED_A);
			expect(id.encryptionKeySuiAddress).toBe(id.userShareEncryptionKeys.getSuiAddress());
		},
		TIMEOUT,
	);

	test('rejects a non-32-byte seed', async () => {
		await expect(deriveDeviceIdentity(new Uint8Array(16))).rejects.toThrow(/32-byte PRF seed/);
	});
});
