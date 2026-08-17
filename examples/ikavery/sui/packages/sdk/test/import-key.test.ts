import type { Keypair } from '@mysten/sui/cryptography';
import { describe, expect, test } from 'bun:test';

import type { RecoveryClient } from '../src/client';
import { importSolanaKey } from '../src/flows/import-key';
import type { NewMemberInput } from '../src/move/members';

// A stand-in client; importSolanaKey validates inputs before touching the client,
// so any object that satisfies the type check is fine for these negative tests.
const fakeClient = {} as RecoveryClient;
const fakeKeypair = {} as Keypair;
const someKeys = {} as never;
const someMembers: NewMemberInput[] = [
	{ scheme: 'ed25519', publicKey: new Uint8Array(32).fill(0xaa) },
];

describe('importSolanaKey input validation', () => {
	test('rejects a 16-byte secret key', async () => {
		await expect(
			importSolanaKey(fakeClient, {
				solanaSecretKey: new Uint8Array(16),
				userShareEncryptionKeys: someKeys,
				gasSigner: fakeKeypair,
				initialMembers: someMembers,
				threshold: 1,
			}),
		).rejects.toThrow(/32 or 64 bytes/);
	});

	test('accepts a 32-byte secret key (early validation passes)', async () => {
		// We don't expect this to succeed end-to-end (no real Sui), but we want to
		// confirm the *length check* doesn't fail. The next failure should come
		// from a downstream call, not the length validator.
		await expect(
			importSolanaKey(fakeClient, {
				solanaSecretKey: new Uint8Array(32),
				userShareEncryptionKeys: someKeys,
				gasSigner: fakeKeypair,
				initialMembers: someMembers,
				threshold: 1,
			}),
		).rejects.not.toThrow(/32 or 64 bytes/);
	});

	test('rejects an empty initialMembers list', async () => {
		await expect(
			importSolanaKey(fakeClient, {
				solanaSecretKey: new Uint8Array(32),
				userShareEncryptionKeys: someKeys,
				gasSigner: fakeKeypair,
				initialMembers: [],
				threshold: 1,
			}),
		).rejects.toThrow(/initialMembers must be non-empty/);
	});

	test('rejects threshold below 1', async () => {
		await expect(
			importSolanaKey(fakeClient, {
				solanaSecretKey: new Uint8Array(32),
				userShareEncryptionKeys: someKeys,
				gasSigner: fakeKeypair,
				initialMembers: someMembers,
				threshold: 0,
			}),
		).rejects.toThrow(/threshold 0 out of range/);
	});

	test('rejects threshold above member count', async () => {
		await expect(
			importSolanaKey(fakeClient, {
				solanaSecretKey: new Uint8Array(32),
				userShareEncryptionKeys: someKeys,
				gasSigner: fakeKeypair,
				initialMembers: someMembers, // length 1
				threshold: 2,
			}),
		).rejects.toThrow(/threshold 2 out of range/);
	});
});
