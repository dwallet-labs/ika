import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import { Secp256r1Keypair } from '@mysten/sui/keypairs/secp256r1';
import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, test } from 'bun:test';

import {
	authSignerFromKeypair,
	authSignerFromPasskey,
	buildCredential,
	credentialFromSerializedSignature,
} from '../src/move/credential';

const PKG = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

describe('buildCredential', () => {
	test('ed25519 path emits a single auth::ed25519_credential call', () => {
		const tx = new Transaction();
		buildCredential(tx, PKG, {
			scheme: 'ed25519',
			publicKey: new Uint8Array(32).fill(0x01),
			signature: new Uint8Array(64).fill(0xaa),
		});
		const calls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		expect(calls.length).toBe(1);
		expect(calls[0]!.MoveCall!.module).toBe('auth');
		expect(calls[0]!.MoveCall!.function).toBe('ed25519_credential');
		expect(calls[0]!.MoveCall!.package).toBe(PKG);
	});

	test('secp256k1 path emits a single auth::secp256k1_credential call', () => {
		const tx = new Transaction();
		buildCredential(tx, PKG, {
			scheme: 'secp256k1',
			publicKey: new Uint8Array(33).fill(0x02),
			signature: new Uint8Array(64).fill(0xbb),
		});
		const calls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		expect(calls.length).toBe(1);
		expect(calls[0]!.MoveCall!.function).toBe('secp256k1_credential');
	});

	test('secp256r1 path emits a single auth::secp256r1_credential call', () => {
		const tx = new Transaction();
		buildCredential(tx, PKG, {
			scheme: 'secp256r1',
			publicKey: new Uint8Array(33).fill(0x03),
			signature: new Uint8Array(64).fill(0xcc),
		});
		const calls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		expect(calls.length).toBe(1);
		expect(calls[0]!.MoveCall!.function).toBe('secp256r1_credential');
	});

	test('webauthn path emits assertion::new + auth::webauthn_credential', () => {
		const tx = new Transaction();
		buildCredential(tx, PKG, {
			scheme: 'webauthn',
			assertion: {
				publicKey: new Uint8Array(33).fill(0x02),
				authenticatorData: new Uint8Array(37).fill(0xab),
				clientDataJSON: new Uint8Array(80).fill(0xcd),
				signature: new Uint8Array(64).fill(0xef),
			},
		});
		const data = tx.getData();
		const calls = data.commands.filter((c) => c.$kind === 'MoveCall');
		expect(calls.length).toBe(2);
		const fns = calls.map((c) => `${c.MoveCall!.module}::${c.MoveCall!.function}`);
		expect(fns).toEqual(['assertion::new', 'auth::webauthn_credential']);
		for (const c of calls) {
			expect(c.MoveCall!.package).toBe(PKG);
		}
	});

	test('sender_address path emits a single auth::sender_credential call with no args', () => {
		const tx = new Transaction();
		buildCredential(tx, PKG, {
			scheme: 'sender_address',
			address: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
		});
		const calls = tx.getData().commands.filter((c) => c.$kind === 'MoveCall');
		expect(calls.length).toBe(1);
		expect(calls[0]!.MoveCall!.module).toBe('auth');
		expect(calls[0]!.MoveCall!.function).toBe('sender_credential');
		expect(calls[0]!.MoveCall!.package).toBe(PKG);
		// No user-supplied args — the Move builder reads ctx.sender() itself.
		expect(calls[0]!.MoveCall!.arguments?.length ?? 0).toBe(0);
	});
});

describe('authSignerFromKeypair', () => {
	test('ed25519 keypair → ed25519 CredentialInput with 32-byte pubkey + 64-byte sig', async () => {
		const kp = new Ed25519Keypair();
		const signer = authSignerFromKeypair(kp);
		const challenge = new Uint8Array(32).fill(0xab);
		const cred = await signer.sign(challenge);
		expect(cred.scheme).toBe('ed25519');
		if (cred.scheme !== 'ed25519') throw new Error();
		expect(cred.publicKey.length).toBe(32);
		expect(cred.signature.length).toBe(64);
	});

	test('secp256k1 keypair → secp256k1 CredentialInput with 33-byte compressed pubkey', async () => {
		const kp = new Secp256k1Keypair();
		const signer = authSignerFromKeypair(kp);
		const cred = await signer.sign(new Uint8Array(32).fill(0xcd));
		expect(cred.scheme).toBe('secp256k1');
		if (cred.scheme !== 'secp256k1') throw new Error();
		expect(cred.publicKey.length).toBe(33);
		expect(cred.signature.length).toBe(64);
	});

	test('secp256r1 keypair → secp256r1 CredentialInput', async () => {
		const kp = new Secp256r1Keypair();
		const signer = authSignerFromKeypair(kp);
		const cred = await signer.sign(new Uint8Array(32).fill(0xef));
		expect(cred.scheme).toBe('secp256r1');
		if (cred.scheme !== 'secp256r1') throw new Error();
		expect(cred.publicKey.length).toBe(33);
		expect(cred.signature.length).toBe(64);
	});

	test('same challenge → same ed25519 signature (deterministic per RFC8032)', async () => {
		const kp = new Ed25519Keypair();
		const signer = authSignerFromKeypair(kp);
		const challenge = new Uint8Array(32).fill(0x42);
		const c1 = await signer.sign(challenge);
		const c2 = await signer.sign(challenge);
		if (c1.scheme !== 'ed25519' || c2.scheme !== 'ed25519') throw new Error();
		expect(Array.from(c1.signature)).toEqual(Array.from(c2.signature));
	});
});

describe('credentialFromSerializedSignature', () => {
	test('round-trips a Sui ed25519 signPersonalMessage signature', async () => {
		const kp = new Ed25519Keypair();
		const challenge = new Uint8Array(32).fill(0x11);
		const { signature } = await kp.signPersonalMessage(challenge);
		const cred = credentialFromSerializedSignature(signature);
		expect(cred.scheme).toBe('ed25519');
		if (cred.scheme !== 'ed25519') throw new Error();
		expect(cred.publicKey.length).toBe(32);
		expect(cred.signature.length).toBe(64);
		expect(Array.from(cred.publicKey)).toEqual(Array.from(kp.getPublicKey().toRawBytes()));
	});

	test('round-trips a secp256k1 signPersonalMessage signature', async () => {
		const kp = new Secp256k1Keypair();
		const challenge = new Uint8Array(32).fill(0x22);
		const { signature } = await kp.signPersonalMessage(challenge);
		const cred = credentialFromSerializedSignature(signature);
		expect(cred.scheme).toBe('secp256k1');
		if (cred.scheme !== 'secp256k1') throw new Error();
		expect(cred.publicKey.length).toBe(33);
		expect(cred.signature.length).toBe(64);
	});

	test('rejects a non-parseable signature string', () => {
		expect(() => credentialFromSerializedSignature('not-a-sig')).toThrow();
	});
});

describe('authSignerFromPasskey', () => {
	test('returns an AuthSigner whose sign() goes through the WebAuthn driver', () => {
		// In Node we can't actually call navigator.credentials, so we just
		// assert the wrapper builds correctly. Hitting the actual passkey path
		// is exercised in browser e2e.
		const signer = authSignerFromPasskey({
			credentialId: new Uint8Array(16).fill(0xaa),
			publicKey: new Uint8Array(33).fill(0xbb),
			rpId: 'example.com',
		});
		expect(typeof signer.sign).toBe('function');
	});
});
