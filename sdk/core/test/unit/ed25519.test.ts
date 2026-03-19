// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { bech32 } from '@scure/base';

import { bytesToHex, Ed25519Keypair, hexToBytes } from '../../src';

describe('Ed25519Keypair', () => {
	const validSeed = new Uint8Array(32);
	crypto.getRandomValues(validSeed);

	describe('fromSeed', () => {
		it('should create keypair from 32-byte seed', () => {
			const keypair = Ed25519Keypair.fromSeed(validSeed);
			expect(keypair.getPublicKeyBytes()).toHaveLength(32);
		});

		it('should reject seeds that are not 32 bytes', () => {
			expect(() => Ed25519Keypair.fromSeed(new Uint8Array(16))).toThrow('32 bytes');
			expect(() => Ed25519Keypair.fromSeed(new Uint8Array(64))).toThrow('32 bytes');
			expect(() => Ed25519Keypair.fromSeed(new Uint8Array(0))).toThrow('32 bytes');
		});

		it('should produce deterministic keys from same seed', () => {
			const first = Ed25519Keypair.fromSeed(validSeed);
			const second = Ed25519Keypair.fromSeed(validSeed);
			expect(first.getPublicKeyBytes()).toEqual(second.getPublicKeyBytes());
			expect(first.getSecretKey()).toEqual(second.getSecretKey());
		});

		it('should produce different keys from different seeds', () => {
			const otherSeed = new Uint8Array(32);
			crypto.getRandomValues(otherSeed);
			const first = Ed25519Keypair.fromSeed(validSeed);
			const second = Ed25519Keypair.fromSeed(otherSeed);
			expect(first.getPublicKeyBytes()).not.toEqual(second.getPublicKeyBytes());
		});
	});

	describe('deriveKeypairFromSeed', () => {
		it('should derive same keypair as fromSeed', () => {
			const fromBytes = Ed25519Keypair.fromSeed(validSeed);
			const fromHex = Ed25519Keypair.deriveKeypairFromSeed(bytesToHex(validSeed));
			expect(fromBytes.getPublicKeyBytes()).toEqual(fromHex.getPublicKeyBytes());
		});

		it('should handle 0x prefix', () => {
			const withPrefix = Ed25519Keypair.deriveKeypairFromSeed('0x' + bytesToHex(validSeed));
			const without = Ed25519Keypair.deriveKeypairFromSeed(bytesToHex(validSeed));
			expect(withPrefix.getPublicKeyBytes()).toEqual(without.getPublicKeyBytes());
		});
	});

	describe('fromSecretKey (hex)', () => {
		it('should round-trip through getSecretKey', () => {
			const original = Ed25519Keypair.fromSeed(validSeed);
			const restored = Ed25519Keypair.fromSecretKey(original.getSecretKey());
			expect(restored.getPublicKeyBytes()).toEqual(original.getPublicKeyBytes());
			expect(restored.getSecretKey()).toEqual(original.getSecretKey());
		});
	});

	describe('fromSecretKey (Bech32)', () => {
		it('should decode suiprivkey Bech32 format', () => {
			const payload = new Uint8Array(33);
			payload[0] = 0x00; // Ed25519 flag
			payload.set(validSeed, 1);
			const encoded = bech32.encode('suiprivkey', bech32.toWords(payload));

			const keypair = Ed25519Keypair.fromSecretKey(encoded);
			const expected = Ed25519Keypair.fromSeed(validSeed);
			expect(keypair.getPublicKeyBytes()).toEqual(expected.getPublicKeyBytes());
		});

		it('should reject non-Ed25519 Bech32 keys', () => {
			const payload = new Uint8Array(33);
			payload[0] = 0x01; // Secp256k1 flag, not Ed25519
			payload.set(validSeed, 1);
			const encoded = bech32.encode('suiprivkey', bech32.toWords(payload));

			expect(() => Ed25519Keypair.fromSecretKey(encoded)).toThrow('Only Ed25519');
		});

		it('should auto-detect format: hex vs Bech32', () => {
			const hexKey = bytesToHex(validSeed);
			expect(hexKey.startsWith('suiprivkey')).toBe(false);
			// hex path
			const fromHex = Ed25519Keypair.fromSecretKey(hexKey);
			expect(fromHex.getPublicKeyBytes()).toEqual(Ed25519Keypair.fromSeed(validSeed).getPublicKeyBytes());
		});
	});

	describe('sign and verify', () => {
		it('should sign and verify a message', async () => {
			const keypair = Ed25519Keypair.fromSeed(validSeed);
			const message = new TextEncoder().encode('test message');

			const signature = await keypair.sign(message);
			expect(signature).toHaveLength(64);

			const isValid = await keypair.verify(message, signature);
			expect(isValid).toBe(true);
		});

		it('should reject tampered message', async () => {
			const keypair = Ed25519Keypair.fromSeed(validSeed);
			const message = new TextEncoder().encode('test message');
			const signature = await keypair.sign(message);

			const tampered = new TextEncoder().encode('tampered message');
			const isValid = await keypair.verify(tampered, signature);
			expect(isValid).toBe(false);
		});

		it('should reject signature from different key', async () => {
			const keypairA = Ed25519Keypair.fromSeed(validSeed);
			const otherSeed = new Uint8Array(32);
			crypto.getRandomValues(otherSeed);
			const keypairB = Ed25519Keypair.fromSeed(otherSeed);

			const message = new TextEncoder().encode('test message');
			const signatureA = await keypairA.sign(message);

			const isValid = await keypairB.verify(message, signatureA);
			expect(isValid).toBe(false);
		});

		it('static verify should work with raw public key', async () => {
			const keypair = Ed25519Keypair.fromSeed(validSeed);
			const message = new TextEncoder().encode('test message');
			const signature = await keypair.sign(message);

			const isValid = Ed25519Keypair.verify(keypair.getPublicKeyBytes(), message, signature);
			expect(isValid).toBe(true);
		});
	});
});
