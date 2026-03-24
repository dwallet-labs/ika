// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Cryptographic utilities for the Ika OWS provider:
 * - Mnemonic encryption/decryption (AES-256-GCM + scrypt)
 * - BIP-44 private key derivation from mnemonic
 * - Hex encoding utilities
 */

import { gcm } from '@noble/ciphers/aes';
import { scrypt } from '@noble/hashes/scrypt.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';

import { Curve } from '@ika.xyz/sdk';

import { OWSError, OWSErrorCode } from './errors.js';

// ─── Scrypt Parameters ───────────────────────────────────────────────────
// Matches OWS core's Ethereum Keystore v3 approach.
const SCRYPT_N = 2 ** 18; // ~256 MiB memory cost
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32; // 256-bit key for AES-256
const SALT_LENGTH = 32;
const NONCE_LENGTH = 12; // AES-256-GCM standard

// ─── Mnemonic Encryption ─────────────────────────────────────────────────

/**
 * Encrypt a mnemonic phrase with AES-256-GCM using a scrypt-derived key.
 */
export function encryptMnemonic(
	mnemonic: string,
	passphrase: string,
): { ciphertext: Uint8Array; salt: Uint8Array; nonce: Uint8Array } {
	const salt = randomBytes(SALT_LENGTH);
	const nonce = randomBytes(NONCE_LENGTH);
	const key = scrypt(passphrase, salt, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: SCRYPT_DKLEN });
	const cipher = gcm(key, nonce);
	const ciphertext = cipher.encrypt(new TextEncoder().encode(mnemonic));
	return { ciphertext, salt, nonce };
}

/**
 * Decrypt a mnemonic phrase encrypted with {@link encryptMnemonic}.
 * @throws {OWSError} EXPORT_FAILED if decryption fails (wrong passphrase).
 */
export function decryptMnemonic(
	ciphertext: Uint8Array,
	salt: Uint8Array,
	nonce: Uint8Array,
	passphrase: string,
): string {
	try {
		const key = scrypt(passphrase, salt, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: SCRYPT_DKLEN });
		const cipher = gcm(key, nonce);
		const plaintext = cipher.decrypt(ciphertext);
		return new TextDecoder().decode(plaintext);
	} catch (e) {
		throw new OWSError(OWSErrorCode.EXPORT_FAILED, 'Failed to decrypt mnemonic — wrong passphrase?', e);
	}
}

// ─── BIP-44 Key Derivation ───────────────────────────────────────────────

/**
 * Derive a private key from a BIP-39 mnemonic via BIP-44 paths.
 *
 * Derivation paths (matching OWS spec):
 * - secp256k1: m/44'/60'/0'/0/{index}  (EVM)
 * - ed25519:   m/44'/501'/{index}'/0'  (Solana)
 * - secp256r1: m/44'/60'/0'/0/{index}  (same as secp256k1)
 */
export function derivePrivateKeyFromMnemonic(
	mnemonic: string,
	curve: Curve,
	index: number,
): Uint8Array {
	const seed = mnemonicToSeedSync(mnemonic);
	const master = HDKey.fromMasterSeed(seed);

	let path: string;
	switch (curve) {
		case Curve.ED25519:
			path = `m/44'/501'/${index}'/0'`;
			break;
		case Curve.SECP256K1:
		case Curve.SECP256R1:
		default:
			path = `m/44'/60'/0'/0/${index}`;
			break;
	}

	const derived = master.derive(path);
	if (!derived.privateKey) {
		throw new OWSError(OWSErrorCode.INVALID_INPUT, `Failed to derive key at path ${path}`);
	}
	return derived.privateKey;
}

// ─── Hex Utilities ───────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	const bytes = new Uint8Array(clean.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export function bytesToBase64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64');
}

export function base64ToBytes(b64: string): Uint8Array {
	return new Uint8Array(Buffer.from(b64, 'base64'));
}
